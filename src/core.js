// src/core.js — the proof core: create, read, bundle, public verify, certificate, health.
// Same request and response shapes as proofledger.io's v1 API.
'use strict';

const path = require('path');
const { assignPublicCertId } = require('./certId');
const platform = require('./platform');

const { proofView, normalizeProofStatus, validateExternalId, HASH_RE, FILENAME_MAX, PUBLIC_ORIGIN } = platform;
const VERIFY_LIMIT_PER_HOUR = Math.max(1, parseInt(process.env.VERIFY_LIMIT_PER_HOUR || '120', 10) || 120);

function mount(app, deps) {
  const { db, apiKeyAuth, idempotent, caps, anchoring, buildBundle, createIpRateLimiter, chainInfo, startedAt, version } = deps;

  const findByExternalId = db.prepare(`SELECT * FROM proofs WHERE user_id = ? AND external_id = ? LIMIT 1`);
  const findByHash = db.prepare(`SELECT * FROM proofs WHERE sha256 = ? ORDER BY anchored_polygon DESC, id DESC LIMIT 1`);
  const findByCertId = db.prepare(`SELECT * FROM proofs WHERE public_cert_id = ? LIMIT 1`);
  const findOwn = db.prepare(`SELECT * FROM proofs WHERE id = ? AND user_id = ?`);
  const findById = db.prepare(`SELECT * FROM proofs WHERE id = ?`);
  const insertProof = db.prepare(`
    INSERT INTO proofs (user_id, sha256, external_id, filename, size, mime, flags_json, status, created_at, creation_method, batch_id)
    VALUES (?, ?, ?, ?, 0, 'application/octet-stream', '{"apiSubmission":true}', 'APPROVED', ?, 'api', ?)
  `);
  const bumpUsage = db.prepare(`UPDATE users SET proofs_used_this_month = proofs_used_this_month + 1 WHERE id = ?`);
  const audit = db.prepare(`INSERT INTO audits (user_id, proof_id, action, meta_json, created_at) VALUES (?, ?, ?, ?, ?)`);

  // ---- health ------------------------------------------------------------------------
  app.get('/api/health', (req, res) => {
    let dbOk = false;
    try { db.prepare('SELECT 1 FROM proofs LIMIT 1').get(); dbOk = true; } catch (e) { console.error('health: database check failed:', e.message); }
    res.status(dbOk ? 200 : 503).json({
      ok: dbOk, db: dbOk, service: 'proofledger-community', version,
      anchoring: anchoring.status(), chain: chainInfo(),
      started_at: startedAt, timestamp: new Date().toISOString(),
    });
  });

  // ---- POST /api/v1/proof ------------------------------------------------------------
  app.post('/api/v1/proof', apiKeyAuth, idempotent, (req, res) => {
    try {
      const { sha256: hash, filename, external_id } = req.body || {};
      if (!hash || !HASH_RE.test(String(hash))) return res.status(400).json({ error: 'A valid 64-character SHA-256 hash is required.' });
      const normalized = String(hash).toLowerCase();
      const fname = String(filename || 'api-submission').slice(0, FILENAME_MAX);

      const ext = validateExternalId(external_id);
      if (ext.error) return res.status(400).json({ error: ext.error });
      if (ext.value !== null) {
        const same = findByExternalId.get(req.user.id, ext.value);
        if (same) return res.status(200).json({ ...proofView(same), already_existed: true });
      }

      const cap = caps.monthlyCap();
      const used = caps.usedThisMonth(req.user.id);
      if (used >= cap) {
        return res.status(429).json({ error: `Monthly proof limit reached (${cap.toLocaleString('en-US')}). ${caps.capHint()}`.trim(), monthly_limit: cap, used_this_month: used });
      }

      const existing = db.prepare(`SELECT id, created_at FROM proofs WHERE sha256 = ? LIMIT 1`).get(normalized);
      const now = new Date().toISOString();
      const batchId = `api-${Date.now()}`;
      const r = insertProof.run(req.user.id, normalized, ext.value, fname, now, batchId);
      const proofId = r.lastInsertRowid;
      assignPublicCertId(db, proofId);
      bumpUsage.run(req.user.id);
      audit.run(req.user.id, proofId, 'API_PROOF_SUBMIT', JSON.stringify({ api_key_id: req.user.api_key_id, api_key_name: req.user.api_key_name }), now);
      anchoring.kick();

      const created = findById.get(proofId);
      return res.status(201).json({
        ...proofView(created),
        duplicate_of: existing ? { id: existing.id, created_at: existing.created_at } : null,
        already_existed: false,
      });
    } catch (err) {
      console.error('API v1 proof error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  });

  // ---- GET /api/v1/proof/:id ---------------------------------------------------------
  app.get('/api/v1/proof/:id', apiKeyAuth, (req, res) => {
    const proofId = parseInt(req.params.id, 10);
    if (isNaN(proofId)) return res.status(400).json({ error: 'Invalid proof ID.' });
    const proof = findOwn.get(proofId, req.user.id);
    if (!proof) return res.status(404).json({ error: 'Proof not found.' });
    const statuses = normalizeProofStatus(proof);
    return res.json({
      ...proofView(proof),
      size: proof.size, mime: proof.mime,
      review_status: statuses.review_status, evidence_readiness: statuses.evidence_readiness,
      bitcoin_anchor_status: null, btc_merkle_root: null, btc_payment_status: 'NONE', bitcoin_explorer_url: null,
    });
  });

  // ---- GET /api/v1/proof/:id/bundle --------------------------------------------------
  app.get('/api/v1/proof/:id/bundle', apiKeyAuth, (req, res) => {
    const proofId = parseInt(req.params.id, 10);
    if (isNaN(proofId)) return res.status(400).json({ error: 'Invalid proof ID.' });
    const proof = findOwn.get(proofId, req.user.id);
    if (!proof) return res.status(404).json({ error: 'Proof not found.' });
    const out = buildBundle(proof);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (String(req.query.download || '') === '1') res.setHeader('Content-Disposition', `attachment; filename="proofledger-bundle-${proof.id}.json"`);
    return res.send(JSON.stringify(out, null, 2));
  });

  // ---- GET /api/v1/verify (public) ---------------------------------------------------
  const verifyRateLimit = createIpRateLimiter({ windowMs: 60 * 60 * 1000, max: VERIFY_LIMIT_PER_HOUR, message: 'Too many verify requests. Try again later.' });
  function verifyLimitOrKey(req, res, next) {
    if ((req.headers.authorization || '').startsWith('Bearer sk_')) return apiKeyAuth(req, res, next);
    return verifyRateLimit(req, res, next);
  }
  function publicProof(proof) {
    const statuses = normalizeProofStatus(proof);
    return {
      id: proof.id, sha256: proof.sha256, filename: proof.filename, size: proof.size,
      created_at: proof.created_at, polygon_anchored_at: proof.polygon_anchored_at || null,
      status: proof.status, review_status: statuses.review_status, polygon_status: statuses.polygon_status,
      bitcoin_status: statuses.bitcoin_status, evidence_readiness: statuses.evidence_readiness,
      chain_tx: proof.chain_tx || null, chain_name: proof.chain_name || null, bitcoin_txid: null, bitcoin_anchor_status: null,
      public_cert_id: proof.public_cert_id || null, user_email: null, issued_via: proof.issued_via || null,
    };
  }
  app.get('/api/v1/verify', verifyLimitOrKey, (req, res) => {
    const hash = String(req.query.hash || '').trim().toLowerCase();
    if (!hash || !/^[a-f0-9]{64}$/.test(hash)) return res.status(400).json({ error: 'A valid 64-character SHA-256 hash is required as ?hash= parameter.' });
    const proof = findByHash.get(hash);
    if (!proof) return res.json({ found: false, sha256: hash });
    return res.json({
      found: true, proof: publicProof(proof),
      certificate_url: platform.certificateUrl(proof.id), verification_url: platform.verificationUrl(hash),
      explorer_url: proof.chain_tx ? `https://polygonscan.com/tx/${proof.chain_tx}` : null, bitcoin_explorer_url: null,
    });
  });

  // ---- certificate (public, by id or PL- certificate id) ----------------------------
  app.get('/api/cert/:id', verifyRateLimit, (req, res) => {
    const raw = String(req.params.id || '').trim();
    const proof = /^\d+$/.test(raw) ? findById.get(parseInt(raw, 10)) : findByCertId.get(raw.toUpperCase());
    if (!proof) return res.status(404).json({ error: 'Certificate not found.' });
    return res.json({
      ...publicProof(proof),
      certificate_url: platform.certificateUrl(proof.id), verification_url: platform.verificationUrl(proof.sha256),
      explorer_url: proof.chain_tx ? `https://polygonscan.com/tx/${proof.chain_tx}` : null,
      bundle_url: `${PUBLIC_ORIGIN}/api/cert/${proof.id}/bundle`,
    });
  });
  // The bundle of a public certificate: it holds nothing the certificate page does not show.
  app.get('/api/cert/:id/bundle', verifyRateLimit, (req, res) => {
    const raw = String(req.params.id || '').trim();
    const proof = /^\d+$/.test(raw) ? findById.get(parseInt(raw, 10)) : findByCertId.get(raw.toUpperCase());
    if (!proof) return res.status(404).json({ error: 'Certificate not found.' });
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="proofledger-bundle-${proof.id}.json"`);
    return res.send(JSON.stringify(buildBundle(proof), null, 2));
  });
  app.get('/cert/:id', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'cert.html')));
}

module.exports = { mount };
