// src/platform.js — batch submission and lookup, the same shapes as proofledger.io's
// POST /api/v1/proofs/batch and GET /api/v1/proofs.
//
// Rules:
//  * external_id is the caller's own record id, up to 128 characters, unique per account.
//    Resending the same external_id returns the same proof instead of a new one, so a
//    retry never doubles up. It is never shown on a public page.
//  * The whole batch is checked first; if the monthly cap cannot take it, nothing is
//    written and the reply says how many are left.
'use strict';

const { assignPublicCertId } = require('./certId');

const BATCH_MAX = 100;
const EXTERNAL_ID_MAX = 128;
const LIST_MAX = 200;
const HASH_RE = /^[a-fA-F0-9]{64}$/;
const FILENAME_MAX = 500;

const PUBLIC_ORIGIN = String(process.env.PUBLIC_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
const certificateUrl = (id) => `${PUBLIC_ORIGIN}/cert/${id}`;
const verificationUrl = (hash) => `${PUBLIC_ORIGIN}/verify.html?hash=${hash}`;

// Status fields as the v1 API describes them. Bitcoin anchoring is not part of this
// server; the fields stay so clients written for proofledger.io read the same shape.
function normalizeProofStatus(p) {
  const polygonStatus = p.chain_tx ? 'ANCHORED' : 'PENDING';
  return {
    review_status: (p.status || 'UNKNOWN').toUpperCase(),
    polygon_status: polygonStatus,
    bitcoin_status: 'NOT_REQUESTED',
    evidence_readiness: polygonStatus === 'ANCHORED' ? 'READY_POLYGON' : 'PENDING_POLYGON',
  };
}

function proofView(p) {
  const statuses = normalizeProofStatus(p);
  return {
    id: p.id,
    sha256: p.sha256,
    external_id: p.external_id || null,
    filename: p.filename,
    status: p.status === 'APPROVED' ? 'approved' : p.status,
    polygon_status: statuses.polygon_status,
    bitcoin_status: statuses.bitcoin_status,
    created_at: p.created_at,
    polygon_anchored_at: p.polygon_anchored_at || null,
    issued_via: p.issued_via || null,
    chain_tx: p.chain_tx || null,
    chain_name: p.chain_name || null,
    bitcoin_txid: null,
    public_cert_id: p.public_cert_id || null,
    certificate_url: certificateUrl(p.id),
    verification_url: verificationUrl(p.sha256),
    explorer_url: p.chain_tx ? `https://polygonscan.com/tx/${p.chain_tx}` : null,
  };
}

const PROOF_COLS = `id, user_id, sha256, external_id, filename, status, created_at,
  polygon_anchored_at, issued_via, chain_tx, chain_name, public_cert_id`;

function validateExternalId(raw) {
  if (raw === undefined || raw === null || raw === '') return { value: null };
  if (typeof raw !== 'string') return { error: 'external_id must be a string.' };
  if (raw.length > EXTERNAL_ID_MAX) return { error: `external_id must be at most ${EXTERNAL_ID_MAX} characters.` };
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { error: 'external_id must not contain control characters.' };
  return { value: raw };
}

function mount(app, deps) {
  const { db, apiKeyAuth, caps, kickAnchoring } = deps;
  const idempotent = deps.idempotent || ((req, res, next) => next());

  const findByExternalId = db.prepare(`SELECT ${PROOF_COLS} FROM proofs WHERE user_id = ? AND external_id = ? LIMIT 1`);
  const insertProof = db.prepare(`
    INSERT INTO proofs (user_id, sha256, external_id, filename, size, mime, flags_json, status, created_at, creation_method, batch_id)
    VALUES (?, ?, ?, ?, 0, 'application/octet-stream', ?, 'APPROVED', ?, 'api_batch', ?)
  `);
  const bumpUsage = db.prepare(`UPDATE users SET proofs_used_this_month = proofs_used_this_month + ? WHERE id = ?`);
  const audit = db.prepare(`INSERT INTO audits (user_id, proof_id, action, meta_json, created_at) VALUES (?, ?, ?, ?, ?)`);

  // Creates up to BATCH_MAX proofs for `user` and answers { status, body } exactly as the
  // route does, so other callers (not only HTTP) can anchor through the same checks.
  function createBatch(user, items, opts = {}) {
    if (!Array.isArray(items) || items.length === 0) {
      return { status: 400, body: { error: 'Send {"items": [{"sha256": "...", "external_id": "...", "filename": "..."}, ...]} with 1 to ' + BATCH_MAX + ' items.' } };
    }
    if (items.length > BATCH_MAX) return { status: 400, body: { error: `At most ${BATCH_MAX} items per batch.` } };

    const checked = [];
    const seenHashes = new Set();
    const seenIds = new Set();
    let invalid = 0;
    for (let i = 0; i < items.length; i++) {
      const it = items[i] && typeof items[i] === 'object' ? items[i] : {};
      const out = { index: i };
      const hash = typeof it.sha256 === 'string' ? it.sha256.trim().toLowerCase() : '';
      if (!HASH_RE.test(hash)) {
        out.result = 'invalid'; out.error = 'sha256 must be a 64-character hex string.';
      } else {
        const ext = validateExternalId(it.external_id);
        if (ext.error) {
          out.result = 'invalid'; out.error = ext.error;
        } else if (ext.value !== null && seenIds.has(ext.value)) {
          out.result = 'invalid'; out.error = 'external_id repeated within this batch.';
        } else if (seenHashes.has(hash) && ext.value === null) {
          out.result = 'invalid'; out.error = 'sha256 repeated within this batch (give each item an external_id if that is intended).';
        } else {
          out.sha256 = hash;
          out.external_id = ext.value;
          out.filename = String(it.filename || 'api-submission').slice(0, FILENAME_MAX);
          seenHashes.add(hash);
          if (ext.value !== null) seenIds.add(ext.value);
        }
      }
      if (out.result === 'invalid') invalid += 1;
      checked.push(out);
    }

    let toCreate = 0;
    for (const c of checked) {
      if (c.result === 'invalid') continue;
      const existing = c.external_id !== null ? findByExternalId.get(user.id, c.external_id) : null;
      if (existing) { c.result = 'exists'; c.proof = proofView(existing); }
      else { c.result = 'create'; toCreate += 1; }
    }

    const cap = caps.monthlyCap();
    const used = caps.usedThisMonth(user.id);
    const remaining = Number.isFinite(cap) ? Math.max(0, cap - used) : null;
    if (remaining !== null && toCreate > remaining) {
      return { status: 429, body: {
        error: `This batch would create ${toCreate} proofs but only ${remaining} remain in this month's limit (${cap}). Nothing was recorded. ${caps.capHint()}`.trim(),
        monthly_limit: cap, used_this_month: used, remaining,
      } };
    }

    const now = new Date().toISOString();
    const batchId = `api-batch-${Date.now()}`;
    const flagsJson = JSON.stringify({ apiSubmission: true, batch: true, ...(opts.flags || {}) });
    const auditMeta = { api_key_id: user.api_key_id || null, api_key_name: user.api_key_name || null, batch_id: batchId, ...(opts.auditMeta || {}) };
    db.transaction(() => {
      for (const c of checked) {
        if (c.result !== 'create') continue;
        const r = insertProof.run(user.id, c.sha256, c.external_id, c.filename, flagsJson, now, batchId);
        assignPublicCertId(db, r.lastInsertRowid);
        c.proof = proofView({ id: r.lastInsertRowid, sha256: c.sha256, external_id: c.external_id, filename: c.filename,
          status: 'APPROVED', created_at: now, chain_tx: null, chain_name: null,
          public_cert_id: db.prepare('SELECT public_cert_id FROM proofs WHERE id = ?').get(r.lastInsertRowid).public_cert_id });
        c.result = 'created';
        audit.run(user.id, r.lastInsertRowid, 'API_PROOF_SUBMIT', JSON.stringify(auditMeta), now);
      }
      if (toCreate) bumpUsage.run(toCreate, user.id);
    })();
    if (toCreate) kickAnchoring();

    const created = checked.filter((c) => c.result === 'created').length;
    const exists = checked.filter((c) => c.result === 'exists').length;
    return { status: created ? 201 : 200, body: {
      batch_id: created ? batchId : null,
      summary: { received: items.length, created, exists, invalid },
      monthly_limit: Number.isFinite(cap) ? cap : null,
      used_this_month: used + created,
      remaining: remaining === null ? null : Math.max(0, remaining - created),
      items: checked.map((c) => ({ index: c.index, result: c.result, ...(c.error ? { error: c.error } : {}), ...(c.proof ? { proof: c.proof } : {}) })),
    } };
  }

  app.post('/api/v1/proofs/batch', apiKeyAuth, idempotent, (req, res) => {
    try {
      const r = createBatch(req.user, req.body && req.body.items);
      return res.status(r.status).json(r.body);
    } catch (err) {
      console.error('API v1 batch error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  });

  // GET /api/v1/proofs: ?external_id=X one proof or 404; ?anchored_since=<ISO>; ?cursor=<id>&limit=<n>
  app.get('/api/v1/proofs', apiKeyAuth, (req, res) => {
    try {
      const q = req.query || {};
      if (q.external_id !== undefined) {
        const ext = validateExternalId(String(q.external_id));
        if (ext.error || ext.value === null) return res.status(400).json({ error: ext.error || 'external_id is required.' });
        const row = findByExternalId.get(req.user.id, ext.value);
        if (!row) return res.status(404).json({ error: 'No proof with that external_id on this account.' });
        return res.json({ proof: proofView(row) });
      }
      const given = (v) => v !== undefined && String(v).trim() !== '';
      let limit = parseInt(q.limit, 10);
      if (!Number.isInteger(limit) || limit < 1) limit = 50;
      if (limit > LIST_MAX) limit = LIST_MAX;
      const cursor = given(q.cursor) ? parseInt(q.cursor, 10) : null;
      if (given(q.cursor) && (!Number.isInteger(cursor) || cursor < 1)) return res.status(400).json({ error: 'cursor must be a proof id from a previous page.' });
      let since = null;
      if (given(q.anchored_since)) {
        const d = new Date(String(q.anchored_since));
        if (Number.isNaN(d.getTime())) return res.status(400).json({ error: 'anchored_since must be an ISO 8601 time, e.g. 2026-10-14T00:00:00Z.' });
        since = d.toISOString();
      }
      const where = ['user_id = ?']; const args = [req.user.id];
      if (since) { where.push('polygon_anchored_at > ?'); args.push(since); }
      if (cursor) { where.push('id < ?'); args.push(cursor); }
      const rows = db.prepare(`SELECT ${PROOF_COLS} FROM proofs WHERE ${where.join(' AND ')} ORDER BY id DESC LIMIT ?`).all(...args, limit + 1);
      const page = rows.slice(0, limit);
      return res.json({ proofs: page.map(proofView), next_cursor: rows.length > limit ? page[page.length - 1].id : null });
    } catch (err) {
      console.error('API v1 proofs list error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  });

  return { createBatch };
}

module.exports = { mount, proofView, normalizeProofStatus, validateExternalId, certificateUrl, verificationUrl, PUBLIC_ORIGIN, BATCH_MAX, EXTERNAL_ID_MAX, HASH_RE, FILENAME_MAX };
