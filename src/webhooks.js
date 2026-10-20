// src/webhooks.js — tell a partner's app when its proof is anchored. Same behaviour and
// signature scheme as proofledger.io's webhooks, so one receiver serves both.
//
// How it works:
//   * A partner registers an https URL and gets a secret, shown once.
//   * A sweeper (every SWEEP_MS) finds proofs on accounts that have an endpoint,
//     created after the endpoint was registered, whose Polygon anchor has landed and
//     that have no event yet, and queues one `proof.polygon.anchored` event per
//     endpoint. (Reading the proofs table beats editing the four places that set
//     chain_tx.) `proof.bitcoin.anchored` is a retired name: Bitcoin anchoring ended
//     2026-10-15, so it is still accepted when an endpoint is registered (older clients
//     may send it) but it never fires.
//   * A delivery worker (every DELIVER_MS) POSTs due deliveries with a signature
//     header and retries on a schedule; after MAX_ATTEMPTS the endpoint is turned off
//     and the owner emailed. Delivery is at least once: partners dedupe by event id.
//
// Signature: `ProofLedger-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`
// The partner recomputes it and compares in constant time.
//
// SSRF blocking (a partner URL must never make this server call something on its own
// network, such as the signer box or a metadata service): https only; the host name is
// resolved here and every address checked against the private/loopback/link-local/
// CGNAT/IPv6-private ranges; the request is made to the exact address that was
// checked (DNS rebinding cannot swap it); redirects are not followed; the response
// body is capped and ignored. `isForbiddenAddress` is exported for tests.
'use strict';

const crypto = require('crypto');
const dns = require('dns').promises;
const https = require('https');
const net = require('net');

const SWEEP_MS = 15 * 1000;
const DELIVER_MS = 10 * 1000;
const TIMEOUT_MS = 10 * 1000;
const MAX_BODY_BYTES = 64 * 1024;
const ENDPOINTS_PER_USER = 5;
// Retry schedule in minutes after each failed attempt: 2,676 minutes (about 45 hours,
// almost two days) in total, then off.
// WEBHOOKS_RETRY_MINUTES (comma list) overrides it, for tests only.
const RETRY_MINUTES = (process.env.WEBHOOKS_RETRY_MINUTES || '').trim()
  ? process.env.WEBHOOKS_RETRY_MINUTES.split(',').map(Number)
  : [1, 5, 30, 120, 360, 720, 1440];
const MAX_ATTEMPTS = RETRY_MINUTES.length + 1;
// Tests run a receiver on 127.0.0.1, which the rules below must refuse. This lets a
// test process allow loopback ONLY; it is never set in production.
const TEST_ALLOW_LOOPBACK = process.env.WEBHOOKS_TEST_ALLOW_LOOPBACK === '1';
// The events that fire, and the default for a new endpoint.
const EVENTS = ['proof.polygon.anchored'];
// Retired names: accepted in a registration so older clients are not refused, never fired.
const RETIRED_EVENTS = ['proof.bitcoin.anchored'];
const ACCEPTED_EVENTS = [...EVENTS, ...RETIRED_EVENTS];

// ---------------------------------------------------------------- address rules
function ipv4ToInt(ip) {
  return ip.split('.').reduce((n, o) => (n << 8) + parseInt(o, 10), 0) >>> 0;
}
const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4ToInt(base), bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0]);

function isForbiddenV4(ip) {
  const n = ipv4ToInt(ip);
  return V4_BLOCKED.some(([base, mask]) => (n & mask) === (base & mask));
}

function isForbiddenAddress(ip) {
  if (net.isIPv4(ip)) return isForbiddenV4(ip);
  if (!net.isIPv6(ip)) return true;
  const low = ip.toLowerCase();
  // IPv4 mapped / compatible: judge the embedded v4 address.
  const m = low.match(/^(?:::ffff:|::)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) return isForbiddenV4(m[1]);
  if (low === '::' || low === '::1') return true;
  const first = parseInt(low.split(':')[0] || '0', 16);
  if ((first & 0xfe00) === 0xfc00) return true;   // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return true;   // fe80::/10 link local
  if ((first & 0xff00) === 0xff00) return true;   // ff00::/8 multicast
  if (low.startsWith('2001:db8') || low.startsWith('2001:0db8')) return true; // documentation
  if (low.startsWith('64:ff9b:')) return true;    // NAT64 can map to private v4
  return false;
}

const forbidden = (ip) => isForbiddenAddress(ip) && !(TEST_ALLOW_LOOPBACK && ip === '127.0.0.1');

async function resolveAllowed(hostname) {
  if (net.isIP(hostname)) {
    if (forbidden(hostname)) throw new Error('address not allowed');
    return hostname;
  }
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('host not allowed');
  }
  let addrs;
  if (TEST_ALLOW_LOOPBACK && hostname.endsWith('.proofledger.test')) {
    addrs = [{ address: '127.0.0.1' }];            // test receiver, no DNS
  } else {
    try {
      addrs = await dns.lookup(hostname, { all: true, verbatim: true });
    } catch (_) {
      throw new Error('host does not resolve');
    }
  }
  if (!addrs.length) throw new Error('host does not resolve');
  for (const a of addrs) {
    if (forbidden(a.address)) throw new Error('address not allowed');
  }
  return addrs[0].address;
}

function parseEndpointUrl(raw) {
  let u;
  try { u = new URL(String(raw)); } catch (_) { return { error: 'url must be a valid absolute URL.' }; }
  if (u.protocol !== 'https:') return { error: 'url must use https.' };
  if (u.username || u.password) return { error: 'url must not contain credentials.' };
  if (u.hash) return { error: 'url must not contain a fragment.' };
  if (u.href.length > 2048) return { error: 'url is too long.' };
  return { url: u };
}

// ---------------------------------------------------------------- signing
function sign(secret, timestamp, body) {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}
function signatureHeader(secret, body, timestamp = Math.floor(Date.now() / 1000)) {
  return `t=${timestamp},v1=${sign(secret, timestamp, body)}`;
}
// For partners' reference implementations and our tests.
function verifySignature(secret, header, body, toleranceSeconds = 300, now = Math.floor(Date.now() / 1000)) {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(header || ''));
  if (!m) return false;
  const t = parseInt(m[1], 10);
  if (Math.abs(now - t) > toleranceSeconds) return false;
  const expected = Buffer.from(sign(secret, t, body), 'hex');
  const given = Buffer.from(m[2], 'hex');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

// ---------------------------------------------------------------- one delivery
// Resolves `url`'s host, checks it, and POSTs `body` to that exact address with the
// host name kept for TLS and the Host header. Never follows redirects.
function postSigned(url, address, secret, body, eventId) {
  return new Promise((resolve) => {
    const timestamp = Math.floor(Date.now() / 1000);
    const req = https.request({
      host: address,
      servername: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method: 'POST',
      timeout: TIMEOUT_MS,
      headers: {
        Host: url.host,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'ProofLedger-Webhooks/1',
        'ProofLedger-Signature': signatureHeader(secret, body, timestamp),
        'ProofLedger-Event-Id': String(eventId),
      },
    }, (res) => {
      let got = 0;
      res.on('data', (c) => { got += c.length; if (got > MAX_BODY_BYTES) req.destroy(); });
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode }));
      res.on('error', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode }));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (e) => resolve({ ok: false, status: 0, error: e.message }));
    req.end(body);
  });
}

// ---------------------------------------------------------------- module
function init(deps) {
  const { db, apiKeyAuth, app, proofView, normalizeProofStatus, notifyOwner, log = console } = deps;
  const idempotent = deps.idempotent || ((req, res, next) => next());
  const buildBundle = deps.buildBundle || null;

  db.exec(`
    CREATE TABLE IF NOT EXISTS webhook_endpoints (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL,
      url           TEXT NOT NULL,
      secret        TEXT NOT NULL,
      events        TEXT NOT NULL DEFAULT '["proof.polygon.anchored"]',
      is_active     INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT NOT NULL,
      disabled_at   TEXT,
      disabled_reason TEXT,
      last_success_at TEXT,
      last_failure_at TEXT,
      failure_streak INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_user ON webhook_endpoints(user_id);
    CREATE TABLE IF NOT EXISTS webhook_events (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL,
      proof_id      INTEGER NOT NULL,
      event_type    TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      UNIQUE(proof_id, event_type)
    );
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id      INTEGER NOT NULL,
      endpoint_id   INTEGER NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending',   -- pending | delivered | failed | abandoned
      attempts      INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT NOT NULL,
      last_status_code INTEGER,
      last_error    TEXT,
      delivered_at  TEXT,
      created_at    TEXT NOT NULL,
      UNIQUE(event_id, endpoint_id)
    );
    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries(status, next_attempt_at);
  `);

  const nowIso = () => new Date().toISOString();

  function endpointView(e) {
    let events = EVENTS;
    try { events = JSON.parse(e.events); } catch (_) { /* keep default */ }
    return {
      id: e.id, url: e.url, events, is_active: !!e.is_active, created_at: e.created_at,
      disabled_at: e.disabled_at || null, disabled_reason: e.disabled_reason || null,
      last_success_at: e.last_success_at || null, last_failure_at: e.last_failure_at || null,
      failure_streak: e.failure_streak,
    };
  }

  // The payload carries the proof as the v1 API describes it, plus the proof bundle
  // (verify-proof file format, src/bundle.js) for the chain this event is about, so a
  // partner can store it and verify without us later.
  function eventBody(eventId, eventType, proof) {
    return JSON.stringify({
      id: `evt_${eventId}`,
      type: eventType,
      created_at: nowIso(),
      data: {
        proof: proofView(proof, normalizeProofStatus),
        bundle: buildBundle ? buildBundle(proof) : null,
      },
    });
  }

  // ---- management endpoints --------------------------------------------------
  app.post('/api/v1/webhooks', apiKeyAuth, idempotent, async (req, res) => {
    try {
      const parsed = parseEndpointUrl(req.body && req.body.url);
      if (parsed.error) return res.status(400).json({ error: parsed.error });
      let events = EVENTS;
      if (req.body && req.body.events !== undefined) {
        if (!Array.isArray(req.body.events) || !req.body.events.length || !req.body.events.every((e) => ACCEPTED_EVENTS.includes(e))) {
          return res.status(400).json({ error: `events must be a non-empty array containing ${EVENTS.join(', ')}.` });
        }
        events = [...new Set(req.body.events)];
      }
      try {
        await resolveAllowed(parsed.url.hostname);
      } catch (e) {
        return res.status(400).json({ error: `url rejected: ${e.message}. Webhooks go only to public https addresses.` });
      }
      const active = db.prepare(`SELECT COUNT(*) n FROM webhook_endpoints WHERE user_id = ? AND is_active = 1`).get(req.user.id).n;
      if (active >= ENDPOINTS_PER_USER) {
        return res.status(400).json({ error: `At most ${ENDPOINTS_PER_USER} active webhook endpoints per account. Delete one first.` });
      }
      const secret = 'whsec_' + crypto.randomBytes(24).toString('hex');
      const r = db.prepare(`INSERT INTO webhook_endpoints (user_id, url, secret, events, created_at) VALUES (?, ?, ?, ?, ?)`)
        .run(req.user.id, parsed.url.href, secret, JSON.stringify(events), nowIso());
      const row = db.prepare(`SELECT * FROM webhook_endpoints WHERE id = ?`).get(r.lastInsertRowid);
      return res.status(201).json({ endpoint: endpointView(row), secret, message: 'Save the secret now. It cannot be shown again.' });
    } catch (err) {
      log.error('webhook create error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  });

  app.get('/api/v1/webhooks', apiKeyAuth, (req, res) => {
    const rows = db.prepare(`SELECT * FROM webhook_endpoints WHERE user_id = ? ORDER BY id DESC`).all(req.user.id);
    return res.json({ endpoints: rows.map(endpointView) });
  });

  app.delete('/api/v1/webhooks/:id', apiKeyAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    const row = Number.isInteger(id) && db.prepare(`SELECT * FROM webhook_endpoints WHERE id = ? AND user_id = ?`).get(id, req.user.id);
    if (!row) return res.status(404).json({ error: 'Webhook endpoint not found.' });
    db.prepare(`DELETE FROM webhook_deliveries WHERE endpoint_id = ?`).run(id);
    db.prepare(`DELETE FROM webhook_endpoints WHERE id = ?`).run(id);
    return res.json({ ok: true });
  });

  // Sends a signed `webhook.test` event right now and reports what the endpoint said.
  app.post('/api/v1/webhooks/:id/test', apiKeyAuth, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const row = Number.isInteger(id) && db.prepare(`SELECT * FROM webhook_endpoints WHERE id = ? AND user_id = ?`).get(id, req.user.id);
    if (!row) return res.status(404).json({ error: 'Webhook endpoint not found.' });
    const url = new URL(row.url);
    let address;
    try { address = await resolveAllowed(url.hostname); } catch (e) { return res.status(400).json({ error: `url rejected: ${e.message}` }); }
    const body = JSON.stringify({ id: `evt_test_${Date.now()}`, type: 'webhook.test', created_at: nowIso(), data: { endpoint_id: row.id } });
    const result = await postSigned(url, address, row.secret, body, `test_${Date.now()}`);
    return res.json({ ok: result.ok, status_code: result.status || null, error: result.error || null });
  });

  // ---- sweeper: find anchored proofs that need an event --------------------------
  const findDue = db.prepare(`
    SELECT p.id AS proof_id, p.user_id, 'proof.polygon.anchored' AS event_type
    FROM proofs p
    WHERE p.chain_tx IS NOT NULL AND p.chain_tx != ''
      AND p.polygon_anchored_at IS NOT NULL
      AND EXISTS (SELECT 1 FROM webhook_endpoints e WHERE e.user_id = p.user_id AND e.is_active = 1
                  AND e.created_at <= p.created_at AND e.events LIKE '%proof.polygon.anchored%')
      AND NOT EXISTS (SELECT 1 FROM webhook_events w WHERE w.proof_id = p.id AND w.event_type = 'proof.polygon.anchored')
    LIMIT 500
  `);
  const insertEvent = db.prepare(`INSERT OR IGNORE INTO webhook_events (user_id, proof_id, event_type, created_at) VALUES (?, ?, ?, ?)`);
  const endpointsFor = db.prepare(`SELECT id, events, created_at FROM webhook_endpoints WHERE user_id = ? AND is_active = 1`);
  const insertDelivery = db.prepare(`INSERT OR IGNORE INTO webhook_deliveries (event_id, endpoint_id, next_attempt_at, created_at) VALUES (?, ?, ?, ?)`);
  const proofCreatedAt = db.prepare(`SELECT created_at FROM proofs WHERE id = ?`);

  const sweep = db.transaction(() => {
    const due = findDue.all();
    let queued = 0;
    for (const d of due) {
      const now = nowIso();
      const r = insertEvent.run(d.user_id, d.proof_id, d.event_type, now);
      if (!r.changes) continue;
      const eventId = r.lastInsertRowid;
      const created = proofCreatedAt.get(d.proof_id).created_at;
      for (const e of endpointsFor.all(d.user_id)) {
        if (e.created_at > created) continue;             // registered after the proof: no backfill
        if (!String(e.events).includes(d.event_type)) continue;
        insertDelivery.run(eventId, e.id, now, now);
        queued += 1;
      }
    }
    return queued;
  });

  // ---- delivery worker ------------------------------------------------------------
  const dueDeliveries = db.prepare(`
    SELECT d.id, d.event_id, d.endpoint_id, d.attempts, e.url, e.secret, e.is_active, e.failure_streak,
           ev.event_type, ev.proof_id, ev.user_id
    FROM webhook_deliveries d
    JOIN webhook_endpoints e ON e.id = d.endpoint_id
    JOIN webhook_events ev ON ev.id = d.event_id
    WHERE d.status = 'pending' AND d.next_attempt_at <= ?
    ORDER BY d.next_attempt_at ASC
    LIMIT 50
  `);
  const loadProof = db.prepare(`SELECT * FROM proofs WHERE id = ?`);
  const markDelivered = db.prepare(`UPDATE webhook_deliveries SET status='delivered', attempts=attempts+1, last_status_code=?, last_error=NULL, delivered_at=? WHERE id=?`);
  const markRetry = db.prepare(`UPDATE webhook_deliveries SET status='pending', attempts=attempts+1, last_status_code=?, last_error=?, next_attempt_at=? WHERE id=?`);
  const markAbandoned = db.prepare(`UPDATE webhook_deliveries SET status='abandoned', attempts=attempts+1, last_status_code=?, last_error=? WHERE id=?`);
  const endpointOk = db.prepare(`UPDATE webhook_endpoints SET last_success_at=?, failure_streak=0 WHERE id=?`);
  const endpointFail = db.prepare(`UPDATE webhook_endpoints SET last_failure_at=?, failure_streak=failure_streak+1 WHERE id=?`);
  const endpointOff = db.prepare(`UPDATE webhook_endpoints SET is_active=0, disabled_at=?, disabled_reason=? WHERE id=? AND is_active=1`);
  const abandonRest = db.prepare(`UPDATE webhook_deliveries SET status='abandoned', last_error='endpoint disabled' WHERE endpoint_id=? AND status='pending'`);

  let delivering = false;
  async function deliverDue() {
    if (delivering) return 0;
    delivering = true;
    let sent = 0;
    try {
      const rows = dueDeliveries.all(nowIso());
      for (const d of rows) {
        if (!d.is_active) { markAbandoned.run(null, 'endpoint disabled', d.id); continue; }
        const proof = loadProof.get(d.proof_id);
        if (!proof) { markAbandoned.run(null, 'proof missing', d.id); continue; }
        const body = eventBody(d.event_id, d.event_type, proof);
        const url = new URL(d.url);
        let result;
        try {
          const address = await resolveAllowed(url.hostname);
          result = await postSigned(url, address, d.secret, body, `evt_${d.event_id}`);
        } catch (e) {
          result = { ok: false, status: 0, error: e.message };
        }
        const now = nowIso();
        if (result.ok) {
          markDelivered.run(result.status, now, d.id);
          endpointOk.run(now, d.endpoint_id);
          sent += 1;
          continue;
        }
        endpointFail.run(now, d.endpoint_id);
        const attempt = d.attempts + 1;                    // this one
        const err = (result.error || `HTTP ${result.status}`).slice(0, 200);
        if (attempt >= MAX_ATTEMPTS) {
          markAbandoned.run(result.status || null, err, d.id);
          const streak = db.prepare(`SELECT failure_streak FROM webhook_endpoints WHERE id=?`).get(d.endpoint_id).failure_streak;
          // Every attempt on this endpoint failing for the whole schedule: switch it off.
          if (streak >= MAX_ATTEMPTS) {
            const off = endpointOff.run(now, `No successful delivery after ${MAX_ATTEMPTS} attempts (last: ${err})`, d.endpoint_id);
            if (off.changes) {
              abandonRest.run(d.endpoint_id);
              try { if (notifyOwner) await notifyOwner(d.user_id, d.url, err); } catch (e) { log.error('webhook owner notice failed:', e); }
            }
          }
        } else {
          const next = new Date(Date.now() + RETRY_MINUTES[attempt - 1] * 60 * 1000).toISOString();
          markRetry.run(result.status || null, err, next, d.id);
        }
      }
    } finally {
      delivering = false;
    }
    return sent;
  }

  let timers = [];
  function start() {
    timers.push(setInterval(() => { try { sweep(); } catch (e) { log.error('webhook sweep error:', e); } }, SWEEP_MS));
    timers.push(setInterval(() => { deliverDue().catch((e) => log.error('webhook deliver error:', e)); }, DELIVER_MS));
    timers.forEach((t) => t.unref && t.unref());
  }
  function stop() { timers.forEach(clearInterval); timers = []; }

  return { start, stop, sweep, deliverDue };
}

module.exports = {
  init, isForbiddenAddress, parseEndpointUrl, signatureHeader, verifySignature, sign,
  EVENTS, RETIRED_EVENTS, ACCEPTED_EVENTS, RETRY_MINUTES, MAX_ATTEMPTS, ENDPOINTS_PER_USER,
};
