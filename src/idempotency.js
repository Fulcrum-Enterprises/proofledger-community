'use strict';
// Idempotency-Key (platform plan section 8 "Retries", Phase 2, 2026-10-15).
//
// A partner whose request timed out does not know whether we recorded it. With
// `external_id` a resend of POST /api/v1/proof is already safe; this header makes every
// keyed POST safe the same way, batch and webhook registration included:
//
//   * Send `Idempotency-Key: <anything unique, up to 200 printable ASCII chars>`.
//   * The first request runs normally. Its 2xx response is stored for 24 hours under
//     (account, route, key).
//   * The same key with the same body within 24 hours gets the stored response back,
//     same status, same JSON, plus `Idempotent-Replayed: true`. Nothing runs twice.
//   * The same key with a different body is refused with 422: that is a bug on the
//     caller's side, and silently returning the other request's result would hide it.
//   * While the first request is still running, a duplicate gets 409.
//   * Only 2xx responses are stored. A 4xx (bad hash, cap reached) frees the key, so
//     the caller can fix the request and resend with the same key.
//
// The key is scoped to the account and the route, so two partners (or two routes) using
// the same string never collide. The body fingerprint is a SHA-256 of the JSON with keys
// sorted, so a client that serialises fields in another order still matches. Rate limits
// run before this (in apiKeyAuth), so a refused 429 is never recorded as the key's result.

const crypto = require('crypto');

const KEY_RE = /^[\x21-\x7e]{1,200}$/;
const TTL_MS = 24 * 60 * 60 * 1000;

function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v);
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
}

function fingerprint(body) {
  return crypto.createHash('sha256').update(stableStringify(body)).digest('hex');
}

function init(deps) {
  const { db } = deps;

  db.exec(`
    CREATE TABLE IF NOT EXISTS idempotency_keys (
      user_id      INTEGER NOT NULL,
      route        TEXT NOT NULL,
      key          TEXT NOT NULL,
      request_hash TEXT NOT NULL,
      status       INTEGER,
      body         TEXT,
      created_at   TEXT NOT NULL,
      PRIMARY KEY (user_id, route, key)
    );
  `);

  const get = db.prepare(`SELECT request_hash, status, body, created_at FROM idempotency_keys WHERE user_id = ? AND route = ? AND key = ?`);
  const reserve = db.prepare(`INSERT INTO idempotency_keys (user_id, route, key, request_hash, status, body, created_at) VALUES (?, ?, ?, ?, NULL, NULL, ?)`);
  const finish = db.prepare(`UPDATE idempotency_keys SET status = ?, body = ? WHERE user_id = ? AND route = ? AND key = ?`);
  const release = db.prepare(`DELETE FROM idempotency_keys WHERE user_id = ? AND route = ? AND key = ?`);
  const sweep = db.prepare(`DELETE FROM idempotency_keys WHERE created_at < ?`);

  function sweepNow() {
    return sweep.run(new Date(Date.now() - TTL_MS).toISOString()).changes;
  }
  sweepNow();
  const timer = setInterval(sweepNow, 10 * 60 * 1000);
  if (timer.unref) timer.unref();

  // Route-level middleware, placed after apiKeyAuth on the POSTs that create things.
  function middleware(req, res, next) {
    const raw = req.headers['idempotency-key'];
    if (raw === undefined) return next();
    const key = String(raw);
    if (!KEY_RE.test(key)) {
      return res.status(400).json({ error: 'Idempotency-Key must be 1 to 200 printable ASCII characters with no spaces.' });
    }
    if (!req.user || !req.user.id) return next();

    const userId = req.user.id;
    const route = (req.route && req.route.path) || req.path;
    const hash = fingerprint(req.body === undefined ? null : req.body);

    const row = get.get(userId, route, key);
    if (row) {
      const fresh = new Date(row.created_at).getTime() >= Date.now() - TTL_MS;
      if (fresh && row.request_hash !== hash) {
        return res.status(422).json({ error: 'This Idempotency-Key was already used with a different request body.' });
      }
      if (fresh && row.status === null) {
        return res.status(409).json({ error: 'A request with this Idempotency-Key is still in progress. Retry in a moment.' });
      }
      if (fresh) {
        res.setHeader('Idempotent-Replayed', 'true');
        return res.status(row.status).type('json').send(row.body);
      }
      release.run(userId, route, key); // expired: run again as a new request
    }

    try {
      reserve.run(userId, route, key, hash, new Date().toISOString());
    } catch (e) {
      return res.status(409).json({ error: 'A request with this Idempotency-Key is still in progress. Retry in a moment.' });
    }

    let settled = false;
    const origJson = res.json.bind(res);
    res.json = function (body) {
      if (!settled) {
        settled = true;
        const code = res.statusCode;
        if (code >= 200 && code < 300) finish.run(code, JSON.stringify(body), userId, route, key);
        else release.run(userId, route, key);
      }
      return origJson(body);
    };
    // The handler threw, or answered without res.json: never leave the key reserved.
    res.on('close', () => {
      if (!settled) { settled = true; try { release.run(userId, route, key); } catch (_) {} }
    });
    return next();
  }

  return { middleware, sweepNow, fingerprint };
}

module.exports = { init, stableStringify, fingerprint, KEY_RE, TTL_MS };
