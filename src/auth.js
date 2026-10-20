// src/auth.js — API key authentication and the two rate limits.
//
// A key is `sk_` + 48 hex characters, made by `proofledger key create`. The database keeps
// only its SHA-256 and the first 11 characters (for lookup); the key itself is shown once.
'use strict';

const crypto = require('crypto');

const API_KEY_LIMIT_PER_MINUTE = Math.max(1, parseInt(process.env.API_KEY_LIMIT_PER_MINUTE || '120', 10) || 120);
const API_KEY_WINDOW_MS = 60 * 1000;

function init({ db }) {
  const keyBuckets = new Map(); // key id -> { start, count }
  const findKey = db.prepare(`
    SELECT ak.*, u.id AS uid, u.email, u.is_disabled, u.proofs_used_this_month, u.usage_month_key
    FROM api_keys ak JOIN users u ON u.id = ak.user_id
    WHERE ak.key_prefix = ? AND ak.is_active = 1
  `);
  const touchKey = db.prepare(`UPDATE api_keys SET last_used_at = ?, usage_count = usage_count + 1 WHERE id = ?`);

  function applyKeyRateLimit(keyId, res) {
    const t = Date.now();
    let b = keyBuckets.get(keyId);
    if (!b || t - b.start >= API_KEY_WINDOW_MS) { b = { start: t, count: 0 }; keyBuckets.set(keyId, b); }
    b.count += 1;
    const resetAt = Math.ceil((b.start + API_KEY_WINDOW_MS) / 1000);
    const remaining = Math.max(0, API_KEY_LIMIT_PER_MINUTE - b.count);
    res.setHeader('X-RateLimit-Limit', String(API_KEY_LIMIT_PER_MINUTE));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(resetAt));
    if (b.count > API_KEY_LIMIT_PER_MINUTE) {
      const retryAfter = Math.min(60, Math.max(1, resetAt - Math.floor(t / 1000)));
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({ error: `Rate limit exceeded: ${API_KEY_LIMIT_PER_MINUTE} requests per minute per API key. Retry after ${retryAfter} s.`, retry_after: retryAfter });
      return false;
    }
    return true;
  }
  setInterval(() => {
    const t = Date.now();
    for (const [k, b] of keyBuckets) if (t - b.start >= API_KEY_WINDOW_MS) keyBuckets.delete(k);
  }, 5 * 60 * 1000).unref?.();

  function apiKeyAuth(req, res, next) {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer sk_')) {
      return res.status(401).json({ error: 'Send an API key: Authorization: Bearer sk_...' });
    }
    const rawKey = header.slice(7).trim();
    if (!/^sk_[a-f0-9]{48}$/.test(rawKey)) return res.status(401).json({ error: 'Invalid API key.' });
    const row = findKey.get(rawKey.slice(0, 11));
    if (!row) return res.status(401).json({ error: 'Invalid API key.' });
    const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const a = Buffer.from(hash); const b = Buffer.from(String(row.key_hash));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Invalid API key.' });
    if (row.is_disabled) return res.status(403).json({ error: 'Account is disabled.' });
    if (!applyKeyRateLimit(row.id, res)) return;
    touchKey.run(new Date().toISOString(), row.id);
    req.user = {
      id: row.uid, email: row.email, is_disabled: row.is_disabled,
      proofs_used_this_month: row.proofs_used_this_month, usage_month_key: row.usage_month_key,
      api_key_id: row.id, api_key_name: row.name,
    };
    next();
  }

  // Fixed window per client IP, for the endpoints that need no key.
  function createIpRateLimiter({ windowMs, max, message }) {
    const buckets = new Map();
    setInterval(() => {
      const t = Date.now();
      for (const [k, b] of buckets) if (t - b.start > windowMs) buckets.delete(k);
    }, Math.min(windowMs, 5 * 60 * 1000)).unref?.();
    return function ipRateLimiter(req, res, next) {
      const k = String(req.ip || '');
      const t = Date.now();
      let b = buckets.get(k);
      if (!b || t - b.start > windowMs) { b = { start: t, count: 0 }; buckets.set(k, b); }
      b.count += 1;
      if (b.count > max) {
        res.setHeader('Retry-After', String(Math.ceil((b.start + windowMs - t) / 1000)));
        return res.status(429).json({ error: message || 'Too many requests.' });
      }
      next();
    };
  }

  // Generating a key: used by the CLI (and by tests).
  function createKey(userId, name) {
    const rawKey = 'sk_' + crypto.randomBytes(24).toString('hex');
    const prefix = rawKey.slice(0, 11);
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const now = new Date().toISOString();
    const r = db.prepare(`INSERT INTO api_keys (user_id, name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(userId, String(name || 'API key').slice(0, 100), prefix, keyHash, now);
    return { id: r.lastInsertRowid, key: rawKey, prefix, created_at: now };
  }

  return { apiKeyAuth, createIpRateLimiter, createKey, API_KEY_LIMIT_PER_MINUTE };
}

module.exports = { init };
