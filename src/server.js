#!/usr/bin/env node
// src/server.js — ProofLedger Community. One process: HTTP API, static pages, the
// anchoring loop and the webhook workers. Configuration comes from .env (see
// .env.example); the database is one SQLite file.
'use strict';

require('dotenv').config({ quiet: true });
const path = require('path');
const express = require('express');

const { db, dbPath } = require('./db');
const auth = require('./auth').init({ db });
const caps = require('./caps').init({ db });
const chain = require('./chain');
const anchoring = require('./anchoring').init({ db });
const { buildBundle } = require('./bundle');
const idempotent = require('./idempotency').init({ db }).middleware;
const platform = require('./platform');
const core = require('./core');
const webhooks = require('./webhooks');
const { version } = require('../package.json');

const PORT = parseInt(process.env.PORT || '3000', 10);
const startedAt = new Date().toISOString();

const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.json({ limit: '256kb' }));

app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: '5m', index: 'index.html' }));

core.mount(app, {
  db, apiKeyAuth: auth.apiKeyAuth, idempotent, caps, anchoring, buildBundle,
  createIpRateLimiter: auth.createIpRateLimiter, chainInfo: chain.describe, startedAt, version,
});
platform.mount(app, { db, apiKeyAuth: auth.apiKeyAuth, idempotent, caps, kickAnchoring: anchoring.kick });
const hooks = webhooks.init({
  db, app, apiKeyAuth: auth.apiKeyAuth, idempotent, proofView: platform.proofView, normalizeProofStatus: platform.normalizeProofStatus,
  buildBundle,
  notifyOwner: async (userId, url, lastError) => {
    const u = db.prepare(`SELECT email FROM users WHERE id = ?`).get(userId);
    console.warn(`[webhooks] endpoint switched off for ${u ? u.email : 'user ' + userId}: ${url} (last error: ${lastError}). Register it again with POST /api/v1/webhooks.`);
  },
});

app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Body is not valid JSON.' });
  console.error('Unhandled error:', err && err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`ProofLedger Community ${version} listening on http://localhost:${PORT} (public URL ${platform.PUBLIC_ORIGIN}, database ${dbPath})`);
  const c = chain.describe();
  console.log(`[chain] anchoring mode: ${c.mode}${c.mode === 'off' ? ' (nothing will be anchored)' : ''}`);
  anchoring.start();
  if (String(process.env.WEBHOOKS_ENABLED || '1') !== '0') hooks.start();
  else console.log('[webhooks] WEBHOOKS_ENABLED=0: deliveries are not sent (registrations are kept).');
});
