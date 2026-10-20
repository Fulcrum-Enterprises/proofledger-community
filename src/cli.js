#!/usr/bin/env node
// src/cli.js — accounts and API keys, from the shell on the server.
//
//   proofledger user add <email> [name]       create an account
//   proofledger user list
//   proofledger key create <email> [name]     print a new key once
//   proofledger key list [email]
//   proofledger key revoke <prefix>           prefix = the first 11 characters (sk_ + 8)
//   proofledger stats                         counts, pending anchors
'use strict';

require('dotenv').config({ quiet: true });
const { db, dbPath } = require('./db');
const auth = require('./auth').init({ db });

const [cmd, sub, ...rest] = process.argv.slice(2);
const now = () => new Date().toISOString();
const die = (msg) => { console.error(msg); process.exit(1); };
const userByEmail = (email) => db.prepare(`SELECT * FROM users WHERE email = ?`).get(String(email || '').trim().toLowerCase());

function usage() {
  console.log(`ProofLedger Community (${dbPath})

  user add <email> [name]
  user list
  key create <email> [name]
  key list [email]
  key revoke <prefix>
  stats`);
}

if (cmd === 'user' && sub === 'add') {
  const email = String(rest[0] || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) die('user add: give an email address.');
  if (userByEmail(email)) die(`user add: ${email} already exists.`);
  const r = db.prepare(`INSERT INTO users (email, name, created_at) VALUES (?, ?, ?)`).run(email, rest.slice(1).join(' ') || null, now());
  console.log(`user ${r.lastInsertRowid}: ${email}`);
} else if (cmd === 'user' && sub === 'list') {
  for (const u of db.prepare(`SELECT id, email, name, is_disabled, created_at FROM users ORDER BY id`).all()) {
    console.log(`${u.id}\t${u.email}\t${u.name || ''}\t${u.is_disabled ? 'disabled' : 'active'}\t${u.created_at}`);
  }
} else if (cmd === 'key' && sub === 'create') {
  const u = userByEmail(rest[0]);
  if (!u) die(`key create: no user ${rest[0] || ''}. Create one with: user add <email>`);
  const k = auth.createKey(u.id, rest.slice(1).join(' ') || 'API key');
  console.log(`API key for ${u.email} (shown once, store it now):\n\n  ${k.key}\n\nUse it as: Authorization: Bearer ${k.key}`);
} else if (cmd === 'key' && sub === 'list') {
  const where = rest[0] ? `WHERE u.email = ?` : '';
  const args = rest[0] ? [String(rest[0]).toLowerCase()] : [];
  for (const k of db.prepare(`SELECT k.id, k.key_prefix, k.name, k.is_active, k.usage_count, k.last_used_at, u.email FROM api_keys k JOIN users u ON u.id = k.user_id ${where} ORDER BY k.id`).all(...args)) {
    console.log(`${k.key_prefix}…\t${k.email}\t${k.name}\t${k.is_active ? 'active' : 'revoked'}\tused ${k.usage_count}\tlast ${k.last_used_at || 'never'}`);
  }
} else if (cmd === 'key' && sub === 'revoke') {
  const prefix = String(rest[0] || '').slice(0, 11);
  if (!/^sk_[a-f0-9]{8}$/.test(prefix)) die('key revoke: give the key prefix (sk_ + 8 characters).');
  const r = db.prepare(`UPDATE api_keys SET is_active = 0 WHERE key_prefix = ? AND is_active = 1`).run(prefix);
  console.log(r.changes ? `revoked ${prefix}…` : `no active key starts with ${prefix}`);
} else if (cmd === 'stats') {
  const n = (sql) => db.prepare(sql).get().n;
  console.log(`users ${n('SELECT COUNT(*) n FROM users')}, keys ${n('SELECT COUNT(*) n FROM api_keys WHERE is_active = 1')}, proofs ${n('SELECT COUNT(*) n FROM proofs')}, anchored ${n('SELECT COUNT(*) n FROM proofs WHERE anchored_polygon = 1')}, pending ${n('SELECT COUNT(*) n FROM proofs WHERE anchored_polygon = 0')}`);
} else {
  usage();
  process.exit(cmd ? 1 : 0);
}
