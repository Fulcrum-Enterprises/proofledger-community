// src/db.js — one SQLite file. Tables the proof core needs; the webhook and idempotency
// modules add their own at start.
'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dbPath = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', 'data', 'proofs.db'));
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    email                   TEXT NOT NULL UNIQUE,
    name                    TEXT,
    is_disabled             INTEGER NOT NULL DEFAULT 0,
    proofs_used_this_month  INTEGER NOT NULL DEFAULT 0,
    usage_month_key         TEXT,
    created_at              TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    key_prefix    TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    is_active     INTEGER NOT NULL DEFAULT 1,
    usage_count   INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix);

  CREATE TABLE IF NOT EXISTS proofs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id),
    sha256              TEXT NOT NULL,
    external_id         TEXT,
    filename            TEXT NOT NULL,
    size                INTEGER NOT NULL DEFAULT 0,
    mime                TEXT NOT NULL DEFAULT 'application/octet-stream',
    flags_json          TEXT,
    status              TEXT NOT NULL DEFAULT 'APPROVED',
    created_at          TEXT NOT NULL,
    chain_tx            TEXT,
    chain_name          TEXT,
    anchored_polygon    INTEGER NOT NULL DEFAULT 0,
    polygon_anchored_at TEXT,
    batch_id            TEXT,
    public_cert_id      TEXT,
    creation_method     TEXT NOT NULL DEFAULT 'api',
    issued_via          TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_proofs_sha256 ON proofs (sha256);
  CREATE INDEX IF NOT EXISTS idx_proofs_user ON proofs (user_id, id);
  CREATE INDEX IF NOT EXISTS idx_proofs_pending ON proofs (anchored_polygon, status);
  CREATE INDEX IF NOT EXISTS idx_proofs_cert ON proofs (public_cert_id);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_proofs_user_external ON proofs (user_id, external_id) WHERE external_id IS NOT NULL;

  CREATE TABLE IF NOT EXISTS audits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    proof_id    INTEGER,
    action      TEXT NOT NULL,
    meta_json   TEXT,
    created_at  TEXT NOT NULL
  );
`);

module.exports = { db, dbPath };
