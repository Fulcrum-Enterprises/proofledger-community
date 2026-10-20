#!/usr/bin/env node
// scripts/scan.js — refuse to ship a secret. Walks the tree (not node_modules, data, .git)
// and fails on anything that looks like a key, token, private key block, email address
// or private network address. Run before every commit: `npm run scan`.
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['node_modules', '.git', 'data', 'test/tmp']);
const SKIP_FILES = new Set(['package-lock.json', 'LICENSE', 'scan.js']);
const RULES = [
  [/sk_(live|test)_[A-Za-z0-9]{8,}/, 'Stripe key'],
  [/\bsk_[a-f0-9]{48}\b/, 'ProofLedger API key'],
  [/\bwhsec_[A-Za-z0-9]{8,}/, 'webhook secret'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/, 'GitHub token'],
  [/\bghu_[A-Za-z0-9]{20,}/, 'GitHub user token'],
  [/AKIA[0-9A-Z]{16}/, 'AWS key'],
  [/-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/, 'private key block'],
  [/\b0x[a-fA-F0-9]{64}\b/, '32-byte hex that could be a private key'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/, 'email address'],
  [/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/, 'private network address'],
  [/\b(134\.122\.\d{1,3}\.\d{1,3}|143\.198\.\d{1,3}\.\d{1,3})\b/, 'a public server address'],
  [/tailscale|ts\.net|ntfy|bitcoind/i, 'operator infrastructure name'],
];
// Allowed by design: the placeholder in the landing page's curl example and the generic
// address in the example env file.
const ALLOW = [
  /sk_\.\.\./,
  /@example\.com|<email>/,                 // reserved example domain (RFC 2606)
  /\['\d+\.\d+\.\d+\.\d+', \d+\]/,          // the SSRF block list in src/webhooks.js
];

let hits = 0;
function scanFile(file) {
  const rel = path.relative(ROOT, file).replace(/\\/g, '/');
  if (SKIP_FILES.has(path.basename(file))) return;
  const text = fs.readFileSync(file, 'utf8');
  text.split(/\r?\n/).forEach((line, i) => {
    if (ALLOW.some((a) => a.test(line))) return;
    for (const [re, what] of RULES) {
      if (re.test(line)) { hits += 1; console.log(`${rel}:${i + 1}: ${what}: ${line.trim().slice(0, 120)}`); break; }
    }
  });
}
function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const rel = path.relative(ROOT, p).replace(/\\/g, '/');
    if (SKIP_DIRS.has(name) || SKIP_DIRS.has(rel)) continue;
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.(js|mjs|json|md|html|css|yml|yaml|txt|example|sh)$/.test(name) || name.startsWith('.env')) scanFile(p);
  }
}
walk(ROOT);
console.log(hits ? `\n${hits} finding(s). Fix them before committing.` : 'scan: clean');
process.exit(hits ? 1 : 0);
