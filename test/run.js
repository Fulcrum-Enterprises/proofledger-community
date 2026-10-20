// test/run.js — starts the server against a scratch database and a fake signer, then
// walks the API: keys, create, read, anchoring, bundle, batch, list, verify, certificate,
// idempotency, the monthly cap, webhook registration rules. `npm test`.
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'plc-test-'));
const SIGNER_PORT = 9876 + Math.floor(Math.random() * 100);
const APP_PORT = 4100 + Math.floor(Math.random() * 500);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = () => crypto.randomBytes(32).toString('hex');
const results = [];
const check = (name, ok, detail) => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== undefined ? '  ' + String(detail).slice(0, 220) : ''}`); };

// ---- fake signer: answers like proofledger.io's signer box ----------------------------
const seen = [];
const signer = http.createServer((req, res) => {
  let body = ''; req.on('data', (c) => { body += c; });
  req.on('end', () => {
    if (req.headers.authorization !== 'Bearer signer-test-token') { res.writeHead(401); return res.end('{"ok":false}'); }
    const { sha256Hex } = JSON.parse(body || '{}');
    seen.push(sha256Hex);
    setTimeout(() => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, txHash: '0x' + sha256Hex, chainName: 'polygon-test' })); }, 20);
  });
});

function call(method, p, body, headers = {}, port = APP_PORT) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path: p, method, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
      let out = ''; res.on('data', (c) => { out += c; });
      res.on('end', () => { try { resolve({ code: res.statusCode, headers: res.headers, json: JSON.parse(out) }); } catch (_) { resolve({ code: res.statusCode, headers: res.headers, text: out }); } });
    });
    req.on('error', reject); if (data) req.write(data); req.end();
  });
}
async function until(fn, ms = 15000, step = 150) { const t0 = Date.now(); let v; while (Date.now() - t0 < ms) { v = await fn(); if (v) return v; await sleep(step); } return fn(); }

function startServer(extraEnv, port) {
  const env = {
    ...process.env, PORT: String(port), DB_PATH: path.join(TMP, `db-${port}.sqlite`), PUBLIC_BASE_URL: `http://127.0.0.1:${port}`,
    POLYGON_ANCHORING_MODE: 'signer', SIGNER_BASE_URL: `http://127.0.0.1:${SIGNER_PORT}`, SIGNER_TOKEN: 'signer-test-token',
    ANCHOR_INTERVAL_MS: '5000', WEBHOOKS_ENABLED: '1', ...extraEnv,
  };
  const proc = spawn(process.execPath, ['src/server.js'], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; proc.stdout.on('data', (d) => { log += d; }); proc.stderr.on('data', (d) => { log += d; });
  return { proc, env, log: () => log };
}
function cli(env, ...args) {
  const r = spawnSync(process.execPath, ['src/cli.js', ...args], { cwd: ROOT, env, encoding: 'utf8' });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

(async () => {
  await new Promise((r) => signer.listen(SIGNER_PORT, '127.0.0.1', r));
  const srv = startServer({}, APP_PORT);
  let up = false;
  for (let i = 0; i < 60 && !up; i++) { await sleep(300); try { const r = await call('GET', '/api/health'); up = r.code === 200; } catch (_) {} }
  if (!up) { console.log('SERVER DID NOT START\n' + srv.log()); process.exit(1); }

  // 1. health
  const h = await call('GET', '/api/health');
  check('health ok, anchoring mode signer', h.json.ok === true && h.json.anchoring.mode === 'signer' && h.json.service === 'proofledger-community', JSON.stringify(h.json).slice(0, 160));

  // 2. CLI: users and keys
  const u1 = cli(srv.env, 'user', 'add', 'dev@example.com', 'Dev One');
  check('cli user add', u1.code === 0 && /user \d+: dev@example\.com/.test(u1.out), u1.out.trim());
  const dup = cli(srv.env, 'user', 'add', 'dev@example.com');
  check('cli user add refuses a duplicate', dup.code === 1, dup.out.trim());
  const k1 = cli(srv.env, 'key', 'create', 'dev@example.com', 'laptop');
  const key1 = (k1.out.match(/sk_[a-f0-9]{48}/) || [])[0];
  check('cli key create prints a key once', !!key1, k1.out.split('\n')[0]);
  cli(srv.env, 'user', 'add', 'other@example.com');
  const key2 = (cli(srv.env, 'key', 'create', 'other@example.com').out.match(/sk_[a-f0-9]{48}/) || [])[0];
  const H1 = { Authorization: `Bearer ${key1}` }, H2 = { Authorization: `Bearer ${key2}` };

  // 3. auth
  const noKey = await call('POST', '/api/v1/proof', { sha256: rnd() });
  check('no key: 401', noKey.code === 401, noKey.code);
  const badKey = await call('POST', '/api/v1/proof', { sha256: rnd() }, { Authorization: 'Bearer sk_' + 'f'.repeat(48) });
  check('unknown key: 401', badKey.code === 401, badKey.code);

  // 4. create
  const fileText = 'hello proofledger community ' + Date.now();
  const filePath = path.join(TMP, 'hello.txt'); fs.writeFileSync(filePath, fileText);
  const fileHash = crypto.createHash('sha256').update(fileText).digest('hex');
  const c1 = await call('POST', '/api/v1/proof', { sha256: fileHash.toUpperCase(), filename: 'hello.txt', external_id: 'doc-1' }, H1);
  check('POST /api/v1/proof 201 with the v1 shape', c1.code === 201 && c1.json.sha256 === fileHash && c1.json.external_id === 'doc-1' && c1.json.status === 'approved' && c1.json.polygon_status === 'PENDING' && /^PL-\d{4}-[0-9A-F]{8}$/.test(c1.json.public_cert_id) && c1.json.certificate_url === `http://127.0.0.1:${APP_PORT}/cert/${c1.json.id}` && c1.json.already_existed === false, JSON.stringify(c1.json).slice(0, 200));
  check('rate limit headers on a keyed call', c1.headers['x-ratelimit-limit'] === '120' && c1.headers['x-ratelimit-remaining'], c1.headers['x-ratelimit-remaining']);
  const again = await call('POST', '/api/v1/proof', { sha256: rnd(), external_id: 'doc-1' }, H1);
  check('same external_id returns the existing proof (200, already_existed)', again.code === 200 && again.json.id === c1.json.id && again.json.already_existed === true, again.code);
  const badHash = await call('POST', '/api/v1/proof', { sha256: 'nope' }, H1);
  check('bad hash 400', badHash.code === 400, badHash.code);
  const badJson = await call('POST', '/api/v1/proof', '{not json', H1);
  check('malformed JSON 400', badJson.code === 400, badJson.code);

  // 5. read + ownership
  const g1 = await call('GET', `/api/v1/proof/${c1.json.id}`, null, H1);
  check('GET /api/v1/proof/:id (owner)', g1.code === 200 && g1.json.sha256 === fileHash && g1.json.bitcoin_status === 'NOT_REQUESTED', g1.code);
  const g2 = await call('GET', `/api/v1/proof/${c1.json.id}`, null, H2);
  check('another account cannot read it (404)', g2.code === 404, g2.code);

  // 6. anchoring through the fake signer
  const anchored = await until(async () => { const r = await call('GET', `/api/v1/proof/${c1.json.id}`, null, H1); return r.json.chain_tx ? r.json : null; }, 20000);
  check('anchored: chain_tx, chain_name, polygon_anchored_at, explorer url', anchored && anchored.chain_tx === '0x' + fileHash && anchored.chain_name === 'polygon-test' && anchored.polygon_anchored_at && anchored.polygon_status === 'ANCHORED' && anchored.explorer_url.includes(anchored.chain_tx), JSON.stringify(anchored).slice(0, 160));
  check('signer received exactly that hash', seen.includes(fileHash), seen.length);

  // 7. bundle
  const b = await call('GET', `/api/v1/proof/${c1.json.id}/bundle`, null, H1);
  check('bundle: verify-proof top-level fields', b.code === 200 && b.json.hash === fileHash && b.json.algorithm === 'sha256' && b.json.blockchain === 'polygon' && b.json.tx_id === '0x' + fileHash && b.json.anchored === true && Array.isArray(b.json.merkle_path) && b.json.anchors.polygon.explorer_url, JSON.stringify(b.json).slice(0, 160));
  fs.writeFileSync(path.join(TMP, 'hello.txt.proof.json'), JSON.stringify(b.json, null, 2));
  // The offline check with the real verify-proof tool: `verify-proof` on PATH (CI installs it
  // with pip), else through uvx, else skipped.
  const bundlePath = path.join(TMP, 'hello.txt.proof.json');
  const candidates = [`verify-proof verify "${filePath}" --proof "${bundlePath}"`, `uvx --from verify-proof verify-proof verify "${filePath}" --proof "${bundlePath}"`];
  let vp = null;
  for (const cmd of candidates) {
    const r = spawnSync(cmd, { encoding: 'utf8', shell: true });
    if (r.status === 0 || (r.status !== 127 && !/not found|not recognized/i.test((r.stderr || '') + (r.stdout || '')))) { vp = r; break; }
  }
  if (!vp) console.log('SKIP  verify-proof not available here');
  else check('verify-proof verifies the file against the bundle offline', vp.status === 0 && /VERIFIED/.test(vp.stdout), (vp.stdout || vp.stderr).trim().slice(0, 160));

  // 8. batch
  const hA = rnd(), hB = rnd();
  const bt = await call('POST', '/api/v1/proofs/batch', { items: [{ sha256: hA, external_id: 'b-1', filename: 'a.bin' }, { sha256: hB }, { sha256: 'bad' }] }, H1);
  check('batch 201: 2 created, 1 invalid', bt.code === 201 && bt.json.summary.created === 2 && bt.json.summary.invalid === 1 && bt.json.items[0].proof.external_id === 'b-1' && bt.json.monthly_limit === null, JSON.stringify(bt.json.summary));
  const bt2 = await call('POST', '/api/v1/proofs/batch', { items: [{ sha256: rnd(), external_id: 'b-1' }] }, H1);
  check('batch re-run with a known external_id: exists, nothing created', bt2.code === 200 && bt2.json.summary.exists === 1 && bt2.json.items[0].proof.sha256 === hA, bt2.code);
  const empty = await call('POST', '/api/v1/proofs/batch', { items: [] }, H1);
  check('empty batch 400', empty.code === 400, empty.code);

  // 9. list + lookup
  await until(async () => { const r = await call('GET', '/api/v1/proofs?limit=50', null, H1); return r.json.proofs.every((p) => p.chain_tx) ? r : null; }, 20000);
  const list = await call('GET', '/api/v1/proofs?limit=2', null, H1);
  check('list newest first, 2 per page, cursor', list.code === 200 && list.json.proofs.length === 2 && list.json.next_cursor, list.json.next_cursor);
  const page2 = await call('GET', `/api/v1/proofs?limit=2&cursor=${list.json.next_cursor}`, null, H1);
  check('second page continues', page2.code === 200 && page2.json.proofs.length >= 1 && page2.json.proofs[0].id < list.json.proofs[1].id, page2.json.proofs.length);
  const byExt = await call('GET', '/api/v1/proofs?external_id=doc-1', null, H1);
  check('lookup by external_id', byExt.code === 200 && byExt.json.proof.id === c1.json.id, byExt.code);
  const otherExt = await call('GET', '/api/v1/proofs?external_id=doc-1', null, H2);
  check('external_id is per account (404 for another key)', otherExt.code === 404, otherExt.code);
  const since = await call('GET', '/api/v1/proofs?anchored_since=2000-01-01T00:00:00Z', null, H1);
  check('anchored_since lists anchored proofs only', since.code === 200 && since.json.proofs.length === 3 && since.json.proofs.every((p) => p.polygon_anchored_at), since.json.proofs.length);

  // 10. public verify + certificate
  const v = await call('GET', `/api/v1/verify?hash=${fileHash}`);
  check('public verify found, no email, certificate link', v.code === 200 && v.json.found === true && v.json.proof.user_email === null && v.json.proof.chain_tx && v.json.certificate_url.endsWith(`/cert/${c1.json.id}`), JSON.stringify(v.json).slice(0, 160));
  const v0 = await call('GET', `/api/v1/verify?hash=${rnd()}`);
  check('public verify not found', v0.code === 200 && v0.json.found === false, v0.code);
  const cert = await call('GET', `/api/cert/${c1.json.public_cert_id}`);
  check('certificate JSON by PL- id', cert.code === 200 && cert.json.id === c1.json.id && cert.json.bundle_url.endsWith(`/api/cert/${c1.json.id}/bundle`), cert.code);
  const certPage = await call('GET', `/cert/${c1.json.id}`);
  check('certificate page served', certPage.code === 200 && /Proof certificate/.test(certPage.text), certPage.code);
  const certBundle = await call('GET', `/api/cert/${c1.json.id}/bundle`);
  check('public bundle by certificate', certBundle.code === 200 && certBundle.json.hash === fileHash, certBundle.code);
  const missing = await call('GET', '/api/cert/PL-2000-DEADBEEF');
  check('unknown certificate 404', missing.code === 404, missing.code);

  // 11. idempotency
  const ik = { ...H1, 'Idempotency-Key': 'idem-' + Date.now() };
  const i1 = await call('POST', '/api/v1/proof', { sha256: rnd(), filename: 'i.bin' }, ik);
  const i2 = await call('POST', '/api/v1/proof', { sha256: i1.json.sha256, filename: 'i.bin' }, ik);
  check('Idempotency-Key replays the stored answer', i1.code === 201 && i2.code === 201 && i2.json.id === i1.json.id && i2.headers['idempotent-replayed'] === 'true', i2.headers['idempotent-replayed']);
  const i3 = await call('POST', '/api/v1/proof', { sha256: rnd(), filename: 'different' }, ik);
  check('same key, different body: 422', i3.code === 422, i3.code);

  // 12. webhooks: registration rules
  const wHttp = await call('POST', '/api/v1/webhooks', { url: 'http://example.com/hook' }, H1);
  check('webhook: http refused', wHttp.code === 400, wHttp.code);
  const wLocal = await call('POST', '/api/v1/webhooks', { url: 'https://127.0.0.1/hook' }, H1);
  check('webhook: loopback refused (SSRF)', wLocal.code === 400, wLocal.code);
  const wOk = await call('POST', '/api/v1/webhooks', { url: 'https://example.com/hook' }, H1);
  check('webhook: https endpoint registered with a secret shown once', wOk.code === 201 && /^whsec_/.test(wOk.json.secret) && wOk.json.endpoint && wOk.json.endpoint.events.includes('proof.polygon.anchored'), JSON.stringify(wOk.json).slice(0, 120));
  const wList = await call('GET', '/api/v1/webhooks', null, H1);
  check('webhook: list without the secret', wList.code === 200 && wList.json.endpoints.length === 1 && !JSON.stringify(wList.json).includes('whsec_'), wList.code);
  const wDel = await call('DELETE', `/api/v1/webhooks/${wOk.json.endpoint.id}`, null, H1);
  check('webhook: delete', wDel.code === 200, wDel.code);

  // 13. key revoke
  const prefix = key1.slice(0, 11);
  const rv = cli(srv.env, 'key', 'revoke', prefix);
  const afterRevoke = await call('GET', `/api/v1/proof/${c1.json.id}`, null, H1);
  check('cli key revoke, then the key is refused', /revoked/.test(rv.out) && afterRevoke.code === 401, afterRevoke.code);
  const stats = cli(srv.env, 'stats');
  check('cli stats', /users 2, keys 1, proofs 4, anchored 4, pending 0/.test(stats.out), stats.out.trim());

  // 14. the monthly cap, on a second server
  const CAP_PORT = APP_PORT + 1;
  const srv2 = startServer({ PROOF_MONTHLY_CAP: '2' }, CAP_PORT);
  let up2 = false;
  for (let i = 0; i < 60 && !up2; i++) { await sleep(300); try { const r = await call('GET', '/api/health', null, {}, CAP_PORT); up2 = r.code === 200; } catch (_) {} }
  cli(srv2.env, 'user', 'add', 'capped@example.com');
  const keyC = (cli(srv2.env, 'key', 'create', 'capped@example.com').out.match(/sk_[a-f0-9]{48}/) || [])[0];
  const HC = { Authorization: `Bearer ${keyC}` };
  const x1 = await call('POST', '/api/v1/proof', { sha256: rnd() }, HC, CAP_PORT);
  const x2 = await call('POST', '/api/v1/proofs/batch', { items: [{ sha256: rnd() }, { sha256: rnd() }] }, HC, CAP_PORT);
  const x3 = await call('POST', '/api/v1/proof', { sha256: rnd() }, HC, CAP_PORT);
  const x4 = await call('POST', '/api/v1/proof', { sha256: rnd() }, HC, CAP_PORT);
  check('cap 2: first ok, batch of 2 refused whole (429, nothing written), second ok, third 429', x1.code === 201 && x2.code === 429 && x2.json.remaining === 1 && x3.code === 201 && x4.code === 429 && x4.json.monthly_limit === 2, `${x1.code} ${x2.code} ${x3.code} ${x4.code}`);
  srv2.proc.kill();

  // 15. off mode warns and anchors nothing
  const OFF_PORT = APP_PORT + 2;
  const srv3 = startServer({ POLYGON_ANCHORING_MODE: 'off', ANCHOR_INTERVAL_MS: '5000' }, OFF_PORT);
  let up3 = false;
  for (let i = 0; i < 60 && !up3; i++) { await sleep(300); try { const r = await call('GET', '/api/health', null, {}, OFF_PORT); up3 = r.code === 200; } catch (_) {} }
  cli(srv3.env, 'user', 'add', 'off@example.com');
  const keyO = (cli(srv3.env, 'key', 'create', 'off@example.com').out.match(/sk_[a-f0-9]{48}/) || [])[0];
  const o1 = await call('POST', '/api/v1/proof', { sha256: rnd() }, { Authorization: `Bearer ${keyO}` }, OFF_PORT);
  await sleep(3000);
  const oh = await call('GET', '/api/health', null, {}, OFF_PORT);
  check('off mode: proof stays pending, health says so', o1.code === 201 && oh.json.anchoring.mode === 'off' && oh.json.anchoring.pending === 1 && /nothing is being anchored/.test(srv3.log()), JSON.stringify(oh.json.anchoring));
  srv3.proc.kill();

  srv.proc.kill(); signer.close();
  const passed = results.filter(Boolean).length;
  console.log(`\n${passed}/${results.length} passed`);
  if (passed !== results.length) console.log('\n--- server log ---\n' + srv.log().slice(-3000));
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
