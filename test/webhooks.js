// test/webhooks.js — address rules, signatures, registration, delivery, retry and auto-off,
// against a local https receiver (self-signed certificate made with openssl; the server
// is told to trust it through NODE_EXTRA_CA_CERTS). The delivery part runs with
// WEBHOOKS_TEST_ALLOW_LOOPBACK=1 because the receiver is on 127.0.0.1, which the SSRF
// rules must refuse otherwise; a separate check proves the override is off by default.
'use strict';

const http = require('http'), https = require('https'), crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn, spawnSync, execFileSync } = require('child_process');
const Database = require('better-sqlite3');
const wh = require('../src/webhooks');

const ROOT = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'plc-wh-'));
const SIGNER_PORT = 9700 + Math.floor(Math.random() * 100), APP_PORT = 4700 + Math.floor(Math.random() * 200), HOOK_PORT = 9400 + Math.floor(Math.random() * 90);
const results = [];
const check = (name, ok, detail) => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== undefined ? '  ' + String(detail).slice(0, 200) : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = () => crypto.randomBytes(32).toString('hex');

// ---- unit: address rules and signature (no server needed)
for (const [ip, bad] of [['127.0.0.1', true], ['10.1.2.3', true], ['100.64.0.9', true], ['172.17.0.1', true], ['192.168.1.30', true], ['169.254.169.254', true], ['0.0.0.0', true], // scan:allow
  ['::1', true], ['fd00::1', true], ['fe80::1', true], ['::ffff:10.0.0.1', true], ['::ffff:8.8.8.8', false], ['8.8.8.8', false], ['1.1.1.1', false], ['203.0.113.5', true], ['2606:4700::1111', false]]) { // scan:allow
  check(`address rule ${ip} -> ${bad ? 'blocked' : 'allowed'}`, wh.isForbiddenAddress(ip) === bad);
}
check('url: http rejected', !!wh.parseEndpointUrl('http://example.com/x').error);
check('url: credentials rejected', !!wh.parseEndpointUrl('https://u:p@example.com/x').error);
check('url: https ok', !wh.parseEndpointUrl('https://example.com/hooks?a=1').error);
const sec = 'whsec_' + rnd();
const body = JSON.stringify({ hello: 'world' });
const hdr = wh.signatureHeader(sec, body);
check('signature verifies', wh.verifySignature(sec, hdr, body));
check('signature fails on body change', !wh.verifySignature(sec, hdr, body + ' '));
check('signature fails on wrong secret', !wh.verifySignature('whsec_other', hdr, body));
check('signature fails when 10 min old', !wh.verifySignature(sec, wh.signatureHeader(sec, body, Math.floor(Date.now() / 1000) - 700), body));

// ---- self-signed certificate for the receiver
const keyP = path.join(TMP, 'key.pem'), crtP = path.join(TMP, 'cert.pem');
const openssl = ['openssl', 'C:/Program Files/Git/usr/bin/openssl.exe'].find((p) => { try { execFileSync(p, ['version'], { stdio: 'ignore' }); return true; } catch (_) { return false; } });
if (!openssl) { console.log('SKIP  openssl not found; delivery checks skipped'); const n = results.filter(Boolean).length; console.log(`\n${n}/${results.length} passed`); process.exit(n === results.length ? 0 : 1); }
execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyP, '-out', crtP, '-days', '2', '-subj', '/CN=hooks.proofledger.test', '-addext', 'subjectAltName=DNS:hooks.proofledger.test'], { stdio: 'ignore' });

const received = []; let mode = 'ok';
const hook = https.createServer({ key: fs.readFileSync(keyP), cert: fs.readFileSync(crtP) }, (req, res) => {
  let b = ''; req.on('data', (c) => { b += c; });
  req.on('end', () => {
    received.push({ headers: req.headers, body: b, path: req.url });
    if (mode === 'fail') { res.writeHead(500); return res.end('nope'); }
    res.writeHead(200); res.end('ok');
  });
});

(async () => {
  await new Promise((r) => hook.listen(HOOK_PORT, '127.0.0.1', r));
  const signer = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const { sha256Hex } = JSON.parse(b || '{}');
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true, txHash: '0x' + sha256Hex, chainName: 'polygon-test' })); }); });
  await new Promise((r) => signer.listen(SIGNER_PORT, '127.0.0.1', r));

  const DB = path.join(TMP, 'proofs.db');
  const baseEnv = { ...process.env, PORT: String(APP_PORT), DB_PATH: DB, PUBLIC_BASE_URL: `http://127.0.0.1:${APP_PORT}`,
    POLYGON_ANCHORING_MODE: 'signer', SIGNER_BASE_URL: `http://127.0.0.1:${SIGNER_PORT}`, SIGNER_TOKEN: 'signer-test-token', ANCHOR_INTERVAL_MS: '5000',
    NODE_EXTRA_CA_CERTS: crtP, WEBHOOKS_RETRY_MINUTES: '0.05,0.05,0.05,0.05,0.05,0.05,0.05' };
  async function startApp(extraEnv) {
    const app = spawn(process.execPath, ['src/server.js'], { cwd: ROOT, env: { ...baseEnv, ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'] });
    app.log = ''; app.stdout.on('data', (d) => { app.log += d; }); app.stderr.on('data', (d) => { app.log += d; });
    let up = false;
    for (let i = 0; i < 60 && !up; i++) { await sleep(300); try { const r = await call('GET', '/api/health'); up = r.code === 200; } catch (_) {} }
    if (!up) { console.log('SERVER DID NOT START\n' + app.log.slice(-3000)); process.exit(1); }
    return app;
  }
  function call(method, p, b, headers = {}) {
    return new Promise((resolve, reject) => {
      const data = b ? JSON.stringify(b) : null;
      const req = http.request({ host: '127.0.0.1', port: APP_PORT, path: p, method, headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
        let out = ''; res.on('data', (c) => { out += c; }); res.on('end', () => { try { resolve({ code: res.statusCode, json: JSON.parse(out) }); } catch (_) { resolve({ code: res.statusCode, text: out.slice(0, 300) }); } }); });
      req.on('error', reject); if (data) req.write(data); req.end();
    });
  }

  let app = await startApp({});
  spawnSync(process.execPath, ['src/cli.js', 'user', 'add', 'hooks@example.com'], { cwd: ROOT, env: baseEnv });
  const keyOut = spawnSync(process.execPath, ['src/cli.js', 'key', 'create', 'hooks@example.com'], { cwd: ROOT, env: baseEnv, encoding: 'utf8' }).stdout;
  const rawKey = (keyOut.match(/sk_[a-f0-9]{48}/) || [])[0];
  const H = { Authorization: `Bearer ${rawKey}` };
  const db = new Database(DB); db.pragma('busy_timeout = 5000');
  const userId = db.prepare(`SELECT id FROM users WHERE email = 'hooks@example.com'`).get().id;

  // ---- default server: loopback and private targets refused at registration
  for (const url of [`https://127.0.0.1:${HOOK_PORT}/h`, 'https://10.1.2.3:8787/h', 'https://localhost/h', 'https://100.64.0.9:8080/h', 'http://example.com/h']) { // scan:allow
    const r = await call('POST', '/api/v1/webhooks', { url }, H);
    check(`register ${url} -> 400`, r.code === 400, `${r.code} ${r.json && r.json.error}`);
  }
  const pub = await call('POST', '/api/v1/webhooks', { url: 'https://example.com/hooks' }, H);
  check('register public https -> 201 with secret shown once', pub.code === 201 && /^whsec_/.test(pub.json.secret) && !pub.json.endpoint.secret, pub.code);
  const list = await call('GET', '/api/v1/webhooks', null, H);
  check('list hides secret', list.code === 200 && list.json.endpoints.length === 1 && !('secret' in list.json.endpoints[0]), '');
  const del = await call('DELETE', `/api/v1/webhooks/${pub.json.endpoint.id}`, null, H);
  check('delete -> ok', del.code === 200 && del.json.ok, del.code);
  app.kill(); await sleep(500);

  // ---- test server: loopback allowed so the local receiver can be used
  app = await startApp({ WEBHOOKS_TEST_ALLOW_LOOPBACK: '1' });
  const ep = await call('POST', '/api/v1/webhooks', { url: `https://hooks.proofledger.test:${HOOK_PORT}/anchored` }, H);
  check('register test receiver -> 201', ep.code === 201, `${ep.code} ${ep.json && ep.json.error}`);
  const secret = ep.json.secret, epId = ep.json.endpoint.id;
  const t = await call('POST', `/api/v1/webhooks/${epId}/test`, null, H);
  check('test ping delivered with valid signature', t.code === 200 && t.json.ok && received.length === 1 && wh.verifySignature(secret, received[0].headers['proofledger-signature'], received[0].body), JSON.stringify(t.json));
  check('test ping body type webhook.test', JSON.parse(received[0].body).type === 'webhook.test', '');
  received.length = 0;

  // a proof made BEFORE the endpoint existed must not be notified
  db.prepare(`INSERT INTO proofs (user_id, sha256, filename, status, created_at, chain_tx, chain_name, anchored_polygon, polygon_anchored_at, creation_method) VALUES (?, ?, 'old', 'APPROVED', '2026-01-01T00:00:00.000Z', '0xold', 'polygon-test', 1, '2026-01-01T00:01:00.000Z', 'api')`).run(userId, rnd());
  const b = await call('POST', '/api/v1/proofs/batch', { items: [{ sha256: rnd(), external_id: 'wh-1' }, { sha256: rnd(), external_id: 'wh-2' }] }, H);
  check('batch created 2', b.code === 201 && b.json.summary.created === 2, b.code);
  const t0 = Date.now();
  while (Date.now() - t0 < 60000 && received.length < 2) await sleep(500);
  check('2 anchored events delivered (not the pre-existing proof)', received.length === 2, `got ${received.length} in ${Math.round((Date.now() - t0) / 1000)}s`);
  const evs = received.map((r) => JSON.parse(r.body));
  check('event shape: type, id, data.proof with external_id + chain_tx, data.bundle', evs.every((e) => e.type === 'proof.polygon.anchored' && /^evt_\d+$/.test(e.id) && e.data.proof.external_id && e.data.proof.chain_tx && e.data.bundle && e.data.bundle.hash === e.data.proof.sha256), JSON.stringify(evs[0]).slice(0, 160));
  check('signatures verify', received.every((r) => wh.verifySignature(secret, r.headers['proofledger-signature'], r.body)), '');
  check('event id header matches body id', received.every((r) => r.headers['proofledger-event-id'] === JSON.parse(r.body).id), '');
  check('no delivery for the old proof', !evs.some((e) => e.data.proof.filename === 'old'), '');
  const dl = db.prepare(`SELECT status, attempts FROM webhook_deliveries WHERE endpoint_id = ?`).all(epId);
  check('deliveries marked delivered, 1 attempt each', dl.length === 2 && dl.every((d) => d.status === 'delivered' && d.attempts === 1), JSON.stringify(dl));
  await sleep(16000);
  check('no duplicate deliveries after another sweep', received.length === 2, received.length);

  // ---- failure: receiver returns 500; retries on the shortened schedule, then the endpoint is switched off
  mode = 'fail'; received.length = 0;
  await call('POST', '/api/v1/proof', { sha256: rnd(), external_id: 'wh-fail' }, H);
  const t1 = Date.now();
  while (Date.now() - t1 < 120000) { const e = db.prepare(`SELECT is_active FROM webhook_endpoints WHERE id = ?`).get(epId); if (!e.is_active) break; await sleep(500); }
  const epRow = db.prepare(`SELECT * FROM webhook_endpoints WHERE id = ?`).get(epId);
  const failD = db.prepare(`SELECT status, attempts FROM webhook_deliveries WHERE endpoint_id = ? AND status != 'delivered'`).get(epId);
  check(`failing endpoint retried ${wh.MAX_ATTEMPTS} times then abandoned`, failD && failD.status === 'abandoned' && failD.attempts === wh.MAX_ATTEMPTS, JSON.stringify(failD));
  check('endpoint switched off with a reason', !epRow.is_active && /No successful delivery/.test(epRow.disabled_reason || ''), epRow.disabled_reason);
  check(`receiver saw exactly ${wh.MAX_ATTEMPTS} attempts`, received.length === wh.MAX_ATTEMPTS, received.length);
  check('owner notice written to the log', /endpoint switched off for hooks@example\.com/.test(app.log), '');
  mode = 'ok'; received.length = 0;
  await call('POST', '/api/v1/proof', { sha256: rnd(), external_id: 'wh-after-off' }, H);
  await sleep(20000);
  check('disabled endpoint receives nothing', received.length === 0, received.length);

  app.kill(); signer.close(); hook.close(); db.close();
  const passed = results.filter(Boolean).length;
  console.log(`\n${passed}/${results.length} passed`);
  if (passed !== results.length) console.log('--- server log tail ---\n' + app.log.slice(-3000));
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
