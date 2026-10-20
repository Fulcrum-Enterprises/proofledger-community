// src/anchoring.js — the one loop that sends pending hashes to the chain.
//
// New proofs call kick(); a timer runs every ANCHOR_INTERVAL_MS as well. Runs are
// serialised, so the same hash is never submitted twice at once. After
// MAX_CONSECUTIVE_FAILURES errors in a row the run stops and the next tick retries, so an
// unreachable RPC or signer is not hammered.
'use strict';

const { submitProofToChain, MODE } = require('./chain');

const INTERVAL_MS = Math.max(5000, parseInt(process.env.ANCHOR_INTERVAL_MS || '60000', 10) || 60000);
const BATCH_LIMIT = 200;
const MAX_CONSECUTIVE_FAILURES = 5;

function init({ db }) {
  const pendingStmt = db.prepare(`
    SELECT id, sha256 FROM proofs
    WHERE anchored_polygon = 0 AND (chain_tx IS NULL OR chain_tx = '') AND status = 'APPROVED'
    ORDER BY id ASC LIMIT ${BATCH_LIMIT}
  `);
  const pendingCount = db.prepare(`SELECT COUNT(*) AS n FROM proofs WHERE anchored_polygon = 0 AND status = 'APPROVED'`);
  const markAnchored = db.prepare(`
    UPDATE proofs SET chain_tx = ?, chain_name = ?, anchored_polygon = 1, batch_id = ?,
      polygon_anchored_at = COALESCE(polygon_anchored_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    WHERE id = ?
  `);
  const getFlags = db.prepare(`SELECT flags_json FROM proofs WHERE id = ?`);
  const setFlags = db.prepare(`UPDATE proofs SET flags_json = ? WHERE id = ?`);

  const state = { running: false, rerun: false, lastRunAt: null, lastError: null, anchoredTotal: 0, warnedOff: false };

  async function runOnce() {
    const pending = pendingStmt.all();
    if (!pending.length) return;
    if (MODE === 'off') {
      if (!state.warnedOff) { console.warn(`[anchoring] ${pending.length} proof(s) waiting but POLYGON_ANCHORING_MODE=off: nothing is being anchored.`); state.warnedOff = true; }
      return;
    }
    const batchId = 'POLY-' + new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
    let failures = 0, anchored = 0;
    for (const row of pending) {
      if (failures >= MAX_CONSECUTIVE_FAILURES) { console.warn(`[anchoring] ${failures} failures in a row, stopping this run.`); break; }
      const r = await submitProofToChain(row.sha256);
      if (r && r.txHash) {
        markAnchored.run(r.txHash, r.chainName || 'polygon', batchId, row.id);
        anchored += 1; failures = 0; state.lastError = null;
      } else {
        const error = (r && r.error) || 'noTxHash';
        let flags = {};
        try { flags = JSON.parse((getFlags.get(row.id) || {}).flags_json || '{}') || {}; } catch (_) { flags = {}; }
        flags.chainError = String(error).slice(0, 300);
        setFlags.run(JSON.stringify(flags), row.id);
        failures += 1; state.lastError = String(error).slice(0, 300);
      }
    }
    state.anchoredTotal += anchored;
    console.log(`[anchoring] anchored ${anchored} of ${pending.length} pending proof(s).`);
  }

  async function run() {
    if (state.running) { state.rerun = true; return; }
    state.running = true;
    try { await runOnce(); } catch (e) { console.error('[anchoring] run error:', e.message); state.lastError = e.message; }
    finally {
      state.running = false; state.lastRunAt = new Date().toISOString();
      if (state.rerun) { state.rerun = false; setImmediate(() => run()); }
    }
  }

  function kick() { run(); }

  function start() {
    setInterval(run, INTERVAL_MS).unref?.();
    setTimeout(run, 2000).unref?.();
  }

  function status() {
    return { mode: MODE, pending: pendingCount.get().n, running: state.running, last_run_at: state.lastRunAt, last_error: state.lastError, anchored_since_start: state.anchoredTotal };
  }

  return { kick, start, status, runOnce };
}

module.exports = { init };
