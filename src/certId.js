// Public certificate id, e.g. PL-2026-1A2B3C4D: the id the verify page's Proof ID tab looks up.
// Same formula the website upload has used since it was added (server.js makePublicCertId). API,
// batch and no-account proofs never got one, so their certificates said "Not assigned"; since
// 2026-10-17 every creation path assigns it and startup backfills older proofs.
const crypto = require('crypto');

function makePublicCertId(id, sha256, createdAtIso) {
  const d = createdAtIso ? new Date(createdAtIso) : null;
  const year = d && !isNaN(d.getTime()) ? d.getUTCFullYear() : new Date().getUTCFullYear();
  const digest = crypto.createHash('sha256').update(`${id}:${sha256 || ''}:${year}`).digest('hex').toUpperCase();
  return `PL-${year}-${digest.slice(0, 8)}`;
}

function assignPublicCertId(db, id) {
  const row = db.prepare('SELECT id, sha256, created_at, public_cert_id FROM proofs WHERE id = ?').get(id);
  if (!row) return null;
  if (row.public_cert_id) return row.public_cert_id;
  const certId = makePublicCertId(row.id, row.sha256, row.created_at);
  db.prepare('UPDATE proofs SET public_cert_id = ? WHERE id = ? AND public_cert_id IS NULL').run(certId, row.id);
  return certId;
}

function backfillPublicCertIds(db) {
  const rows = db.prepare('SELECT id FROM proofs WHERE public_cert_id IS NULL').all();
  for (const r of rows) assignPublicCertId(db, r.id);
  return rows.length;
}

module.exports = { makePublicCertId, assignPublicCertId, backfillPublicCertIds };
