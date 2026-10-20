// src/bundle.js — a proof bundle: one JSON document with everything needed to verify a
// proof without this server, in the file format the open-source `verify-proof` package
// reads (its top-level fields), plus the record and the anchor details.
'use strict';

const FORMAT = 'proofledger-bundle/1';
const PUBLIC_ORIGIN = String(process.env.PUBLIC_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');

function polygonAnchor(p) {
  const tx = p.chain_tx || null;
  return {
    blockchain: 'polygon',
    network: p.chain_name || null,
    anchored: !!tx,
    tx_id: tx,
    anchored_at: tx ? (p.polygon_anchored_at || null) : null,
    merkle_path: [],
    explorer_url: tx ? `https://polygonscan.com/tx/${tx}` : null,
  };
}

function buildBundle(p) {
  const polygon = polygonAnchor(p);
  const hash = String(p.sha256 || '').toLowerCase();
  return {
    format: FORMAT,
    service: 'proofledger-community',
    generated_at: new Date().toISOString(),

    hash,
    algorithm: 'sha256',
    blockchain: polygon.blockchain,
    tx_id: polygon.tx_id,
    anchored_at: polygon.anchored_at,
    merkle_path: [],
    anchored: polygon.anchored,

    proof_id: p.id,
    external_id: p.external_id || null,
    public_cert_id: p.public_cert_id || null,
    filename: p.filename || null,
    created_at: p.created_at,
    issued_via: p.issued_via || null,
    certificate_url: `${PUBLIC_ORIGIN}/cert/${p.id}`,
    verification_url: `${PUBLIC_ORIGIN}/verify.html?hash=${hash}`,

    anchors: { polygon },

    how_to_verify: [
      'Hash the original file with SHA-256 and compare it with `hash`.',
      'Open `anchors.polygon.explorer_url`; the transaction input data is 0xbf084408 followed by the hash, and the block time is the anchor time.',
      'Offline check: `pip install verify-proof`, then `verify-proof verify <file> --proof bundle.json` (no network call; it uses the top-level fields).',
    ],
  };
}

module.exports = { buildBundle, FORMAT };
