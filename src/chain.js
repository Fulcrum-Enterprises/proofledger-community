// src/chain.js — writing a hash to Polygon.
//
// A ProofLedger anchor is one ordinary transaction whose calldata is the ABI encoding of
// `submitProof(bytes32 hash)`: the 4-byte selector 0xbf084408 followed by the 32-byte
// SHA-256. proofledger.io sends it to the signing wallet's own address (a self-send), so
// no contract is involved and anyone can read the hash straight off the transaction input
// on a block explorer. Verification needs nothing else: the hash is in the input data, the
// block timestamp is the anchor time.
//
// Modes (POLYGON_ANCHORING_MODE):
//   local   this process holds POLYGON_PRIVATE_KEY and sends through POLYGON_RPC_URL
//   signer  a separate box holds the key; POST {sha256Hex} to SIGNER_BASE_URL/polygon/submit-proof
//           with SIGNER_TOKEN, the protocol proofledger.io's own signer speaks
//   off     nothing is sent; proofs stay pending (only for trying the API)
'use strict';

const axios = require('axios');
const { ethers } = require('ethers');

const MODE = String(process.env.POLYGON_ANCHORING_MODE || 'local').toLowerCase();
const SELECTOR = '0xbf084408'; // keccak256("submitProof(bytes32)")[:4]
const CHAIN_NAMES = { 137: 'polygon-mainnet', 80002: 'polygon-amoy' };

let wallet = null;
let provider = null;
let chainNameCache = process.env.CHAIN_NAME || null;

function calldataFor(sha256Hex) {
  return SELECTOR + sha256Hex.toLowerCase();
}

async function localSetup() {
  if (wallet) return;
  const rpc = process.env.POLYGON_RPC_URL;
  const key = process.env.POLYGON_PRIVATE_KEY;
  if (!rpc || !key) throw new Error('POLYGON_RPC_URL and POLYGON_PRIVATE_KEY are required in local mode');
  provider = new ethers.JsonRpcProvider(rpc);
  wallet = new ethers.Wallet(key, provider);
  if (!chainNameCache) {
    const net = await provider.getNetwork();
    chainNameCache = CHAIN_NAMES[Number(net.chainId)] || `chain-${net.chainId}`;
  }
}

async function submitLocal(sha256Hex) {
  await localSetup();
  const to = process.env.ANCHOR_TO || wallet.address;
  const tx = await wallet.sendTransaction({ to, data: calldataFor(sha256Hex) });
  const receipt = await tx.wait();
  if (!receipt || receipt.status !== 1) throw new Error(`transaction ${tx.hash} failed`);
  return { ok: true, txHash: tx.hash, chainName: chainNameCache, error: null };
}

async function submitSigner(sha256Hex) {
  const base = String(process.env.SIGNER_BASE_URL || '').replace(/\/+$/, '');
  const token = process.env.SIGNER_TOKEN;
  if (!base || !token) throw new Error('SIGNER_BASE_URL and SIGNER_TOKEN are required in signer mode');
  const resp = await axios.post(`${base}/polygon/submit-proof`, { sha256Hex }, {
    timeout: Number(process.env.SIGNER_TIMEOUT_MS || 120000),
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Connection: 'close' },
  });
  const data = resp.data || {};
  return {
    ok: Boolean(data.ok ?? true),
    txHash: data.txHash || data.hash || null,
    chainName: data.chainName || chainNameCache || 'polygon',
    error: data.error ? String(data.error) : null,
  };
}

// Returns { ok, txHash, chainName, error }. Never throws; never logs a request object
// (that is how a signer token once ended up in a log file).
async function submitProofToChain(sha256Hex) {
  try {
    if (MODE === 'off') return { ok: false, txHash: null, chainName: null, error: 'anchoring is off (POLYGON_ANCHORING_MODE=off)' };
    if (MODE === 'signer') return await submitSigner(sha256Hex);
    if (MODE === 'local') return await submitLocal(sha256Hex);
    return { ok: false, txHash: null, chainName: null, error: `unknown POLYGON_ANCHORING_MODE "${MODE}"` };
  } catch (err) {
    const status = err && err.response && err.response.status;
    const body = err && err.response && err.response.data;
    const msg = String((err && err.message) || err) + (status ? ` (HTTP ${status})` : '') + (body ? ' body=' + JSON.stringify(body).slice(0, 200) : '');
    console.error('[chain] submit failed:', msg);
    return { ok: false, txHash: null, chainName: chainNameCache, error: msg };
  }
}

function describe() {
  return { mode: MODE, chain: chainNameCache, selector: SELECTOR };
}

module.exports = { submitProofToChain, describe, calldataFor, SELECTOR, MODE };
