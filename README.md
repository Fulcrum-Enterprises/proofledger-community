# ProofLedger Community

A self-hostable proof-of-existence server. It records the SHA-256 fingerprint of a file on the Polygon blockchain, issues a certificate and a proof bundle, and speaks the same API as [proofledger.io](https://proofledger.io), so the same clients, the same `verify-proof` tool and the same integrations work against your own server.

A proof shows that a file with that exact fingerprint existed by the anchor time and has not changed since. It does not show who made the file, and it is not a copyright registration. The record is a public Polygon transaction; anyone can check it without this server.

Licence: AGPL-3.0. The hosted edition at proofledger.io adds a managed signer, backups, partner branding, webhooks at scale, the GitHub App, the Zapier, Make and n8n integrations, and support.

## Run it

You need Node 18 or newer, and a Polygon wallet holding a little POL for gas (an anchor costs a fraction of a cent).

```bash
git clone https://github.com/Fulcrum-Enterprises/proofledger-community
cd proofledger-community
npm ci
cp .env.example .env        # set PUBLIC_BASE_URL, POLYGON_RPC_URL and POLYGON_PRIVATE_KEY
npm start
```

Or with Docker: `cp .env.example .env`, edit it, then `docker compose up -d`. The database is one SQLite file in the `proofledger-data` volume. Back it up.

Make an account and a key on the server:

```bash
node src/cli.js user add you@example.com
node src/cli.js key create you@example.com "laptop"
```

The key is printed once. Then:

```bash
curl -X POST http://localhost:3000/api/v1/proof \
  -H "Authorization: Bearer sk_..." -H "Content-Type: application/json" \
  -d '{"sha256": "<64 hex characters>", "filename": "contract.pdf", "external_id": "contract-42"}'
```

Within a minute the proof's `chain_tx` fills in. `GET /api/v1/proof/<id>/bundle` gives you a file you can keep next to the original and check offline years later:

```bash
pip install verify-proof
verify-proof verify contract.pdf --proof bundle.json
```

## How a proof is written

One ordinary Polygon transaction, sent from the configured wallet to its own address, whose input data is the ABI encoding of `submitProof(bytes32)`: the selector `0xbf084408` followed by the 32-byte SHA-256. No contract is involved. Open the transaction on a block explorer: the hash is in the input data, the block time is the anchor time. This is exactly what proofledger.io writes, so a Community proof and a hosted proof look the same on chain.

Anchoring modes (`POLYGON_ANCHORING_MODE`):

- `local`: this process holds `POLYGON_PRIVATE_KEY` and sends through `POLYGON_RPC_URL`. Simplest. Keep the wallet small; it only needs gas money.
- `signer`: a separate machine holds the key and this server POSTs `{sha256Hex}` to `SIGNER_BASE_URL/polygon/submit-proof` with `SIGNER_TOKEN`. Same protocol as proofledger.io's own signer box, for people who do not want a key on a public server.
- `off`: nothing is sent; proofs stay pending. For trying the API only, and the server says so in its log and on `/api/health`.

## API

Same shapes as proofledger.io's v1 API ([reference](https://proofledger.io/api.html)); clients written for one work against the other by changing the base URL.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/proof` | key | Record one hash. `external_id` (your own record id) makes retries safe: the same id returns the same proof. |
| POST | `/api/v1/proofs/batch` | key | Up to 100 hashes in one call, each with its own `external_id`. Checked as a whole first. |
| GET | `/api/v1/proof/:id` | key | One proof, with `polygon_status`, `chain_tx`, `polygon_anchored_at`. |
| GET | `/api/v1/proof/:id/bundle` | key | The proof bundle (`?download=1` as an attachment). |
| GET | `/api/v1/proofs` | key | `?external_id=` one proof; `?anchored_since=<ISO>` what anchored after a time; `?cursor=&limit=` pages. |
| GET | `/api/v1/verify?hash=` | none | Public lookup by hash. Rate limited per IP. |
| GET | `/api/cert/:id` | none | Certificate JSON by proof id or `PL-` certificate id; `/api/cert/:id/bundle` its bundle; `/cert/:id` the page. |
| POST/GET/DELETE | `/api/v1/webhooks` | key | Signed `proof.polygon.anchored` deliveries to an https URL, with retries. `POST /api/v1/webhooks/:id/test` sends a sample. |
| GET | `/api/health` | none | Database, anchoring mode and queue, version. |

Headers: `Idempotency-Key` on the creating POSTs replays a stored answer for 24 hours; every keyed call carries `X-RateLimit-*`; a 429 carries `Retry-After`.

Webhook signature: `ProofLedger-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`. Partner URLs must be https and public: private, loopback and link-local addresses are refused, the host is resolved here and the request pinned to the checked address, redirects are not followed.

Limits (`.env`): `PROOF_MONTHLY_CAP` per account (0 = none), `API_KEY_LIMIT_PER_MINUTE`, `VERIFY_LIMIT_PER_HOUR`.

## Clients and tools

- [`verify-proof`](https://github.com/Fulcrum-Enterprises/verify-proof) (PyPI, npm): offline verification, Python and Node API clients (`base_url` points at your server), an MCP server, agent run receipts.
- The [GitHub Action](https://github.com/marketplace/actions/proofledger-release-timestamp) takes an `api-base` input.
- Anything that speaks the proofledger.io API.

## Pages

`/` explains the server, `/verify.html` hashes a file in the browser (never uploaded) and looks it up, `/cert/<id>` shows a certificate. Minimal by design; put your own front end on the API.

## Operating notes

- Run it behind a TLS-terminating proxy and set `TRUST_PROXY=1` so rate limits see the client address.
- Back up the SQLite file. Losing it loses the record of which hash belongs to which account; the anchors on chain remain.
- The wallet key in `local` mode is a hot key. Fund it for gas only.
- `npm test` runs the suite against a scratch database and a fake signer; `npm run scan` refuses secrets, email addresses and private addresses in the tree.

## Licence

AGPL-3.0-only. If you run a modified version as a service, you must offer its source to the people who use it. ProofLedger is a trademark of ProofLedger LLC; the hosted service at proofledger.io is a separate product.
