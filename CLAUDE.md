# encedo-pgp-js — CLAUDE.md

## Purpose
JavaScript library for OpenPGP encryption/decryption/signing using Encedo HEM hardware security module.
Private keys never leave the HSM — only public key export, signatures, and ECDH shared secrets cross the API.

Part of **Encedo Mail** project (Phase 2).

## Project layout
```
src/
  index.js          ← public API re-exports
  keychain.js       ← DESCR schema for PGP keys in HSM + search helpers
  wkd-client.js     ← WKD public key lookup (advanced + direct method)
  wkd-publish.js    ← POST/DELETE keys to encedo-wkd API
  cert-builder.js   ← Build OpenPGP v4 certificate from HSM keys (RFC 4880)
  openpgp-bridge.js ← Encrypt/decrypt via OpenPGP.js + HSM ECDH
test/
  util.js              ← parseArgs, prompt helpers
  test-keygen.js       ← Generate key pair in HSM + build cert
  test-wkd-lookup.js   ← WKD lookup for any email
  test-encrypt.js      ← Encrypt to WKD recipient
  test-decrypt.js      ← Decrypt with HSM key
  test-sign.js         ← Sign with HSM Ed25519 key
../../hem-sdk-js/hem-sdk.js  ← HEM SDK (separate repo, sibling folder)
```

## Dependencies
- `openpgp@^6` — OpenPGP.js for encrypt/decrypt/parsing
- `hem-sdk-js` — Encedo HEM SDK (sibling repo at `../hem-sdk-js/`)

## Key design decisions
- **ES modules** (`"type": "module"`) — all files use `import/export`
- **DESCR schema**: keys in HSM tagged as `PGP:role=self:email=<email>:type=sign|ecdh`
- **cert-builder.js** implements RFC 4880 packet encoding from scratch (no external PGP lib for key building) — allows precise control over what the HSM signs
- **Ed25519 (not Ed25519ph)** used for cert signatures — HSM receives SHA-256 digest of the signing data; GPG verifies with standard Ed25519
- **RFC 6637 §8 KDF** implemented locally (SHA-256 + AES-256 KW) — ECDH shared secret comes from HSM, everything else is local
- **AES-KW unwrap** uses Node.js `id-aes256-wrap` cipher (not WebCrypto) — TODO: replace with pure WebCrypto for browser compatibility
- WKD lookup: advanced method first (`openpgpkey.<domain>`), 5s timeout, fallback to direct

## Phase 2 — completed tests (tested against real HSM at https://my.ence.do)
| Test | Description | Status |
|---|---|---|
| T2.0 | WKD hash + lookup | ✅ |
| T2.1 | HSM keygen + RFC 4880 cert (Ed25519 + X25519) | ✅ |
| T2.3 | Encrypt to WKD recipient key | ✅ |
| T2.4 | Encrypt + decrypt via HSM ECDH | ✅ |
| T2.5 | Ed25519 sign via HSM (verified with Node.js crypto) | ✅ |

## Key bugs fixed during Phase 2
- **cert-builder.js**: RFC 6637 §9 — ECDH subkey body order must be `OID | MPI | KDF params` (KDF params were before MPI)
- **cert-builder.js**: `Ed25519ph` → `Ed25519` for cert signatures (GPG verifies standard Ed25519, not pre-hashed variant)
- **openpgp-bridge.js PKESK**: openpgp.js v6 `pkesk.encrypted = { V, C }` — not an array; `V` is raw MPI bytes (no 2-byte bit count header), `C.data` is wrapped key
- **openpgp-bridge.js AES-KW**: WebCrypto `unwrapKey` cannot unwrap non-standard sizes; replaced with Node.js `id-aes256-wrap`
- **hem-sdk.js searchKeys**: API expects base64-encoded DESCR with `^` prefix regex pattern
- **hem-sdk.js createKeyPair**: missing `mode` field (`ED25519→ExDSA`, `CURVE25519→ECDH`)
- **hem-sdk.js #req()**: Node.js `fetch` (undici) sends chunked encoding → HTTP 411; fixed with `node:https` + explicit `Content-Length`
- **hem-sdk.js agent**: HSM rejects keep-alive connections → `agent: false` (fresh TLS per request)
- **HSM scopes**: `keymgmt:use:<KID>` is per-key — need separate use tokens for sign key and ECDH key

## HSM key types
| OpenPGP role | HEM type    | Algorithm |
|---|---|---|
| Primary signing key | ED25519   | Ed25519 |
| ECDH subkey        | CURVE25519 | X25519  |

## DESCR schema (keychain.js)
```
PGP:role=self:email=jan@firma.pl:type=sign:slot=1   ← own signing key
PGP:role=self:email=jan@firma.pl:type=ecdh:slot=1   ← own ECDH key
PGP:role=peer:email=alice@proton.me:type=ecdh        ← peer key (for encryption)
```
DESCR values are base64-encoded when passed to HEM API (`encodeDescr()`).

## Known limitations / TODOs
- `openpgp-bridge.js` decryption: PKESK packet field access depends on openpgp.js v6 internals — verify with real encrypted mail in T2.4
- Signing in `encryptMessage()` not yet implemented (Phase 3)
- `test-sign.js` outputs raw signature only — full OpenPGP signed message wrapping is Phase 3
- Fingerprint in `test-decrypt.js` requires `--cert` argument — store alongside kid in production

## HEM SDK methods used (hem-sdk.js)
| Method | Used in |
|---|---|
| `hemCheckin()` | all test scripts |
| `authorizePassword(pw, scope)` | all test scripts |
| `createKeyPair(token, label, type, descr)` | test-keygen.js |
| `getPubKey(token, kid)` | cert-builder, test-decrypt |
| `searchKeys(token, descrPattern)` | test-decrypt, test-sign |
| `exdsaSignBytes(token, kid, data)` | cert-builder |
| `ecdh(token, kid, peerPubB64)` | openpgp-bridge (decrypt) |
