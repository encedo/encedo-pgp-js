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
- **Ed25519ph** signing variant used in cert signatures (pre-hashed: HSM receives SHA-256 digest, not raw data) — avoids large data transfer to/from HSM
- **RFC 6637 §8 KDF** implemented locally (SHA-256 + AES-256 KW) — ECDH shared secret comes from HSM, everything else is local
- WKD lookup: advanced method first (`openpgpkey.<domain>`), 5s timeout, fallback to direct

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
