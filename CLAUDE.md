# encedo-pgp-js — CLAUDE.md

## Purpose
JavaScript library for OpenPGP encryption/decryption/signing using Encedo HEM hardware security module.
Private keys never leave the HSM — only public key export, signatures, and ECDH shared secrets cross the API.

Works identically in **Node.js 20+** and **modern browsers** (no bundler required for source use).

Part of **Encedo Mail** project — PGP integration for Carbonio webmail plugin.

## Project layout
```
src/
  index.js          ← public API re-exports (entry point for rollup bundle)
  keychain.js       ← DESCR schema for PGP keys in HSM + encode/decode helpers
  wkd-client.js     ← WKD public key lookup (advanced + direct method), async wkdHash
  wkd-publish.js    ← POST/DELETE keys to encedo-wkd API (server auth required)
  cert-builder.js   ← Build OpenPGP v4 cert from HSM keys; signCleartextMessage()
  openpgp-bridge.js ← Encrypt/decrypt/sign/verify/import via OpenPGP.js + HSM
  runtime/
    index.js        ← Auto-detects Node vs Browser, delegates to implementation
    node-crypto.js  ← sha1, sha256, aes256KeyUnwrap via node:crypto
    browser-crypto.js ← sha1, sha256, aes256KeyUnwrap via crypto.subtle (AES-KW)
dist/
  encedo-pgp.browser.js  ← rollup bundle for browser (413KB, includes openpgp)
  encedo-pgp.node.js     ← rollup bundle for Node.js (1.2MB, includes openpgp)
test/
  util.js              ← parseArgs, prompt helpers
  test-keygen.js       ← Generate key pair in HSM + build+export cert
  test-wkd-lookup.js   ← WKD lookup for any email
  test-wkd-import.js   ← Import peer pubkeys from WKD into HSM (sign+ecdh)
  test-encrypt.js      ← Encrypt to WKD recipient
  test-decrypt.js      ← Decrypt with HSM key (fingerprint from WKD)
  test-sign.js         ← Sign with HSM Ed25519, full OpenPGP cleartext format
  test-verify-hsm.js   ← Verify cleartext signed message via HSM
pgp-test.html          ← Full interactive browser tester
../../hem-sdk-js/hem-sdk.js  ← HEM SDK (separate repo, sibling folder)
```

## Dependencies
- `openpgp@^6` — OpenPGP.js for encrypt/decrypt/parsing
- `hem-sdk-js` — Encedo HEM SDK (sibling repo at `../hem-sdk-js/`)
- **devDependencies**: `rollup`, `@rollup/plugin-node-resolve`, `@rollup/plugin-alias`

## Build
```bash
npm run build   # produces dist/encedo-pgp.browser.js + dist/encedo-pgp.node.js
```
`rollup.config.js` substitutes `runtime/index.js` with the concrete implementation
(browser-crypto or node-crypto) at build time — no dynamic imports in bundles.

## Key design decisions
- **ES modules** (`"type": "module"`) — all files use `import/export`
- **Runtime split**: `src/runtime/index.js` detects `process.versions?.node` and dynamically imports the correct backend. Bundles use static substitution.
- **DESCR schema**: keys in HSM tagged per `keychain.js` — change strings there only
- **Ed25519 (not Ed25519ph)**: HSM receives SHA-256 digest; GPG verifies standard Ed25519
- **RFC 6637 §8 KDF**: ECDH shared secret from HSM, KDF+AES-KW done locally
- **AES-KW unwrap**: Node uses `node:crypto` (id-aes256-wrap); Browser uses native `crypto.subtle.unwrapKey` with `AES-KW` + HMAC target (accepts arbitrary unwrapped key lengths)
- **WKD lookup**: advanced method first (`openpgpkey.<domain>`), 5s timeout, fallback to direct
- **No absolute paths** in any src file

## Public API (src/openpgp-bridge.js + src/cert-builder.js)

| Function | Description |
|---|---|
| `buildCertificate(hem, token, kid_sign, kid_ecdh, email, opts)` | Build OpenPGP v4 cert from HSM keys |
| `armorCertificate(cert)` | Binary cert → armored PGP PUBLIC KEY BLOCK |
| `signCleartextMessage(hem, token, kid_sign, keyId8, message)` | HSM Ed25519 → `-----BEGIN PGP SIGNED MESSAGE-----` |
| `encryptMessage(plaintext, emails)` | Encrypt to WKD recipients (local WebCrypto) |
| `encryptMessageHSM(hem, signTok, ecdhTok, kid_sign, kid_ecdh, email, plaintext)` | Encrypt using cert rebuilt from HSM |
| `decryptMessage(armored, hem, token, kid_ecdh, pubkey32, fingerprint)` | Decrypt via HSM ECDH |
| `decryptAndVerify(armored, hem, token, kid_ecdh, pubkey32, fp, armoredSenderKey)` | Decrypt + verify sig locally (Thunderbird/Proton compat) |
| `decryptAndVerifyHSM(armored, hem, ecdhTok, kid_ecdh, pubkey32, fp, verifyTok, kid_sender)` | Decrypt + verify sig via HSM |
| `encryptAndSign(hem, signTok, kid_sign, keyId8, recipients, plaintext)` | Sign+encrypt in one SEIPD: OPS+LiteralData+Sig (Thunderbird/Proton compat) |
| `verifySignedMessage(armored, armoredPubKey)` | Verify cleartext sig locally |
| `verifySignedMessageHSM(hem, token, kid, armored)` | Verify cleartext sig via HSM |
| `importKeyFromWKD(hem, token, email)` | Import Ed25519+X25519 from WKD → HSM with DESCR tags |

## DESCR schema (keychain.js)
```
ETSPGP:self,<email>,sign,<iat>[,<exp>]  ← own Ed25519 signing key
ETSPGP:self,<email>,ecdh,<iat>[,<exp>]  ← own X25519 ECDH key
ETSPGP:peer,<email>,sign                ← peer Ed25519 (for verify via HSM)
ETSPGP:peer,<email>,ecdh                ← peer X25519 (for encrypt via HSM)
```
`iat` = Unix timestamp from keygen, baked into cert fingerprint/keyId.
All DESCR strings built by `DESCR.*()` helpers — change in `keychain.js` only.
DESCR values are base64-encoded when passed to HEM API (`encodeDescr()`).
Key search: `findSelfSign(keys, email)`, `findSelfEcdh(keys, email)`, `findPeerSign(keys, email)`, `findPeerEcdh(keys, email)` — match any `iat`.
| Operation | Scope |
|---|---|
| List / search keys | `keymgmt:list` |
| Generate key pair | `keymgmt:gen` |
| Import public key | `keymgmt:imp` |
| Sign / verify / ECDH / getPubKey | `keymgmt:use:<KID>` (per key) |

## Known limitations / pending work
- WKD Publish not in browser tester (requires server-side auth — will be done in Carbonio plugin)
- `decryptAndVerifyHSM` for embedded sigs uses `sigPkt.signatureData` (openpgp.js v6 internal) — verify still works but may need adjustment on openpgp.js upgrade
- hem-sdk.js `searchKeys`: offset/limit path params not yet wired (TODO in SDK)

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
