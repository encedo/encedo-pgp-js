# encedo-pgp-js

JavaScript library for OpenPGP encryption, decryption, signing and key management via the [Encedo HEM](https://encedo.com) hardware security module.

**Private keys never leave the HSM.** All Ed25519 signing and X25519 ECDH operations are performed on the device. The library works identically in Node.js 20+ and modern browsers.

Part of **Encedo Mail**. See [ARCH.md](../ARCH.md) for full system architecture.

---

## Requirements

- Node.js 20+ **or** modern browser (Chrome/Firefox/Safari/Edge)
- [`openpgp@^6`](https://www.npmjs.com/package/openpgp) — only runtime dependency
- [hem-sdk-js](../hem-sdk-js/) — Encedo HEM client (sibling folder `../hem-sdk-js/`)

---

## Install

```bash
npm install
# hem-sdk-js must be at ../hem-sdk-js/
```

### Build distribution bundles

```bash
npm run build
# dist/encedo-pgp.browser.js   (~413 KB, includes openpgp, uses WebCrypto)
# dist/encedo-pgp.node.js      (~1.2 MB, includes openpgp, uses node:crypto)
```

**Note for webpack consumers:** the browser bundle embeds its own openpgp.js instance.
When webpack processes it, openpgp internals get corrupted. Solution: import only
pure-byte HSM functions from the bundle (`buildHsmSignaturePkt`, `hsmDecryptPkesk`,
`signCleartextMessage`, `buildCertificate`), and do all high-level openpgp API calls
using a separately bundled openpgp instance. See [ARCH.md](../ARCH.md).

---

## Source layout

```
src/
  index.js              ← Public API (re-exports everything)
  keychain.js           ← DESCR schema for keys in HSM + encode/decode/find helpers
  cert-builder.js       ← Build OpenPGP v4 certs from HSM keys; signCleartextMessage()
  openpgp-bridge.js     ← Encrypt/decrypt/sign/verify + new HSM-only exports
  wkd-client.js         ← WKD lookup (advanced + direct method)
  wkd-publish.js        ← POST/DELETE keys to encedo-wkd API
  runtime/
    index.js            ← Auto-detects Node vs Browser
    node-crypto.js      ← sha1, sha256, aes256KeyUnwrap via node:crypto
    browser-crypto.js   ← sha1, sha256, aes256KeyUnwrap via crypto.subtle
dist/
  encedo-pgp.browser.js
  encedo-pgp.node.js
test/
  test-keygen.js        ← Generate key pair + build + export cert
  test-sign.js          ← Sign cleartext message
  test-verify-hsm.js    ← Verify cleartext sig via HSM
  test-encrypt.js       ← Encrypt to WKD recipient
  test-decrypt.js       ← Decrypt with HSM key
  test-wkd-lookup.js    ← WKD lookup
  test-wkd-import.js    ← Import peer key from WKD
```

---

## Public API

### cert-builder.js

| Export | Description |
|--------|-------------|
| `buildCertificate(hem, signToken, kid_sign, kid_ecdh, email, opts?)` | Build OpenPGP v4 binary cert from HSM keys. `opts.ecdhToken`, `opts.timestamp` (iat), `opts.expiryTimestamp`. HSM calls: `getPubKey` ×2, `exdsaSignBytes` ×2. |
| `armorCertificate(cert)` | Binary cert → `-----BEGIN PGP PUBLIC KEY BLOCK-----` |
| `signCleartextMessage(hem, signToken, kid_sign, keyId8, message)` | Sign plaintext → `-----BEGIN PGP SIGNED MESSAGE-----`. HSM calls: `exdsaSignBytes` ×1. |

### openpgp-bridge.js

| Export | Description |
|--------|-------------|
| `buildHsmSignaturePkt(hem, signToken, kid_sign, keyId8, plaintext)` | Build raw Ed25519 OpenPGP sig packet + literal data bytes. Zero openpgp.js calls. HSM: `exdsaSignBytes` ×1. Returns `{ sigPkt: Uint8Array, dataBytes: Uint8Array }`. |
| `hsmDecryptPkesk(ephemeralRaw, wrappedKey, fingerprint, algoId, hem, token, kid_ecdh)` | Decrypt PKESK session key via HSM ECDH + RFC 6637 KDF + AES-KW. HSM: `ecdh` ×1. Returns `{ data: Uint8Array, algoId }`. **Note:** `algoId` returned as number — caller resolves enum name in webpack context. |
| `encryptMessage(plaintext, emails)` | Encrypt to WKD recipients (local WebCrypto). |
| `encryptAndSign(hem, signTok, kid_sign, keyId8, recipients, plaintext)` | Sign+encrypt OPS+LiteralData+Sig inside SEIPD. |
| `decryptMessage(armored, hem, token, kid_ecdh, pubkey32, fingerprint)` | Decrypt via HSM ECDH. |
| `decryptAndVerify(armored, hem, token, kid_ecdh, pubkey32, fp, armoredSenderKey)` | Decrypt + verify embedded sig. |
| `verifySignedMessage(armored, armoredPubKey)` | Verify cleartext sig locally. |
| `importKeyFromWKD(hem, token, email)` | Import Ed25519+X25519 from WKD → HSM. |

### keychain.js

| Export | Description |
|--------|-------------|
| `DESCR` | Object with factory functions: `selfSign(email, iat, exp?)`, `selfEcdh(email, iat, exp?)`, `peerSign(email)`, `peerEcdh(email)` |
| `encodeDescr(plain)` | Base64-encode DESCR string for HSM API |
| `decodeDescr(key)` | Parse base64 DESCR from HSM key object → `{ role, email, keyType, iat, exp }` |
| `findSelfSign(keys, email)` | Find own Ed25519 key for email |
| `findSelfEcdh(keys, email)` | Find own X25519 key for email |
| `findPeerSign(keys, email)` | Find peer Ed25519 key |
| `findPeerEcdh(keys, email)` | Find peer X25519 key |

### wkd-client.js

| Export | Description |
|--------|-------------|
| `lookupKey(email)` | WKD fetch → `Uint8Array \| null`. Advanced method first, falls back to direct. |
| `wkdHash(localPart)` | Z-Base-32(SHA-1(lowercase)) |

### wkd-publish.js

| Export | Description |
|--------|-------------|
| `publishKey(wkdBase, email, cert, authToken?)` | POST binary cert to encedo-wkd |
| `revokeKey(wkdBase, email, authToken?)` | DELETE key from encedo-wkd |

---

## HSM Token Scopes

| Operation | Scope |
|-----------|-------|
| List / search keys | `keymgmt:list` |
| Generate key pair | `keymgmt:gen` |
| Import public key | `keymgmt:imp` |
| Delete key | `keymgmt:del` |
| getPubKey / sign / ECDH | `keymgmt:use:<KID>` (per key) |

---

## DESCR schema

Keys in HSM are tagged by their `description` field (base64-encoded):

| DESCR | Meaning |
|-------|---------|
| `ETSPGP:self,<email>,sign,<iat>[,<exp>]` | Own Ed25519 signing key |
| `ETSPGP:self,<email>,ecdh,<iat>[,<exp>]` | Own X25519 ECDH key |
| `ETSPGP:peer,<email>,sign` | Peer Ed25519 key (for verify) |
| `ETSPGP:peer,<email>,ecdh` | Peer X25519 key (for encrypt) |

`iat` = Unix timestamp from keygen — baked into cert fingerprint so cert is deterministic.

---

## CLI Tests

```bash
node test/test-keygen.js    --hsm https://my.ence.do --email alice@example.com
node test/test-sign.js      --email alice@example.com --message "Hello"
node test/test-encrypt.js   --to alice@example.com --message "Secret"
node test/test-decrypt.js   --email alice@example.com --file /tmp/message.asc
node test/test-wkd-lookup.js --email alice@example.com
node test/test-wkd-import.js --email bob@example.com
```
