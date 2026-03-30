# encedo-pgp-js

JavaScript library for OpenPGP encryption/decryption/signing via [Encedo HEM](https://encedo.com) hardware security module.
Private keys never leave the HSM.

Part of **Encedo Mail** — Phase 2.

---

## Requirements

- Node.js 20+
- `openpgp@^6` (`npm install`)
- [hem-sdk-js](https://github.com/encedo/hem-sdk-js) cloned as sibling folder (`../hem-sdk-js/`)
- Encedo PPA (USB) or EPA connected and reachable

---

## Install

```bash
git clone https://github.com/encedo/encedo-pgp-js
cd encedo-pgp-js
npm install

# hem-sdk-js must be accessible at ../hem-sdk-js/
# (already cloned as sibling in this workspace)
```

---

## Quick start

### 1. Generate key pair in HSM + build OpenPGP certificate

```bash
node test/test-keygen.js \
  --hsm https://my.ence.do \
  --email jan@pgptest.pl
# Output: ASCII-armored public key cert on stdout
# Stderr: kid_sign, kid_ecdh, fingerprint

# Import into local GPG:
node test/test-keygen.js --hsm https://my.ence.do --email jan@pgptest.pl | gpg --import
```

### 2. Publish key to WKD server

```bash
node test/test-keygen.js --hsm https://my.ence.do --email jan@pgptest.pl > /tmp/pubkey.asc

gpg --dearmor < /tmp/pubkey.asc | base64 -w0 > /tmp/pubkey.b64
curl -X POST http://localhost:8089/api/publish \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"jan@pgptest.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"
```

### 3. Look up a key via WKD

```bash
node test/test-wkd-lookup.js --email alice@proton.me
```

### 4. Encrypt a message

```bash
node test/test-encrypt.js \
  --to alice@proton.me \
  --message "Hello Alice, this is encrypted!"
```

### 5. Decrypt a message

```bash
node test/test-decrypt.js \
  --hsm https://my.ence.do \
  --email jan@pgptest.pl \
  --eml path/to/encrypted.eml \
  --cert /tmp/pubkey.asc
```

---

## DESCR schema (keys in HSM)

Keys are tagged by description field:

| Role | DESCR | Key type |
|------|-------|----------|
| Own signing key | `PGP:role=self:email=<email>:type=sign:slot=1` | ED25519 |
| Own ECDH key    | `PGP:role=self:email=<email>:type=ecdh:slot=1` | CURVE25519 |
| Peer key        | `PGP:role=peer:email=<email>:type=ecdh`         | CURVE25519 (public) |

---

## API

```javascript
import { encryptMessage, decryptMessage } from 'encedo-pgp-js';
import { buildCertificate, armorCertificate } from 'encedo-pgp-js';
import { lookupKey } from 'encedo-pgp-js';
import { publishKey, revokeKey } from 'encedo-pgp-js';
import { DESCR, findOwnKeys } from 'encedo-pgp-js';
```

See [src/index.js](src/index.js) for full export list and individual module files for JSDoc.

---

## End-to-end test (T2.6 from plan)

```
1. node test/test-keygen.js → builds cert
2. Publish cert to encedo-wkd (curl /api/publish)
3. Send from ProtonMail to jan@pgptest.pl
   → ProtonMail auto-encrypts (WKD lookup)
4. Download EML from Carbonio SOAP API
5. node test/test-decrypt.js --eml encrypted.eml
   → plaintext on stdout ✓
```
