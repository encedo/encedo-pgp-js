# encedo-pgp-js

JavaScript library for OpenPGP encryption, decryption, signing and key management via the [Encedo HEM](https://encedo.com) hardware security module.

**Private keys never leave the HSM.** All Ed25519 signing and X25519 ECDH operations are performed on the device. The library works identically in Node.js and modern browsers — no bundler required for source use, or use the pre-built bundles in `dist/`.

Part of **Encedo Mail** — PGP integration for Carbonio.

---

## Requirements

- Node.js 20+ **or** a modern browser (Chrome/Firefox/Safari/Edge)
- [`openpgp@^6`](https://www.npmjs.com/package/openpgp) — the only runtime dependency
- [hem-sdk-js](https://github.com/encedo/hem-sdk-js) — Encedo HEM client (sibling folder `../hem-sdk-js/`)
- Encedo PPA (USB) or EPA reachable at a known URL (default: `https://my.ence.do`)

---

## Install

```bash
git clone https://github.com/encedo/encedo-pgp-js
cd encedo-pgp-js
npm install

# hem-sdk-js must be accessible at ../hem-sdk-js/
git clone https://github.com/encedo/hem-sdk-js ../hem-sdk-js
```

### Build distribution bundles (optional)

```bash
npm run build
# Produces:
#   dist/encedo-pgp.browser.js   (413 KB, includes openpgp, uses WebCrypto)
#   dist/encedo-pgp.node.js      (1.2 MB, includes openpgp, uses node:crypto)
```

---

## Architecture

```
your app
  ├── hem-sdk-js/hem-sdk.js          HEM API client (auth, sign, ECDH, key import)
  └── encedo-pgp-js/
        src/
          index.js                   Public API (re-exports everything)
          keychain.js                DESCR schema for keys stored in HSM
          cert-builder.js            Build OpenPGP v4 certificates from HSM keys
          openpgp-bridge.js          Encrypt / decrypt / sign / verify / WKD import
          wkd-client.js              WKD lookup (fetch recipient public key)
          wkd-publish.js             WKD publish / revoke (server-side authorisation needed)
          runtime/
            index.js                 Auto-detects Node vs Browser
            node-crypto.js           SHA-1, SHA-256, AES-KW via node:crypto
            browser-crypto.js        SHA-1, SHA-256, AES-KW via crypto.subtle
```

The runtime facade (`src/runtime/index.js`) selects the correct crypto backend automatically — the same source code runs in both environments.

---

## Key schema (DESCR)

Keys in the HSM are identified by their `description` field (base64-encoded UTF-8 string). The schema is defined in `src/keychain.js`:

| DESCR string | Meaning |
|---|---|
| `PGP:role=self:email=<email>:type=sign:slot=1` | Own Ed25519 signing key |
| `PGP:role=self:email=<email>:type=ecdh:slot=1` | Own X25519 ECDH key |
| `PGP:role=peer:email=<email>:type=sign` | Peer Ed25519 key (imported for verify) |
| `PGP:role=peer:email=<email>:type=ecdh` | Peer X25519 key (imported for encrypt) |

All DESCR strings are built by `DESCR.*()` helpers in `keychain.js` — change them there and nowhere else.

---

## API Reference

### Key generation & export

```js
import { HEM } from '../hem-sdk-js/hem-sdk.js';
import { buildCertificate, armorCertificate } from './src/cert-builder.js';
import { DESCR, encodeDescr } from './src/keychain.js';

const hem = new HEM('https://my.ence.do');
await hem.hemCheckin();
const password = 'your-hsm-password';

// 1. Authorize
const genToken  = await hem.authorizePassword(password, 'keymgmt:gen');
const listToken = await hem.authorizePassword(password, 'keymgmt:list');

// 2. Generate Ed25519 (sign) + X25519 (ecdh) key pair
const { kid: kid_sign } = await hem.createKeyPair(
  genToken, 'alice@example.com', 'ED25519',
  encodeDescr(DESCR.selfSign('alice@example.com'))
);
const { kid: kid_ecdh } = await hem.createKeyPair(
  genToken, 'alice@example.com', 'CURVE25519',
  encodeDescr(DESCR.selfEcdh('alice@example.com'))
);

// 3. Build and export OpenPGP v4 certificate
const signToken = await hem.authorizePassword(password, `keymgmt:use:${kid_sign}`);
const ecdhToken = await hem.authorizePassword(password, `keymgmt:use:${kid_ecdh}`);

const { cert } = await buildCertificate(
  hem, signToken, kid_sign, kid_ecdh, 'alice@example.com', { ecdhToken }
);
const armored = armorCertificate(cert);
// armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
```

---

### Sign a message

```js
import { signCleartextMessage } from './src/cert-builder.js';

// Requires: keymgmt:use:<kid_sign> token
const signed = await signCleartextMessage(
  hem, signToken, kid_sign, keyId8, 'Hello World'
);
// signed = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello World\n..."
```

`keyId8` is the 8-byte OpenPGP key ID (Uint8Array) — obtain it from the WKD cert:
```js
import * as openpgp from 'openpgp';
import { lookupKey } from './src/wkd-client.js';
const keyBytes = await lookupKey('alice@example.com');
const pubKey   = await openpgp.readKey({ binaryKey: keyBytes });
const keyId8   = Uint8Array.from(pubKey.getKeyID().bytes, c => c.charCodeAt(0));
```

---

### Verify a signed message

**Local (openpgp.js):**
```js
import { verifySignedMessage } from './src/openpgp-bridge.js';
const { valid, keyID } = await verifySignedMessage(armoredSigned, armoredPubKey);
```

**Via HSM** (requires the signer's key to be imported — see WKD Import below):
```js
import { verifySignedMessageHSM } from './src/openpgp-bridge.js';
// Requires: keymgmt:use:<kid_sign> token for the peer key
await verifySignedMessageHSM(hem, useToken, kidPeerSign, armoredSigned);
// Throws on invalid signature (HTTP 406 from HSM)
```

---

### Encrypt a message

**To a WKD recipient (local WebCrypto, ephemeral ECDH):**
```js
import { encryptMessage } from './src/openpgp-bridge.js';
const armored = await encryptMessage('Hello!', ['bob@example.com']);
```

**To a recipient whose keys are in the HSM** (cert rebuilt from HSM — no WKD needed):
```js
import { encryptMessageHSM } from './src/openpgp-bridge.js';
// Requires: keymgmt:use:<kid_sign> + keymgmt:use:<kid_ecdh> tokens for recipient's keys
const armored = await encryptMessageHSM(
  hem, signToken, ecdhToken, kid_sign, kid_ecdh, 'bob@example.com', 'Hello!'
);
```

---

### Decrypt a message

```js
import { decryptMessage } from './src/openpgp-bridge.js';

// fingerprint = 20-byte SHA-1 fingerprint of the X25519 subkey (from WKD cert)
const plaintext = await decryptMessage(
  armoredMessage, hem, ecdhToken, kid_ecdh, pubkey32, fingerprint
);
```

Get `pubkey32` and `fingerprint` from WKD:
```js
import * as openpgp from 'openpgp';
import { lookupKey } from './src/wkd-client.js';
const keyBytes   = await lookupKey('alice@example.com');
const key        = await openpgp.readKey({ binaryKey: keyBytes });
const pubkey32   = Uint8Array.from(atob(pubInfo.pubkey), c => c.charCodeAt(0));
const fingerprint = Uint8Array.from(key.getSubkeys()[0].getFingerprint().match(/.{2}/g)
  .map(b => parseInt(b, 16)));
```

---

### Import peer key from WKD

```js
import { importKeyFromWKD } from './src/openpgp-bridge.js';
// Requires: keymgmt:imp token
const impToken = await hem.authorizePassword(password, 'keymgmt:imp');
const { kidSign, kidEcdh } = await importKeyFromWKD(hem, impToken, 'bob@example.com');
// Both keys stored in HSM with DESCR.peerSign / DESCR.peerEcdh tags
```

---

### WKD Lookup

```js
import { lookupKey } from './src/wkd-client.js';
const keyBytes = await lookupKey('alice@example.com'); // Uint8Array or null
```

---

## Browser usage

```html
<script type="importmap">
  { "imports": { "openpgp": "https://unpkg.com/openpgp@6/dist/openpgp.min.mjs" } }
</script>
<script type="module">
  import { HEM } from '../../hem-sdk-js/hem-sdk.js';
  import { signCleartextMessage } from './src/cert-builder.js';
  // OR from pre-built bundle (no importmap needed):
  // import { signCleartextMessage } from './dist/encedo-pgp.browser.js';
</script>
```

See `pgp-test.html` for a complete interactive browser tester.

---

## CLI Tests

```bash
# Generate keys
node test/test-keygen.js --hsm https://my.ence.do --email alice@example.com

# Sign
node test/test-sign.js --email alice@example.com --message "Hello"

# Verify via HSM
node test/test-sign.js --email alice@example.com --message "Hello" 2>/dev/null \
  | node test/test-verify-hsm.js --email alice@example.com

# Encrypt
node test/test-encrypt.js --to alice@example.com --message "Secret"

# Decrypt
node test/test-decrypt.js --email alice@example.com --file /tmp/message.asc

# WKD lookup
node test/test-wkd-lookup.js --email alice@example.com

# Import peer key from WKD
node test/test-wkd-import.js --email bob@example.com
```

---

## HSM Token Scopes Required

| Operation | Scope |
|---|---|
| List / search keys | `keymgmt:list` |
| Generate key pair | `keymgmt:gen` |
| Import public key | `keymgmt:imp` |
| Sign / verify / ECDH | `keymgmt:use:<KID>` |

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
