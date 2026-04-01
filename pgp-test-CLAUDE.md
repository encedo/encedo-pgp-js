# encedo-pgp-js — Browser Test Page
## Implementation Notes for VSCode

---

## Environment

- File: `pgp-test.html` — standalone, no build step
- Server: `npx http-server . -p 8080` (required for ES modules + WebCrypto)
- Browser: Chrome / Firefox (WebCrypto.subtle available on localhost)
- HSM: `https://my.ence.do` (HTTPS — no mixed content issues)
- CORS: already configured on PPA/EPA

---

## Module Structure

```
encedo-pgp-js/
├── pgp-test.html           <- UI (done)
├── src/
│   ├── index.js            <- public API export
│   ├── hem-client.js       <- HEM REST wrapper
│   ├── openpgp-bridge.js   <- OpenPGP.js v6 + custom ECDH backend
│   ├── cert-builder.js     <- builds OpenPGP certificate from HSM keys
│   ├── wkd-client.js       <- WKD lookup (advanced + direct method)
│   ├── wkd-publish.js      <- POST pubkey to encedo-wkd server
│   └── keychain.js         <- DESCR schema, key search, import
└── test/
    └── pgp-test.js         <- UI logic (wires HTML to src/)
```

Import in pgp-test.html:
```html
<script type="module" src="test/pgp-test.js"></script>
```

---

## HEM REST — Key Facts

- Base URL: `https://my.ence.do` (configurable in UI)
- Auth: `POST /api/auth { password }` -> Bearer token
- Token: kept in memory only (never localStorage)
- All requests: `Authorization: Bearer <token>`

### Endpoints used

| Operation    | Method | Path                    | Body / Params                        |
|--------------|--------|-------------------------|--------------------------------------|
| Auth         | POST   | `/api/auth`             | `{ password }`                       |
| Key search   | POST   | `/api/key/search`       | `{ prefix, prefix_match: true }`     |
| Key generate | POST   | `/api/key/generate`     | `{ algo, label, descr }`             |
| Key export   | GET    | `/api/key/{kid}/export` | —                                    |
| ECDH         | POST   | `/api/ecdh`             | `{ kid, pubkey: <base64> }`          |
| Sign (EdDSA) | POST   | `/api/exdsa_sign`       | `{ kid, data: <base64> }`            |

### Key Search prefix rules

- Minimum 6 characters required for prefix_match
- Use `"PGP:ro"` to find all PGP keys
- Use `"PGP:role=self:"` for own keys (sign + ecdh)
- Use `"PGP:role=peer:"` for keychain (others' pubkeys)

---

## DESCR Schema

```
Own keys (private — generated in HSM):
  PGP:role=self:email=user@domain.tld:type=sign:slot=1   <- Ed25519 master key
  PGP:role=self:email=user@domain.tld:type=ecdh:slot=1   <- X25519 encryption subkey

Peer keys (public — imported to HSM keychain):
  PGP:role=peer:email=alice@domain.tld:type=sign         <- Ed25519 pubkey
  PGP:role=peer:email=alice@domain.tld:type=ecdh         <- X25519 pubkey
```

---

## Section: Auth

```
Input:  hsmUrl, password
Action: POST /api/auth { password }
Store:  token in memory (module-level variable)
Output: session info (expiry, device info)
UI:     statusDot -> green, authBadge -> CONNECTED
```

---

## Section: Generate Keypair

```
Input:  email, slot (default 1)
Action:
  1. POST /api/key/generate { algo: "ed25519", label: email,
        descr: "PGP:role=self:email={email}:type=sign:slot={slot}" }
     -> kid_sign

  2. POST /api/key/generate { algo: "x25519", label: email,
        descr: "PGP:role=self:email={email}:type=ecdh:slot={slot}" }
     -> kid_ecdh

  3. cert-builder.js:
     - GET /api/key/{kid_sign}/export -> Ed25519 pubkey bytes
     - GET /api/key/{kid_ecdh}/export -> X25519 pubkey bytes
     - build OpenPGP UID packet (email)
     - build Master Key packet (Ed25519)
     - build Subkey packet (X25519)
     - POST /api/exdsa_sign (kid_sign, self-sig payload) -> sig1
     - POST /api/exdsa_sign (kid_sign, subkey binding sig) -> sig2
     - assemble certificate

Output: ASCII-armored OpenPGP public key certificate
Buttons: Copy, Download as .asc
```

---

## Section: Key List

```
Action: POST /api/key/search { prefix: "PGP:ro", prefix_match: true }
Output: list of key items showing:
  - algo tag (Ed25519 / X25519)
  - DESCR field
  - kid (truncated)
Refresh button: re-runs search
```

---

## Section: Export Public Key

```
Input:  email or kid
Action:
  - if email: search by "PGP:role=self:email={email}:type=sign"
              + "PGP:role=self:email={email}:type=ecdh"
  - if kid: direct export
  - cert-builder.js: rebuild armored certificate
Output: ASCII-armored public key
Buttons: Copy, Download .asc
```

---

## Section: Sign

```
Input:  signing key (email or kid_sign), message text
Action:
  1. if email: resolve kid_sign via key search
  2. openpgp.sign({ message, signingKeys: proxyKey })
     proxyKey.sign = async (hash) =>
       POST /api/exdsa_sign { kid: kid_sign, data: base64(hash) }
Output: armored OpenPGP signed message (cleartext + signature)
Note:   SHA-512 computed locally by OpenPGP.js, only hash goes to HSM
```

---

## Section: Verify

```
Input:  armored signed message, optional armored pubkey
Action:
  - if no pubkey: look in HSM keychain (search peer keys)
  - openpgp.verify({ message, verificationKeys: pubkey })
  - 100% local WebCrypto — HSM not involved
Output: VALID / INVALID + fingerprint + signing date
```

---

## Section: Encrypt

```
Input:  recipient email or pubkey (armored), message, optional sign checkbox
Action:
  - if email and no pubkey: WKD lookup first
  - openpgp.encrypt({ message, encryptionKeys: recipientPubkey })
  - 100% local WebCrypto — HSM not involved
  - if sign checkbox: also call exdsa_sign via HSM proxy key
Output: armored PGP message (BEGIN PGP MESSAGE)
Note:   ephemeral X25519 keypair generated locally in WebCrypto
```

---

## Section: Decrypt

```
Input:  decryption key (email or kid_ecdh), armored PGP message
Action:
  1. if email: resolve kid_ecdh via key search
  2. openpgp.decrypt({ message, decryptionKeys: proxyKey })
     proxyKey.decrypt = async (sessionKeyAlgo, { ephemeralKey, wrappedKey }) =>
       a. POST /api/ecdh { kid: kid_ecdh, pubkey: base64(ephemeralKey) }
          -> shared_secret
       b. OpenPGP KDF locally (SHA-256 + params per RFC 4880 §13.5)
          -> wrapping_key
       c. AES Key Unwrap locally (RFC 3394)
          -> session_key (CEK)
       (OpenPGP.js then decrypts body with session_key)
Output: plaintext message
Note:   private key NEVER leaves HSM — only ECDH shared secret returned
```

---

## Section: WKD Lookup / Publish

### Lookup
```
Input:  email address
Action:
  1. compute hash: ZBase32(SHA1(localPart.toLowerCase()))
  2. try Advanced method:
     GET https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={local}
  3. fallback Direct method:
     GET https://{domain}/.well-known/openpgpkey/hu/{hash}?l={local}
  4. parse OpenPGP key packet
  5. verify UID contains email
Output: armored pubkey + fingerprint
Button: "Import to HSM Keychain"
  -> POST /api/key/import with DESCR: "PGP:role=peer:email={email}:type=ecdh"
```

### Publish
```
Input:  WKD server URL, email (key must exist in HSM)
Action:
  1. export pubkey for email from HSM (cert-builder)
  2. POST {wkdServerUrl}/api/publish { email, pubkey_base64 }
     Authorization: Bearer {zm_auth_token from Carbonio session}
     (for standalone test: use a test token or skip auth)
Output: success / error from encedo-wkd server
```

---

## OpenPGP KDF — RFC 4880 §13.5

Required for decrypt — implemented locally in openpgp-bridge.js:

```javascript
// After ECDH returns shared_secret from HSM:
async function openpgpKdf(sharedSecret, algo, fingerprint) {
    // param string per RFC 4880
    const params = buildKdfParams(algo, fingerprint);
    const hashInput = new Uint8Array([0x00, 0x00, 0x00, 0x01,
        ...sharedSecret, ...params]);
    const digest = await crypto.subtle.digest('SHA-256', hashInput);
    return new Uint8Array(digest).slice(0, keySize(algo));
}
```

---

## WKD Hash — Z-Base-32

```javascript
const ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function wkdHash(localPart) {
    // SHA1 of lowercase local part -> Z-Base-32 encode
    // Note: Z-Base-32 alphabet differs from standard Base32
}
```

---

## OpenPGP.js import

```html
<!-- In pgp-test.html -->
<script type="importmap">
{
  "imports": {
    "openpgp": "https://unpkg.com/openpgp@6/dist/openpgp.min.mjs"
  }
}
</script>
<script type="module" src="test/pgp-test.js"></script>
```

---

## End-to-End Test Scenarios

```
T1 -- Full own cycle:
      Generate(email) -> Export -> Encrypt(to self) -> Decrypt
      Verifies: keygen, cert-builder, ECDH decrypt

T2 -- Sign and verify:
      Generate(email) -> Sign(message) -> Verify(signed, pubkey)
      Verifies: EdDSA sign via HSM, local verify

T3 -- WKD interop:
      Export pubkey -> Publish to encedo-wkd
      -> from ProtonMail: send encrypted to that email
      -> Decrypt in test page
      Verifies: full interop with external client

T4 -- Encrypt to external:
      WKD Lookup(alice@proton.me) -> Encrypt -> send via SMTP
      -> ProtonMail decrypts successfully
      Verifies: outbound encryption interop
```

---

## Notes

- OpenPGP.js v6 is required (RFC 9580, supports X25519/Ed25519 natively)
- All crypto that touches private key goes through HSM
- KDF, AES Key Wrap/Unwrap, AES-GCM: local WebCrypto only
- Token stored in JS module scope — lost on page refresh (correct behavior)
- Z-Base-32 != standard Base32 — different alphabet, common mistake
