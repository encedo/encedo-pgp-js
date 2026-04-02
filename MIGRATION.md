# OpenPGP v4 → v6 (RFC 9580): Migration Analysis

## Key Protocol Differences

| Aspect | v4 (RFC 4880) | v6 (RFC 9580) |
|---|---|---|
| Packet version | `0x04` | `0x06` |
| Ed25519 algo ID | 22 (EdDSA + OID) | **27** (native, no OID) |
| X25519 algo ID | 18 (ECDH + OID) | **25** (native, no OID) |
| Fingerprint | SHA-1, 20 B, prefix `0x99` | **SHA-256, 32 B**, prefix `0x9B` + 4-byte len |
| Key ID | last 8 B of fingerprint | **first** 8 B of fingerprint |
| KDF (ECDH) | RFC 6637 §8 (SHA-256 + AES-256-KW) | **HKDF-SHA-256** + AES-128-KW |
| Signature salt | none | **32 B random salt** |
| Encryption | SEIPD v1 (MDC) | **SEIPD v2 (AEAD: AES-OCB/GCM)** |
| Issuer subpacket | type 16 (Key ID) | type 28 (Issuer Fingerprint) |
| Signature trailer | `0x04 0xFF <4B len>` | **`0x06 0xFF <4B len>`** |

---

## Component Analysis

### 1. `cert-builder.js` — medium effort

Mechanical but numerous changes to binary structures:

- `buildPublicKeyBody()` / `buildX25519SubkeyBody()`: remove OIDs, change version `4→6`, change algo IDs `22→27`, `18→25`; X25519 key format in v6 is raw 32 B (no `0x40` MPI prefix)
- `computeFingerprint()`: SHA-1 → SHA-256; prefix `0x99 || u16be(len)` → `0x9B || u32be(len)`
- `computeKeyId()`: `.slice(12)` → `.slice(0, 8)` (first 8 bytes)
- `sigHashPrefix()` / `buildSigPacketBody()`: version `4→6`, prepend 32 B salt before hashedSubpkts
- Signature trailer: `[0x04, 0xFF, ...]` → `[0x06, 0xFF, ...]`
- Issuer subpacket: type 16 (8 B key ID) → type 28 (33 B: version byte + 32 B fingerprint)
- `kdfParams` in subkey: `0x09` (AES-256) → `0x07` (AES-128) — HKDF produces 128-bit KWK

**Estimate: 1–1.5 days**

---

### 2. `openpgp-bridge.js` — large effort

The most significant change is the KDF and PKESK parsing.

**KDF** — `rfc6637kdf()` must be replaced entirely:
```
v4 RFC 6637:  SHA-256(counter || Z || OID_len || OID || algoId || kdfField || "Anonymous Sender    " || fp20)
v6 HKDF:      HKDF-SHA-256(ikm = eph_pub32 || recv_pub32 || Z, salt = "", info = "OpenPGP X25519")
              → 16 B KWK for AES-128-KW
```
OID, fingerprint and "Anonymous Sender" disappear — completely different algorithm.

**PKESK v6 (algo 25)**:
- No MPI encoding — ephemeral key is raw 32 B
- Different `pkesk.encrypted` structure — need to verify what openpgp.js exposes for algo 25
- Wrapped key: AES-128-KW instead of AES-256-KW → smaller output

**`encryptAndSign()`**: add salt generation, update trailer, use Issuer Fingerprint subpacket (type 28)

**`decryptAndVerifyHSM()`**: handle v6 signature format with salt when reconstructing the hash

**Estimate: 2–3 days**

---

### 3. `runtime/` — small effort

- Add `hkdf(ikm, salt, info, length)`:
  - Browser: `crypto.subtle.deriveBits` with HKDF algorithm
  - Node: `crypto.hkdfSync`
- AES-128-KW: likely works unchanged, only different key size (16 B instead of 32 B)

**Estimate: 0.5 days**

---

### 4. openpgp.js API alignment — verify before full implementation

openpgp.js v6 (already in use) supports RFC 9580 but may require `config.v6Keys = true` or specific API calls. Critical question: does `openpgp.readKey()` accept a manually-built v6 binary cert? The project builds packets manually and does not use openpgp.js key generation — this needs experimental verification.

Potential problem: openpgp.js may not expose PKESK internals for algo 25 the same way as for algo 18, potentially requiring a different decryption path or library update.

**Estimate: 0.5–1 day** (verification + potential workarounds)

---

### 5. Tests and interoperability

- Verify generated v6 cert with `gpg --list-keys` (gpg 2.4+ supports RFC 9580)
- Encrypt from Thunderbird/ProtonMail to a v6 key
- Decrypt in the opposite direction
- Update `test-keygen.js`, `test-encrypt.js`, `test-decrypt.js`, `test-sign.js`
- WKD publish/lookup: v6 keys have different fingerprints — no collision with existing v4 keys

**Estimate: 1–2 days**

---

## Effort Summary

| Component | Effort |
|---|---|
| `cert-builder.js` | 1–1.5 days |
| `openpgp-bridge.js` | 2–3 days |
| `runtime/` (HKDF) | 0.5 days |
| openpgp.js API alignment | 0.5–1 day |
| Tests + interop | 1–2 days |
| **Total** | **5–8 days** |

---

## Recommendation

The highest risk area is **HKDF + PKESK v6 parsing** — the openpgp.js internals may or may not expose what is needed. Before full implementation, run a 2–3 hour spike: generate a v6 key with gpg, encrypt a message to it, and inspect how openpgp.js v6 parses the PKESK algo 25 packet — this will confirm whether the `pkesk.encrypted` path provides the same field access as for algo 18.

Backwards compatibility (supporting both v4 and v6 simultaneously) would add approximately 2 additional days.
