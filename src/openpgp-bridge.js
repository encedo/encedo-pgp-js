/**
 * openpgp-bridge.js — OpenPGP message encryption/decryption/signing via Encedo HEM.
 *
 * Encryption:  standard OpenPGP.js (recipient's public key from WKD)
 * Decryption:  parses PKESK packets → HSM ECDH → RFC 6637 KDF → AES-KW → session key
 * Signing:     Ed25519 signature via HSM
 *
 * ECDH KDF reference: RFC 6637 §8 (with SHA-256, AES-256 key wrap)
 * AES key unwrap:     RFC 3394 (via Web Crypto AES-KW)
 */

import * as openpgp from 'openpgp';
import crypto from 'node:crypto';
import { lookupKey } from './wkd-client.js';

// OID for curve25519 (X25519) in OpenPGP — must match cert-builder.js
const OID_X25519 = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/**
 * Encrypt a plaintext message to one or more recipients.
 * Recipient public keys are fetched from WKD automatically.
 *
 * @param {string}   plaintext     Message body
 * @param {string[]} toEmails      Recipient email addresses
 * @param {object}   [opts]
 * @param {object}   [opts.signingHem]    HEM instance (for signing)
 * @param {string}   [opts.signingToken]  JWT token
 * @param {string}   [opts.signingKid]    Ed25519 key ID for signing
 * @returns {Promise<string>}  ASCII-armored encrypted (+ optionally signed) message
 */
export async function encryptMessage(plaintext, toEmails, opts = {}) {
  // Fetch all recipient public keys from WKD
  const encryptionKeys = [];
  for (const email of toEmails) {
    const keyBytes = await lookupKey(email);
    if (!keyBytes) throw new Error(`No WKD key found for ${email}`);
    const pubKey = await openpgp.readKey({ binaryKey: keyBytes });
    encryptionKeys.push(pubKey);
  }

  const message = await openpgp.createMessage({ text: plaintext });
  const armoredMessage = await openpgp.encrypt({ message, encryptionKeys });

  if (opts.signingHem) {
    console.warn('openpgp-bridge: signing during encrypt not yet implemented — sending unsigned');
  }

  return armoredMessage;
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/**
 * Decrypt an OpenPGP message using an HSM-stored X25519 key.
 *
 * Flow:
 *   1. Parse message and find the PKESK packet addressed to our key
 *   2. Extract ephemeral public key and AES-wrapped session key
 *   3. Perform X25519 ECDH on HSM
 *   4. Derive key-wrapping-key using RFC 6637 §8 KDF (SHA-256)
 *   5. Unwrap session key with AES-256 Key Wrap (RFC 3394)
 *   6. Decrypt message body with the session key
 *
 * @param {string}  armoredMessage  ASCII-armored or binary OpenPGP message
 * @param {object}  hem             HEM instance
 * @param {string}  token           JWT with keymgmt:use:<kid_ecdh> scope
 * @param {string}  kid_ecdh        X25519 key ID in HSM
 * @param {Uint8Array} ourPubkey32  Our 32-byte X25519 public key (from getPubKey)
 * @param {Uint8Array} fingerprint  20-byte SHA-1 fingerprint of our ECDH subkey
 * @returns {Promise<string>}  Decrypted plaintext
 */
export async function decryptMessage(armoredMessage, hem, token, kid_ecdh, ourPubkey32, fingerprint) {
  const message = await openpgp.readMessage({ armoredMessage });

  // Find PKESK packet (tag 1) addressed to our key
  const pkeskPackets = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
  if (pkeskPackets.length === 0) throw new Error('No PKESK packet found in message');

  // Try each PKESK (there may be multiple recipients)
  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, token, kid_ecdh, ourPubkey32, fingerprint);
      const { data } = await openpgp.decrypt({
        message,
        sessionKeys: [sessionKey],
      });
      return data;
    } catch (e) {
      // This PKESK was not addressed to us (or decryption failed) — try next
      continue;
    }
  }

  throw new Error('Could not decrypt: no matching PKESK for our key');
}

/**
 * Decrypt a single PKESK (Public-Key Encrypted Session Key) packet.
 * Only supports algorithm 18 (ECDH, curve25519).
 *
 * @returns {Promise<{ data: Uint8Array, algorithm: string }>}  Session key
 */
async function decryptPkesk(pkesk, hem, token, kid_ecdh, ourPubkey32, fingerprint) {
  // openpgp.js v6: for algo 18 (ECDH), pkesk.encrypted = { V, C }
  //   V   — Uint8Array MPI of ephemeral public key (2-byte bit count + 0x40 + 32 bytes)
  //   C   — ECDHSymmetricKey instance, C.data = wrapped session key bytes

  if (pkesk.publicKeyAlgorithm !== 18 && pkesk.publicKeyAlgorithm !== undefined) {
    throw new Error(`Unsupported PKESK algorithm: ${pkesk.publicKeyAlgorithm}`);
  }

  const { V, C } = pkesk.encrypted;
  if (!V || !C) throw new Error('Unexpected PKESK encrypted structure (missing V or C)');

  // V is returned by openpgp.js readMPI — already WITHOUT the 2-byte bit count header.
  // For ECDH X25519: V = 0x40 (native prefix) + 32 key bytes = 33 bytes total.
  const ephemeral32 = stripNativePrefix(V);

  // C.data is the wrapped session key (already without the 1-byte length prefix)
  const wrappedKey = C.data;

  // 1. ECDH in HSM
  const ephemeralB64 = toB64(ephemeral32);
  const sharedSecret = await hem.ecdh(token, kid_ecdh, ephemeralB64);

  // 2. RFC 6637 §8 KDF — derive key-wrapping key
  const kdfHashId = 8; // SHA-256
  const kdfSymId  = 9; // AES-256
  const kwkLen    = 32; // bytes for AES-256

  const kwk = await rfc6637kdf(sharedSecret, kdfHashId, kdfSymId, fingerprint, OID_X25519, kwkLen);

  // 3. AES-256 Key Unwrap (RFC 3394) via WebCrypto AES-KW
  const sessionKeyAlgo = pkesk.sessionKeyAlgorithm
    ?? openpgp.enums.symmetric.aes256; // default assumption

  const algoId = typeof sessionKeyAlgo === 'number'
    ? sessionKeyAlgo
    : openpgp.enums.write(openpgp.enums.symmetric, sessionKeyAlgo);

  const sessionKeyData = await aesKeyUnwrap(kwk, wrappedKey, algoId);
  const algoName = openpgp.enums.read(openpgp.enums.symmetric, algoId);

  return { data: sessionKeyData, algorithm: algoName };
}

// ---------------------------------------------------------------------------
// RFC 6637 §8 — ECDH KDF
// ---------------------------------------------------------------------------

/**
 * Derive a key-wrapping key from an ECDH shared secret per RFC 6637 §8.
 *
 * KDF(Z) = SHA-256( 00 00 00 01 || Z || Param )
 * Param = OID_len || OID || 0x12 || 03 01 hash sym || "Anonymous Sender    " || fingerprint
 *
 * @param {Uint8Array} Z           32-byte ECDH shared secret
 * @param {number}     hashId      Hash algorithm ID (8 = SHA-256)
 * @param {number}     symId       Symmetric algorithm ID (9 = AES-256)
 * @param {Uint8Array} fingerprint 20-byte v4 key fingerprint
 * @param {Uint8Array} curveOID    Curve OID bytes (without length prefix)
 * @param {number}     keyLen      Output key length in bytes (16 or 32)
 * @returns {Promise<Uint8Array>}
 */
async function rfc6637kdf(Z, hashId, symId, fingerprint, curveOID, keyLen) {
  const counter  = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
  const oidLen   = new Uint8Array([curveOID.length]);
  const algoId   = new Uint8Array([0x12]);          // 18 decimal = ECDH
  const kdfField = new Uint8Array([0x03, 0x01, hashId, symId]);
  const sender   = new TextEncoder().encode('Anonymous Sender    '); // exactly 20 bytes

  const data = concat(counter, Z, oidLen, curveOID, algoId, kdfField, sender, fingerprint);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return hash.slice(0, keyLen);
}

// ---------------------------------------------------------------------------
// AES-256 Key Unwrap (RFC 3394) via WebCrypto
// ---------------------------------------------------------------------------

/**
 * Unwrap a session key using AES Key Wrap (RFC 3394).
 * Returns the unwrapped session key bytes (with PKCS#5 padding stripped).
 */
async function aesKeyUnwrap(kwk, wrappedKey, _symAlgoId) {
  // AES-256 Key Unwrap per RFC 3394.
  // Uses Node.js crypto 'id-aes256-wrap' — for browser compatibility this needs to be replaced.
  // TODO: implement pure WebCrypto fallback for browser use.
  const { createDecipheriv } = await import('node:crypto');
  const IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
  const decipher = createDecipheriv('id-aes256-wrap', Buffer.from(kwk), IV);
  // Do NOT call setAutoPadding() — not supported on wrap ciphers.
  // Do NOT call decipher.final() — wrap cipher produces all output in update().
  const plaintext = new Uint8Array(decipher.update(Buffer.from(wrappedKey)));
  return stripPkcs5(plaintext);
}

/**
 * Strip PKCS#5 padding from AES Key Wrap result (RFC 4880 §13.5).
 * Returns the raw session key bytes (without leading sym_algo byte and trailing checksum).
 */
function stripPkcs5(padded) {
  const padLen = padded[padded.length - 1];
  if (padLen < 1 || padLen > 8) throw new Error('Invalid PKCS#5 padding');
  return padded.slice(1, padded.length - padLen - 2); // strip sym_algo + checksum + padding
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stripNativePrefix(bytes) {
  // Remove 0x40 native encoding prefix if present
  return bytes.length === 33 && bytes[0] === 0x40 ? bytes.slice(1) : bytes;
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function toB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
