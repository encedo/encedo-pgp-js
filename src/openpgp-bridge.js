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
import { lookupKey } from './wkd-client.js';
import { aes256KeyUnwrap, sha256 } from './runtime/index.js';
import { DESCR, encodeDescr } from './keychain.js';

// OID for curve25519 (X25519) in OpenPGP — must match cert-builder.js
const OID_X25519 = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);

// ---------------------------------------------------------------------------
// Encrypt using recipient public key stored in HSM
// ---------------------------------------------------------------------------

/**
 * Encrypt a message to a recipient whose OpenPGP keys are stored in the HSM.
 * Rebuilds the recipient's OpenPGP certificate from HSM key material (sign + ecdh),
 * so no WKD lookup is needed — the HSM is the source of trust.
 *
 * Required scopes:
 *   signToken  — keymgmt:use:<kid_sign>  (to rebuild self-signed cert)
 *   ecdhToken  — keymgmt:use:<kid_ecdh>
 *
 * @param {object} hem        HEM instance
 * @param {string} signToken  JWT for sign key use
 * @param {string} ecdhToken  JWT for ECDH key use
 * @param {string} kid_sign   Ed25519 key ID in HSM
 * @param {string} kid_ecdh   X25519 key ID in HSM
 * @param {string} email      Recipient email (used for UID in cert)
 * @param {string} plaintext  Message to encrypt
 * @returns {Promise<string>} ASCII-armored encrypted message
 */
export async function encryptMessageHSM(hem, signToken, ecdhToken, kid_sign, kid_ecdh, email, plaintext, opts = {}) {
  const { buildCertificate } = await import('./cert-builder.js');
  const { cert } = await buildCertificate(hem, signToken, kid_sign, kid_ecdh, email, { ecdhToken, timestamp: opts.timestamp ?? 0 });
  const pubKey  = await openpgp.readKey({ binaryKey: cert });
  const message = await openpgp.createMessage({ text: plaintext });
  return openpgp.encrypt({ message, encryptionKeys: pubKey });
}

// ---------------------------------------------------------------------------
// Encrypt using recipient public key fetched from WKD (local WebCrypto)

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
  let lastErr = null;
  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, token, kid_ecdh, ourPubkey32, fingerprint);
      const { data } = await openpgp.decrypt({
        message,
        sessionKeys: [sessionKey],
      });
      return data;
    } catch (e) {
      console.error('decryptMessage PKESK failed:', e);
      lastErr = e;
      continue;
    }
  }

  throw new Error(`Could not decrypt: ${lastErr?.message ?? 'no matching PKESK for our key'}`);
}

/**
 * Decrypt a PGP message (HSM ECDH) and verify the embedded signature locally.
 * Compatible with messages produced by Thunderbird, Proton, and standard OpenPGP clients.
 *
 * @param {string}     armoredMessage   ASCII-armored PGP message
 * @param {object}     hem              HEM instance
 * @param {string}     token            JWT with keymgmt:use:<kid_ecdh> scope
 * @param {string}     kid_ecdh         X25519 key ID in HSM
 * @param {Uint8Array} ourPubkey32      Our 32-byte X25519 public key
 * @param {Uint8Array} fingerprint      20-byte SHA-1 fingerprint of our ECDH subkey
 * @param {string}     armoredSenderKey Armored public key of the sender (for verification)
 * @returns {Promise<{ data: string, valid: boolean, keyID: string }>}
 *   data  — decrypted plaintext
 *   valid — true if signature is valid
 *   keyID — hex key ID of the signing key (upper case)
 */
export async function decryptAndVerify(armoredMessage, hem, token, kid_ecdh, ourPubkey32, fingerprint, armoredSenderKey) {
  const message    = await openpgp.readMessage({ armoredMessage });
  const senderKey  = await openpgp.readKey({ armoredKey: armoredSenderKey });

  const pkeskPackets = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
  if (pkeskPackets.length === 0) throw new Error('No PKESK packet found in message');

  let lastErr = null;
  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, token, kid_ecdh, ourPubkey32, fingerprint);
      console.error('decryptAndVerify: sessionKey OK, calling openpgp.decrypt...');
      const result = await openpgp.decrypt({
        message,
        sessionKeys: [sessionKey],
        verificationKeys: [senderKey],
      });
      console.error('decryptAndVerify: openpgp.decrypt OK, data.length=', result.data?.length);
      const sig = result.signatures[0];
      if (!sig) return { data: result.data, valid: false, keyID: null };
      try {
        await sig.verified;
        return { data: result.data, valid: true, keyID: sig.keyID.toHex().toUpperCase() };
      } catch {
        return { data: result.data, valid: false, keyID: sig.keyID?.toHex().toUpperCase() ?? null };
      }
    } catch (e) {
      console.error('decryptAndVerify PKESK failed:', e);
      lastErr = e;
      continue;
    }
  }

  throw new Error(`Could not decrypt: ${lastErr?.message ?? 'no matching PKESK for our key'}`);
}

/**
 * Decrypt a PGP message (HSM ECDH) and verify the embedded signature via HSM.
 * The sender's public key must have been previously imported via importKeyFromWKD()
 * (stored with DESCR.peerSign tag).
 *
 * @param {string}     armoredMessage  ASCII-armored PGP message
 * @param {object}     hem             HEM instance
 * @param {string}     ecdhToken       JWT with keymgmt:use:<kid_ecdh> scope
 * @param {string}     kid_ecdh        X25519 key ID in HSM (recipient)
 * @param {Uint8Array} ourPubkey32     Our 32-byte X25519 public key
 * @param {Uint8Array} fingerprint     20-byte SHA-1 fingerprint of our ECDH subkey
 * @param {string}     verifyToken     JWT with keymgmt:use:<kid_sender_sign> scope
 * @param {string}     kid_sender_sign Ed25519 key ID in HSM (imported sender key)
 * @returns {Promise<{ data: string, valid: boolean }>}
 */
export async function decryptAndVerifyHSM(armoredMessage, hem, ecdhToken, kid_ecdh, ourPubkey32, fingerprint, verifyToken, kid_sender_sign) {
  const message = await openpgp.readMessage({ armoredMessage });

  const pkeskPackets = message.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
  if (pkeskPackets.length === 0) throw new Error('No PKESK packet found in message');

  let plaintext = null;
  let lastErr = null;
  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, ecdhToken, kid_ecdh, ourPubkey32, fingerprint);
      const { data } = await openpgp.decrypt({ message, sessionKeys: [sessionKey] });
      plaintext = data;
      break;
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  if (plaintext === null) throw new Error(`Could not decrypt: ${lastErr?.message ?? 'no matching PKESK for our key'}`);

  // Extract signature bytes from the message and verify via HSM
  const sigPackets = message.packets.filterByTag(openpgp.enums.packet.signature);
  if (!sigPackets.length) return { data: plaintext, valid: false };

  // Reconstruct the signed data: LiteralData packet content + sig packet hash prefix + trailer
  // openpgp.js v6: get the literal data packet
  const litPackets = message.packets.filterByTag(openpgp.enums.packet.literalData);
  if (!litPackets.length) return { data: plaintext, valid: false };

  const litData  = litPackets[0];
  const sigPkt   = sigPackets[0];

  // Build the data that was hashed for this signature (RFC 4880 §5.2.4)
  // For literal data signatures: hash over the literal body + sig hash prefix + trailer
  const litBody      = litData.data instanceof Uint8Array ? litData.data
                     : new TextEncoder().encode(litData.data);
  const hashedLen    = sigPkt.rawNotations?.length ?? 0; // fallback
  // Use openpgp.js internal: sigPkt.signatureData has the hash prefix bytes
  const sigData      = sigPkt.signatureData; // Uint8Array: version+type+algo+hash+hashedSubpkts
  const trailerLen   = sigData.length;
  const trailer      = new Uint8Array([0x04, 0xFF,
    (trailerLen>>>24)&0xFF, (trailerLen>>>16)&0xFF, (trailerLen>>>8)&0xFF, trailerLen&0xFF]);
  const hash         = await sha256(concat(litBody, sigData, trailer));

  // Reconstruct 64-byte sig from R+S MPIs
  const { sig64 } = parseSigPacketForVerify(sigPkt.write());

  try {
    await hem.exdsaVerify(verifyToken, kid_sender_sign, hash, sig64, 'Ed25519');
    return { data: plaintext, valid: true };
  } catch {
    return { data: plaintext, valid: false };
  }
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
  if (!V || !C) {
    console.error('decryptPkesk: unexpected structure', JSON.stringify({ keys: Object.keys(pkesk.encrypted ?? {}), algo: pkesk.publicKeyAlgorithm }));
    throw new Error('Unexpected PKESK encrypted structure (missing V or C)');
  }

  // V is returned by openpgp.js readMPI — already WITHOUT the 2-byte bit count header.
  // For ECDH X25519: V = 0x40 (native prefix) + 32 key bytes = 33 bytes total.
  const ephemeral32 = stripNativePrefix(V);
  console.error(`decryptPkesk: V.length=${V?.length} ephemeral32.length=${ephemeral32?.length} C.data.length=${C?.data?.length}`);

  // C.data is the wrapped session key (already without the 1-byte length prefix)
  const wrappedKey = C.data;

  // 1. ECDH in HSM
  const ephemeralB64 = toB64(ephemeral32);
  const sharedSecret = await hem.ecdh(token, kid_ecdh, ephemeralB64);

  // 2. RFC 6637 §8 KDF — derive key-wrapping key
  const kdfHashId = 8; // SHA-256
  const kdfSymId  = 9; // AES-256
  const kwkLen    = 32; // bytes for AES-256

  console.error(`decryptPkesk: sharedSecret.length=${sharedSecret?.length} fingerprint.length=${fingerprint?.length} wrappedKey.length=${wrappedKey?.length}`);
  const kwk = await rfc6637kdf(sharedSecret, kdfHashId, kdfSymId, fingerprint, OID_X25519, kwkLen);
  console.error(`decryptPkesk: kwk=${Array.from(kwk).map(b=>b.toString(16).padStart(2,'0')).join('')}`);

  // 3. AES-256 Key Unwrap (RFC 3394) via WebCrypto AES-KW
  const sessionKeyAlgo = pkesk.sessionKeyAlgorithm
    ?? openpgp.enums.symmetric.aes256; // default assumption

  const algoId = typeof sessionKeyAlgo === 'number'
    ? sessionKeyAlgo
    : openpgp.enums.write(openpgp.enums.symmetric, sessionKeyAlgo);

  const sessionKeyData = await aesKeyUnwrap(kwk, wrappedKey, algoId);
  const algoName = openpgp.enums.read(openpgp.enums.symmetric, algoId);
  console.error(`decryptPkesk: sessionKeyData.length=${sessionKeyData?.length} algoId=${algoId} algoName=${algoName}`);

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
  const hash = await sha256(data);
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
  const plaintext = await aes256KeyUnwrap(kwk, wrappedKey);
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

// Low-level packet encoding (mirrors private helpers in cert-builder.js)
function u16be(n) { return new Uint8Array([n >> 8, n & 0xFF]); }
function u32be(n) { return new Uint8Array([(n>>>24)&0xFF, (n>>>16)&0xFF, (n>>>8)&0xFF, n&0xFF]); }

/** Encode a new-format OpenPGP packet (RFC 4880 §4.2). */
function pktEncode(tag, body) {
  const len = body.length;
  let hdr;
  if (len < 192) {
    hdr = new Uint8Array([0xC0 | tag, len]);
  } else if (len < 8384) {
    const b = len - 192;
    hdr = new Uint8Array([0xC0 | tag, ((b >> 8) & 0xFF) + 192, b & 0xFF]);
  } else {
    hdr = new Uint8Array([0xC0 | tag, 0xFF, (len>>>24)&0xFF, (len>>>16)&0xFF, (len>>>8)&0xFF, len&0xFF]);
  }
  return concat(hdr, body);
}

/** Encode one OpenPGP subpacket: length | type | data. */
function subpktEncode(type, data) {
  const body = concat(new Uint8Array([type]), data);
  return concat(new Uint8Array([body.length]), body);
}

/**
 * Encode an Ed25519 64-byte signature (R||S) as two OpenPGP MPIs.
 * Each component is a "native" MPI: bit-count (2 bytes) + raw bytes.
 */
function encodeEdDSASig(sig64) {
  function nativeMPI(bytes32) {
    let bits = 256;
    for (let i = 0; i < bytes32.length; i++) {
      if (bytes32[i] === 0) { bits -= 8; continue; }
      let b = bytes32[i], lz = 0;
      while (!(b & 0x80)) { b <<= 1; lz++; }
      bits -= lz;
      break;
    }
    if (bits <= 0) bits = 1;
    return concat(u16be(bits), bytes32);
  }
  return concat(nativeMPI(sig64.slice(0, 32)), nativeMPI(sig64.slice(32, 64)));
}

// ---------------------------------------------------------------------------
// Verify cleartext signed message (local openpgp.js)
// ---------------------------------------------------------------------------

/**
 * Verify an ASCII-armored OpenPGP cleartext signed message.
 *
 * @param {string} armoredSigned  -----BEGIN PGP SIGNED MESSAGE----- ...
 * @param {string} armoredPubKey  -----BEGIN PGP PUBLIC KEY BLOCK----- ...
 * @returns {Promise<{ valid: boolean, keyID: string }>}
 */
export async function verifySignedMessage(armoredSigned, armoredPubKey) {
  const message   = await openpgp.readCleartextMessage({ cleartextMessage: armoredSigned });
  const publicKey = await openpgp.readKey({ armoredKey: armoredPubKey });
  const result    = await openpgp.verify({ message, verificationKeys: [publicKey] });
  const sig       = result.signatures[0];
  if (!sig) throw new Error('No signature found in message');
  await sig.verified; // throws if signature is invalid
  return { valid: true, keyID: sig.keyID.toHex().toUpperCase() };
}

// ---------------------------------------------------------------------------
// Helpers for HSM-based verify
// ---------------------------------------------------------------------------

function canonicalizeCleartext(text) {
  return text
    .split('\n')
    .map(l => l.replace(/\r$/, '').replace(/[ \t]+$/, ''))
    .join('\r\n');
}

/** Parse armored cleartext message into { text, sigBinary }. */
function parseCleartextArmored(armored) {
  const lines = armored.replace(/\r\n/g, '\n').split('\n');
  let i = 1;
  while (i < lines.length && lines[i] !== '') i++;
  i++; // skip blank line after headers
  const bodyLines = [];
  while (i < lines.length && !lines[i].startsWith('-----BEGIN PGP SIGNATURE-----')) {
    const l = lines[i++];
    bodyLines.push(l.startsWith('- ') ? l.slice(2) : l);
  }
  i += 2; // skip sig marker + blank line
  let b64 = '';
  while (i < lines.length && !lines[i].startsWith('=') && !lines[i].startsWith('-----')) {
    b64 += lines[i++];
  }
  return { text: bodyLines.join('\n'), sigBinary: Uint8Array.from(atob(b64), c => c.charCodeAt(0)) };
}

/** Parse new-format OpenPGP sig packet; return { signatureData (hashPrefix), sig64 }. */
function parseSigPacketForVerify(data) {
  let off = 1; // skip tag byte (0xC2)
  const fb = data[off++];
  let bodyLen;
  if (fb < 192) {
    bodyLen = fb;
  } else if (fb < 224) {
    bodyLen = ((fb - 192) << 8) + data[off++] + 192;
  } else {
    bodyLen = (data[off] << 24) | (data[off+1] << 16) | (data[off+2] << 8) | data[off+3];
    off += 4;
  }
  const body = data.slice(off, off + bodyLen);
  // body: [ver=4, sigType, pkAlgo=22, hashAlgo=8, hashedLen(2), ...hashed, unhashedLen(2), ...unhashed, hashLeft2(2), ...MPIs]
  const hashedLen = (body[4] << 8) | body[5];
  const signatureData = body.slice(0, 6 + hashedLen); // the "hashPrefix"
  let pos = 6 + hashedLen;
  const unhashedLen = (body[pos] << 8) | body[pos + 1];
  pos += 2 + unhashedLen + 2; // skip unhashed subpkts + hashLeft2
  // R MPI
  const rBits = (body[pos] << 8) | body[pos + 1]; pos += 2;
  const rData = body.slice(pos, pos + Math.ceil(rBits / 8)); pos += rData.length;
  // S MPI
  const sBits = (body[pos] << 8) | body[pos + 1]; pos += 2;
  const sData = body.slice(pos, pos + Math.ceil(sBits / 8));
  // Reconstruct 64-byte sig (left-pad each to 32 bytes)
  const sig64 = new Uint8Array(64);
  sig64.set(rData, 32 - rData.length);
  sig64.set(sData, 64 - sData.length);
  return { signatureData, sig64 };
}

// ---------------------------------------------------------------------------
// Verify cleartext signed message via HSM (uses imported public key in HSM)
// ---------------------------------------------------------------------------

/**
 * Verify an ASCII-armored OpenPGP cleartext signed message using the HSM.
 * The signer's public key must have been previously imported via importKeyFromWKD().
 *
 * Required scope: 'keymgmt:use:<kid>'
 *
 * @param {object} hem            HEM instance
 * @param {string} token          JWT with keymgmt:use:<kid> scope
 * @param {string} kid            KID of the imported public key in HSM
 * @param {string} armoredSigned  -----BEGIN PGP SIGNED MESSAGE----- ...
 * @returns {Promise<true>}  Resolves on success, throws on invalid signature (HTTP 406)
 */
export async function verifySignedMessageHSM(hem, token, kid, armoredSigned) {
  const { text, sigBinary }      = parseCleartextArmored(armoredSigned);
  const { signatureData, sig64 } = parseSigPacketForVerify(sigBinary);
  const canonical  = canonicalizeCleartext(text);
  const msgBytes   = new TextEncoder().encode(canonical);
  const len        = signatureData.length;
  const trailer    = new Uint8Array([0x04, 0xFF, (len>>>24)&0xFF, (len>>>16)&0xFF, (len>>>8)&0xFF, len&0xFF]);
  const hash       = await sha256(concat(msgBytes, signatureData, trailer));
  return hem.exdsaVerify(token, kid, hash, sig64, 'Ed25519');
}

// ---------------------------------------------------------------------------
// Sign + Encrypt (one OpenPGP message, Thunderbird/Proton compatible)
// ---------------------------------------------------------------------------

/**
 * Sign and encrypt a message using an HSM Ed25519 signing key and one or more
 * recipient public keys.  Produces a standard OpenPGP inline-signed encrypted
 * message compatible with Thunderbird, Proton, Enigmail, and GPG:
 *
 *   PKESK  (one per recipient)
 *   SEIPD {
 *     OnePassSignaturePacket  (tag 4)
 *     LiteralDataPacket       (tag 11)
 *     SignaturePacket         (tag 2)
 *   }
 *
 * Required scope: keymgmt:use:<kid_sign>
 *
 * @param {object}     hem        HEM instance
 * @param {string}     signToken  JWT with keymgmt:use:<kid_sign> scope
 * @param {string}     kid_sign   Ed25519 key ID in HSM
 * @param {Uint8Array} keyId8     8-byte OpenPGP key ID of the signing key
 *                                (last 8 bytes of SHA-1 fingerprint; returned by buildCertificate)
 * @param {Array}      recipients Array of recipient descriptors (see below)
 * @param {string}     plaintext  Message to sign and encrypt
 * @returns {Promise<string>}     ASCII-armored encrypted+signed message
 *
 * Recipient descriptors (one of):
 *   - string containing '@'  → email address, WKD lookup performed automatically
 *   - string containing '-'  → ASCII-armored PGP public key block
 *   - openpgp.PublicKey      → already-parsed public key object
 */
export async function encryptAndSign(hem, signToken, kid_sign, keyId8, recipients, plaintext) {
  const ts = Math.floor(Date.now() / 1000);

  // ── 1. Resolve all recipient public keys ────────────────────────────────
  const encryptionKeys = [];
  for (const r of recipients) {
    if (r && typeof r === 'object' && r.keyPacket !== undefined) {
      // Already an openpgp.PublicKey / Subkey object
      encryptionKeys.push(r);
    } else if (typeof r === 'string' && r.includes('@')) {
      // Email address → WKD lookup
      const keyBytes = await lookupKey(r);
      if (!keyBytes) throw new Error(`encryptAndSign: no WKD key found for ${r}`);
      encryptionKeys.push(await openpgp.readKey({ binaryKey: keyBytes }));
    } else if (typeof r === 'string') {
      // Armored public key block
      encryptionKeys.push(await openpgp.readKey({ armoredKey: r }));
    } else {
      throw new Error('encryptAndSign: invalid recipient — must be email, armored key, or openpgp.PublicKey');
    }
  }
  if (encryptionKeys.length === 0) throw new Error('encryptAndSign: no recipients');

  // ── 2. Encode plaintext bytes ────────────────────────────────────────────
  //   RFC 4880 §5.9: for a binary signature (type 0x00), only the literal data
  //   content bytes are signed — not the LiteralData packet header (format, timestamp).
  const dataBytes = new TextEncoder().encode(plaintext);

  // ── 3. Build hashed subpackets for the signature ─────────────────────────
  //   Signature creation time (subpkt 2) + issuer key ID (subpkt 16).
  const hashedSubpkts = concat(
    subpktEncode(2,  u32be(ts)),   // sig creation time
    subpktEncode(16, keyId8),      // issuer key ID
  );

  // ── 4. sigData = the bytes included in the hash (RFC 4880 §5.2.4) ────────
  //   v4 | sigType=0x00 | pkAlgo=22(EdDSA) | hashAlgo=8(SHA-256) | hashedLen | hashedSubpkts
  const sigData = concat(
    new Uint8Array([4, 0x00, 22, 8]),
    u16be(hashedSubpkts.length),
    hashedSubpkts,
  );
  const trailer = concat(new Uint8Array([0x04, 0xFF]), u32be(sigData.length));

  // ── 5. Hash and sign via HSM ─────────────────────────────────────────────
  const hash  = await sha256(concat(dataBytes, sigData, trailer));
  const sig64 = await hem.exdsaSignBytes(signToken, kid_sign, hash, 'Ed25519');

  // ── 6. Build SignaturePacket body (tag 2) ─────────────────────────────────
  //   sigData | unhashedLen | unhashedSubpkts | hashLeft2 | R_MPI | S_MPI
  const unhashedSubpkts = new Uint8Array(0); // issuer already in hashed subpkts
  const sigBody = concat(
    sigData,
    u16be(unhashedSubpkts.length),
    unhashedSubpkts,
    hash.slice(0, 2),          // left-two hash bytes (quick check)
    encodeEdDSASig(sig64),     // R MPI + S MPI
  );
  const sigPkt = pktEncode(2, sigBody);

  // ── 7. Build signed Message and encrypt ──────────────────────────────────
  //   We use openpgp.createMessage + message.sign(existingSig) rather than
  //   openpgp.readMessage({ binaryMessage: concat(opsPkt, litPkt, sigPkt) }).
  //
  //   Why: readMessage stops consuming the PacketList stream after the first
  //   "streaming" packet (LiteralData). The trailing SignaturePacket is left in
  //   the internal stream and never enters the PacketList array. PacketList.write()
  //   only iterates the array, so the Sig packet is silently dropped from the
  //   SEIPD content → decrypt throws "Missing trailing signature packets".
  //
  //   message.sign([], [], existingSig) assembles [OPS, LiteralData, Sig] directly
  //   into the PacketList array (no streaming), so write() serialises all three.
  const litMsg    = await openpgp.createMessage({ binary: dataBytes, format: 'binary' });
  const existingSig = await openpgp.readSignature({ binarySignature: sigPkt });
  const signedMsg = await litMsg.sign([], [], existingSig);
  return openpgp.encrypt({
    message: signedMsg,
    encryptionKeys,
    config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed },
  });
}

// ---------------------------------------------------------------------------
// Import WKD key into HSM
// ---------------------------------------------------------------------------

/**
 * Fetch a public key from WKD and import both Ed25519 (sign) and X25519 (ecdh) keys
 * into the HSM with proper DESCR tags (DESCR.peerSign / DESCR.peerEcdh).
 *
 * Required scope: 'keymgmt:imp'
 *
 * @param {object} hem    HEM instance
 * @param {string} token  JWT with keymgmt:imp scope
 * @param {string} email  Email address for WKD lookup
 * @returns {Promise<{kidSign: string, kidEcdh: string}>}
 */
export async function importKeyFromWKD(hem, token, email) {
  const keyBytes = await lookupKey(email);
  if (!keyBytes) throw new Error(`No WKD key found for ${email}`);
  const pubKey = await openpgp.readKey({ binaryKey: keyBytes });

  // Primary key — Ed25519 sign
  const signRaw32   = stripNativePrefix(pubKey.keyPacket.publicParams.Q);
  const signDescr   = encodeDescr(DESCR.peerSign(email));
  const { kid: kidSign } = await hem.importPublicKey(token, email.slice(0, 32), 'ED25519', signRaw32, signDescr);

  // Subkey — X25519 ECDH
  const subkeys = pubKey.getSubkeys();
  const ecdhSubkey = subkeys.find(sk => sk.keyPacket?.publicParams?.Q);
  if (!ecdhSubkey) throw new Error(`No X25519 subkey found for ${email}`);
  const ecdhRaw32  = stripNativePrefix(ecdhSubkey.keyPacket.publicParams.Q);
  const ecdhDescr  = encodeDescr(DESCR.peerEcdh(email));
  const { kid: kidEcdh } = await hem.importPublicKey(token, `${email.slice(0, 28)}/E`, 'CURVE25519', ecdhRaw32, ecdhDescr);

  return { kidSign, kidEcdh };
}
