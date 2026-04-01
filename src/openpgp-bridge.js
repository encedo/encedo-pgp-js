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
export async function encryptMessageHSM(hem, signToken, ecdhToken, kid_sign, kid_ecdh, email, plaintext) {
  const { buildCertificate } = await import('./cert-builder.js');
  const { cert } = await buildCertificate(hem, signToken, kid_sign, kid_ecdh, email, { ecdhToken });
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

  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, token, kid_ecdh, ourPubkey32, fingerprint);
      const result = await openpgp.decrypt({
        message,
        sessionKeys: [sessionKey],
        verificationKeys: [senderKey],
      });
      const sig = result.signatures[0];
      if (!sig) return { data: result.data, valid: false, keyID: null };
      try {
        await sig.verified;
        return { data: result.data, valid: true, keyID: sig.keyID.toHex().toUpperCase() };
      } catch {
        return { data: result.data, valid: false, keyID: sig.keyID?.toHex().toUpperCase() ?? null };
      }
    } catch (e) {
      continue;
    }
  }

  throw new Error('Could not decrypt: no matching PKESK for our key');
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
  for (const pkesk of pkeskPackets) {
    try {
      const sessionKey = await decryptPkesk(pkesk, hem, ecdhToken, kid_ecdh, ourPubkey32, fingerprint);
      const { data } = await openpgp.decrypt({ message, sessionKeys: [sessionKey] });
      plaintext = data;
      break;
    } catch (e) {
      continue;
    }
  }
  if (plaintext === null) throw new Error('Could not decrypt: no matching PKESK for our key');

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
