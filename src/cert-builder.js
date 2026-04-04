/**
 * cert-builder.js — Build an OpenPGP v4 public-key certificate from keys stored in Encedo HEM.
 *
 * Implements RFC 4880 packet encoding:
 *   - Primary key:  Algorithm 22 (EdDSA / Ed25519)
 *   - User ID
 *   - UID certification signature (type 0x13, signed by primary key via HSM)
 *   - Subkey:       Algorithm 18 (ECDH, curve25519)
 *   - Subkey binding signature (type 0x18, signed by primary key via HSM)
 *
 * OIDs used:
 *   Ed25519  (algo 22): 1.3.6.1.4.1.11591.15.1  = 2b 06 01 04 01 da 47 0f 01  (9 bytes)
 *   X25519   (algo 18): 1.3.6.1.4.1.3029.1.5.1  = 2b 06 01 04 01 97 55 01 05 01 (10 bytes)
 *
 * References:
 *   RFC 4880  — OpenPGP Message Format
 *   RFC 6637  — Elliptic Curve Cryptography in OpenPGP (ECDH KDF)
 *   draft-koch-eddsa-for-openpgp — EdDSA in OpenPGP
 */

import { sha1, sha256 } from './runtime/index.js';

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

const OID_ED25519 = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]); // 9 bytes
const OID_X25519  = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]); // 10 bytes

// ---------------------------------------------------------------------------
// Low-level byte helpers
// ---------------------------------------------------------------------------

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function u16be(n) { return new Uint8Array([n >> 8, n & 0xFF]); }
function u32be(n) { return new Uint8Array([(n>>>24)&0xFF, (n>>>16)&0xFF, (n>>>8)&0xFF, n&0xFF]); }

/** Encode new-format OpenPGP packet (tag + body). */
function packet(tag, body) {
  const hdr = [0xC0 | tag];
  const len = body.length;
  if (len < 192) {
    hdr.push(len);
  } else if (len < 8384) {
    const b = len - 192;
    hdr.push(((b >> 8) & 0xFF) + 192, b & 0xFF);
  } else {
    hdr.push(0xFF, (len>>>24)&0xFF, (len>>>16)&0xFF, (len>>>8)&0xFF, len&0xFF);
  }
  return concat(new Uint8Array(hdr), body);
}

/**
 * Encode an OpenPGP MPI.
 * For Ed25519/X25519 keys: bytes from HSM are in their native 32-byte form.
 * We prefix them with 0x40 (native encoding marker) per draft-koch-eddsa §4.
 * The 0x40 prefix byte makes the bit count 263 (bit 6 of 0x40 is the first significant bit).
 */
function encodePubkeyMPI(rawKey32) {
  // 0x40 prefix + 32 key bytes = 33 bytes
  // Bit count: 0x40 = 0100 0000, so first significant bit is bit 6 → bit count = 263
  const data = concat(new Uint8Array([0x40]), rawKey32);
  return concat(u16be(263), data);
}

/**
 * Encode an Ed25519 signature (64 bytes = R || S) as two OpenPGP MPIs.
 * R and S are in native little-endian Ed25519 encoding.
 * Per draft-koch-eddsa, each is encoded as a native MPI (byte string with standard MPI bit count).
 */
function encodeEddsaSignatureMPIs(sig64) {
  const R = sig64.slice(0, 32);
  const S = sig64.slice(32, 64);
  return concat(nativeMPI(R), nativeMPI(S));
}

function nativeMPI(bytes32) {
  // Count significant bits treating first byte as most significant
  let bitCount = 256;
  for (let i = 0; i < bytes32.length; i++) {
    if (bytes32[i] === 0) { bitCount -= 8; continue; }
    let b = bytes32[i], lz = 0;
    while (!(b & 0x80)) { b <<= 1; lz++; }
    bitCount -= lz;
    break;
  }
  if (bitCount <= 0) bitCount = 1;
  return concat(u16be(bitCount), bytes32);
}

// ---------------------------------------------------------------------------
// Signature subpackets
// ---------------------------------------------------------------------------

function subpkt(type, data) {
  const body = concat(new Uint8Array([type]), data instanceof Uint8Array ? data : new Uint8Array(data));
  return concat(new Uint8Array([body.length]), body);
}

function sigCreationTime(ts) {
  return subpkt(2, u32be(ts));
}

function keyFlagsSubpkt(flags) {
  return subpkt(27, new Uint8Array([flags]));
}

function preferredSymAlgos() {
  // AES-256 (9), AES-128 (7)
  return subpkt(11, new Uint8Array([9, 7]));
}

function preferredHashAlgos() {
  // SHA-256 (8), SHA-512 (10)
  return subpkt(21, new Uint8Array([8, 10]));
}

function preferredCompression() {
  // ZLIB (2), ZIP (1), Uncompressed (0)
  return subpkt(22, new Uint8Array([2, 1, 0]));
}

function featuresSubpkt() {
  // Modification detection code (0x01)
  return subpkt(30, new Uint8Array([0x01]));
}

function issuerSubpkt(keyId8) {
  return subpkt(16, keyId8);
}

/** Key Expiration Time subpacket (type 9) — seconds after key creation, 0 = no expiry. */
function keyExpirationTimeSubpkt(secondsFromCreation) {
  return subpkt(9, u32be(secondsFromCreation));
}

// Key flags: certify + sign = 0x03; encrypt comms + storage = 0x0C
const KEY_FLAG_CERT_SIGN = 0x03;
const KEY_FLAG_ENCRYPT   = 0x0C;

// ---------------------------------------------------------------------------
// Key ID
// ---------------------------------------------------------------------------

/**
 * Compute the 8-byte key ID from a v4 public key packet body.
 * Key ID = last 8 bytes of SHA-1 fingerprint.
 */
async function computeKeyId(keyBody) {
  const header = concat(new Uint8Array([0x99]), u16be(keyBody.length));
  const fingerprint = await sha1(concat(header, keyBody));
  return fingerprint.slice(12); // last 8 bytes
}

/**
 * Compute 20-byte SHA-1 fingerprint from a v4 public key packet body.
 */
async function computeFingerprint(keyBody) {
  const header = concat(new Uint8Array([0x99]), u16be(keyBody.length));
  return await sha1(concat(header, keyBody));
}

// ---------------------------------------------------------------------------
// Packet bodies
// ---------------------------------------------------------------------------

/**
 * Build the body (without packet header) of a v4 public key packet.
 * Used for both primary key (tag 6) and subkey (tag 14).
 */
function buildPublicKeyBody(algo, keyBytes, timestamp, extraAlgoFields) {
  return concat(
    new Uint8Array([4]),   // version
    u32be(timestamp),
    new Uint8Array([algo]),
    ...(extraAlgoFields ?? []),
    encodePubkeyMPI(keyBytes),
  );
}

/** Build Ed25519 primary key body (algo 22). */
function buildEd25519KeyBody(pubkey32, timestamp) {
  const oid = concat(new Uint8Array([OID_ED25519.length]), OID_ED25519);
  return buildPublicKeyBody(22, pubkey32, timestamp, [oid]);
}

/** Build X25519 / curve25519 ECDH subkey body (algo 18). */
function buildX25519SubkeyBody(pubkey32, timestamp) {
  // RFC 6637 §9 order: version | timestamp | algo | OID | MPI | KDF params
  // KDF params must come AFTER the MPI (not before).
  const oid = concat(new Uint8Array([OID_X25519.length]), OID_X25519);
  // KDF params: 03 01 hash_alg(08=SHA-256) sym_alg(09=AES-256)
  const kdfParams = new Uint8Array([0x03, 0x01, 0x08, 0x09]);
  return concat(
    new Uint8Array([4]),       // version
    u32be(timestamp),
    new Uint8Array([18]),      // algo = ECDH
    oid,
    encodePubkeyMPI(pubkey32), // MPI before KDF params
    kdfParams,
  );
}

/** Build UID packet body. */
function buildUidBody(uid) {
  return new TextEncoder().encode(uid);
}

// ---------------------------------------------------------------------------
// Signature construction
// ---------------------------------------------------------------------------

/**
 * Build the "hash data" prefix for a v4 signature packet per RFC 4880 §5.2.4.
 * This is the invariant part included in the hash (before the hashed subpackets trailer).
 */
function sigHashPrefix(sigType, pubkeyAlgo, hashAlgo, hashedSubpkts) {
  return concat(
    new Uint8Array([4, sigType, pubkeyAlgo, hashAlgo]),
    u16be(hashedSubpkts.length),
    hashedSubpkts,
  );
}

/**
 * Build the trailer appended after the signature data before hashing (RFC 4880 §5.2.4).
 * Trailer = 0x04 0xFF + 4-byte BE length of (version + sigtype + algo + hash + hashed subpkts).
 */
function sigTrailer(hashPrefix) {
  return concat(
    new Uint8Array([0x04, 0xFF]),
    u32be(hashPrefix.length),
  );
}

/**
 * Hash the data to be signed for a UID certification signature (type 0x13).
 *
 * Data = 0x99 || 2-byte-len || primaryKeyBody
 *      + 0xB4 || 4-byte-len || uidBody
 *      + hashPrefix + trailer
 */
async function hashUidCertification(primaryKeyBody, uidBody, hashPrefix) {
  const keyOctet  = concat(new Uint8Array([0x99]), u16be(primaryKeyBody.length), primaryKeyBody);
  const uidOctet  = concat(new Uint8Array([0xb4]), u32be(uidBody.length), uidBody);
  const trailer   = sigTrailer(hashPrefix);
  return await sha256(concat(keyOctet, uidOctet, hashPrefix, trailer));
}

/**
 * Hash the data to be signed for a subkey binding signature (type 0x18).
 *
 * Data = 0x99 || 2-byte-len || primaryKeyBody
 *      + 0x99 || 2-byte-len || subkeyBody
 *      + hashPrefix + trailer
 */
async function hashSubkeyBinding(primaryKeyBody, subkeyBody, hashPrefix) {
  const keyOctet    = concat(new Uint8Array([0x99]), u16be(primaryKeyBody.length), primaryKeyBody);
  const subkeyOctet = concat(new Uint8Array([0x99]), u16be(subkeyBody.length), subkeyBody);
  const trailer     = sigTrailer(hashPrefix);
  return await sha256(concat(keyOctet, subkeyOctet, hashPrefix, trailer));
}

/**
 * Assemble a complete v4 signature packet body from its parts.
 */
function buildSigPacketBody(sigType, hashedSubpkts, unhashedSubpkts, hashLeft2, sigMPIs) {
  return concat(
    new Uint8Array([4, sigType, 22, 8]), // version, type, EdDSA, SHA-256
    u16be(hashedSubpkts.length),
    hashedSubpkts,
    u16be(unhashedSubpkts.length),
    unhashedSubpkts,
    hashLeft2,
    sigMPIs,
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a self-signed OpenPGP v4 certificate from two HSM keys.
 *
 * @param {object} hem       HEM instance (from hem-sdk.js)
 * @param {string} token     Bearer JWT with keymgmt:use scope for kid_sign
 * @param {string} kid_sign  Ed25519 primary key ID in HSM
 * @param {string} kid_ecdh  X25519 ECDH subkey ID in HSM
 * @param {string} email     User email address (UID = "<email>")
 * @param {object} [opts]
 * @param {number} [opts.timestamp]  Key creation timestamp (default: now)
 * @returns {Promise<{ cert: Uint8Array, fingerprint: Uint8Array, keyId: Uint8Array }>}
 *   cert        — binary OpenPGP public key certificate
 *   fingerprint — 20-byte SHA-1 fingerprint of primary key
 *   keyId       — 8-byte key ID of primary key
 */
// ---------------------------------------------------------------------------
// Cleartext signed message
// ---------------------------------------------------------------------------

/** Normalize text for cleartext signing: strip trailing whitespace, CRLF line endings */
function canonicalizeText(text) {
  return text
    .split('\n')
    .map(line => line.replace(/\r$/, '').replace(/[ \t]+$/, ''))
    .join('\r\n');
}

/**
 * Sign a message as OpenPGP cleartext signed message.
 *
 * @param {object}     hem       HEM instance
 * @param {string}     token     JWT with keymgmt:use:<kid_sign> scope
 * @param {string}     kid_sign  Ed25519 key ID in HSM
 * @param {Uint8Array} keyId8    8-byte OpenPGP key ID of the signing key
 * @param {string}     message   Plaintext message to sign
 * @returns {Promise<string>}  ASCII-armored cleartext signed message
 */
export async function signCleartextMessage(hem, token, kid_sign, keyId8, message) {
  const ts = Math.floor(Date.now() / 1000);

  const canonical = canonicalizeText(message);
  const msgBytes  = new TextEncoder().encode(canonical);

  const hashedSubpkts = sigCreationTime(ts);
  const hashPrefix    = sigHashPrefix(0x01, 22, 8, hashedSubpkts); // 0x01 = canonical text
  const trailer       = sigTrailer(hashPrefix);

  const hash  = await sha256(concat(msgBytes, hashPrefix, trailer));
  const sig64 = await hem.exdsaSignBytes(token, kid_sign, hash, 'Ed25519');

  const unhashedSubpkts = issuerSubpkt(keyId8);
  const sigBody = buildSigPacketBody(
    0x01, hashedSubpkts, unhashedSubpkts,
    hash.slice(0, 2),
    encodeEddsaSignatureMPIs(sig64),
  );
  const sigPkt = packet(2, sigBody);

  // Dash-escape lines starting with '-'
  const escaped = message.split('\n')
    .map(line => line.startsWith('-') ? '- ' + line : line)
    .join('\n');

  const b64    = btoa(String.fromCharCode(...sigPkt));
  const lines  = b64.match(/.{1,76}/g).join('\n');
  const crc    = computeCrc24(sigPkt);
  const crcB64 = btoa(String.fromCharCode((crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF));

  return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n${escaped}\n-----BEGIN PGP SIGNATURE-----\n\n${lines}\n=${crcB64}\n-----END PGP SIGNATURE-----\n`;
}

export async function buildCertificate(hem, token, kid_sign, kid_ecdh, email, opts = {}) {
  const ts = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const uid = email;
  // expiryTimestamp is an absolute Unix timestamp; convert to seconds-from-creation for subpacket
  const expirySeconds = opts.expiryTimestamp ? (opts.expiryTimestamp - ts) : 0;

  // 1. Fetch public keys from HSM
  // token must be scoped to keymgmt:use:<kid_sign> (used for signing + getPubKey of sign key)
  // opts.ecdhToken must be scoped to keymgmt:use:<kid_ecdh> (for getPubKey of ecdh key)
  const ecdhToken = opts.ecdhToken ?? token;
  const signKeyInfo = await hem.getPubKey(token, kid_sign);
  const ecdhKeyInfo = await hem.getPubKey(ecdhToken, kid_ecdh);

  const signPub32 = fromB64(signKeyInfo.pubkey); // 32-byte Ed25519 public key
  const ecdhPub32 = fromB64(ecdhKeyInfo.pubkey); // 32-byte X25519 public key

  // 2. Build key bodies (without packet headers)
  const primaryKeyBody = buildEd25519KeyBody(signPub32, ts);
  const subkeyBody     = buildX25519SubkeyBody(ecdhPub32, ts);
  const uidBody        = buildUidBody(uid);

  // 3. Compute key ID and fingerprints
  const keyId              = await computeKeyId(primaryKeyBody);
  const fingerprint        = await computeFingerprint(primaryKeyBody);
  const ecdhFingerprint    = await computeFingerprint(subkeyBody);

  // 4. Build UID certification signature (type 0x13)
  const certHashedSubpkts = concat(
    sigCreationTime(ts),
    keyFlagsSubpkt(KEY_FLAG_CERT_SIGN),
    preferredSymAlgos(),
    preferredHashAlgos(),
    preferredCompression(),
    featuresSubpkt(),
    ...(expirySeconds > 0 ? [keyExpirationTimeSubpkt(expirySeconds)] : []),
  );
  const certHashPrefix = sigHashPrefix(0x13, 22, 8, certHashedSubpkts);
  const certHash = await hashUidCertification(primaryKeyBody, uidBody, certHashPrefix);
  const certSig64 = await hem.exdsaSignBytes(token, kid_sign, certHash, 'Ed25519');
  // Ed25519ph = pre-hashed variant (we pass the SHA-256 hash of the data to the HSM)
  const certUnhashedSubpkts = issuerSubpkt(keyId);
  const certSigBody = buildSigPacketBody(
    0x13,
    certHashedSubpkts,
    certUnhashedSubpkts,
    certHash.slice(0, 2),
    encodeEddsaSignatureMPIs(certSig64),
  );

  // 5. Build subkey binding signature (type 0x18)
  const subkeyHashedSubpkts = concat(
    sigCreationTime(ts),
    keyFlagsSubpkt(KEY_FLAG_ENCRYPT),
    ...(expirySeconds > 0 ? [keyExpirationTimeSubpkt(expirySeconds)] : []),
  );
  const subkeyHashPrefix = sigHashPrefix(0x18, 22, 8, subkeyHashedSubpkts);
  const subkeyHash = await hashSubkeyBinding(primaryKeyBody, subkeyBody, subkeyHashPrefix);
  const subkeySig64 = await hem.exdsaSignBytes(token, kid_sign, subkeyHash, 'Ed25519');
  const subkeyUnhashedSubpkts = issuerSubpkt(keyId);
  const subkeySigBody = buildSigPacketBody(
    0x18,
    subkeyHashedSubpkts,
    subkeyUnhashedSubpkts,
    subkeyHash.slice(0, 2),
    encodeEddsaSignatureMPIs(subkeySig64),
  );

  // 6. Assemble certificate
  // Tag 6 = public key, tag 13 = user ID, tag 2 = signature, tag 14 = public subkey
  const cert = concat(
    packet(6,  primaryKeyBody),
    packet(13, uidBody),
    packet(2,  certSigBody),
    packet(14, subkeyBody),
    packet(2,  subkeySigBody),
  );

  return { cert, fingerprint, keyId, ecdhFingerprint };
}

/**
 * Export a certificate as ASCII-armored OpenPGP public key block.
 */
export function armorCertificate(certBytes) {
  const b64 = btoa(String.fromCharCode(...certBytes));
  const lines = b64.match(/.{1,76}/g).join('\n');
  const crc24 = computeCrc24(certBytes);
  const crcB64 = btoa(String.fromCharCode((crc24 >> 16) & 0xFF, (crc24 >> 8) & 0xFF, crc24 & 0xFF));
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${lines}\n=${crcB64}\n-----END PGP PUBLIC KEY BLOCK-----\n`;
}

function computeCrc24(data) {
  let crc = 0xB704CE;
  for (const b of data) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x864CFB;
    }
  }
  return crc & 0xFFFFFF;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fromB64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
