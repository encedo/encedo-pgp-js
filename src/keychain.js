/**
 * keychain.js — DESCR schema for PGP keys stored in Encedo HEM.
 *
 * Compact format (comma-separated, prefix ETSPGP):
 *   ETSPGP:self,<email>,sign,<iat>[,<exp>]  — own Ed25519 signing key
 *   ETSPGP:self,<email>,ecdh,<iat>[,<exp>]  — own X25519 ECDH key
 *   ETSPGP:peer,<email>,sign                — peer Ed25519 (for verify via HSM)
 *   ETSPGP:peer,<email>,ecdh                — peer X25519 (for encrypt via HSM)
 *
 * iat / exp: Unix timestamps in seconds (JWT convention).
 *   iat — key creation time, baked into the OpenPGP cert fingerprint/keyId
 *   exp — optional expiry, informational only
 *
 * DESCR values are base64-encoded when passed to HEM API.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// DESCR string builders
// ---------------------------------------------------------------------------

export const DESCR = {
  /** Own signing key. iat required (= keygen timestamp). */
  selfSign: (email, iat, exp) =>
    exp ? `ETSPGP:self,${email},sign,${iat},${exp}`
        : `ETSPGP:self,${email},sign,${iat}`,

  /** Own ECDH key. iat required (= keygen timestamp). */
  selfEcdh: (email, iat, exp) =>
    exp ? `ETSPGP:self,${email},ecdh,${iat},${exp}`
        : `ETSPGP:self,${email},ecdh,${iat}`,

  /** Peer signing key (no timestamp — we don't control peer's keygen). */
  peerSign: (email) => `ETSPGP:peer,${email},sign`,

  /** Peer ECDH key. */
  peerEcdh: (email) => `ETSPGP:peer,${email},ecdh`,

  // Prefix patterns for searchKeys() — must end at a field boundary
  selfAll: (email) => `ETSPGP:self,${email},`,
  peerAll: (email) => `ETSPGP:peer,${email},`,
  allPgp:  ()      => 'ETSPGP:',
};

// ---------------------------------------------------------------------------
// Encoding helpers (HEM API stores descr as base64)
// ---------------------------------------------------------------------------

/** Encode a plain DESCR string for use in createKeyPair() / importPublicKey() */
export function encodeDescr(plainDescr) {
  return btoa(String.fromCharCode(...enc.encode(plainDescr)));
}

/** Decode a Uint8Array description (from listKeys/searchKeys) back to a string */
export function decodeDescr(uint8arr) {
  if (!uint8arr) return '';
  return dec.decode(uint8arr);
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/**
 * Parse a plain DESCR string into structured fields.
 *
 * @param {string} str  Plain (not base64) DESCR string
 * @returns {{ role:'self'|'peer', email:string, type:'sign'|'ecdh', iat:number|null, exp:number|null }|null}
 */
export function parseDescr(str) {
  if (typeof str !== 'string' || !str.startsWith('ETSPGP:')) return null;
  const [role, email, type, iatStr, expStr] = str.slice(7).split(',');
  if (!role || !email || !type) return null;
  return {
    role,
    email,
    type,
    iat: iatStr !== undefined ? Number(iatStr) : null,
    exp: expStr !== undefined ? Number(expStr) : null,
  };
}

// ---------------------------------------------------------------------------
// Key search helpers
// ---------------------------------------------------------------------------

/**
 * Find a key by exact DESCR string.
 * @param {Array} keys        Result array from hem.searchKeys/listKeys
 * @param {string} descrPlain Plain (not base64) DESCR string to match exactly
 */
export function findByDescr(keys, descrPlain) {
  return keys.find(k => decodeDescr(k.description) === descrPlain) ?? null;
}

/** Find own signing key (any iat) for email. */
export function findSelfSign(keys, email) {
  return keys.find(k => {
    const d = parseDescr(decodeDescr(k.description));
    return d?.role === 'self' && d?.email === email && d?.type === 'sign';
  }) ?? null;
}

/** Find own ECDH key (any iat) for email. */
export function findSelfEcdh(keys, email) {
  return keys.find(k => {
    const d = parseDescr(decodeDescr(k.description));
    return d?.role === 'self' && d?.email === email && d?.type === 'ecdh';
  }) ?? null;
}

/** Find peer signing key for email. */
export function findPeerSign(keys, email) {
  return findByDescr(keys, DESCR.peerSign(email));
}

/** Find peer ECDH key for email. */
export function findPeerEcdh(keys, email) {
  return findByDescr(keys, DESCR.peerEcdh(email));
}

/**
 * Find both own keys for an email.
 * @returns {{ sign: key|null, ecdh: key|null }}
 */
export function findOwnKeys(keys, email) {
  return {
    sign: findSelfSign(keys, email),
    ecdh: findSelfEcdh(keys, email),
  };
}

