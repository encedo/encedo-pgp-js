/**
 * keychain.js — DESCR schema for PGP keys stored in Encedo HEM.
 *
 * Keys in HSM are identified by their DESCR (description) field.
 * Plain string DESCRs are base64-encoded when passed to HEM API and
 * decoded back to strings for comparison/search.
 *
 * Convention:
 *   PGP:role=self:email=<email>:type=sign   — own Ed25519 signing key
 *   PGP:role=self:email=<email>:type=ecdh   — own X25519 ECDH key
 *   PGP:role=peer:email=<email>:type=sign   — peer's Ed25519 key (stored for verification)
 *   PGP:role=peer:email=<email>:type=ecdh   — peer's X25519 key (stored for encryption)
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// DESCR string builders
// ---------------------------------------------------------------------------

export const DESCR = {
  selfSign: (email, slot = 1) => `PGP:role=self:email=${email}:type=sign:slot=${slot}`,
  selfEcdh: (email, slot = 1) => `PGP:role=self:email=${email}:type=ecdh:slot=${slot}`,
  peerSign: (email)            => `PGP:role=peer:email=${email}:type=sign`,
  peerEcdh: (email)            => `PGP:role=peer:email=${email}:type=ecdh`,

  // Prefix patterns for searchKeys()
  selfAll: (email) => `PGP:role=self:email=${email}`,
  peerAll: (email) => `PGP:role=peer:email=${email}`,
  allPgp:  ()      => 'PGP:',
};

// ---------------------------------------------------------------------------
// Encoding helpers (HEM API stores descr as base64)
// ---------------------------------------------------------------------------

/** Encode a plain DESCR string for use in createKeyPair() */
export function encodeDescr(plainDescr) {
  return btoa(String.fromCharCode(...enc.encode(plainDescr)));
}

/** Decode a Uint8Array description (from listKeys/searchKeys) back to a string */
export function decodeDescr(uint8arr) {
  if (!uint8arr) return '';
  return dec.decode(uint8arr);
}

// ---------------------------------------------------------------------------
// Key search helpers
// ---------------------------------------------------------------------------

/**
 * Find a key by exact DESCR in the result of hem.searchKeys() / hem.listKeys().
 * @param {Array} keys  Result array from hem.searchKeys/listKeys
 * @param {string} descrPlain  Plain (not base64) DESCR string to match exactly
 * @returns {{ kid, label, type, description }|null}
 */
export function findByDescr(keys, descrPlain) {
  return keys.find(k => decodeDescr(k.description) === descrPlain) ?? null;
}

/**
 * Find all own PGP keys for an email from HEM key list.
 * @param {Array} keys  Result from hem.searchKeys(token, DESCR.selfAll(email))
 * @param {string} email
 * @returns {{ sign: key|null, ecdh: key|null }}
 */
export function findOwnKeys(keys, email) {
  return {
    sign: findByDescr(keys, DESCR.selfSign(email)),
    ecdh: findByDescr(keys, DESCR.selfEcdh(email)),
  };
}
