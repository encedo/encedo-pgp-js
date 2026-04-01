/**
 * wkd-client.js — WKD (Web Key Directory) public key lookup.
 *
 * Tries advanced method first (openpgpkey.<domain>), fallback to direct method.
 * Returns raw binary OpenPGP pubkey packet or null if not found.
 *
 * RFC: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/
 */

import { sha1 } from './runtime/index.js';

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/**
 * Compute the WKD Z-Base-32 hash for the local part of an email address.
 * Must match the server-side wkd.py implementation.
 */
export async function wkdHash(localPart) {
  const hashBytes = await sha1(new TextEncoder().encode(localPart.toLowerCase()));
  return zbase32(hashBytes);
}

const ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function zbase32(bytes) {
  let buf = 0, bits = 0, out = '';
  for (const byte of bytes) {
    buf = (buf << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ZBASE32[(buf >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += ZBASE32[(buf << (5 - bits)) & 0x1f];
  return out;
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/**
 * Look up an OpenPGP public key via WKD.
 * Tries advanced method first, then falls back to direct method.
 *
 * @param {string} email  e.g. 'jan@pgptest.pl'
 * @returns {Promise<Uint8Array|null>}  Binary OpenPGP pubkey packet, or null if not found
 */
export async function lookupKey(email) {
  const [local, domain] = email.split('@');
  const hash = await wkdHash(local);

  // Advanced method: openpgpkey.<domain> with domain path
  try {
    const url = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${encodeURIComponent(local)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const buf = await res.arrayBuffer();
      return new Uint8Array(buf);
    }
  } catch { /* fall through to direct method */ }

  // Direct method: <domain> with direct path
  try {
    const url = `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${encodeURIComponent(local)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const buf = await res.arrayBuffer();
      return new Uint8Array(buf);
    }
  } catch { /* key not found */ }

  return null;
}
