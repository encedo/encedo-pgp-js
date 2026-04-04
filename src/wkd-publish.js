/**
 * wkd-publish.js — Publish/revoke OpenPGP public keys via encedo-wkd API.
 */

/**
 * Publish a binary OpenPGP public key to the encedo-wkd server.
 *
 * @param {string}     wkdUrl      Base URL of encedo-wkd, e.g. 'https://mailserver/wkd'
 * @param {string}     email       Recipient email address
 * @param {Uint8Array} pubkeyBytes Binary OpenPGP public key packet
 * @param {string}     [authToken] Carbonio auth token (X-Auth-Token); required when server has carbonio_url set
 * @returns {Promise<{ ok: boolean, hash: string }>}
 */
export async function publishKey(wkdUrl, email, pubkeyBytes, authToken) {
  const pubkey_base64 = btoa(String.fromCharCode(...pubkeyBytes));
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['X-Auth-Token'] = authToken;
  const res = await fetch(`${wkdUrl}/api/publish`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, pubkey_base64 }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`WKD publish failed: HTTP ${res.status} — ${err.error ?? 'unknown error'}`);
  }
  return res.json();
}

/**
 * Revoke (remove) a public key from the encedo-wkd server.
 *
 * @param {string} wkdUrl      Base URL of encedo-wkd
 * @param {string} email       Email address whose key to remove
 * @param {string} [authToken] Carbonio auth token (X-Auth-Token); required when server has carbonio_url set
 * @returns {Promise<{ ok: boolean }>}
 */
export async function revokeKey(wkdUrl, email, authToken) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['X-Auth-Token'] = authToken;
  const res = await fetch(`${wkdUrl}/api/revoke`, {
    method: 'DELETE',
    headers,
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(`WKD revoke failed: HTTP ${res.status} — ${err.error ?? 'unknown error'}`);
  }
  return res.json();
}
