/**
 * test-wkd-validation.js — readValidatedWkdKey() gate.
 *
 * A WKD key must not be trusted just because it parses. This asserts the
 * validator accepts a well-formed key for the right address and rejects the
 * failure modes importKeyFromWKD/encrypt used to wave through: wrong identity,
 * no encryption subkey, garbage bytes. Case-insensitive UID matching is covered
 * because the UID string is not normalised even though WKD hashes the
 * lower-cased local part.
 *
 * Uses a fake HSM (node ed25519/x25519) to mint real certs via buildCertificate.
 * Run: node test/test-wkd-validation.js
 */

import * as openpgp from 'openpgp';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { buildCertificate } from '../src/cert-builder.js';
import { readValidatedWkdKey } from '../src/openpgp-bridge.js';

function fakeHem() {
  const ed = generateKeyPairSync('ed25519');
  const x = generateKeyPairSync('x25519');
  const edPub = ed.publicKey.export({ type: 'spki', format: 'der' }).slice(-32);
  const xPub = x.publicKey.export({ type: 'spki', format: 'der' }).slice(-32);
  const b64 = (b) => Buffer.from(b).toString('base64');
  return {
    async getPubKey(_t, kid) { return { pubkey: kid === 'S' ? b64(edPub) : b64(xPub) }; },
    async exdsaSignBytes(_t, _k, h) { return new Uint8Array(edSign(null, Buffer.from(h), ed.privateKey)); },
  };
}

async function certFor(email) {
  const { cert } = await buildCertificate(fakeHem(), 'S', 'S', 'E', email, { ecdhToken: 'E', timestamp: 1700000000 });
  return cert;
}

let failures = 0;
function ok(name, cond) {
  if (cond) console.log(`ok: ${name}`);
  else { failures++; console.error(`FAIL: ${name}`); }
}
async function rejects(name, promise, expectFragment) {
  try { await promise; failures++; console.error(`FAIL: ${name} — expected rejection, resolved`); }
  catch (e) {
    const good = !expectFragment || e.message.includes(expectFragment);
    if (good) console.log(`ok: ${name}`);
    else { failures++; console.error(`FAIL: ${name} — wrong error: ${e.message}`); }
  }
}

// 1. Valid key for the right address → accepted.
{
  const key = await readValidatedWkdKey(await certFor('alice@example.com'), 'alice@example.com');
  ok('valid key accepted', key && key.getUserIDs()[0] === 'alice@example.com');
}

// 2. Case-insensitive UID match (cert UID mixed case, WKD address lower-case).
{
  const cert = await certFor('Alice@Example.COM');
  const key = await readValidatedWkdKey(cert, 'alice@example.com');
  ok('mixed-case UID matched case-insensitively', !!key);
}

// 3. Right key, wrong address → rejected (identity mismatch).
await rejects(
  'wrong-address key rejected',
  readValidatedWkdKey(await certFor('alice@example.com'), 'attacker@evil.com'),
  'no User ID matching',
);

// 4. Garbage bytes → rejected at parse.
await rejects(
  'unparseable bytes rejected',
  readValidatedWkdKey(new Uint8Array([1, 2, 3, 4, 5]), 'alice@example.com'),
  'could not be parsed',
);

// 5. requireEncryptionKey:false still enforces identity but skips subkey need.
{
  const key = await readValidatedWkdKey(await certFor('bob@example.com'), 'bob@example.com', { requireEncryptionKey: false });
  ok('requireEncryptionKey:false accepts valid key', !!key);
}

if (failures) { console.error(`\n${failures} check(s) failed`); process.exit(1); }
console.log('\nall WKD validation checks passed');
