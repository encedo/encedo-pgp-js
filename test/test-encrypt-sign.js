/**
 * test-encrypt-sign.js — Round-trip test: sign+encrypt → decrypt+verify via HSM.
 *
 * Usage:
 *   node test/test-encrypt-sign.js \
 *     --hsm https://my.ence.do \
 *     --email krzysztof@encedo.com \
 *     [--to recipient@domain.tld | --armoredKey path/to/pubkey.asc] \
 *     [--message "Hello"] \
 *     [--password <pw>]
 *
 *   If --to / --armoredKey are omitted, the message is encrypted back to the
 *   sender (self-loop) so the test is self-contained.
 *
 * The test:
 *  1. Finds selfSign + selfEcdh keys in HSM for --email
 *  2. encryptAndSign → produces armored message
 *  3. decryptAndVerify → decrypts + verifies signature (using WKD pubkey of sender)
 *  4. Asserts plaintext matches and signature is valid
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import { encryptAndSign, decryptAndVerify } from '../src/openpgp-bridge.js';
import { DESCR, decodeDescr, findSelfSign, findSelfEcdh } from '../src/keychain.js';
import { lookupKey } from '../src/wkd-client.js';
import { parseArgs, prompt } from './util.js';
import * as openpgp from 'openpgp';

const args      = parseArgs(process.argv.slice(2));
const hsmUrl    = args.hsm      ?? 'https://my.ence.do';
const email     = args.email    ?? 'krzysztof@encedo.com';
const toEmail   = args.to       ?? email;         // default: self-loop
const keyFile   = args.armoredKey;
const message   = args.message  ?? `Round-trip test at ${new Date().toISOString()}`;
const password  = args.password ?? await prompt('HSM password: ');

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

// ── 1. Find own keys in HSM ───────────────────────────────────────────────
const listToken = await hem.authorizePassword(password, 'keymgmt:list');

const ownKeys = await hem.searchKeys(listToken, DESCR.selfAll(email));
const signKey = findSelfSign(ownKeys, email);
const ecdhKey = findSelfEcdh(ownKeys, email);
if (!signKey) { console.error(`No Ed25519 key in HSM for ${email}`); process.exit(1); }
if (!ecdhKey) { console.error(`No X25519 key in HSM for ${email}`); process.exit(1); }

console.error(`Ed25519 kid : ${signKey.kid}`);
console.error(`X25519  kid : ${ecdhKey.kid}`);

const signToken = await hem.authorizePassword(password, `keymgmt:use:${signKey.kid}`);
const ecdhToken = await hem.authorizePassword(password, `keymgmt:use:${ecdhKey.kid}`);

// ── 2. Get keyId8 + ecdhFingerprint from WKD cert ─────────────────────────
//   WKD cert is the authoritative source — keyId is whatever timestamp it was
//   built with. No need to re-derive from HSM.
console.error('Fetching sender cert from WKD...');
const senderKeyBytes = await lookupKey(email);
if (!senderKeyBytes) { console.error(`No WKD key found for ${email} — publish key first`); process.exit(1); }
const senderPubKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
const keyId8 = senderPubKey.keyPacket.getKeyID().write();
const ecdhFingerprint = Uint8Array.from(senderPubKey.getSubkeys()[0].getFingerprint().match(/.{2}/g).map(b => parseInt(b, 16)));
console.error(`keyId       : ${Buffer.from(keyId8).toString('hex').toUpperCase()}`);
console.error(`ECDH fingerprint: ${Buffer.from(ecdhFingerprint).toString('hex').toUpperCase()}`);

// ── 3. Resolve recipient ───────────────────────────────────────────────────
let recipient;
if (keyFile) {
  const { default: fs } = await import('node:fs');
  recipient = fs.readFileSync(keyFile, 'utf8').trim();
  console.error(`Recipient   : ${toEmail} (from file ${keyFile})`);
} else {
  recipient = toEmail;
  console.error(`Recipient   : ${toEmail}`);
}

// ── 4. Sign + Encrypt ─────────────────────────────────────────────────────
console.error(`\nPlaintext   : ${message}`);
console.error('Signing and encrypting...');
const armored = await encryptAndSign(hem, signToken, signKey.kid, keyId8, [recipient], message);
console.error(`Armored msg : ${armored.length} bytes`);
if (args.debug) console.log(armored);

// ── 5. Get sender pubkey for verification — already fetched from WKD above ─
const armoredSenderKey = senderPubKey.armor();
console.error(`Sender pubkey from WKD.`);

// ── 6. Get our ECDH pubkey (needed for decryption) ────────────────────────
//   We decrypt to ourselves (self-loop) or recipient if --to is self.
//   If encrypting to a different recipient, skip decryption test.
if (toEmail !== email) {
  console.error(`\nRecipient (${toEmail}) ≠ sender (${email}) — skipping decrypt step.`);
  console.error('✓ encryptAndSign succeeded. Pipe to recipient for manual verification.');
  console.log(armored);
  process.exit(0);
}

const pubInfo = await hem.getPubKey(ecdhToken, ecdhKey.kid);
const pubkey32 = Uint8Array.from(atob(pubInfo.pubkey), c => c.charCodeAt(0));

// ── 7. Decrypt + Verify ───────────────────────────────────────────────────
console.error('\nDecrypting and verifying signature...');
const result = await decryptAndVerify(
  armored, hem, ecdhToken, ecdhKey.kid, pubkey32, ecdhFingerprint,
  armoredSenderKey
);

console.error(`Plaintext   : ${result.data}`);
console.error(`Sig valid   : ${result.valid}`);
console.error(`Sig keyID   : ${result.keyID}`);

// ── 8. Assert ─────────────────────────────────────────────────────────────
let ok = true;

if (result.data !== message) {
  console.error(`FAIL: plaintext mismatch`);
  console.error(`  expected : ${JSON.stringify(message)}`);
  console.error(`  got      : ${JSON.stringify(result.data)}`);
  ok = false;
}

if (!result.valid) {
  console.error('FAIL: signature not valid');
  ok = false;
}

if (ok) {
  console.error('\n✓ PASS — sign+encrypt → decrypt+verify round-trip OK');
} else {
  console.error('\n✗ FAIL');
  process.exit(1);
}

function atob(b64) {
  return Buffer.from(b64, 'base64').toString('binary');
}
