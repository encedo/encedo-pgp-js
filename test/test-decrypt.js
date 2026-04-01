/**
 * test-decrypt.js — Decrypt a PGP-encrypted message using an HSM key.
 *
 * Usage:
 *   node test/test-decrypt.js \
 *     --hsm https://my.ence.do \
 *     --email jan@pgptest.pl \
 *     --eml path/to/encrypted.eml \
 *     [--password <pw>]
 *
 * The script looks up kid_ecdh from HSM by DESCR, fetches pubkey and fingerprint,
 * then decrypts the message.
 *
 * Output: plaintext message on stdout.
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import { decryptMessage } from '../src/openpgp-bridge.js';
import { DESCR, decodeDescr, findSelfEcdh } from '../src/keychain.js';
import { lookupKey } from '../src/wkd-client.js';
import { parseArgs, prompt } from './util.js';
import fs from 'node:fs';
import * as openpgp from 'openpgp';

const args     = parseArgs(process.argv.slice(2));
const hsmUrl   = args.hsm   ?? 'https://my.ence.do';
const email    = args.email ?? 'test@pgptest.pl';
const emlPath  = args.eml   ?? args.file;
const password = args.password ?? await prompt('HSM password: ');

if (!emlPath) { console.error('Usage: --eml <path>'); process.exit(1); }

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

// Authorize for key listing and use
const listToken = await hem.authorizePassword(password, 'keymgmt:list');

// Find our ECDH key by DESCR
const keys = await hem.searchKeys(listToken, DESCR.selfAll(email));
const ecdhKey = findSelfEcdh(keys, email);
if (!ecdhKey) {
  console.error(`No ECDH key found for ${email} — run test-keygen.js first`);
  process.exit(1);
}
console.error(`ECDH kid: ${ecdhKey.kid}`);

const useToken = await hem.authorizePassword(password, `keymgmt:use:${ecdhKey.kid}`);

// Fetch public key and compute fingerprint
const pubInfo = await hem.getPubKey(useToken, ecdhKey.kid);
const pubkey32 = fromB64(pubInfo.pubkey);

// Get subkey fingerprint from WKD cert (or --cert file)
let fingerprint;
if (args.cert) {
  const certData = fs.readFileSync(args.cert, 'utf8');
  const key = await openpgp.readKey({ armoredKey: certData });
  const subkeys = key.getSubkeys();
  fingerprint = fromHex(subkeys[0].getFingerprint());
  console.error(`Subkey fingerprint (from cert file): ${Buffer.from(fingerprint).toString('hex').toUpperCase()}`);
} else {
  const keyBytes = await lookupKey(email);
  if (!keyBytes) { console.error(`No WKD key found for ${email} — use --cert path/to/pubkey.asc`); process.exit(1); }
  const key = await openpgp.readKey({ binaryKey: keyBytes });
  const subkeys = key.getSubkeys();
  fingerprint = fromHex(subkeys[0].getFingerprint());
  console.error(`Subkey fingerprint (from WKD): ${Buffer.from(fingerprint).toString('hex').toUpperCase()}`);
}

// Read the encrypted message
const armoredMessage = fs.readFileSync(emlPath, 'utf8');

console.error('Decrypting...');
const plaintext = await decryptMessage(armoredMessage, hem, useToken, ecdhKey.kid, pubkey32, fingerprint);

console.log(plaintext);

function fromB64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function fromHex(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}
