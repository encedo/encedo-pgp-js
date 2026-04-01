/**
 * test-sign.js — Sign a message using an HSM Ed25519 key (OpenPGP cleartext format).
 *
 * Usage:
 *   node test/test-sign.js \
 *     --hsm https://my.ence.do \
 *     --email krzysztof@encedo.com \
 *     --message "Hello World" \
 *     [--password <pw>]
 *
 * Output:
 *   ASCII-armored PGP signed message on stdout.
 *   Verify with: gpg --verify <(node test/test-sign.js ...)
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import * as openpgp from 'openpgp';
import { signCleartextMessage } from '../src/cert-builder.js';
import { lookupKey } from '../src/wkd-client.js';
import { DESCR, decodeDescr, findSelfSign, parseDescr } from '../src/keychain.js';
import { parseArgs, prompt } from './util.js';
import fs from 'node:fs';

const args      = parseArgs(process.argv.slice(2));
const hsmUrl    = args.hsm     ?? 'https://my.ence.do';
const email     = args.email   ?? 'krzysztof@encedo.com';
const password  = args.password ?? await prompt('HSM password: ');
const plaintext = args.message ?? (args.file ? fs.readFileSync(args.file, 'utf8') : 'Test signed message');

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

const listToken = await hem.authorizePassword(password, 'keymgmt:list');

// Find signing key by DESCR
const keys    = await hem.searchKeys(listToken, DESCR.selfAll(email));
const signKey = findSelfSign(keys, email);
if (!signKey) {
  console.error(`No sign key found for ${email} — run test-keygen.js first`);
  process.exit(1);
}
console.error(`Sign kid: ${signKey.kid}`);

// Get key ID from WKD cert
const keyBytes = await lookupKey(email);
if (!keyBytes) {
  console.error(`No WKD key found for ${email} — publish key first`);
  process.exit(1);
}
const pubKey = await openpgp.readKey({ binaryKey: keyBytes });
const keyId8 = Uint8Array.from(pubKey.getKeyID().bytes, c => c.charCodeAt(0));
console.error(`Key ID: ${Buffer.from(keyId8).toString('hex').toUpperCase()}`);

const useToken = await hem.authorizePassword(password, `keymgmt:use:${signKey.kid}`);

const armored = await signCleartextMessage(hem, useToken, signKey.kid, keyId8, plaintext);
console.log(armored);
console.error(`Sign kid: ${signKey.kid}`);

// Get key ID from WKD cert
const keyBytes = await lookupKey(email);
if (!keyBytes) {
  console.error(`No WKD key found for ${email} — publish key first`);
  process.exit(1);
}
const pubKey = await openpgp.readKey({ binaryKey: keyBytes });
const keyId8 = Uint8Array.from(pubKey.getKeyID().bytes, c => c.charCodeAt(0));
console.error(`Key ID: ${Buffer.from(keyId8).toString('hex').toUpperCase()}`);

const useToken = await hem.authorizePassword(password, `keymgmt:use:${signKey.kid}`);

const armored = await signCleartextMessage(hem, useToken, signKey.kid, keyId8, plaintext);
console.log(armored);
