/**
 * test-sign.js — Sign a message using an HSM Ed25519 key.
 *
 * Usage:
 *   node test/test-sign.js \
 *     --hsm https://my.ence.do \
 *     --email jan@pgptest.pl \
 *     --message "Hello World" \
 *     [--password <pw>]
 *
 * Output:
 *   ASCII-armored signed message on stdout.
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import * as openpgp from 'openpgp';
import { DESCR, decodeDescr } from '../src/keychain.js';
import { parseArgs, prompt } from './util.js';
import fs from 'node:fs';

const args     = parseArgs(process.argv.slice(2));
const hsmUrl   = args.hsm   ?? 'https://my.ence.do';
const email    = args.email ?? 'test@pgptest.pl';
const password = args.password ?? await prompt('HSM password: ');
const plaintext = args.message ?? (args.file ? fs.readFileSync(args.file, 'utf8') : 'Test signed message');
const certPath  = args.cert;

if (!certPath) {
  console.error('Usage: --cert path/to/pubkey.asc (required for signing key metadata)');
  process.exit(1);
}

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

const listToken = await hem.authorizePassword(password, 'keymgmt:list');

// Find signing key
const keys = await hem.searchKeys(listToken, DESCR.selfSign(email));
const signKey = keys.find(k => decodeDescr(k.description) === DESCR.selfSign(email));
if (!signKey) {
  console.error(`No sign key found for ${email} — run test-keygen.js first`);
  process.exit(1);
}
console.error(`Sign kid: ${signKey.kid}`);

const useToken = await hem.authorizePassword(password, `keymgmt:use:${signKey.kid}`);

// Sign the data using HSM directly (detached signature)
const msgBytes  = new TextEncoder().encode(plaintext);
const sig64     = await hem.exdsaSignBytes(useToken, signKey.kid, msgBytes, 'Ed25519');
const sigHex    = Buffer.from(sig64).toString('hex');

console.error(`Signature (hex): ${sigHex}`);

// TODO: wrap in proper OpenPGP signed message format using the cert
// For now, output the raw signature alongside the message for verification
console.log('=== MESSAGE ===');
console.log(plaintext);
console.log('=== Ed25519 SIGNATURE (base64) ===');
console.log(btoa(String.fromCharCode(...sig64)));
console.error('\nVerify with: gpg --verify (after cert-builder integration in Phase 3)');
