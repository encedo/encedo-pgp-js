/**
 * test-verify-hsm.js — Verify an OpenPGP cleartext signed message via the HSM.
 *
 * The signer's public key must already exist in the HSM (generated via keygen).
 * The key is found by email address using DESCR.selfSign() pattern.
 *
 * Usage:
 *   node test/test-verify-hsm.js \
 *     --hsm https://my.ence.do \
 *     --email krzysztof@encedo.com \
 *     --file /tmp/signed.asc \
 *     [--password <pw>]
 *
 *   # Or pipe from test-sign.js:
 *   node test/test-sign.js --email krzysztof@encedo.com --message "Hello" 2>/dev/null \
 *     | node test/test-verify-hsm.js --email krzysztof@encedo.com
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import { verifySignedMessageHSM } from '../src/openpgp-bridge.js';
import { DESCR, decodeDescr } from '../src/keychain.js';
import { parseArgs } from './util.js';
import fs from 'node:fs';
import readline from 'node:readline';

const args   = parseArgs(process.argv.slice(2));
const hsmUrl = args.hsm   ?? 'https://my.ence.do';
const email  = args.email ?? 'krzysztof@encedo.com';

// Read signed message from --file or stdin FIRST — before any prompt that uses readline
let armoredSigned;
if (args.file) {
  armoredSigned = fs.readFileSync(args.file, 'utf8');
} else {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  armoredSigned = chunks.join('');
}

// Read password: if stdin was a pipe we must use /dev/tty, otherwise stdin is fine
async function promptPassword(question) {
  const isTTY = process.stdin.isTTY;
  const input = isTTY ? process.stdin : fs.createReadStream('/dev/tty');
  const rl = readline.createInterface({ input, output: process.stderr });
  return new Promise(resolve => rl.question(question, ans => {
    rl.close();
    if (!isTTY) input.destroy();
    resolve(ans);
  }));
}

const password = args.password ?? await promptPassword('HSM password: ');
armoredSigned = armoredSigned.trim();
if (!armoredSigned) {
  console.error('No signed message provided (use --file or pipe from stdin)');
  process.exit(1);
}

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

// Find sign key — check selfSign first, then peerSign
const listToken = await hem.authorizePassword(password, 'keymgmt:list');
const selfKeys = await hem.searchKeys(listToken, DESCR.selfSign(email));
let signKey = selfKeys.find(k => decodeDescr(k.description) === DESCR.selfSign(email));
if (!signKey) {
  const peerKeys = await hem.searchKeys(listToken, DESCR.peerSign(email));
  signKey = peerKeys.find(k => decodeDescr(k.description) === DESCR.peerSign(email));
}
if (!signKey) {
  console.error(`No sign key found in HSM for ${email}`);
  process.exit(1);
}
console.error(`Sign kid: ${signKey.kid}`);

const useToken = await hem.authorizePassword(password, `keymgmt:use:${signKey.kid}`);

try {
  await verifySignedMessageHSM(hem, useToken, signKey.kid, armoredSigned);
  console.log('✓ VALID — signature verified by HSM');
} catch (e) {
  if (e.message?.includes('406')) {
    console.error('✗ INVALID — signature verification failed (HSM returned 406)');
  } else {
    console.error(`✗ ERROR: ${e.message}`);
  }
  process.exit(1);
}
