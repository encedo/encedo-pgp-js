/**
 * test-wkd-import.js — Import a public key from WKD into the HSM keychain.
 *
 * Imports both Ed25519 (sign) and X25519 (ecdh) keys with DESCR.peerSign/peerEcdh tags,
 * so they can be found by verifySignedMessageHSM() and future HSM-based encrypt.
 *
 * Usage:
 *   node test/test-wkd-import.js \
 *     --hsm https://my.ence.do \
 *     --email bob@encedo.com \
 *     [--password <pw>]
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import { importKeyFromWKD } from '../src/openpgp-bridge.js';
import { parseArgs, prompt } from './util.js';

const args     = parseArgs(process.argv.slice(2));
const hsmUrl   = args.hsm      ?? 'https://my.ence.do';
const email    = args.email    ?? 'bob@encedo.com';
const password = args.password ?? await prompt('HSM password: ');

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();

const impToken = await hem.authorizePassword(password, 'keymgmt:imp');

console.error(`Importing WKD keys for: ${email}`);
const { kidSign, kidEcdh } = await importKeyFromWKD(hem, impToken, email);
console.log(`Imported sign key — KID: ${kidSign}`);
console.log(`Imported ecdh key — KID: ${kidEcdh}`);
