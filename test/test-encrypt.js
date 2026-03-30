/**
 * test-encrypt.js — Encrypt a message to a WKD recipient.
 *
 * Usage:
 *   node test/test-encrypt.js --to alice@proton.me --message "Hello, Alice!"
 *   node test/test-encrypt.js --to alice@proton.me --file plaintext.eml
 *
 * Output:
 *   ASCII-armored PGP message on stdout.
 */

import { encryptMessage } from '../src/openpgp-bridge.js';
import { parseArgs } from './util.js';
import fs from 'node:fs';

const args = parseArgs(process.argv.slice(2));
const to   = args.to ?? args.email;
if (!to) { console.error('Usage: --to <email>'); process.exit(1); }

const plaintext = args.message ?? (args.file ? fs.readFileSync(args.file, 'utf8') : 'Test message from encedo-pgp-js');

console.error(`Encrypting to: ${to}`);
const armored = await encryptMessage(plaintext, [to]);
console.log(armored);
console.error('Done. Pipe to file or send via Carbonio.');
