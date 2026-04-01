/**
 * test-wkd-lookup.js — Look up a public key via WKD.
 *
 * Usage:
 *   node test/test-wkd-lookup.js --email alice@proton.me
 *
 * Output:
 *   Prints hex key ID and armored public key to stdout.
 *   Key can be verified with:  node test/test-wkd-lookup.js ... | gpg --import
 */

import * as openpgp from 'openpgp';
import { lookupKey, wkdHash } from '../src/wkd-client.js';
import { parseArgs } from './util.js';

const args  = parseArgs(process.argv.slice(2));
const email = args.email ?? 'test@pgptest.pl';

console.error(`Looking up WKD key for: ${email}`);
const [local, domain] = email.split('@');
console.error(`  hash: ${await wkdHash(local)} (Z-Base-32 of SHA1("${local.toLowerCase()}"))`);

const keyBytes = await lookupKey(email);
if (!keyBytes) {
  console.error('Key not found (404 from both advanced and direct WKD methods)');
  process.exit(1);
}

console.error(`Found key: ${keyBytes.length} bytes`);

try {
  const key = await openpgp.readKey({ binaryKey: keyBytes });
  const primaryUser = await key.getPrimaryUser();
  console.error(`  UID:         ${primaryUser.user.userID.userID}`);
  console.error(`  Fingerprint: ${key.getFingerprint().toUpperCase()}`);
  console.error(`  Algorithm:   ${key.keyPacket.algorithm}`);
  console.log(await openpgp.armor(openpgp.enums.armor.publicKey, keyBytes));
} catch (e) {
  // Might be a raw public key packet—just hex dump
  console.error('Could not parse as OpenPGP key, raw hex:');
  console.log(Buffer.from(keyBytes).toString('hex'));
}
