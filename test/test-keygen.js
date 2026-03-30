/**
 * test-keygen.js — Generate Ed25519 + X25519 key pair in HSM and build OpenPGP certificate.
 *
 * Usage:
 *   node test/test-keygen.js --hsm https://my.ence.do --email jan@pgptest.pl [--password <pw>]
 *
 * Output:
 *   Prints kid_sign, kid_ecdh, and ASCII-armored public key cert to stdout.
 *   Cert can be verified with: gpg --import < output.asc && gpg --list-keys
 */

import { HEM } from '../../hem-sdk-js/hem-sdk.js';
import { buildCertificate, armorCertificate } from '../src/cert-builder.js';
import { DESCR, encodeDescr } from '../src/keychain.js';
import { parseArgs, prompt } from './util.js';

const args = parseArgs(process.argv.slice(2));
const hsmUrl  = args.hsm   ?? 'https://my.ence.do';
const email   = args.email ?? 'test@pgptest.pl';

const hem = new HEM(hsmUrl, { debug: !!args.debug });
await hem.hemCheckin();  // fast-fail before asking for password

const password = args.password ?? await prompt('HSM password: ');

const listToken = await hem.authorizePassword(password, 'keymgmt:list');
const genToken  = await hem.authorizePassword(password, 'keymgmt:gen');

// Generate Ed25519 signing key
const signDescrPlain = DESCR.selfSign(email);
const signDescrB64   = encodeDescr(signDescrPlain);
const { kid: kid_sign } = await hem.createKeyPair(genToken, `pgp-sign-${email}`, 'ED25519', signDescrB64);
console.error(`kid_sign = ${kid_sign}`);

// Generate X25519 ECDH key
const ecdhDescrPlain = DESCR.selfEcdh(email);
const ecdhDescrB64   = encodeDescr(ecdhDescrPlain);
const { kid: kid_ecdh } = await hem.createKeyPair(genToken, `pgp-ecdh-${email}`, 'CURVE25519', ecdhDescrB64);
console.error(`kid_ecdh = ${kid_ecdh}`);

// Authorize for key use — separate token per key (scope must match KID)
const useToken     = await hem.authorizePassword(password, `keymgmt:use:${kid_sign}`);
const useEcdhToken = await hem.authorizePassword(password, `keymgmt:use:${kid_ecdh}`);

// Build and output the certificate
const { cert, fingerprint, keyId } = await buildCertificate(hem, useToken, kid_sign, kid_ecdh, email, { ecdhToken: useEcdhToken });
const armored = armorCertificate(cert);

console.log(armored);
console.error(`fingerprint = ${Buffer.from(fingerprint).toString('hex').toUpperCase()}`);
console.error(`key_id      = ${Buffer.from(keyId).toString('hex').toUpperCase()}`);
console.error(`\nDone. Import with: node test/test-keygen.js ... | gpg --import`);
