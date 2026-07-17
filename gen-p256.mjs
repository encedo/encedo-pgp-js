// Generuje testowy klucz OpenPGP na krzywej NIST P-256 (ECDSA sign + ECDH subkey).
// Uzycie:  node gen-p256.mjs "Imie Nazwisko <email@domena>"  [haslo]
//   node gen-p256.mjs "P256 Test <p256@encedo.com>"
//   node gen-p256.mjs "P256 Test <p256@encedo.com>" tajnehaslo
// Zapisuje: p256-<local>.pub.asc (publiczny) i p256-<local>.sec.asc (prywatny).

import { writeFileSync } from 'node:fs';
import * as openpgp from 'openpgp';

const userIdStr = process.argv[2];
const passphrase = process.argv[3] || undefined;
if (!userIdStr) {
  console.error('Podaj User ID, np:  node gen-p256.mjs "P256 Test <p256@encedo.com>"');
  process.exit(1);
}
// wyciagnij email + name z "Name <email>"
const m = userIdStr.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
const name = m ? m[1] : '';
const email = m ? m[2] : userIdStr.trim();

const { publicKey, privateKey } = await openpgp.generateKey({
  type: 'ecc',
  curve: 'nistP256',          // NIST P-256  (zmien na nistP384 / nistP521 dla innych)
  userIDs: [{ name, email }],
  passphrase,
  format: 'armored',
});

const local = email.split('@')[0].replace(/[^a-z0-9._-]/gi, '_');
const pub = `p256-${local}.pub.asc`;
const sec = `p256-${local}.sec.asc`;
writeFileSync(pub, publicKey);
writeFileSync(sec, privateKey);

// pokaz keyID/fingerprint
const key = await openpgp.readKey({ armoredKey: publicKey });
const ai = key.getAlgorithmInfo();
console.log('OK — wygenerowano klucz NIST P-256');
console.log('  User ID    :', userIdStr);
console.log('  Algorytm   :', ai.algorithm, ai.curve);
console.log('  keyID       :', key.getKeyID().toHex().toUpperCase());
console.log('  fingerprint:', key.getFingerprint().toUpperCase());
for (const sk of key.getSubkeys()) {
  const a = sk.getAlgorithmInfo();
  console.log('  subkey     :', sk.getKeyID().toHex().toUpperCase(), '|', a.algorithm, a.curve);
}
console.log('  publiczny  :', pub);
console.log('  prywatny   :', sec, passphrase ? '(zaszyfrowany haslem)' : '(BEZ hasla)');
