import { createHash, createDecipheriv } from 'node:crypto';

export async function sha1(bytes) {
  return new Uint8Array(createHash('sha1').update(bytes).digest());
}

export async function sha256(bytes) {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

export async function aes256KeyUnwrap(kek, wrappedKey) {
  const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
  const decipher = createDecipheriv('id-aes256-wrap', Buffer.from(kek), iv);
  // final() enforces the RFC 3394 integrity check (the A6A6… register). Without it a
  // tampered wrapper or wrong KEK could pass through as garbage; the browser backend's
  // WebCrypto AES-KW already verifies this, so keep the two paths equivalent.
  const out = Buffer.concat([decipher.update(Buffer.from(wrappedKey)), decipher.final()]);
  return new Uint8Array(out);
}