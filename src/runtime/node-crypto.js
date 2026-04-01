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
  return new Uint8Array(decipher.update(Buffer.from(wrappedKey)));
}