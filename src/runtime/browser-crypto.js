export async function sha1(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-1', bytes));
}

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

// ---------------------------------------------------------------------------
// RFC 3394 AES-256 Key Unwrap — pure WebCrypto implementation
//
// AES Key Wrap uses AES in a mode that processes 64-bit (8-byte) blocks.
// WebCrypto exposes AES-KW natively — we can use it directly.
// ---------------------------------------------------------------------------

export async function aes256KeyUnwrap(kek, wrappedKey) {
  const aesKwKey = await globalThis.crypto.subtle.importKey(
    'raw', kek,
    { name: 'AES-KW' },
    false, ['unwrapKey']
  );
  // Target algorithm must accept arbitrary key lengths — HMAC does (unlike AES-CBC/GCM).
  // The unwrapped bytes are algo_byte || session_key || checksum || padding (40 bytes).
  const unwrapped = await globalThis.crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    aesKwKey,
    'AES-KW',
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign']
  );
  return new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', unwrapped));
}