const runtimeModulePromise = selectRuntimeModule();

function selectRuntimeModule() {
  const isNode = typeof process !== 'undefined' && process.versions?.node;
  return isNode ? import('./node-crypto.js') : import('./browser-crypto.js');
}

async function getRuntime() {
  return runtimeModulePromise;
}

export async function sha1(bytes) {
  return (await getRuntime()).sha1(bytes);
}

export async function sha256(bytes) {
  return (await getRuntime()).sha256(bytes);
}

export async function aes256KeyUnwrap(kek, wrappedKey) {
  return (await getRuntime()).aes256KeyUnwrap(kek, wrappedKey);
}