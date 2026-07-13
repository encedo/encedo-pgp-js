/**
 * test-mpi-encoding.js — regression guard for RFC 4880 §3.2 minimal MPI encoding.
 *
 * Ed25519 R/S components have a ~1/256 chance of a leading 0x00 octet. A non-minimal
 * MPI (declared bit length shorter than the emitted byte count) desyncs any strict
 * parser: it reads ceil(bits/8) octets and the leftover corrupts the next MPI, so the
 * signature fails to verify. This test asserts the encoder trims leading zeros.
 *
 * No HSM / network / openpgp needed — pure byte-level round-trip.
 *
 * Run: node test/test-mpi-encoding.js
 */

function u16be(n) { return new Uint8Array([n >> 8, n & 0xFF]); }
function concat(...a) {
  const t = a.reduce((n, x) => n + x.length, 0);
  const o = new Uint8Array(t); let f = 0;
  for (const x of a) { o.set(x, f); f += x.length; }
  return o;
}

// Mirror of the fixed nativeMPI in cert-builder.js / openpgp-bridge.js.
function nativeMPI(bytes32) {
  let start = 0;
  while (start < bytes32.length && bytes32[start] === 0) start++;
  if (start === bytes32.length) return u16be(0);
  const trimmed = bytes32.slice(start);
  let b = trimmed[0], lz = 0;
  while (!(b & 0x80)) { b <<= 1; lz++; }
  const bitCount = trimmed.length * 8 - lz;
  return concat(u16be(bitCount), trimmed);
}

function encodeSig(sig64) {
  return concat(nativeMPI(sig64.slice(0, 32)), nativeMPI(sig64.slice(32, 64)));
}

/** Parse two MPIs the way a strict parser does: read ceil(bits/8) octets, left-pad to 32. */
function parseSigTo64(buf) {
  let pos = 0;
  const rBits = (buf[pos] << 8) | buf[pos + 1]; pos += 2;
  const r = buf.slice(pos, pos + Math.ceil(rBits / 8)); pos += r.length;
  const sBits = (buf[pos] << 8) | buf[pos + 1]; pos += 2;
  const s = buf.slice(pos, pos + Math.ceil(sBits / 8)); pos += s.length;
  const sig = new Uint8Array(64);
  sig.set(r, 32 - r.length);
  sig.set(s, 64 - s.length);
  return { sig, consumed: pos };
}

function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

let failures = 0;
function check(name, cond) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`); }
  else console.log(`ok: ${name}`);
}

// 1. Explicit leading-zero case (the bug that shipped): R starts with 0x00.
{
  const sig = new Uint8Array(64);
  sig[0] = 0x00; sig[1] = 0xAB; for (let i = 2; i < 64; i++) sig[i] = (i * 7) & 0xFF;
  sig[32] = 0x00; sig[33] = 0x00; sig[34] = 0x9C; // S with two leading zeros
  const buf = encodeSig(sig);
  const { sig: got, consumed } = parseSigTo64(buf);
  check('leading-zero: parser consumes the whole buffer', consumed === buf.length);
  check('leading-zero: R||S reconstructed exactly', eq(got, sig));
}

// 2. Full-width case: both MSBs set, nothing to trim.
{
  const sig = new Uint8Array(64).fill(0xFF);
  const buf = encodeSig(sig);
  const { sig: got, consumed } = parseSigTo64(buf);
  check('full-width: 64 payload bytes preserved', buf.length === 68);
  check('full-width: consumed all', consumed === buf.length);
  check('full-width: R||S exact', eq(got, sig));
}

// 3. Randomised round-trip — deterministic PRNG so the run is reproducible.
{
  let seed = 0x12345678, bad = 0, hitZero = 0;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) & 0xFF;
  for (let t = 0; t < 5000; t++) {
    const sig = new Uint8Array(64);
    for (let i = 0; i < 64; i++) sig[i] = rnd();
    if (sig[0] === 0 || sig[32] === 0) hitZero++;
    const { sig: got, consumed } = parseSigTo64(encodeSig(sig));
    if (consumed !== encodeSig(sig).length || !eq(got, sig)) bad++;
  }
  check(`randomised: 5000 round-trips exact (${hitZero} exercised a leading zero)`, bad === 0 && hitZero > 0);
}

if (failures) { console.error(`\n${failures} check(s) failed`); process.exit(1); }
console.log('\nall MPI encoding checks passed');
