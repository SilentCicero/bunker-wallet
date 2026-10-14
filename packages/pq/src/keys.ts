import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
export type PQMode = 'c10' | 'mldsa44';
export function derivePQSeed(seed: Uint8Array, mode: PQMode, account = 0, index = 0, epoch = 0) {
  if (seed.length !== 64 || !['c10', 'mldsa44'].includes(mode)) throw new Error('Invalid PQ derivation');
  const info = new Uint8Array(12), view = new DataView(info.buffer);
  [account, index, epoch].forEach((v, i) => { if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error('Invalid PQ path'); view.setUint32(i * 4, v); });
  return hkdf(sha512, seed, new TextEncoder().encode(mode === 'c10' ? 'BUNKER_C10_FIPS_V1' : 'BUNKER_MLDSA44_V1'), info, mode === 'c10' ? 48 : 32);
}
const Q = 8380417;
const mod = (n: number) => ((n % Q) + Q) % Q;
function power(a: number, n: number) { let r = 1; while (n) { if (n & 1) r = mod(r * a); a = mod(a * a); n >>>= 1; } return r; }
const zetas = Array.from({length:256}, (_, i) => power(1753, parseInt(i.toString(2).padStart(8, '0').split('').reverse().join(''), 2)));
export function decodeMLDSAPublicKey(pk: Uint8Array) {
  if (pk.length !== 1312) throw new Error('ML-DSA-44 public key must be 1312 bytes');
  const rows: number[][] = [];
  for (let row = 0; row < 4; row++) {
    const poly: number[] = [];
    for (let i = 0; i < 256; i++) { const bit = i * 10, pos = 32 + row * 320 + (bit >>> 3); poly.push(((pk[pos]! | pk[pos + 1]! << 8) >>> (bit & 7)) & 1023); }
    rows.push(poly);
  }
  // Every 10-bit value is canonical. This floor rejects known degeneracy, NOT proof of KeyGen provenance.
  const large = rows.flat().filter(v => { const x = mod(v * 8192); return Math.abs(x > Q / 2 ? x - Q : x) > (Q - 1) / 88; }).length;
  if (large < 512) throw new Error('Degenerate ML-DSA public key');
  return rows;
}
/** Exact public-side port of pinned Fireblocks prepare.py. Input must originate from trusted local KeyGen. */
export function prepareMLDSA(pk: Uint8Array) {
  const rows = decodeMLDSAPublicKey(pk), blob = new Uint8Array(20545), view = new DataView(blob.buffer);
  blob.set(shake256(pk, {dkLen:64}), 1); let offset = 65;
  const write = (poly: number[]) => { for (let w = 0; w < 32; w++) for (let s = 0; s < 8; s++) view.setUint32(offset + w * 32 + (7 - s) * 4, poly[w * 8 + s]!); offset += 1024; };
  for (const row of rows) {
    const a = row.map(v => mod(v * 8192)); let m = 0;
    for (let len = 128; len >= 1; len /= 2) for (let start = 0; start < 256; start += 2 * len) {
      const z = zetas[++m]!;
      for (let j = start; j < start + len; j++) { const t = mod(z * a[j + len]!); a[j + len] = mod(a[j]! - t); a[j] = mod(a[j]! + t); }
    }
    write(a);
  }
  for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) {
    const seed = new Uint8Array(34); seed.set(pk.subarray(0,32)); seed[32] = j; seed[33] = i;
    let poly: number[] = [];
    for (let want = 864; poly.length < 256; want *= 2) {
      const buf = shake128(seed, {dkLen:want}); poly = [];
      for (let pos = 0; pos + 3 <= buf.length && poly.length < 256; pos += 3) { const v = buf[pos]! | buf[pos+1]! << 8 | (buf[pos+2]! & 127) << 16; if (v < Q) poly.push(v); }
    }
    write(poly);
  }
  return blob;
}
export type C10Wasm = { memory: WebAssembly.Memory; input(): number; output(): number; keygen(): void; sign(): number };
export function c10Keygen(wasm: C10Wasm, seed: Uint8Array) {
  if (seed.length !== 48) throw new Error('C10 derivation requires 48 bytes');
  new Uint8Array(wasm.memory.buffer, wasm.input(),48).set(seed); wasm.keygen();
  return new Uint8Array(wasm.memory.buffer, wasm.output(),32).slice();
}
export function c10Sign(wasm: C10Wasm, digest: Uint8Array) {
  if (digest.length !== 32) throw new Error('C10 signs a 32-byte digest');
  new Uint8Array(wasm.memory.buffer, wasm.input(),32).set(digest);
  if (wasm.sign() !== 4008) throw new Error('C10 signing failed');
  return new Uint8Array(wasm.memory.buffer, wasm.output(),4008).slice();
}
