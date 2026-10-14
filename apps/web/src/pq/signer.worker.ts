import { mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes, type Hex } from 'viem';
import { derivePQSeed, prepareMLDSA, c10Keygen, c10Sign, type C10Wasm, type PQMode } from '../../../../packages/pq/src/keys';
import wasmURL from './generated/c10.wasm?url';
let mode: PQMode | undefined, secret: Uint8Array | undefined, wasm: C10Wasm | undefined;
self.onmessage = async (event: MessageEvent) => {
 const {id, op} = event.data;
 try {
  if (op === 'init') {
   mode = undefined; secret?.fill(0); secret = undefined; wasm = undefined;
   const mnemonic = event.data.mnemonic as string;
   if (typeof mnemonic !== 'string' || mnemonic.trim().split(/\s+/).length !== 24 || !validateMnemonic(mnemonic,wordlist)) throw new Error();
   mode = event.data.mode;
   if (mode !== 'c10' && mode !== 'mldsa44') throw new Error();
   const master = await mnemonicToSeed(mnemonic), seed = derivePQSeed(master,mode);
   master.fill(0);
   try {
    let pk: Uint8Array, blob: Uint8Array | undefined;
    if (mode === 'c10') {
     const bytes = await (await fetch(wasmURL)).arrayBuffer();
     wasm = (await WebAssembly.instantiate(bytes)).instance.exports as C10Wasm;
     pk = c10Keygen(wasm, seed);
    } else { const keys = ml_dsa44.keygen(seed); secret = keys.secretKey; pk = keys.publicKey; blob = prepareMLDSA(pk); }
    self.postMessage({id, result:{mode, publicKey:bytesToHex(pk), ...(blob ? {blob:bytesToHex(blob)} : {})}});
   } finally { seed.fill(0); }
  } else if (op === 'sign') {
   if (!/^0x[0-9a-fA-F]{64}$/.test(event.data.digest)) throw new Error();
   const digest = hexToBytes(event.data.digest as Hex);
   const sig = mode === 'c10' && wasm ? c10Sign(wasm,digest) : mode === 'mldsa44' && secret ? ml_dsa44.sign(digest,secret) : undefined;
   if (!sig) throw new Error();
   self.postMessage({id,result:bytesToHex(sig)});
  } else throw new Error();
 } catch { mode = undefined; secret?.fill(0); secret = undefined; wasm = undefined; self.postMessage({id,error:'PQ signer failed. Lock and recover before retrying.'}); }
};
