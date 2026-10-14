import type {Hex} from 'viem';
import type {PQMode} from '../../../../packages/pq/src/keys';
export type PublicPQ = {mode:PQMode; publicKey:Hex; blob?:Hex};
/** One worker per unlocked experimental wallet. Lock/cancel terminates WASM and rejects every in-flight response. */
export class PQSigner {
 private worker: Worker | undefined;
 private next = 0;
 private pending: {id:number;resolve:(v:any)=>void;reject:(e:Error)=>void} | undefined;
 constructor(makeWorker = () => new Worker(new URL('./signer.worker.ts',import.meta.url),{type:'module'})) {
  this.worker = makeWorker();
  this.worker.onmessage = ({data}) => { const p = this.pending; if (!p || p.id !== data.id) return; this.pending = undefined; if (data.error) { p.reject(new Error(data.error)); this.close(); } else p.resolve(data.result); };
  this.worker.onerror = () => this.close();
  this.worker.onmessageerror = () => this.close();
 }
 private request(op:string, data:object) { if (!this.worker || this.pending) return Promise.reject(new Error('Signer locked or busy')); return new Promise<any>((resolve,reject)=>{const id=++this.next;this.pending={id,resolve,reject};try{this.worker!.postMessage({id,op,...data})}catch{this.close()}}); }
 init(mnemonic:string,mode:PQMode):Promise<PublicPQ>{return this.request('init',{mnemonic,mode})}
 sign(digest:Hex):Promise<Hex>{return this.request('sign',{digest})}
 close(){this.worker?.terminate();this.worker=undefined;this.pending?.reject(new Error('Signer locked'));this.pending=undefined}
}
