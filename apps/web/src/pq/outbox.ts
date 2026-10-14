import {mnemonicToSeed} from '@scure/bip39';
import {hkdf} from '@noble/hashes/hkdf.js';
import {sha512} from '@noble/hashes/sha2.js';
import {bytesToHex,hexToBytes,type Hex} from 'viem';
export type SealedTransaction={iv:Hex;ciphertext:Hex};
const utf8=new TextEncoder();
/** Separate mnemonic-derived AEAD key; never persisted. No raw transaction or root seed enters localStorage. */
export async function outboxKey(mnemonic:string,identity:string){
 const seed=await mnemonicToSeed(mnemonic),key=hkdf(sha512,seed,utf8.encode('BUNKER_TX_OUTBOX_V1'),utf8.encode(identity),32);seed.fill(0);
 try{return await crypto.subtle.importKey('raw',Uint8Array.from(key).buffer,'AES-GCM',false,['encrypt','decrypt'])}finally{key.fill(0)}
}
export async function sealTransaction(key:CryptoKey,value:unknown,aad:string):Promise<SealedTransaction>{
 const iv=crypto.getRandomValues(new Uint8Array(12)),plain=utf8.encode(JSON.stringify(value));
 try{return{iv:bytesToHex(iv),ciphertext:bytesToHex(new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(aad)},key,plain)))}}finally{plain.fill(0)}
}
export async function openTransaction(key:CryptoKey,sealed:SealedTransaction,aad:string):Promise<unknown>{
 if(!/^0x[0-9a-f]{24}$/.test(sealed.iv)||!/^0x(?:[0-9a-f]{2})+$/.test(sealed.ciphertext)||sealed.ciphertext.length>400000)throw new Error('Invalid encrypted outbox');
 const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:Uint8Array.from(hexToBytes(sealed.iv)).buffer,additionalData:utf8.encode(aad)},key,Uint8Array.from(hexToBytes(sealed.ciphertext)).buffer));
 try{return JSON.parse(new TextDecoder().decode(plain))}finally{plain.fill(0)}
}
