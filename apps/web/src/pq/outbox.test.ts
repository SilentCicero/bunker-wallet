import {test,expect} from 'bun:test';
import {outboxKey,sealTransaction,openTransaction} from './outbox';
test('signed outbox is encrypted and authenticates wallet identity, hash and intent',async()=>{
 const phrase='abandon '.repeat(23)+'art',key=await outboxKey(phrase,'Sepolia c10 public identity');const intent={raw:'0x02public-test-only',nonce:3,value:'123'};
 const sealed=await sealTransaction(key,intent,'kind:fund/hash:abc');expect(JSON.stringify(sealed)).not.toContain(intent.raw);expect(await openTransaction(key,sealed,'kind:fund/hash:abc')).toEqual(intent);
 await expect(openTransaction(key,sealed,'kind:fund/hash:substituted')).rejects.toThrow();
 const wrong=await outboxKey(phrase,'Sepolia mldsa44 public identity');await expect(openTransaction(wrong,sealed,'kind:fund/hash:abc')).rejects.toThrow();
 const changed={...sealed,ciphertext:(sealed.ciphertext.slice(0,-2)+(sealed.ciphertext.endsWith('00')?'01':'00')) as `0x${string}`};await expect(openTransaction(key,changed,'kind:fund/hash:abc')).rejects.toThrow();
});
