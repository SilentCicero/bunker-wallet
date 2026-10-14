import {test,expect} from 'bun:test';
import {PQSigner} from './signer';
test('lock/cancel rejects in-flight work, terminates worker and ignores stale messages',async()=>{
 let sent:any,terminated=false;const fake={onmessage:undefined as any,onerror:undefined as any,postMessage:(m:any)=>sent=m,terminate:()=>{terminated=true}};
 const signer=new PQSigner(()=>fake as unknown as Worker);
 const pending=signer.init('public test phrase','c10');
 await expect(signer.sign(('0x'+'00'.repeat(32)) as any)).rejects.toThrow('busy');
 signer.close();await expect(pending).rejects.toThrow('locked');expect(terminated).toBe(true);
 fake.onmessage({data:{id:sent.id,result:{publicKey:'late'}}});
 await expect(signer.init('another public test phrase','mldsa44')).rejects.toThrow('locked');
});
test('failed reinitialization terminates identity instead of retaining an old signing key',async()=>{
 let sent:any,terminated=false;const fake={onmessage:undefined as any,onerror:undefined as any,postMessage:(m:any)=>sent=m,terminate:()=>{terminated=true}};
 const signer=new PQSigner(()=>fake as unknown as Worker);
 const first=signer.init('test','c10');fake.onmessage({data:{id:sent.id,result:{mode:'c10',publicKey:'test'}}});await first;
 const failed=signer.init('invalid','mldsa44');fake.onmessage({data:{id:sent.id,error:'Invalid initialization'}});await expect(failed).rejects.toThrow('Invalid initialization');expect(terminated).toBe(true);
 await expect(signer.sign(('0x'+'00'.repeat(32)) as any)).rejects.toThrow('locked');
});
test('synchronous dispatch and message decoding failures close rather than wedge the signer',async()=>{
 let terminated=false;const fake={onmessage:undefined as any,onerror:undefined as any,onmessageerror:undefined as any,postMessage:()=>{throw new Error('structured clone failed')},terminate:()=>{terminated=true}};
 const signer=new PQSigner(()=>fake as unknown as Worker);await expect(signer.init('test','c10')).rejects.toThrow('locked');expect(terminated).toBe(true);await expect(signer.init('test','c10')).rejects.toThrow('locked');
 const fake2={...fake,postMessage:()=>{}};const other=new PQSigner(()=>fake2 as unknown as Worker);const pending=other.init('test','c10');fake2.onmessageerror();await expect(pending).rejects.toThrow('locked');
});
