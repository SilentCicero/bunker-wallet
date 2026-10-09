import {describe,expect,test} from "bun:test";
import {decryptMnemonic,encryptMnemonic,newMnemonic,validMnemonic} from "./index";
const metadata={chainId:31337 as const,derivation:"m/44'/60'/7331'/0/index" as const,sequenceVersion:1 as const};
describe("encrypted vault",()=>{
  test("creates a 24-word phrase",()=>expect(validMnemonic(newMnemonic())).toBe(true));
  test("encrypts and restores with authenticated metadata",async()=>{const m=newMnemonic(),v=await encryptMnemonic(m,"correct horse battery staple",metadata),stored=JSON.stringify(v);expect(stored).not.toContain(m);expect(stored).not.toMatch(/"(?:mnemonic|seed|phrase|privateKey)"/);expect(await decryptMnemonic(v,"correct horse battery staple")).toBe(m);await expect(decryptMnemonic(v,"wrong-password-value")).rejects.toThrow("could not be opened")});
  test("rejects ciphertext tampering",async()=>{const v=await encryptMnemonic(newMnemonic(),"correct horse battery staple",metadata);v.cipher.ciphertext=`${v.cipher.ciphertext.slice(0,-2)}00`;await expect(decryptMnemonic(v,"correct horse battery staple")).rejects.toThrow("could not be opened")});
  test("rejects dangerous imported KDF bounds",async()=>{const v=await encryptMnemonic(newMnemonic(),"correct horse battery staple",metadata);v.kdf.memoryKiB=999999;await expect(decryptMnemonic(v,"correct horse battery staple")).rejects.toThrow("unsafe")});
});
