import { expect, test } from "bun:test";
import { validateTransferIntent, assertSupportedChain } from "./index";
const intent = {chainId:31337,safe:"0x0000000000000000000000000000000000000010" as const,recipient:"0x0000000000000000000000000000000000000011" as const,currentOwner:"0x0000000000000000000000000000000000000012" as const,nextOwner:"0x0000000000000000000000000000000000000013" as const,nonce:25n,value:1n,nextIndex:25};
test("accepts dynamic rotation beyond 20 without commitments",()=>expect(validateTransferIntent(intent)).toEqual(intent));
test("rejects owner reuse within intent",()=>expect(()=>validateTransferIntent({...intent,nextOwner:intent.currentOwner})).toThrow());
test("restricts chains",()=>expect(()=>assertSupportedChain(1)).toThrow());
