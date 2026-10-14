import{expect,test}from"bun:test";import{validateManifest}from"./index";
test("rejects legacy deployment manifest before address checks",()=>expect(()=>validateManifest({chainId:31337,safeVersion:"1.4.1",guardVersion:1} as never)).toThrow("V2"));
test("rejects mainnet before any RPC use",()=>expect(()=>validateManifest({chainId:1,safeVersion:"1.4.1"} as never)).toThrow("Mainnet"));
