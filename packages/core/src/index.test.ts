import { describe, expect, test } from "bun:test";
import { BATCH_SIZE, SecurityPolicyError, commitmentProof, commitmentRoot, ownerLeaf, rotationsRemaining, verifyProof } from "./index";
const owners = Array.from({ length: BATCH_SIZE }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`);
const context = { chainId: 31337, safe: "0x00000000000000000000000000000000000000aa" as const, version: 1 };
describe("finite committed owner sequence", () => {
  test("matches the Solidity BUNKER_OWNER_V1 commitment vector", () => expect(commitmentRoot(context, owners)).toBe("0x697039bcac59eaa66dd0a5d790f77338130bc23812db93b61edb9d288e479d38"));
  test("proves every ordered owner and rejects substitution", () => { const root=commitmentRoot(context,owners); for(let i=0;i<20;i++) expect(verifyProof(root,ownerLeaf(context,i,owners[i] as `0x${string}`),commitmentProof(context,owners,i))).toBe(true); expect(verifyProof(root,ownerLeaf(context,1,owners[2] as `0x${string}`),commitmentProof(context,owners,1))).toBe(false); });
  test("binds commitments to chain and Safe", () => { expect(commitmentRoot(context,owners)).not.toBe(commitmentRoot({...context,chainId:11155111},owners)); expect(commitmentRoot(context,owners)).not.toBe(commitmentRoot({...context,safe:"0x00000000000000000000000000000000000000bb"},owners)); });
  test("rejects reused owners and reserves final rotation", () => { expect(()=>commitmentRoot(context,[...owners.slice(0,19),owners[0]!])).toThrow(SecurityPolicyError); expect(rotationsRemaining(18)).toBe(1); expect(rotationsRemaining(19)).toBe(0); });
});
