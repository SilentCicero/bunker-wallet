import { describe, expect, test } from "bun:test";
import { concatHex, encodeAbiParameters, keccak256, padHex, size, sliceHex, stringToHex, toHex, type Address, type Hex } from "viem";
import { c10KeyId, encodeHybridSignatures, hybridMessageDigest, type HybridMessage } from "./hybrid";

const addr = (n: number) => toHex(n, { size: 20 }) as Address;
const word = (n: number) => toHex(n, { size: 32 });
const preimage = (safe: Address) => concatHex(["0x1901", keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }],
  [keccak256(stringToHex("EIP712Domain(uint256 chainId,address verifyingContract)")), 31337n, safe],
)), word(123)]);
const input: HybridMessage = { chainId: 31337, safe: addr(100), preimage: preimage(addr(100)), algorithm: 1, version: 1, adapter: addr(200), keyId: c10KeyId(toHex(1n << 128n, { size: 32 }), toHex(2n << 128n, { size: 32 })), verifier: addr(300), verifierCodeHash: keccak256("0x00"), epoch: 7n };
const ecSignature = concatHex([word(1), word(2), "0x1b"]);
const pq = (n: number) => `0x${"ab".repeat(n)}` as Hex;

describe("local hybrid signature encoding", () => {
  test("both owner orderings and raw lengths, independently of linked-list order", () => {
    for (const [ec, adapter] of [[addr(2), addr(3)], [addr(3), addr(2)]] as const) {
      for (const algorithm of [1, 2] as const) {
        const length = algorithm === 1 ? 4008 : 2420;
        const sig = encodeHybridSignatures(ec, adapter, ecSignature, pq(length), algorithm);
        const c = BigInt(ec) < BigInt(adapter) ? 65 : 0;
        expect(size(sig)).toBe(162 + length);
        expect(sliceHex(sig, c, c + 32)).toBe(padHex(adapter, { size: 32 }));
        expect(BigInt(sliceHex(sig, c + 32, c + 64))).toBe(130n);
        expect(sliceHex(sig, c + 64, c + 65)).toBe("0x00");
        expect(sliceHex(sig, 65 - c, 130 - c)).toBe(ecSignature);
        expect(BigInt(sliceHex(sig, 130, 162))).toBe(BigInt(length));
        expect(sliceHex(sig, 162)).toBe(pq(length));
      }
    }
  });
  test("rejects malformed boundaries and noncanonical EC forms", () => {
    const encode = (sig = ecSignature, raw = pq(4008), ec = addr(2), adapter = addr(3), algorithm = 1) =>
      encodeHybridSignatures(ec, adapter, sig, raw, algorithm as 1);
    for (const v of [0, 1, 26, 29, 31, 32]) expect(() => encode(concatHex([word(1), word(2), toHex(v, { size: 1 })]))).toThrow();
    for (const sig of [concatHex([word(0), word(2), "0x1b"]), concatHex([word(1), word(0), "0x1b"]), concatHex([word(1), `0x${"ff".repeat(32)}`, "0x1b"]), `${ecSignature}0` as Hex]) expect(() => encode(sig)).toThrow();
    for (const n of [0, 2420, 4007, 4009]) expect(() => encode(ecSignature, pq(n))).toThrow();
    expect(() => encode(ecSignature, pq(4008), addr(2), addr(2))).toThrow();
    expect(() => encode(ecSignature, pq(4008), addr(0))).toThrow();
    expect(() => encode(ecSignature, pq(4008), addr(1))).toThrow();
    expect(() => encode(ecSignature, pq(4008), "0xzz" as Address)).toThrow();
    expect(() => encode(ecSignature, pq(4008), addr(2), addr(3), 3)).toThrow();
  });
});

describe("hybrid digest", () => {
  test("fixed Solidity-compatible digest formula and every identity binding", () => {
    // Also asserted in Solidity's testDigestFormulaVector.
    expect(hybridMessageDigest(input)).toBe("0x9dcd1c137a47b5d7c35f2b55600b2b94f6007234fc8afe245b7bacff7efbee70");
    for (const change of [{ algorithm: 2 }, { adapter: addr(201) }, { keyId: word(11) }, { verifier: addr(301) }, { verifierCodeHash: word(12) }, { epoch: 8n }, { preimage: concatHex([sliceHex(input.preimage, 0, 34), word(124)]) }]) {
      expect(hybridMessageDigest({ ...input, ...change } as HybridMessage)).not.toBe(hybridMessageDigest(input));
    }
  });
  test("rejects wrong chain, Safe, framing, version, epoch and missing identities", () => {
    for (const change of [{ chainId: 1 }, { safe: addr(101) }, { version: 2 }, { epoch: -1n }, { epoch: 1n << 256n }, { keyId: word(0) }, { verifierCodeHash: "0x12" }, { preimage: `0x1902${input.preimage.slice(6)}` }, { preimage: `${input.preimage}00` }, { algorithm: 0 }]) {
      expect(() => hybridMessageDigest({ ...input, ...change } as HybridMessage)).toThrow();
    }
  });
  test("C10 keys are canonical left-aligned, key commitment uses two ABI words", () => {
    const seed = toHex(1n << 128n, { size: 32 }); const root = toHex(2n << 128n, { size: 32 });
    expect(c10KeyId(seed, root)).toBe(keccak256(concatHex([seed, root])));
    for (const bad of [word(1), word(0), "0x12" as Hex]) expect(() => c10KeyId(bad, root)).toThrow();
  });
});
