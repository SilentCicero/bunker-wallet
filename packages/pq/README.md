# Experimental browser cryptography

Not independently audited. Trusted-client KeyGen and complete deployed-data attestation are mandatory; on-chain length/floor/codehash checks are not KeyGen provenance. See `docs/experimental-browser-pq.md` for protocol and recovery/outbox boundaries.

## Pins and adaptations

- C10: https://github.com/nconsigny/SPHINCs- at `55b2f3e25d8d7cc0df33ccdb13becca1a168b26f`. `verifiers/c10/src/SPHINCs-C10Asm.sol` is the pinned source, MIT license included. Solc0.8.30, Paris, viaIR, optimizer200.
- `c10/src/{hash,wots,fors,merkle,sphincs}.rs` adapt the parameterized upstream `signer-wasm` core, with corrected C10 comments. Dedicated parameters N16/H18/D2/A11/K13/W8/L43/TARGET_SUM205 and a minimal raw-WASM `lib.rs` replace the C13 wrapper. No upstream mnemonic/private-key/message-derived fixture wrapper is included. Inputs are independently domain-separated HKDF bytes. Only tiny-keccak2.0.2 and locked crunchy are required. Cargo.lock is committed; build used rustc1.97.1 and wasm32-unknown-unknown. Raw exports are single-threaded/no-import; the browser owns them exclusively inside a dedicated worker.
- ML-DSA signer: exact `@noble/post-quantum`0.7.1 (upstream gitHead `a23736036d4d5b34dd3a9e0ee312fd43d00154ac`), locked by bun.lock. Real ML-DSA-44 KeyGen with32-byte seed and hedged signing, pure/empty context. This dependency version is not independently audited; do not describe it otherwise.
- ML-DSA verifier: https://github.com/fireblocks-labs/evm-ml-dsa-verifier at `cca262b537a5ac2ee55efb427e5c61de0308e566`. `verifiers/mldsa/src` and `helper.hex` are pinned upstream sources/data, MIT license included. Solc0.8.30, Osaka, viaIR, optimizer10000. Helper runtime hash `0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b` is enforced.
- `src/keys.ts` ports the **public-side** layout/NTT/ExpandA of that revision's `prepare/{prepare.py,mldsa_min.py}`. Noble implements KeyGen/signing; the port only prepares public data. Integer products remain below2^53. The centered-lift rule is an explicit rejection floor, never proof that all accepted keys are sound.

`bun run pq:build` compiles the isolated verifiers and experimental contracts using Forge, compiles dedicated C10 WASM using Cargo, and writes `apps/web/src/pq/generated/{artifacts.json,c10.wasm}`. Runtime immutable slots are named from compiler AST—not guessed by slot occurrence count. The build rejects runtime/initcode sizes above EVM limits and does not touch Standard's compiler/artifacts. ML-DSA verifier runtime24032bytes is close to EIP170; keep compiler settings pinned.

## Evidence and public fixtures

`test-vectors/c10-public-test.sig` is a publicly known disposable fixture: C10 seed input48 bytes of01, message32 bytes of02. It matches the pinned Python `c10-fips` signer, native Rust and WASM byte-for-byte; it is never imported by the browser wallet. Native check: `cd c10 && cargo test --release --locked`. `keys.test.ts` also checks WASM and a Python-derived ML-DSA blob hash for standard KeyGen_internal(00*32), domain separation, actual signing and weak-key rejection.

`tests/fixtures/sepolia-safe-1.4.1.json` records the actual official Safe1.4.1/factory/MultiSend and proxy runtime at Sepolia block0xb594b7. The local lifecycle runner verifies their pinned hashes and uses these actual bytecodes only as test environment fixtures. It deploys experimental contracts and cryptographic components normally, without mock cryptography. Fixture keys/addresses are public: never fund them on any real network.

Measured dedicated WASM: approximately64KB uncompressed; exported linear memory was1,179,648bytes after fixture keygen and1,900,544bytes after fixture signing in Bun. This is not total browser-process memory, a bound for all inputs, or a mobile benchmark. C10 remains a custom finite-budget construction; there is no NIST status claim.
