# Contracts

Unaudited local/Ethereum Sepolia research contracts targeting official Safe 1.4.1. **Legacy** `BunkerRotationGuard` permits only a canonical `MultiSendCallOnly` delegatecall containing an ETH transfer, exactly `0.001 ETH` funding for the next EOA owner, and `swapOwner(SENTINEL,current,next)`. Its deployed/runtime artifact is retained for existing-Safe recovery. Refunds, modules, arbitrary calls, guard changes, and mainnet deployment are blocked for these legacy Safes.

`BunkerSafeSetup` installs and initializes the guard during `Safe.setup`, so proxy creation has no unguarded owner window. The guard accepts canonical ABI padding, verifies the pinned MultiSend runtime hash, rejects contract/sentinel/Safe owners, and commits a fixed 20-owner sequence. Nineteen ordinary rotations are available; the final owner remains reserved because a reviewed refill or migration protocol does not yet exist.

Run:

```bash
PATH="$HOME/.foundry/bin:$PATH" forge test
```

The integration suite deploys the official vendored Safe singleton, proxy factory, canonical `MultiSendCallOnly`, setup helper, and guard locally. It proves atomic setup, canonical padded execution, recipient transfer, next-owner gas funding, owner rotation, malformed funding rejection, and explicit sequence exhaustion.

These Standard contracts remain unaudited. Ethereum Sepolia use must remain disposable and restricted-value; mainnet and meaningful funds are prohibited.

## Fresh Standard V3 on the isolated preview

`BunkerRotationGuardV3` is a separate, unaudited guard deployed per fresh Standard Safe; it does not alter legacy Safes or remove their runtime artifact. It accepts 1–8 external `CALL`s (at most 8192 calldata bytes each), then exactly 0.001 test ETH funding of the next committed EOA and `swapOwner(SENTINEL,current,next)` in the same `MultiSendCallOnly` transaction. It rejects inner delegatecall, Safe/self/guard/MultiSend/singleton/proxy-factory targets, malformed batches, modules, refunds and failed post-execution rotation. The browser UI still submits **ETH sends only**. Its 20-owner sequence still supports just **19 ordinary rotations**, without Standard refill; do not treat this as unlimited contract-call authority. `test/BunkerSafeV3.t.sol` exercises real Safe execution, multiple calls, revert rollback, malformed signatures, replay and dependency tampering. This is local test evidence, not an independent security review.

## Local hybrid kernel — chain 31337 ONLY

`HybridSafeOwner.sol`, `BunkerHybridFactory.sol`, and `BunkerHybridRotationGuard.sol` are a separate, unaudited research kernel. Constructors and authorization paths reject other chains, including Sepolia. This 31337-only kernel remains unchanged; legacy Standard artifacts are retained. The separate Sepolia V3 preview does create PQ modes through `../contracts-experimental`. There is no browser PQ signer or deploy-script integration. **Do not use meaningful funds.**

Implemented:

- Legacy Safe `isValidSignature(bytes,bytes)` returning `0x20c13b0b`; exactly 66 bytes `0x1901 || SafeDomain || SafeTxStructHash`. Validation is bound to the calling Safe, chain, immutable key/algorithm/version/verifier/codehash/epoch and adapter address. Unbound adapters cannot validate. Verifier calls are static, require exactly one ABI word equal to 1, and fail closed on errors. Adapter/verifier/blob identity changes fail closed.
- Factory-controlled atomic creation: deploy unbound adapter, initialize real Safe proxy with `[EC,PQ]`, threshold 2 and a fixed helper that ONLY installs the fixed guard; bind the adapter, initialize/attest policy, return. There is no public first-caller binding or arbitrary delegatecall authorization. Only exact adapters recorded by this factory are accepted. Anyone can prepare a rotation candidate, but only current owners can install it.
- Canonical signatures: exactly two sorted 65-byte entries, EC `v=27/28` and low-s, PQ `v=0`, canonical padded adapter address, dynamic offset 130, length plus exactly 4008 (C10) or 2420 (ML-DSA) raw bytes, no trailing padding. Signature address sorting is independent of the fixed linked list `[EC,PQ]`. Approved-hash and eth_sign execution bypasses are rejected by the guard. Safe's public `checkSignatures` itself does not invoke the guard and is not a complete policy attestation.
- No modules, fallback, refunds or arbitrary delegatecalls. Singleton, proxy runtime, owner order, threshold, guard storage and pinned MultiSendCallOnly are attested before/after execution. Correctly signed recipient reentry is blocked; failures roll back Safe nonce, transfers, owners and guard state.

### Three exact batch grammars

All operations use zero-value delegatecall to the pinned MultiSendCallOnly; all packed suboperations are CALLs and all outer gas/refund fields are zero. Re-encoding equality enforces canonical ABI words, lengths and zero padding.

1. Ordinary ETH spend (indices 0–18): nonzero ETH transfer with empty calldata to a nonzero, non-Safe recipient; exactly 0.001 ETH to the next committed EOA; `safe.swapOwner(SENTINEL,currentEC,nextEC)`.
2. PQ maintenance: only `safe.swapOwner(currentEC,currentPQ,nextPQ)`. Candidate must be factory-created, bound to this Safe, same algorithm, epoch+1, and a never-used key identity. This maintenance operation retains EC and does not consume its sequence. Replacement cannot authorize itself.
3. Renewal (only index 19): exactly 0.001 ETH to reserved EOA; `safe.swapOwner(SENTINEL,currentEC,reservedEC)`; `guard.renew(address[20])`. Both current signatures commit all new addresses. The guard permits this call only inside this exact locked batch, checks the swap happened, rejects duplicate/previously committed EOAs and resets index to zero. Thus the last EOA is usable for renewal even when ordinary spending is exhausted. Keep enough Safe ETH for funding; there is no owner/threshold reduction or lost-key bypass.

### Exact signed-message formula

Solidity and `packages/safe/src/hybrid.ts` use:

```text
SafeDomain = keccak256(abi.encode(
  keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), uint256(31337), safe))
M = keccak256(abi.encode(
  keccak256("BUNKER_HYBRID_PQ_V1"), uint256(31337), safe,
  keccak256(preimage), uint256(algorithm), uint256(1), adapter,
  bytes32(keyId), verifier, bytes32(verifierCodeHash), uint256(epoch)))
```

Addresses are ABI address words. Algorithm 1 is experimental keccak SPHINCS+C10 FIPS-address variant (NOT NIST SLH-DSA); algorithm 2 is ML-DSA-44. C10 keyId is `keccak256(abi.encode(pkSeed,pkRoot))`: each nonzero bytes32 contains a left-aligned 16-byte value, low 128 bits zero. ML-DSA keyId is the admitted prepared-blob runtime codehash. The C10 verifier receives `M` as bytes32. ML-DSA receives exactly the 32 raw digest bytes as its message, non-prehashed mode, empty context; do not prepend its internal `0x0000` message prefix.

### Actual ABI pins and security blockers

Adapters match actual inspected upstream interfaces, but no upstream source is vendored and no PQ security is claimed by the local mock tests:

- Nicolas Consigny `SPHINCs-` commit `55b2f3e25d8d7cc0df33ccdb13becca1a168b26f`, `src/keccak/SPHINCs-C10Asm.sol`: `verify(bytes32 pkSeed,bytes32 pkRoot,bytes32 message,bytes sig) returns(bool)`, 4008 raw signature bytes. Its browser WASM path is C13, not this C10 signer. Upstream needs a newer compiler than this project's 0.8.24.
- Fireblocks `evm-ml-dsa-verifier` commit `cca262b537a5ac2ee55efb427e5c61de0308e566`, `src/MLDSA44Verifier.sol`: `verify(address pkBlob,bytes message,bytes signature) returns(bool)`, 2420 raw signature bytes. Its verifier pins its Keccak helper codehash at construction and verification. Prepared blob runtime length is 20545, **a structural check, never proof of genuine/non-degenerate key material**. Full mandatory reviewed registration described in upstream `docs/SAFETY.md` is not supplied. Upstream also needs a newer compiler/EVM than this profile.

Factory construction pins supplied verifier/dependency codehashes and a finite, constructor-only `admittedLocalFixture` codehash list. Empty list disables ML-DSA. This is explicit local fixture admission, **NOT reviewed ML-DSA key validation**; no mutable administrator can add fixtures or change dependencies. Multiple admitted fixture hashes permit local ML-DSA rotation tests. A codehash pin alone is not proof that supplied code is audited, non-upgradeable or the claimed verifier: independently inspect the verifier and every dependency before real integration. Losing either signing key can make funds inaccessible.

`test/BunkerHybridIntegration.t.sol` uses real vendored Safe contracts and conspicuously named mock verifiers, exclusively under `test/`. Tests cover paired authorization and both numeric address orderings, framing/domain/codehash failures, static verification, EC/PQ rotation, index-19 renewal, key reuse, binding, no modules/administrative mutations, reentry and rollback. The TS tests share a fixed digest vector with the actual Solidity adapter. Mocks do not validate cryptography, key registration, browser signing, real-verifier gas or network limits. Independent review, real signer/verifier interoperability, full ML-DSA registration and cryptographic audits remain release blockers.

### Separate experimental browser path

The later user-authorized trusted-client Sepolia implementation is in `../contracts-experimental`, with independently built verifiers in `../pq/verifiers`. It does not widen or modify this directory’s local-only hybrid kernel or legacy Standard artifacts; fresh Standard V3 has a separately generated artifact. See [browser implementation and trust boundaries](../../docs/experimental-browser-pq.md).
