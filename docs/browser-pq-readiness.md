# Browser PQ readiness assessment

Historical feasibility assessment. The user subsequently authorized **experimental trusted-client generation**, not length-only or trustless registration. A separately namespaced browser/Sepolia implementation now exists behind an explicit build flag; see [implementation, validation and remaining release gates](experimental-browser-pq.md). Public activation remains a separate review/deployment decision. The original local research kernel is unchanged.

## C10: implementable local signer work

At upstream `nconsigny/SPHINCs-` commit `55b2f3e25d8d7cc0df33ccdb13becca1a168b26f`, the parameterized Rust core in `signer-wasm/src` appears suitable for a dedicated C10 WASM build. The supplied target is C13 and must not be shipped unchanged. Source assessment only: no adapted build or browser benchmark has been run.

Required fixed parameters: N16/H18/D2/A11/K13/W8/L43/TARGET_SUM205, producing 4008-byte signatures. Target the Python `c10-fips` variant and actual `SPHINCs-C10Asm.sol`, not legacy JARDIN, C13, or SLH-DSA. Keep the current EC derivation unchanged. Define a separate versioned mnemonic-to-PQ derivation with algorithm and epoch domain separation; never use the reference CLI's public-message-derived fixture keys for wallets.

Next implementation slice: pinned dedicated WASM build, worker lifetime/cancellation handling, reproducible recovery vectors, Python/native/WASM/Solidity differential tests. Then validate actual Safe + hybrid guard + factory + rotation/renewal together, including recovery after broadcast interruption. Do not remove local-chain gates just because a standalone signature verifies.

## ML-DSA: registration trust model must be resolved

At Fireblocks commit `cca262b537a5ac2ee55efb427e5c61de0308e566`, canonical raw public-key length (1312), exact prepared-blob layout (20545), codehash integrity and proof of possession do **not** establish genuine/nondegenerate key generation.

The feasibility reviewer reproduced public-data signatures accepted by the raw-key Python reference for both all-zero and all-1023 t1 public-key coefficients, with honest preprocessing. This was a reference reproduction, not a newly run Solidity exploit. Recomputing `prepare(pk)` on-chain, or switching to raw-key verification, does not resolve that scheme-level issue. The documented centered-lift nondegeneracy floor rejects these examples but is not a complete genuineness certificate. Existing fixture admission remains local-only.

Two distinct architectures must not be conflated:

1. **Publicly verifiable registration:** reviewed evidence of the full relation `pk = ML-DSA-44.KeyGen_internal(privateSeed).publicKey`, plus exact blob preprocessing. A proof system/circuit and its quantum-security assumptions need independent review. Never reveal the seed on-chain. No audited implementation was established in this assessment.
2. **Explicit trusted-client generation:** the browser generates/rederives a private seed, derives the key/blob, and attests exact deployment before funding or authorizing rotation. This is an upstream-described client-trust model, not universal permissionless genuine-key validation. It requires an explicit security/product decision and review; it cannot silently replace Bunker's existing registration requirement. Imported arbitrary public keys must not be treated as validated.

No registration authority, custody service, weaker predicate or expanded allowlist is approved by this assessment. Browser ML-DSA signing itself is ordinary engineering; `@noble/post-quantum` is a candidate but is not currently installed, pinned or validated. Existing `@noble/hashes` provides hashes, not an ML-DSA signer.

## Common integration and release gates

- Authenticate mode, derivation version, parameter/address-layout version, epoch and key identity in recovery metadata; attest restored keys against the actual Safe state.
- Preserve existing Standard wallets and their derivation/guard. Hybrid creation is a separate atomic 2-of-2 setup, not a local mode toggle or silent migration.
- Complete browser creation, signing, EC/PQ rotation, sequence renewal, recovery and offline flows. Test stale state, lock/cancel, two tabs and uncertain transaction outcomes.
- Pin independently built verifier artifacts without changing the Standard Solidity profile. Validate target-fork compatibility and actual deployment/execution limits.
- Use genuine signatures with actual verifiers throughout lifecycle tests, not only mock guard tests or etched standalone Safe fixtures.
- Measure mobile/browser latency, memory and target-chain costs; do not substitute Foundry fixture gas for a fee estimate.
- Independent cryptographic and implementation review remains required before public PQ activation. No public PQ deployment or meaningful funds.

Assessment checks: reviewer ran five existing hybrid Bun tests and two targeted Foundry tests, and reproduced the two degenerate reference-key cases. No new browser implementation, browser signer tests, or Sepolia transactions were performed in this assessment.

Primary references: upstream `signer-wasm/src/{params,hash,wots,fors,merkle,sphincs,keygen}.rs`, `script/signer.py`, C10 verifier source; Fireblocks `docs/SAFETY.md` (client-trust model, degeneracy, generation provenance, audit requirements), `prepare/prepare.py`, `prepare/mldsa_min.py`, and `pythonref/dilithium_py/dilithium/dilithium.py`. See also [current hybrid plan](hybrid-pq-plan.md).
