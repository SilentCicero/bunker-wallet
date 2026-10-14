> Update: a separately gated, unaudited trusted-client browser path is now available on [the experimental Sepolia preview](https://bunker-wallet-pq-sepolia-test.pages.dev) for disposable test ETH. See [its implementation and limits](experimental-browser-pq.md). The local31337 research kernel described below remains unchanged; its original browser blockers are historical, not a claim of audited security or production readiness.

# Optional hybrid post-quantum signing: repo-specific plan

## Implementation status — 2026-10-12

This section describes the **local-only research kernel**, not the separate browser/Sepolia experiment:

- `packages/contracts/src/HybridSafeOwner.sol`: C10 and ML-DSA-44 owner adapters using the actual pinned verifier ABIs and Safe's legacy contract-owner signature interface.
- `BunkerHybridFactory.sol`: atomic setup/binding and immutable dependency pins. ML-DSA uses an explicit finite local-fixture hash allowlist, **not reviewed key registration**.
- `BunkerHybridRotationGuard.sol`: exact 2-of-2 policy, constrained ETH spend/EC rotation, PQ key rotation, renewable owner sequences, and no module/recovery downgrade.
- `packages/safe/src/hybrid.ts`: strict sorted signature encoding and domain-separated digest helpers.
- These research-kernel constructors and authorization paths are restricted to **chain 31337**. A separately namespaced Sepolia experiment now exists; mainnet remains disabled. Standard contracts and their deployment artifacts are unchanged.
- Setup displays Standard, Quantum Shield and Maximum. PQ creation requires the exact experimental preview build; default/production builds keep it disabled. No UI selection changes an existing Safe's on-chain policy.

Validation of this implementation: **26 Foundry tests, 32 Bun tests, 9 default Playwright tests, and 5 separately enabled local persistence tests passed**; typecheck and production build passed. The persistence checks did not submit chain transactions. A bounded independent code review found an integrity-attestation gap; it was corrected and regression-tested, including replacement-blob mutation/rollback/retry, valid alternate Safe signature forms, CREATE2 collision/prefunding, and simulation rollback. This is not a cryptographic audit.

Separate genuine-verifier checks also passed for each algorithm: verifier acceptance/wrong-message rejection, plus real adapter + Safe combined execution, each-signature-alone failure and replay rejection. These four external checks were run outside the repository and are not shipped test evidence. Their Safe fixture does not install the hybrid guard; do not combine this evidence into a claim of end-to-end browser/PQ/guard validation. The local research kernel did not vendor upstream verifiers; the separate experiment pins and builds their sources. The research fixtures did not deploy publicly.

See [contract implementation and test instructions](../packages/contracts/README.md). The plan below is the original design/release checklist, not a claim that all phases are complete. The separate experiment has a genuine C10 browser signer and trusted-client ML-DSA key generation/attestation, **not** a trustless KeyGen registration proof, independent audit, hardware/offline integration or mainnet readiness. No lost-key bypass has been added.

## Scope and evidence

Inspected `https://github.com/SilentCicero/bunker-wallet` at commit `02ebc6fceab88f688444a86587adc5b3a5688203` on 2026-10-12. This is a source-level authorization map and implementation plan, not an audit, live deployment attestation, or PQ implementation. No chain transactions were submitted. Paths and line references below refer to that commit.

Baseline checks: `bun test` passed 27 tests; `/root/.foundry/bin/forge test` in `packages/contracts` passed 7 integration tests. These test current ECDSA behavior, not the proposed hybrid policy.

## 1. Actual authorization and deployment

### Versions and networks

- Vendored Safe source declares **1.4.1** (`packages/contracts/lib/@safe-global/safe-contracts/contracts/Safe.sol:47`). The app manually constructs transactions using viem, rather than a Safe Protocol Kit integration. Root `package.json` pins viem 2.57.3 and solc 0.8.24. Vendored source provenance and release-bytecode equivalence still require release review; the version string alone is not proof.
- Runtime allowlist is **Anvil 31337 and Ethereum Sepolia 11155111** (`packages/core/src/index.ts:5-15`, `BunkerRotationGuard.sol:36-38`). Browser transactions use Sepolia; the local UI is a simulation, not an Anvil wallet. Local scripts/tests exercise Anvil separately.
- Base Sepolia and Arbitrum Sepolia appear in offline/vault TypeScript unions, but are **not enabled by runtime policy**. Mainnet RPC is used for ENS resolution only (`apps/web/src/burner.ts:58-71`); it is not a supported spending network.
- Sepolia addresses pinned in `apps/web/src/burner.ts:25-30`:

| Component | Address |
|---|---|
| Safe singleton | `0x41675C099F32341bf84BFc5382aF534df5C7461a` |
| Proxy factory | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` |
| MultiSendCallOnly | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` |

The app checks their runtime hashes before deployment. Guard and setup helper are newly deployed per creation. Attestation checks Safe proxy/guard runtime hashes, singleton slot, owners, threshold, empty modules, zero fallback, and guard state (`burner.ts:124-143`). This review did not query any user's live Safe.

### Authorization map

Contract paths below are relative to `packages/contracts`; application paths are relative to the repo root.

| Route | Current authorization and behavior | Hybrid implications |
|---|---|---|
| Browser ETH spend | `App.tsx:33` → `demoSendETH` → `rotatedWrite` (`apps/web/src/burner.ts:159-193,290`). Current EOA signs the full Safe EIP-712 hash, checked against `getTransactionHash`; broadcaster calls `execTransaction`. | Replace single-signature builder, not just the creation screen. Re-attest current policy before signing. |
| Batch execution | `src/BunkerRotationGuard.sol:61-84`: only delegatecall to code-hash-pinned MultiSendCallOnly, containing exactly a nonzero ETH send, 0.001 ETH funding of the next EOA, and `swapOwner(SENTINEL,current,next)`. Refunds disabled. | New hybrid guard must retain explicit allowed batch grammar and postconditions; do not allow arbitrary Safe self-calls. |
| ECDSA owner rotation | Guard initialization, precheck and postcheck require one owner and threshold 1; signatures must be exactly 65 bytes with canonical ECDSA v/s. | Current guard rejects both PQ adapters and combined signatures. Need a new guard version, setup path, artifacts and attestation. |
| Module execution | Vendored `base/ModuleManager.sol:81-95` executes for an enabled module without owner signatures **or transaction guard checks**. Current setup enables none; browser and guard require an empty module list. | Empty modules are a security invariant. Checking modules in the transaction guard cannot protect a Safe that already has a malicious enabled module. |
| Owner/threshold mutations | Vendored `base/OwnerManager.sol:58-128` requires Safe self-calls. Current guard admits only its prescribed swap; additions, removals and threshold changes are outside its grammar. | Allow only reviewed ECDSA/PQ swaps under current 2-of-2; assert exactly the intended two owners and threshold 2 afterwards. |
| Setup and funding | `burner.ts:233-259`; `src/BunkerSafeSetup.sol:15-18`. Factory atomically initializes `[EOA]`, threshold 1, zero fallback/payment, and delegatecalls helper to initialize/install guard. Separate EOA funding follows attestation. | Setup helper is privileged delegatecall code. Hybrid owner/key registration must finish atomically before funds arrive; test hostile/partial initialization. EOA setup/gas balances are not protected by the Safe threshold. |
| Guard/fallback/singleton changes | Only pinned MultiSend is permitted as delegatecall target; parser does not admit guard/fallback replacement or migration calls. Fallback starts at zero; app checks relevant storage slots. | No upgrade escape hatch. Do not enable arbitrary delegatecall merely to support migration. |
| Hash approval and alternate signatures | Vendored `Safe.sol:274-347` supports contract, approved-hash and eth_sign forms; current guard accepts only v=27/28, 65-byte ECDSA. `approveHash` alone does not execute a transaction. | Define and test accepted hybrid signature forms. Prefer exactly ECDSA + v=0 contract-owner signature; adapter must expose no generic execute/approveHash route. |
| Recovery | `App.tsx:37-39`, `burner.ts:202-205,260-288`: restore phrase and saved/supplied Safe address, read active index, derive owner, verify remaining committed sequence. No alternate on-chain recovery authority found. | Restore both algorithms and authenticate metadata. Losing an unrecoverable PQ key must not permit EC-only removal. |
| Browser session | `apps/web/src/unlockedSession.ts`: mnemonic ciphertext and non-extractable WebCrypto key in IndexedDB allow session restoration. | This is local unlocking, not a Safe session-key module. Same-origin/device compromise threatens both keys derived from one seed. |
| Offline and relay | `packages/offline/src/index.ts:4-33` accepts only one 65-byte signature; `apps/relayer/src/index.ts` validates syntax/checksum only and never broadcasts. | Version envelopes for hybrid metadata/signatures; do not mistake format acceptance for verified authorization. Keep relay broadcast disabled until independently implemented/tested. |
| Simulation entry point | Vendored `common/StorageAccessible.sol` has `simulateAndRevert`, an arbitrary delegatecall that always reverts. | Include rollback tests; not a persistent state-changing execution route. |
| SDK/dapp routes | No implemented WalletConnect, hardware signer, ERC-4337/session-key execution or arbitrary dapp transaction path found in first-party app. Message UI is disabled and Safe fallback is zero. | Do not claim existing dapp EIP-1271 compatibility. Adding a handler or module is separate security scope. |

### Rotation, failures and recovery today

The browser derives Sepolia owners at `m/44'/60'/7331'/0/index`. Guard initialization commits 20 future owners, but permits only 19 ordinary rotations. Each spend atomically transfers ETH, funds the next broadcaster, and rotates. Reverting execution rolls back owner and guard state; an existing integration test covers a reverting recipient.

`reconcilePending` promotes a candidate key only after observing it as the sole on-chain owner. There is an operational gap: `pendingPrivateKey` is set before `writeContract`, whose rejection is outside the receipt-handling try block. A rejected submission can leave the session blocked pending manual reload/recovery. Multi-device coordination is not implemented; the chain nonce is authoritative, but stale-client UX and reconciliation need explicit tests.

The final reserved commitment is **not an implemented migration route**. At index 19 the current guard rejects further spending, including any migration attempt. No refill or guard-removal entry point exists.

### Counterfactual address and migration

`burner.ts:246-249` uses a random salt nonce and `createChainSpecificProxyWithNonce`. Vendored `proxies/SafeProxyFactory.sol:88-95` derives its CREATE2 salt from the initializer hash, salt nonce, and chain ID. Therefore changing owners, threshold, helper or setup data changes the predicted address. Current UI obtains the address from the creation receipt; it does not expose a counterfactual prefunding flow or reconstruct the address from the seed alone.

Existing guarded Safes cannot be upgraded in place through the supported authorization path. Before exhaustion, ETH can be moved to a separately created, verified hybrid Safe using an ordinary allowed transfer (which still funds/rotates the old EOA). This changes the wallet address, is not atomic with creation, and needs a gas/funding budget. After index 19 there is no supported spend/migration route. Do not promise same-address migration, recovery of exhausted Safes, or migration of arbitrary tokens.

## 2. Correct Safe contract-owner interface and message binding

Implement two narrow owner adapters only after verifier provenance and key-registration gates below are settled:

- `C10SafeOwner`: immutable algorithm/version, key material/commitment, verifier identity and epoch.
- `MLDSA44SafeOwner`: immutable validated public-key blob identity/commitment, verifier identity and epoch.

**Critical ABI detail:** Safe 1.4.1's `execTransaction` contract-owner branch calls legacy `isValidSignature(bytes,bytes)` and expects **`0x20c13b0b`**, not the bytes32 overload's `0x1626ba7e`. See vendored `Safe.sol:315` and `interfaces/ISignatureValidator.sol:3-20`. A modern-only implementation will fail.

The supplied bytes are the **66-byte EIP-712 preimage** (`0x1901 || domainSeparator || SafeTx struct hash`), not decoded transaction calldata (`Safe.sol:383-410`). That hash commits to destination, value, calldata, operation, nonce, and all Safe gas/refund fields; the domain commits to chain and Safe. Specify a versioned PQ message binding this preimage/hash plus algorithm, adapter/key identity and epoch. If adapters inspect individual operation fields, include a bounded canonical witness and recompute the entire preimage; never trust duplicated caller-provided fields without recomputation. Do not accidentally omit Safe refund fields from the PQ authorization.

Validate caller/Safe binding, preimage/domain, signature framing, key/version/epoch, verifier identity, and exact successful verifier result. Reverts, malformed returndata and unsupported versions fail closed. Signature validation is read-only. **Safe increments its nonce before signature checking** (`Safe.sol:170`); do not naïvely compare an operation nonce to the current storage nonce. Also test public read-only signature checks separately from execution.

Resolve deployment binding before coding: an adapter whose constructor embeds its Safe address and a Safe initializer embedding the adapter address can create a circular CREATE2 dependency. Specify and review a one-time atomic binding protocol (with no unbound interval exposed to funds), or a non-circular address derivation design. A permissionless first-caller-wins binding is unacceptable. Verifier code must not be silently upgradeable behind an immutable address; pin/review dependencies and blob contents, not just addresses.

Serialize two 65-byte static signature entries in ascending **owner address** order. For the contract entry, r holds the padded adapter address, s holds the byte offset to dynamic signature length, v=0. Append length + PQ payload. Owner signature sorting is different from Safe's owner linked-list order: preserve ECDSA first in the linked list if retaining `swapOwner(SENTINEL,...)`; derive/verify the actual predecessor for PQ swaps.

## 3. Registration gates before usable PQ adapters

Source pins resolved during implementation:

- [Consigny keccak C10](https://github.com/nconsigny/SPHINCs-/tree/55b2f3e25d8d7cc0df33ccdb13becca1a168b26f), commit `55b2f3e25d8d7cc0df33ccdb13becca1a168b26f`, MIT. Select the current FIPS-ADRS variant, not legacy JARDIN; its browser WASM signer is C13, not C10.
- [Fireblocks ML-DSA-44](https://github.com/fireblocks-labs/evm-ml-dsa-verifier/tree/cca262b537a5ac2ee55efb427e5c61de0308e566), commit `cca262b537a5ac2ee55efb427e5c61de0308e566`, MIT. Its `prepare.py` builds blobs but does not implement the full mandatory registration validator in `docs/SAFETY.md`.

Both remain unaudited research implementations. Algorithm names, ABI availability, proof of possession and upstream gas claims are not approval to ship. Bunker's 0.8.24 compiler profile is unchanged; upstream real-verifier checks use separate local compiler profiles.

Required inputs/deliverables:

1. Pin source URLs, commit hashes, compiler settings, licenses, deployed code where applicable, signer formats, algorithm parameters, and test vectors.
2. Review actual C10 implementation, not only interface; verify encoding and security assumptions. Label it experimental SPHINCS+C10, **not NIST SLH-DSA**. Link the pinned implementation and FIPS 205 with that distinction.
3. Independently review ML-DSA prepared-blob generation and the mandatory validation path. Prove the blob corresponds to a genuine, non-degenerate ML-DSA-44 public key and contains the required consistent preprocessing; possession alone is insufficient. Add invalid/degenerate/mismatched blob fixtures. Treat upstream research/unaudited status as a release blocker, not a footnote.
4. Registration must reject invalid keys atomically, bind verified material to the adapter, and have no replaceable verifier/blob authority that bypasses both owners.
5. Independent integration review and cryptographic audits before meaningful/live funds. Keep mainnet disabled. Mock verifiers can test Safe wiring, but cannot substantiate PQ security.

## 4. Hybrid guard, lifecycle and recovery

Create a distinct hybrid policy version rather than weakening the existing standard guard. Initialization/precheck/postcheck must establish exactly `[rotating ECDSA owner, approved PQ adapter]`, threshold 2, no modules, and the reviewed fallback/singleton/guard state. Preserve the constrained ETH-transfer path initially; broad dapp execution is not needed for the first milestone.

Specify narrow PQ-rotation and sequence-renewal operations before deployment. PQ rotation swaps to a newly validated adapter under the **current** two signatures, binds the next key/epoch, and retains threshold 2. Replacement must not authorize itself. Do not reproduce the current finite-sequence lockout without a reviewed exit/renewal protocol and explicit user warning.

Lifecycle rules:

- Failed operation: transaction rolls back all owner/epoch changes; browser does not promote candidates.
- Unknown receipt: persist only safe transaction metadata, reconcile nonce/owners/epoch and receipt before retry; no blind resubmission with different intent.
- Multiple devices: re-read attested chain state before signing; stale nonce/epoch triggers explicit refresh and fresh confirmation. No local epoch override.
- Old adapter/key: signatures cannot authorize the new epoch or another Safe/chain/mode.
- Lost key: restore from verified backup, otherwise funds may be inaccessible. No ECDSA-only emergency bypass in a product claiming continuous 2-of-2.
- One root seed: use reviewed algorithm-specific domain-separated derivation and versioned authenticated backup metadata. One-unlock UX gives algorithmic diversity, **not independent factors**.

Touch points: contracts/setup/Foundry tests; `scripts/compile-contract.ts` and generated `apps/web/src/safeArtifacts.ts`; `burner.ts` creation, attestation, signature assembly, rotation, reconciliation and recovery; offline/vault schema versioning. All `demoSendETH` callers, including smoke and sponsor scripts, must remain consistent with explicit wallet mode.

## 5. Product integration

After verified backend support exists, add a keyboard-accessible three-choice creation control, Standard selected by default. PQ choices stay unavailable until their gates pass; never present a UI selection as on-chain protection.

- **Standard:** existing rotating ECDSA, no PQ signature.
- **Quantum Shield:** ECDSA + experimental SPHINCS+C10, both required.
- **Maximum:** ECDSA + ML-DSA-44, both required; standardized algorithm (FIPS 204), not wallet/verifier certification. The label is not evidence of a stronger security ranking.

Expose mode and “both signatures required” in wallet state and confirmation. One confirmation can coordinate both signers; display real latency and failures. Version recovery metadata with mode, Safe, chain, adapter/key identifiers, derivation versions and epoch. Derive displayed protection from verified chain state, not a local setting.

Cost display needs measured deployment, blob registration, adapter, Safe execution, calldata, next-owner funding and signer latency on each enabled network. Upstream C10/ML-DSA gas numbers are not Bunker benchmarks; do not hard-code relative cost promises. EIP-1271 dapp signing needs a separately reviewed message domain/handler design: do not reuse transaction authorization blindly or relax wrong-caller checks to make integrations work.

Use the product claim **“optional hybrid post-quantum signing”**. Do not claim “truly quantum-proof,” independent factors from one seed, or an audited/certified implementation.

## 6. Validation and rollout gates

Extend the existing Foundry suite rather than add another framework. Required checks include:

- ECDSA alone fails; PQ alone fails; correct pair succeeds through real Safe 1.4.1.
- Both numerical owner orderings, dynamic offsets/bounds, duplicates, truncation, malformed/oversized payloads, alternate Safe signature forms and wrong magic values.
- Wrong caller/chain/Safe/nonce/operation/calldata/value/gas/refund fields, algorithm/version/key/epoch, replay and cross-adapter reuse fail.
- Genuine verifier vectors succeed; invalid keys/blobs, wrong signatures, verifier reverts/short returndata and changed dependencies fail closed.
- EC/PQ rotations and renewal preserve owner set/threshold/policy; stale clients, rejected submissions, uncertain receipts and reorgs cannot incorrectly promote keys.
- Attempts to enable/use modules, change threshold/guard/fallback/singleton, use delegatecall/storage-write payloads, exploit recovery/session routes or reenter from recipients fail. Also demonstrate that a deliberately module-enabled Safe is rejected by attestation; transaction-guard checks do not intercept module execution.
- Atomic setup/binding, prefunding/address prediction, occupied CREATE2 addresses, unauthorized initialization and migration edge cases.
- Explicit compatibility tests for each intended SDK and EIP-1271 dapp path; unsupported paths remain disabled.
- Actual calldata and RPC limits, gas and fee estimates, next-owner gas sufficiency, browser/mobile signer time/memory, backup/restore and accessibility.

Rollout order: local adapter wiring with conspicuously mocked verification → pinned real verifiers and key-validation vectors locally → independent review → disposable-value Sepolia trials → security audits and explicit network-specific release approval. Passing existing tests or using standardized ML-DSA does not satisfy those gates.

**Next release prerequisite:** complete and independently review genuine key registration and browser signers, then integrate creation/recovery/rotation with verified on-chain mode and epoch. Atomic binding, constrained hybrid guard operations and finite-sequence renewal now have local implementations; this is not audit approval. PQ UI choices remain disabled, and test mocks are never browser dependencies.
