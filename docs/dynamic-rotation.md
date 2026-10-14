# Dynamic rotation V2 (0.2.0-alpha.1)

Unaudited local/Anvil and Ethereum Sepolia only. No mainnet, meaningful funds, audit, or post-quantum safety claim.

## Policy

`BunkerRotationGuard.VERSION()` is 2. `initialize()` reads the Safe's single initial EOA owner and marks `consumed[safe][initialOwner] = true`. It does not accept future owners. `BunkerSafeSetup.setup(guard)` initializes and installs the guard during atomic proxy creation.

Every permitted operation remains exactly one pinned `MultiSendCallOnly` delegatecall containing: a positive ETH send with empty calldata; exactly 0.001 ETH to the chosen next owner; and `swapOwner(SENTINEL,current,next)`. No arbitrary calls, refunds, modules, guard changes, or upgrade bypass. Zero, sentinel, Safe-self, code-bearing and previously consumed next owners are rejected. The executing lock prevents nested rotation. Only successful post-execution ownership verification consumes the candidate and increments the uint256 rotation counter. Reverts roll back transfers, Safe nonce, owner, pending state, counter and consumption together. Competing transactions signed at one Safe nonce cannot both succeed; losing candidates are not consumed.

There is no fixed key batch, future precommitment, Merkle proof, reserve transition, or nineteenth-rotation stop. History is per Safe, not global across wallets. A key already used elsewhere is not detectable from this history.

## Security tradeoff

**A compromised current signer can authorize an attacker-controlled fresh next signer. Historical reuse prevention does not prevent signer substitution.** This is an intentional difference from the old fixed precommitment design. It does not prevent theft by a current signer, seed compromise, a compromised browser, or a pending-signature attack. Public keys and signatures still use ECDSA. Never describe V2 as substitution-proof or quantum-safe.

## Local selection and recovery

The default derives only the next local key at `m/44'/60'/7331'/0/index`. The derivation index is independent of the on-chain rotation counter. The browser lets the user explicitly choose another index or a separately backed-up 24-word phrase. A chosen historical address is rejected, not silently reused. Switching seeds requires recording the new phrase, chosen index, and stable Safe address before broadcasting. The browser removes the old password vault after a confirmed seed switch and stores the active phrase in its existing device-encrypted session; retain offline backups. An old password vault cannot recover a different seed.

A session serializes rotation preparation before its first asynchronous read. It keeps an unresolved candidate until receipt reconciliation; it promotes the candidate only after a successful receipt and matching current owner. Broadcast/receipt uncertainty fails closed; recover against chain state if no transaction hash is available. After local-state loss, enter the stable Safe address and the phrase controlling the current owner. Search an explicit index range (1–1000 keys per search). Automatic session restoration searches indices 0–99 and opens manual recovery with the bounded-search error if no match is found; use manual recovery for a different range. A recovered Safe address is saved again for subsequent sessions. A retry after an uncertain owner read reconciles the original receipt without broadcasting a second transfer; a failed UI refresh retains the confirmed action until refresh succeeds. An unsuccessful bounded search is not proof that the phrase is wrong. Never infer the derivation index from the rotation counter. Lost new seed material cannot be recovered from old seeds or chain history.

## Legacy compatibility and migration

V1 immutable guarded Safes are **not upgraded**, and V2 runtime-hash attestation rejects them. No V1 `state` tuple or committed-owner list is reinterpreted as V2. Existing deployed websites and historic live-test evidence may still be V1; this source change is not a hosted deployment.

Create a new V2 Safe with a new stable address. If the legacy V1 wallet still permits an ordinary send, its V1 tooling may transfer disposable ETH to the new wallet while respecting its old rotation/funding rules. This is a transfer, not an in-place migration. Exhausted V1 Safes have no new escape path; do not claim otherwise. Keep legacy backups and compatible V1 tooling until handling any remaining test funds. Do not import V1 contracts as V2 or change a V1 vault's authenticated metadata by hand.

The encrypted vault container remains format 1 for compatible phrase decryption; new metadata uses `sequenceVersion: 2`, while legacy `sequenceVersion: 1` vaults remain readable **as phrase backups only**, not proof of V2 contract compatibility. Offline transfer envelopes and deployment manifests require guard version 2; envelopes also require format version 2 and reject Merkle-proof fields. The loopback syntax-only validator is `/v2/validate`; it remains unable to verify or broadcast transactions.
