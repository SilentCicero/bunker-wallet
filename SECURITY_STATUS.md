# Security status

**Public status: unaudited local/testnet alpha. Do not use mainnet or meaningful funds.**

## Implemented

- Default local preview uses a hidden, memory-only BIP-39 mnemonic and fully hardened BIP-32 owner paths, with no RPC, faucet, broadcast, persistence, or real assets.
- Optional Ethereum Sepolia Safe 1.4.1 proxy deployment using the official canonical singleton, proxy factory, and `MultiSendCallOnly` addresses.
- Atomic Safe setup helper that initializes and installs `BunkerRotationGuard` during proxy creation.
- Runtime hash checks for official Safe components before deployment and Safe owner/module/guard/singleton attestation before funding.
- ETH send, exact next-owner gas funding, and owner rotation in one guarded Safe transaction.
- Fixed 20-owner sequence with 19 ordinary rotations; contract/sentinel/Safe owners, modules, refunds, arbitrary calls, and guard changes are rejected.
- Canonical ABI-padding support and 65-byte canonical-low-s ECDSA signature policy.
- Receipt-uncertainty reconciliation before promoting the next browser signer.
- Recovery-phrase mode derives owners deterministically; quick setup remains memory-only and unrecoverable after refresh.
- 24-word BIP-39 generation and authenticated Argon2id/AES-GCM local vaults.
- Runtime chain policy limited to local Anvil `31337` and Ethereum Sepolia `11155111`.

## Disabled

Mainnet; ERC-20 and message UI; arbitrary contract calls; Safe refunds; modules; guard changes; sequence refill; Ledger/Trezor signing; manual injected signing; WalletConnect; QR transport; production relayer deployment; emergency bypasses.

## Test status and release blockers

Foundry integration tests execute the vendored Safe 1.4.1 proxy, setup helper, guard, and MultiSend path locally. They cover atomic setup, canonical padded execution, ETH transfer, next-owner funding, owner rotation, malformed funding rejection, and sequence exhaustion. Browser CI covers the BIP-39/hardened-BIP-32 local preview and verifies that every Sepolia entry point remains disabled.

Restricted-value Ethereum Sepolia tests passed on 2026-10-09. The direct smoke covered deploy → fund → ETH send → exact next-owner funding → two successive owner rotations → phrase recovery. A separate local-only browser run generated a fresh 24-word phrase in the app without storing it, funded the displayed setup address through the protected sponsor Safe, clicked through Safe creation, submitted two ETH sends, and verified stable-address continuity plus owner progression from key 1 to key 3 against chain state. Sanitized evidence is stored locally with the E2E secret rather than committed with transaction identifiers. The hosted Sepolia UI remains disabled.

Still required before broader use:

1. Independent audit of the setup helper, guard, browser Safe transaction builder, and recovery flow.
2. Expanded parser fuzzing, malicious recipient/reentrancy tests, and bytecode/proxy attestation tests.
3. A reviewed sequence refill or migration protocol before the nineteenth rotation.
4. Physical Ledger/Trezor firmware testing before hardware support claims.

Browser encryption protects data at rest. It cannot protect a phrase while entered or unlocked from malicious page code, extensions, browser compromise, or the operating system. JavaScript cannot guarantee secure erasure.
