# Security status

**Public status: unaudited local/testnet alpha. Do not use mainnet or meaningful funds.**

## Implemented

- Domain-separated, ordered fixed-batch commitment and proofs in TypeScript.
- Strict bounded offline JSON envelopes with checksums and zero Safe refund fields.
- 24-word BIP-39 generation and authenticated Argon2id/AES-GCM local vaults.
- Runtime chain policy accepts only local Anvil `31337` and Sepolia `11155111`.
- Static web UI and loopback-only validation relay with no signing key.
- Sepolia-only setup keys, copied-address QuickNode faucet handoff, demo-wallet deployment, and ETH/ERC-20/message actions.
- Contract compilation and static review enforce atomic action, next-owner funding, and owner activation while preserving the wallet contract address.
- Recovery-phrase mode derives owners deterministically; quick setup remains memory-only and is unrecoverable after refresh.

## Disabled

Mainnet; arbitrary contract calls; Safe refunds; modules; guard changes; Ledger/Trezor signing; manual injected signing; WalletConnect; QR transport; production relayer deployment; emergency bypasses. The demo permits only ETH transfer, ERC-20 `transfer`, and bounded message events.

## Test status and release blockers

The browser onboarding and faucet handoff are automated in CI. No funded live Sepolia deployment/action test or Solidity execution/fuzz suite exists yet.


1. Independent audit of the Sepolia demonstration contract and guard behavior against the future exact Safe deployment.
2. Real Anvil Safe proxy integration, adversarial Foundry fuzzing, atomic setup-helper validation, and verified contract code hashes.
3. A reviewed sequence refill or migration protocol that prevents final-owner lockout.
4. Physical Ledger/Trezor firmware matrix before hardware support claims.
5. Sepolia restricted-value exercise and reproducible CI release evidence.

Browser encryption protects data at rest. It cannot protect a phrase while entered or unlocked from malicious page code, extensions, browser compromise, or the operating system. JavaScript cannot guarantee secure erasure.
