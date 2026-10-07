# Security status

**Public status: unaudited local/testnet alpha. Do not use mainnet or meaningful funds.**

## Implemented

- Domain-separated, ordered fixed-batch commitment and proofs in TypeScript.
- Strict bounded offline JSON envelopes with checksums and zero Safe refund fields.
- 24-word BIP-39 generation and authenticated Argon2id/AES-GCM local vaults.
- Runtime chain policy accepts only local Anvil `31337` and Ethereum Sepolia `11155111`.
- Static web UI and loopback-only validation relay with no signing key.
- Default local preview uses no RPC, faucet, broadcast, persistence, or real assets.
- Optional Ethereum Sepolia setup uses memory-only keys, a copied-address Google Cloud faucet handoff, demo-wallet deployment, and ETH sends.
- Contract compilation and static review enforce atomic action, next-owner funding, and owner activation while preserving the wallet contract address.
- Recovery-phrase mode derives owners deterministically; quick setup remains memory-only and is unrecoverable after refresh.

## Disabled

Mainnet; ERC-20 and message UI; arbitrary contract calls; Safe refunds; modules; guard changes; Ledger/Trezor signing; manual injected signing; WalletConnect; QR transport; production relayer deployment; emergency bypasses. The hosted UI exposes ETH sends only; compatibility methods remain in the unaudited demonstration contract.

## Test status and release blockers

The local preview and optional Sepolia faucet handoff are automated in CI. No funded live Ethereum Sepolia deployment/action test or Solidity execution/fuzz suite exists yet.


1. Independent audit of the Ethereum Sepolia demonstration contract and guard behavior against the future exact Safe deployment.
2. Real Anvil Safe proxy integration, adversarial Foundry fuzzing, atomic setup-helper validation, and verified contract code hashes.
3. A reviewed sequence refill or migration protocol that prevents final-owner lockout.
4. Physical Ledger/Trezor firmware matrix before hardware support claims.
5. Ethereum Sepolia restricted-value exercise and reproducible CI release evidence.

Browser encryption protects data at rest. It cannot protect a phrase while entered or unlocked from malicious page code, extensions, browser compromise, or the operating system. JavaScript cannot guarantee secure erasure.
