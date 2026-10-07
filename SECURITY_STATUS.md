# Security status

**Public status: unaudited local/testnet alpha. Do not use mainnet or meaningful funds.**

## Enabled and tested

- Domain-separated, ordered fixed-batch commitment and proofs in TypeScript.
- Strict bounded offline JSON envelopes with checksums and zero Safe refund fields.
- 24-word BIP-39 generation and authenticated Argon2id/AES-GCM local vaults.
- Runtime chain policy accepts only local Anvil `31337` and Sepolia `11155111`.
- Static web UI and loopback-only validation relay with no signing key.

## Disabled

Mainnet; transaction signing and broadcasting; dynamic refill; arbitrary contract and token calls; Safe refunds; modules; guard changes; Ledger/Trezor claims; manual injected signing; WalletConnect; QR transport; production relayer deployment; emergency bypasses.

## Release blockers

1. Independent audit of guard behavior against the exact Safe 1.4.1 deployment.
2. Real Anvil Safe proxy integration, adversarial Foundry fuzzing, atomic setup-helper validation, and verified contract code hashes.
3. A reviewed sequence refill or migration protocol that prevents final-owner lockout.
4. Physical Ledger/Trezor firmware matrix before hardware support claims.
5. Sepolia restricted-value exercise and reproducible CI release evidence.

Browser encryption protects data at rest. It cannot protect a phrase while entered or unlocked from malicious page code, extensions, browser compromise, or the operating system. JavaScript cannot guarantee secure erasure.
