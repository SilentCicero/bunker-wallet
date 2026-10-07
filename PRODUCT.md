# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

SolidJS PWA and Tailwind CSS v4 in a strict TypeScript Bun workspace; Solidity contracts tested with Foundry; local-only Bun relayer; static web deployment on Cloudflare Pages.

## Users

Security-conscious Ethereum users evaluating owner-key rotation with disposable local or testnet funds.

## Product Purpose

Bunker Wallet is an open-source Safe account experiment that atomically advances to a precommitted fresh ECDSA owner after each supported transaction, reducing historical public-key exposure.

## Positioning

Unlike a conventional single-key wallet, supported transfers and owner rotation are one guarded Safe operation against a domain-separated committed owner sequence.

## Operating Context

Users create or restore a browser seed, secure a backup, prepare narrowly supported Safe transactions, review rotation details, and move unsigned or signed envelopes between online and offline-capable devices.

## Capabilities and Constraints

The hosted alpha is limited to local Anvil and Base Sepolia. Mainnet deployment, signing, and broadcasting are disabled. The first release supports a finite committed sequence and ETH-transfer-only transaction envelopes. Dynamic commitment refill, QR transport, arbitrary contract calls, hardware signing, manual injected signers, funded Safe refunds, and production relaying remain disabled until their security gates are met.

## Brand Commitments

Bunker Wallet. Precise, calm, professional language; no unqualified “quantum-safe,” “air-gapped,” or secure-erasure claims. Minimal neutral surfaces with one restrained mint/teal accent, light and dark themes, no gradients or decorative clutter.

## Evidence on Hand

The approved engineering specification is stored externally in the originating request. No audit, production deployments, physical-device compatibility results, customer claims, or mainnet safety evidence exists.

## Product Principles

- Security claims never outrun evidence.
- Every supported spend requires an atomic authorized owner rotation.
- External inputs are bounded, parsed, and independently recomputed.
- Secret material is short-lived and never intentionally logged or persisted as plaintext.
- Unmet security gates disable features instead of weakening warnings.

## Accessibility & Inclusion

Target WCAG 2.2 AA with keyboard operation, visible focus, responsive layouts, reduced-motion support, and comprehensible security warnings.
