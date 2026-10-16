# V2 local validation evidence

Validated on 2026-10-14 on branch `feat/dynamic-signer-rotation`. This is engineering test evidence, **not an audit**, hosted deployment, mainnet approval, or live Sepolia V2 verification.

## Executed checks

| Command | Actual result |
| --- | --- |
| `bun install --frozen-lockfile` | Checked 118 installs across 138 packages; no changes |
| `bun test` | 29 pass, 0 fail; 52 assertions across 9 files |
| `bun run typecheck` | Exit 0 |
| `bun run contract:test` | 11 passed, 0 failed, 0 skipped |
| `bun run build` | Guard 5511 bytes; helper 398 bytes; Vite production build succeeded |
| `bun run release:verify` | Verified 8 static build files |
| `bun audit` | No vulnerabilities found (dependency advisory check, not a contract audit) |
| `bun run dependency:report` | Report generated successfully |
| `bun run test:e2e` | 8 passed, 7 gated tests skipped |
| `BROWSER_SEPOLIA_E2E=1 VITE_BROWSER_SEPOLIA_E2E=1 bun run test:e2e --grep 'Sepolia persistence'` | All 5 gated persistence tests passed |
| `VITE_SEPOLIA_RPC=http://127.0.0.1:1854 bun scripts/safe-anvil-smoke.ts` | 28 rotations, concurrent submission, arbitrary index and seed-switch recovery passed |
| `DYNAMIC_ANVIL_RPC=http://127.0.0.1:1854 VITE_SEPOLIA_RPC=http://127.0.0.1:1854 VITE_BROWSER_SEPOLIA_E2E=1 bun run test:e2e --grep 'dynamic V2'` | 2 passed |
| `git diff --check` | Exit 0 |

The Anvil commands used a local Sepolia fork started with `anvil --fork-url https://ethereum-sepolia-rpc.publicnode.com --port 1854 --silent`. Transactions and faucet balance changes stayed on that local fork. Bun was 1.3.14, Forge 1.8.3, solc 0.8.24. CI pins its own Forge version.

## Coverage and review fixes

- Safe integration executes 25 successive rotations and rejects every historical owner including the initial and currently active owner.
- Recipient revert rolls back ETH, funding, owner, nonce, pending state, consumption and counter; the same candidate can subsequently succeed.
- Two signatures targeting the same Safe nonce cannot both succeed; the losing candidate remains available. Browser preparation also rejects simultaneous sends.
- Reentrant recipient execution and a recipient deploying code at the proposed owner address are rejected without weakening the ETH-only policy.
- Browser E2E chooses a new seed at derivation index 147, offers manual recovery when automatic indices 0–99 do not match, clears all browser storage, recovers by explicit range and saves the Safe address again.
- Injected RPC failures after mining exposed two duplicate-send bugs during review: owner reconciliation and a subsequent UI balance refresh could each cause a retry to send again. Both regressions were observed failing, fixed, and rerun successfully. Retrying now reconciles the original transfer instead of broadcasting another.
- Recovery fallback previously said a backed-up wallet could not be restored; it now opens manual recovery with the search error. A separate failing assertion caught the missing restored Safe address persistence.

## Follow-up UI review validation

The two UI review defects were reproduced with failing browser assertions before their fixes:

- Selecting seed B then recovering seed A without Lock deleted A’s encrypted vault after an A rotation. The regression now verifies the vault is unchanged and reload restores the actual A signer. App no longer holds a parallel selected mnemonic; persistence uses the reconciled signer session, and recovery clears UI selection/confirmed-action state.
- After a mined transaction’s owner read failed, changing both amount and recipient on retry mislabeled the original hash with the new amount. A second case with empty amount and invalid recipient blocked reconciliation entirely. Both now pass: pending state retains the original Safe, recipient and amount; reconciliation precedes new-form validation; history reports the original amount, recipient and hash. Recipient balance checks and the rotation count prove no second payment.

Follow-up checks rerun: 29 unit tests / 52 assertions passed; typecheck and production build passed; 11 contract tests passed; release verification checked 8 static files; default browser suite 8 passed / 7 gated skipped; gated persistence 5 passed; local-fork dynamic browser regressions 2 passed; `git diff --check` passed. Playwright emitted its expected service-worker-blocked warnings in the browser-restart persistence test. Dependency installation/audit/report and the 28-rotation smoke rows above are earlier implementation evidence, not rerun for this UI-only follow-up. No contracts or security restrictions changed.

## Limits

No live V2 Sepolia transactions were broadcast and no hosted site was deployed. Live scripts require explicit opt-in and disposable funding; legacy V1 evidence is not evidence for V2. Hardware signing and unsupported transaction types remain disabled. Additional independent security review and parser/property fuzzing remain required before any broader use. A compromised current signer can still substitute an attacker-controlled fresh owner. Bounded recovery needs the correct seed and derivation range; lost seed material cannot be reconstructed from chain history.
