# Security decisions

| Decision | Alpha behavior | Reason |
|---|---|---|
| Mainnet | Rejected in pure policy and hidden from UI | External audit is mandatory. |
| Owner sequence | Fixed 20-address batch; last transition reserved | Dynamic refill authorization is unresolved and exhaustion can lock funds. |
| Execution | ETH transfer plus one exact `swapOwner` only | Reduces privileged-call and persistent-authority surface. |
| Refund fields | All zero | Safe refund economics are an additional value-transfer channel. |
| Modules and fallback | No modules; fallback must be absent | Module execution can bypass transaction guards. |
| Offline | Bounded file transport only | QR parsing expands unreviewed input surface. Cached PWA means offline-capable, not offline-verified. |
| Vault | Argon2id + AES-256-GCM or seed-only with no persistence | Passwords are not encryption keys; plaintext storage is prohibited. |
| Hardware/manual | Disabled and unverified | Generic APIs do not prove sequence derivation or clear review. |
| Relayer | Loopback validation only, no key | Broadcasting requires live state, simulation, replay, and economics controls. |
