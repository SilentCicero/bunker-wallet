# Architecture

```mermaid
flowchart LR
  UI[SolidJS PWA] --> Core[Pure policy + commitments]
  UI --> Vault[Argon2id / AES-GCM vault]
  UI --> File[Bounded offline envelope]
  File --> Relay[Loopback validator]
  Core -. future audited integration .-> Safe[Safe 1.4.1 proxy]
  Safe -. exact batch .-> Guard[BunkerRotationGuard]
```

The browser UI is not a trust boundary. `core`, `offline`, and `vault` isolate reviewable logic but compile into the same origin. The intended on-chain path is one pinned `MultiSendCallOnly` delegatecall: an ETH transfer with no calldata followed by the Safe's exact owner swap. The guard is present as reviewable research source, not a deployment artifact.
