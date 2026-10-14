# Contracts

Unaudited local/Ethereum Sepolia research contracts targeting official Safe 1.4.1. `BunkerRotationGuard` permits only a canonical `MultiSendCallOnly` delegatecall containing an ETH transfer, exactly `0.001 ETH` funding for the next EOA owner, and `swapOwner(SENTINEL,current,next)`. Refunds, modules, arbitrary calls, guard changes, and mainnet deployment are blocked.

`BunkerSafeSetup` installs and initializes the guard during `Safe.setup`, so proxy creation has no unguarded owner window. The guard accepts canonical ABI padding, verifies the pinned MultiSend runtime hash, rejects contract/sentinel/Safe owners, and consumes the initial owner. V2 accepts any fresh next EOA selected by the current signer, permanently records it only on successful atomic replacement, and increments a uint256 rotation counter. There are no future commitments or fixed rotation limits. A compromised current signer can substitute an attacker-controlled fresh owner.

Run:

```bash
PATH="$HOME/.foundry/bin:$PATH" forge test
```

The integration suite deploys the official vendored Safe singleton, proxy factory, canonical `MultiSendCallOnly`, setup helper, and guard locally. It proves atomic setup, canonical padded execution, recipient transfer, next-owner gas funding, owner rotation, malformed funding rejection, 25 consecutive rotations, all historical-owner rejection, complete rollback, and simultaneous pending rotation exclusion.

These contracts remain unaudited. Ethereum Sepolia use must remain disposable and restricted-value; mainnet and meaningful funds are prohibited.
