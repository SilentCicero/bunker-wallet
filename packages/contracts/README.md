# BunkerRotationGuard

Unaudited local/Sepolia research contract targeting Safe 1.4.1. It permits only a pinned `MultiSendCallOnly` delegatecall containing one empty-calldata ETH transfer followed by `swapOwner(SENTINEL,current,next)`. Refund economics, modules, refill, upgrades, and the final committed transition are blocked.

The contract has not passed Foundry or real-Safe integration tests in this repository because Foundry is not installed. It must not be deployed or funded until atomic bootstrap, guard-slot permanence, exact Safe behavior, bytecode hashes, fuzzing, and external review are complete.
