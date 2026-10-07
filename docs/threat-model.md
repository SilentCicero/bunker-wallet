# Threat model

Assume the page, extensions, RPC, coordinator, imported files, and relay can be malicious. The alpha validates formats and policy locally but cannot make a compromised browser trustworthy. Atomic rotation reduces historical ECDSA public-key exposure after confirmation; it does not remove the pending-transaction attack window, stop seed theft, or provide post-quantum signatures. On-chain safety depends on an unaudited custom guard and exact Safe behavior, so deployment is blocked.

Primary failure modes are malicious calldata, Safe module bypass, altered refund fields, stale state, replay, sequence exhaustion, compromised seed entry, hostile imports, and misleading offline state. Controls fail closed and unsupported paths remain disabled.
