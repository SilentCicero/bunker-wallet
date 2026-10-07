# Offline files

The current UI can create and inspect versioned demonstration files. Payloads are capped at 64 KiB, reject unknown fields, use canonical decimal and hex forms, require zero refund economics, and carry a Keccak checksum. The checksum detects mutation but does not authenticate the coordinator or live chain. Signing and broadcasting are disabled until the production encoder, authenticated checkpoint, exact Safe hash, simulation, nonce reconciliation, and signature policy are integrated.
