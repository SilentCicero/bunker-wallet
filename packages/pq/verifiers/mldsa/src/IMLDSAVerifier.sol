// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title  IMLDSAVerifier — entry-point interface for on-chain FIPS 204
///         ML-DSA-44 signature verification.
/// @notice Verification semantics:
///           * parameter set ML-DSA-44 (FIPS 204), pure (non-prehashed),
///             *external* interface with an EMPTY context string, i.e. the
///             verifier itself forms M' = 0x00 || 0x00 || M;
///           * `signature` is the standard 2420-byte sigEncode output
///             (FIPS 204 Algorithm 26);
///           * `pkBlob` is the address of a data contract whose *code* is
///             exactly the output of prepare/prepare.py run on the standard
///             1312-byte FIPS 204 public key (see docs/SAFETY.md section 3 for
///             the MANDATORY registration-time validation of that blob);
///           * the verdict is a deterministic function of
///             (pkBlob code, message, signature) alone — independent of block
///             context, caller and gas;
///           * safe to call via STATICCALL: no state writes, no logs, no
///             contract creation, no self-destruct, no delegatecall.
///         Returning `false` and reverting are both "not accepted"; only `true`
///         is acceptance.
interface IMLDSAVerifier {
    /// @param pkBlob    data contract holding the prepared public-key blob
    /// @param message   the message M (raw, not domain-separated)
    /// @param signature 2420-byte FIPS 204 ML-DSA-44 signature
    /// @return accepted true iff the signature is valid for (pkBlob, message)
    function verify(address pkBlob, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool accepted);
}
