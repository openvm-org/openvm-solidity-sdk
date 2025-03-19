// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

/// @notice This contract provides a thin wrapper around the Halo2 verifier
/// outputted by `snark-verifier`.
///
/// @dev This contract should be inherited by the `snark-verifier` output.
abstract contract OpenVmHalo2Verifier {
    error InvalidPartialProofLength();
    error InvalidGuestPvsLength();
    error ProofVerificationFailed();

    uint256 private constant PARTIAL_PROOF_LENGTH = (12 + 43) * 32;

    uint256 private constant FULL_PROOF_LENGTH = (12 + 2 + 32 + 43) * 32;

    /// @notice A wrapper that constructs the proof into the right format for
    /// use with the `snark-verifier` verification.
    ///
    /// @dev This function assumes that `publicValues` encodes one `bytes32`
    /// hash which is the hash of the public values.
    ///
    /// The verifier expected proof format is:
    /// proof[..12 * 32]: KZG accumulators
    /// proof[12 * 32..13 * 32]: app exe commit
    /// proof[13 * 32..14 * 32]: leaf exe commit
    /// proof[14 * 32..46 * 32]: guestPvsHash[0..32]
    /// proof[46 * 32..]: Guest PVs Suffix
    ///
    /// Or with hex offsets
    ///
    /// proof[..0x180]: KZG accumulators
    /// proof[0x180..0x1a0]: app exe commit
    /// proof[0x1a0..0x1c0]: leaf exe commit
    /// proof[0x1c0..0x5c0]: guestPvsHash[0..32]
    /// proof[0x5c0..]: Guest PVs Suffix
    ///
    /// @param partialProof All components of the proof except the Guest PVs,
    /// leaf and app exe commits. The expected format is:
    /// `abi.encodePacked(KZG accumulators, Guest PVs Suffix)`
    /// @param guestPvs The PVs revealed by the OpenVM guest program. This
    /// contract is only compatible with a reveal of exactly 32 bytes.
    /// @param appExeCommit The commitment to the RISC-V executable whose execution
    /// is being verified.
    /// @param leafExeCommit The commitment to the leaf verifier.
    function verifyProof(
        bytes calldata partialProof,
        bytes calldata guestPvs,
        bytes32 appExeCommit,
        bytes32 leafExeCommit
    ) external view {
        if (guestPvs.length != 32) revert InvalidGuestPvsLength();
        if (partialProof.length != PARTIAL_PROOF_LENGTH) revert InvalidPartialProofLength();

        //  We will format the pvsHash and construct the full proof payload
        //  below for submission to the verifier.

        // The assembly code should perform the same function as the following
        // solidity code:
        //
        // bytes memory guestPvsPayload = new bytes(32 * 32);
        // for (uint256 i = 0; i < 32; ++i) {
        //     bytes1 pvsByte = guestPvs[i];
        //     guestPvsPayload = bytes.concat(guestPvsPayload, bytes32(uint256(uint8(pvsByte))));
        // }
        //
        // bytes memory proof =
        //     abi.encodePacked(partialProof[0:0x180], appExeCommit, leafExeCommit, guestPvsPayload, partialProof[0x180:]);
        //
        // (bool success,) = address(this).staticcall(proof);
        // if (!success) revert ProofVerificationFailed();

        /// @solidity memory-safe-assembly
        assembly {
            let fmp := mload(0x40)
            mstore(0x40, add(fmp, FULL_PROOF_LENGTH))

            let guestPvsHash := calldataload(guestPvs.offset)

            // Copy the KZG accumulators (length 0x180) into the beginning of
            // the memory buffer
            calldatacopy(fmp, partialProof.offset, 0x180)

            // Copy the App Exe Commit and Leaf Exe Commit into the memory buffer
            mstore(add(fmp, 0x180), appExeCommit)
            mstore(add(fmp, 0x1a0), leafExeCommit)

            // Copy the Guest PVs Suffix (length 43 * 32 = 0x560) into the
            // end of the memory buffer (between 0x5c0 - TOTAL_PROOF_LENGTH),
            // leaving 32 words in between for the guestPvsHash.
            //
            // Begin copying from the end of the KZG accumulators in the
            // calldata buffer (0x180)
            calldatacopy(add(fmp, 0x5c0), add(partialProof.offset, 0x180), 0x560)

            // Copy each byte of the guestPvsHash into the proof. It copies the
            // most significant bytes of guestPvsHash first.
            let guestPvsMemOffset := add(fmp, 0x1c0)
            mstore(add(guestPvsMemOffset, 0x00), byte(0x00, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x20), byte(0x01, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x40), byte(0x02, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x60), byte(0x03, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x80), byte(0x04, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0xa0), byte(0x05, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0xc0), byte(0x06, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0xe0), byte(0x07, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x100), byte(0x08, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x120), byte(0x09, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x140), byte(0x0a, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x160), byte(0x0b, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x180), byte(0x0c, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x1a0), byte(0x0d, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x1c0), byte(0x0e, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x1e0), byte(0x0f, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x200), byte(0x10, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x220), byte(0x11, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x240), byte(0x12, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x260), byte(0x13, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x280), byte(0x14, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x2a0), byte(0x15, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x2c0), byte(0x16, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x2e0), byte(0x17, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x300), byte(0x18, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x320), byte(0x19, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x340), byte(0x1a, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x360), byte(0x1b, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x380), byte(0x1c, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x3a0), byte(0x1d, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x3c0), byte(0x1e, guestPvsHash))
            mstore(add(guestPvsMemOffset, 0x3e0), byte(0x1f, guestPvsHash))

            // Self-call using the proof as calldata
            if iszero(staticcall(gas(), address(), fmp, FULL_PROOF_LENGTH, 0, 0)) {
                mstore(0x00, 0xd611c318) // ProofVerificationFailed()
                revert(0x1c, 0x04)
            }
        }
    }
}
