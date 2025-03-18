// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

error ProofVerificationFailed();
error InvalidAppExeCommit();
error InvalidLeafExeCommit();

function formatAndVerifyProof(
    bytes calldata partialProof,
    bytes memory publicValues,
    address verifier,
    bytes32 appExeCommit,
    bytes32 leafExeCommit
) view {
    /// @solidity memory-safe-assembly
    assembly {
        let partialProofLength := partialProof.length
        let pvsLength := mload(publicValues)
        let totalProofLength := add(partialProofLength, pvsLength)
        let suffixOffset := add(pvsLength, 0x1c0)

        // Allocate for the memory usage as a safety measure.
        let fmp := mload(0x40)
        mstore(0x40, add(fmp, totalProofLength))

        if iszero(eq(calldataload(add(partialProof.offset, 0x180)), appExeCommit)) {
            mstore(0x00, 0x8cda48cf) // InvalidAppExeCommit()
            revert(0x1c, 0x04)
        }

        if iszero(eq(calldataload(add(partialProof.offset, 0x1a0)), leafExeCommit)) {
            mstore(0x00, 0x438a69e7) // InvalidLeafExeCommit()
            revert(0x1c, 0x04)
        }

        // Copy the Guest PVs Prefix (length 0x1c0) into the beginning of
        // the memory buffer
        calldatacopy(fmp, partialProof.offset, 0x1c0)

        // Copy the Guest PVs Suffix (length 43 * 32 = 0x560) into the
        // end of the memory buffer (between suffixOffset - TOTAL_PROOF_LENGTH),
        // leaving 32 words in between for the guestPvsHash.
        //
        // Begin copying from the end of the Guest PVs Prefix in the
        // calldata buffer (0x1c0)
        calldatacopy(add(fmp, suffixOffset), add(partialProof.offset, 0x1c0), 0x560)

        // Copy each byte of the guestPvsHash into the proof. It copies the
        // most significant bytes of guestPvsHash first.

        // Begin by loading 32-byte segments and copying each byte into its own memory slot.
        let wordCount := div(pvsLength, 32)
        let pvsReadOffset := add(publicValues, 0x20)

        let guestPvsMemOffset := add(fmp, 0x1c0)
        for { let i := 0 } iszero(eq(i, wordCount)) { i := add(i, 1) } {
            let word := mload(add(pvsReadOffset, shl(5, i)))
            for { let j := 0 } iszero(eq(j, 32)) { j := add(j, 1) } {
                mstore(add(guestPvsMemOffset, add(shl(5, i), j)), byte(j, word))
            }
        }

        // Then, copy the remaining bytes into the memory buffer.
        let remainder := mod(pvsLength, 32)
        guestPvsMemOffset := add(guestPvsMemOffset, shl(5, wordCount))

        let remainingBytes := mload(add(pvsReadOffset, shl(5, wordCount)))
        for { let i := 0 } iszero(eq(i, remainder)) { i := add(i, 1) } {
            mstore(add(guestPvsMemOffset, shl(5, i)), byte(i, remainingBytes))
        }

        if iszero(staticcall(gas(), verifier, fmp, totalProofLength, 0, 0)) {
            mstore(0x00, 0xd611c318) // ProofVerificationFailed()
            revert(0x1c, 0x04)
        }
    }
}
