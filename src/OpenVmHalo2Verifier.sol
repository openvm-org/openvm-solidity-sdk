// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import { AxiomV2QueryVerifier } from "./Halo2Verifier.sol";

type MemoryPointer is uint256;

/// @notice This contract provides a thin wrapper around the Halo2 verifier
/// outputted by `snark-verifier`, exposing a more user-friendly interface.
contract OpenVmHalo2Verifier is AxiomV2QueryVerifier {
    /// @dev Invalid partial proof length
    error InvalidPartialProofLength();

    /// @dev Invalid guest PVs length
    error InvalidGuestPvsLength();

    /// @dev Proof verification failed
    error ProofVerificationFailed();

    /// @dev The length of the partial proof, in bytes
    uint256 private constant PARTIAL_PROOF_LENGTH = (12 + 43) * 32;

    /// @dev The length of the guest PVs, in bytes. This value is set by OpenVM.
    uint256 private constant GUEST_PVS_LENGTH = 32;

    /// @dev The length of the full proof, in bytes
    uint256 private constant FULL_PROOF_LENGTH = (12 + 2 + GUEST_PVS_LENGTH + 43) * 32;

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
    /// proof[14 * 32..(14 + GUEST_PVS_LENGTH) * 32]: guestPvs[0..GUEST_PVS_LENGTH]
    /// proof[(14 + GUEST_PVS_LENGTH) * 32..]: Guest PVs Suffix
    ///
    /// Or with hex offsets
    ///
    /// proof[..0x180]: KZG accumulators
    /// proof[0x180..0x1a0]: app exe commit
    /// proof[0x1a0..0x1c0]: leaf exe commit
    /// proof[0x1c0..(0x1c0 + GUEST_PVS_LENGTH * 32)]: guestPvs[0..GUEST_PVS_LENGTH]
    /// proof[(0x1c0 + GUEST_PVS_LENGTH * 32)..]: Guest PVs Suffix
    ///
    /// @param partialProof All components of the proof except the Guest PVs,
    /// leaf and app exe commits. The expected format is:
    /// `abi.encodePacked(KZG accumulators, Guest PVs Suffix)`
    /// @param guestPvs The PVs revealed by the OpenVM guest program.
    /// @param appExeCommit The commitment to the RISC-V executable whose execution
    /// is being verified.
    /// @param leafExeCommit The commitment to the leaf verifier.
    function verifyProof(
        bytes calldata guestPvs,
        bytes calldata partialProof,
        bytes32 appExeCommit,
        bytes32 leafExeCommit
    ) external view {
        // We will format the public values and construct the full proof payload
        // below.

        MemoryPointer proofPtr = _constructProof(guestPvs, partialProof, appExeCommit, leafExeCommit);

        uint256 fullProofLength = FULL_PROOF_LENGTH;
        assembly {
            // Self-call using the proof as calldata
            if iszero(staticcall(gas(), address(), proofPtr, fullProofLength, 0, 0)) {
                mstore(0x00, 0xd611c318) // ProofVerificationFailed()
                revert(0x1c, 0x04)
            }
        }
    }

    function _constructProof(
        bytes calldata guestPvs,
        bytes calldata partialProof,
        bytes32 appExeCommit,
        bytes32 leafExeCommit
    ) internal pure returns (MemoryPointer proofPtr) {
        if (guestPvs.length != GUEST_PVS_LENGTH) revert InvalidGuestPvsLength();
        if (partialProof.length != PARTIAL_PROOF_LENGTH) revert InvalidPartialProofLength();

        // The assembly code should perform the same function as the following
        // solidity code:
        //
        // ```solidity
        // bytes memory proof =
        //     abi.encodePacked(partialProof[0:0x180], appExeCommit, leafExeCommit, guestPvsPayload, partialProof[0x180:]);
        // ```
        //
        // where `guestPvsPayload` is a memory payload with each byte in
        // `guestPvs` separated into its own word.

        uint256 fullProofLength = FULL_PROOF_LENGTH;

        /// @solidity memory-safe-assembly
        assembly {
            proofPtr := mload(0x40)
            // Allocate the memory as a safety measure
            mstore(0x40, add(proofPtr, fullProofLength))

            // Copy the KZG accumulators (length 0x180) into the beginning of
            // the memory buffer
            calldatacopy(proofPtr, partialProof.offset, 0x180)

            // Copy the App Exe Commit and Leaf Exe Commit into the memory buffer
            mstore(add(proofPtr, 0x180), appExeCommit)
            mstore(add(proofPtr, 0x1a0), leafExeCommit)

            // Copy the Guest PVs Suffix (length 43 * 32 = 0x560) into the
            // end of the memory buffer, leaving GUEST_PVS_LENGTH words in
            // between for the guestPvsPayload.
            //
            // Begin copying from the end of the KZG accumulators in the
            // calldata buffer (0x180)
            let suffixProofOffset := add(0x1c0, shl(5, GUEST_PVS_LENGTH))
            calldatacopy(add(proofPtr, suffixProofOffset), add(partialProof.offset, 0x180), 0x560)

            // Copy each byte of the guestPvs into the proof. It copies the
            // most significant bytes of guestPvs first.
            let guestPvsMemOffset := add(proofPtr, 0x1c0)
            for { let i := 0 } lt(i, GUEST_PVS_LENGTH) { i := add(i, 1) } {
                calldatacopy(add(guestPvsMemOffset, add(shl(5, i), 0x1f)), add(guestPvs.offset, i), 0x01)
            }
        }
    }
}
