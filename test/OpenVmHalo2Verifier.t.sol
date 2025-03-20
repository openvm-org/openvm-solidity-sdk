// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { OpenVmHalo2Verifier, MemoryPointer } from "../src/OpenVmHalo2Verifier.sol";
import { Test, console2, safeconsole as console } from "forge-std/Test.sol";

contract OpenVmHalo2VerifierTest is Test, OpenVmHalo2Verifier {
    bytes partialProof;
    bytes32 appExeCommit = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    bytes32 guestPvsHash = 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE;

    uint256 private constant FULL_PROOF_WORDS = (12 + 2 + 32 + 43);

    uint256 private constant FULL_PROOF_LENGTH = (12 + 2 + 32 + 43) * 32;

    function setUp() public {
        partialProof = new bytes(55 * 32);
        for (uint256 i = 0; i < 55; i++) {
            for (uint256 j = 0; j < 32; j++) {
                partialProof[i * 32 + j] = bytes1(uint8(i));
            }
        }
    }

    function test_verifyProof() public view {
        this.verify(abi.encodePacked(guestPvsHash), partialProof, appExeCommit);
    }

    function test_proofFormat() public view {
        this.constructAndCheckProof(abi.encodePacked(guestPvsHash), partialProof, appExeCommit);
    }

    function testFuzz_proofFormat(uint256 partialProofSeed, bytes32 _guestPvsHash, bytes32 _appExeCommit) public {
        vm.assume(_guestPvsHash != bytes32(0));
        vm.assume(_appExeCommit != bytes32(0));

        bytes memory _partialProof = new bytes(55 * 32);
        for (uint256 i = 0; i < 55 * 32; ++i) {
            bytes1 _byte = bytes1(uint8(uint256(keccak256(abi.encodePacked(partialProofSeed, i)))));
            _partialProof[i] = _byte;
        }

        partialProof = _partialProof;
        guestPvsHash = _guestPvsHash;
        appExeCommit = _appExeCommit;

        test_proofFormat();
    }

    function constructAndCheckProof(bytes calldata _guestPvs, bytes calldata _partialProof, bytes32 _appExeCommit)
        external
        view
    {
        MemoryPointer proofPtr = _constructProof(_guestPvs, _partialProof, _appExeCommit);

        // _constructProof will return a pointer to memory that will hold the
        // proof data in a block of size FULL_PROOF_LENGTH. However, this won't
        // be directly compatible with `bytes memory` since it will be missing
        // the length as the first word. So below, we will
        //
        // 1. Move all the data down by 32 bytes in memory
        // 2. Set the length in the first word which we just created the space for
        // 3. Allocate the memory for the length (32 bytes)
        // 4. Create a `bytes memory` pointer which points to the length

        uint256 i = FULL_PROOF_WORDS - 1;
        while (true) {
            uint256 currentPtr = MemoryPointer.unwrap(proofPtr) + i * 32;
            // console.log("currentPtr", currentPtr);
            uint256 destPtr = MemoryPointer.unwrap(proofPtr) + ((i + 1) * 32);
            // console.log("destPtr", destPtr);
            assembly {
                mstore(destPtr, mload(currentPtr))
            }
            if (i == 0) break;
            i--;
        }

        bytes memory proof;
        assembly {
            // 2.
            mstore(proofPtr, FULL_PROOF_LENGTH)
            // 3.
            mstore(0x40, add(mload(0x40), 0x20))

            // 4.
            proof := proofPtr
        }

        this.checkProofFormat(proof);
    }

    function checkProofFormat(bytes calldata proof) external view {
        bytes memory partialProofExpected = partialProof;

        bytes memory kzgAccumulators = proof[0:0x180];
        bytes memory guestPvsSuffix = proof[0x5c0:];
        bytes memory _partialProof = abi.encodePacked(kzgAccumulators, guestPvsSuffix);
        require(keccak256(_partialProof) == keccak256(partialProofExpected), "Partial proof mismatch");

        bytes memory _appExeCommit = proof[0x180:0x1a0];
        bytes memory _leafExeCommit = proof[0x1a0:0x1c0];

        require(bytes32(_appExeCommit) == appExeCommit, "App exe commit mismatch");
        require(bytes32(_leafExeCommit) == LEAF_EXE_COMMIT, "Leaf exe commit mismatch");

        bytes32 guestPvsHashExpected = guestPvsHash;
        bytes calldata _guestPvsHash = proof[0x1c0:0x5c0];
        for (uint256 i = 0; i < 32; ++i) {
            uint256 expected = uint256(uint8(guestPvsHashExpected[i]));
            uint256 actual = uint256(bytes32(_guestPvsHash[i * 32:(i + 1) * 32]));
            require(expected == actual, "Guest PVs hash mismatch");
        }
    }

    function test_RevertWhen_InvalidPartialProofLength() public {
        vm.expectRevert(abi.encodeWithSelector(OpenVmHalo2Verifier.InvalidPartialProofLength.selector));
        this.verify(abi.encodePacked(guestPvsHash), hex"aa", appExeCommit);
    }

    function test_RevertWhen_InvalidGuestPvsLength() public {
        vm.expectRevert(abi.encodeWithSelector(OpenVmHalo2Verifier.InvalidGuestPvsLength.selector));
        this.verify(partialProof, hex"aa", appExeCommit);
    }
}
