// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { OpenVmHalo2Verifier } from "../src/OpenVmHalo2Verifier.sol";
import { Test, console2, safeconsole as console } from "forge-std/Test.sol";

contract MockVerifier is OpenVmHalo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        return hex"";
    }
}

contract OpenVmHalo2VerifierTest is Test, OpenVmHalo2Verifier {
    bytes partialProof;
    bytes32 appExeCommit = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    bytes32 leafExeCommit = 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE;
    bytes32 guestPvsHash = 0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD;

    function setUp() public {
        partialProof = new bytes(55 * 32);
        for (uint256 i = 0; i < 55; i++) {
            for (uint256 j = 0; j < 32; j++) {
                partialProof[i * 32 + j] = bytes1(uint8(i));
            }
        }
    }

    function test_proofFormat() public view {
        this.verifyProof(abi.encodePacked(guestPvsHash), partialProof, appExeCommit, leafExeCommit);
    }

    function testFuzz_proofFormat(
        uint256 partialProofSeed,
        bytes32 _guestPvsHash,
        bytes32 _appExeCommit,
        bytes32 _leafExeCommit
    ) public {
        vm.assume(_guestPvsHash != bytes32(0));
        vm.assume(_appExeCommit != bytes32(0));
        vm.assume(_leafExeCommit != bytes32(0));

        bytes memory _partialProof = new bytes(55 * 32);
        for (uint256 i = 0; i < 55 * 32; ++i) {
            bytes1 _byte = bytes1(uint8(uint256(keccak256(abi.encodePacked(partialProofSeed, i)))));
            _partialProof[i] = _byte;
        }

        partialProof = _partialProof;
        guestPvsHash = _guestPvsHash;
        appExeCommit = _appExeCommit;
        leafExeCommit = _leafExeCommit;

        test_proofFormat();
    }

    function test_RevertWhen_InvalidPartialProofLength() public {
        vm.expectRevert(abi.encodeWithSelector(OpenVmHalo2Verifier.InvalidPartialProofLength.selector));
        this.verifyProof(abi.encodePacked(guestPvsHash), hex"aa", appExeCommit, leafExeCommit);
    }

    function test_RevertWhen_InvalidGuestPvsLength() public {
        vm.expectRevert(abi.encodeWithSelector(OpenVmHalo2Verifier.InvalidGuestPvsLength.selector));
        this.verifyProof(partialProof, hex"aa", appExeCommit, leafExeCommit);
    }

    fallback(bytes calldata) external returns (bytes memory) {
        bytes memory partialProofExpected = partialProof;

        bytes memory kzgAccumulators = msg.data[0:0x180];
        bytes memory guestPvsSuffix = msg.data[0x5c0:];
        bytes memory _partialProof = abi.encodePacked(kzgAccumulators, guestPvsSuffix);
        require(keccak256(_partialProof) == keccak256(partialProofExpected), "Partial proof mismatch");

        bytes memory _appExeCommit = msg.data[0x180:0x1a0];
        bytes memory _leafExeCommit = msg.data[0x1a0:0x1c0];

        require(bytes32(_appExeCommit) == appExeCommit, "App exe commit mismatch");
        require(bytes32(_leafExeCommit) == leafExeCommit, "Leaf exe commit mismatch");

        bytes32 guestPvsHashExpected = guestPvsHash;
        bytes calldata _guestPvsHash = msg.data[0x1c0:0x5c0];
        for (uint256 i = 0; i < 32; ++i) {
            uint256 expected = uint256(uint8(guestPvsHashExpected[i]));
            uint256 actual = uint256(bytes32(_guestPvsHash[i * 32:(i + 1) * 32]));
            require(expected == actual, "Guest PVs hash mismatch");
        }

        return hex"";
    }
}
