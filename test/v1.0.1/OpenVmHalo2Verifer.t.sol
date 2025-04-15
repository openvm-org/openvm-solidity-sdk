// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { LibString } from "../helpers/LibString.sol";
import { Test, console2, safeconsole as console } from "forge-std/Test.sol";
import { OpenVmHalo2Verifier } from "../../src/v1.0.1/OpenVmHalo2Verifier.sol";

contract OpenVmHalo2VerifierTest is Test {
    bytes proofData;
    bytes32 appExeCommit = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    bytes32 appVmCommit = 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE;
    bytes guestPvs;

    uint256 constant PUBLIC_VALUES_LENGTH = 32;
    OpenVmHalo2Verifier verifier;

    function setUp() public {
        proofData = new bytes(55 * 32);
        for (uint256 i = 0; i < 55; i++) {
            for (uint256 j = 0; j < 32; j++) {
                proofData[i * 32 + j] = bytes1(uint8(i));
            }
        }

        verifier = new OpenVmHalo2Verifier();
    }

    function test_ValidProofVerifies() public view {
        string memory evmProofJson = vm.readFile("test/v1.0.1/evm.proof");
        bytes32 _appExeCommit = vm.parseJsonBytes32(evmProofJson, ".app_exe_commit");
        bytes32 _appVmCommit = vm.parseJsonBytes32(evmProofJson, ".app_vm_commit");
        bytes memory _guestPvs = vm.parseJsonBytes(evmProofJson, ".user_public_values");
        bytes memory accumulator = vm.parseJsonBytes(evmProofJson, ".proof_data.accumulator");
        bytes memory proof = vm.parseJsonBytes(evmProofJson, ".proof_data.proof");
        bytes memory _proofData = abi.encodePacked(accumulator, proof);

        verifier.verify(_guestPvs, _proofData, _appExeCommit, _appVmCommit);
    }

    function test_ProofFormat() public {
        guestPvs = new bytes(PUBLIC_VALUES_LENGTH);
        for (uint256 i = 0; i < PUBLIC_VALUES_LENGTH; i++) {
            guestPvs[i] = bytes1(uint8(i));
        }

        (bool success,) = address(verifier).delegatecall(
            abi.encodeCall(OpenVmHalo2Verifier.verify, (guestPvs, proofData, appExeCommit, appVmCommit))
        );
        require(success, "Verification failed");
    }

    fallback(bytes calldata proof) external returns (bytes memory) {
        bytes memory proofDataExpected = proofData;

        uint256 proofSuffixOffset = 0x1c0 + (32 * PUBLIC_VALUES_LENGTH);

        bytes memory kzgAccumulator = proof[0:0x180];
        bytes memory proofSuffix = proof[proofSuffixOffset:];
        bytes memory _proofData = abi.encodePacked(kzgAccumulator, proofSuffix);

        require(keccak256(_proofData) == keccak256(proofDataExpected), "Partial proof mismatch");

        bytes memory _appExeCommit = proof[0x180:0x1a0];
        bytes memory _appVmCommit = proof[0x1a0:0x1c0];

        require(bytes32(_appExeCommit) == appExeCommit, "App exe commit mismatch");
        require(bytes32(_appVmCommit) == appVmCommit, "App vm commit mismatch");

        bytes calldata _guestPvs = proof[0x1c0:0x1c0 + 32 * PUBLIC_VALUES_LENGTH];
        for (uint256 i = 0; i < PUBLIC_VALUES_LENGTH; ++i) {
            uint256 expected = uint256(uint8(guestPvs[i]));
            uint256 actual = uint256(bytes32(_guestPvs[i * 32:(i + 1) * 32]));
            require(expected == actual, "Guest PVs hash mismatch");
        }

        // Suppress return value warning
        assembly {
            return(0x00, 0x00)
        }
    }

    function test_RevertWhen_InvalidPublicValuesLength() public {
        bytes memory invalidPvs = new bytes(0);
        bytes4 sig = bytes4(keccak256("InvalidPublicValuesLength(uint256,uint256)"));

        vm.expectRevert(abi.encodeWithSelector(sig, 32, invalidPvs.length));
        verifier.verify(invalidPvs, hex"", bytes32(0), bytes32(0));
    }

    function test_RevertWhen_InvalidProofDataLength() public {
        bytes memory invalidProofData = new bytes(0);
        bytes4 sig = bytes4(keccak256("InvalidProofDataLength(uint256,uint256)"));

        bytes memory pvs = new bytes(PUBLIC_VALUES_LENGTH);

        vm.expectRevert(abi.encodeWithSelector(sig, 55 * 32, invalidProofData.length));
        verifier.verify(pvs, invalidProofData, appExeCommit, appVmCommit);
    }

    function test_RevertWhen_ProofVerificationFailed() public {
        bytes memory _proofData = new bytes(55 * 32);
        bytes memory pvs = new bytes(PUBLIC_VALUES_LENGTH);

        bytes4 sig = bytes4(keccak256("ProofVerificationFailed()"));

        vm.expectRevert(abi.encodeWithSelector(sig));
        verifier.verify(pvs, _proofData, appExeCommit, appVmCommit);
    }
}
