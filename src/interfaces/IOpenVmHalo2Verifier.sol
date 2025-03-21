// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IOpenVmHalo2Verifier {
    function verify(bytes calldata publicValues, bytes calldata proofData, bytes32 appExeCommit) external view;
}
