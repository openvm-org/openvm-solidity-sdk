// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IOpenVmHalo2Verifier {
    function verify(bytes calldata guestPvs, bytes calldata partialProof, bytes32 appExeCommit) external view;
}
