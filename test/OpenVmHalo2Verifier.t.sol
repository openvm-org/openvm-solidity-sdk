// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import { OpenVmHalo2Verifier, MemoryPointer } from "../src/OpenVmHalo2Verifier.sol";
import { Test, console2, safeconsole as console } from "forge-std/Test.sol";

contract OpenVmHalo2VerifierTest is Test, OpenVmHalo2Verifier {
    bytes partialProof;

    bytes private constant kzgAccumulators =
        hex"000000000000000000000000000000000000000000d1437a9bb9ac3c1a16992c00000000000000000000000000000000000000000021a9ab5617c2d7d6ccf9af0000000000000000000000000000000000000000000008ba19dc0f462a92dc0900000000000000000000000000000000000000000025694ae0246cb4b406b0970000000000000000000000000000000000000000004ec055f528761bb24e7098000000000000000000000000000000000000000000000b0dcb882b8af688ddc4000000000000000000000000000000000000000000e7eb1b7903923438cc8b54000000000000000000000000000000000000000000af1197617343468c85c9d6000000000000000000000000000000000000000000002d22b55036423bb4c266000000000000000000000000000000000000000000280255aa13e24534841355000000000000000000000000000000000000000000bcffb01f01132cb2ea1eb20000000000000000000000000000000000000000000000c69662a512b8d21501";
    bytes private constant suffix =
        hex"2775c493e84b4ea63465d98b4666134e274cd3d66eaf6b59a6dbeddb594de2091ae1f48e567caf12f2b888d339ba7f99ab4603cf008397276d562f67ad058c9410cc4bdb94e881438afc407093d722a48089d5784437d52a4bafc6e9819bf4e00bec156cd36cb7f7883d9ed0196b4f2ce825b2b579a08ec670d0b8708d476f610d620bbaac86de1c27ad5dfce81d3479c72e603025c1b3dc30559150467c1680022031fdd52469b8884250650abf7fb3c5a38018c285e3412d266f937aa0ef2c0d07838c09f45be93e8c0f653eddcb3565cb6c124dca1433684aba18f8cb58802af17390906939ca5d7f37bcd2f02f5138c9afcdd6ebe543dbbee0f775e1c40d2722ddbd7b4c08aba7a4f7ebd96b801afb946e453e69ea9ce118d47f6408b21914042c2f38028b0c160541d4fadb04a1a5b647cc8569247377be8202a468b1cb279b82a31e702f57385e36f7734f6b391d6a50fd14d09e0c30eab5cc4c8c6e5029bd146dea01b1b317ec886eaef10e4752867f6a0f88f20ba6e23b5a842e930d2883c12cbcf1306cedc382aa0207cb33cf01435390660f944e69687fb16ce7180c474460f997bd0efff02754973fd493cda33c7b364b89997409dbac35ca54f01b74498360f00fbf7092e589de2020641a954a27c92b862303dad302f258c9530c729d2baeccb32dbce5bf1ddc0758529f020b75806fd0b3cdf61670d88027e5028badbe0381b6eb6b68955284be0f85de4865ffcde32a8ce08182fe3cd433e91074bce48f7cb8295e8af1d1d9ccacce4490506e7adc9b29e88aba93f1b207ed28328bfe9f6cf3b6d3547bdb430f48898f78fa6c3e18234c855e0a52bb78c5d0131533e4a471a039c7cab0f266daf91f1834589a624400edc4398e7e828f582c07aa42c25d1b672cfb45eac915f8c4dbafd3205c29100c2992d45affacb9f19020535efdc88776c1c3aca1260df676ddfe99782c48ec29d38eea6b12f06d536702d6164196e22b4e348c9afe0c8f5572b4651c01cc00314a2291cc27e1763a762c1e3fbb8e98f1b99abdfdfa786508d7cc44df1d5d02f934bf3014a36090e464273f4d8c1b7877eb0b290223dac7d9cf81ec17f791d11aa4a1b68f9693796e7b0a8e03eceb1e616b44d174568825ffaca4cbeb4c4aab4e0e9c6723385e3cdeca273c175f927edc0111bc70e928bb1082a6b835e3ce1e3ed65c0dff86922d451806fb038d5521c9ba7fa99d60dc5f69d561b00799c6daa0ea4e43a3d33a456b2b19ed25f31ceebf094342dc5da14ef72395949b799483d059a7e65a246a8f45ad1c48b3b8a76fb17dc5a80bfe5d7900a9870397d653644d404cde9ab38c8b4aea0d3e6682eb89cfb1f50e1e5a8140543232c48d76b947416ee9950c0f5dc11b200e5bf99a7434f8174b56d22164d8b76bf640310d52d589a046d53b117d2bf3f9112b7a7fce911175c9801442086a89b0973b4d957ae8e947879c51835ef64fa027cbfabaddc03997a2b92fd79f0973f694696f56543e83a8f19119473ebff740014caa87269b99c0adf301358c2f3776c760068bf7b596de58dc752d758e7ed3224cbc8d6edda7bc8c4547db51d9c78ce44a178a6e03cae750dfbe643acd08972f5ae0952cd44c62797787661c879af3a7330a53b23bcdd93aa7e3d61039d95622a882f24f6ecd1fc5400d4c8abf867ec3d5a2de8388fa8d6d1026227c6716a002cbf4a89570842bd00a4c0fda5a055473d973f1115d49e77fef7a69fee3131803e935eaeea4bf493566a48ab82e4bf8c3552cc58376974341021ce82f09f4081ddbcbab8b9c65979a5643d145e8fd093cd3769a353c8c9f58830719ec0683c422b28a02f74ca326db6911af0e9bc67cb42007a65ad3e8942d823ba0c31ae2c322f45f1f54aca1193f948c49885fee5960695994cb73b2f572a8ac2be49192b5";
    bytes32 appExeCommit = bytes32(0x0063802e02e9f8db01adecac53ea5c1db95bdbacf7800b9e29e27527cfd2613b);
    bytes32 guestPvsHash = bytes32(uint256(0));

    uint256 private constant FULL_PROOF_WORDS = (12 + 2 + 32 + 43);

    uint256 private constant FULL_PROOF_LENGTH = (12 + 2 + 32 + 43) * 32;

    function setUp() public {
        partialProof = abi.encodePacked(kzgAccumulators, suffix);
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
