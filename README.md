# OpenVM Solidity SDK

This repo houses OpenVM verifier contracts generated on official release commits of the [openvm](https://github.com/openvm-org/openvm) repo with the default VM config using the `cargo-openvm` cli tool. Advanced VM configurations may require their own generations.

## Installation

To install `openvm-solidity-sdk` as a dependency in your forge project, run the following:

```bash
forge install openvm-org/openvm-solidity-sdk
```

## Usage

If you are using a deployed instance of the verifier contract, then you can import the interfaces in your contract directly.

```solidity
import { IOpenVmHalo2Verifier } from "openvm-solidity-sdk/v1.1.1/interfaces/IOpenVmHalo2Verifier.sol";

contract MyContract {
    function myFunction() public view {
        // ... snip ...

        IOpenVmHalo2Verifier(verifierAddress)
            .verify(publicValues, proofData, appExeCommit, appVmCommit);

        // ... snip ...
    }
}
```

If you want to deploy your own instance of the verifier contract, you can use `forge create`:

```bash
forge create src/v1.1.1/OpenVmHalo2Verifier.sol:OpenVmHalo2Verifier --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast
```

If you want to import the verifier contract into your own repository for testing purposes, note that it is locked to Solidity version `0.8.19`. If your project uses a different version, the import may not compile. As a workaround, you can compile the contract separately and use `vm.etch()` to inject the raw bytecode into your tests.

## Audits

You can find the audit reports for these contracts in the [OpenVM repo](https://github.com/openvm-org/openvm/tree/main/audits).
