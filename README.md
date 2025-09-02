# OpenVM Solidity SDK

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/openvm-org/openvm-solidity-sdk)

This repository contains OpenVM verifier contracts generated from official release commits of the [openvm](https://github.com/openvm-org/openvm) repository using the default VM configuration via the cargo-openvm CLI tool. If you're using an advanced or custom VM configuration, you may need to generate and maintain your own verifier contracts separately.

The contracts are built on every _minor_ release as OpenVM guarantees verifier backward compatibility across patch releases.

## Installation

To install `openvm-solidity-sdk` as a dependency in your forge project, run the following:

```bash
forge install openvm-org/openvm-solidity-sdk
```

## Usage

If you are using a deployed instance of the verifier contract, then you can import the interfaces in your contract directly.

```solidity
import { IOpenVmHalo2Verifier } from "openvm-solidity-sdk/v1.4/interfaces/IOpenVmHalo2Verifier.sol";

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
forge create src/v1.4/OpenVmHalo2Verifier.sol:OpenVmHalo2Verifier --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast
```

If you want to import the verifier contract into your own repository for testing purposes, note that it is locked to Solidity version `0.8.19`. If your project uses a different version, the import may not compile. As a workaround, you can compile the contract separately and use `vm.etch()` to inject the raw bytecode into your tests.

## Audits

Versions v1.2 and later of these contracts are recommended for production use. The code to generate these contracts from release commits of OpenVM was [audited](https://github.com/openvm-org/openvm/blob/main/audits/v1.1.1-cantina-report.pdf) by [Cantina](https://cantina.xyz/) in April 2025.

## Security

See [SECURITY.md](SECURITY.md).
