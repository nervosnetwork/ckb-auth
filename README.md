# ckb-auth
A consolidated library featuring numerous blockchains authentication techniques
on CKB-VM. More details in [auth.md](./docs/auth.md). We also write a [simple
script](./examples/auth-c-demo/auth_demo.c) to demonstrate how to use this
library.

## Motivation
The [CKB-VM](https://github.com/nervosnetwork/ckb-vm) in CKB has provided a
multitude of advanced smart contract functionalities that are not typically
found within other blockchain networks. CKB presents a seamless solution for
implementing blockchain interoperability. Through the utilization of ckb-auth, a
sophisticated smart contract library, users can effortlessly access CKB assets
from alternate blockchain wallets, such as Ethereum or Bitcoin, without the use
of a CKB wallet. 

To illustrate, considering a scenario where Alice only possesses an Ethereum
wallet, Bob can transmit assets, including CKB or NFT, to Alice. With the
application of ckb-auth, Alice can effectively utilize and transfer these assets
using her Ethereum wallet without requiring the creation of a CKB wallet
throughout the process.

## Integration
The following blockchains are supported:

* [Bitcoin](./docs/bitcoin.md)
* [Ethereum](./docs/ethereum.md)
* [EOS](./docs/eos.md)
* [Tron](./docs/tron.md)
* Dogecoin
* CKB
* [Litecoin](./docs/litecoin.md)
* [Cardano](./docs/cardano.md)
* [Monero](./docs/monero.md)
* [Solana](./docs/solana.md)
* [Ripple](./docs/XRP.md)

## Build

``` bash
git submodule update --init
make all-via-docker
```
For more details, please check out [CI script](./.github/workflows/rust.yml).

## Test

All test case commands are located in `tests/Makefile`.

### Installing Dependencies

```shell
make install_all
```

### Running All Tests
```bash
cd tests && make all_tests
```

## Test with Spawn (activated after hardfork 2023)
Before running test cases with spawn support, please install ckb-debugger for next hardfork:
```bash
cargo install --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger
```
Then run:

```bash
cd tests/auth_spawn_rust && make all
```

## Directory Structure

```
├── build
├── c
├── ckb-auth-rs
├── ckb-auth-types
├── deps
├── docs
├── examples
│   ├── auth-c-demo
│   └── auth-rust-demo
├── tests
│   ├── Makefile
│   ├── auth-c-tests
│   └── auth-spawn-tests
├─ tools
│   ├── ckb-auth-cli
│   ├── rippled
│   └── tron
└─ Makefile
```

| Directory         | Description                               |
| ----------------- | ----------------------------------------- |
| build             | Build output                              |
| c                 | ckb-auth code, written in C language      |
| ckb-auth-rs       | Rust interface of ckb-auth                |
| ckb-auth-types    | Public code referenced by contracts and test cases |
| deps              | Dependencies of ckb-auth using C language |
| docs              | Detailed introduction to each chain in ckb-auth |
| examples          | All examples                              |
| tests             | All test cases                            |
| tools             | ckb-auth-cli and end-to-end testing tools |

