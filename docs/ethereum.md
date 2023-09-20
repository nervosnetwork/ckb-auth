# [Ethereum Lock](../README.md)

Here, we are conducting comparative testing using the official Ethereum tool [go-ethereum](https://geth.ethereum.org/) (Version 1.12.2).

## Install
You can install it in the following ways:

* Package Managers, supported on: Mac (brew), Ubuntu, FreeBSD, Arch Linux. For specific instructions, please refer to the [official documentation](https://geth.ethereum.org/docs/getting-started/installing-geth).
* [Download the standalone bundle](https://geth.ethereum.org/downloads)
* Building from [source code](https://github.com/ethereum/go-ethereum)

Within the `geth` package, there are multiple executable files. Here, we will focus on using `geth` and `ethkey`.

* `geth` for creating accounts and generating addresses.
* `ethkey` for signature and verification.

Please note that if you are using the standalone bundle or building from source code, it's advisable to add the installation directory to your environment variables for ease of use.

### Build from source code
Keep in mind that compiling `geth` requires a [golang environment](https://go.dev/doc/install).

```
git clone https://github.com/ethereum/go-ethereum.git
cd go-ethereum
make all
```


As `ethkey` is required, we compile all components for convenience. The compiled results can be found in the `build/bin` directory. It's recommended to add this directory to your 'PATH' environment variable for ease of use.

## Address
First, you need to create a test account (you will need to set a password):
```shell
geth account new
```

Once created, look for this line in the output:
```
Public address of the key:   <BIN>
Path of the secret key file: <FILE_PATH>
```

Here, the account's address and private key file are displayed. If you didn't take note of it at the time, you can use `geth account list` to query it.

In Ethereum, the `Address` is a 20-byte fixed-length array. When used in programs (geth and ckb-auth-cli), it will handle the leading `0x`.

## Signature

Ethereum's message is calculated using sha3: `Ethereum Signed Message:\n` + 'message' hash. While ckb-auth's message is a fixed length of 32 bytes, so here, `ethkey` supports the input of messages in both textual form and through a file (by using the `--msgfile` parameter). In this context, Ethereum's message is directly utilized as a data parameter hash, necessitating the use of the `--msgfile` to input a file.

You can use the command provided by `ckb-auth-cli ethereum generate` to convert the message to file:
```shell
message=0011223344556677889900112233445500112233445566778899001122334455
message_file=
ckb-auth-cli ethereum generate -m $message --msgfile $message_file
```
(You need to set the path of `message_file` here)

After generating the message file, you can use `ethkey` to sign:
```shell
my_key_file=
ethkey signmessage --msgfile $message_file $my_key_file
```
output:
```
Signature: 5a62aa66a32a41fb44a58e7284ca964952da485dc0fcec24dadb7402d65274d8733f9a2c34274c573d09743d04f25fdfb00ffee8d821a1422c7d3f4e97ce97e100
```

After signing, you can verify it using geth to prevent any basic errors:
```shell
ethkey verifymessage --msgfile $message_file 0x027a5b3c90216149a42ceaa0431ac7179d0e663b 5a62aa66a32a41fb44a58e7284ca964952da485dc0fcec24dadb7402d65274d8733f9a2c34274c573d09743d04f25fdfb00ffee8d821a1422c7d3f4e97ce97e100
```

* Here need to pay attention to the order of command parameters.

## Verify

This can now be verified in ckb-auth:

```shell
ckb-auth-cli ethereum verify -a 027a5b3c90216149a42ceaa0431ac7179d0e663b -s 5a62aa66a32a41fb44a58e7284ca964952da485dc0fcec24dadb7402d65274d8733f9a2c34274c573d09743d04f25fdfb00ffee8d821a1422c7d3f4e97ce97e100 -m 0011223344556677889900112233445500112233445566778899001122334455
```

