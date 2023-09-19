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
./geth account new
```

Once created, look for this line in the output:
```
Public address of the key:   <BIN>
Path of the secret key file: <FILE_PATH>
```

Here, the account's address and private key file are displayed. If you didn't take note of it at the time, you can use `geth account list` to query it.

In Ethereum, the `Address` is a 20-byte fixed-length array. When used in programs (geth and ckb-auth-cli), it will handle the leading `0x`.

## Signature

Ethereum's message is calculated using sha3: `Ethereum Signed Message:\n` + 'message' hash. While ckb-auth's message is a fixed length of 32 bytes, so here, we use a 32-character string for the message.

You can generate a ckb-auth-compatible message using the following command:
```shell
my_key_file=
message=00112233445566778899001122334455
./ethkey signmessage $my_key_file $message
```
output:
```
Signature: 2d87792d122d9187433bffee9723483cca9c8f848d14a9b772f247ff75637103448d825ff0366a1b6572f48b03ef28705feedeb009e9d95c190922435ae271f401
```

After signing, you can verify it using geth to prevent any basic errors:
```shell
./ethkey verifymessage 0x027a5b3c90216149a42ceaa0431ac7179d0e663b 2d87792d122d9187433bffee9723483cca9c8f848d14a9b772f247ff75637103448d825ff0366a1b6572f48b03ef28705feedeb009e9d95c190922435ae271f401 $message
```

## Verify

As mentioned earlier, ckb-auth uses a 32-byte message, while geth uses text. You can convert the message used by geth into ckb-auth's format using ckb-auth-cli.

Since ckb-auth-cli has already processed the message, you can directly use the 32-character message used when signing with geth, or you can use the 64-character message generated using `ckb-auth-cli ethereum parse`. So, you can directly use geth's signature for verification:

```shell
ckb-auth-cli ethereum parse -m 00112233445566778899001122334455
```

output
```
3030313132323333343435353636373738383939303031313232333334343535
```

Here, we use ckb-auth to verify the signature from geth:
```shell
ckb-auth-cli ethereum verify -a 027a5b3c90216149a42ceaa0431ac7179d0e663b -s 2d87792d122d9187433bffee9723483cca9c8f848d14a9b772f247ff75637103448d825ff0366a1b6572f48b03ef28705feedeb009e9d95c190922435ae271f401 -m 3030313132323333343435353636373738383939303031313232333334343535
```
