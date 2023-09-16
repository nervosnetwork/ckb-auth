# [Ethereum Lock](../README.md)

Here, we are conducting comparative testing using the official Ethereum tool [go-ethereum](https://geth.ethereum.org/) (Version 1.12.2).

## Install
You can download the binary files following the [official guide](https://geth.ethereum.org/docs/getting-started/installing-geth). Alternatively, you can compile from [source](https://github.com/ethereum/go-ethereum) (requires a golang environment).

Since we are only performing `signature` and `verify`, there is no need to configure geth.
We will be using:
* `geth` for creating accounts and generating addresses.
* `ethkey` for signature and verification.

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
