# [Bitcoin Lock](../README.md)

Here, we will be conducting comparative testing using [Bitcoin Core](https://bitcoincore.org) (Version 25.0), an official wallet. 
For a more in-depth look at the specific implementations of Bitcoin, you can refer to the [source code](https://github.com/bitcoin/bitcoin).

**Please note:** that we will be using `legacy addresses`. This choice is due to the fact that the current version (25.0) of Bitcoin Core defaults to `segwit addresses`, which are not supported by `signmessage` and `verifymessage`. For further details on this matter, you can check the [Github Issues](https://github.com/bitcoin/bitcoin/issues/10542).


## Quick Start

### Install Bitcoin Core

Download the binary archive from [here](https://bitcoincore.org/bin/bitcoin-core-25.0/), choose the file corresponding to your platform, and unarchive it. (Note: If you are using MacOS, we recommend downloading the `.tar.gz` file, `.dmg` file only provides GUI tools.)

Once you have completed these steps, you can start the background program: `bitcoind`. The signature and verify we need to do later need to rely on this service to process.
```shell
bitcoind
```

Normally, we will only be using `signature` and `verify` here, without involving on-chain data. Therefore, you can consider disabling network transmission in the configuration file.
Instructions on how to configure it will be provided in the following section.


### Create Wallet and Address

To create a test wallet and receiving address, use the following commands:
```shell
bitcoin-cli createwallet "Test"
bitcoin-cli getnewaddress label1 legacy
```
**Note:** Ensure that the address_type is specified as `legacy` here, as failure may occur in subsequent signature processes otherwise.

Output address:
```
1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih
```

### Generate Signature

First, you need to generate a 32-byte data segment as message:
```shell
message=0011223344556677889900112233445500112233445566778899001122334455
```

Next, use the `bitcoin-cli` for signing:
```shell
bitcoin-cli -rpcwallet=Test signmessage 1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih $message
```
If the wallet has set a password before, you need to use `walletpassphrase` to unlock it first.

Once the signing is successful, it will output the signature result, which is encoded in base64:
```
H0v6+IkWf0WL6MDCz0K6XeTiNSChoiDIEzgJQMadJi78NoHE3roRx8QX1mnK57on5w5doBXOFBn1kwpOpPgVwPM=
```

### Verify

Here you can directly pass the address, signature and message to ckb-auth-cli to verify:
```shell
ckb-auth-cli bitcoin verify -a 1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih -s H0v6+IkWf0WL6MDCz0K6XeTiNSChoiDIEzgJQMadJi78NoHE3roRx8QX1mnK57on5w5doBXOFBn1kwpOpPgVwPM= -m 0011223344556677889900112233445500112233445566778899001122334455
```


## Details of Bitcoin

### Cofing Bitcoin Core

If you wish to perform testing using a GUI or disable network activity, please refer to the configuration instructions below.
[Help](https://jlopp.github.io/bitcoin-core-config-generator/)

The configuration file for Bitcoin Core (`bitcoin.conf`) is located in different directories based on the platform:
- Linux: `~/.bitcoin/bitcoin.conf`
- Windows: `%UserProfile%\AppData\Roaming\Bitcoin\bitcoin.conf`
- MacOS: `$HOME/Library/Application Support/Bitcoin/bitcoin.conf`

If you are using it for the first time, you will need to manually create these directories and files. If you want to specify a custom directory, you can also check the `bitcoind` or `bitcoin-qt` help.

Disabling network activity is mainly done to reduce disk usage:

```text
networkactive=0
```

Configuring the default address type is necessary because Bitcoin's sign message does not support `segwit addresses`, and the GUI does not provide an option to choose during address creation. Therefore, it needs to be configured here:

```
addresstype=legacy
```

Note: The command line requires starting `bitcoind` as a background process, while the GUI (bitcoin-qt) also starts a background service. Running both simultaneously can lead to conflicts (listening port), but they share the same default configuration file.

### Create Address

As mentioned earlier, creating addresses via the command line won't be detailed here.

To create addresses in the GUI:

- Create a wallet: `File` -> `Create Wallet`.
- Generate a receiving address: In the `Receive` tab, click the "Create new receiving address" button.
- After creation, you will see the `Address` in the lower part of a separate window. You can check the addresses held by the current wallet in the table below.

If the address starts with `bc` or `tb`, make sure to verify the correctness of the above configurations.

The returned address is encoded in base58, with a decoded length greater than 21 bytes. Among these, the first 20 bytes represent the public key hash value, which will be used for verification later.

### Signature

To sign a message in the GUI:

- `File` -> `Sign Message`, and enter the corresponding values for signing.

In ckb-auth, the message uses a fixed 32 bytes, but it internally converts the message to hexadecimal with a length of 64 bytes. Therefore, ensure that the message remains 32 bytes when generating it. If the data to be signed is too long, consider hashing it. For signing in Bitcoin, you can directly use this string.

Please note: When signing in Bitcoin, case sensitivity should be observed. Ckb-auth uses lowercase letters exclusively.

The returned signature data is encoded in base64, with a fixed binary length of 65 bytes. In this case, no special handling is required. After decoding, you can directly pass it to ckb-auth.

### Verify

Before using `ckb-auth-cli verify`, consider verifying in Bitcoin Core first to prevent discrepancies:

Command line:

```shell
bitcoin-cli verifymessage 1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih H0v6+IkWf0WL6MDCz0K6XeTiNSChoiDIEzgJQMadJi78NoHE3roRx8QX1mnK57on5w5doBXOFBn1kwpOpPgVwPM= 0011223344556677889900112233445500112233445566778899001122334455
```

If verification is successful, it will output `true`.

In the GUI:

- `File` -> `Verify Message`, and enter the corresponding data.

In ckb-auth-cli, base58 decoding is performed on the address, with the first 20 bytes used as the public key hash. The message is decoded to 32 bytes, and the signature is base64 decoded. After passing these data to ckb-auth, the verification process is similar to that in Bitcoin Core, and further details will not be reiterated here.
