# [Bitcoin Lock](../README.md)

Here, use the official wallet [Bitcoin Core](https://bitcoincore.org) (Version 25.0). ([Source code](https://github.com/bitcoin/bitcoin))

**Please note:** that we will be using `legacy addresses`. This choice is due to the fact that the current version (25.0) of Bitcoin Core defaults to `segwit addresses`, which are not supported by `signmessage` and `verifymessage`. For further details on this matter, For details, please see this [Github Issues](https://github.com/bitcoin/bitcoin/issues/10542).


## Quick Start

### Install Bitcoin Core

Download the binary archive from [here](https://bitcoincore.org/bin/bitcoin-core-25.0/), choose the file corresponding to platform, and unarchive it. (Note: If MacOS, we recommend downloading the `.tar.gz` file, `.dmg` file only provides GUI tools.)

After installation is complete, start the background program: `bitcoind`. The signature and verify we need to do later need to rely on this service to process.
```shell
bitcoind -chain=regtest -daemonwait
```
(For the convenience of testing, start Bitcoin Core in Regtest mode and run it in the background, waiting until it is fully started.)

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

Regarding Bitcoin's support for multiple address formats, you can [refer to](https://en.bitcoin.it/wiki/List_of_address_prefixes) the following link to understand how to distinguish between these addresses

### Generate Signature

To begin, generate a 32-byte data segment as the message:
```shell
message=0011223344556677889900112233445500112233445566778899001122334455
```

Next, use the `bitcoin-cli` for signing:
```shell
bitcoin-cli -rpcwallet=Test signmessage 1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih $message
```
If the wallet requires a password, unlock it first using `walletpassphrase`.

Once the signing is successful, it will output the signature result, which is encoded in base64:
```
H0v6+IkWf0WL6MDCz0K6XeTiNSChoiDIEzgJQMadJi78NoHE3roRx8QX1mnK57on5w5doBXOFBn1kwpOpPgVwPM=
```

### Verify

Pass the address, signature and message to ckb-auth-cli to verify:
```shell
ckb-auth-cli bitcoin verify -a 1CSbWFszmuQiPCRPsaDhhb2NuFTEZFQqih -s H0v6+IkWf0WL6MDCz0K6XeTiNSChoiDIEzgJQMadJi78NoHE3roRx8QX1mnK57on5w5doBXOFBn1kwpOpPgVwPM= -m 0011223344556677889900112233445500112233445566778899001122334455
```


## Details of Bitcoin

### Cofing Bitcoin Core

For GUI testing or disabling network activity, refer to the configuration instructions below.
[Help](https://jlopp.github.io/bitcoin-core-config-generator/)

The configuration file for Bitcoin Core (`bitcoin.conf`) is located in different directories based on the platform:
- Linux: `~/.bitcoin/bitcoin.conf`
- Windows: `%UserProfile%\AppData\Roaming\Bitcoin\bitcoin.conf`
- MacOS: `$HOME/Library/Application Support/Bitcoin/bitcoin.conf`

First time using, need to manually create these directories and files. 

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
- After creation, the 'Address' will be visible in the lower part of a separate window. The addresses held by the current wallet can be checked in the table below.

If the address starts with `bc` or `tb`, make sure to verify the correctness of the above configurations.

The returned address is encoded in base58, with a decoded length greater than 21 bytes. Among these, the first 20 bytes represent the public key hash value, which will be used for verification later.

### Signature

To sign a message in the GUI:

- `File` -> `Sign Message`, and enter the corresponding values for signing.

In ckb-auth, the message uses a fixed 32 bytes, but it internally converts the message to hexadecimal with a length of 64 bytes. Therefore, ensure that the message remains 32 bytes when generating it. If the data to be signed is too long, consider hashing it. For signing in Bitcoin, just use string directly.

Please note: When signing in Bitcoin, case sensitivity should be observed. Ckb-auth uses lowercase letters exclusively.

The returned signature data is encoded in base64, with a fixed binary length of 65 bytes. In this case, no special processing is required and passed directly to ckb-auth

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

## Unisat Wallet
Bitcoin Wallet [Unisat](https://hk.unisat.io/), an open-source browser extension, supports Chrome, Firefox, Edge, and Brave browsers.

As Unisat's user interface does not independently support the signing of messages, [API](https://docs.unisat.io/dev/unisat-developer-service/unisat-wallet#signmessage) is utilized here for signing.

API Principle: After installation, the plugin injects a class named "unisat" into the page upon completion of initialization. All API communication with the wallet is conducted through this class.

### Installation and Account Creation
* [Chrome web store](https://chromewebstore.google.com/detail/unisat-wallet/ppbibelpcjmhbdihakflkdcoccbgbkpo)
* For other browsers, compilation is required using the [source code](https://github.com/unisat-wallet/extension).

It is recommended to use Unisat under Chrome, and all subsequent operations are also performed within Chrome.


### Obtaining the Address

Initially, after installation, follow the prompts to create a new account. Note that during creation, you can choose the `Address Type`, and after creation, it can be modified: Settings (bottom right gear icon) -> Address Type.

ckb-auth supports Native Segwit, Nested Segwit, and Legacy.
Taproot is not supported. According to official information, Taproot uses Schnorr, but in Unisat, if the Address type is set to Taproot, the signature still uses secp256k1.

To obtain the complete address, use one of the following methods:
1. In the UI, click "Receive" to enter the page, then click on the address below the QR code to copy.

2. On any page, bring up DevTools (shortcut: F12). Enter the following code in the Console to retrieve the current address.
```js
await unisat.getAccounts()
```

Output
```
['bc1qngwkvfhwnp79dzfkdw8ylfaptcv9gzvk8ggvd4']
```

### Generating a Signature
In the browser's DevTools, input the code, and in the subsequent confirmation window, click the "Sign" button to generate the signature.

```js
await unisat.signMessage("0011223344556677889900112233445500112233445566778899001122334455");
```

Output:
```
'GzYPwz0f6SVquNRya5qqwXAYjRHo8c2XVO2IDk0ILbXBCwCYwWupDli3ubi1gkfD6olVIG12BBKqXSkNWBA4ykM='
```

Note that signatures generated for the same account but with different Address Types are not interchangeable. Therefore, if you wish to test other types, switch the address before signing.


### Verify
Use ckb-auth-cli to verify the signed data:
```shell
./ckb-auth-cli unisat verify -a bc1qngwkvfhwnp79dzfkdw8ylfaptcv9gzvk8ggvd4 \
    -s GzYPwz0f6SVquNRya5qqwXAYjRHo8c2XVO2IDk0ILbXBCwCYwWupDli3ubi1gkfD6olVIG12BBKqXSkNWBA4ykM= \
    -m 0011223344556677889900112233445500112233445566778899001122334455
```

Due to an issue with Unisat's signature, there is a misalignment in the first byte, specifically regarding the signature type flag. To address this, a separate command has been created in the code to handle the correction before usage.
