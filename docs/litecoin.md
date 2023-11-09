# ckb-auth litecoin interoperability
Below uses the address `msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn` whose corresponding private key is
`cSoKeLipWLXgdonv3pxE7XBp37yPVAnFcio3ZfGvsdjSWZa67cFJ`. See below on how to import this private
key into the wallet.

```
export KEY="cSoKeLipWLXgdonv3pxE7XBp37yPVAnFcio3ZfGvsdjSWZa67cFJ" ADDRESS="msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn"
```

Ckb-auth library is able to verify a lot of blockchain signatures including the litecoin.
We can use `litecoin-cli` (or other compatible wallet) to generate valid signatures and validate them on-chain with ckb-auth.

A simple way to use litecoin signature algorithm to lock ckb cells
is to sign the transaction hash (or maybe `sighash_all`, i.e. hashing all fields 
including transaction hash and other witnesses in this input group)
with `litecoin-cli`, and then leverage ckb-auth to check the validity of this signature.
See [the docs](./auth.md) for more details.

# Verify transaction with ckb-auth-cli
Assume that the message (`sighash_all` result) to be signed is

```
8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
```

## Sign the message with litecoin-cli
``
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet signmessage msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn 8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
```
which outputs
```
ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E=
```
## Verify the signature with `verify` subcommand
```
ckb-auth-cli -- litecoin verify -s ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E= --encoding base64 -p 88043d56e0079d30927ebf8bb99358d7ddad7ad8 -m 8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
```
This commands return zero if and only if verification succeeded.

# Signing a transaction with litecoin-cli

## Downloading the litecoin binaries
The commands below download the official `litecoin` binaries (e.g. `litecoind` for litecoin daemon,
`litecoin-cli` for litecoin command line client) into the directory `/usr/local`.

```bash
tarball=litecoin.tar.gz
wget -O "$tarball" https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz
tar xvzf "$tarball"
sudo cp -r litecoin-*/* /usr/local
```

## Starting the litecoin daemon
Litecoin daemon is required in order to for litecoin-cli to work. For example,
to work with Litecoin in a test environment, you need to start a Litecoin testnet node.
You can do this using the `litecoind` command with the `-testnet` option. Here's how:
```bash
litecoind -testnet -daemon
```

## Creating a new account or use the existing litecoin account
To sign a message, you will need to create a litecoin wallet
(for illustration, we use wallet `ckb-auth-test-wallet` below)
and a litecoin account (for illustration, we use account with
private key `cQoJiU5ECnVpRqfV5dWKDE2sLQq6516Tja1Hb1GABUV24n7WkqV4` below) to sign messages.

If you already have a wallet, load the wallet `ckb-auth-test-wallet` with
`litecoin-cli -testnet loadwallet ckb-auth-test-wallet` and skip this step.

To create a wallet named `ckb-auth-test-wallet`, import private key
`cQoJiU5ECnVpRqfV5dWKDE2sLQq6516Tja1Hb1GABUV24n7WkqV4` into this wallet and 
label this account with `ckb-auth-test-privkey`, we can run
```bash
litecoin-cli -testnet createwallet ckb-auth-test-wallet
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet importprivkey cSoKeLipWLXgdonv3pxE7XBp37yPVAnFcio3ZfGvsdjSWZa67cFJ ckb-auth-test-privkey false
```

## Obtaining the litecoin address to sign data
Due to the deprecation of [old address format (p2pkh address)](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses) ([upstream bitcoin switched to Hierarchical Deterministic (HD) Wallet](https://river.com/learn/terms/h/hd-wallet)),
we need to obtain the legacy p2pkh address of the litecoin account to sign messages.

The easiest way to do such thing is to label the account (say with `ckb-auth-test-privkey`) 
and dump all its address, we can run 
```
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet getaddressesbylabel ckb-auth-test-privkey
```
Here's the output when I run that script:
```json

{
  "msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn": {
    "purpose": "receive"
  },
  "Qe2ByfdQjU5AUZTvZ4XCrmQxHQctBXavWL": {
    "purpose": "receive"
  },
  "tltc1q3qzr64hqq7wnpyn7h79mny6c6lw667kcjva8fn": {
    "purpose": "receive"
  },
  "tmweb1qqv6l9zx5vvg3m4mtu4ag37emha0rgh3rkz7t4a6pluqsqfs37krx5q7pl6cyylpjzw9q4js4t64upy4nfreqwy9mgj4zg5xd3dxsml4y7qyq00mz": {
    "purpose": "receive"
  }
}
```

The legacy p2pkh addresses are normally with short length (see [How is a Litecoin address generated?](https://bitcoin.stackexchange.com/questions/65282/how-is-a-litecoin-address-generated) and [address format - litecoin constants and prefixes](https://bitcoin.stackexchange.com/questions/62781/litecoin-constants-and-prefixes) for details).
As a rule of thumb, we can use the addresses started with m or n in litecoin testnet and addresses started with L for litecoin mainnet.
For example, here the short addresses  `msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn`
may be used to sign message, while another short address 
`Qe2ByfdQjU5AUZTvZ4XCrmQxHQctBXavWL` does not work.

If the account is not labelled, you may run `litecoin-cli -testnet listreceivedbyaddress 1 true`
to dump all addresses and find out the desired legacy address from there.

## Obtaining public key hash needed by ckb-auth
To obtain public key hash of address `msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn`, we need to decode it with
base58 and then take the [1, 21) bytes of the resulting binary data (i.e. dropping the first byte, and
take the following 20 bytes of data). You may [decode it online](http://lenschulwitz.com/base58) or run
the command `base58 -d <<< msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn| xxd -s 1 -l 20 -p` 
([keis/base58](https://github.com/keis/base58) and [xxd(1)](https://linux.die.net/man/1/xxd)required).

## Signing a message with litecoin-cli
To sign the message `29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157`, we can run
```bash
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet signmessage 2msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn 8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E=
```
whose output `ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E=` is the base64-encoded form of the signature. The binary form can be fed to ckb-auth for authentication.

