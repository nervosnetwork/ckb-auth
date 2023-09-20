# Building ckb-auth-cli
There are some required binaries that need to be built in order to run [`ckb-auth-cli`](../tests/auth_rust/src/bin/ckb-auth-cli.rs).
We can run the following shell script to do so.
```bash
cd ./tests/auth_rust/
./run.sh
```

# Using ckb-auth-cli
ckb-auth-cli is a command line utility to facilitate the creation and verification of transaction
with ckb-auth as lock script.

## Get the pub key hash with `parse` sub command.
Given the account we want to sign messages with, we obtain pub key hash like data that will be used later by ckb-auth to
verify the validity of a signature. ckb-auth will verify that the signature is valid and
it is signed by someone with pubkey hashed to this data.

## Get the message to sign with `generate` subcommand.
This step is used to generate the message for the native blockchain clients to sign.
The same message will be used by ckb-auth internally. ckb-auth will check the validity of the
signature in the transaction against this message.

## Sign the message with litecoin-cli
We can now sign the message with native blockchain clients. Depending on the specific blockchains,
each blockchain wallets accept different parameters and output different data. See below for each
blockchains.

## Verify the signature with `verify` subcommand
ckb-auth-cli generate the same transaction and set the signature to the one generated above,
and then it checks the validity of this transaction. This will return zero if and only if verification succeeded.

# integrations
##  litecoin
See [litecoin docs](./litecoin.md).

