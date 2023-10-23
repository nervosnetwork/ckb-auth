# [EOS](../README.md)

In this guide, we will explore how to test `ckb-auth` using the official EOS tool: `cleos`.

## Quick Start

### Installing EOS

To get started, we recommend using precompiled binary files. You can find the official installation tutorial [here](https://developers.eos.io/manuals/eos/latest/install/install-prebuilt-binaries). Please keep in mind the following:

- Support is available only for x86 CPUs.
- It's advisable to use the officially recommended systems.
  - In this document, we will focus on using the `cleos` binary.

### Creating Key Pairs

One of the advantages of `cleos` is that it can directly generate a key pair for signing. Here's how you can do it:

```bash
cleos create key --to-console
```

This command will produce output like this:
```text
Private key: 5K97VWAvvY7BGqojUwTkZ279EDfCXzae9DoArmw1DCcDHXwqpgp
Public key: EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU
```

### Signing Transactions

When using `cleos` for signing, you'll need three parameters: a private key, a chain ID, and the transaction data. Here's an example of how to sign a transaction:

```bash
cleos sign -k 5K97VWAvvY7BGqojUwTkZ279EDfCXzae9DoArmw1DCcDHXwqpgp \
  -c 00112233445566778899aabbccddeeff00000000000000000000000000000000 \
  "{ \"context_free_data\": [\"\00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"] }"
```

Output:
```text
{
  "expiration": "1970-01-01T00:00:00",
  "ref_block_num": 0,
  "ref_block_prefix": 0,
  "max_net_usage_words": 0,
  "max_cpu_usage_ms": 0,
  "delay_sec": 0,
  "context_free_actions": [],
  "actions": [],
  "transaction_extensions": [],
  "signatures": [
    "SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns"
  ],
  "context_free_data": [
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  ]
}
```

In the given command, `-c` (Chain ID) is a 32-byte binary data that can be acquired from `nodeos`, the core service daemon running on every EOSIO node. Alternatively, it can be entered manually. When entering it manually, if it's too long, only the beginning is used; if it's too short, it will be padded with 0s. (Please note that while cleos may perform some corrections to the chain ID, `ckb-auth-cli` does not.)

A transaction is presented in JSON format and contains all the essential information for the transaction. `cleos` allows the use of `{}` to represent an empty JSON as a parameter. In this context, the `context_free_data` field is used to store the CKB sign message, enabling its inclusion in the signature. It's important to note that `cleos` only supports the use of double quotation marks (") when parsing JSON; single quotation marks (') should not be used.

After successful execution, you will receive a JSON data structure with the signature stored in the "signatures" field.

### Verifying Signatures

You can verify the generated signature using the `cleos validate signatures` command. Here's how you can do it:

```bash
cleos validate signatures \
  -c 00112233445566778899aabbccddeeff00000000000000000000000000000000 \
  "{ \"signatures\": \
    [ \"SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns\" ], \
  \"context_free_data\": \
    [ \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\" ] }"
```

Output:
```text
[
  "EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU"
]
```

This command will output the public key of the signature, which you can manually compare to the one generated earlier.

To complete the verification process, you can also use `ckb-auth-cli`:

```shell
ckb-auth-cli eos verify \
  --pubkey EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU \
  --signature SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns \
  --chain_id 00112233445566778899aabbccddeeff00000000000000000000000000000000 \
  --message 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

If successful, it will return "Success."

## EOS Transaction Details

### Public Key

In EOS transactions, public keys are used directly instead of an address. There's no need for conversion. An EOS public key is a text string, such as `EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU`. It consists of three parts:

- The prefix for the public key is typically "EOS," although it's possible for this prefix to be different, such as "PUB_K1." For more details on this, please refer to the code [here](https://github.com/EOSIO/fc/blob/863dc8d371fd4da25f89cb08b13737f009a9cec7/src/crypto/public_key.cpp#L77). However, in ckb-auth-cli, only "EOS" is supported as the prefix.

- The text following the prefix can be decoded using the default Base58 decoding method. After decoding, it results in a 37-byte binary data. The first 33 bytes of this data represent the actual public key, and the last 4 bytes are used for checksum purposes to verify the integrity of the public key.

- During the verification process, the public key is hashed using `Ripemd160`, and the first 4 bytes of the resulting data are compared to validate its authenticity.

Because EOS doesn't have addresses, and CKB-auth's `pubkeyhash` can only store 20 bytes, a similar signing method to CKB is applied to the public key. It's hashed using Blake2b-256, and the first 20 bytes of the resulting hash serve as the "public key hash" for CKB-auth.

### Signing and Verification

The provided information explains that `cleos` offers a "sign" subcommand for signing transactions. This signing process requires a private key, the chain ID, and the transaction as its inputs. You can find more details in the [official documentation](https://developers.eos.io/welcome/v2.1/protocol-guides/transactions_protocol).

The chain ID identifies the specific EOSIO blockchain and consists of a hash of its genesis state, which depends on the blockchain’s initial configuration parameters. In `cleos`, if you do not specify the chain ID, it will be obtained from `nodeos`. `nodeos` is the core service daemon that operates on every EOSIO node and plays a central role in managing the blockchain. This automatic retrieval of the chain ID from `nodeos` simplifies the process of signing transactions by ensuring the correct chain ID is used for the specific blockchain you are interacting with.

If the `chain-id` is not detected in `cleos`, it will be obtained through `nodeos`. (`nodeos` is the core service daemon that runs on every EOSIO node; you can refer to the [documentation](https://developers.eos.io/manuals/eos/latest/nodeos/index) for more information).

The provided information also explains that in the transaction, the signature is based on the data in the `context_free_data` field of the JSON. This field is converted to hexadecimal in `cleos`, and the CKB sign message is placed in this field. It's important to note that, in practice, a fixed value can be used here, such as filling it with `0` or using the mainnet's ID. For more technical details, you can refer to [this source](https://github.com/EOSIO/eos/blob/master/libraries/chain/transaction.cpp#L47).

After the signing process is completed, a JSON response is returned, from which the signature data can be extracted:

```
SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns
```

This string is similar to a public key, with a prefix indicating its purpose, and "K1" signifying that it's using a K1 curve. The following data is still encoded in Base58. When decoded, the first 65 bytes represent the actual signature data, followed by a 4-character checksum.