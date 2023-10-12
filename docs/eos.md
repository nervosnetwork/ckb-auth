# [EOS](../README.md)
Here use the EOS official tool `cleos` control testing tool.

In this context, the EOS official tool `cleos` is used alongside the ckb-auth for comparison.

## Quick Start

### Install eos
Recommend using precompiled binary files. You can find the official tutorial [here](https://developers.eos.io/manuals/eos/latest/install/install-prebuilt-binaries).

Please note:
- Support is only available for x86 CPUs.
- It's advisable to use the officially recommended systems.
- In this document, only the `cleos`` binary will be used.


### Create Key Pairs 

`cleos` can directly generate a key pair for signing without the need to create a account, unlike other tools. (It also provides account management, but generating such a key pair within the account.)

```bash
cleos create key --to-console
```

Output:
```text
Private key: 5K97VWAvvY7BGqojUwTkZ279EDfCXzae9DoArmw1DCcDHXwqpgp
Public key: EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU
```

### Sign

When signing with `cleos`, three parameters are used: private key, chain-id and transaction.

* Chain-id is a 32-byte binary data that can be obtained from `Nodeos` (`nodeos` is the core service daemon that runs on every EOSIO node) or entered manually. When entered manually, if it's too long, only the beginning is used, and if it's too short, it will fill with 0.
* Transaction is in JSON format and contains the necessary information for the transaction. cleos allows the use of `{}` (an empty JSON) as a parameter. In this context, the `context_free_data` field is employed to store the CKB sign message, enabling it to participate in the signature. Important to note: `cleos` only supports the use of double quotation marks (") when parsing JSON. Single quotation marks (') should not be used.

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

After successful execution, it will output a JSON data structure in which the `signatures` are stored in the signatures field.

### Verify

Begin by verify the generated signature using `cleos validate signatures`. (Based on the previous data, some unused data has been removed)

```
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
This command will only output the public key of the signature. Here, need to manually compare it to the one generated earlier.

Finally, verify the signature using `ckb-auth-cli`.

```shell
ckb-auth-cli eos verify \
  --pubkey EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU \
  --signature SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns \
  --chain_id 00112233445566778899aabbccddeeff00000000000000000000000000000000 \
  --message 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

If successful, output `Success`

## Details of EOS

### Public key

In EOS transactions, public keys are directly used instead of an address. Therefore, there is no need for conversion here. The public key in EOS is a text string.
e.g. `EOS8Mizk2hTcnU8t3hpYErmNuWmptstbsmr3gGUeQY9swEw2AxeyU`

It consists of three parts:
* Prefix EOS. It's possible for this to be other text, like PUB_K1([For details, please refer to the code](https://github.com/EOSIO/fc/blob/863dc8d371fd4da25f89cb08b13737f009a9cec7/src/crypto/public_key.cpp#L77)). However, in ckb-auth-cli, only EOS is supported as the prefix.
* The text after the prefix can be decoded using the default Base58 decoding. After decoding, Aafter decoding, it is a 37-byte binary data. The first 33 bytes in this data represent the actual public key, and the last 4 bytes are for checksum (used to verify the integrity of the public key).
* When verifying, the public key is hashed using `Ripemd160`, and the first 4 bytes of the resulting data are compared for validation.

Because EOS doesn't have address, and CKB-auth's `pubkeyhash` can only store 20 bytes, a similar signing method to CKB will be applied to the public key here. It will be hashed using Blake2b-256, and the first 20 bytes of the resulting hash will serve as the "public key hash" for CKB-auth.


### Sign and Verify

The provided information explains that cleos offers a "sign" subcommand for signing transactions. This signing process requires a private key, the chain ID, and the transaction as its inputs. [Official documentation](https://developers.eos.io/welcome/v2.1/protocol-guides/transactions_protocol).


The chain ID identifies the actual EOSIO blockchain and consists of a hash of its genesis state, which depends on the blockchain’s initial configuration parameters.
In `cleos`, if you do not specify the chain ID, it will be obtained from nodeos. nodeos is the core service daemon that runs on every EOSIO node and plays a central role in managing the blockchain. This automatic retrieval of the chain ID from nodeos simplifies the process of signing transactions by ensuring that the correct chain ID is used for the specific blockchain you are interacting with.
In `cleos`, if not detected `chain-id`, it will be get through `nodeos`. (`nodeos` is the core service daemon that runs on every EOSIO node, [Documentation](https://developers.eos.io/manuals/eos/latest/nodeos/index)).

The information provided explains that in the transaction, the signature is based on the data in the context_free_data field of the JSON. This field is converted to hexadecimal in cleos, and the CKB sign message is placed in this field. It's worth noting that in practice, A fixed value can be used here, such as filling it with `0` or using the mainnet's ID.
[Details of hash](https://github.com/EOSIO/eos/blob/master/libraries/chain/transaction.cpp#L47)

After the signing process is completed, a json will be returned, from which the signature data can be obtained:
```
SIG_K1_KVot8AfLZKPiuwBZKxgco4pKCCfedjtrzyJij6iTmNfkq7Pw4HgizKNBCaXCMs8TNWFUg92g653LEW5GJyS1YFJw7Ciqns
```

This string is similar to a public key, with a prefix indicating its purpose, and K1 signifying that it's using a K1 curve.
The following data is still encoded in Base58. When decoded, the first 65 bytes are the actual signature data, followed by a 4-character checksum.
