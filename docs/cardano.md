# [Cardano Lock](../README.md)

## Quick Start

### Install Tools
#### cardano-cli
cardano-cli is an official tool provided by Cardano, which enables key management as well as transaction construction and signing. It can be installed using the command
```bash
cd tests/cardano_lock && make install_cardano_tools
```
Or by downloading it from the [official](https://github.com/input-output-hk/cardano-node/releases/tag/8.0.0).

#### ckb-auth-cli
ckb-auth-cli is a tool designed to assist in testing ckb-auth. Its source code can be found in the 'tools/ckb-auth-cli' directory and can be compiled directly using:
```bash
cargo build
```

### Generate key
You can generate key files (including private and public keys) using the cardano-cli. The command to do so is as follows:
```bash
mkdir -p tests/cardano_lock/test_data
tests/cardano_lock/bin/cardano-cli node key-gen \
    --cold-verification-key-file tests/cardano_lock/test_data/cold.vkey.json \
    --cold-signing-key-file tests/cardano_lock/test_data/cold.skey.json \
    --operational-certificate-issue-counter-file tests/cardano_lock/test_data/cold.counter.json
```
The private key is stored in the `cold.skey.json` file, while the public key is stored in the `cold.vkey.json` file. These files are in JSON format, and the key is stored in `cborHex`. The hexadecimal data represents the key, with the actual key data following the "5820" prefix and being 32 bytes long.
Afterward, you can obtain the hash of the public key for use with ckb-auth-cli. The public key needs to include all the data from the cborHex field in `cold.vkey.json` (the program will handle this data).
```bash
tools/ckb-auth-cli/target/debug/ckb-auth-cli cardano parse --vkey tests/cardano_lock/test_data/cold.vkey.json
```

### Signature
To demonstrate the verification process, we will be using ckb-auth-cli, which directly calls ckb-auth. Therefore, we can use any 32-byte data as the signature message. Generate the transaction and sign it using the following command:
```bash
message="0011223344556677889900112233445500112233445566778899001122334455"
tests/cardano_lock/bin/cardano-cli transaction build-raw \
    --shelley-era \
    --tx-in $message#0 \
    --tx-out addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v+1 \
    --invalid-hereafter 0 \
    --fee 7 \
    --out-file tests/cardano_lock/test_data/cardano_tx.json
tests/cardano_lock/bin/cardano-cli transaction sign \
    --tx-body-file tests/cardano_lock/test_data/cardano_tx.json \
    --signing-key-file tests/cardano_lock/test_data/cold.skey.json \
    --mainnet \
    --out-file tests/cardano_lock/test_data/cardano_tx.signed.json
```
Once the execution is complete, the signed data will be stored in `cardano_tx.signed.json`, following a format similar to that of a key. Later on, you can directly extract the `cborHex` from it for verification purposes.

### Verify
Here use ckb-auth-cli for verify
```bash
tools/ckb-auth-cli/target/debug/ckb-auth-cli cardano verify -p <Public key hash> -m $message --signature_file tests/cardano_lock/test_data/cardano_tx.signed.json
```

### Signature
Signatures are structured using [CBOR](https://datatracker.ietf.org/doc/html/rfc7049). In order to ensure compatibility with cardano-cli and the security of transactions, some modifications have been made to the original structure here:
The transaction hash of the Input is passed into ```generate_sighash_all``` function in ckb-auth as a hash.

| byte string | length | data |
| ----------- | ------ | ---- |
|          58 |     20 | d8e3a41c95c7ed8fd4213fd5def288605ed76db6ed63b1f19fb932b52479da3f |


## Details of Cardano
The previous section provided a simple verification of Cardano-related signatures. However, the `tests/cardano_lock` directory provides comprehensive tests. By running [`make all`](../tests/cardano_lock/Makefile), you can execute the tests, which will build a complete CKB transaction and use the auth-c-demo contract for verification. The entire process is secure.

### Some considerations regarding cardano-cli
Here, it is mentioned that the files outputted by `cardano-cli` are in JSON format, as shown below:
```json
{
    "type": "StakePoolSigningKey_ed25519",
    "description": "Stake Pool Operator Signing Key",
    "cborHex": "5820d8e3a41c95c7ed8fd4213fd5def288605ed76db6ed63b1f19fb932b52479da3f"
}
```
The data is stored in the `cborHex` field using CBOR encoding. In the above example:
|          58 |     20 | d8e3a41c95c7ed8fd4213fd5def288605ed76db6ed63b1f19fb932b52479da3f |
| ----------- | ------ | ---- |
| byte string | length | data |


### Generating Keys

`cardano-cli` can directly generate keys, and both the public and private keys can be obtained as hexadecimal data.

### Signing

`cardano-cli` can generate transactions and sign them. The data is divided into three parts: transaction details, signature-related data (public key and signature), and metadata. When signing, the transaction's relevant information is hashed (using blake2b 256), and the resulting 32-byte data is used as the signature message for signing. You can obtain the signature message using the following command:
```bash
./tests/cardano_lock/bin/cardano-cli transaction txid --tx-body-file tests/cardano_lock/test_data/cardano_tx.json
```
Alternatively, you can use `cardano_tx.signed.json` since they contain the same transaction information, resulting in the same hash.

Since Cardano's transaction information does not have a suitable location to store the sign-message used to ensure the uniqueness of the CKB transaction, this data is placed in the input tx. You can parse the transaction information using the following command:
```
./tests/cardano_lock/bin/cardano-cli transaction view --tx-body-file tests/cardano_lock/test_data/cardano_tx.signed.json
```
It will produce an output similar to:
```
auxiliary scripts: null
certificates: null
collateral inputs: null
era: Shelley
fee: 7 Lovelace
inputs:
- 0011223344556677889900112233445500112233445566778899001122334455#0
metadata: null
mint: null
outputs:
- address: addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v
  address era: Shelley
  amount: 1 Lovelace
  network: Testnet
  payment credential key hash: 54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9
  reference script: null
  stake reference: null
reference inputs: null
required signers (payment key hashes needed for scripts): null
return collateral: null
total collateral: null
update proposal: null
validity range:
  time to live: 0
withdrawals: null
```
The `inputs` field stores the message for CKB transaction uniqueness.

Finally, you can use the following command to decode the CBOR data and view the corresponding signature result:
```bash
tests/cardano_lock/bin/cardano-cli text-view decode-cbor  --in-file tests/cardano_lock/test_data/cardano_tx.signed.json
```

In `ckb-auth`, we will use the signed data as a complete witness for verification.

### [Verification](../c/auth.c#L331)

Using the successfully signed data and the public key, you can construct a CKB-auth transaction. During verification:
First, the CBOR-formatted witness data needs to be parsed. This will provide the message, public key, and signature.
Next, the message is checked to ensure that it matches the result computed by the contract, thus preventing transaction forgery.
Finally, `ed25519_verify` is used to verify the signature. Additionally, the obtained public key is hashed and compared to the public key hash in the `args` field.
