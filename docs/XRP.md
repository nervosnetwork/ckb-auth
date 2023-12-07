# XRP lock


## Quick Start

### Start rippled service
To start the `rippled` service, simply execute `./tools/rippled/start_rippled.sh`.

```bash
source ./tools/rippled/start_rippled.sh
```

If successful, it will output the name of the created Docker container. You can use the `source` command to export the `RIPPLED_CMD` alias for subsequent operations. Alternatively, you can directly use `docker exec -it <docker container ID> rippled -a`.

### Generate key

Generate a set of keys using `rippled wallet_propose`.

```bash
RIPPLED_CMD wallet_propose
```

Output:
```json
{
   "result" : {
      "account_id" : "r9uxsGD37LBsCALPjm8FtLQqptmoB6Qvqm",
      "key_type" : "secp256k1",
      "master_key" : "MOTH ONLY CANE DIED WAVE LUKE HUNT BONN GATE LOVE MUSH SEEK",
      "master_seed" : "snwMt2dJVZdBvmyLDK3tSCypPdZna",
      "master_seed_hex" : "B10BACD9268AEB9C67877F398C1999BF",
      "public_key" : "aBPT8cq89dj2eLcb69ut8UKMeoDeH31YyY5w1iPnKDaBgbBjJckD",
      "public_key_hex" : "02C631D5651CBBAC715BED6C92B2A23556A60612B8A0118148EDC0A8FC189DBC31",
      "status" : "success"
   }
}
```

If successful, the `status` will display `success` (you can use the same method to check the success of subsequent `rippled` commands). In the subsequent operations, you will need the `master_seed` for generating private keys for signing, and the `account_id` will be involved in verification.


### Sign
Before signing with `rippled`, you need to convert the CKB sign message to an address supported by Ripple:

```bash
CKB_SIGN_MESSAGE=0011223344556677889900112233445566778899001122334455667788990011
./tools/ckb-auth-cli/target/debug/ckb-auth-cli ripple parse --hex_to_address $CKB_SIGN_MESSAGE
```

Output:
```
rEnBxmzps1MkjuWpr4hoKxmJg5QM7CsGff
```

Then, use `rippled`'s sign function for signing:
```bash
RIPPLED_CMD sign <master_seed> '{"TransactionType": "Payment", "Account": "<CKB_MESSAGE_HASH>", "Destination": "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX", "Amount": { "currency": "USD", "value": "1", "issuer" : "<CKB_MESSAGE_HASH>" }, "Sequence": 360, "Fee": "10000"}' offline
```

* The `CKB_MESSAGE_HASH` should be the address processed by `ckb-auth-cli ripple parse`.

The result of signing with the above key and message will be in JSON format:
```json
{
   "result" : {
      "deprecated" : "This command has been deprecated and will be removed in a future version of the server. Please migrate to a standalone signing tool.",
      "status" : "success",
      "tx_blob" : "1200002280000000240000016861D4838D7EA4C6800000000000000000000000000055534400000000009A5C933C8ECA0B2A0039ADC50335C71D31311639684000000000002710732102C631D5651CBBAC715BED6C92B2A23556A60612B8A0118148EDC0A8FC189DBC3174473045022100EFE2AE5990633E0D67D4C3AF4AB3BA4A1FA89181A62D0ABC2351CDAFA9E49AEA022000C0D0AA7E7F5421438BD3CB34D8507A6A8A9CCB9418A2837D1691E97D29165781149A5C933C8ECA0B2A0039ADC50335C71D3131163983143E9D4A2B8AA0780F682D136F7A56D6724EF53754",
      "tx_json" : {
         "Account" : "rEnBxmzps1MkjuWpr4hoKxmJg5QM7CsGff",
         "Amount" : {
            "currency" : "USD",
            "issuer" : "rEnBxmzps1MkjuWpr4hoKxmJg5QM7CsGff",
            "value" : "1"
         },
         "Destination" : "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX",
         "Fee" : "10000",
         "Flags" : 2147483648,
         "Sequence" : 360,
         "SigningPubKey" : "02C631D5651CBBAC715BED6C92B2A23556A60612B8A0118148EDC0A8FC189DBC31",
         "TransactionType" : "Payment",
         "TxnSignature" : "3045022100EFE2AE5990633E0D67D4C3AF4AB3BA4A1FA89181A62D0ABC2351CDAFA9E49AEA022000C0D0AA7E7F5421438BD3CB34D8507A6A8A9CCB9418A2837D1691E97D291657",
         "hash" : "EDA06467734EA0A957F1B2B69ADD4EBCFCF3F1EC3A2737ECE15B6D8427410BEE"
      }
   }
}
```

### Verify
To verify the signature, you will need the `account_id` (generated using `wallet_propose`).
In the output above, we need to use the `tx_blob` as the entire signature input to `auth` for verification.
```bash
./tools/ckb-auth-cli/target/debug/ckb-auth-cli ripple verify -p <RIPPLE ADDRESS ID> -s <tx_blob> -m $CKB_SIGN_MESSAGE
```


## Details of Ripple

### [rippled](https://github.com/XRPLF/rippled)

rippled is the official service program provided by XPR. The official distribution does not include a standalone binary file, but it can be installed using the following methods:
* Docker image: There are multiple Docker images available for rippled. Here, I have chosen one that is convenient to use.
* [Precompiled installation](https://xrpl.org/install-rippled.html)
* [Local compilation](https://github.com/XRPLF/rippled/blob/develop/BUILD.md)

The rippled service requires a configuration file, which can be found in [tools/rippled/config](../tools/rippled/config).
Additionally, it utilizes the [stand-alone mode](https://xrpl.org/commandline-usage.html#stand-alone-mode-options) in conjunction with the configuration file.

### Generating Keys
Using `wallet_propose` will generate a new set of keys each time. Ripple supports secp256k1 and ed25519 key types, but only the default secp256k1 is supported here.
Both the public and private keys can be generated using a `seed`. The seed is only 16 bytes long, but it needs to be hashed once in XPR to obtain the true 32-byte seed. The private and public keys can be derived from the true seed.
The `account_id` is generated from the public key and requires multiple hashing operations followed by base58 encoding. You can refer to [RippleAuth::hex_to_address](../tests/auth_rust/src/lib.rs) for more details. Additionally, `ckb-auth-cli ripple parse --address_to_hex` can be used to parse the `account_id`.

### Sign
The official Ripple documentation does not provide a tool for signing arbitrary data. Therefore, the `sign` command of rippled is used here. The `Account` structure is utilized to store the ckb sign message for signing (to prevent tampering with the transaction). Since the `Account` stores the `account_id`, the ckb sign message needs to be processed beforehand (similar to the process of converting pubkey key to account_id). The `issuer` value is set to the same `account_id` (as rippled verifies this value, it needs to be filled).

After a successful sign operation, a JSON object is returned. The data in the `tx_blob` field can be directly used as the auth witness, while `TxnSignature` contains the actual signature data.
However, it is important to note that the length of the signed data is not fixed because when generating the ckb sign message, the witness length needs to be determined. Therefore, trailing zeros are padded, and the number of zeros is written in the last byte. This logic should be handled by the developer (considering that ckb-auth is a library and should not perform extensive business data handling, [refer to](../tests/auth-c-lock/auth_c_lock.c#L213)).

### Verify
Since the Ripple message has been processed, a `convert_ripple_message` function is implemented to convert the message. Before performing verification, the data from the sign operation needs to be parsed to obtain the ckb sign message (hashed), public key, and signature data. The parsing process follows the information provided on the [official website](https://xrpl.org/serialization.html). As the `type code` of this data is sorted during serialization, only parsing up to `8` is necessary to obtain the required data.
Once the required data is obtained, the ckb sign message needs to be validated first to prevent transaction tampering. After message validation, secp256k1 verification is performed. The verification process differs slightly from the default method in CKB and uses a separate function for verification. Finally, the public key is hashed using the Ripple approach and verified.