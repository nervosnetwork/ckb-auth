# [TONCOIN](../README.md)

# Installing toncoin and setup a wallet

First [get a wallet](https://ton.org/en/wallets?locale=en&pagination[limit]=-1)
and set up a wallet account.

# Creating a `ton_proof` with the wallet

TODO: any easier way to create `ton_proof` for arbitrary message?

In order to sign CKB transactions with toncoin, we need to create
[`ton_proof`](https://docs.ton.org/develop/dapps/ton-connect/protocol/requests-responses#address-proof-signature-ton_proof)
with the wallet extension/app, which is an ed25519 signature to
an message related to CKB transaction.

We need to follow the instructions from [Signing and Verification | The Open Network](https://docs.ton.org/develop/dapps/ton-connect/sign),
create an javascript application to talk to the browser extension and then ask the extension to create a valid ton_proof for the message `hex(sighash_all)` (i.e. the hex string of the result of [generate_sighash_all](https://github.com/nervosnetwork/ckb-auth/pull/22)).

Under the hood, ton wallet extension would create a ed25519 signature as follows

```
signature = Ed25519Sign(privkey, sha256(0xffff ++ utf8_encode("ton-connect") ++ sha256(message)))
message = utf8_encode("ton-proof-item-v2/") ++
          Address ++
          AppDomain ++
          Timestamp ++
          Payload
```

where

```
Prefix = 18 bytes "ton-proof-item-v2/" string without trailing null
Address = Big endian work chain (uint32) + address (32 bytes)
AppDomain = Little endian domain length (uint32) + domain (string without trailling null)
Timestamp = Epoch seconds Little endian uint64
Payload = Arbitrary bytes, we use the result of applying sighash_all to the transaction here
```

Below is a sample of `ton_proof` created by [Tonkeeper](https://tonkeeper.com/) to 
[Getgems](https://getgems.io/).

```
{
  "operationName": "loginTonConnect",
  "variables": {
    "payload": {
      "address": "0:a0b96c234f6dede6d56df40ca81315bb73c30d1a9d9f8fbc14d440c73ef6d510",
      "authApplication": "prd=injected plf=windows app=Tonkeeper v=3.3.12 mp=2 f=SendTransaction,[object Object]",
      "chain": "-239",
      "domainLengthBytes": 10,
      "domainValue": "getgems.io",
      "payload": "gems",
      "signature": "eN9vr+Yv6vm5iBuC/daBC18PqwhGUAedtODHuaSh1VJBOKwrQ2ICOk/31YjDTUYxGaHZ7eT+L4dJN1oJGuK5AQ==",
      "timestamp": 1698873010,
      "walletStateInit": "te6cckECFgEAAwQAAgE0AgEAUQAAAAApqaMXfVPCXYWmAMWvtyplExvJyD5PxMuxMpRSUFk34gJrsFxAART/APSkE/S88sgLAwIBIAkEBPjygwjXGCDTH9Mf0x8C+CO78mTtRNDTH9Mf0//0BNFRQ7ryoVFRuvKiBfkBVBBk+RDyo/gAJKTIyx9SQMsfUjDL/1IQ9ADJ7VT4DwHTByHAAJ9sUZMg10qW0wfUAvsA6DDgIcAB4wAhwALjAAHAA5Ew4w0DpMjLHxLLH8v/CAcGBQAK9ADJ7VQAbIEBCNcY+gDTPzBSJIEBCPRZ8qeCEGRzdHJwdIAYyMsFywJQBc8WUAP6AhPLassfEss/yXP7AABwgQEI1xj6ANM/yFQgR4EBCPRR8qeCEG5vdGVwdIAYyMsFywJQBs8WUAT6AhTLahLLH8s/yXP7AAIAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwICAUgTCgIBIAwLAFm9JCtvaiaECAoGuQ+gIYRw1AgIR6STfSmRDOaQPp/5g3gSgBt4EBSJhxWfMYQCASAODQARuMl+1E0NcLH4AgFYEg8CASAREAAZrx32omhAEGuQ64WPwAAZrc52omhAIGuQ64X/wAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDRUUAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+IAeAH6APQEMPgnbyIwUAqhIb7y4FCCEHBsdWeDHrFwgBhQBMsFJs8WWPoCGfQAy2kXyx9SYMs/IMmAQPsABpq/MVw=",
      "publicKey": "7d53c25d85a600c5afb72a65131bc9c83e4fc4cbb1329452505937e2026bb05c"
    }
  },
  "extensions": {
    "persistedQuery": {
      "version": 1,
      "sha256Hash": "b3dee5aa59be0610e5fe26054d974fd7d561f5db9987769b21d302635e48b4ab"
    }
  }
}
```

In this example, the message to be signed is 
`sha256(0xffff ++ utf8_encode("ton-connect") ++ sha256(message)))`

where `message` is the concatenation of 

```
746f6e2d70726f6f662d6974656d2d76322f (prefix "ton-proof-item-v2/")
00000000 (work chain)
a0b96c234f6dede6d56df40ca81315bb73c30d1a9d9f8fbc14d440c73ef6d510 (address)
0a000000 (domain length)
67657467656d732e696f (domain "getgems.io")
b2be426500000000 (timestamp)
payload 67656d73 (payload "gems")
```

A valid CKB transaction is one valid `ton_proof` created with ckb sighash_all result as payload.

# Required information for ckb-auth to verify the validity of `ton_proof`

Ckb-auth requires the signature, public key and `message` structure above without payload
(payload is assumed to be sighash_all result in valid CKB transaction)
to verify the validity of the signature.

Given the above `ton_proof` a valid transaction witness can be constructed as follows.

Since the size of the witness is not static (as the message is dynamically-sized) and
its length is relevant in computing transaction hash. We pad the whole witness to a memory region of size
512. The first part of these memory region is a little-endian `uint16_t` integer represents the length of
the effective witness. From there follows the signature and public key, finally the message without prefix and payload,
i.e. Address ++ AppDomain ++ Timestamp above.
