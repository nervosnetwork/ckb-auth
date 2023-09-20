In this document, we will introduce a new concept, `auth` (authentication). It
was firstly introduced in [RFC:
Omnilock](https://github.com/nervosnetwork/rfcs/pull/343). It's used for
authentication by validating signature for different blockchains.

### Compile dependencies
Before using the following APIs, it is necessary to compile CKB contracts.

To compile, use the following commands in the root directory. The generated files will be located in the `build` directory.

```
git submodule update --init
make all-via-docker
```

If you need to test or use `ckb-auth-cli`, you also need to compile the `auth-demo`:

```
capsule build
make -f examples/auth-demo/Makefile all-via-docker
```

For detailed instructions, please refer to the [README.md](../README.md) or [CI](../.github/workflows/rust.yml).

### Definition

```C
typedef struct CkbAuthType {
  uint8_t algorithm_id;
  uint8_t content[20];
} CkbAuthType;

```

It is a data structure with 21 bytes. The content can be hash (blake160 or some
other hashes) of public key, preimage, or some others. The blake160 hash function
is defined as first 20 bytes of [blake2b
hash](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#crypto-primitives).

### Auth Algorithm Id
Here we list some known `algorithm_id` which have been implemented already:

#### CKB(algorithm_id=0)

It is implemented by default CKB lock script: secp256k1_blake160_sighash_all. More details in [reference implementation](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_sighash_all.c).

Key parameters:
* signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
* pubkey: 33-byte compressed pubkey
* pubkey hash: blake160 of pubkey


#### Ethereum(algorithm_id=1)

It is implemented by blockchain Ethereum.
[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L199)

Key parameters:

  - signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
  - pubkey: 64-byte uncompressed pubkey
  - pubkey hash: last 20 bytes of pubkey keccak hash

#### EOS(algorithm_id=2)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L206)

Key parameters: Same as ethereum

#### Tron(algorithm_id=3)
[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L213)

Key parameters: Same as ethereum

#### Bitcoin(algorithm_id=4)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L220)

Key parameters:
- signature: a 65-byte signature defined in [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
- pubkey: 65-byte uncompressed pubkey
- pubkey hash: first 20 bytes of sha256 and ripemd160 on pubkey

#### Dogecoin(algorithm_id=5)

[reference implementation](https://github.com/XuJiandong/pw-lock/blob/e7f5f2379185d4acf18af38645559102e100a545/c/pw_lock.h#L227)

Key parameters: same as bitcoin

#### CKB MultiSig(algorithm_id=6)

[reference implementation](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_multisig_all.c)

Key parameters:
- signature: multisig_script | Signature1 | Signature2 | ...
- pubkey: variable length, defined as multisig_script(S | R | M | N | PubKeyHash1 | PubKeyHash2 | ...)
- pubkey hash: blake160 on pubkey

`multisig_script` has following structure:
```
+-------------+------------------------------------+-------+
|             |           Description              | Bytes |
+-------------+------------------------------------+-------+
| S           | reserved field, must be zero       |     1 |
| R           | first nth public keys must match   |     1 |
| M           | threshold                          |     1 |
| N           | total public keys                  |     1 |
| PubkeyHash1 | blake160 hash of compressed pubkey |    20 |
|  ...        |           ...                      |  ...  |
| PubkeyHashN | blake160 hash of compressed pubkey |    20 |
```


#### Schnorr(algorithm_id=7)

Key parameters:
- signature: 32 bytes pubkey + 64 bytes signature
- pubkey: 32 compressed pubkey
- pubkey hash: blake160 of pubkey

#### Litecoin(algorithm_id=10)

Key parameters: same as bitcoin

#### CardanoLock(algorithm_id=11)

Key parameters:
- signature: cardano signed data.
- pubkey: 32 compressed pubkey
- pubkey hash: blake160 of pubkey

#### Monero(algorithm_id=12)

Key parameters:
- signature: monero signature
- mode: 1 byte hardcoded to 00 to indicate we are using spend key to sign transactions
- spend key: 32 bytes of the public spend key
- view key: 32 bytes of the public view key
- pubkey hash: blake160 of (mode || spend key || view key)

#### Solana(algorithm_id=13)

Key parameters:
- signature: solana signature
- public key: the public key of the signer
- message: the message solana client signed

#### More blockchains Support Are Ongoing ...
- Ripple
#### Ripple(algorithm_id=14)

Key parameters:
- signature: ripple signature (tx_blob field).
- pubkey: 32 compressed pubkey.
- pubkey hash: sha256 and ripemd160 of pubkey, refer to [ckb-auth-cli ripple parse](../tools/ckb-auth-cli/src/ripple.rs).

...

### Low Level APIs

We define some low level APIs to auth (Authentication), which can be also used for other purposes.
It is based on the following idea:
* [RFC: Swappable Signature Verification Protocol Spec](https://talk.nervos.org/t/rfc-swappable-signature-verification-protocol-spec/4802)
* [Ideas on chained locks](https://talk.nervos.org/t/ideas-on-chained-locks/5887)

First we define the "EntryType":
```C
typedef struct EntryType {
    uint8_t code_hash[32];
    uint8_t hash_type;
    uint8_t entry_category;
} EntryType;
```

* code_hash/hash_type

  the cell which contains the code binary
* entry_category

  The entry to the algorithm. Now there are 2 categories:
  - dynamic library
  - spawn (activated after hardfork 2023)

### Entry Category: Dynamic Library
We define the follow functions when entry category is `dynamic library`:
```C
int ckb_auth_validate(uint8_t auth_algorithm_id, const uint8_t *signature,
    uint32_t signature_size, const uint8_t *message, uint32_t message_size,
    uint8_t *pubkey_hash, uint32_t pubkey_hash_size);
```
The first argument denotes the `algorithm_id` in `CkbAuthType` described above. The arguments `signature` and
`pubkey_hash` are described in `key parameters` mentioned above.

A valid dynamic library denoted by `EntryType` should provide `ckb_auth_validate` exported function.

### Entry Category: Spawn
This category shares same arguments and behavior to dynamic library. It uses `spawn` instead of `dynamic library`. When
entry category is `spawn`, its arguments format is below:

```text
<auth algorithm id>  <signature>  <message>  <pubkey hash>
```
They will be passed as `argv` in `spawn` syscall, in hex format. An example of arguments:
```
20 000000000000AA11 000000000000BB22 000000000000CC33
```

The `auth algorithm id` denotes the `algorithm_id` in `CkbAuthType` described above. The fields `signature` and
`pubkey_hash` are described in `key parameters` mentioned above.

We can implement different auth algorithm ids in same code binary. 


### High Level APIs
The following API can combine the low level APIs together:
```C
int ckb_auth(EntryType* entry, CkbAuthType *id, uint8_t *signature, uint32_t signature_size, const uint8_t *message32)
```
Most of developers only need to use this function without knowing the low level APIs.


### Rust High Level APIs
Provide a Rust interface, you can directly call the related functions of ckb-auth in rust.

Dependencies name: `ckb-auth-rs`

#### API Description
``` rust
pub fn ckb_auth(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError>
```

`CkbEntryType` : On-chain information and calling method of auth script.

`CkbAuthType` : Auth Algorithm Id and public key hash

`signature` : signature data.

`message` : Participate in the message data of the signature.

