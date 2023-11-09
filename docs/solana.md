# ckb-auth solana interoperability
Ckb-auth library is able to verify a lot of blockchain signatures including the solana.
We can use `solana` (or other compatible wallet) to generate valid signatures and validate them on-chain with ckb-auth.

A simple way to use solana signature algorithm to lock ckb cells
is to sign the transaction hash (or maybe `sighash_all`, i.e. hashing all fields 
including transaction hash and other witnesses in this input group)
with `solana-cli`, and then leverage ckb-auth to check the validity of this signature.
See [the docs](./auth.md) for more details.

# Generate and verify transaction with ckb-auth-cli
Assume that the message (`sighash_all` result) to be signed is

```
e0dcaff0aac47033faf574450bf90b792777b3ce3e284e2d6b3559a5dbb12a09
```

whose base58 representation is

```
G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon
```
## Sign the message with the official solana command
Run
```
solana transfer --fee-payer keypair.json --from keypair.json --blockhash G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon 6dN24Y1wBW66CxLfXbRT9umy1PMed8ZmfMWsghopczFg 0 --output json --verbose --dump-transaction-message --sign-only
```
which outputs
```
{
  "blockhash": "G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon",
  "message": "AgABBJSNMEbMgjVcD2BXPvhOXxJU05GvhaDy1fk4eHjaxqwi/utkQqq8LIfr9fI22x+/1HP8IUQtr3uq8nk4FejyvYJTmxv1p8BT0M957h8yk9jMKdP9h5TCYtl0IFgKC5YD/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4Nyv8KrEcDP69XRFC/kLeSd3s84+KE4tazVZpduxKgkBAwIBAgwCAAAAAAAAAAAAAAA=",
  "signers": [
    "JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV=yvm9SbU1RorG4Kz6BLRbwmg2JhdZNgbRM1dH4NwBzEqU7UgAnNL41sAVSAp1nVUoXnYzq3qq2TNgDv9SNgb7GpH"
  ]
}
```
Here the string in signers field starts with `JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV` is composed of the public key `JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV` and
the signature `yvm9SbU1RorG4Kz6BLRbwmg2JhdZNgbRM1dH4NwBzEqU7UgAnNL41sAVSAp1nVUoXnYzq3qq2TNgDv9SNgb7GpH`.
The actual message signed is in the message field.

## Verify the signature with `verify` subcommand
```
ckb-auth-cli solana verify -a JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV -s yvm9SbU1RorG4Kz6BLRbwmg2JhdZNgbRM1dH4NwBzEqU7UgAnNL41sAVSAp1nVUoXnYzq3qq2TNgDv9SNgb7GpH --solanamessage AgABBJSNMEbMgjVcD2BXPvhOXxJU05GvhaDy1fk4eHjaxqwi/utkQqq8LIfr9fI22x+/1HP8IUQtr3uq8nk4FejyvYJTmxv1p8BT0M957h8yk9jMKdP9h5TCYtl0IFgKC5YD/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4Nyv8KrEcDP69XRFC/kLeSd3s84+KE4tazVZpduxKgkBAwIBAgwCAAAAAAAAAAAAAAA= -m e0dcaff0aac47033faf574450bf90b792777b3ce3e284e2d6b3559a5dbb12a09
```
This commands return zero if and only if verification succeeded.

# Signing a transaction with solana-cli

## Downloading the solana binaries
The commands below download the official `solana` binaries into the directory `/usr/local`.

```bash
tarball=solana-release-x86_64-unknown-linux-gnu.tar.bz2
wget -O "$tarball" https://github.com/solana-labs/solana/releases/download/v1.16.1/solana-release-x86_64-unknown-linux-gnu.tar.bz2
tar xvaf "$tarball"
sudo cp -r solana-*/* /usr/local/
solana --help
```


## Creating a new account or use the existing solana account
See also [Keypairs and Wallets | Solana Cookbook](https://solanacookbook.com/references/keypairs-and-wallets.html#how-to-generate-a-new-keypair)
```
solana-keygen new -o keypair.json # Create a new keypair
solana-keygen recover -o keypair.json # Recover old keypair from seed phrase
```

## Obtaining public key hash needed by ckb-auth
The public key hash is the first 20 bits of the public key hashed by `blake2b_256`.
We can obtain the public key by running.
```bash
solana-keygen pubkey keypair.json
```
The result of this command is base58-encoded (like `JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV`).
You may [decode it online](http://lenschulwitz.com/base58) or run
the command `base58 -d <<< JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV | xxd` 
([keis/base58](https://github.com/keis/base58) and [xxd(1)](https://linux.die.net/man/1/xxd)required).

## Signing a message with solana cli
To sign the message `e0dcaff0aac47033faf574450bf90b792777b3ce3e284e2d6b3559a5dbb12a09`, we need to first obtain
the base58 encoding of the message, which is `5Tx8F3jgSHx21CbtjwmdaKPLM5tWmreWAnPrbqHomSJF` and then run the command
```bash
solana transfer --fee-payer keypair.json --from keypair.json --blockhash G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon 6dN24Y1wBW66CxLfXbRT9umy1PMed8ZmfMWsghopczFg 0 --output json --verbose --dump-transaction-message --sign-only
```
Here we construct a valid transaction with the message embedded as blockhash in the transaction.
When this transaction is signed by our private key, ckb-auth will recognize it as a valid transaction.
Here the command line argument `6dN24Y1wBW66CxLfXbRT9umy1PMed8ZmfMWsghopczFg` represents the receiver account,
and `0` represents the transaction amount. ckb-auth does not really care about the receiver account and amount,
as long as the signature is valid and the solana message contains the message we intend to sign as blockhash.
The output of the above command is
```json
{
  "blockhash": "G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon",
  "message": "AgABBJSNMEbMgjVcD2BXPvhOXxJU05GvhaDy1fk4eHjaxqwi/utkQqq8LIfr9fI22x+/1HP8IUQtr3uq8nk4FejyvYJTmxv1p8BT0M957h8yk9jMKdP9h5TCYtl0IFgKC5YD/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4Nyv8KrEcDP69XRFC/kLeSd3s84+KE4tazVZpduxKgkBAwIBAgwCAAAAAAAAAAAAAAA=",
  "signers": [
    "JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV=yvm9SbU1RorG4Kz6BLRbwmg2JhdZNgbRM1dH4NwBzEqU7UgAnNL41sAVSAp1nVUoXnYzq3qq2TNgDv9SNgb7GpH"
  ]
}
```

Here the base64 message is a compact representation of the solana transaction to be signed by
`JA6jjaAha7SNVryoecCcNTH7vvqwhX8nBDiyAfeP1FcV`, and it contains the blockhash we passed.
The signers fields include the base58-encoded public key and the signature. The public key and
the signature are separated by an equality sign (`=`). Below script shows the contents of
public key and signature.

```bash
for i in $(solana transfer --fee-payer keypair.json --from keypair.json --blockhash G8mW5A2r4ab8gnmCB4abus21BN8vyMa3hbLg91AcsMon 6dN24Y1wBW66CxLfXbRT9umy1PMed8ZmfMWsghopczFg 0 --output json --verbose --dump-transaction-message --sign-only | jq -r '.signers[]' | tr '=' '\n'); do base58 -d <<< "$i" | xxd; echo; done
```

A sample output is
```
00000000: feeb 6442 aabc 2c87 ebf5 f236 db1f bfd4  ..dB..,....6....
00000010: 73fc 2144 2daf 7baa f279 3815 e8f2 bd82  s.!D-.{..y8.....

00000000: 3117 73da 00cc 4133 9d44 eb40 df90 0228  1.s...A3.D.@...(
00000010: 0d72 2418 04a7 0fff d767 934c b785 6dab  .r$......g.L..m.
00000020: 1257 2d88 f252 13e5 b755 fae6 f3a8 95ee  .W-..R...U......
00000030: 3ab7 9bc1 b3b0 1c18 1e57 eaf4 6292 8002  :........W..b...
```

## Required information for ckb-auth to verify the validity of solana signatures
Ckb-auth requires the signature, public key and message to verify the validity of the signature.
The signature and public key are contained in the signers of `solana transfer` output,
and the message correponds to the field message of `solana transfer` output. 
Signature, public key and message all together form the witness of this transaction.
Since the size of the witness is not static (as the message is dynamically-sized) and
its length is relevant in computing transaction hash. We pad the whole witness to a memory region of size
512. The first part of these memory region is a little-endian `uint16_t` integer represents the length of
the effective witness. From there follows the actually witness.

For example, here is the witness that will be read by ckb-auth
```
00000000: 1601 33f2 9e94 d650 f5de 73b8 4c83 5fa8  ..3....P..s.L._.
00000010: db2c 1f5a 6854 9594 a778 29e8 45a7 47db  .,.ZhT...x).E.G.
00000020: 9618 4fd8 0547 c18e 9e58 374a 7360 b905  ..O..G...X7Js`..
00000030: cb8c 51e0 0023 de84 5957 81b2 13bf 283e  ..Q..#..YW....(>
00000040: 3905 4c0d 9b63 b23d c285 a21f 75b4 a343  9.L..c.=....u..C
00000050: e9b7 4ee2 f4eb 79f3 1a4b 721d 1f3d 1f1a  ..N...y..Kr..=..
00000060: 1c70 0200 0104 948d 3046 cc82 355c 0f60  .p......0F..5\.`
00000070: 573e f84e 5f12 54d3 91af 85a0 f2d5 f938  W>.N_.T........8
00000080: 7878 dac6 ac22 4c0d 9b63 b23d c285 a21f  xx..."L..c.=....
00000090: 75b4 a343 e9b7 4ee2 f4eb 79f3 1a4b 721d  u..C..N...y..Kr.
000000a0: 1f3d 1f1a 1c70 539b 1bf5 a7c0 53d0 cf79  .=...pS.....S..y
000000b0: ee1f 3293 d8cc 29d3 fd87 94c2 62d9 7420  ..2...).....b.t
000000c0: 580a 0b96 03ff 0000 0000 0000 0000 0000  X...............
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 7e97 cfe1 ffbb 973e ceb7  ......~......>..
000000f0: 0c3a 11d9 4d6b 2921 718a 5d9c ce46 1c83  .:..Mk)!q.]..F..
00000100: e2a8 d266 66a3 0103 0201 020c 0200 0000  ...ff...........
00000110: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000120: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000190: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Here the first two bytes 0x1601 = 278 in little endian represent the length of the whole effective witness buffer.
Then we have the real signature `33f29e94d650f5de73b84c835fa8db2c1f5a68549594a77829e845a747db96184fd80547c18e9e58374a7360b905cb8c51e00023de84595781b213bf283e3905`,
followed by the real public key `4c0d9b63b23dc285a21f75b4a343e9b74ee2f4eb79f31a4b721d1f3d1f1a1c70` that is used to sign the message
`02000104948d3046cc82355c0f60573ef84e5f1254d391af85a0f2d5f9387878dac6ac224c0d9b63b23dc285a21f75b4a343e9b74ee2f4eb79f31a4b721d1f3d1f1a1c70539b1bf5a7c053d0cf79ee1f3293d8cc29d3fd8794c262d97420580a0b9603ff00000000000000000000000000000000000000000000000000000000000000007e97cfe1ffbb973eceb70c3a11d94d6b2921718a5d9cce461c83e2a8d26666a301030201020c020000000000000000000000`.
The rest of the message is just a padding that is used to ensure signature have fixed length.
