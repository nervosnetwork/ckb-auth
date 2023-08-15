# ckb-auth secp256r1 interoperability
Ckb-auth library is able to verify ECDSA signatures over secp256r1 curve with sha256 as digest algorithm.
A simple way to use ECDSA-SHA256/secp256r1 signature algorithm to lock ckb cells
is to sign the transaction hash (or maybe `sighash_all`, i.e. hashing all fields 
including transaction hash and other witnesses in this input group)
with `litecoin-cli`, and then leverage ckb-auth to check the validity of this signature.
See [the docs](./auth.md) for more details.

# Generate signature with openssl

## Install openssl
Openssl is available from most operating systems. Refer to your favorite package manager to install it.

## Creating or importing secp256r1 private key
You may follow the instructions here to import your existing secp256r1 private key.
Or you can generate a new one with 
```
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
```
 

## Obtaining the public key hash
We can create a public key file (`public.pem`) corresponding to the private key file (`private.pem`) with the command
```
openssl ec -in private.pem -pubout -out public.pem
```

To show the detailed information about this public key. We can run
```
openssl ec -text -inform PEM -in public.pem -pubin
```

Below is a sample output

```
read EC key
Public-Key: (256 bit)
pub:
    04:1c:cb:e9:1c:07:5f:c7:f4:f0:33:bf:a2:48:db:
    8f:cc:d3:56:5d:e9:4b:bf:b1:2f:3c:59:ff:46:c2:
    71:bf:83:ce:40:14:c6:88:11:f9:a2:1a:1f:db:2c:
    0e:61:13:e0:6d:b7:ca:93:b7:40:4e:78:dc:7c:cd:
    5c:a8:9a:4c:a9
ASN1 OID: prime256v1
NIST CURVE: P-256
writing EC key
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHMvpHAdfx/TwM7+iSNuPzNNWXelL
v7EvPFn/RsJxv4POQBTGiBH5ohof2ywOYRPgbbfKk7dATnjcfM1cqJpMqQ==
-----END PUBLIC KEY-----
```

Here the binary string `04:1c:...:a9` is a binary representation of the public key, where `04` represents uncompressed public key,
i.e. both x and y coordinates are given in the following binary string.
And the public key hash is the blake2b 256 hash of the binary string excluding the first byte `04`.
That is the pubkey hash is just the blake2b 256 hash of `1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9`.

## Sign the message
To sign the message with hex `29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157`, we can run

```
xxd -r -p <<< 29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157 > message
```
to save this message into file `message` and then run

```
openssl dgst -sha256 -sign private.pem message > signature
```
to save the signature into file `signature`

The final signature field of the ckb transaction should be this signature concatenated with the above public key.
