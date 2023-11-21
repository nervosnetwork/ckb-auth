# [Dogecoin](../README.md)

To work with Dogecoin, utilize the official command-line tool: [DogecoinCore](https://github.com/dogecoin/dogecoin/tree/v1.14.6).

Dogecoin shares many similarities with [Bitcoin](./bitcoin.md), including its signature algorithm and command-line tools. Here, we will focus on the distinctive aspects that set Dogecoin apart.

## Installation and Configuration
[Download](https://github.com/dogecoin/dogecoin/releases/tag/v1.14.6)
- It's essential to note that, much like `BitcoinCore` on Mac, Dogecoin provides GUI tools exclusively.
- For configuration, you can use the official default settings. If you prefer not to synchronize with online nodes, you can add `proxy=127.0.0.1:12345` to the configuration, using a non-existent proxy.

Start Dogecoin with the following command:
```
./dogecoind -daemonwait
```

## Generate a Key

When using dogecoin-cli for the first time, the `getaddressesbyaccount` command will automatically generate a new key group. Account information is stored in `wallet.dat`.

```bash
./dogecoin-cli getaddressesbyaccount ""
```

```
[
  "DNF59P3dX2S2i188aPfBfL4aecs9gWtBt8"
]
```

A Dogecoin address always begins with the letter `D`, followed by content encoded in Base58, which includes the `public key hash` and a `checksum`. [You can find the code to parse and check addresses here](../tools/ckb-auth-cli/src/chain_command/dogecoin.rs#L52).

## Sign

Dogecoin Core supports signing and verifying messages.

```bash
./dogecoin-cli signmessage DNF59P3dX2S2i188aPfBfL4aecs9gWtBt8 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Output:
```
IIu/kxASl/W/5o3bjTD4KKBCQKcsDPUdp0+1Xu4vy0FhcpSfsIPu5Mi90VV0FGsN2gdlUvQFswTI886CeKNp7So=
```

The output signature data is Base58 encoded and can be used directly in ckb-auth.

To verify with `Dogecoin Core`:

```bash
./dogecoin-cli verifymessage DNF59P3dX2S2i188aPfBfL4aecs9gWtBt8 IIu/kxASl/W/5o3bjTD4KKBCQKcsDPUdp0+1Xu4vy0FhcpSfsIPu5Mi90VV0FGsN2gdlUvQFswTI886CeKNp7So= 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Output:
```
true
```

## Verify

To verify in ckb-auth-cli:

```bash
ckb-auth-cli dogecoin verify -a DNF59P3dX2S2i188aPfBfL4aecs9gWtBt8 -s IIu/kxASl/W/5o3bjTD4KKBCQKcsDPUdp0+1Xu4vy0FhcpSfsIPu5Mi90VV0FGsN2gdlUvQFswTI886CeKNp7So= -m 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Verification in Dogecoin is quite similar to Bitcoin, with the exception of address handling. For the most part, Bitcoin code can be used.