# [Tron](../README.md)

Tron's wallets and tools do not support standalone signature operations. Therefore, we use the officially provided SDK and `ckb-auth` for comparative testing.
[Official website](https://tronweb.network/)

Tron's signature mechanism relies on secp256k1, which is also used by [Ethereum](./ethereum.md).

## TronWeb
`TronWeb` is the official SDK provided by Tron, with its source code available on [GitHub](https://github.com/tronprotocol/tronweb). Within the [`tools/tron`](../tools/tron/) directory, there is a straightforward signature demo. This demo generates a set of keys, signs a message with the private key from this set, and verifies the signature.

The message is a 32-byte binary data, corresponding to the ckb signature message.

To run the demo, you will need `nodejs` and the `tronweb` module.
- **Node.js**: You can download the appropriate binary package from the [Official website](https://nodejs.org/en), extract it, and add the directory to your `PATH`.
- To install 'tronweb', navigate to the directory [`tools/tron`](../tools/tron/) and run the command: `npm install tronweb`. (Please note that this command may require proxy configuration and will place the dependencies in the `node_modules` directory in the current location.)

Once you've installed the dependencies, you can run the demo using this command:
```bash
node main.js
```

Output
```text
key: {
  privateKey: '13B9751EDFC5F25ABCB6AE0A8DF387C0B473CF52D8A71125358EBC735F157ABA',
  publicKey: '046B0EE21A47F54AD838D6F7C97A01067CC4F0BFA94C96F96A90516A24EC1E686F73EEEC973CAC5977563072035D6FEC23B22627F0EDF428F141F33300BDBE7BFF',
  address: {
    base58: 'TNzoqJ2ZCVZAzTsR5sKA6N5zardVodSi5x',
    hex: '418EE7208C79F1FB62C124875C22CA082CCF6C89F6'
  }
}
msg data: 01122334445566778899aabbccddeeff01122334445566778899aabbccddeeff
msg hash: 0x98ebdce9b9c574540113cef6e187404fd804bc0aff17d1ea4b977ff7cbaefe2b
sign: 0xdec4f45b74a3b19926a5d17b1a28d9c18f0e2982d764b0477269815827954ca43b27e004802d11d07311fb856ef53a7554c8301dae087d3ebbf14de4fea1eb9f1b
verify ret pubkey address: TNzoqJ2ZCVZAzTsR5sKA6N5zardVodSi5x


Success
```

Here's an explanation of the output content:
- `key-privateKey`: This is the plaintext private key stored as a hexadecimal string.
- `key-publicKey`: The plaintext public key, also in hexadecimal string format.
- `key-address-base58`: The address encoded in base58, commonly used in Tron.
- `key-address-hex`: The hexadecimal form of the address, which is not commonly used.
- `msg data`: The data to be signed is a fixed length of 32 bytes, necessary for verification in ckb-auth-cli.
- `msg hash`: The actual data used for signing, derived from multiple hashes of the msg data. This result is displayed for reference or debugging purposes.
- `sign`: The result of the signature, in hexadecimal string format. In this case, it's 65 bytes long.
- `verify ret pubkey address`: The result of the signature, in hexadecimal string format. In this case, it's 65 bytes long.

## Address
In Tron, the address is encoded by default in base58 format, and after decoding, it consists of 42 bytes.

The first byte is a fixed value of 0x41, and the subsequent data structure is the same as in `Ethereum`. [Refer to](https://developers.tron.network/docs/account).

In the `ckb-auth-cli tron verify` command, the tool also checks the integrity of the Tron address to ensure it matches this format.

## Sign
The Tron signature process is indeed very similar to Ethereum, with a minor difference in how the message is hashed. Before hashing the message in Tron, a fixed prefix, `TRON Signed Message`, is added to it. This prefix is used as part of the hashing process for Tron signatures.

### Verify

The Tron verification process is similar to Ethereum, and the ckb-auth-cli tron verify command is used for verification purposes. This command is designed to verify Tron signatures, similar to how Ethereum signatures are verified.

```
./ckb-auth-cli tron verify -a TNzoqJ2ZCVZAzTsR5sKA6N5zardVodSi5x -s 0xdec4f45b74a3b19926a5d17b1a28d9c18f0e2982d764b0477269815827954ca43b27e004802d11d07311fb856ef53a7554c8301dae087d3ebbf14de4fea1eb9f1b -m 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```
The output "Success" indicates a successful verification.
