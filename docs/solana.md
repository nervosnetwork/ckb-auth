# ckb-auth solana interoperability

Here's an explanation of Solana using [Phantom Wallet](https://phantom.app/).

## Install Wallet and Create Account

Simply follow the instructions provided by the [official website](https://phantom.app/download) for installation. After installation, proceed to create or import an account as prompted.

## Sign

Open any HTTPS web page -> Launch debugging tools -> Access the console.

Execute the following javascript code in the console to obtain the public key and signature.
```javascript
async function Sign(msg) {
    let provider = window.phantom?.solana;
    if (!provider.isConnected) {
        let resp = await provider.connect();
    }

    const encode_msg = new TextEncoder().encode(msg);
    const signed = await provider.signMessage(encode_msg, "utf8");
    console.log(signed);

    console.log(`public key: ${signed.publicKey.toString()}`);
    console.log(`sign data: ${Array.from(signed.signature).map(byte => byte.toString(16).padStart(2, '0')).join('')}`);
}
Sign("0011223344556677889900112233445500112233445566778899001122334455");
```

Output:
```
public key: EmAkvbZrWHvqdWadFaAtmgPDPnuERQrPAhGdb9h4LM9p
VM493:12 sign data: 0101591c8e25ec1c97b5a3e3d20c5909fb0cca35024370083f8a9b4753870a5b34f9e783876fbd2657b79a737d03c24c8006fc1acab6a3745728fd41785c8d05
```

*Note: When executing signMessage, Phantom Wallet will prompt a window. You may need to enter a password and confirm the signing content.*

### Signing Mechanism (Optional Section)

After installing the Phantom browser extension, some JavaScript code is injected into the browser, enabling interaction with the Wallet for various operations such as transaction initiation. Phantom provides an API for signing: [signMessage](https://docs.phantom.app/solana/signing-a-message).

Solana uses `ed25519` for signatures, which differs from CKB. Additionally, Solana's transaction address directly utilizes the `Public key` (Base58 encoded) instead of `Public key hash`. However, due to CKB-auth's mechanism, the `Public key` here is decoded and hashed (ckb-blake2b) to serve as the `address`.

When using this mechanism, consider the following:
* In the example above, the sign actually returns a `Uint8Array` with a length of 64. For ease of command-line transmission, it is converted into a hexadecimal string.
* Phantom's JS API is only enabled on *HTTPS* pages. Here, we directly operate in the console of any web page.
* Different browsers may have different methods for opening debugging tools. Refer to the browser's documentation for specifics. Here, Chrome is used.
* The dApp combines the signature and public key, placing the signature first followed by the public key. The resulting data is sent to the P2P network.
* The blake160 hash of the public key must match the 20-byte auth content. In Solana, the 32-byte public key can be decoded from the address via base58, but it can't directly fit into the 20-byte auth content, hence the blake160 hash.
* For ed25519 message, signature, and public key, the ed25519 verify function is utilized for validation.
* Unlike secp256k1, an ed25519 signature cannot independently recover the public key. Therefore, both the signature and an additional public key are required for validation.

## Verify

To verify in ckb-auth-cli:

```bash
ckb-auth-cli -- solana verify \
  -p EmAkvbZrWHvqdWadFaAtmgPDPnuERQrPAhGdb9h4LM9p \
  -s 0101591c8e25ec1c97b5a3e3d20c5909fb0cca35024370083f8a9b4753870a5b34f9e783876fbd2657b79a737d03c24c8006fc1acab6a3745728fd41785c8d05 \
  -m 0011223344556677889900112233445500112233445566778899001122334455
```