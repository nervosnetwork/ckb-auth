# verify secp256r1 signature signed to a raw message (without hashing)

This is the raw message version of [./secp256r1.md](./secp256r1.md), i.e.
we are using the message as it is without calculating the sha256 digest of the message first.

We can sign the message as shown in [./secp256r1.md](./secp256r1.md), and then
calculate the message digest, and put the digest in place of message, and the
create transactions as in [./secp256r1.md](./secp256r1.md).

For example, given the same message `29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157`
as in [./secp256r1.md](./secp256r1.md).

All we need to do is change the algorithm ID to 17 and the replace `29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157`
with `4fb7632dfcd5ed376b5dc1e454846628b3cd95b10a8a79d6b6fea56c633ec490`, the sha256 hash
obtained by the following command.

```
xxd -r -p <<< 29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157 | sha256sum
4fb7632dfcd5ed376b5dc1e454846628b3cd95b10a8a79d6b6fea56c633ec490  -
```
