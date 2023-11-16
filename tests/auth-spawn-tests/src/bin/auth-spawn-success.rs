use auth_spawn_rust::{
    generate_sighash_all, read_tx_template, update_auth_code_hash, update_witness,
};
use ckb_crypto::secp::Privkey;
use ckb_types::H256;

static G_PRIVKEY_BUF: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = Privkey::from(H256::from(G_PRIVKEY_BUF));

    let mut tx = read_tx_template("templates/auth-spawn-success.json")?;
    update_auth_code_hash(&mut tx);

    let message = generate_sighash_all(&tx, 0)?;

    let sig = private_key
        .sign_recoverable(&H256::from(message))
        .expect("sign")
        .serialize();

    update_witness(&mut tx, vec![sig]);

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}
