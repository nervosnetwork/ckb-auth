use auth_spawn_rust::*;

use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::packed::Byte32;
use ckb_types::{bytes::Bytes, core::ScriptHashType};
use lazy_static::lazy_static;

pub const G_PRIVATE_KEY_PATH: &str = "test_data/cold.skey.json";
pub const G_PUBLIC_KEY_PATH: &str = "test_data/cold.vkey.json";
pub const G_TX_PATH: &str = "test_data/cardano_tx.json";
pub const G_TX_SIGNED_PATH: &str = "test_data/cardano_tx.signed.json";

pub const G_CKB_TX_INDEX: usize = 0;

lazy_static! {
    pub static ref AUTH_DL: Bytes = Bytes::from(&include_bytes!("../../../../build/auth")[..]);
    pub static ref AUTH_DL_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1) {
        Some(v) => {
            if v == "--get-sign-hash" {
                get_sign_hash();
                return Ok(());
            }
        }
        None => (),
    };

    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);

    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(&public_key));

    let witness = load_signature(G_TX_SIGNED_PATH);
    update_witness(&mut tx, vec![witness.clone()]);

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);

    Ok(())
}

fn get_sign_hash() {
    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json").unwrap();
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key));

    let hash = Byte32::new(generate_sighash_all(&tx, G_CKB_TX_INDEX).unwrap());

    let output_str = format!("{:#x}", hash);
    println!("{}", &output_str[2..]);
}

pub fn load_file(path: &str) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();

    let mut raw_data = v.get("cborHex").unwrap().to_string();
    if raw_data.as_bytes()[0] == '\"' as u8 {
        raw_data = String::from(&raw_data[1..raw_data.len() - 1]);
    }

    hex::decode(&raw_data).unwrap()
}

pub fn load_public_key(path: &str) -> Vec<u8> {
    let key = load_file(path);
    if key[0] != 0x58 || key[1] != 0x20 {
        panic!("Private key is invalid, data: {:02X?}, path: {}", key, path);
    }
    if key.len() != 32 + 2 {
        panic!("Load key failed, len is not 32, {:02X?}", key);
    }

    key[2..].to_vec()
}

pub fn load_signature(path: &str) -> Vec<u8> {
    let data = load_file(path);
    data
}

pub fn update_args(tx: &mut ReprMockTransaction, auth_id: u8, pub_key_hash: &[u8]) {
    let inputs = &mut tx.mock_info.inputs;

    let mut args = Vec::<u8>::with_capacity(21);
    args.resize(21, 0);
    args[0] = auth_id;
    args[1..].copy_from_slice(&pub_key_hash[0..20]);

    for i in inputs {
        let mut data = i.output.lock.args.as_bytes().to_vec();
        data[0..21].copy_from_slice(&args);
        i.output.lock.args = JsonBytes::from_vec(data);
    }
}
