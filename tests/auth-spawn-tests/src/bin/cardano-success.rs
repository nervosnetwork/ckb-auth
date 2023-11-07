use auth_spawn_rust::*;
use blake2b_rs::Blake2bBuilder;
use cardano_message_signing::{
    cbor::{CBORArray, CBORObject, CBORValue},
    utils::Deserialize,
    utils::{Int, ToBytes},
};
use cardano_serialization_lib::{
    crypto::{Ed25519Signature, PrivateKey, PublicKey},
    utils::hash_transaction,
    TransactionBody,
};
use cbor_event::de::Deserializer;
use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::packed::Byte32;
use ckb_types::{bytes::Bytes, core::ScriptHashType};
use lazy_static::lazy_static;
use molecule::prelude::*;
use std::env;

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
    let args: Vec<String> = env::args().collect();
    match args.get(1) {
        Some(v) => {
            if v == "--get-sign-hash" {
                get_sign_hash();
            }
            return Ok(());
        }
        None => (),
    };

    check_cardano_sign()?;

    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));
    update_witness_pubkey(&mut tx, &public_key);

    let witness = load_signature(G_TX_SIGNED_PATH);
    update_witness(&mut tx, vec![witness.clone()]);
    // println!("{:02x?}", tx.tx.witnesses.get(0).unwrap().as_bytes());

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}

fn get_sign_hash() {
    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json").unwrap();
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));

    let hash = Byte32::new(generate_sighash_all(&tx, G_CKB_TX_INDEX).unwrap());

    let output_str = format!("{:#x}", hash);
    println!("{}", &output_str[2..]);
}

fn update_witness_pubkey(tx: &mut ReprMockTransaction, public_key: &PublicKey) {
    let witness = tx.tx.witnesses.get_mut(G_CKB_TX_INDEX).unwrap();

    let data = witness.as_bytes()[20..].to_vec();
    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let mut root2 = CBORArray::new();
    root2.add(&root.get(0));

    let mut sign_data = CBORObject::new();
    sign_data.insert(
        &CBORValue::new_int(&Int::new_i32(0)),
        &CBORValue::new_bytes(public_key.as_bytes()),
    );
    root2.add(&CBORValue::new_object(&sign_data));
    root2.add(&root.get(1));

    update_witness(tx, vec![root2.to_bytes()]);
}

fn check_cardano_sign() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = load_private_key(G_PRIVATE_KEY_PATH);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);

    assert_eq!(private_key.to_public().as_bytes(), public_key.as_bytes());

    let tx_data = load_signature(G_TX_PATH);
    // println!("len({}) {:02x?}", tx_data.len(), tx_data);

    let tx_body =
        TransactionBody::from_bytes(tx_data[1..].to_vec()).expect("new tx body from bytes");

    // println!("{:02x?}", tx_body.to_bytes());
    let tx_hash = hash_transaction(&tx_body);
    let tx_hash2 = cardano_blake2b_256(&tx_body.to_bytes());
    assert_eq!(tx_hash.to_bytes(), tx_hash2);
    // println!("{:02x?}", tx_hash2);

    let (sign_data, pubkey) = get_signature_struct(G_TX_SIGNED_PATH);
    assert_eq!(public_key.as_bytes(), pubkey);

    // println!("{:02x?}", sign_data);
    // println!("{:02x?}", pubkey);

    let ret = public_key.verify(&tx_hash2, &Ed25519Signature::from_bytes(sign_data).unwrap());
    assert!(ret);

    Ok(())
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

pub fn load_private_key(path: &str) -> PrivateKey {
    let key = load_file(path);
    if key[0] != 0x58 || key[1] != 0x20 {
        panic!("Private key is invalid, data: {:02X?}, path: {}", key, path);
    }
    if key.len() != 32 + 2 {
        panic!("Load key failed, len is not 32, {:02X?}", key);
    }

    PrivateKey::from_normal_bytes(&key[2..]).unwrap()
}

pub fn load_public_key(path: &str) -> PublicKey {
    let key = load_file(path);
    if key[0] != 0x58 || key[1] != 0x20 {
        panic!("Private key is invalid, data: {:02X?}, path: {}", key, path);
    }
    if key.len() != 32 + 2 {
        panic!("Load key failed, len is not 32, {:02X?}", key);
    }

    PublicKey::from_bytes(&key[2..]).unwrap()
}

pub fn load_signature_file(path: &str) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();

    let mut data = v.get("cborHex").unwrap().to_string();

    if data.as_bytes()[0] == '\"' as u8 {
        data = String::from(&data[1..data.len() - 1]);
    }

    hex::decode(data).unwrap()
}

pub fn load_signature(path: &str) -> Vec<u8> {
    let data = load_file(path);

    data
}

pub fn get_signature_struct(path: &str) -> (Vec<u8>, Vec<u8>) {
    let data = load_file(path);

    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let sign_buf = root
        .get(1)
        .as_object()
        .unwrap()
        .get(&CBORValue::new_int(&Int::new_i32(0)))
        .unwrap()
        .as_array()
        .unwrap()
        .get(0)
        .as_array()
        .unwrap()
        .get(1)
        .as_bytes()
        .unwrap();

    let data = load_file(path);

    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let pubkey_buf = root
        .get(1)
        .as_object()
        .unwrap()
        .get(&CBORValue::new_int(&Int::new_i32(0)))
        .unwrap()
        .as_array()
        .unwrap()
        .get(0)
        .as_array()
        .unwrap()
        .get(0)
        .as_bytes()
        .unwrap();

    (sign_buf, pubkey_buf)
}

pub fn cardano_blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Blake2bBuilder::new(32).build();

    ctx.update(data);
    let mut r = [0u8; 32];
    ctx.finalize(&mut r);
    r
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
