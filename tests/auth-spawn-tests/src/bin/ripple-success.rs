use auth_spawn_rust::{
    generate_sighash_all, get_auth_code_hash, get_auth_hash_type, read_tx_template, update_witness,
};
use ckb_auth_rs::EntryCategoryType;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::bytes::Bytes;
use hex::decode;
use ripple_keypairs::{Algorithm, Entropy, Seed};

const G_RIPPLED_KEY_SEED_HEX: &str = "E2F503ADCAC98625CF31D89DED58B9DE";

// PUBKEY: 03D290362A408EFD37E8CA0A055A4D394AAE5C38FED2E452703D9ACBCA1EDECA9B

fn update_args(tx: &mut ReprMockTransaction, pubkey: [u8; 20]) {
    let mut args: Vec<u8> = vec![0x0Eu8];
    args.extend_from_slice(&pubkey);
    args.extend_from_slice(&get_auth_code_hash());
    args.extend_from_slice(&[get_auth_hash_type(), EntryCategoryType::Spawn as u8]);

    for input in &mut tx.mock_info.inputs {
        input.output.lock.args =
            ckb_jsonrpc_types::JsonBytes::from_bytes(Bytes::from(args.clone()));
    }
}

fn hash_ripemd160(data: &[u8]) -> [u8; 20] {
    use mbedtls::hash::*;
    let mut md = Md::new(Type::Ripemd).unwrap();
    md.update(data).expect("hash ripemd update");
    let mut out = [0u8; 20];
    md.finish(&mut out).expect("hash ripemd finish");

    out
}

fn hash_sha256(data: &[u8]) -> [u8; 32] {
    use mbedtls::hash::*;
    let mut md = Md::new(Type::Sha256).unwrap();
    md.update(data).expect("hash sha256 update");
    let mut out = [0u8; 32];
    md.finish(&mut out).expect("hash sha256 finish");

    out
}

fn get_ripple_hash(data: &[u8]) -> [u8; 20] {
    hash_ripemd160(&hash_sha256(data))
}

fn generate_ripple_tx(ckb_sign_msg: &[u8], pubkey: &[u8], sign: Option<&[u8]>) -> Vec<u8> {
    assert_eq!(ckb_sign_msg.len(), 20);
    assert_eq!(pubkey.len(), 33);

    let tx_temp_1: &str =
        "1200002280000000240000016861D4838D7EA4C680000000000000000000000000005553440000000000";
    let tx_temp_2: &str = "684000000000002710";
    let tx_temp_3: &str = "83143E9D4A2B8AA0780F682D136F7A56D6724EF53754";

    let mut padding_zero = 0usize;

    let mut buf = Vec::new();
    if sign.is_none() {
        buf.extend_from_slice(&[0x53, 0x54, 0x58, 0x00]);
    }

    buf.extend_from_slice(&decode(tx_temp_1).unwrap());
    buf.extend_from_slice(ckb_sign_msg);
    buf.extend_from_slice(&decode(tx_temp_2).unwrap());

    buf.extend_from_slice(&[0x73, 0x21]);
    buf.extend_from_slice(pubkey);

    if sign.is_some() {
        let sign_len = sign.as_ref().unwrap().len();
        buf.extend_from_slice(&[0x74, sign_len as u8]);
        buf.extend_from_slice(sign.unwrap());

        padding_zero = 72 - sign_len;
    }

    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(ckb_sign_msg);

    buf.extend_from_slice(&decode(tx_temp_3).unwrap());

    if sign.is_some() {
        for _ in 0..padding_zero {
            buf.push(0);
        }
        buf.push(padding_zero as u8 + 1);
    }

    buf
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let (private_key, public_key) = Seed::random().derive_keypair().expect("generate keypair");
    let base_seed: [u8; 16] = decode(G_RIPPLED_KEY_SEED_HEX).unwrap().try_into().unwrap();
    let (private_key, public_key) = Seed::new(Entropy::Array(base_seed), &Algorithm::Secp256k1)
        .derive_keypair()
        .unwrap();

    let mut tx = read_tx_template("templates/ripple-success.json")?;
    let pubkey_data = decode(public_key.to_string()).unwrap();
    let pubkey_hash = get_ripple_hash(&pubkey_data);
    update_args(&mut tx, pubkey_hash.clone());

    let message = generate_sighash_all(&tx, 0)?;
    let r_message = get_ripple_hash(&message);

    // println!(
    //     "pubkey_hash:{}\nmsg:{}\nrmsg:{}",
    //     hex::encode(pubkey_hash),
    //     hex::encode(message),
    //     hex::encode(r_message)
    // );

    let sign_msg = generate_ripple_tx(&r_message, &pubkey_data, None);
    // println!("sign msg: {}", hex::encode(&sign_msg));

    let sign_data = private_key.sign(&sign_msg);
    let sign_data: Vec<u8> = hex::decode(sign_data.to_string()).unwrap();
    let witness = generate_ripple_tx(&r_message, &pubkey_data, Some(&sign_data));
    update_witness(&mut tx, vec![witness]);

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}
