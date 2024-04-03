pub mod auto_complete;
pub mod hash;

pub mod blockchain {
    pub use ckb_types::packed::{
        Byte, Byte32, Byte32Reader, Byte32Vec, Byte32VecReader, ByteReader, Bytes, BytesOpt,
        BytesOptReader, BytesReader, BytesVec, BytesVecReader, Script, WitnessArgs,
        WitnessArgsBuilder, WitnessArgsReader,
    };
}
use anyhow;
use anyhow::Context;
use ckb_auth_rs::EntryCategoryType;
use ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_types::core::ScriptHashType;
use ckb_types::molecule::{bytes::Bytes, prelude::*};
use ckb_types::packed;
use ckb_types::packed::CellOutput;
use ckb_types::packed::Script;
use ckb_types::packed::WitnessArgsBuilder;
use ckb_types::prelude::*;
use std::collections::HashMap;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use auto_complete::auto_complete;
use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction};
use hash::hash;
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use serde_json::from_str as from_json_str;

lazy_static! {
    pub static ref AUTH_DL: Bytes = Bytes::from(&include_bytes!("../../../build/auth")[..]);
    pub static ref AUTH_DL_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;
}

fn load_tx(tx_file: &str) -> Result<ReprMockTransaction, anyhow::Error> {
    let mock_tx =
        read_to_string(tx_file).with_context(|| format!("Failed to read from {}", tx_file))?;
    let mut mock_tx = auto_complete(&mock_tx)?;

    let tx_file = PathBuf::from(tx_file);
    // replace_data
    let regex = Regex::new(r"\{\{ ?data (.+?) ?\}\}").unwrap();
    mock_tx = regex
        .replace_all(&mock_tx, |caps: &Captures| -> String {
            let cap1 = &caps[1];
            let path = if !Path::new(cap1).is_absolute() {
                let root = tx_file.parent().unwrap();
                root.join(cap1)
            } else {
                Path::new(cap1).to_path_buf()
            };
            let data = std::fs::read(&path);
            if data.is_err() {
                panic!("Read {:?} failed : {:?}", path, data);
            }
            let data = data.unwrap();
            hex::encode(data)
        })
        .to_string();

    // replace_hash
    let regex = Regex::new(r"\{\{ ?hash (.+?) ?\}\}").unwrap();
    mock_tx = regex
        .replace_all(&mock_tx, |caps: &Captures| -> String {
            let cap1 = &caps[1];
            let path = if !Path::new(cap1).is_absolute() {
                let root = tx_file.parent().unwrap();
                root.join(cap1)
            } else {
                Path::new(cap1).to_path_buf()
            };
            let data = std::fs::read(path).unwrap();
            hex::encode(blake2b_256(data))
        })
        .to_string();

    // prelude_type_id
    let mut type_id_dict = HashMap::new();
    let rule = Regex::new(r"\{\{ ?def_type (.+?) ?\}\}").unwrap();
    for caps in rule.captures_iter(&mock_tx) {
        let type_id_name = &caps[1];
        assert!(!type_id_dict.contains_key(type_id_name));
        let type_id_script = Script::new_builder()
            .args(Bytes::from(type_id_name.to_string()).pack())
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let type_id_script_hash = type_id_script.calc_script_hash();
        let type_id_script_hash = format!("{:x}", type_id_script_hash);
        type_id_dict.insert(type_id_name.to_string(), type_id_script_hash);
    }

    // replace_def_type
    let regex = Regex::new(r#""?\{\{ ?def_type (.+?) ?\}\}"?"#).unwrap();
    mock_tx = regex
        .replace_all(&mock_tx, |caps: &Captures| -> String {
            let cap1 = &caps[1];
            let type_id_script_json = ckb_jsonrpc_types::Script {
                code_hash: TYPE_ID_CODE_HASH,
                hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                args: ckb_jsonrpc_types::JsonBytes::from_vec(cap1.as_bytes().to_vec()),
            };
            return serde_json::to_string_pretty(&type_id_script_json).unwrap();
        })
        .to_string();

    // replace_ref_type
    let regex = Regex::new(r"\{\{ ?ref_type (.+?) ?\}\}").unwrap();
    mock_tx = regex
        .replace_all(&mock_tx, |caps: &Captures| -> String {
            let cap1 = &caps[1];
            return type_id_dict[&cap1.to_string()].clone();
        })
        .to_string();

    let repr_mock_tx: ReprMockTransaction =
        from_json_str(&mock_tx).with_context(|| "in from_json_str(&mock_tx)")?;

    Ok(repr_mock_tx)
}

pub fn read_tx_template(file_name: &str) -> Result<ReprMockTransaction, anyhow::Error> {
    let mut repr_mock_tx = load_tx(file_name)?;

    if repr_mock_tx.tx.cell_deps.len() == 0 {
        repr_mock_tx.tx.cell_deps = repr_mock_tx
            .mock_info
            .cell_deps
            .iter()
            .map(|c| c.cell_dep.clone())
            .collect::<Vec<_>>();
    }
    if repr_mock_tx.tx.inputs.len() == 0 {
        repr_mock_tx.tx.inputs = repr_mock_tx
            .mock_info
            .inputs
            .iter()
            .map(|c| c.input.clone())
            .collect::<Vec<_>>();
    }
    Ok(repr_mock_tx)
}

pub fn create_script_from_cell_dep(
    tx: &ReprMockTransaction,
    index: usize,
    use_type: bool,
) -> Result<packed::Script, anyhow::Error> {
    assert!(index < tx.mock_info.cell_deps.len());
    let code_hash = if use_type {
        let cell_dep = &tx.mock_info.cell_deps[index];
        let script = cell_dep.output.type_.clone().unwrap();
        let script: packed::Script = script.into();
        hash(script.as_slice())
    } else {
        let data = tx.mock_info.cell_deps[index].data.as_bytes();
        hash(data)
    };
    let hash_type = if use_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data1
    };
    let script = packed::Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();
    Ok(script)
}

// Now, only support lock script
fn get_group(index: usize, repr_tx: &ReprMockTransaction) -> Vec<usize> {
    let lock = repr_tx.mock_info.inputs[index].output.lock.clone();
    let mut result = vec![];
    for (i, x) in repr_tx.mock_info.inputs.iter().enumerate() {
        if lock == x.output.lock {
            result.push(i);
        }
    }
    result
}

pub fn generate_sighash_all(
    tx: &ReprMockTransaction,
    index: usize,
) -> Result<[u8; 32], anyhow::Error> {
    let lock_indexs = get_group(index, &tx);
    if lock_indexs.is_empty() {
        panic!("not get lock index");
    }

    let witness = tx
        .tx
        .witnesses
        .get(lock_indexs[0])
        .unwrap()
        .as_bytes()
        .to_vec();
    let witness = packed::WitnessArgs::new_unchecked(Bytes::from(witness));

    let witness = packed::WitnessArgsBuilder::default()
        .lock({
            let data = witness.lock().to_opt().unwrap();

            let mut buf = Vec::new();
            buf.resize(data.len(), 0);
            Some(Bytes::from(buf)).pack()
        })
        .input_type(witness.input_type())
        .output_type(witness.output_type())
        .build();

    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];

    let mock_tx: MockTransaction = tx.clone().into();

    let tx_hash = mock_tx.tx.calc_tx_hash();
    blake2b.update(&tx_hash.raw_data());
    // println!("--hash: {:02X?}", &tx_hash.raw_data().to_vec());
    let witness_data = witness.as_bytes();
    blake2b.update(&(witness_data.len() as u64).to_le_bytes());
    blake2b.update(&witness_data);

    // group
    if lock_indexs.len() > 1 {
        for i in 1..lock_indexs.len() {
            let witness = mock_tx.tx.witnesses().get(lock_indexs[i]).unwrap();

            blake2b.update(&(witness.len() as u64).to_le_bytes());
            blake2b.update(&witness.raw_data());
        }
    }

    let normal_witness_len = std::cmp::max(tx.tx.inputs.len(), tx.tx.outputs.len());
    if tx.tx.inputs.len() < normal_witness_len {
        for i in tx.tx.inputs.len()..normal_witness_len {
            let witness = mock_tx.tx.witnesses().get(i).unwrap();

            blake2b.update(&(witness.len() as u64).to_le_bytes());
            blake2b.update(&witness.raw_data());
        }
    }

    blake2b.finalize(&mut message);
    Ok(message)
}

pub fn get_auth_code_hash() -> [u8; 32] {
    CellOutput::calc_data_hash(&AUTH_DL)
        .as_slice()
        .to_vec()
        .try_into()
        .unwrap()
}

pub fn get_auth_hash_type() -> u8 {
    AUTH_DL_HASH_TYPE.clone().into()
}

pub fn update_auth_code_hash(tx: &mut ReprMockTransaction) {
    let hash = get_auth_code_hash();
    for input in tx.mock_info.inputs.as_mut_slice() {
        let mut buf = input.output.lock.args.as_bytes().to_vec();
        buf.extend_from_slice(&hash);
        buf.extend_from_slice(&[get_auth_hash_type(), EntryCategoryType::Spawn as u8]);

        input.output.lock.args = JsonBytes::from_vec(buf);
    }
}

pub fn update_witness(tx: &mut ReprMockTransaction, witnesses_data: Vec<Vec<u8>>) {
    tx.tx.witnesses.clear();

    for witness in witnesses_data {
        tx.tx.witnesses.push(JsonBytes::from_bytes(
            WitnessArgsBuilder::default()
                .lock(Some(Bytes::from(witness.to_vec())).pack())
                .build()
                .as_bytes(),
        ));
    }
    // println!("{:02x?}", tx.tx.witnesses.get(0).unwrap().as_bytes());
}
