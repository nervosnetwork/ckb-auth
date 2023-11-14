use super::*;
use auth_c_tests::{
    auth_builder, gen_tx, gen_tx_scripts_verifier, sign_tx, DummyDataLoader, TestConfig,
};
use ckb_auth_types::{AuthAlgorithmIdType, EntryCategoryType};
use ckb_testtool::ckb_types::bytes::Bytes;

const MAX_CYCLES: u64 = 10_000_000;

#[test]
fn test_dll() {
    let auth = auth_builder(AuthAlgorithmIdType::Ckb, false).unwrap();
    let mut config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    let contract_bin: Bytes = Loader::default().load_binary("auth-rust-demo");
    config.auth_bin = Some(contract_bin);
    config.script_hash_type = Some(ckb_testtool::ckb_types::core::ScriptHashType::Data1.into());

    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);

    let verifier = gen_tx_scripts_verifier(tx, data_loader);
    verifier.verify(MAX_CYCLES).expect("pass verification");
}

#[test]
fn test_spawn() {
    let auth = auth_builder(AuthAlgorithmIdType::Ckb, false).unwrap();
    let mut config = TestConfig::new(&auth, EntryCategoryType::Spawn, 1);
    let contract_bin: Bytes = Loader::default().load_binary("auth-rust-demo");
    config.auth_bin = Some(contract_bin);
    config.script_hash_type = Some(ckb_testtool::ckb_types::core::ScriptHashType::Data1.into());

    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);

    let verifier = gen_tx_scripts_verifier(tx, data_loader);
    verifier.verify(MAX_CYCLES).expect("pass verification");
}
