#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_auth_rs::EntryCategoryType;
use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{hardfork::HardForks, EpochNumberWithFraction, HeaderView},
    prelude::*,
    H256,
};
use log::{Level, LevelFilter, Metadata, Record};
use rand::{thread_rng, Rng};
use sha3::{digest::generic_array::typenum::private::IsEqualPrivate, Digest, Keccak256};
use std::sync::Arc;

use hex_literal::hex;

use crate::{
    assert_script_error, auth_builder, auth_program::use_libecc, build_resolved_tx, debug_printer,
    gen_args, gen_tx, gen_tx_scripts_verifier, gen_tx_with_grouped_args, sign_tx, Auth,
    AuthAlgorithmIdType, AuthErrorCodeType, BitcoinAuth, BitcoinSignVType, CKbAuth,
    CkbMultisigAuth, DogecoinAuth, DummyDataLoader, EosAuth, EthereumAuth, LitecoinAuth,
    SchnorrAuth, TestConfig, TronAuth, MAX_CYCLES,
};

fn verify_unit(config: &TestConfig) -> Result<u64, ckb_error::Error> {
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);

    let verifier = gen_tx_scripts_verifier(tx, data_loader);
    verifier.verify(MAX_CYCLES)
}

fn assert_result_ok(res: Result<u64, ckb_error::Error>, des: &str) {
    assert!(
        res.is_ok(),
        "pass {} verification, des: {}",
        des,
        res.unwrap_err().to_string()
    );
}

fn assert_result_error(res: Result<u64, ckb_error::Error>, des: &str, err_codes: &[i32]) {
    assert!(
        res.is_err(),
        "pass failed {} verification, des: run ok",
        des
    );
    let err_str = res.unwrap_err().to_string();
    let mut is_assert = false;
    for err_code in err_codes {
        if err_str.contains(format!("error code {}", err_code).as_str()) {
            is_assert = true;
            break;
        }
    }

    if !is_assert {
        assert!(false, "pass {} verification, des: {}", des, err_str);
    }
}

fn unit_test_success(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 1);
    assert_result_ok(verify_unit(&config), "");
}

fn unit_test_multiple_args(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 5);

    assert_result_ok(verify_unit(&config), "multiple args");
}

fn unit_test_multiple_group(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let mut data_loader = DummyDataLoader::new();

    let config = TestConfig::new(auth, run_type, 1);

    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![
            (gen_args(&config), 1),
            (gen_args(&config), 1),
            (gen_args(&config), 1),
        ],
        &config,
        &mut rng,
    );

    let _tx = sign_tx(tx, &config);
    // let _verifier = gen_tx_scripts_verifier(tx, data_loader);

    assert_result_ok(verify_unit(&config), "multiple group");
}

fn unit_test_faileds(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    // public key
    {
        let mut config = TestConfig::new(auth, run_type.clone(), 1);
        config.incorrect_pubkey = true;

        assert_result_error(
            verify_unit(&config),
            "public key",
            &[AuthErrorCodeType::Mismatched as i32],
        );
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign_size = crate::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = crate::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }
}

fn unit_test_common_with_auth(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type.clone());
    unit_test_multiple_args(auth, run_type.clone());
    unit_test_multiple_group(auth, run_type.clone());

    unit_test_faileds(auth, run_type.clone());
}

fn unit_test_common_with_runtype(
    algorithm_type: AuthAlgorithmIdType,
    run_type: EntryCategoryType,
    using_official_client: bool,
) {
    let auth = auth_builder(algorithm_type, using_official_client).unwrap();
    unit_test_common_with_auth(&auth, run_type);
}

fn unit_test_common_all_runtype(auth: &Box<dyn Auth>) {
    unit_test_common_with_auth(auth, EntryCategoryType::Exec);
    unit_test_common_with_auth(auth, EntryCategoryType::DynamicLinking);
    unit_test_common_with_auth(auth, EntryCategoryType::Spawn);
}

fn unit_test_common(algorithm_type: AuthAlgorithmIdType) {
    for t in [
        EntryCategoryType::Exec,
        EntryCategoryType::DynamicLinking,
        EntryCategoryType::Spawn,
    ] {
        unit_test_common_with_runtype(algorithm_type.clone(), t, false);
    }
}

fn unit_test_common_official(algorithm_type: AuthAlgorithmIdType) {
    for t in [
        EntryCategoryType::Exec,
        EntryCategoryType::DynamicLinking,
        EntryCategoryType::Spawn,
    ] {
        unit_test_common_with_runtype(algorithm_type.clone(), t, true);
    }
}

#[test]
fn ckb_verify() {
    unit_test_common(AuthAlgorithmIdType::Ckb);
}

#[test]
fn ethereum_verify() {
    unit_test_common(AuthAlgorithmIdType::Ethereum);
}

#[test]
fn eos_verify() {
    unit_test_common(AuthAlgorithmIdType::Eos);
}

#[test]
fn tron_verify() {
    unit_test_common(AuthAlgorithmIdType::Tron);
}

#[test]
fn bitcoin_verify() {
    unit_test_common(AuthAlgorithmIdType::Bitcoin);
}

#[test]
fn bitcoin_v_type_verify() {
    let mut auth = crate::BitcoinAuth::new();
    auth.v_type = BitcoinSignVType::P2PKHUncompressed;
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = crate::BitcoinAuth::new();
    auth.v_type = BitcoinSignVType::P2PKHCompressed;
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = crate::BitcoinAuth::new();
    auth.v_type = BitcoinSignVType::SegwitP2SH;
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = crate::BitcoinAuth::new();
    auth.v_type = BitcoinSignVType::SegwitBech32;
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));
}

#[test]
fn bitcoin_pubkey_recid_verify() {
    #[derive(Clone)]
    pub struct BitcoinFailedAuth(BitcoinAuth);
    impl Auth for BitcoinFailedAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            self.0.get_pub_key_hash()
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            BitcoinAuth::btc_convert_message(message)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            let priv_key = Privkey::from_slice(&self.0.secret_key);

            let sign = priv_key.sign_recoverable(&msg).expect("sign").serialize();
            assert_eq!(sign.len(), 65);

            let mut rng = rand::thread_rng();
            let mut recid: u8 = rng.gen_range(0, 4);
            while recid == sign[64] && recid < 31 {
                recid = rng.gen_range(0, 4);
            }
            let mut mark: u8 = sign[64];
            if self.0.v_type == BitcoinSignVType::P2PKHCompressed {
                mark = mark | 4;
            }
            let mut ret = BytesMut::with_capacity(65);
            ret.put_u8(mark);
            ret.put(&sign[0..64]);
            Bytes::from(ret)
        }
    }

    let auth: Box<dyn Auth> = Box::new(BitcoinFailedAuth {
        0: BitcoinAuth::default(),
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[
            AuthErrorCodeType::InvalidArg as i32,
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::ErrorWrongState as i32,
        ],
    );
}

#[test]
fn dogecoin_verify() {
    unit_test_common(AuthAlgorithmIdType::Dogecoin);
}

#[test]
fn litecoin_verify() {
    unit_test_common(AuthAlgorithmIdType::Litecoin);
}

#[test]
fn litecoin_verify_official() {
    // We need litecoin binaries to test signing.
    if which::which("litecoin-cli").is_err() {
        return;
    }
    unit_test_common_official(AuthAlgorithmIdType::Litecoin);
}

#[test]
fn monero_verify() {
    unit_test_common(AuthAlgorithmIdType::Monero);
}

#[test]
fn solana_verify() {
    unit_test_common(AuthAlgorithmIdType::Solana);
}

#[test]
fn ripple_verify() {
    unit_test_common(AuthAlgorithmIdType::Ripple);
}

#[test]
fn secp256r1_verify() {
    use_libecc();
    unit_test_common(AuthAlgorithmIdType::Secp256r1);
}

#[test]
fn convert_eth_error() {
    #[derive(Clone)]
    struct EthConverFaileAuth(EthereumAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Ethereum as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 28] = b"\x19Ethereum Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            let ret = H256::from_slice(r.as_slice()).expect("convert_keccak256_hash");
            ret
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth: Box<dyn Auth> = Box::new(EthConverFaileAuth {
        0: EthereumAuth {
            privkey,
            pubkey,
            chain_id: None,
            recid: None,
            recid_add_27: false,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver eth",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_tron_error() {
    #[derive(Clone)]
    struct TronConverFaileAuth(TronAuth);
    impl Auth for TronConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Tron as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 24] = b"\x19TRON Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            H256::from_slice(r.as_slice()).expect("convert_keccak256_hash")
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);
    let auth: Box<dyn Auth> = Box::new(TronConverFaileAuth {
        0: TronAuth { privkey, pubkey },
    });
    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver tron",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_btc_error() {
    #[derive(Clone)]
    struct BtcConverFaileAuth(BitcoinAuth);
    impl Auth for BtcConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            self.0.get_pub_key_hash()
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = crate::calculate_sha256(&temp2);
            let msg = crate::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.secret_key, self.0.v_type)
        }
    }

    let auth: Box<dyn Auth> = Box::new(BtcConverFaileAuth {
        0: BitcoinAuth::default(),
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn convert_doge_error() {
    #[derive(Clone)]
    struct DogeConverFaileAuth(DogecoinAuth);
    impl Auth for DogeConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            self.0.get_pub_key_hash()
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = crate::calculate_sha256(&temp2);
            let msg = crate::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0 .0.secret_key, self.0 .0.v_type)
        }
    }

    let auth: Box<dyn Auth> = Box::new(DogeConverFaileAuth {
        0: DogecoinAuth {
            0: BitcoinAuth::default(),
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver doge",
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn convert_lite_error() {
    #[derive(Clone)]
    struct LiteConverFaileAuth(LitecoinAuth);
    impl Auth for LiteConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            self.0.get_pub_key_hash()
        }
        fn get_algorithm_type(&self) -> u8 {
            AuthAlgorithmIdType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = crate::calculate_sha256(&temp2);
            let msg = crate::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            self.0.sign(msg)
        }
    }

    let auth: Box<dyn Auth> = Box::new(LiteConverFaileAuth {
        0: LitecoinAuth {
            official: false,
            btc: BitcoinAuth::default(),
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver lite",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[derive(Clone)]
pub struct CkbMultisigFailedAuth(CkbMultisigAuth);
impl Auth for CkbMultisigFailedAuth {
    fn get_pub_key_hash(&self) -> Vec<u8> {
        self.0.hash.clone()
    }
    fn get_algorithm_type(&self) -> u8 {
        AuthAlgorithmIdType::CkbMultisig as u8
    }
    fn sign(&self, msg: &H256) -> Bytes {
        let sign_data = self.0.multickb_sign(msg);
        let mut buf = BytesMut::with_capacity(sign_data.len() + 10);
        buf.put(sign_data);
        buf.put(Bytes::from([0; 10].to_vec()));
        buf.freeze()
    }
    fn get_sign_size(&self) -> usize {
        self.0.get_mulktisig_size()
    }
}

fn unit_test_ckbmultisig(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type.clone());
    unit_test_multiple_args(auth, run_type.clone());
    unit_test_multiple_group(auth, run_type.clone());

    // public key
    {
        let mut config = TestConfig::new(auth, run_type.clone(), 1);
        config.incorrect_pubkey = true;

        assert_result_error(verify_unit(&config), "public key", &[-51]);
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign_size = crate::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type.clone(), 1);
        config.incorrect_sign_size = crate::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 3, 1);
        let config = TestConfig::new(&auth, run_type.clone(), 1);
        assert_result_error(verify_unit(&config), "cnt failed", &[-43]);
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 4);
        let config = TestConfig::new(&auth, run_type.clone(), 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-44]);

        // #define ERROR_INVALID_REQUIRE_FIRST_N -44
    }

    {
        let auth: Box<dyn Auth> = Box::new(CkbMultisigFailedAuth {
            0: {
                let pubkeys_cnt = 2;
                let threshold = 2;
                let require_first_n = 0;
                let (pubkey_data, privkeys) =
                    CkbMultisigAuth::generator_key(pubkeys_cnt, threshold, require_first_n);
                let hash = ckb_hash::blake2b_256(&pubkey_data);
                CkbMultisigAuth {
                    pubkeys_cnt,
                    threshold,
                    pubkey_data,
                    privkeys,
                    hash: hash[0..20].to_vec(),
                }
            },
        });
        let config = TestConfig::new(&auth, run_type.clone(), 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-22]);
        // #define ERROR_WITNESS_SIZE -22
    }
}

#[test]
fn ckbmultisig_verify() {
    let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 1);
    unit_test_ckbmultisig(&auth, EntryCategoryType::Exec);
    unit_test_ckbmultisig(&auth, EntryCategoryType::DynamicLinking);
    unit_test_ckbmultisig(&auth, EntryCategoryType::Spawn);
}

#[test]
fn ckbmultisig_verify_sing_size_failed() {}

#[test]
fn schnorr_verify() {
    unit_test_common(AuthAlgorithmIdType::Schnorr);
}

#[test]
fn abnormal_algorithm_type() {
    #[derive(Clone)]
    struct AbnormalAuth {}
    impl crate::Auth for AbnormalAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            [0; 20].to_vec()
        }
        fn get_algorithm_type(&self) -> u8 {
            32
        }
        fn sign(&self, _msg: &H256) -> Bytes {
            Bytes::from([0; 85].to_vec())
        }
    }

    let auth: Box<dyn Auth> = Box::new(AbnormalAuth {});
    {
        let config = TestConfig::new(&auth, EntryCategoryType::Exec, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
    {
        let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
    {
        let config = TestConfig::new(&auth, EntryCategoryType::Spawn, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
}

#[test]
fn ethereum_recid() {
    let mut auth = EthereumAuth::new();
    auth.chain_id = Some(20);
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = EthereumAuth::new();
    auth.chain_id = Some(31);
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = EthereumAuth::new();
    auth.recid_add_27 = true;
    unit_test_common_all_runtype(&(auth as Box<dyn Auth>));

    let mut auth = EthereumAuth::new();
    auth.recid = Some(3);
    let config = TestConfig::new(&(auth as Box<dyn Auth>), EntryCategoryType::Spawn, 1);
    assert_result_error(
        verify_unit(&config),
        "recid(3) check ",
        &[AuthErrorCodeType::InvalidArg as i32],
    );

    let mut auth = EthereumAuth::new();
    auth.recid = Some(26);
    let config = TestConfig::new(&(auth as Box<dyn Auth>), EntryCategoryType::Spawn, 1);
    assert_result_error(
        verify_unit(&config),
        "recid(26) check",
        &[AuthErrorCodeType::InvalidArg as i32],
    );

    let mut auth = EthereumAuth::new();
    auth.recid = Some(34);
    let config = TestConfig::new(&(auth as Box<dyn Auth>), EntryCategoryType::Spawn, 1);
    assert_result_error(
        verify_unit(&config),
        "recid(34) check",
        &[AuthErrorCodeType::InvalidArg as i32],
    );
}
