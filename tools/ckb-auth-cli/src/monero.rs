extern crate monero as monero_rs;

use super::{utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_tests::{
    auth_builder, build_resolved_tx, debug_printer, gen_tx_scripts_verifier,
    gen_tx_with_pub_key_hash, get_message_to_sign, set_signature, DummyDataLoader, MoneroAuth,
    TestConfig, MAX_CYCLES,
};
use ckb_auth_types::{AuthAlgorithmIdType, EntryCategoryType};

use ckb_types::bytes::{BufMut, BytesMut};
use clap::{arg, ArgMatches, Command};
use core::str::FromStr;
use hex::encode;
use monero_rs::Address;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MoneroMode {
    Spend,
    View,
}

impl FromStr for MoneroMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "spend" => Ok(MoneroMode::Spend),
            "view" => Err(anyhow!(
                "View mode is currently not supported, use spend instead"
            )),
            _ => Err(anyhow!("Only spend mode is supported")),
        }
    }
}

pub struct MoneroLockArgs {}

impl BlockChainArgs for MoneroLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "monero"
    }
    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The address to parse"))
            .arg(
                arg!(-m --mode <MODE> "The mode to sign transactions (currently the only valid value is spend)")
                    .required(false),
            )
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message"))
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash verify against"))
            .arg(
                arg!(-m --mode <MODE> "The mode to sign transactions (currently the only valid value is spend)")
                    .required(false),
            )
            .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(MoneroLock {})
    }
}

pub struct MoneroLock {}

impl BlockChain for MoneroLock {
    fn parse(&self, operate_matches: &ArgMatches) -> Result<(), Error> {
        let address = operate_matches
            .get_one::<String>("address")
            .expect("get parse address");

        let address: Address = FromStr::from_str(address)?;

        let mode = operate_matches
            .get_one::<String>("mode")
            .map(String::as_str)
            .unwrap_or("spend");

        let mode: MoneroMode = FromStr::from_str(mode)?;
        let pubkey_hash = MoneroAuth::get_pub_key_hash(
            &address.public_spend,
            &address.public_view,
            mode == MoneroMode::Spend,
        );

        println!("{}", encode(pubkey_hash));

        Ok(())
    }

    fn generate(&self, operate_matches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = operate_matches
            .get_one::<String>("pubkeyhash")
            .expect("Must get pubkeyhash");
        let pubkey_hash: [u8; 20] = decode_string(pubkey_hash, "hex")
            .expect("decode pubkey")
            .try_into()
            .unwrap();

        let run_type = EntryCategoryType::Spawn;
        // Note that we must set the official parameter of auth_builder to be true here.
        // The difference between official=true and official=false is that the later
        // convert the message to a form that can be signed directly with secp256k1.
        // This is not intended as the monero-cli will do the conversion internally,
        // and then sign the converted message. With official set to be true, we don't
        // do this kind of conversion in the auth data structure.
        let auth = auth_builder(AuthAlgorithmIdType::Monero, true).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let message_to_sign = get_message_to_sign(tx, &config);

        println!("{}", encode(message_to_sign.as_bytes()));
        Ok(())
    }

    fn verify(&self, operate_matches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = operate_matches
            .get_one::<String>("pubkeyhash")
            .expect("Must get pubkeyhash");
        let pubkey_hash: [u8; 20] = decode_string(pubkey_hash, "hex")
            .expect("decode pubkey")
            .try_into()
            .unwrap();

        let signature = operate_matches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let signature: Vec<u8> = decode_string(signature, "base58_monero")?;

        let address = operate_matches
            .get_one::<String>("address")
            .expect("get parse address");

        let address: Address = FromStr::from_str(address)?;

        let mode = operate_matches
            .get_one::<String>("mode")
            .map(String::as_str)
            .unwrap_or("spend");

        let mode: MoneroMode = FromStr::from_str(mode)?;
        let pub_key_info = MoneroAuth::get_pub_key_info(
            &address.public_spend,
            &address.public_view,
            mode == MoneroMode::Spend,
        );
        let mut data = BytesMut::with_capacity(signature.len() + pub_key_info.len());
        data.put(signature.as_slice());
        data.put(pub_key_info.as_slice());
        let signature = data.freeze();

        let algorithm_type = AuthAlgorithmIdType::Monero;
        let run_type = EntryCategoryType::Spawn;
        let auth = auth_builder(algorithm_type, false).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let signature = signature;
        let tx = set_signature(tx, &signature);
        let _resolved_tx = build_resolved_tx(&data_loader, &tx);

        let mut verifier = gen_tx_scripts_verifier(tx, data_loader);
        verifier.set_debug_printer(debug_printer);
        let result = verifier.verify(MAX_CYCLES);
        if result.is_err() {
            dbg!(result.unwrap_err());
            panic!("Verification failed");
        }
        println!("Signature verification succeeded!");

        Ok(())
    }
}
