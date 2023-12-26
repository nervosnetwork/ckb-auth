use crate::{
    auth_script::run_auth_exec,
    utils::{calculate_sha256, decode_string},
    BlockChain, BlockChainArgs,
};
use anyhow::{anyhow, Error};
use bitcoin::bech32::{self, FromBase32};
use ckb_auth_rs::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};

pub struct UnisatLockArgs {}

impl BlockChainArgs for UnisatLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "unisat"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <PUBKEYHASH> "The unisat address"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(UnisatLock {})
    }
}

pub struct UnisatLock {}

#[derive(PartialEq, Eq)]
enum UnisatLockAddressType {
    NativeSegwit,
    NestedSegwit,
    Taproot,
    Legacy,
}

impl BlockChain for UnisatLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("unisat does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("unisat does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let (address, addr_type) = Self::get_publickey_hash(
            operate_mathches
                .get_one::<String>("address")
                .expect("Get address from args"),
        );

        let mut signature = decode_string(
            operate_mathches
                .get_one::<String>("signature")
                .expect("Get signature from args"),
            "base64",
        )
        .expect("decode signature from base64 string");

        let message = hex::decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("Get message from args"),
        )
        .expect("decode message");

        if signature.len() != 65 {
            return Err(anyhow!("unisat signature size is not 65"));
        }
        if addr_type == UnisatLockAddressType::NestedSegwit {
            let recid = (signature[0] - 27) % 4;
            signature[0] = recid + 35;
        } else {
            let recid = (signature[0] - 27) % 4;
            signature[0] = recid + 31;
        }

        if message.len() != 32 {
            return Err(anyhow!("unisat message size is not 32"));
        }
        run_auth_exec(AuthAlgorithmIdType::Bitcoin, &address, &message, &signature)?;

        println!("Signature verification succeeded!");
        Ok(())
    }
}

impl UnisatLock {
    fn get_publickey_hash(address: &str) -> ([u8; 20], UnisatLockAddressType) {
        let r_address = Self::parse_address_with_native_segwit(address);
        if r_address.is_some() {
            return (r_address.unwrap(), UnisatLockAddressType::NativeSegwit);
        }

        let r_address = Self::parse_address_with_nested_segwit(address);
        if r_address.is_some() {
            return (r_address.unwrap(), UnisatLockAddressType::NestedSegwit);
        }

        let r_address = Self::_parse_address_with_taproot(address);
        if r_address.is_some() {
            return (r_address.unwrap(), UnisatLockAddressType::Taproot);
        }

        let r_address = Self::parse_address_with_legacy(address);
        if r_address.is_some() {
            return (r_address.unwrap(), UnisatLockAddressType::Legacy);
        }
        panic!("unknow parse address");
    }

    fn parse_address_with_native_segwit(address: &str) -> Option<[u8; 20]> {
        let r = bech32::decode(address);
        if r.is_err() {
            return None;
        }
        let (_hrp, address, _v) = r.unwrap();

        let address = Vec::<u8>::from_base32(&address[1..33]);
        if address.is_err() {
            return None;
        }
        let address = address.unwrap();
        if address.len() != 20 {
            return None;
        }

        Some(address.try_into().unwrap())
    }

    fn parse_address_with_nested_segwit(address: &str) -> Option<[u8; 20]> {
        let address = bs58::decode(address).into_vec();
        if address.is_err() {
            return None;
        }
        let address = address.unwrap();
        Self::check_sum(&address);

        Some(address[1..21].try_into().unwrap())
    }

    fn _parse_address_with_taproot(_address: &str) -> Option<[u8; 20]> {
        // Unsupport
        None
    }

    fn parse_address_with_legacy(address: &str) -> Option<[u8; 20]> {
        let address = bs58::decode(address).into_vec();
        if address.is_err() {
            return None;
        }
        let address = address.unwrap();

        if address.len() < 21 {
            return None;
        }

        Self::check_sum(&address);

        Some(address[1..21].try_into().unwrap())
    }

    fn check_sum(data: &[u8]) {
        let checksum = calculate_sha256(&calculate_sha256(&data[0..21]));
        assert_eq!(checksum[..4], data[21..]);
    }
}
