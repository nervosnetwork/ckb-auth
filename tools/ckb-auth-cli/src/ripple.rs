use super::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct RippleLockArgs {}

impl BlockChainArgs for RippleLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "ripple"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(--hex_to_address <HEX> "Hex to ripple address"))
            .arg(arg!(--address_to_hex <HEX> "Ripple address to hex"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(RippleLock {})
    }
}

pub struct RippleLock {}

impl BlockChain for RippleLock {
    fn parse(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = operate_mathches.get_one::<String>("hex_to_address");
        if address.is_some() {
            let add =
                Self::get_ripple_address(&decode(address.unwrap()).expect("Decode address hex"));

            println!("{}", add);
        }

        let address = operate_mathches.get_one::<String>("address_to_hex");
        if address.is_some() {
            let data = Self::address_to_hex(&address.unwrap());
            println!("{}", hex::encode(data));
        }

        Ok(())
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("ripple does not generate"))
    }

    fn verify(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("ripple does not verify"))
    }
}

impl RippleLock {
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

    fn base58_encode(d: &[u8]) -> String {
        let alpha =
            bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
                .expect("generate base58");

        bs58::encode(d).with_alphabet(&alpha).into_string()
    }

    fn get_ripple_address(data: &[u8]) -> String {
        let data = Self::hash_sha256(data);
        let data = Self::hash_ripemd160(&data);

        let mut data = {
            let mut buf = vec![0u8];
            buf.extend_from_slice(&data);
            buf
        };

        let checksum = Self::hash_sha256(&Self::hash_sha256(&data))[..4].to_vec();
        data.extend_from_slice(&checksum);

        // println!("get address, ripemd({}): {:?}", data.len(), &data);

        Self::base58_encode(&data)
    }

    fn address_to_hex(address: &str) -> Vec<u8> {
        let alpha =
            bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
                .expect("generate base58");

        let hex = bs58::decode(address)
            .with_alphabet(&alpha)
            .into_vec()
            .expect("");
        hex[1..21].to_vec()
    }
}
