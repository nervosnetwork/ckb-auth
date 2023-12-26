use crate::{auth_script::run_auth_exec, utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use bitcoin::bech32::{self, FromBase32, ToBase32, Variant};
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

impl BlockChain for UnisatLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("unisat does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("unisat does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = operate_mathches
            .get_one::<String>("address")
            .expect("Get address from args");
        let (_hrp, address, _v) = bech32::decode(&address).expect("decode bech32");
        let address = Vec::<u8>::from_base32(&address[1..33]).unwrap();

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

        if address.len() < 20 {
            return Err(anyhow!("unisat address invalidate"));
        }
        if signature.len() != 65 {
            return Err(anyhow!("unisat signature size is not 65"));
        }
        signature[0] += 4;
        if message.len() != 32 {
            return Err(anyhow!("unisat message size is not 32"));
        }

        run_auth_exec(AuthAlgorithmIdType::Bitcoin, &address, &message, &signature)?;

        println!("Signature verification succeeded!");
        Ok(())
    }
}
