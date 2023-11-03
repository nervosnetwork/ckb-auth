use super::{BlockChain, BlockChainArgs};
use crate::utils::decode_string;
use anyhow::{anyhow, Error};
use ckb_auth_tests::AlgorithmType;
use clap::{arg, ArgMatches, Command};
// use ckb_auth_tests::AlgorithmType;
// use hex::decode;

pub struct BitcoinLockArgs {}

impl BlockChainArgs for BitcoinLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "bitcoin"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <PUBKEYHASH> "The bitcoin address"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(BitcoinLock {})
    }
}

pub struct BitcoinLock {}

impl BlockChain for BitcoinLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("bitcoin does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("bitcoin does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = bs58::decode(
            operate_mathches
                .get_one::<String>("address")
                .expect("Get address from args"),
        )
        .into_vec()
        .expect("get base58");

        let signature = decode_string(
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

        if address.len() < 21 {
            return Err(anyhow!("bitcoin address invalidate"));
        }
        if signature.len() != 65 {
            return Err(anyhow!("bitcoin signature size is not 65"));
        }
        if message.len() != 32 {
            return Err(anyhow!("bitcoin message size is not 32"));
        }

        let pubkey_hash = &address[1..21];

        super::auth_script::run_auth_exec(
            AlgorithmType::Bitcoin,
            pubkey_hash,
            &message,
            &signature,
        )?;

        println!("Signature verification succeeded!");
        Ok(())
    }
}
