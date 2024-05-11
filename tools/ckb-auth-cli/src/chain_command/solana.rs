use crate::auth_script::run_auth_exec;

use crate::{utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};

pub struct SolanaLockArgs {}

impl BlockChainArgs for SolanaLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "solana"
    }
    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkey <PUBKEY> "The pubkey"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signed message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(SolanaLock {})
    }
}

pub struct SolanaLock {}

impl BlockChain for SolanaLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("solana does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("solana does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey = operate_mathches
            .get_one::<String>("pubkey")
            .expect("get verify address");

        let pubkey = bs58::decode(pubkey).into_vec().unwrap();

        let message = hex::decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get message"),
        )
        .expect("decode message");

        let signature = hex::decode(
            operate_mathches
                .get_one::<String>("signature")
                .expect("get verify signature"),
        )
        .expect("decode signature");

        let signature = [signature, pubkey.clone()].concat();

        let pubkey_hash = ckb_hash::blake2b_256(pubkey)[0..20].to_vec();

        run_auth_exec(
            AuthAlgorithmIdType::Solana,
            &pubkey_hash,
            &message,
            &signature,
        )?;

        println!("Signature verification succeeded!");

        Ok(())
    }
}
