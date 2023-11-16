use crate::{
    auth_script::run_auth_exec,
    utils::{calculate_sha256, decode_string},
};
use crate::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};

pub struct DogecoinLockArgs {}

impl BlockChainArgs for DogecoinLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "dogecoin"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <PUBKEYHASH> "The dogecoin address"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(DogecoinLock {})
    }
}

pub struct DogecoinLock {}

impl BlockChain for DogecoinLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("dogecoin does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("dogecoin does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = operate_mathches
            .get_one::<String>("address")
            .expect("Get address from args");
        let address = bs58::decode(&address).into_vec().expect("get base58");

        // https://github.com/dogecoin/dogecoin/blob/v1.14.6/src/chainparams.cpp#L167
        if address[0] != 30 {
            return Err(anyhow!("The first byte of address is not 30"));
        }

        let checksum = calculate_sha256(&calculate_sha256(&address[..21]));
        if checksum[..4] != address[21..] {
            return Err(anyhow!("Address Checksum failed,"));
        }

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
            return Err(anyhow!("dogecoin address invalidate"));
        }
        if signature.len() != 65 {
            return Err(anyhow!("dogecoin signature size is not 65"));
        }
        if message.len() != 32 {
            return Err(anyhow!("dogecoin message size is not 32"));
        }

        let pubkey_hash = &address[1..21];

        run_auth_exec(
            AuthAlgorithmIdType::Dogecoin,
            pubkey_hash,
            &message,
            &signature,
        )?;

        println!("Success");
        Ok(())
    }
}
