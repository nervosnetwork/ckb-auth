use crate::{auth_script::run_auth_exec, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct TronLockArgs {}

impl BlockChainArgs for TronLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "tron"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The public key hash to verify against"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(TronLock {})
    }
}

pub struct TronLock {}

impl BlockChain for TronLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("Tron does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("Tron does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = bs58::decode(
            operate_mathches
                .get_one::<String>("address")
                .expect("get Tron address"),
        )
        .into_vec()
        .expect("address decode base58");

        if address.len() != 25 {
            return Err(anyhow!("Address len is not 20 ({})", address.len()));
        }

        if address[0] != 0x41 {
            return Err(anyhow!(
                "Tron address PREFIX not 0x41 (0x{:02x?})",
                address[0]
            ));
        }

        let checksum = {
            // check address
            use sha2::{Digest, Sha256};
            let mut hasher1 = Sha256::new();
            hasher1.update(&address[..21]);

            let mut hasher2 = Sha256::new();
            hasher2.update(hasher1.finalize());
            hasher2.finalize()
        };
        if address[21..] != checksum[..4] {
            return Err(anyhow!("Tron address checksum failed"));
        }

        let signature = decode({
            let d = operate_mathches
                .get_one::<String>("signature")
                .expect("get Tron signature");

            if d.starts_with("0x") {
                &d[2..]
            } else {
                &d
            }
        })
        .expect("decode signature");

        if signature.len() != 65 {
            return Err(anyhow!("signature len is not 65 ({})", signature.len()));
        }

        let message = decode({
            operate_mathches
                .get_one::<String>("message")
                .expect("get Tron signauthe message")
        })
        .expect("decode signature message data");

        if message.len() != 32 {
            return Err(anyhow!("message len is not 32 ({})", message.len()));
        }

        run_auth_exec(
            AuthAlgorithmIdType::Tron,
            &address[1..21],
            &message,
            &signature,
        )?;

        println!("Success");
        Ok(())
    }
}
