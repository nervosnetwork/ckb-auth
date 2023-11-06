use super::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_types::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct EthereumLockArgs {}

impl BlockChainArgs for EthereumLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "ethereum"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-m --message <MESSAGE> "Generate message binary for ethereum signing"))
            .arg(arg!(--msgfile <MESSAGE_FILE> "Output file"))
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <PUBKEYHASH> "The ethereum address"))
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
        Err(anyhow!("ethereum does not generate"))
    }

    fn generate(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let message = decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("Get signature message"),
        )
        .expect("Decode message");
        if message.len() != 32 {
            return Err(anyhow!("Signature length must be 32"));
        }

        let msgfile = operate_mathches
            .get_one::<String>("msgfile")
            .expect("Get signature message output file");

        let msgfile = std::path::PathBuf::from(msgfile);
        // if msgfile.exists() && msgfile.is_file() {
        //      std::fs::remove_file(&msgfile);
        // }

        std::fs::write(msgfile, message).expect("write message file");

        Ok(())
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let mut address = operate_mathches
            .get_one::<String>("address")
            .expect("Get address from args")
            .clone();
        if address.starts_with("0x") {
            address = address[2..].to_string();
        }
        let address = decode(&address).expect("decode address");

        let signature = decode(
            operate_mathches
                .get_one::<String>("signature")
                .expect("Get signature from args"),
        )
        .expect("decode ethereum signature");

        let message = decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("Get message from args"),
        )
        .expect("decode ethereum message");

        if address.len() != 20 {
            return Err(anyhow!("ethereum address invalidate"));
        }
        if signature.len() != 65 {
            return Err(anyhow!("ethereum signature size is not 65"));
        }
        if message.len() != 32 {
            return Err(anyhow!("ethereum message size is not 32"));
        }

        super::auth_script::run_auth_exec(
            AuthAlgorithmIdType::Ethereum,
            &address,
            &message,
            &signature,
        )?;

        println!("Ethereum Signature verification succeeded!");
        Ok(())
    }
}
