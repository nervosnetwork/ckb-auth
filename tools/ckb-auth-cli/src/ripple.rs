use super::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::{AlgorithmType, RippleAuth};
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct RippleLockArgs {}

impl BlockChainArgs for RippleLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "ripple"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(--hex_to_address <HEX> "Hex to ripple address"))
            .arg(arg!(--address_to_hex <HEX> "Ripple address to hex (Only the result after hash can be returned here)"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkey <PUBKEYHASH> "The pubkey hash to verify against, (Can be source hex or ripple address)"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
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
                RippleAuth::hex_to_address(&decode(address.unwrap()).expect("Decode address hex"));

            println!("{}", add);
        }

        let address = operate_mathches.get_one::<String>("address_to_hex");
        if address.is_some() {
            let data = RippleAuth::base58_decode(&address.unwrap());
            println!("{}", hex::encode(data));
        }

        Ok(())
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("ripple does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey = {
            let data = operate_mathches
                .get_one::<String>("pubkey")
                .expect("get ripple pubkey");
            RippleAuth::base58_decode(&data)[..20].to_vec()
        };

        let signature = {
            let data = decode(
                operate_mathches
                    .get_one::<String>("signature")
                    .expect("get ripple signature"),
            )
            .expect("parse ripple signature to hex");

            data
        };

        let message = decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get ripple message"),
        )
        .expect("parse ripple message");

        super::auth_script::run_auth_exec(AlgorithmType::Ripple, &pubkey, &message, &signature)?;

        println!("Signature verification succeeded");
        Ok(())
    }
}
