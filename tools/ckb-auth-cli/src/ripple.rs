use super::{
    utils::{calculate_ripemd160, calculate_sha256},
    BlockChain, BlockChainArgs,
};
use anyhow::{anyhow, Error};
use ckb_auth_types::AuthAlgorithmIdType;
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
            let add = hex_to_address(&decode(address.unwrap()).expect("Decode address hex"));

            println!("{}", add);
        }

        let address = operate_mathches.get_one::<String>("address_to_hex");
        if address.is_some() {
            let data = ripple_base58_decode(&address.unwrap());
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
            ripple_base58_decode(&data)[..20].to_vec()
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

        super::auth_script::run_auth_exec(
            AuthAlgorithmIdType::Ripple,
            &pubkey,
            &message,
            &signature,
        )?;

        println!("Signature verification succeeded");
        Ok(())
    }
}

fn ripple_base58_encode(d: &[u8]) -> String {
    let alpha = bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
        .expect("generate base58");

    bs58::encode(d).with_alphabet(&alpha).into_string()
}

fn ripple_base58_decode(s: &str) -> Vec<u8> {
    let alpha = bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
        .expect("generate base58");

    let hex = bs58::decode(s).with_alphabet(&alpha).into_vec().expect("");
    hex[1..21].to_vec()
}

fn hex_to_address(data: &[u8]) -> String {
    let data = calculate_sha256(data);
    let data: [u8; 20] = calculate_ripemd160(&data);

    let mut data = {
        let mut buf = vec![0u8];
        buf.extend_from_slice(&data);
        buf
    };

    let checksum = calculate_sha256(&calculate_sha256(&data))[..4].to_vec();
    data.extend_from_slice(&checksum);
    ripple_base58_encode(&data)
}
