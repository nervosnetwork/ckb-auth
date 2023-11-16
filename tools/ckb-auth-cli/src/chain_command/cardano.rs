use crate::{auth_script::run_auth_exec, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct CardanoLockArgs {}

impl BlockChainArgs for CardanoLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "cardano"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-x --hex <HEX> "The public key hex"))
            .arg(arg!(--vkey <VKEY> "The pubkey file output by cardano-cli"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to verify against"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(--signature_file <SIGNATUREFILE> "The signature file output by cardano-cli"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(CardanoLock {})
    }
}

pub struct CardanoLock {}

impl BlockChain for CardanoLock {
    fn parse(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey = operate_mathches.get_one::<String>("hex");

        let pubkey = if pubkey.is_some() {
            decode(pubkey.unwrap()).expect("decode")
        } else {
            let pubkey_file = operate_mathches
                .get_one::<String>("vkey")
                .expect("get pubkey file");
            get_data_by_cddl(&pubkey_file)
        };

        let pubkey_hash = ckb_hash::blake2b_256(&pubkey[2..]);
        println!("{}", hex::encode(&pubkey_hash[0..20]));

        Ok(())
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("cardano does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = decode(
            operate_mathches
                .get_one::<String>("pubkeyhash")
                .expect("get cardano pubkey hash"),
        )
        .expect("decode pubkey hash");

        let signature = operate_mathches.get_one::<String>("signature");

        let signature = if signature.is_some() {
            decode(signature.unwrap()).expect("decode signature data")
        } else {
            let signature_file = operate_mathches
                .get_one::<String>("signature_file")
                .expect("get cardano signauthe file");
            get_data_by_cddl(&signature_file)
        };

        let message = decode({
            let msg = operate_mathches
                .get_one::<String>("message")
                .expect("get cardano signauthe message");
            let pos = msg.find("#");
            if pos.is_some() {
                msg[0..pos.unwrap()].to_string()
            } else {
                msg.clone()
            }
        })
        .expect("decode signature message data");

        cardano_verify(&pubkey_hash, &message, &signature)?;

        println!("Signature verification succeeded!");
        Ok(())
    }
}

pub fn cardano_verify(pubkey_hash: &[u8], message: &[u8], sign: &[u8]) -> Result<(), Error> {
    if pubkey_hash.len() != 20 {
        panic!("Cardano public key len is not 20 ({})", pubkey_hash.len());
    }

    if message.len() != 32 {
        panic!("Cardano message len is not 32 ({})", message.len());
    }

    run_auth_exec(AuthAlgorithmIdType::Cardano, pubkey_hash, message, sign)
}

fn get_data_by_cddl(path: &str) -> Vec<u8> {
    let data = std::fs::read(path).expect("read cddl file");
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();

    let mut raw_data = v.get("cborHex").unwrap().to_string();
    if raw_data.as_bytes()[0] == '\"' as u8 {
        raw_data = String::from(&raw_data[1..raw_data.len() - 1]);
    }

    decode(raw_data).expect("decode cddl hex")
}
