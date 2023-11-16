extern crate monero as monero_rs;

use crate::{auth_script::run_auth_exec, utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AuthAlgorithmIdType;

use ckb_types::bytes::{BufMut, BytesMut};
use clap::{arg, ArgMatches, Command};
use core::str::FromStr;

use monero_rs::Address;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MoneroMode {
    Spend,
    View,
}

impl FromStr for MoneroMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "spend" => Ok(MoneroMode::Spend),
            "view" => Err(anyhow!(
                "View mode is currently not supported, use spend instead"
            )),
            _ => Err(anyhow!("Only spend mode is supported")),
        }
    }
}

pub fn get_pub_key_info(
    public_spend: &monero::PublicKey,
    public_view: &monero::PublicKey,
    use_spend_key: bool,
) -> Vec<u8> {
    let mut buff = BytesMut::with_capacity(1 + 32 * 2);
    let mode: u8 = if use_spend_key { 0 } else { 1 };
    buff.put_u8(mode);
    buff.put(public_spend.as_bytes());
    buff.put(public_view.as_bytes());
    buff.freeze().into()
}

pub struct MoneroLockArgs {}

impl BlockChainArgs for MoneroLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "monero"
    }
    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The address to parse"))
            .arg(
                arg!(-m --mode <MODE> "The mode to sign transactions (currently the only valid value is spend)")
                    .required(false),
            )
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message"))
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash verify against"))
            .arg(
                arg!(--mode <MODE> "The mode to sign transactions (currently the only valid value is spend)")
                    .required(false),
            )
            .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The message to verify"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(MoneroLock {})
    }
}

pub struct MoneroLock {}

impl BlockChain for MoneroLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("litecoin does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("litecoin does not generate"))
    }

    fn verify(&self, operate_matches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = operate_matches
            .get_one::<String>("pubkeyhash")
            .expect("Must get pubkeyhash");
        let pubkey_hash: [u8; 20] = decode_string(pubkey_hash, "hex")
            .expect("decode pubkey")
            .try_into()
            .unwrap();

        let signature = operate_matches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let signature: Vec<u8> = decode_string(signature, "base58_monero")?;

        let address = operate_matches
            .get_one::<String>("address")
            .expect("get parse address");

        let address: Address = FromStr::from_str(address)?;

        let mode = operate_matches
            .get_one::<String>("mode")
            .map(String::as_str)
            .unwrap_or("spend");

        let mode: MoneroMode = FromStr::from_str(mode)?;
        let pub_key_info = get_pub_key_info(
            &address.public_spend,
            &address.public_view,
            mode == MoneroMode::Spend,
        );
        let mut data = BytesMut::with_capacity(signature.len() + pub_key_info.len());
        data.put(signature.as_slice());
        data.put(pub_key_info.as_slice());
        let signature = data.freeze();

        let message = hex::decode(
            operate_matches
                .get_one::<String>("message")
                .expect("get message from args"),
        )
        .expect("decode message");

        run_auth_exec(
            AuthAlgorithmIdType::Monero,
            &pubkey_hash,
            &message,
            &signature,
        )?;

        println!("Signature verification succeeded!");

        Ok(())
    }
}
