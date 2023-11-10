use crate::{auth_script::run_auth_exec, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_types::AuthAlgorithmIdType;
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct LitecoinLockArgs {}

impl BlockChainArgs for LitecoinLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "litecoin"
    }
    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The address to parse"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd .arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash will be included in the message").required(false))
      .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message").required(false))
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd .arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash verify against"))
      .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to verify against"))
      .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
      .arg(arg!(-m --message <message> "The message to verify"))
      .arg(arg!(-e --encoding <ENCODING> "The encoding of the signature (may be hex or base64)"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(LitecoinLock {})
    }
}

pub struct LitecoinLock {}

impl BlockChain for LitecoinLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("litecoin does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("litecoin does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = get_pubkey_hash_by_args(operate_mathches)?;

        let signature = operate_mathches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let _message = hex::decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get message from args"),
        )
        .expect("decode message");

        let encoding = operate_mathches
            .get_one::<String>("encoding")
            .expect("get verify encoding");

        let signature: Vec<u8> = decode_string(signature, encoding)?;

        let message = hex::decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get message from args"),
        )
        .expect("decode message");
        run_auth_exec(
            AuthAlgorithmIdType::Litecoin,
            &pubkey_hash,
            &message,
            &signature,
        )?;

        println!("Signature verification succeeded!");

        Ok(())
    }
}

fn get_pubkey_hash_by_args(sub_matches: &ArgMatches) -> Result<[u8; 20], Error> {
    let pubkey_hash: Option<&String> = sub_matches.get_one::<String>("pubkeyhash");
    let pubkey_hash: [u8; 20] = if pubkey_hash.is_some() {
        decode(pubkey_hash.unwrap())
            .expect("decode pubkey")
            .try_into()
            .unwrap()
    } else {
        let address = sub_matches
            .get_one::<String>("address")
            .expect("get generate address");
        get_pub_key_hash_from_address(address)?
            .try_into()
            .expect("address buf to [u8; 20]")
    };

    Ok(pubkey_hash)
}

fn get_pub_key_hash_from_address(address: &str) -> Result<Vec<u8>, Error> {
    // base58 -d <<< mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2 | xxd -s 1 -l 20 -p
    let bytes = bs58::decode(&address).into_vec()?;
    Ok(bytes[1..21].into())
}

fn decode_string(s: &str, encoding: &str) -> Result<Vec<u8>, Error> {
    match encoding {
        "hex" => Ok(hex::decode(s)?),
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD.decode(s)?)
        }
        _ => Err(anyhow!("Unknown encoding {}", encoding)),
    }
}
