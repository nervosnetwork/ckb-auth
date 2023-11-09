use crate::auth_script::run_auth_exec;

use crate::{utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use auth_c_tests::SolanaAuth;
use ckb_auth_types::AuthAlgorithmIdType;
use ckb_types::bytes::{BufMut, BytesMut};
use clap::{arg, ArgMatches, Command};

pub struct SolanaLockArgs {}

impl BlockChainArgs for SolanaLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "solana"
    }
    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The address to parse"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash will be included in the message").required(false))
      .arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to include in the message").required(false))
      .arg(arg!(-e --encoding <ENCODING> "The encoding of the signature (may be hex or base64)"))
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-a --address <ADDRESS> "The pubkey address whose hash verify against"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(--solanamessage <MESSAGE> "The message output by solana command"))
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
        let address = operate_mathches
            .get_one::<String>("address")
            .expect("get verify address");

        let signature = operate_mathches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let solana_message = operate_mathches
            .get_one::<String>("solanamessage")
            .expect("get solanamessage");

        let pubkey_hash: [u8; 20] = get_pub_key_hash_from_address(address)?
            .try_into()
            .expect("address buf to [u8; 20]");

        let mut data = Vec::new();
        data.extend_from_slice(decode_string(signature, "base58")?.as_slice());
        data.extend_from_slice(decode_string(address, "base58")?.as_slice());
        data.extend_from_slice(decode_string(solana_message, "base64")?.as_slice());
        // This is the fixed size of a solana "signature"
        // TODO: we shouldn't hard code 512 here.
        let mut signature = [0u8; 512].to_vec();
        let len = u16::try_from(data.len()).unwrap();
        signature[..2].copy_from_slice(&len.to_le_bytes());
        signature[2..(data.len() + 2)].copy_from_slice(&data);

        let message = hex::decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get message from args"),
        )
        .expect("decode message");

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

fn get_pub_key_hash_from_address(address: &str) -> Result<Vec<u8>, Error> {
    let hash = ckb_hash::blake2b_256(bs58::decode(&address).into_vec()?);
    Ok(hash[0..20].into())
}
