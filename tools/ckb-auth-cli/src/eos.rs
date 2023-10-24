use super::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::{calculate_ripemd160, AlgorithmType};
use clap::{arg, ArgMatches, Command};
use hex::decode;
use sha2::{Digest, Sha256};

pub struct EosLockArgs {}

impl BlockChainArgs for EosLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "eos"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkey <PUBKEY> "The public key to verify against"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(
                arg!(-c --chain_id <CHAIN_ID> "The chain id that will be used to sign the transaction"),
            )
            .arg(arg!(-m --message <MESSAGE> "message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(EosLock {})
    }
}

pub struct EosLock {}

impl BlockChain for EosLock {
    fn parse(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("EOS does not parse"))
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("EOS does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey = operate_mathches
            .get_one::<String>("pubkey")
            .expect("get EOS public key");

        let signature = operate_mathches
            .get_one::<String>("signature")
            .expect("get EOS signature");

        let chain_id = decode(
            operate_mathches
                .get_one::<String>("chain_id")
                .expect("get chain id"),
        )
        .expect("decode chain id");

        let message = decode({
            let msg = operate_mathches
                .get_one::<String>("message")
                .expect("get EOS signauthe message");
            let pos = msg.find("#");
            if pos.is_some() {
                msg[0..pos.unwrap()].to_string()
            } else {
                msg.clone()
            }
        })
        .expect("decode signature message data");

        if chain_id.len() != 32 {
            return Err(anyhow!("chainid size not 32"));
        }

        if message.len() != 32 {
            return Err(anyhow!("message size not 32"));
        }

        let mut hasher = Sha256::new();
        hasher.update(&chain_id);
        hasher.update([0x00u8, 0x00u8, 0x00u8, 0x00u8]);
        hasher.update([0x00u8, 0x00u8]);
        hasher.update([0x00u8, 0x00u8, 0x00u8, 0x00u8]);
        hasher.update([0x00u8]);
        hasher.update([0x00u8]);
        hasher.update([0x00u8]);
        hasher.update([0x00u8]);
        hasher.update([0x00u8]);
        hasher.update([0x00u8]);

        let mut hasher2 = Sha256::new();
        hasher2.update([0x01u8]);
        hasher2.update([0x20u8]);
        hasher2.update(&message);

        hasher.update(hasher2.finalize());

        let message = hasher.finalize();

        if !pubkey.starts_with("EOS") {
            return Err(anyhow!("EOS public key illegal"));
        }
        let pubkey = bs58::decode(&pubkey[3..])
            .into_vec()
            .expect("Decode EOS public key by base58");

        let pubkey_checksum = calculate_ripemd160(&pubkey[..33]);
        if pubkey_checksum[..4] != pubkey[33..] {
            return Err(anyhow!("check public key failed"));
        }
        let pubkey = pubkey[..33].to_vec();

        if !signature.starts_with("SIG_K1_") {
            return Err(anyhow!("EOS No delimiter in string"));
        }

        let signature = bs58::decode(&signature[7..])
            .into_vec()
            .expect("Decode EOS signature key by base58");

        // Checksum
        let sign = signature[..65].to_vec();
        let check = signature[65..].to_vec();
        let sign_checksum = {
            let mut buf = sign.clone();
            buf.extend_from_slice("K1".as_bytes());
            calculate_ripemd160(&buf)
        };
        if sign_checksum[..4] != check {
            return Err(anyhow!("check signature failed"));
        }

        let pubkey_hash = ckb_hash::blake2b_256(pubkey);
        
        super::auth_script::run_auth_exec(AlgorithmType::Eos, &pubkey_hash[..20], &message, &sign)?;

        println!("Success");
        Ok(())
    }
}
