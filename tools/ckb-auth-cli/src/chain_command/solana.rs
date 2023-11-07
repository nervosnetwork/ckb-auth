use crate::utils::encode_to_string;

use crate::{utils::decode_string, BlockChain, BlockChainArgs};
use anyhow::Error;
use ckb_auth_tests::{
    auth_builder, debug_printer, gen_tx_scripts_verifier, gen_tx_with_pub_key_hash,
    get_message_to_sign, set_signature, DummyDataLoader, SolanaAuth, TestConfig, MAX_CYCLES,
};
use ckb_auth_types::{AuthAlgorithmIdType, EntryCategoryType};
use ckb_types::bytes::{BufMut, BytesMut};
use clap::{arg, ArgMatches, Command};
use hex::{decode, encode};

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
            .arg(arg!(-m --message <MESSAGE> "The message output by solana command"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(SolanaLock {})
    }
}

pub struct SolanaLock {}

impl BlockChain for SolanaLock {
    fn parse(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = operate_mathches
            .get_one::<String>("address")
            .expect("get parse address");

        let pubkey_hash: [u8; 20] = get_pub_key_hash_from_address(address)?
            .try_into()
            .expect("address buf to [u8; 20]");

        println!("{}", encode(pubkey_hash));

        Ok(())
    }

    fn generate(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = get_pubkey_hash_by_args(operate_mathches)?;

        let run_type = EntryCategoryType::Spawn;
        let auth = auth_builder(AuthAlgorithmIdType::Solana, true).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let message_to_sign = get_message_to_sign(tx, &config);

        let encoding = operate_mathches
            .get_one::<String>("encoding")
            .map(String::as_str)
            .unwrap_or("base58");
        println!(
            "{}",
            encode_to_string(&message_to_sign, encoding).expect("Encode")
        );
        Ok(())
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let address = operate_mathches
            .get_one::<String>("address")
            .expect("get verify address");

        let signature = operate_mathches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let message = operate_mathches
            .get_one::<String>("message")
            .expect("get verify message");

        let pubkey_hash: [u8; 20] = get_pub_key_hash_from_address(address)?
            .try_into()
            .expect("address buf to [u8; 20]");

        let mut data = BytesMut::new();
        data.put(decode_string(&signature, "base58")?.as_slice());
        data.put(decode_string(&address, "base58")?.as_slice());
        data.put(decode_string(&message, "base64")?.as_slice());
        let signature = data.freeze();

        let algorithm_type = AuthAlgorithmIdType::Solana;
        let run_type = EntryCategoryType::Spawn;
        let auth = auth_builder(algorithm_type, false).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let wrapped_signature =
            SolanaAuth::wrap_signature(&signature).expect("signature size not too large");
        let tx = set_signature(tx, &wrapped_signature.to_vec().into());
        let mut verifier = gen_tx_scripts_verifier(tx, data_loader);

        verifier.set_debug_printer(debug_printer);
        let result = verifier.verify(MAX_CYCLES);
        if result.is_err() {
            dbg!(result.unwrap_err());
            panic!("Verification failed");
        }
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
    let hash = ckb_hash::blake2b_256(bs58::decode(&address).into_vec()?);
    Ok(hash[0..20].into())
}
