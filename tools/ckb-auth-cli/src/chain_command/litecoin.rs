use crate::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use auth_c_tests::{
    auth_builder, debug_printer, gen_tx_scripts_verifier, gen_tx_with_pub_key_hash,
    get_message_to_sign, set_signature, DummyDataLoader, TestConfig, MAX_CYCLES,
};
use ckb_auth_types::{AuthAlgorithmIdType, EntryCategoryType};
use clap::{arg, ArgMatches, Command};
use hex::{decode, encode};

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
      .arg(arg!(-e --encoding <ENCODING> "The encoding of the signature (may be hex or base64)"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(LitecoinLock {})
    }
}

pub struct LitecoinLock {}

impl BlockChain for LitecoinLock {
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
        // Note that we must set the official parameter of auth_builder to be true here.
        // The difference between official=true and official=false is that the later
        // convert the message to a form that can be signed directly with secp256k1.
        // This is not intended as the litecoin-cli will do the conversion internally,
        // and then sign the converted message. With official set to be true, we don't
        // do this kind of conversion in the auth data structure.
        let auth = auth_builder(AuthAlgorithmIdType::Litecoin, true).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let message_to_sign = get_message_to_sign(tx, &config);

        println!("{}", encode(message_to_sign.as_bytes()));
        Ok(())
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = get_pubkey_hash_by_args(operate_mathches)?;

        let signature = operate_mathches
            .get_one::<String>("signature")
            .expect("get verify signature");

        let encoding = operate_mathches
            .get_one::<String>("encoding")
            .expect("get verify encoding");

        let signature: Vec<u8> = decode_string(signature, encoding)?;

        let algorithm_type = AuthAlgorithmIdType::Litecoin;
        let run_type = EntryCategoryType::Spawn;
        let auth = auth_builder(algorithm_type, false).unwrap();
        let config = TestConfig::new(&auth, run_type, 1);
        let mut data_loader = DummyDataLoader::new();
        let tx = gen_tx_with_pub_key_hash(&mut data_loader, &config, pubkey_hash.to_vec());
        let signature = signature.into();
        let tx = set_signature(tx, &signature);
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
