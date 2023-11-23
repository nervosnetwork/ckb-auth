use anyhow::{anyhow, Error};
use ckb_auth_cli::{
    chain_command::{
        BitcoinLockArgs, CardanoLockArgs, DogecoinLockArgs, EosLockArgs, EthereumLockArgs,
        LitecoinLockArgs, MoneroLockArgs, RippleLockArgs, SolanaLockArgs, TronLockArgs,
    },
    BlockChainArgs,
};
use clap::Command;

fn cli(block_chain_args: &[Box<dyn BlockChainArgs>]) -> Command {
    let mut cmd = Command::new("ckb-auth-cli")
        .about("A command-line interface for CKB-Auth")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true);

    for block_chain in block_chain_args {
        cmd = cmd.subcommand(
            Command::new(block_chain.block_chain_name())
                .arg_required_else_help(true)
                .subcommand(
                    block_chain.reg_parse_args(
                        Command::new("parse")
                            .about("Parse an address and obtain the pubkey hash")
                            .arg_required_else_help(true),
                    ),
                )
                .subcommand(
                    block_chain.reg_generate_args(
                        Command::new("generate")
                            .about("Parse an address and obtain the pubkey hash")
                            .arg_required_else_help(true),
                    ),
                )
                .subcommand(
                    block_chain.reg_verify_args(
                        Command::new("verify")
                            .about("Verify a signature")
                            .arg_required_else_help(true),
                    ),
                ),
        );
    }

    cmd
}

// fn print_pubkey_hash(pubkey: &[u8]) {
//     let pubkey_hash = ckb_hash::blake2b_256(pubkey);
//     println!("pubkey hash: {}", hex::encode(&pubkey_hash[0..20]));
// }

fn main() -> Result<(), Error> {
    let block_chain_args = [
        Box::new(LitecoinLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(CardanoLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(MoneroLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(SolanaLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(RippleLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(BitcoinLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(EthereumLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(EosLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(TronLockArgs {}) as Box<dyn BlockChainArgs>,
        Box::new(DogecoinLockArgs {}) as Box<dyn BlockChainArgs>,
    ];

    let matches = cli(block_chain_args.as_slice()).get_matches();

    let (block_chain_name, sub_matches) = matches.subcommand().expect("get subcommand");

    let subcommand = block_chain_args
        .iter()
        .find(|f| f.block_chain_name() == block_chain_name)
        .expect("unsupported subcommand")
        .get_block_chain();

    match sub_matches.subcommand() {
        Some(("parse", operate_mathches)) => subcommand.parse(operate_mathches),
        Some(("generate", operate_mathches)) => subcommand.generate(operate_mathches),
        Some(("verify", operate_mathches)) => subcommand.verify(operate_mathches),
        _ => Err(anyhow!("unsupported operate")),
    }
}
