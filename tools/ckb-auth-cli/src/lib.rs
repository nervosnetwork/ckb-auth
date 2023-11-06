mod auth_script;
mod bitcoin;
mod cardano;
mod eos;
mod ethereum;
mod litecoin;
mod monero;
mod ripple;
mod solana;
mod tron;
mod utils;

pub use crate::monero::MoneroLockArgs;
pub use bitcoin::BitcoinLockArgs;
pub use cardano::CardanoLockArgs;
pub use eos::EosLockArgs;
pub use ethereum::EthereumLockArgs;
pub use litecoin::LitecoinLockArgs;
pub use ripple::RippleLockArgs;
pub use solana::SolanaLockArgs;
pub use tron::TronLockArgs;

use anyhow::Error;
use clap::{ArgMatches, Command};

pub trait BlockChainArgs {
    fn block_chain_name(&self) -> &'static str;
    fn reg_parse_args(&self, cmd: Command) -> Command;
    fn reg_generate_args(&self, cmd: Command) -> Command;
    fn reg_verify_args(&self, cmd: Command) -> Command;

    fn get_block_chain(&self) -> Box<dyn BlockChain>;
}

pub trait BlockChain {
    fn parse(&self, operate_mathches: &ArgMatches) -> Result<(), Error>;
    fn generate(&self, operate_mathches: &ArgMatches) -> Result<(), Error>;
    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error>;
}
