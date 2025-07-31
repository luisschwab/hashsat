//! hashsat: a bitcoin passphrase cracker

use clap::Parser;
use error::HashsatError;

pub(crate) mod cli;
pub(crate) mod cracker;
pub(crate) mod error;
pub(crate) mod types;

use crate::cli::{Arguments, parse_cli_arguments};
use crate::cracker::crack;
use crate::types::Wallet;

fn main() -> Result<(), HashsatError> {
    let args: Arguments = Arguments::parse();
    let mut wallet: Wallet = parse_cli_arguments(args)?;

    // crack 'em up!
    match crack(&mut wallet) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("\n\nerr: {e}\n");
            std::process::exit(1)
        }
    }
}
