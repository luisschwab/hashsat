//! hashsat: a bitcoin passphrase cracker

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{
    Address, AddressType, Network,
    bip32::{self, DerivationPath},
};
use clap::{Parser, builder::PossibleValuesParser};

use crate::{error::HashsatError, types::Wallet};

#[derive(Parser, Debug)]
#[command(version, name = "hashsat", about = "a bitcoin passphrase cracker")]
pub(crate) struct Arguments {
    #[arg(
        short,
        long,
        value_name = "mnemonic",
        help = "12, 15, 18, 21 or 24 word mnemonic"
    )]
    pub(crate) mnemonic: String,

    #[arg(short, long, value_name = "network", default_value = "bitcoin", value_parser = PossibleValuesParser::new(["bitcoin", "signet", "testnet3", "testnet4"]), help = "The bitcoin network to search for addresses at")]
    pub(crate) network: String,

    #[arg(
        short,
        long,
        value_name = "target_address",
        help = "A known address from your wallet. It must be within `search_width` for it to be found"
    )]
    pub(crate) target_address: String,

    #[arg(
        short,
        long,
        value_name = "derivation_path",
        help = "The derivation path for your wallet. Use this flag if your wallet has a non-standard derivation path"
    )]
    pub(crate) derivation_path: Option<String>,

    #[arg(
        short,
        long,
        value_name = "search_width",
        default_value_t = 10,
        help = "How many addresses to derive on each tried wallet. Your `target_address` derivation index has to be lower or equal to this"
    )]
    pub(crate) search_width: usize,

    #[arg(
        short = 'l',
        long,
        value_name = "max_passphrase_len",
        default_value_t = 10,
        help = "The maximum passphrase lenght to be searched. Will return an error if your address is not found within the search space"
    )]
    pub(crate) max_passphrase_length: usize,
}

/// Parse the CLI arguments into a [`Wallet`].
pub(crate) fn parse_cli_arguments(args: Arguments) -> Result<Wallet, HashsatError> {
    // Parse the mnemonic.
    let mnemonic = Mnemonic::from_str(&args.mnemonic)?;
    // Parse the network.
    let network = Network::from_str(&args.network)?;
    // Parse the target address.
    let target_address = Address::from_str(&args.target_address)?.require_network(network)?;
    // Parse the derivation path, if provided; or use the standard derivation path for the address
    // type.
    let derivation_path = if args.derivation_path.is_some() {
        DerivationPath::from_str(&args.derivation_path.unwrap())?
    } else {
        match target_address.address_type() {
            Some(AddressType::P2pkh) => DerivationPath::from_str("m/44'/0'/0'")?,
            //Some(AddressType::P2sh) => DerivationPath::from_str("m/49'/0'/0'")?,
            Some(AddressType::P2sh) => {
                return Err(HashsatError::UnsupportedAddressType(
                    AddressType::P2sh.to_string(),
                ));
            }
            Some(AddressType::P2wpkh) => DerivationPath::from_str("m/84'/0'/0'")?,
            //Some(AddressType::P2wsh) => DerivationPath::from_str("m/84'/0'/0'")?,
            Some(AddressType::P2wsh) => {
                return Err(HashsatError::UnsupportedAddressType(
                    AddressType::P2tr.to_string(),
                ));
            }
            //Some(AddressType::P2tr) => DerivationPath::from_str("m/86'/0'/0'")?,
            Some(AddressType::P2tr) => {
                return Err(HashsatError::UnsupportedAddressType(
                    AddressType::P2tr.to_string(),
                ));
            }
            _ => {
                return Err(HashsatError::InvalidDerivationPath(
                    bip32::Error::InvalidDerivationPathFormat,
                ));
            }
        }
    };
    // Get the search width.
    let search_width = args.search_width;
    // Get the maximum passphrase lenght.
    let max_passphrase_len = args.max_passphrase_length;

    Ok(Wallet {
        mnemonic,
        target_address,
        derivation_path,
        search_width,
        max_passphrase_len,
        network,
        passphrase: None,
        xpub: None,
        xpriv: None,
    })
}
