//! hashsat: a bitcoin passphrase cracker

#![allow(clippy::enum_variant_names)]

use bitcoin::bip32;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum HashsatError {
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(#[from] bip39::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(#[from] bitcoin::address::ParseError),

    #[error("Invalid network: {0}")]
    InvalidNetwork(#[from] bitcoin::network::ParseNetworkError),

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] bip32::Error),

    #[error("Unsupported script type: {0}")]
    UnsupportedAddressType(String),

    #[error("Depleted search space of ({0},{1}) chars before finding any matches")]
    DepletedSearchSpace(usize, usize),

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
}
