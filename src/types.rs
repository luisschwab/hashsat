//! hashsat: a bitcoin passphrase cracker

use core::fmt;

use bip39::Mnemonic;
use bitcoin::{
    Address, Network,
    bip32::{DerivationPath, Xpriv, Xpub},
};

/// Abstract representation of a lost wallet.
#[derive(Debug)]
pub(crate) struct Wallet {
    /// The BIP39-compliant mnemonic.
    pub(crate) mnemonic: Mnemonic,
    /// The alphabet used to search for the passphrase.
    pub(crate) alphabet: String,
    /// The target address where it is known coins are locked.
    pub(crate) target_address: Address,
    /// The derivation path used on the search.
    /// The deafault derivation path for the address type will be used if this is left empty.
    pub(crate) derivation_path: DerivationPath,
    /// The maximum search width for a parent key on the BIP32 HD tree.
    pub(crate) search_width: usize,
    /// The maximum passphrase length to search.
    pub(crate) passphrase_length_range: (usize, usize),
    /// The network to be searched.
    pub(crate) network: Network,
    /// The cracked passphrase.
    pub(crate) passphrase: Option<String>,
    /// The cracked extended public key.
    pub(crate) xpub: Option<Xpub>,
    /// The cracked extended private key.
    pub(crate) xpriv: Option<Xpriv>,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mnemonic: {}", self.mnemonic)?;
        writeln!(f, "alphabet: {}", self.alphabet)?;
        writeln!(f, "target address: {}", self.target_address)?;
        writeln!(f, "derivation path: {}", self.derivation_path)?;
        writeln!(f, "search width: {}", self.search_width)?;
        writeln!(
            f,
            "passphrase length range: ({},{})",
            self.passphrase_length_range.0, self.passphrase_length_range.1
        )?;
        writeln!(f, "network: {}", self.network)?;
        writeln!(
            f,
            "passphrase: {}",
            self.passphrase.as_deref().unwrap_or("not found yet")
        )?;
        writeln!(
            f,
            "xpub: {}",
            self.xpub
                .as_ref()
                .map_or("not found yet".to_string(), |x| x.to_string())
        )?;
        writeln!(
            f,
            "xpriv: {}",
            self.xpriv
                .as_ref()
                .map_or("not found yet".to_string(), |x| x.to_string())
        )
    }
}
