//! hashsat: a bitcoin passphrase cracker

use std::{
    io::{Write, stdout},
    time::{Duration, Instant},
};

use bitcoin::{
    Address, NetworkKind,
    bip32::{ChildNumber, Xpriv, Xpub},
    key::Secp256k1,
};

/// The alphabet used to crack the passphrase. This will not cover the most secure passphrases, but
/// most people don't use special characters on them.
const ALPHABET_ALPHANUMERIC: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#[allow(dead_code)]
const ALPHABET_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
#[allow(dead_code)]
const ALPHABET_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const COMMAS: [&str; 4] = ["", ".", "..", "..."];
const SPINNERS: [char; 4] = ['\\', '|', '/', '–'];

use crate::{error::HashsatError, types::Wallet};

/// Crack the passphrase with [`ALPHABET`] until [`MAX_PASSPHRASE_LEN`] is depleted.
/// TODO(@luisschwab): make this async and parallel.
pub(crate) fn crack(wallet: &mut Wallet) -> Result<(), HashsatError> {
    // Hide the cursor.
    print!("\x1b[?25l");
    stdout().flush()?;

    println!("\nspinning up hashers...\n");
    std::thread::sleep(Duration::from_secs(1));
    print_cracking_params(wallet);

    // Generate all possible passphrases, which are lazy eval'd.
    let passphrases = generate_passphrases_up_to(wallet.max_passphrase_len, ALPHABET_ALPHANUMERIC);

    // Derive a wallet from each passphrase, then derive
    // some addresses and check against the target.
    let start = Instant::now();
    let (mut comma_idx, mut spinner_idx) = (0, 0);
    for (tries, passphrase) in passphrases.enumerate() {
        if tries % 169 == 0 {
            let elapsed = start.elapsed();

            print!(
                "\r{} cracking sats : {} ({} wallets in {}){:<3}",
                SPINNERS[spinner_idx],
                passphrase,
                format_number(tries),
                format_duration(elapsed),
                COMMAS[comma_idx],
            );
            stdout().flush()?;

            // Update idx's.
            if tries % 6 == 0 {
                comma_idx = (comma_idx + 1) % COMMAS.len();
            }
            spinner_idx = (spinner_idx + 1) % SPINNERS.len();
        }

        if let Some(jackpot) = derive_wallet(wallet, &passphrase) {
            wallet.passphrase = Some(jackpot.0);
            wallet.xpub = Some(jackpot.1);
            wallet.xpriv = Some(jackpot.2);

            let elapsed = start.elapsed();
            print!(
                "\r{} cracking sats : {} ({} wallets in {}){:<3}",
                SPINNERS[spinner_idx],
                passphrase,
                format_number(tries),
                format_duration(elapsed),
                COMMAS[comma_idx],
            );
            stdout().flush()?;

            println!("\n\nJACKPOT!");
            println!(
                "hashsat found your lost sats in {} and {} tries ({} wallets per second)\n",
                format_duration(start.elapsed()),
                format_number(tries),
                tries as u64 / start.elapsed().as_secs()
            );
            println!("{wallet}");

            // Unhide the cursor.
            print!("\x1b[?25h");

            return Ok(());
        }
    }

    // Unhide the cursor.
    print!("\x1b[?25h");

    Err(HashsatError::DepletedSearchSpace(wallet.max_passphrase_len))
}

/// Generate all candidate passphrases up to size `size` using the `Radix Conversion` algorithm.
///
/// Rust iterators are lazy (they're only evaluated when used),
/// so we are not allocating a shit ton of memory with all passphrase combinations.
fn generate_passphrases_up_to(size: usize, alphabet: &str) -> impl Iterator<Item = String> {
    (1..=size).flat_map(move |length| {
        let chars: Vec<char> = alphabet.chars().collect();
        (0..(chars.len() as u128).pow(length as u32)).map(move |mut n| {
            let mut result = String::new();
            for _ in 0..length {
                result.push(chars[n as usize % chars.len()]);
                n /= chars.len() as u128;
            }
            result
        })
    })
}

#[allow(dead_code)]
/// Generate all candidate passphrases of size `size` using the `Radix Conversion` algorithm.
///
/// Rust iterators are lazy (they're only evaluated when used),
/// so we are not allocating a shit ton of memory with all passphrase combinations.
///
/// TODO(@luisschwab): allow the user to search passphrases of exact lenght.
fn generate_passphrases_of(size: usize, alphabet: &str) -> impl Iterator<Item = String> {
    let chars: Vec<char> = alphabet.chars().collect();
    (0..(chars.len() as u128).pow(size as u32)).map(move |mut n| {
        let mut result = String::new();
        for _ in 0..size {
            result.push(chars[n as usize % chars.len()]);
            n /= chars.len() as u128;
        }
        result
    })
}

/// Create a BIP32 wallet from seed and passphrase,
/// derive `derivation_width` addresses and see if any match `target_address`.
///
/// Returns ([`Passphrase`, `Xpub`, `Xpriv`]) if `target_address` is within the wallet. If not,
/// returns None.
fn derive_wallet(wallet: &Wallet, passphrase: &String) -> Option<(String, Xpub, Xpriv)> {
    // Spawn `secp256k1` context.
    let secp = Secp256k1::new();

    // Derive the seed from mnemonic and passphrase.
    let seed = wallet.mnemonic.to_seed_normalized(passphrase);

    // Create the master extended private and public keys.
    let master_xpriv = Xpriv::new_master(NetworkKind::from(wallet.network), &seed).unwrap();
    let master_xpub = Xpub::from_priv(&secp, &master_xpriv);

    // Derive some addresses from external and internal keychains and see if they are a match.
    let mut addresses: Vec<Address> = Vec::new();
    for keychain_kind in 0..1 {
        for idx in 0..wallet.search_width {
            // Append `/keychain_kind` (keychain kind).
            let derivation_path = wallet.derivation_path.child(ChildNumber::Normal {
                index: keychain_kind,
            });
            // Append `/idx` (child number).
            let derivation_path = derivation_path.child(ChildNumber::Normal { index: idx as u32 });

            let xpriv = master_xpriv.derive_priv(&secp, &derivation_path).unwrap();
            let xpub = Xpub::from_priv(&secp, &xpriv);
            let compressed_pubkey = xpub.to_pub();

            let address = match wallet.derivation_path[0] {
                ChildNumber::Hardened { index: 44 } => {
                    Address::p2pkh(compressed_pubkey, wallet.network)
                }
                // TODO(@luisschwab): can we even support P2SH? I don't think so.
                //ChildNumber::Hardened { index: 49 } => Address::p2sh(&compressed_pubkey,
                // wallet.network).unwrap(),
                ChildNumber::Hardened { index: 84 } => {
                    Address::p2wpkh(&compressed_pubkey, wallet.network)
                }
                // TODO(@luisschwab): figure out Taproot addresses. Just use the internal key?
                //ChildNumber::Hardened { index: 86 } => Address::p2tr(&compressed_pubkey,
                // wallet.network),
                _ => Address::p2wpkh(&compressed_pubkey, wallet.network),
            };
            addresses.push(address);
        }
    }

    if addresses.contains(&wallet.target_address) {
        Some((passphrase.to_owned(), master_xpub, master_xpriv))
    } else {
        None
    }
}

/// Format a [`Duration`] in the `hh:mm:ss` format.
fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Format a number with commas as the thousands separator.
fn format_number(n: usize) -> String {
    n.to_string()
        .chars()
        .rev()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
        .chars()
        .rev()
        .collect()
}

/// Print cracking parameters.
fn print_cracking_params(wallet: &Wallet) {
    println!("cracking");
    println!(" \"{}\"", wallet.mnemonic);
    println!("with target address");
    println!(" \"{}\"", wallet.target_address);
    println!("on network");
    println!(" {}", wallet.network);
    println!("with search width of");
    println!(
        " {} addresses ({} external + {} internal)",
        2 * wallet.search_width,
        wallet.search_width,
        wallet.search_width
    );
    println!("and maximum passphrase length of");
    println!(" {} characters\n", wallet.max_passphrase_len);
    std::thread::sleep(Duration::from_secs(1));
}
