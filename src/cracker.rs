//! hashsat: a bitcoin passphrase cracker

use std::{
    io::{Write, stdout},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    Address, NetworkKind,
    bip32::{ChildNumber, Xpriv, Xpub},
    key::Secp256k1,
};
use rand::{rng, seq::SliceRandom};
use rayon::iter::{ParallelBridge, ParallelIterator};

use crate::{error::HashsatError, types::Wallet};

#[rustfmt::skip]
const ALPHABET_ALPHANUMERIC: &str ="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ALPHABET_ALPHANUMERIC_UPPERCASE: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_ALPHANUMERIC_LOWERCASE: &str = "0123456789abcdefghijklmnopqrstuvwxyz";
const ALPHABET_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const ALPHABET_NUMERIC: &str = "0123456789";

const COMMAS: [&str; 4] = ["", ".", "..", "..."];
const SPINNERS: [char; 4] = ['\\', '|', '/', '–'];

/// Round-Robin iteration between different length passphrases.
struct RoundRobinIter {
    /// Iterators for each passphrase subset.
    passphrase_subset_iters: Vec<Box<dyn Iterator<Item = String> + Send>>,
    /// Current position in the Round-Robin cycle.
    current_idx: usize,
    /// Keep track of exhausted subsets.
    exhausted_subsets: Vec<bool>,
}

impl RoundRobinIter {
    fn new(min: usize, max: usize, alphabet: String) -> Self {
        let mut passphrase_subset_iters = Vec::new();
        for size in min..=max {
            // Scramble the alphabet on every run so walks across
            // the search space are random instead of lexicographical.
            // This make sure that different runs walk different paths.
            let mut chars: Vec<char> = alphabet.chars().collect();
            chars.shuffle(&mut rng());
            let scrambled_alphabet: String = chars.into_iter().collect();

            let iter = generate_passphrases_of_size(size, scrambled_alphabet.clone());
            passphrase_subset_iters.push(Box::new(iter) as Box<dyn Iterator<Item = String> + Send>);
        }
        let n_subsets = passphrase_subset_iters.len();

        Self {
            passphrase_subset_iters,
            current_idx: 0,
            exhausted_subsets: vec![false; n_subsets],
        }
    }
}

impl Iterator for RoundRobinIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.passphrase_subset_iters.is_empty() {
            return None;
        }

        let start_idx = self.current_idx;
        loop {
            if !self.exhausted_subsets[self.current_idx] {
                if let Some(passphrase) = self.passphrase_subset_iters[self.current_idx].next() {
                    self.current_idx = (self.current_idx + 1) % self.passphrase_subset_iters.len();
                    return Some(passphrase);
                } else {
                    self.exhausted_subsets[self.current_idx] = true;
                }
            }
            self.current_idx = (self.current_idx + 1) % self.passphrase_subset_iters.len();

            if self.current_idx == start_idx
                && self.exhausted_subsets.iter().all(|&exhausted| exhausted)
            {
                return None;
            }
        }
    }
}

/// Crack the passphrase with [`ALPHABET`] until [`MAX_PASSPHRASE_LEN`] is depleted.
/// TODO(@luisschwab): make this async and parallel.
pub(crate) fn crack(wallet: &mut Wallet) -> Result<(), HashsatError> {
    // Hide the cursor.
    print!("\x1b[?25l");
    stdout().flush()?;

    println!("\nspinning up hashers...\n");
    std::thread::sleep(Duration::from_secs(1));
    print_cracking_params(wallet);

    // Select the alphabet.
    let alphabet = get_alphabet(&wallet.alphabet);

    // Passphrase ranges.
    let min = wallet.passphrase_length_range.0;
    let max = wallet.passphrase_length_range.1;

    // Thread-common state.
    let found = Arc::new(AtomicBool::new(false));
    let tries_ctr = Arc::new(AtomicUsize::new(0));
    let curr_passphrase = Arc::new(Mutex::new(String::new()));

    // Start time.
    let start = Instant::now();

    // Progress thread.
    let found_clone = found.clone();
    let tries_ctr_clone = tries_ctr.clone();
    let curr_passphrase_clone = curr_passphrase.clone();
    let progress_handle = thread::spawn(move || {
        let (mut comma_idx, mut spinner_idx) = (0, 0);

        while !found_clone.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));

            let tries = tries_ctr_clone.load(Ordering::Relaxed);
            if tries > 0 {
                let elapsed = start.elapsed();
                let curr_passphrase = curr_passphrase_clone.lock().unwrap().clone();

                print!(
                    "\r{} cracking sats : {} ({} wallets in {}){:<3}",
                    SPINNERS[spinner_idx],
                    curr_passphrase,
                    format_number(tries),
                    format_duration(elapsed),
                    COMMAS[comma_idx],
                );
                stdout().flush().unwrap_or(());

                comma_idx = (comma_idx + 1) % COMMAS.len();
                spinner_idx = (spinner_idx + 1) % SPINNERS.len();
            }
        }
    });

    // Round-Robin iterator: join subsets into a unified iterator.
    let rr_iter = RoundRobinIter::new(min, max, alphabet.to_string());
    let crack_res = rr_iter.par_bridge().find_any(|passphrase| {
        // Update progress counter
        let tries = tries_ctr.fetch_add(1, Ordering::Relaxed);

        // Update the progress bar with the current passphrase every once in a while.
        if tries % 69 == 0 {
            *curr_passphrase.lock().unwrap() = passphrase.clone();
        }

        // Test and assert this passphrase against the wallet
        // parameters. `find_any` will return the findings if they are `Some()`.
        derive_wallet_and_assert(wallet, passphrase).is_some()
    });

    // Signal progress thread to stop.
    found.store(true, Ordering::Relaxed);
    progress_handle.join().unwrap();

    let total_tries = tries_ctr.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    match crack_res {
        Some(jackpot) => {
            if let Some((passphrase, xpub, xpriv)) = derive_wallet_and_assert(wallet, &jackpot) {
                wallet.passphrase = Some(passphrase.clone());
                wallet.xpub = Some(xpub);
                wallet.xpriv = Some(xpriv);

                print!(
                    "\r{} cracking sats : {} ({} wallets in {}){:<3}",
                    SPINNERS[0],
                    passphrase,
                    format_number(total_tries),
                    format_duration(elapsed),
                    COMMAS[0],
                );
                stdout().flush()?;

                println!("\n\nJACKPOT!");
                println!(
                    "hashsat found your lost sats in {} and {} tries ({} wallets per second)\n",
                    format_duration(elapsed),
                    format_number(total_tries),
                    if elapsed.as_secs() > 0 {
                        total_tries as u64 / elapsed.as_secs()
                    } else {
                        total_tries as u64
                    }
                );
                println!("{wallet}");

                // Unhide the cursor.
                print!("\x1b[?25h");

                Ok(())
            } else {
                Ok(())
            }
        }
        None => {
            // Unhide the cursor.
            print!("\x1b[?25h");

            println!("\nSearch space depleted without finding passphrase");
            Err(HashsatError::DepletedSearchSpace(min, max))
        }
    }
}

#[allow(dead_code)]
/// Generate all candidate passphrases up to size `size` using the `Radix Conversion` algorithm.
///
/// Rust iterators are lazy (they're only evaluated when used),
/// so we are not allocating a shit ton of memory with all passphrase combinations.
fn generate_passphrases_up_to(size: usize, alphabet: String) -> impl Iterator<Item = String> {
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

/// Generate all candidate passphrases of size `size` using the `Radix Conversion` algorithm.
///
/// Rust iterators are lazy (they're only evaluated when used),
/// so we are not allocating a shit ton of memory with all passphrase combinations.
fn generate_passphrases_of_size(size: usize, alphabet: String) -> impl Iterator<Item = String> {
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
fn derive_wallet_and_assert(wallet: &Wallet, passphrase: &String) -> Option<(String, Xpub, Xpriv)> {
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

/// Get the alphabet from it's identifier.
fn get_alphabet(identifier: &str) -> &'static str {
    match identifier {
        "alphanumeric" => ALPHABET_ALPHANUMERIC,
        "alphanumeric_uppercase" => ALPHABET_ALPHANUMERIC_UPPERCASE,
        "alphanumeric_lowercase" => ALPHABET_ALPHANUMERIC_LOWERCASE,
        "uppercase" => ALPHABET_UPPERCASE,
        "lowercase" => ALPHABET_LOWERCASE,
        "numeric" => ALPHABET_NUMERIC,
        _ => ALPHABET_ALPHANUMERIC,
    }
}

/// Print cracking parameters.
fn print_cracking_params(wallet: &Wallet) {
    println!("cracking");
    println!(" {}", wallet.mnemonic);
    println!("using alphabet");
    println!(" {} ({})", wallet.alphabet, get_alphabet(&wallet.alphabet));
    println!("with target address");
    println!(" {}", wallet.target_address);
    println!("on network");
    println!(" {}", wallet.network);
    println!("with search width of");
    println!(
        " {} addresses ({} external + {} internal)",
        2 * wallet.search_width,
        wallet.search_width,
        wallet.search_width
    );
    println!("and passphrase length range of");
    println!(
        " ({},{})",
        wallet.passphrase_length_range.0, wallet.passphrase_length_range.1
    );
    println!("using");
    println!(" {} threads", rayon::current_num_threads());
    println!();
    std::thread::sleep(Duration::from_secs(1));
}
