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

#[rustfmt::skip]
const ALPHABET_ALPHANUMERIC: &str ="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ALPHABET_ALPHANUMERIC_UPPERCASE: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_ALPHANUMERIC_LOWERCASE: &str = "0123456789abcdefghijklmnopqrstuvwxyz";
const ALPHABET_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const ALPHABET_NUMERIC: &str = "0123456789";

const COMMAS: [&str; 4] = ["", ".", "..", "..."];
const SPINNERS: [char; 4] = ['\\', '|', '/', '–'];

use crate::{error::HashsatError, types::Wallet};

#[derive(Clone)]
struct CrackResult {
    passphrase: String,
    xpub: Xpub,
    xpriv: Xpriv,
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
    let crack_res = Arc::new(Mutex::new(None::<CrackResult>));
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
                    "\r{} cracking sats : {:?} ({} wallets in {}){:<3}",
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

    // Generate all possible passphrases, which are lazy eval'd.
    let mut passphrase_set: Vec<Box<dyn Iterator<Item = String> + Send>> = Vec::new();
    for size in min..=max {
        let passphrase_subset = generate_passphrases_of_size(size, alphabet);
        passphrase_set.push(Box::new(passphrase_subset));
    }
    let passphrase_set_len = passphrase_set.len() - 1;

    let handles: Vec<_> = passphrase_set
        .into_iter()
        .enumerate()
        .map(|(idx, passphrase_subset)| {
            let wallet_clone = wallet.clone();
            let found_clone = found.clone();
            let tries_ctr_clone = tries_ctr.clone();
            let crack_res_clone = crack_res.clone();
            let curr_passphrase_clone = curr_passphrase.clone();

            thread::spawn(move || {
                println!("hasher {idx} ready!");
                if idx >= passphrase_set_len {
                    println!();
                }

                for passphrase in passphrase_subset {
                    if found_clone.load(Ordering::Relaxed) {
                        break;
                    }

                    if tries_ctr_clone.fetch_add(1, Ordering::Relaxed) % 21 == 0 {
                        *curr_passphrase_clone.lock().unwrap() = passphrase.clone();
                    }

                    // Derive a wallet from each passphrase, then derive
                    // some addresses and check against the target.
                    if let Some((passphrase, xpub, xpriv)) =
                        derive_wallet_and_assert(&wallet_clone, &passphrase)
                    {
                        found_clone.store(true, Ordering::Relaxed);
                        *crack_res_clone.lock().unwrap() = Some(CrackResult {
                            passphrase,
                            xpub,
                            xpriv,
                        });
                        break;
                    }
                }
            })
        })
        .collect();

    // Wait for all threads.
    for handle in handles {
        handle.join().unwrap();
    }

    // Stop progress thread.
    found.store(true, Ordering::Relaxed);
    progress_handle.join().unwrap();

    // Check the final result (jackpot or depleted search space).
    let final_crack_res = crack_res.lock().unwrap().take();
    let total_tries_ctr = tries_ctr.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    if let Some(jackpot) = final_crack_res {
        wallet.passphrase = Some(jackpot.passphrase.clone());
        wallet.xpub = Some(jackpot.xpub);
        wallet.xpriv = Some(jackpot.xpriv);

        print!(
            "\r{} cracking sats : {} ({} wallets in {}){:<3}",
            SPINNERS[0],
            jackpot.passphrase,
            format_number(total_tries_ctr),
            format_duration(elapsed),
            COMMAS[0],
        );
        stdout().flush()?;

        println!("\n\nJACKPOT!");
        println!(
            "hashsat found your lost sats in {} and {} tries ({} wallets per second)\n",
            format_duration(elapsed),
            format_number(total_tries_ctr),
            if elapsed.as_secs() > 0 {
                total_tries_ctr as u64 / elapsed.as_secs()
            } else {
                total_tries_ctr as u64
            }
        );
        println!("{wallet}");

        // Unhide the cursor.
        print!("\x1b[?25h");

        Ok(())
    } else {
        // Unhide the cursor.
        print!("\x1b[?25h");

        Err(HashsatError::DepletedSearchSpace(min, max))
    }
}

#[allow(dead_code)]
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

/// Generate all candidate passphrases of size `size` using the `Radix Conversion` algorithm.
///
/// Rust iterators are lazy (they're only evaluated when used),
/// so we are not allocating a shit ton of memory with all passphrase combinations.
///
/// TODO(@luisschwab): allow the user to search passphrases of exact lenght.
fn generate_passphrases_of_size(size: usize, alphabet: &str) -> impl Iterator<Item = String> {
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
        " ({},{}) \n",
        wallet.passphrase_length_range.0, wallet.passphrase_length_range.1
    );
    std::thread::sleep(Duration::from_secs(1));
}
