alias b := build
alias c := check
alias f := fmt
alias i := install

_default:
    @just --list

# Build the binary in release mode
build:
    cargo build --release

# Check the code
check:
    cargo +nightly fmt --all -- --check
    cargo check
    cargo clippy

# Format the code
fmt:
    cargo +nightly fmt

# Install the binary to Cargo's PATH
install: build
    cargo install --path . --force
    
