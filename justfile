alias b := build
alias c := check
alias f := fmt

_default:
    @just --list

build:
    cargo build

check:
    cargo +nightly fmt --all -- --check
    cargo check
    cargo clippy

fmt:
    cargo +nightly fmt
