use std::fmt::{self};

use clap::{Parser, Subcommand};

use crate::{
    fuzz::{FuzzArgs, handle_fuzz},
    hashes::{HashArgs, handle_hash},
    login::{LoginArgs, handle_login},
    theme::print_banner,
};

pub mod bypass;
pub mod credentials;
pub mod fuzz;
pub mod hashes;
pub mod login;
pub mod shared;
pub mod theme;
pub mod utils;
pub mod wordlists_iterator;

///A brute forcer attack maker
#[derive(Parser, Debug)]
#[command(name="keysweep", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Login(LoginArgs),

    Fuzz(FuzzArgs),

    Hash(HashArgs),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Login(login) => write!(f, "=== LOGIN ===\n{login}"),
            Command::Fuzz(fuzz) => write!(f, "=== FUZZ ===\n{fuzz}"),
            Command::Hash(hash) => write!(f, "=== HASH ===\n{hash}"),
        }
    }
}

fn main() {
    let args = Cli::parse();

    print_banner();
    println!("{}", args.command);
    println!("___________________________________________________________________");

    match args.command {
        Command::Login(login) => handle_login(login),
        Command::Fuzz(fuzz) => handle_fuzz(fuzz),
        Command::Hash(hash) => handle_hash(hash),
    }
}
