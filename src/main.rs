use std::fmt::{self};

use clap::{Parser, Subcommand};

use crate::{
    fuzz::{FuzzArgs, handle_fuzz},
    hashes::{HashArgs, handle_hash},
    login::{LoginArgs, handle_login},
};

pub mod bypass;
pub mod fuzz;
pub mod hashes;
pub mod login;
pub mod shared;
pub mod utils;
pub mod wordlists_iterator;

pub const RED: &str = "\x1b[91m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[96m";
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const RESET: &str = "\x1b[0m";
pub const GRAY: &str = "\x1b[90m";
pub const BG_YELLOW: &str = "\x1b[43m";

///A brute forcer attack maker
#[derive(Parser, Debug)]
#[command(name="keysweep", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone)]
pub enum CredentialSource {
    Single(String),
    Wordlist(String), // path
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

const BANNER: &str = r#"
  _  __    {Y} ___ {R}                          
 | |/ /___ {Y}/ _ \{R}____ __ _____ ___ _ __
 | ' </ -_){Y} |_|{R}(_-< V  V / -_) -_) '_ \
 |_|\_\___|{Y}\   {R}/__/\_/\_/\___\___| .__/
           {Y} | |_ {R}                |_|   
           {Y} | |_/{R}
           {Y} | |_ {R}
           {Y} |_|_/{R}"#;

fn print_banner() {
    println!("{}", BANNER.replace("{Y}", YELLOW).replace("{R}", RESET));
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
