pub mod form;

use std::fmt;

use clap::{Args, Subcommand};

use crate::{
    CredentialSource,
    login::form::{FormParams, brute_form},
    shared::{
        args::GeneralArgs,
        args_display::{Pretty, fmt_vec},
    },
};

#[derive(Subcommand, Debug)]
pub enum LoginMode {
    /// Submit credentials through an HTML login form
    Form {
        /// Target login page URL
        #[arg(short, long, value_name = "URL")]
        url: String,

        /// Username field name
        #[arg(long, default_value = "username", value_name = "FIELD")]
        user_field: String,

        /// Password field name
        #[arg(long, default_value = "password", value_name = "FIELD")]
        pass_field: String,

        /// Text indicating a failed login attempt
        ///
        /// Multiple values can be separated with commas.
        #[arg(long, value_delimiter = ',', value_name = "TEXT")]
        invalid_text: Vec<String>,

        /// Generate spoofed IP addresses for the X-Forwarded-For header
        ///
        /// Example: --spoof 100
        #[arg(short = 's', long, value_name = "COUNT")]
        spoof: Option<u32>,
    },
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Username to test
    #[arg(short = 'u', long, conflicts_with = "user_list", value_name = "USER")]
    pub username: Option<String>,

    /// Password to test
    #[arg(short = 'p', long, conflicts_with = "pass_list", value_name = "PASS")]
    pub password: Option<String>,

    /// File containing usernames (one per line)
    #[arg(short = 'U', long, conflicts_with = "username", value_name = "FILE")]
    pub user_list: Option<String>,

    /// File containing passwords (one per line)
    #[arg(short = 'P', long, conflicts_with = "password", value_name = "FILE")]
    pub pass_list: Option<String>,

    #[command(flatten)]
    pub general: GeneralArgs,

    #[command(subcommand)]
    pub mode: LoginMode,
}

impl fmt::Display for LoginMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginMode::Form {
                url,
                user_field,
                pass_field,
                invalid_text,
                spoof,
            } => {
                let mut s = String::new();
                let mut p = Pretty::new(&mut s, 12).indent(2);

                writeln!(f, "Form")?;

                p.field("URL", url)?;
                p.field("User Field", user_field)?;
                p.field("Pass Field", pass_field)?;

                if !invalid_text.is_empty() {
                    p.field("Invalid Text", fmt_vec(invalid_text))?;
                }

                if let Some(spoof) = spoof {
                    p.field("Spoof", spoof)?;
                }

                write!(f, "{s}")
            }
        }
    }
}

impl fmt::Display for LoginArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 10);

        match (&self.username, &self.user_list) {
            (Some(user), _) => p.field("Username", user)?,
            (_, Some(list)) => p.field("User List", list)?,
            _ => {}
        }

        match (&self.password, &self.pass_list) {
            (Some(pass), _) => p.field("Password", pass)?,
            (_, Some(list)) => p.field("Pass List", list)?,
            _ => {}
        }

        p.field("Mode", &self.mode)?;

        write!(f, "{s}")?;
        write!(f, "{}", self.general)
    }
}

pub struct LoginParams {
    pub users: CredentialSource,
    pub passwords: CredentialSource,

    pub general_args: GeneralArgs,
}

/// Resolve a `(single, list)` CLI pair — exactly one is `Some`, enforced by
/// clap's `conflicts_with` — into the `CredentialSource` the brute-forcer expects.
fn resolve_credential_source(single: Option<String>, list: Option<String>) -> CredentialSource {
    match (single, list) {
        (Some(value), None) => CredentialSource::Single(value),
        (None, Some(path)) => CredentialSource::Wordlist(path),
        _ => unreachable!("clap enforces exactly one of these two args is set"),
    }
}

pub fn handle_login(login: LoginArgs) {
    let users = resolve_credential_source(login.username, login.user_list);
    let passwords = resolve_credential_source(login.password, login.pass_list);

    let client = reqwest::blocking::Client::new();

    match login.mode {
        LoginMode::Form {
            url,
            user_field,
            pass_field,
            invalid_text,
            spoof,
        } => {
            brute_form(
                LoginParams {
                    users,
                    passwords,
                    general_args: login.general,
                },
                FormParams {
                    client,
                    url,
                    user_field,
                    pass_field,
                    invalid_text,
                    spoof,
                },
            );
        }
    }
}
