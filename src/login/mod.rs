pub mod basic_auth;
pub mod form;

use clap::{Args, Subcommand};
use std::fmt;

use crate::{
    credentials::CredentialSource,
    login::{
        basic_auth::brute_basic_auth,
        form::{FormParams, brute_form},
    },
    outputs::OUTPUT_HANDLER,
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

        /// Additional form fields to include in the request body
        ///
        /// Format: field1=value1,field2=value2
        #[arg(long, value_delimiter = ',', value_name = "FIELDS")]
        other_fields: Vec<String>,
    },
    BasicAuth {
        /// Target URL requiring basic authentication
        #[arg(short, long, value_name = "URL")]
        url: String,
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
                other_fields,
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

                if !other_fields.is_empty() {
                    p.field("Other Fields", fmt_vec(other_fields))?;
                }

                write!(f, "{s}")
            }
            LoginMode::BasicAuth { url } => {
                let mut s = String::new();
                let mut p = Pretty::new(&mut s, 12).indent(2);

                writeln!(f, "Basic Auth")?;

                p.field("URL", url)?;

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

pub fn handle_login(login: LoginArgs) {
    let users = CredentialSource::from_pair(login.username, login.user_list);
    let passwords = CredentialSource::from_pair(login.password, login.pass_list);

    OUTPUT_HANDLER
        .lock()
        .unwrap()
        .set_formats(login.general.output_format.clone());

    let client = reqwest::blocking::Client::new();
    let login_params = LoginParams {
        users,
        passwords,
        general_args: login.general,
    };

    match login.mode {
        LoginMode::Form {
            url,
            user_field,
            pass_field,
            invalid_text,
            spoof,
            other_fields,
        } => {
            brute_form(
                login_params,
                FormParams {
                    client,
                    url,
                    user_field,
                    pass_field,
                    invalid_text,
                    spoof,
                    other_fields,
                },
            );
        }
        LoginMode::BasicAuth { url } => {
            brute_basic_auth(login_params, url, client);
        }
    }
}
