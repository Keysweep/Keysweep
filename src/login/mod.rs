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
        args::{CredentialArgs, GeneralArgs},
        args_display::{Pretty, fmt_vec},
    },
};

#[derive(Subcommand, Debug)]
pub enum LoginMode {
    /// Submit credentials through an HTML login form
    Form {
        #[command(flatten)]
        creds: CredentialArgs,

        #[command(flatten)]
        general: GeneralArgs,

        /// Target login page URL
        #[arg(long, value_name = "URL")]
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
    /// Submit credentials through HTTP Basic Authentication
    BasicAuth {
        #[command(flatten)]
        creds: CredentialArgs,

        #[command(flatten)]
        general: GeneralArgs,

        /// Target URL requiring basic authentication
        #[arg(short, long, value_name = "URL")]
        url: String,
    },
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[command(subcommand)]
    pub mode: LoginMode,
}

impl fmt::Display for LoginMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 12).indent(2);
        match self {
            LoginMode::Form {
                creds,
                general,
                url,
                user_field,
                pass_field,
                invalid_text,
                spoof,
                other_fields,
            } => {
                writeln!(f, "Form")?;

                creds.display(&mut p)?;
                general.display(&mut p)?;

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
            LoginMode::BasicAuth {
                creds,
                general,
                url,
            } => {
                writeln!(f, "Basic Auth")?;

                creds.display(&mut p)?;
                general.display(&mut p)?;
                p.field("URL", url)?;

                write!(f, "{s}")
            }
        }
    }
}

pub struct LoginParams {
    pub users: CredentialSource,
    pub passwords: CredentialSource,

    pub general_args: GeneralArgs,
}

fn build_login_params(creds: CredentialArgs, general: GeneralArgs) -> LoginParams {
    OUTPUT_HANDLER
        .lock()
        .unwrap()
        .set_formats(general.output_format.clone());

    let users = CredentialSource::from_pair(creds.username, creds.user_list);
    let passwords = CredentialSource::from_pair(creds.password, creds.pass_list);

    LoginParams {
        users,
        passwords,
        general_args: general,
    }
}

pub fn handle_login(login: LoginArgs) {
    let client = reqwest::blocking::Client::new();

    match login.mode {
        LoginMode::Form {
            creds,
            general,
            url,
            user_field,
            pass_field,
            invalid_text,
            spoof,
            other_fields,
        } => {
            let login_params = build_login_params(creds, general);

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
        LoginMode::BasicAuth {
            creds,
            general,
            url,
        } => {
            let login_params = build_login_params(creds, general);
            brute_basic_auth(login_params, url, client);
        }
    }
}
