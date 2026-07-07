use std::fmt;

use clap::Args;

use crate::{
    fuzz::keywords::{CombineMode, WordlistBinding},
    outputs::OutputFormat,
    shared::args_display::Pretty,
};

#[derive(Args, Debug)]
pub struct CredentialArgs {
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
}
impl CredentialArgs {
    pub fn display(&self, p: &mut Pretty<'_>) -> Result<(), fmt::Error> {
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

        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub struct GeneralArgs {
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 40, value_name = "NUM")]
    pub threads: usize,

    #[command(flatten)]
    pub filter: WordlistFilter,

    /// Output format into a file (can be specified multiple times)
    #[arg(short = 'o', long, value_name = "FORMAT")]
    pub output_format: Vec<OutputFormat>,
}
impl GeneralArgs {
    pub fn display(&self, p: &mut Pretty<'_>) -> Result<(), fmt::Error> {
        p.field("Threads", self.threads)?;
        if let Some(len) = self.filter.min_len {
            p.field("Min Length", len)?;
        }

        if let Some(len) = self.filter.max_len {
            p.field("Max Length", len)?;
        }
        p.field("Skip Empty", self.filter.skip_empty)?;

        if !self.output_format.is_empty() {
            let formats: Vec<String> = self.output_format.iter().map(|f| f.to_string()).collect();
            p.field("Output Format", formats.join(", "))?;
        }
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub struct FuzzGeneralArgs {
    /// Wordlist binding: PATH or PATH:KEYWORD. Repeatable for multiple FUZZ keywords.
    ///
    /// Example: -w users.txt:FUZZ -w pins.txt:FUZ2Z
    /// A binding with no ':KEYWORD' suffix defaults to FUZZ.
    #[arg(
        short = 'w',
        long = "fuzz-list",
        value_name = "PATH[:KEYWORD]",
        required = true
    )]
    pub fuzz_lists: Vec<WordlistBinding>,

    /// How to combine multiple wordlists when more than one keyword is used
    #[arg(long = "combine", default_value = "clusterbomb", value_name = "MODE")]
    pub combine_mode: CombineMode,

    /// Only report responses with these status codes (comma-separated)
    ///
    /// If unset, all are reported except those in --fc.
    /// Example: --mc 200,301,403
    #[arg(long = "mc", value_delimiter = ',', value_name = "CODES")]
    pub match_codes: Vec<u16>,

    /// Filter out responses with these status codes (comma-separated)
    ///
    /// Ignored if --mc is set. Example: --fc 404,400
    #[arg(long = "fc", value_delimiter = ',', value_name = "CODES", default_values_t = vec![404])]
    pub filter_codes: Vec<u16>,

    /// Filter out responses with these body/payload sizes in bytes (comma-separated)
    #[arg(long = "fs", value_delimiter = ',', value_name = "SIZES")]
    pub filter_sizes: Vec<u64>,

    /// Delay between each thread's requests, in milliseconds (0 = no throttling)
    #[arg(long = "delay-ms", default_value_t = 0, value_name = "MS")]
    pub delay_ms: u64,
}

impl FuzzGeneralArgs {
    pub fn display(&self, p: &mut Pretty<'_>) -> Result<(), fmt::Error> {
        let fuzz_lists: Vec<String> = self.fuzz_lists.iter().map(|f| f.to_string()).collect();
        p.field("Fuzz Lists", fuzz_lists.join(", "))?;
        p.field("Combine Mode", self.combine_mode.to_string())?;

        if !self.match_codes.is_empty() {
            let codes: Vec<String> = self.match_codes.iter().map(|c| c.to_string()).collect();
            p.field("Match Codes", codes.join(", "))?;
        }

        if !self.filter_codes.is_empty() {
            let codes: Vec<String> = self.filter_codes.iter().map(|c| c.to_string()).collect();
            p.field("Filter Codes", codes.join(", "))?;
        }

        if !self.filter_sizes.is_empty() {
            let sizes: Vec<String> = self.filter_sizes.iter().map(|s| s.to_string()).collect();
            p.field("Filter Sizes", sizes.join(", "))?;
        }

        if self.delay_ms != 0 {
            p.field("Delay (ms)", self.delay_ms)?;
        }

        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub struct WordlistFilter {
    /// Skip words shorter than this length
    #[arg(short = 'n', long = "min-len", value_name = "NUM")]
    pub min_len: Option<usize>,

    /// Skip words longer than this length
    #[arg(short = 'x', long = "max-len", value_name = "NUM")]
    pub max_len: Option<usize>,

    /// Skip empty lines in the word list
    #[arg(short = 'e', long = "skip-empty")]
    pub skip_empty: bool,
}
