use std::fmt;

use clap::Args;

use crate::{outputs::OutputFormat, shared::args_display::Pretty};

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

impl fmt::Display for GeneralArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 12);

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

        write!(f, "{s}")
    }
}
