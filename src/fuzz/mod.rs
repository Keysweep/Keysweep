use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand};

pub mod keywords;
pub mod targets;

use keywords::{CombineMode, WordlistBinding};
use targets::http::{HttpTarget, parse_headers};
use targets::{FireResult, FuzzTarget};

use crate::shared::args::GeneralArgs;
use crate::shared::args_display::{Pretty, fmt_vec};
use crate::utils::create_progress;
use crate::{GREEN, MAGENTA, RED, RESET, YELLOW};

#[derive(Subcommand, Debug)]
pub enum FuzzMode {
    /// Fuzz an HTTP(S) target: URL, headers, and/or body may contain FUZZ keywords
    Http {
        /// Target URL containing one or more FUZZ-style keywords
        ///
        /// Example: https://example.com/FUZZ or https://example.com/page?id=FUZZ&t=FUZ2Z
        #[arg(short, long, value_name = "URL")]
        url: String,

        /// HTTP method to use
        #[arg(short = 'X', long, default_value = "GET", value_name = "METHOD")]
        method: String,

        /// Extra header, may contain a FUZZ keyword in its value. Repeatable.
        ///
        /// Example: -H "Authorization: Bearer FUZZ"
        #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,

        /// Request body template, may contain FUZZ keywords (e.g. for POST/PUT)
        #[arg(short = 'd', long = "data", value_name = "BODY")]
        body: Option<String>,

        /// Per-request timeout in milliseconds
        #[arg(long = "timeout-ms", default_value_t = 10_000, value_name = "MS")]
        timeout_ms: u64,
    },
}

#[derive(Args, Debug)]
pub struct FuzzArgs {
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
    fuzz_lists: Vec<WordlistBinding>,

    /// How to combine multiple wordlists when more than one keyword is used
    #[arg(long = "combine", default_value = "clusterbomb", value_name = "MODE")]
    combine_mode: CombineMode,

    /// Only report responses with these status codes (comma-separated)
    ///
    /// If unset, all are reported except those in --fc.
    /// Example: --mc 200,301,403
    #[arg(long = "mc", value_delimiter = ',', value_name = "CODES")]
    match_codes: Vec<u16>,

    /// Filter out responses with these status codes (comma-separated)
    ///
    /// Ignored if --mc is set. Example: --fc 404,400
    #[arg(long = "fc", value_delimiter = ',', value_name = "CODES", default_values_t = vec![404])]
    filter_codes: Vec<u16>,

    /// Filter out responses with these body/payload sizes in bytes (comma-separated)
    #[arg(long = "fs", value_delimiter = ',', value_name = "SIZES")]
    filter_sizes: Vec<u64>,

    /// Delay between each thread's requests, in milliseconds (0 = no throttling)
    #[arg(long = "delay-ms", default_value_t = 0, value_name = "MS")]
    delay_ms: u64,

    #[command(flatten)]
    general: GeneralArgs,

    #[command(subcommand)]
    mode: FuzzMode,
}

impl fmt::Display for FuzzMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzMode::Http {
                url,
                method,
                headers,
                body,
                timeout_ms,
            } => {
                let mut s = String::new();
                let mut p = Pretty::new(&mut s, 8).indent(2);

                writeln!(f, "HTTP")?;

                p.field("URL", url)?;
                p.field("Method", method)?;

                if !headers.is_empty() {
                    p.field("Headers", fmt_vec(headers))?;
                }

                if let Some(body) = body {
                    p.field("Body", body)?;
                }

                p.field("Timeout", format!("{timeout_ms}ms"))?;

                write!(f, "{s}")
            }
        }
    }
}

impl fmt::Display for FuzzArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 12);

        p.field("Fuzz Lists", fmt_vec(&self.fuzz_lists))?;

        p.field("Combine Mode", format!("{:?}", self.combine_mode))?;

        if !&self.match_codes.is_empty() {
            p.field("Match Codes", fmt_vec(&self.match_codes))?;
        }
        if !&self.filter_codes.is_empty() {
            p.field("Filter Codes", fmt_vec(&self.filter_codes))?;
        }
        if !&self.filter_sizes.is_empty() {
            p.field("Filter Sizes", fmt_vec(&self.filter_sizes))?;
        }
        if self.delay_ms != 0 {
            p.field("Delay", format!("{}ms", self.delay_ms))?;
        }

        p.field("Mode", &self.mode)?;

        write!(f, "{s}")?;
        write!(f, "{}", self.general)
    }
}

struct ReportFilter {
    match_codes: Arc<Vec<u16>>,
    filter_codes: Arc<Vec<u16>>,
    filter_sizes: Arc<Vec<u64>>,
}

impl ReportFilter {
    /// `--mc` takes priority over `--fc` when both could apply.
    fn should_report(&self, status: u16, size: u64) -> bool {
        if !self.match_codes.is_empty() {
            return self.match_codes.contains(&status) && !self.filter_sizes.contains(&size);
        }

        !self.filter_codes.contains(&status) && !self.filter_sizes.contains(&size)
    }
}

struct WorkerContext {
    combine_mode: CombineMode,
    lists: Arc<Vec<keywords::LoadedWordlist>>,
    target: Arc<dyn FuzzTarget>,
    filter: ReportFilter,
}

fn status_color(status: u16) -> &'static str {
    match status {
        200..=299 => GREEN,
        300..=399 => YELLOW,  // yellow
        400..=499 => RED,     // red
        500..=599 => MAGENTA, // magenta
        _ => RESET,
    }
}

/// Render the resolved substitution map as a compact label for output, e.g.
/// "FUZZ=admin FUZ2Z=1234".
fn sub_label(sub: &keywords::Substitution) -> String {
    let mut keys: Vec<&String> = sub.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| format!("{k}={}", sub[*k]))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn handle_fuzz(fuzz: FuzzArgs) {
    let lists = match keywords::load_wordlists(&fuzz.fuzz_lists) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{RED}error loading wordlists: {e}{RESET}");
            return;
        }
    };

    let combine_mode = fuzz.combine_mode;
    let total = keywords::total_items(combine_mode, &lists);
    if total == 0 {
        eprintln!("{RED}no work items produced (empty wordlist combination){RESET}");
        return;
    }

    let target: Arc<dyn FuzzTarget> = match build_target(fuzz.mode) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{RED}error configuring target: {e}{RESET}");
            return;
        }
    };

    let threads = fuzz.general.threads.max(1);
    let delay = Duration::from_millis(fuzz.delay_ms);
    let pb = create_progress(total);
    let index = Arc::new(AtomicU64::new(0));

    let ctx = Arc::new(WorkerContext {
        combine_mode,
        lists: Arc::new(lists),
        target,
        filter: ReportFilter {
            match_codes: Arc::new(fuzz.match_codes),
            filter_codes: Arc::new(fuzz.filter_codes),
            filter_sizes: Arc::new(fuzz.filter_sizes),
        },
    });

    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let index = index.clone();
        let ctx = ctx.clone();
        let pb = pb.clone();

        workers.push(thread::spawn(move || {
            run_worker(&index, total, &ctx, &pb, delay);
        }));
    }

    for w in workers {
        w.join().unwrap();
    }

    pb.finish_with_message("Done");
}

/// Pull work items from the shared `index` counter until exhausted, firing each
/// at `target` and printing results that pass the match/filter rules.
fn run_worker(
    index: &AtomicU64,
    total: u64,
    ctx: &WorkerContext,
    pb: &indicatif::ProgressBar,
    delay: Duration,
) {
    loop {
        let i = index.fetch_add(1, Ordering::Relaxed);
        if i >= total {
            break;
        }

        let sub = keywords::substitution_at(ctx.combine_mode, &ctx.lists, i);
        let FireResult {
            status,
            size,
            elapsed_ms,
            label,
            error,
        } = ctx.target.fire(&sub);

        if let Some(err) = error {
            pb.println(format!(
                "{RED}probe failed [{}]: {err}{RESET}",
                sub_label(&sub)
            ));
        } else if ctx.filter.should_report(status, size) {
            let color = status_color(status);
            pb.println(format!(
                "[{color}{label}{RESET}] {GREEN}{:<30}{RESET} : Size: {size:>6}, Elapsed: {elapsed_ms:>5}ms",
                sub_label(&sub),
            ));
        }

        pb.inc(1);

        if !delay.is_zero() {
            thread::sleep(delay);
        }
    }
}

fn build_target(mode: FuzzMode) -> Result<Arc<dyn FuzzTarget>, String> {
    match mode {
        FuzzMode::Http {
            url,
            method,
            headers,
            body,
            timeout_ms,
        } => {
            let header_templates = parse_headers(&headers)?;
            let target = HttpTarget::new(
                url,
                method,
                header_templates,
                body,
                Duration::from_millis(timeout_ms),
            )?;
            Ok(Arc::new(target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keywords::Substitution;
    use std::sync::Arc as StdArc;

    fn sub(pairs: &[(&str, &str)]) -> Substitution {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), StdArc::from(*v)))
            .collect()
    }

    fn filter(match_codes: &[u16], filter_codes: &[u16], filter_sizes: &[u64]) -> ReportFilter {
        ReportFilter {
            match_codes: Arc::new(match_codes.to_vec()),
            filter_codes: Arc::new(filter_codes.to_vec()),
            filter_sizes: Arc::new(filter_sizes.to_vec()),
        }
    }
    // --- should_report ---

    #[test]
    fn reports_everything_by_default() {
        let f = filter(&[], &[], &[]);
        assert!(f.should_report(200, 100));
        assert!(f.should_report(404, 0));
    }

    #[test]
    fn filter_codes_suppress_matching_status() {
        let f = filter(&[], &[404], &[]);
        assert!(!f.should_report(404, 100));
        assert!(f.should_report(200, 100));
    }

    #[test]
    fn filter_sizes_suppress_matching_size() {
        let f = filter(&[], &[], &[0]);
        assert!(!f.should_report(200, 0));
        assert!(f.should_report(200, 100));
    }

    #[test]
    fn match_codes_take_priority_over_filter_codes() {
        let f = filter(&[404], &[404], &[]);
        // 404 is in filter_codes, but match_codes overrides it.
        assert!(f.should_report(404, 100));
        assert!(!f.should_report(200, 100));
    }

    #[test]
    fn match_codes_still_respect_filter_sizes() {
        let f = filter(&[200], &[], &[0]);
        assert!(!f.should_report(200, 0));
        assert!(f.should_report(200, 100));
    }

    // --- sub_label ---

    #[test]
    fn sub_label_formats_single_keyword() {
        let s = sub(&[("FUZZ", "admin")]);
        assert_eq!(sub_label(&s), "FUZZ=admin");
    }

    #[test]
    fn sub_label_sorts_multiple_keywords() {
        // Insert in reverse order; output should still be alphabetical.
        let s = sub(&[("FUZ2Z", "1234"), ("FUZZ", "admin")]);
        assert_eq!(sub_label(&s), "FUZ2Z=1234 FUZZ=admin");
    }

    #[test]
    fn sub_label_empty_substitution_is_empty_string() {
        let s = Substitution::new();
        assert_eq!(sub_label(&s), "");
    }
}
