use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand};

pub mod keywords;
pub mod targets;

use keywords::CombineMode;
use targets::http::{HttpTarget, parse_headers};
use targets::{FireResult, FuzzTarget};

use crate::outputs::OUTPUT_HANDLER;
use crate::shared::args::{FuzzGeneralArgs, GeneralArgs};
use crate::shared::args_display::{Pretty, fmt_vec};
use crate::theme::{GREEN, MAGENTA, RED, RESET, YELLOW};
use crate::utils::create_progress;

trait FuzzProtocol {
    fn fuzz_args(&self) -> &FuzzGeneralArgs;
    fn general(&self) -> &GeneralArgs;
    fn build_target(self: Box<Self>) -> Result<Arc<dyn FuzzTarget>, String>;
    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

#[derive(Args, Debug)]
pub struct HttpFuzzArgs {
    #[command(flatten)]
    fuzz_args: FuzzGeneralArgs,

    #[command(flatten)]
    general: GeneralArgs,

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
}

impl FuzzProtocol for HttpFuzzArgs {
    fn fuzz_args(&self) -> &FuzzGeneralArgs {
        &self.fuzz_args
    }

    fn general(&self) -> &GeneralArgs {
        &self.general
    }

    fn build_target(self: Box<Self>) -> Result<Arc<dyn FuzzTarget>, String> {
        let header_templates = parse_headers(&self.headers)?;
        let target = HttpTarget::new(
            self.url,
            self.method,
            header_templates,
            self.body,
            Duration::from_millis(self.timeout_ms),
        )?;
        Ok(Arc::new(target))
    }

    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 8).indent(2);

        writeln!(f, "HTTP")?;

        self.fuzz_args.display(&mut p)?;
        self.general.display(&mut p)?;

        p.field("URL", &self.url)?;
        p.field("Method", &self.method)?;

        if !self.headers.is_empty() {
            p.field("Headers", fmt_vec(&self.headers))?;
        }

        if let Some(body) = &self.body {
            p.field("Body", body)?;
        }

        p.field("Timeout", format!("{}ms", self.timeout_ms))?;

        write!(f, "{s}")
    }
}

#[derive(Subcommand, Debug)]
pub enum FuzzMode {
    /// Fuzz an HTTP(S) target: URL, headers, and/or body may contain FUZZ keywords
    Http(HttpFuzzArgs),
}

impl FuzzMode {
    fn into_protocol(self) -> Box<dyn FuzzProtocol> {
        match self {
            FuzzMode::Http(args) => Box::new(args),
        }
    }
}

impl fmt::Display for FuzzMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzMode::Http(args) => args.display(f),
        }
    }
}

#[derive(Args, Debug)]
pub struct FuzzArgs {
    #[command(subcommand)]
    pub mode: FuzzMode,
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

pub fn handle_fuzz(mode: FuzzMode) {
    let proto = mode.into_protocol();

    // Cloned out before build_target() consumes `proto`.
    let fuzz_args = proto.fuzz_args().clone();
    let general = proto.general().clone();

    let lists = match keywords::load_wordlists(&fuzz_args.fuzz_lists, general.filter) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{RED}error loading wordlists: {e}{RESET}");
            return;
        }
    };

    let combine_mode = fuzz_args.combine_mode;
    let total = keywords::total_items(combine_mode, &lists);
    if total == 0 {
        eprintln!("{RED}no work items produced (empty wordlist combination){RESET}");
        return;
    }

    let target: Arc<dyn FuzzTarget> = match proto.build_target() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{RED}error configuring target: {e}{RESET}");
            return;
        }
    };

    OUTPUT_HANDLER
        .lock()
        .unwrap()
        .set_formats(general.output_format.clone());

    let threads = general.threads.max(1);
    let delay = Duration::from_millis(fuzz_args.delay_ms);
    let pb = create_progress(total);
    let index = Arc::new(AtomicU64::new(0));

    let ctx = Arc::new(WorkerContext {
        combine_mode,
        lists: Arc::new(lists),
        target,
        filter: ReportFilter {
            match_codes: Arc::new(fuzz_args.match_codes),
            filter_codes: Arc::new(fuzz_args.filter_codes),
            filter_sizes: Arc::new(fuzz_args.filter_sizes),
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
            OUTPUT_HANDLER.lock().unwrap().write_fuzz(
                sub_label(&sub).as_str(),
                &status.to_string(),
                size,
                elapsed_ms,
            );
        }

        pb.inc(1);

        if !delay.is_zero() {
            thread::sleep(delay);
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
