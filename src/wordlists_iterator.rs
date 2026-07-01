use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use indicatif::ProgressBar;

use crate::credentials::CredentialSource;
use crate::shared::args::{GeneralArgs, WordlistFilter};
use crate::shared::line_validation::is_valid_line;
use crate::utils::create_progress;

fn filtered_lines(
    path: &str,
    filter: &WordlistFilter,
) -> Result<impl Iterator<Item = String>, String> {
    let file = File::open(path).map_err(|e| format!("failed to open {path}: {e}"))?;
    let filter = filter.clone();
    Ok(BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(move |line| is_valid_line(line, filter.clone())))
}

fn read_filtered_lines(path: &str, filter: &WordlistFilter) -> Result<Vec<String>, String> {
    Ok(filtered_lines(path, filter)?.collect())
}

fn count_filtered_lines(path: &str, filter: &WordlistFilter) -> Result<u64, String> {
    Ok(filtered_lines(path, filter)?.count() as u64)
}

/// Search `candidates` for a single `target`, spread across up to `threads`
/// scoped workers. Stops as soon as any worker finds a match, printing
/// `report(target, candidate)` via the progress bar at most once.
fn search_one(
    target: &str,
    candidates: &[String],
    threads: usize,
    pb: &ProgressBar,
    validate: &(impl Fn(&str) -> bool + Sync),
    report: &(impl Fn(&str, &str) -> String + Sync),
) {
    let found = AtomicBool::new(false);
    let index = AtomicUsize::new(0);

    thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                loop {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }

                    let i = index.fetch_add(1, Ordering::Relaxed);
                    let Some(candidate) = candidates.get(i) else {
                        return;
                    };

                    pb.inc(1);

                    if validate(candidate) {
                        pb.println(report(target, candidate));
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });
}

/// Brute-force `candidates` against every item in `targets` — e.g. every
/// password against every username, or every wordlist entry against every
/// hash.
///
/// The `threads` budget is spent at whichever level actually has more than
/// one item to parallelize:
/// - a single target searches `candidates` with the full thread pool.
/// - multiple targets (a wordlist) are each handed to one worker, so the
///   pool is spread across targets instead of nested per-target, avoiding a
///   `threads` blow-up in OS threads.
///
/// `make_validator` runs once per target, so callers can precompute
/// per-target state (e.g. decoding a hash's hex once) instead of repeating
/// it for every candidate. `report` formats the message printed on a match.
pub fn run_search<F, V>(
    targets: CredentialSource,
    candidates: CredentialSource,
    general_args: GeneralArgs,
    make_validator: F,
    report: impl Fn(&str, &str) -> String + Sync,
) -> Result<(), String>
where
    F: Fn(&str) -> V + Sync,
    V: Fn(&str) -> bool + Sync,
{
    let candidates = match candidates {
        CredentialSource::Single(word) => vec![word],
        CredentialSource::Wordlist(path) => read_filtered_lines(&path, &general_args.filter)?,
    };

    let target_count = match &targets {
        CredentialSource::Single(_) => 1,
        CredentialSource::Wordlist(path) => count_filtered_lines(path, &general_args.filter)?,
    };

    let total = target_count * candidates.len() as u64;
    let pb = create_progress(total);
    let threads = general_args.threads.max(1);

    match targets {
        CredentialSource::Single(target) => {
            let validate = make_validator(&target);
            search_one(&target, &candidates, threads, &pb, &validate, &report);
        }

        CredentialSource::Wordlist(path) => {
            let (tx, rx) = crossbeam_channel::bounded::<String>(threads * 2);
            let filter = general_args.filter.clone();

            thread::scope(|scope| {
                scope.spawn(move || {
                    let Ok(file) = File::open(&path) else { return };

                    for line in BufReader::new(file).lines().map_while(Result::ok) {
                        if !is_valid_line(&line, filter.clone()) {
                            continue;
                        }
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                });

                for _ in 0..threads {
                    let rx = rx.clone();
                    // Re-borrow the shared, non-'static state so `move` below
                    // only takes ownership of these cheap references (plus
                    // this worker's own `rx`), not the originals.
                    let make_validator = &make_validator;
                    let candidates = &candidates;
                    let pb = &pb;
                    let report = &report;

                    scope.spawn(move || {
                        while let Ok(target) = rx.recv() {
                            let validate = make_validator(&target);
                            search_one(&target, candidates, 1, pb, &validate, report);
                        }
                    });
                }
            });
        }
    }

    pb.finish_with_message("Done");
    Ok(())
}
