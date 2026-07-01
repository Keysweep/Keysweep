use indicatif::ProgressBar;

use crate::CredentialSource;
use crate::shared::args::GeneralArgs;
use crate::shared::line_validation::is_valid_line;
use crate::utils::create_progress;
use crate::{GREEN, RESET};
use crossbeam_channel::bounded;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    thread,
};
pub fn login_iterator<F>(
    users: CredentialSource,
    passwords: CredentialSource,
    general_args: GeneralArgs,
    validator: F,
) -> Result<(), String>
where
    F: Fn(&str, &str) -> bool + Send + Sync + 'static,
{
    let validator = Arc::new(validator);

    // Load passwords once.
    let passwords = Arc::new(match passwords {
        CredentialSource::Single(pass) => vec![pass],
        CredentialSource::Wordlist(path) => {
            BufReader::new(File::open(path).map_err(|e| e.to_string())?)
                .lines()
                .map_while(Result::ok)
                .filter(|line| is_valid_line(line, general_args.filter.clone()))
                .collect::<Vec<_>>()
        }
    });

    let user_count = match &users {
        CredentialSource::Single(_) => 1,
        CredentialSource::Wordlist(path) => {
            BufReader::new(File::open(path).map_err(|e| e.to_string())?)
                .lines()
                .map_while(Result::ok)
                .filter(|line| is_valid_line(line, general_args.filter.clone()))
                .count() as u64
        }
    };

    let total = user_count * passwords.len() as u64;
    let pb = create_progress(total);

    match users {
        CredentialSource::Single(user) => {
            try_passwords(&user, passwords, pb.clone(), validator, general_args)
                .map_err(|e| e.to_string())?;
        }

        CredentialSource::Wordlist(path) => {
            let (tx, rx) = bounded::<String>(general_args.threads * 2);
            let rx = Arc::new(std::sync::Mutex::new(rx));

            // Producer
            {
                let tx = tx.clone();

                thread::spawn(move || {
                    let file = File::open(path).ok()?;
                    let reader = BufReader::new(file);

                    for line in reader.lines().map_while(Result::ok) {
                        let _ = tx.send(line);
                    }

                    Some(())
                });
            }

            drop(tx);

            let mut workers = Vec::with_capacity(general_args.threads);

            for _ in 0..general_args.threads {
                let rx = rx.clone();
                let passwords = passwords.clone();
                let validator = validator.clone();
                let pb = pb.clone();
                let general_args = general_args.clone();

                workers.push(thread::spawn(move || {
                    loop {
                        let user = {
                            let lock = rx.lock().unwrap();
                            lock.recv().ok()
                        };

                        let user = match user {
                            Some(user) => user,
                            None => break,
                        };

                        let _ = try_passwords(
                            &user,
                            passwords.clone(),
                            pb.clone(),
                            validator.clone(),
                            general_args.clone(),
                        );
                    }
                }));
            }

            for worker in workers {
                worker.join().unwrap();
            }
        }
    }

    pb.finish_with_message("Done");

    Ok(())
}

pub fn try_passwords<F>(
    user: &str,
    passwords: Arc<Vec<String>>,
    pb: Arc<ProgressBar>,
    validator: Arc<F>,
    general_args: GeneralArgs,
) -> std::io::Result<()>
where
    F: Fn(&str, &str) -> bool + Send + Sync + 'static,
{
    let found = Arc::new(AtomicBool::new(false));
    let index = Arc::new(AtomicUsize::new(0));
    let user = Arc::new(user.to_owned());

    let mut workers = Vec::with_capacity(general_args.threads);

    for _ in 0..general_args.threads {
        let found = found.clone();
        let index = index.clone();
        let passwords = passwords.clone();
        let validator = validator.clone();
        let pb = pb.clone();
        let user = user.clone();

        workers.push(thread::spawn(move || {
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                let i = index.fetch_add(1, Ordering::Relaxed);
                if i >= passwords.len() {
                    break;
                }

                let pass = &passwords[i];

                pb.inc(1);

                if validator(&user, pass) {
                    pb.println(format!(
                        "[{GREEN}+{RESET}] Username: {GREEN}{user}{RESET} Password: {GREEN}{pass}{RESET}"
                    ));

                    found.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }));
    }

    for worker in workers {
        worker.join().unwrap();
    }

    Ok(())
}

pub fn hash_iterator<F>(
    hashes: CredentialSource,
    wordlist: String,
    general_args: GeneralArgs,
    validator: F,
) -> Result<(), String>
where
    F: Fn(Option<&[u8]>, &str, &str) -> bool + Send + Sync + 'static,
{
    let validator = Arc::new(validator);

    let lines = Arc::new(
        BufReader::new(File::open(&wordlist).map_err(|e| e.to_string())?)
            .lines()
            .map_while(Result::ok)
            .filter(|line| is_valid_line(line, general_args.filter.clone()))
            .collect::<Vec<_>>(),
    );

    let line_count = lines.len() as u64;

    let hash_count = match &hashes {
        CredentialSource::Single(_) => 1,
        CredentialSource::Wordlist(path) => {
            BufReader::new(File::open(path).map_err(|e| e.to_string())?)
                .lines()
                .count() as u64
        }
    };

    let total = hash_count * line_count;

    let pb = create_progress(total);
    match hashes {
        CredentialSource::Single(hash) => {
            try_hashes(&hash, lines, pb.clone(), validator, general_args)
                .map_err(|e| e.to_string())?;
        }

        CredentialSource::Wordlist(hashes_path) => {
            let (tx, rx) = bounded::<String>(general_args.threads * 2);
            let rx = Arc::new(std::sync::Mutex::new(rx));

            // producer
            {
                let tx = tx.clone();
                thread::spawn(move || {
                    let file = File::open(hashes_path).ok()?;
                    let reader = BufReader::new(file);

                    for line in reader.lines().map_while(Result::ok) {
                        let _ = tx.send(line);
                    }
                    Some(())
                });
            }

            drop(tx);

            let mut workers = Vec::with_capacity(general_args.threads);

            for _ in 0..general_args.threads {
                let rx = rx.clone();
                let lines = lines.clone();
                let validator = validator.clone();
                let pb = pb.clone();
                let general_args = general_args.clone();

                workers.push(thread::spawn(move || {
                    loop {
                        let hash = {
                            let lock = rx.lock().unwrap();
                            lock.recv().ok()
                        };

                        let hash = match hash {
                            Some(h) => h,
                            None => break,
                        };

                        let _ = try_hashes(
                            &hash,
                            lines.clone(),
                            pb.clone(),
                            validator.clone(),
                            general_args.clone(),
                        );
                    }
                }));
            }

            for w in workers {
                w.join().unwrap();
            }
        }
    }

    pb.finish_with_message("Done");
    Ok(())
}

pub fn try_hashes<F>(
    hash: &str,
    lines: Arc<Vec<String>>,
    pb: Arc<ProgressBar>,
    validator: Arc<F>,
    general_args: GeneralArgs,
) -> std::io::Result<()>
where
    F: Fn(Option<&[u8]>, &str, &str) -> bool + Send + Sync + 'static,
{
    let found = Arc::new(AtomicBool::new(false));
    let index = Arc::new(AtomicUsize::new(0));
    let hash_bytes = Arc::new(hex::decode(hash).ok());
    let hash = Arc::new(hash.to_owned());

    let mut workers = Vec::with_capacity(general_args.threads);

    for _ in 0..general_args.threads {
        let found = found.clone();
        let index = index.clone();
        let validator = validator.clone();
        let lines = lines.clone();
        let hash = hash.clone();
        let pb = pb.clone();
        let hash_bytes = hash_bytes.clone();

        workers.push(thread::spawn(move || {
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                let i = index.fetch_add(1, Ordering::Relaxed);
                if i >= lines.len() {
                    break;
                }

                let line = &lines[i];

                pb.inc(1);

                if validator(hash_bytes.as_deref(), &hash, line) {
                    pb.println(format!(
                        "[{GREEN}+{RESET}] Hash: {GREEN}{hash}{RESET} Word: {GREEN}{line}{RESET}",
                    ));

                    found.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }));
    }

    for w in workers {
        w.join().unwrap();
    }

    Ok(())
}
