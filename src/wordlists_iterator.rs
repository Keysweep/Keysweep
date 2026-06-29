use indicatif::ProgressBar;

use crate::CredentialSource;
use crate::shared::args::GeneralArgs;
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
    threads: usize,
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
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        }
    });

    let user_count = match &users {
        CredentialSource::Single(_) => 1,
        CredentialSource::Wordlist(path) => {
            BufReader::new(File::open(path).map_err(|e| e.to_string())?)
                .lines()
                .count() as u64
        }
    };

    let total = user_count * passwords.len() as u64;
    let pb = create_progress(total);

    match users {
        CredentialSource::Single(user) => {
            try_passwords(&user, passwords, pb.clone(), validator, threads)
                .map_err(|e| e.to_string())?;
        }

        CredentialSource::Wordlist(path) => {
            let (tx, rx) = bounded::<String>(threads * 2);
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

            let mut workers = Vec::with_capacity(threads);

            for _ in 0..threads {
                let rx = rx.clone();
                let passwords = passwords.clone();
                let validator = validator.clone();
                let pb = pb.clone();

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
                            threads,
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
    threads: usize,
) -> std::io::Result<()>
where
    F: Fn(&str, &str) -> bool + Send + Sync + 'static,
{
    let found = Arc::new(AtomicBool::new(false));
    let index = Arc::new(AtomicUsize::new(0));
    let user = Arc::new(user.to_owned());

    let mut workers = Vec::with_capacity(threads);

    for _ in 0..threads {
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

    let words = Arc::new(
        BufReader::new(File::open(&wordlist).map_err(|e| e.to_string())?)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?,
    );

    let word_count = words.len() as u64;

    let hash_count = match &hashes {
        CredentialSource::Single(_) => 1,
        CredentialSource::Wordlist(path) => {
            BufReader::new(File::open(path).map_err(|e| e.to_string())?)
                .lines()
                .count() as u64
        }
    };

    let total = hash_count * word_count;

    let pb = create_progress(total);
    match hashes {
        CredentialSource::Single(hash) => {
            try_hashes(&hash, words, pb.clone(), validator, general_args)
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
                let words = words.clone();
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
                            words.clone(),
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
    words: Arc<Vec<String>>,
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
        let words = words.clone();
        let hash = hash.clone();
        let pb = pb.clone();
        let params = general_args.clone();
        let hash_bytes = hash_bytes.clone();

        workers.push(thread::spawn(move || {
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                let i = index.fetch_add(1, Ordering::Relaxed);
                if i >= words.len() {
                    break;
                }

                let word = &words[i];

                if params.skip_empty && word.is_empty() {
                    continue;
                }

                if let Some(min) = params.min_len
                    && word.len() < min
                {
                    continue;
                }

                if let Some(max) = params.max_len
                    && word.len() > max
                {
                    continue;
                }

                pb.inc(1);

                if validator(hash_bytes.as_deref(), &hash, word) {
                    pb.println(format!(
                        "[{GREEN}+{RESET}] Hash: {GREEN}{hash}{RESET} Word: {GREEN}{word}{RESET}",
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
