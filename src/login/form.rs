use reqwest::header::CONTENT_TYPE;

use crate::{
    bypass::ip::IpSpoofer,
    login::LoginParams,
    outputs::OUTPUT_HANDLER,
    theme::{GREEN, RESET},
    utils::warn,
    wordlists_iterator::run_search,
};

pub struct FormParams {
    pub client: reqwest::blocking::Client,
    pub url: String,
    pub user_field: String,
    pub pass_field: String,
    pub invalid_text: Vec<String>,
    pub spoof: Option<u32>,
}

pub fn brute_form(login_params: LoginParams, form_params: FormParams) {
    let spoofer = form_params.spoof.map(|count| {
        let mut s = IpSpoofer::new();
        s.generate_ip(count);
        s
    });

    let client = form_params.client;
    let url = form_params.url;
    let user_field = form_params.user_field;
    let pass_field = form_params.pass_field;
    let invalid_text = form_params.invalid_text;

    if invalid_text.is_empty() {
        warn("Invalid Text is empty.");
    }

    // Submit one (user, pass) attempt; use a blocking client so we can run
    // synchronously from the worker threads in `search::run_search`.
    let submit = |user: &str, pass: &str| -> bool {
        let mut builder = client.post(&url).header(CONTENT_TYPE, "text/html");

        if let Some(spoofer) = &spoofer {
            builder = builder.header("X-Forwarded-For", spoofer.select_ip());
        }

        let res = builder
            .body(format!("{user_field}={user}&{pass_field}={pass}"))
            .send();

        match res {
            Ok(r) => {
                let text = r.text().unwrap_or_default();
                !invalid_text.iter().any(|invalid| text.contains(invalid))
            }
            Err(_) => false,
        }
    };

    let make_validator = |user: &str| {
        let user = user.to_owned();
        move |pass: &str| submit(&user, pass)
    };

    let report = |user: &str, pass: &str| {
        OUTPUT_HANDLER.lock().unwrap().write_login(user, pass);
        format!("[{GREEN}+{RESET}] Username: {GREEN}{user}{RESET} Password: {GREEN}{pass}{RESET}")
    };

    let result = run_search(
        login_params.users,
        login_params.passwords,
        login_params.general_args,
        make_validator,
        report,
    );

    if let Err(err) = result {
        eprintln!("{err}");
    }
}
