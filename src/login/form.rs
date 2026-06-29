use std::sync::Arc;

use reqwest::header::CONTENT_TYPE;

use crate::{
    bypass::ip::IpSpoofer, login::LoginParams, utils::warn, wordlists_iterator::login_iterator,
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
    let spoofer = if let Some(spoof_nb) = form_params.spoof {
        let mut s = IpSpoofer::new();
        s.generate_ip(spoof_nb);
        Some(Arc::new(s))
    } else {
        None
    };

    let user_field = form_params.user_field;
    let pass_field = form_params.pass_field;
    let invalid_text = form_params.invalid_text;

    if invalid_text.is_empty() {
        warn("Invalid Text is empty.");
    }
    let form_auth = move |user: &str, pass: &str| -> bool {
        // use a blocking client so we can run synchronously from main
        let mut builder = form_params
            .client
            .post(&form_params.url)
            .header(CONTENT_TYPE, "text/html");

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

    let result = login_iterator(
        login_params.users,
        login_params.passwords,
        login_params.threads,
        form_auth,
    );

    if let Err(err) = result {
        eprintln!("{err}");
    }
}
