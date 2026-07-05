use crate::{
    login::LoginParams,
    outputs::OUTPUT_HANDLER,
    theme::{GREEN, RESET},
    wordlists_iterator::run_search,
};
use base64::{Engine as _, engine::general_purpose};

pub fn brute_basic_auth(login_params: LoginParams, url: String, client: reqwest::blocking::Client) {
    let submit = |user: &str, pass: &str| -> bool {
        let res = client
            .get(&url)
            .header(
                "Authorization",
                format!(
                    "Basic {}",
                    general_purpose::STANDARD.encode(format!("{user}:{pass}"))
                ),
            )
            .send();

        match res {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    };

    let make_validator = |user: &str| {
        let user = user.to_owned();
        move |pass: &str| submit(&user, pass)
    };

    let report = |user: &str, pass: &str| {
        OUTPUT_HANDLER.lock().unwrap().write_login(user, pass);
        format!(
            "[{GREEN}Basic Auth{RESET}] Username: {GREEN}{user}{RESET} Password: {GREEN}{pass}{RESET}"
        )
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
