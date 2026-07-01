use std::sync::Arc;

use crate::theme::{BG_YELLOW, GRAY, RESET, YELLOW};
use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress(total: u64) -> Arc<ProgressBar> {
    let pb = Arc::new(ProgressBar::new(total));

    pb.set_style(
        ProgressStyle::with_template(&format!(
            "{{spinner:.gray}} {GRAY}[{{elapsed_precise}}]{RESET} \
         ▕{{bar:45.green/red}}▏ \
         {{percent:>3}}% \
         {GRAY}({{pos}}/{{len}}){RESET} \
         {GRAY}|{RESET} {{per_sec}} \
         {GRAY}| ETA {{eta_precise}}{RESET}",
        ))
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ ")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    pb
}

pub fn warn(text: &str) {
    println!("{BG_YELLOW}[Warn]{RESET} {YELLOW}{text}{RESET}");
}
