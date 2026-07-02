use std::{
    fmt,
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum OutputFormat {
    Json,
    Csv,
    Text,
    Html,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Csv => write!(f, "csv"),
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Html => write!(f, "html"),
        }
    }
}

/// A single recorded result. Each variant only carries the fields that
/// actually apply to it — no `Option`s that might be unexpectedly unset.
enum OutputEntry {
    Hash {
        hash: String,
        word: String,
    },
    Login {
        username: String,
        password: String,
    },
    Fuzzing {
        sub_label: String,
        status: String,
        size: u64,
        elapsed_ms: u128,
    },
}

impl OutputEntry {
    fn headers(&self) -> &'static [&'static str] {
        match self {
            OutputEntry::Hash { .. } => &["Hash", "Word"],
            OutputEntry::Login { .. } => &["Username", "Password"],
            OutputEntry::Fuzzing { .. } => &["Sub Label", "Status", "Size", "Elapsed (ms)"],
        }
    }

    /// Field values for this entry, in the same order as `headers()`.
    fn values(&self) -> Vec<String> {
        match self {
            OutputEntry::Hash { hash, word } => vec![hash.clone(), word.clone()],
            OutputEntry::Login { username, password } => {
                vec![username.clone(), password.clone()]
            }
            OutputEntry::Fuzzing {
                sub_label,
                status,
                size,
                elapsed_ms,
            } => vec![
                sub_label.clone(),
                status.clone(),
                size.to_string(),
                elapsed_ms.to_string(),
            ],
        }
    }
}

pub struct OutputHandler {
    formats: Vec<OutputFormat>,
    entries: Vec<OutputEntry>,
    started_at: SystemTime,
}

impl OutputHandler {
    pub fn new() -> Self {
        Self {
            formats: Vec::new(),
            entries: Vec::new(),
            started_at: SystemTime::now(),
        }
    }

    pub fn set_formats(&mut self, formats: Vec<OutputFormat>) {
        self.formats = formats;
    }

    pub fn write_hash(&mut self, hash: &str, word: &str) {
        self.entries.push(OutputEntry::Hash {
            hash: hash.to_string(),
            word: word.to_string(),
        });
    }

    pub fn write_login(&mut self, username: &str, password: &str) {
        self.entries.push(OutputEntry::Login {
            username: username.to_string(),
            password: password.to_string(),
        });
    }

    pub fn write_fuzz(&mut self, sub_label: &str, status: &str, size: u64, elapsed_ms: u128) {
        self.entries.push(OutputEntry::Fuzzing {
            sub_label: sub_label.to_string(),
            status: status.to_string(),
            size,
            elapsed_ms,
        });
    }

    pub fn save_to_files(&self) {
        for format in &self.formats {
            match format {
                OutputFormat::Json => self.save_json(),
                OutputFormat::Csv => self.save_csv(),
                OutputFormat::Text => self.save_text(),
                OutputFormat::Html => self.save_html(),
            }
        }
    }

    fn save_json(&self) {
        // unchanged — JSON is key-value per record, so there's no "empty column" issue here.
        let content = "[\n".to_string()
            + &self
                .entries
                .iter()
                .map(|entry| match entry {
                    OutputEntry::Hash { hash, word } => format!(
                        "  {{\"hash\": \"{}\", \"word\": \"{}\"}}",
                        Self::escape_json(hash),
                        Self::escape_json(word)
                    ),
                    OutputEntry::Login { username, password } => format!(
                        "  {{\"username\": \"{}\", \"password\": \"{}\"}}",
                        Self::escape_json(username),
                        Self::escape_json(password)
                    ),
                    OutputEntry::Fuzzing { sub_label, status, size, elapsed_ms } => format!(
                        "  {{\"sub_label\": \"{}\", \"status\": \"{}\", \"size\": {}, \"elapsed_ms\": {}}}",
                        Self::escape_json(sub_label),
                        Self::escape_json(status),
                        size,
                        elapsed_ms
                    ),
                })
                .collect::<Vec<String>>()
                .join(",\n")
            + "\n]";

        self.write_file("keysweep_output.json", content);
    }

    fn save_csv(&self) {
        // Header (and therefore column count) is decided by which kind is
        // present. Assumes a single run only ever writes one kind — see note below.
        let header = self
            .entries
            .first()
            .map(|e| {
                e.headers()
                    .iter()
                    .map(|h| h.to_lowercase().replace(' ', "_"))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|| "hash,word".to_string());

        let content = header
            + "\n"
            + &self
                .entries
                .iter()
                .map(|e| e.values().join(","))
                .collect::<Vec<String>>()
                .join("\n");

        self.write_file("keysweep_output.csv", content);
    }

    fn save_text(&self) {
        // unchanged
        let content = self
            .entries
            .iter()
            .map(|entry| match entry {
                OutputEntry::Hash { hash, word } => {
                    format!("Hash: {hash} | Word: {word}")
                }
                OutputEntry::Login { username, password } => {
                    format!("Username: {username} | Password: {password}")
                }
                OutputEntry::Fuzzing { sub_label, status, size, elapsed_ms } => {
                    format!("Sub Label: {sub_label} | Status: {status} | Size: {size} | Elapsed: {elapsed_ms}ms")
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        self.write_file("keysweep_output.txt", content);
    }

    fn save_html(&self) {
        let content = self.build_html_content();
        self.write_file("keysweep_output.html", content);
    }

    /// Shared "write to cwd, print where it went" tail used by every format.
    fn write_file(&self, filename: &str, content: String) {
        let path = std::env::current_dir().unwrap().join(filename);
        println!("Output: {}", path.display());
        std::fs::write(&path, content)
            .unwrap_or_else(|e| panic!("Failed to write to {filename}: {e}"));
    }

    fn build_html_content(&self) -> String {
        let started_at = Self::format_timestamp(self.started_at);
        let generated_at = Self::format_timestamp(SystemTime::now());
        let elapsed = SystemTime::now()
            .duration_since(self.started_at)
            .unwrap_or_default();
        let elapsed_text = Self::format_duration(elapsed);
        let result_count = self.entries.len();

        let default_headers: &[&str] = &["Hash", "Word"];
        let headers = self
            .entries
            .first()
            .map(OutputEntry::headers)
            .unwrap_or(default_headers);

        let header_row = headers
            .iter()
            .map(|h| format!("<th>{h}</th>"))
            .collect::<Vec<_>>()
            .join("\n            ");

        let rows = if self.entries.is_empty() {
            format!(
                "<tr><td colspan=\"{}\">No matches were found.</td></tr>",
                headers.len()
            )
        } else {
            self.entries
                .iter()
                .map(|entry| {
                    let cells = entry
                        .values()
                        .iter()
                        .map(|v| format!("<td>{}</td>", Self::escape_html(v)))
                        .collect::<String>();
                    format!("<tr>{cells}</tr>")
                })
                .collect::<Vec<String>>()
                .join("\n")
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keysweep Output</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; }}
        .summary {{ background: #f5f5f5; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
        th {{ background: #eee; }}
    </style>
</head>
<body>
    <h1>Keysweep Output</h1>
    <div class="summary">
        <p><strong>Started:</strong> {started_at}</p>
        <p><strong>Generated:</strong> {generated_at}</p>
        <p><strong>Elapsed:</strong> {elapsed_text}</p>
        <p><strong>Results:</strong> {result_count}</p>
    </div>
    <table>
        <tr>
            {header_row}
        </tr>
        {rows}
    </table>
</body>
</html>"#
        )
    }

    fn escape_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn escape_json(input: &str) -> String {
        input
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }

    fn format_timestamp(timestamp: SystemTime) -> String {
        let duration = timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let total_seconds = duration.as_secs();
        let seconds_in_day = total_seconds % 86_400;
        let hours = seconds_in_day / 3600;
        let minutes = (seconds_in_day % 3600) / 60;
        let seconds = seconds_in_day % 60;

        let mut days = total_seconds / 86_400;
        let mut year = 1970u64;
        while days >= Self::days_in_year(year) {
            days -= Self::days_in_year(year);
            year += 1;
        }

        let mut month = 1u64;
        while days >= Self::days_in_month(year, month) {
            days -= Self::days_in_month(year, month);
            month += 1;
        }

        let day = days + 1;

        format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
    }

    fn days_in_year(year: u64) -> u64 {
        if Self::is_leap_year(year) { 366 } else { 365 }
    }

    fn days_in_month(year: u64, month: u64) -> u64 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if Self::is_leap_year(year) => 29,
            2 => 28,
            _ => 0,
        }
    }

    fn is_leap_year(year: u64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }
}

pub static OUTPUT_HANDLER: LazyLock<Mutex<OutputHandler>> =
    LazyLock::new(|| Mutex::new(OutputHandler::new()));
