use std::collections::HashMap;
use std::time::Instant;

use reqwest::blocking::Client;

use super::{FireResult, FuzzTarget};
use crate::fuzz::keywords::{self, Substitution};

/// HTTP(S) fuzz target. Substitution keywords may appear in the URL, in header
/// values, or in the request body — `apply` runs on each independently.
pub struct HttpTarget {
    client: Client,
    url_template: String,
    method: String,
    header_templates: Vec<(String, String)>,
    body_template: Option<String>,
}

impl HttpTarget {
    pub fn new(
        url_template: String,
        method: String,
        header_templates: Vec<(String, String)>,
        body_template: Option<String>,
        timeout: std::time::Duration,
    ) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        Ok(Self {
            client,
            url_template,
            method,
            header_templates,
            body_template,
        })
    }

    fn error_result(elapsed_ms: u128, message: String) -> FireResult {
        FireResult {
            status: 0,
            size: 0,
            elapsed_ms,
            label: "ERR".to_string(),
            error: Some(message),
        }
    }
}

impl FuzzTarget for HttpTarget {
    fn fire(&self, sub: &Substitution) -> FireResult {
        let target_url = keywords::apply(&self.url_template, sub);

        let mut builder = match self.method.to_uppercase().as_str() {
            "GET" => self.client.get(&target_url),
            "POST" => self.client.post(&target_url),
            "HEAD" => self.client.head(&target_url),
            "PUT" => self.client.put(&target_url),
            "DELETE" => self.client.delete(&target_url),
            "PATCH" => self.client.patch(&target_url),
            other => return Self::error_result(0, format!("unsupported method: {other}")),
        };

        for (name, value_template) in &self.header_templates {
            builder = builder.header(name, keywords::apply(value_template, sub));
        }

        if let Some(body_template) = &self.body_template {
            builder = builder.body(keywords::apply(body_template, sub));
        }

        let start = Instant::now();
        match builder.send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let elapsed_ms = start.elapsed().as_millis();
                // Read the body for accurate size — content-length isn't always
                // sent (e.g. chunked responses), and filtering needs the real size.
                let size = resp.bytes().map(|b| b.len() as u64).unwrap_or(0);

                FireResult {
                    status,
                    size,
                    elapsed_ms,
                    label: status.to_string(),
                    error: None,
                }
            }
            Err(e) => Self::error_result(start.elapsed().as_millis(), e.to_string()),
        }
    }

    fn protocol_name(&self) -> &'static str {
        "HTTP"
    }
}

/// Parse `-H "Name: ValueTemplate"` CLI args into (name, value) pairs.
pub fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for h in raw {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| format!("invalid header '{h}', expected 'Name: Value'"))?;
        out.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(out)
}

/// Convenience: dedupe/validate headers map for display purposes.
pub fn headers_to_map(headers: &[(String, String)]) -> HashMap<String, String> {
    headers.iter().cloned().collect()
}
