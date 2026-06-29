use crate::fuzz::keywords::Substitution;

pub mod http;

#[derive(Debug, Clone)]
pub struct FireResult {
    /// Protocol-specific status signal: HTTP status code, or a synthetic code
    pub status: u16,
    /// Size of the response payload in bytes.
    pub size: u64,
    /// Round-trip time for the probe.
    pub elapsed_ms: u128,
    /// Human-readable label shown in output instead of a raw status code,
    pub label: String,
    /// Error string if the probe failed outright (connection refused, timeout, etc).
    pub error: Option<String>,
}

pub trait FuzzTarget: Send + Sync {
    fn fire(&self, sub: &Substitution) -> FireResult;

    /// Display name for banners/logging, e.g. "HTTP" or "TCP".
    fn protocol_name(&self) -> &'static str;
}
