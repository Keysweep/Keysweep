use std::fmt;

#[derive(Clone)]
pub enum CredentialSource {
    Single(String),
    Wordlist(String), // path
}

impl CredentialSource {
    pub fn from_pair(single: Option<String>, list: Option<String>) -> Self {
        match (single, list) {
            (Some(v), None) => Self::Single(v),
            (None, Some(p)) => Self::Wordlist(p),
            _ => unreachable!("Keysweep enforces exactly one of these two args"),
        }
    }
}

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialSource::Single(v) => write!(f, "{}", v),
            CredentialSource::Wordlist(p) => write!(f, "{}", p),
        }
    }
}
