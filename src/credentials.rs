use std::fmt;

#[derive(Clone)]
pub enum CredentialSource {
    Single(String),
    Wordlist(String), // path
}

impl CredentialSource {
    pub fn from_pair(single: Option<String>, list: Option<String>) -> Result<Self, String> {
        match (single, list) {
            (Some(v), None) => Ok(Self::Single(v)),
            (None, Some(p)) => Ok(Self::Wordlist(p)),
            (Some(_), Some(_)) => {
                Err("Provide either a single credential or a wordlist path, not both".to_string())
            }
            (None, None) => Err(
                "Provide exactly one credential source: single value or wordlist path".to_string(),
            ),
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
