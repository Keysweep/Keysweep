use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;

/// Error type for keyword/wordlist parsing. A plain `String` won't satisfy
/// clap's derived `value_parser`, which requires `FromStr::Err: std::error::Error`.
#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

impl From<String> for ParseError {
    fn from(s: String) -> Self {
        ParseError(s)
    }
}

/// How multiple wordlists/keywords are combined into a stream of substitutions.
///
/// - `clusterbomb`: cartesian product of all wordlists (every combination)
/// - `pitchfork`: zipped, index-aligned (wordlist[i] for each keyword at position i)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CombineMode {
    #[default]
    Clusterbomb,
    Pitchfork,
}

impl FromStr for CombineMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "clusterbomb" => Ok(CombineMode::Clusterbomb),
            "pitchfork" => Ok(CombineMode::Pitchfork),
            other => Err(ParseError(format!(
                "unknown combine mode '{other}', expected 'clusterbomb' or 'pitchfork'"
            ))),
        }
    }
}

/// A single `-w path/to/list.txt:KEYWORD` binding from the CLI.
#[derive(Debug, Clone)]
pub struct WordlistBinding {
    pub keyword: String,
    pub path: String,
}

impl FromStr for WordlistBinding {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept "path:KEYWORD" or bare "path" (defaults to FUZZ).
        match s.rsplit_once(':') {
            Some((path, keyword)) if !keyword.is_empty() && looks_like_keyword(keyword) => {
                Ok(WordlistBinding {
                    keyword: keyword.to_string(),
                    path: path.to_string(),
                })
            }
            _ => Ok(WordlistBinding {
                keyword: "FUZZ".to_string(),
                path: s.to_string(),
            }),
        }
    }
}

impl fmt::Display for WordlistBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.path, self.keyword)
    }
}

/// Heuristic: keywords are short, uppercase-ish tokens like FUZZ, FUZ2Z, USERFUZZ.
/// This avoids misparsing Windows-style paths (`C:\wordlists\x.txt`) as a keyword.
fn looks_like_keyword(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A loaded wordlist tied to its keyword.
pub struct LoadedWordlist {
    pub keyword: String,
    pub words: Arc<Vec<String>>,
}

pub fn load_wordlists(bindings: &[WordlistBinding]) -> Result<Vec<LoadedWordlist>, String> {
    let mut seen = HashMap::new();
    let mut out = Vec::with_capacity(bindings.len());

    for b in bindings {
        if let Some(prev) = seen.insert(b.keyword.clone(), b.path.clone()) {
            if prev != b.path {
                return Err(format!(
                    "keyword '{}' is bound to two different wordlists ('{}' and '{}')",
                    b.keyword, prev, b.path
                ));
            }
        }

        let file = File::open(&b.path).map_err(|e| format!("failed to open {}: {e}", b.path))?;
        let words: Vec<String> = BufReader::new(file)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to read {}: {e}", b.path))?
            .into_iter()
            .filter(|l| !l.is_empty())
            .collect();

        if words.is_empty() {
            return Err(format!("wordlist {} is empty", b.path));
        }

        out.push(LoadedWordlist {
            keyword: b.keyword.clone(),
            words: Arc::new(words),
        });
    }

    Ok(out)
}

/// A single concrete substitution: keyword -> chosen word, for one work item.
pub type Substitution = HashMap<String, Arc<str>>;

/// Total number of work items a combine mode will produce for the given wordlists.
pub fn total_items(mode: CombineMode, lists: &[LoadedWordlist]) -> u64 {
    match mode {
        CombineMode::Clusterbomb => lists.iter().map(|l| l.words.len() as u64).product(),
        CombineMode::Pitchfork => lists
            .iter()
            .map(|l| l.words.len() as u64)
            .min()
            .unwrap_or(0),
    }
}

/// Given a flat work index `i`, resolve the concrete substitution map for that index,
/// under the given combine mode. This is what lets work be distributed across threads
/// via a simple shared `AtomicU64` counter without needing a generator/channel.
pub fn substitution_at(mode: CombineMode, lists: &[LoadedWordlist], i: u64) -> Substitution {
    let mut sub = Substitution::with_capacity(lists.len());

    match mode {
        CombineMode::Pitchfork => {
            for l in lists {
                let idx = (i as usize) % l.words.len();
                sub.insert(l.keyword.clone(), Arc::from(l.words[idx].as_str()));
            }
        }
        CombineMode::Clusterbomb => {
            // Mixed-radix decomposition of the flat index into per-list indices.
            // Last wordlist varies fastest (matches ffuf's iteration order).
            let mut remainder = i;
            let mut per_list_idx = vec![0usize; lists.len()];
            for (pos, l) in lists.iter().enumerate().rev() {
                let len = l.words.len() as u64;
                per_list_idx[pos] = (remainder % len) as usize;
                remainder /= len;
            }
            for (l, idx) in lists.iter().zip(per_list_idx) {
                sub.insert(l.keyword.clone(), Arc::from(l.words[idx].as_str()));
            }
        }
    }

    sub
}

/// Apply a substitution map to a template string, replacing every occurrence of
/// each keyword. Longer keywords are replaced first so `FUZ2Z` doesn't get
/// clobbered by a naive `FUZZ` replace pass (they don't overlap here, but this
/// keeps behavior correct if keyword names are ever made to share prefixes).
pub fn apply(template: &str, sub: &Substitution) -> String {
    let mut keywords: Vec<&String> = sub.keys().collect();
    keywords.sort_by_key(|k| std::cmp::Reverse(k.len()));

    let mut out = template.to_string();
    for k in keywords {
        out = out.replace(k.as_str(), sub[k].as_ref());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(keyword: &str, words: &[&str]) -> LoadedWordlist {
        LoadedWordlist {
            keyword: keyword.to_string(),
            words: Arc::new(words.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn clusterbomb_covers_all_combinations() {
        let lists = vec![list("FUZZ", &["a", "b"]), list("FUZ2Z", &["1", "2", "3"])];
        let total = total_items(CombineMode::Clusterbomb, &lists);
        assert_eq!(total, 6);

        let mut seen = std::collections::HashSet::new();
        for i in 0..total {
            let s = substitution_at(CombineMode::Clusterbomb, &lists, i);
            seen.insert((s["FUZZ"].to_string(), s["FUZ2Z"].to_string()));
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn pitchfork_zips_by_index() {
        let lists = vec![list("FUZZ", &["a", "b", "c"]), list("FUZ2Z", &["1", "2"])];
        let total = total_items(CombineMode::Pitchfork, &lists);
        assert_eq!(total, 2); // bounded by shortest list

        let s0 = substitution_at(CombineMode::Pitchfork, &lists, 0);
        assert_eq!(s0["FUZZ"].as_ref(), "a");
        assert_eq!(s0["FUZ2Z"].as_ref(), "1");

        let s1 = substitution_at(CombineMode::Pitchfork, &lists, 1);
        assert_eq!(s1["FUZZ"].as_ref(), "b");
        assert_eq!(s1["FUZ2Z"].as_ref(), "2");
    }

    #[test]
    fn apply_replaces_multiple_keywords_independently() {
        let mut sub = Substitution::new();
        sub.insert("FUZZ".to_string(), Arc::from("admin"));
        sub.insert("FUZ2Z".to_string(), Arc::from("1234"));

        let result = apply("https://example.com/FUZZ?token=FUZ2Z", &sub);
        assert_eq!(result, "https://example.com/admin?token=1234");
    }

    #[test]
    fn keyword_binding_parses_path_and_keyword() {
        let b: WordlistBinding = "wordlists/users.txt:FUZZ".parse().unwrap();
        assert_eq!(b.keyword, "FUZZ");
        assert_eq!(b.path, "wordlists/users.txt");
    }

    #[test]
    fn keyword_binding_defaults_to_fuzz() {
        let b: WordlistBinding = "wordlists/users.txt".parse().unwrap();
        assert_eq!(b.keyword, "FUZZ");
    }

    #[test]
    fn keyword_binding_handles_windows_path_without_keyword() {
        let b: WordlistBinding = r"C:\wordlists\users.txt".parse().unwrap();
        assert_eq!(b.keyword, "FUZZ");
        assert_eq!(b.path, r"C:\wordlists\users.txt");
    }
}
