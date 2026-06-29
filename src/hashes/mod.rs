use std::fmt;

use clap::{Args, Subcommand};
use hmac::{Hmac, KeyInit, Mac};
use md4::Md4;
use md5::Md5;
use sha_crypt::{PasswordHash, PasswordVerifier, ShaCrypt};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::{
    CredentialSource,
    shared::{args::GeneralArgs, args_display::Pretty},
    wordlists_iterator::hash_iterator,
};

type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;

#[derive(Subcommand, Debug, Clone, Copy)]
enum HashType {
    SHA512,
    SHA512Crypt,
    SHA384,
    SHA256,
    SHA224,
    SHA1,
    MD5,
    MD4,
    Bcrypt,
    Ntlm,
    NTLMV2,
    HMACSHA1,
}

#[derive(Args, Debug)]
pub struct HashArgs {
    /// Hash to test
    #[arg(long = "hash", conflicts_with = "hash_list", value_name = "HASH")]
    hash: Option<String>,

    /// File containing hashes (one per line)
    #[arg(long = "hash_list", conflicts_with = "hash", value_name = "FILE")]
    hash_list: Option<String>,

    /// File containing words (one per line)
    #[arg(short = 'W', long = "word_list", value_name = "FILE")]
    word_list: String,

    #[command(subcommand)]
    hash_type: HashType,

    #[command(flatten)]
    general: GeneralArgs,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashType::SHA512 => "SHA-512",
            HashType::SHA512Crypt => "SHA-512-crypt",
            HashType::SHA384 => "SHA-384",
            HashType::SHA256 => "SHA-256",
            HashType::SHA224 => "SHA-224",
            HashType::SHA1 => "SHA-1",
            HashType::MD5 => "MD5",
            HashType::MD4 => "MD4",
            HashType::Bcrypt => "bcrypt",
            HashType::Ntlm => "NTLM",
            HashType::NTLMV2 => "NTLM v2",
            HashType::HMACSHA1 => "HMAC-SHA-1",
        };
        write!(f, "{name}")
    }
}

impl fmt::Display for HashArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut p = Pretty::new(&mut s, 10);

        match (&self.hash, &self.hash_list) {
            (Some(hash), _) => p.field("Hash", hash)?,
            (_, Some(list)) => p.field("Hash List", list)?,
            _ => {}
        }

        p.field("Wordlist", &self.word_list)?;
        p.field("Hash Type", self.hash_type)?;

        write!(f, "{s}")?;
        write!(f, "{}", self.general)
    }
}

/// Hash `password` with digest `D` and compare against `expected_bytes`.
///
/// Panics if `expected_bytes` is `None` — callers that pass digest-based hash
/// types are expected to have already decoded the hash to bytes.
fn verify_digest<D: Digest>(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    let mut hasher = D::new();
    hasher.update(password.as_bytes());
    hasher.finalize().as_slice() == expected_bytes.expect("verify_digest requires decoded bytes")
}

pub fn verify_sha512(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Sha512>(expected_bytes, password)
}

pub fn verify_sha384(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Sha384>(expected_bytes, password)
}

pub fn verify_sha256(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Sha256>(expected_bytes, password)
}

pub fn verify_sha224(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Sha224>(expected_bytes, password)
}

pub fn verify_sha1(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Sha1>(expected_bytes, password)
}

pub fn verify_md5(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Md5>(expected_bytes, password)
}

pub fn verify_md4(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    verify_digest::<Md4>(expected_bytes, password)
}

pub fn verify_sha512_crypt(expected: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(expected) else {
        return false;
    };
    ShaCrypt::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn verify_bcrypt(expected_hash: &str, password: &str) -> bool {
    bcrypt::verify(password, expected_hash).unwrap_or(false)
}

/// NT hash = MD4(UTF-16LE(password)).
fn nt_hash(password: &str) -> impl AsRef<[u8]> {
    let mut hasher = Md4::new();
    for unit in password.encode_utf16() {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize()
}

pub fn verify_ntlm(expected_bytes: Option<&[u8]>, password: &str) -> bool {
    nt_hash(password).as_ref() == expected_bytes.expect("ntlm requires decoded bytes")
}

/// A parsed NetNTLMv2 challenge/response line, in the format:
/// `username::domain:server_challenge:nt_proof:blob`
#[derive(Debug)]
pub struct NetNtlmV2 {
    username: String,
    domain: String,
    server_challenge: Vec<u8>,
    nt_proof: Vec<u8>,
    blob: Vec<u8>,
}

pub fn parse_netntlmv2(line: &str) -> Result<NetNtlmV2, String> {
    let mut parts = line.trim().splitn(7, ':');

    let username = parts.next().ok_or("missing username")?.to_owned();

    if !parts.next().unwrap_or("").is_empty() {
        return Err("expected empty LM field".into());
    }

    let domain = parts.next().ok_or("missing domain")?.to_owned();
    let server_challenge =
        hex::decode(parts.next().ok_or("missing challenge")?).map_err(|e| e.to_string())?;
    let nt_proof =
        hex::decode(parts.next().ok_or("missing NT proof")?).map_err(|e| e.to_string())?;
    let blob = hex::decode(parts.next().ok_or("missing blob")?).map_err(|e| e.to_string())?;

    Ok(NetNtlmV2 {
        username,
        domain,
        server_challenge,
        nt_proof,
        blob,
    })
}

pub fn verify_ntlmv2(expected: &str, password: &str) -> bool {
    let Ok(parsed) = parse_netntlmv2(expected) else {
        return false;
    };

    let nt_hash = nt_hash(password);

    // NTLMv2 key = HMAC-MD5(NT hash, Uppercase(username) || domain)
    let identity = format!("{}{}", parsed.username.to_uppercase(), parsed.domain);
    let mut mac = HmacMd5::new_from_slice(nt_hash.as_ref()).expect("HMAC accepts any key length");
    for unit in identity.encode_utf16() {
        mac.update(&unit.to_le_bytes());
    }
    let ntlmv2_key = mac.finalize().into_bytes();

    // NT proof = HMAC-MD5(NTLMv2 key, ServerChallenge || Blob)
    let mut mac = HmacMd5::new_from_slice(&ntlmv2_key).expect("HMAC accepts any key length");
    mac.update(&parsed.server_challenge);
    mac.update(&parsed.blob);

    mac.finalize().into_bytes().as_slice() == parsed.nt_proof.as_slice()
}

pub fn verify_hmac_sha1(expected: &str, password: &str) -> bool {
    let Some((hash_hex, salt)) = expected.rsplit_once(':') else {
        return false;
    };

    let Ok(expected_bytes) = hex::decode(hash_hex) else {
        return false;
    };

    let Ok(mut mac) = HmacSha1::new_from_slice(salt.as_bytes()) else {
        return false;
    };
    mac.update(password.as_bytes());

    mac.verify_slice(&expected_bytes).is_ok()
}

/// Dispatch to the verifier matching `hash_type`. Digest-based types use
/// `hash_bytes` (pre-decoded); text-based formats (bcrypt, NTLMv2, HMAC) parse
/// `hash` themselves since they carry their own encoding (salt, params, etc).
fn verify(hash_type: HashType, hash_bytes: Option<&[u8]>, hash: &str, word: &str) -> bool {
    match hash_type {
        HashType::SHA512 => verify_sha512(hash_bytes, word),
        HashType::SHA512Crypt => verify_sha512_crypt(hash, word),
        HashType::SHA384 => verify_sha384(hash_bytes, word),
        HashType::SHA256 => verify_sha256(hash_bytes, word),
        HashType::SHA224 => verify_sha224(hash_bytes, word),
        HashType::SHA1 => verify_sha1(hash_bytes, word),
        HashType::MD5 => verify_md5(hash_bytes, word),
        HashType::MD4 => verify_md4(hash_bytes, word),
        HashType::Bcrypt => verify_bcrypt(hash, word),
        HashType::Ntlm => verify_ntlm(hash_bytes, word),
        HashType::NTLMV2 => verify_ntlmv2(hash, word),
        HashType::HMACSHA1 => verify_hmac_sha1(hash, word),
    }
}

pub fn handle_hash(hash: HashArgs) {
    let hashes = match (hash.hash, hash.hash_list) {
        (Some(single), None) => CredentialSource::Single(single),
        (None, Some(list)) => CredentialSource::Wordlist(list),
        _ => unreachable!("clap enforces exactly one of --hash / --hash_list"),
    };

    let hash_type = hash.hash_type;
    let hash_crack = move |hash_bytes: Option<&[u8]>, hash: &str, word: &str| {
        verify(hash_type, hash_bytes, hash, word)
    };

    if let Err(err) = hash_iterator(hashes, hash.word_list, hash.general, hash_crack) {
        eprintln!("{err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- digest-based verifiers ---

    #[test]
    fn sha256_matches_known_hash() {
        // sha256("password") = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        let expected =
            hex::decode("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
                .unwrap();
        assert!(verify_sha256(Some(&expected), "password"));
        assert!(!verify_sha256(Some(&expected), "wrong"));
    }

    #[test]
    fn md5_matches_known_hash() {
        // md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        let expected = hex::decode("5f4dcc3b5aa765d61d8327deb882cf99").unwrap();
        assert!(verify_md5(Some(&expected), "password"));
        assert!(!verify_md5(Some(&expected), "wrong"));
    }

    #[test]
    fn sha1_matches_known_hash() {
        // sha1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
        let expected = hex::decode("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8").unwrap();
        assert!(verify_sha1(Some(&expected), "password"));
        assert!(!verify_sha1(Some(&expected), "wrong"));
    }

    #[test]
    #[should_panic(expected = "verify_digest requires decoded bytes")]
    fn verify_digest_panics_without_decoded_bytes() {
        verify_sha256(None, "password");
    }

    // --- NTLM ---

    #[test]
    fn ntlm_matches_known_hash() {
        // NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
        let expected = hex::decode("8846f7eaee8fb117ad06bdd830b7586c").unwrap();
        assert!(verify_ntlm(Some(&expected), "password"));
        assert!(!verify_ntlm(Some(&expected), "wrong"));
    }

    // --- bcrypt ---

    #[test]
    fn bcrypt_matches_and_rejects() {
        let hash = bcrypt::hash("password", bcrypt::DEFAULT_COST).unwrap();
        assert!(verify_bcrypt(&hash, "password"));
        assert!(!verify_bcrypt(&hash, "wrong"));
    }

    #[test]
    fn bcrypt_malformed_hash_returns_false_not_panic() {
        assert!(!verify_bcrypt("not-a-real-hash", "password"));
    }

    // --- NetNTLMv2 parsing ---

    fn sample_netntlmv2_line() -> String {
        // username::DOMAIN:<16-byte challenge>:<16-byte proof>:<blob>
        format!(
            "alice::CORP:{}:{}:{}",
            "11".repeat(8),
            "22".repeat(16),
            "33".repeat(20)
        )
    }

    #[test]
    fn parse_netntlmv2_extracts_all_fields() {
        let line = sample_netntlmv2_line();
        let parsed = parse_netntlmv2(&line).unwrap();

        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.domain, "CORP");
        assert_eq!(parsed.server_challenge, vec![0x11; 8]);
        assert_eq!(parsed.nt_proof, vec![0x22; 16]);
        assert_eq!(parsed.blob, vec![0x33; 20]);
    }

    #[test]
    fn parse_netntlmv2_rejects_nonempty_lm_field() {
        let line = format!(
            "alice:SOMEHASH:CORP:{}:{}:{}",
            "11".repeat(8),
            "22".repeat(16),
            "33".repeat(20)
        );
        assert!(parse_netntlmv2(&line).is_err());
    }

    #[test]
    fn parse_netntlmv2_rejects_missing_fields() {
        assert!(parse_netntlmv2("alice::CORP:abcd").is_err());
    }

    #[test]
    fn parse_netntlmv2_rejects_invalid_hex() {
        let line = "alice::CORP:zzzz:abcd:1234";
        assert!(parse_netntlmv2(line).is_err());
    }

    #[test]
    fn verify_ntlmv2_rejects_malformed_input() {
        assert!(!verify_ntlmv2("not:a:valid:line", "password"));
    }

    // --- HMAC-SHA1 ---

    #[test]
    fn hmac_sha1_matches_known_value() {
        // HMAC-SHA1(key="salt123", msg="password"), hex-encoded.
        let mut mac = HmacSha1::new_from_slice(b"salt123").unwrap();
        mac.update(b"password");
        let digest = hex::encode(mac.finalize().into_bytes());

        let expected = format!("{digest}:salt123");
        assert!(verify_hmac_sha1(&expected, "password"));
        assert!(!verify_hmac_sha1(&expected, "wrong"));
    }

    #[test]
    fn hmac_sha1_rejects_missing_salt_separator() {
        assert!(!verify_hmac_sha1("deadbeef", "password"));
    }

    #[test]
    fn hmac_sha1_rejects_invalid_hex() {
        assert!(!verify_hmac_sha1("nothex:salt", "password"));
    }

    // --- dispatch ---

    #[test]
    fn verify_dispatches_to_correct_algorithm() {
        let expected = hex::decode("5f4dcc3b5aa765d61d8327deb882cf99").unwrap();
        assert!(verify(HashType::MD5, Some(&expected), "", "password"));
        assert!(!verify(HashType::MD5, Some(&expected), "", "wrong"));
    }

    // --- display ---

    #[test]
    fn hash_type_display_names() {
        assert_eq!(HashType::SHA512.to_string(), "SHA-512");
        assert_eq!(HashType::NTLMV2.to_string(), "NTLM v2");
        assert_eq!(HashType::Bcrypt.to_string(), "bcrypt");
    }
}
