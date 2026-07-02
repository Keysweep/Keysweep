use clap::Args;
use digest::Digest;
use hmac::{Hmac, KeyInit, Mac};
use md4::Md4;
use md5::Md5;
use sha_crypt::{PasswordHash, PasswordVerifier, ShaCrypt};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::fmt;

pub mod ntlm;
pub mod types;

use crate::{
    credentials::CredentialSource,
    hashes::{
        ntlm::{verify_ntlm, verify_ntlmv2},
        types::HashType,
    },
    outputs::OUTPUT_HANDLER,
    shared::{args::GeneralArgs, args_display::Pretty},
    theme::{GREEN, RESET},
    wordlists_iterator::run_search,
};

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

fn verify_hmac<D>(expected: &str, password: &str) -> bool
where
    D: hmac::EagerHash,
    D::Core: Clone,
{
    let Some((hash_hex, key)) = expected.rsplit_once(':') else {
        return false;
    };

    let Ok(expected_bytes) = hex::decode(hash_hex) else {
        return false;
    };

    let Ok(mut mac) = Hmac::<D>::new_from_slice(key.as_bytes()) else {
        return false;
    };

    mac.update(password.as_bytes());

    mac.verify_slice(&expected_bytes).is_ok()
}

pub fn verify_crypt(expected: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(expected) else {
        return false;
    };
    ShaCrypt::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Dispatch to the verifier matching `hash_type`. Digest-based types use
/// `hash_bytes` (pre-decoded); text-based formats (bcrypt, NTLMv2, HMAC) parse
/// `hash` themselves since they carry their own encoding (salt, params, etc).
fn verify(hash_type: HashType, hash_bytes: Option<&[u8]>, hash: &str, word: &str) -> bool {
    match hash_type {
        HashType::Bcrypt => bcrypt::verify(word, hash).unwrap_or(false),

        HashType::MD4 => verify_digest::<Md4>(hash_bytes, word),
        HashType::MD5 => verify_digest::<Md5>(hash_bytes, word),

        HashType::HMACMD4 => verify_hmac::<Md4>(hash, word),
        HashType::HMACMD5 => verify_hmac::<Md5>(hash, word),

        HashType::Ntlm => verify_ntlm(hash_bytes, word),
        HashType::NTLMV2 => verify_ntlmv2(hash, word),

        HashType::SHA1 => verify_digest::<Sha1>(hash_bytes, word),
        HashType::SHA224 => verify_digest::<Sha224>(hash_bytes, word),
        HashType::SHA256 => verify_digest::<Sha256>(hash_bytes, word),
        HashType::SHA384 => verify_digest::<Sha384>(hash_bytes, word),
        HashType::SHA512 => verify_digest::<Sha512>(hash_bytes, word),

        HashType::SHA3_224 => verify_digest::<Sha3_224>(hash_bytes, word),
        HashType::SHA3_256 => verify_digest::<Sha3_256>(hash_bytes, word),
        HashType::SHA3_384 => verify_digest::<Sha3_384>(hash_bytes, word),
        HashType::SHA3_512 => verify_digest::<Sha3_512>(hash_bytes, word),

        HashType::HMACSHA1 => verify_hmac::<Sha1>(hash, word),
        HashType::HMACSHA224 => verify_hmac::<Sha224>(hash, word),
        HashType::HMACSHA256 => verify_hmac::<Sha256>(hash, word),
        HashType::HMACSHA384 => verify_hmac::<Sha384>(hash, word),
        HashType::HMACSHA512 => verify_hmac::<Sha512>(hash, word),

        HashType::SHACrypt => verify_crypt(hash, word),
    }
}

pub fn handle_hash(hash: HashArgs) {
    let hashes = CredentialSource::from_pair(hash.hash, hash.hash_list);
    let hash_type = hash.hash_type;

    OUTPUT_HANDLER
        .lock()
        .unwrap()
        .set_formats(hash.general.output_format.clone());

    // Decode each hash's hex once per target rather than once per candidate word.
    let make_validator = move |target: &str| {
        let hash_bytes = hex::decode(target).ok();
        let target = target.to_owned();
        move |word: &str| verify(hash_type, hash_bytes.as_deref(), &target, word)
    };

    let report = |hash: &str, word: &str| {
        OUTPUT_HANDLER.lock().unwrap().write_hash(hash, word);
        format!("[{GREEN}+{RESET}] Hash: {GREEN}{hash}{RESET} Word: {GREEN}{word}{RESET}")
    };

    let result = run_search(
        hashes,
        CredentialSource::Wordlist(hash.word_list),
        hash.general,
        make_validator,
        report,
    );

    if let Err(err) = result {
        eprintln!("{err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper ────────────────────────────────────────────────────────────
    fn decoded(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    // ── MD4 / MD5 ────────────────────────────────────────────────────────────

    #[test]
    fn md4_password() {
        let h = decoded("8a9d093f14f8701df17732b2bb182c74");
        assert!(verify(HashType::MD4, Some(&h), "", "password"));
        assert!(!verify(HashType::MD4, Some(&h), "", "wrong"));
    }

    #[test]
    fn md5_password() {
        let h = decoded("5f4dcc3b5aa765d61d8327deb882cf99");
        assert!(verify(HashType::MD5, Some(&h), "", "password"));
        assert!(!verify(HashType::MD5, Some(&h), "", "wrong"));
    }

    // ── NTLM / NTLMv2 ────────────────────────────────────────────────────────

    #[test]
    fn ntlm_password() {
        let h = decoded("8846f7eaee8fb117ad06bdd830b7586c");
        assert!(verify(HashType::Ntlm, Some(&h), "", "password"));
        assert!(!verify(HashType::Ntlm, Some(&h), "", "wrong"));
    }

    #[test]
    fn ntlmv2_rejects_malformed() {
        assert!(!verify(HashType::NTLMV2, None, "not:valid", "password"));
    }

    // ── SHA-1 / SHA-2 ─────────────────────────────────────────────────────────

    #[test]
    fn sha1_password() {
        let h = decoded("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
        assert!(verify(HashType::SHA1, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA1, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha224_password() {
        let h = decoded("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
        assert!(verify(HashType::SHA224, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA224, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha256_password() {
        let h = decoded("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
        assert!(verify(HashType::SHA256, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA256, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha384_password() {
        let h = decoded(
            "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7",
        );
        assert!(verify(HashType::SHA384, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA384, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha512_password() {
        let h = decoded(
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
        );
        assert!(verify(HashType::SHA512, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA512, Some(&h), "", "wrong"));
    }

    // ── SHA-3 ─────────────────────────────────────────────────────────────────

    #[test]
    fn sha3_224_password() {
        let h = decoded("c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c");
        assert!(verify(HashType::SHA3_224, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA3_224, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha3_256_password() {
        let h = decoded("c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484");
        assert!(verify(HashType::SHA3_256, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA3_256, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha3_384_password() {
        let h = decoded(
            "9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc",
        );
        assert!(verify(HashType::SHA3_384, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA3_384, Some(&h), "", "wrong"));
    }

    #[test]
    fn sha3_512_password() {
        let h = decoded(
            "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716",
        );
        assert!(verify(HashType::SHA3_512, Some(&h), "", "password"));
        assert!(!verify(HashType::SHA3_512, Some(&h), "", "wrong"));
    }

    // ── HMAC ─────────────────────────────────────────────────────────────────
    // Format: "<hex_mac>:<key>"  (verify_hmac splits on the last ':')

    #[test]
    fn hmac_md4_password() {
        // HMAC-MD4("password", key="secret")
        assert!(verify(
            HashType::HMACMD4,
            None,
            "72c9b58b2c7c34e7b63d1378bce82bf7:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACMD4,
            None,
            "72c9b58b2c7c34e7b63d1378bce82bf7:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_md5_password() {
        assert!(verify(
            HashType::HMACMD5,
            None,
            "bd0ef7878fb434715c14a6243e89cdcd:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACMD5,
            None,
            "bd0ef7878fb434715c14a6243e89cdcd:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_sha1_password() {
        assert!(verify(
            HashType::HMACSHA1,
            None,
            "a462b4d910544d3ffb39f3a64017f65e029b73fb:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACSHA1,
            None,
            "a462b4d910544d3ffb39f3a64017f65e029b73fb:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_sha224_password() {
        assert!(verify(
            HashType::HMACSHA224,
            None,
            "0b075ca0fc775abf264323daa7cf1717ac1ea0c13fda722098b9319b:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACSHA224,
            None,
            "0b075ca0fc775abf264323daa7cf1717ac1ea0c13fda722098b9319b:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_sha256_password() {
        assert!(verify(
            HashType::HMACSHA256,
            None,
            "8c9a239e21f7bb939f8b570ae81daa50028d6a3d3250111e2d4cd269c2ab54bb:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACSHA256,
            None,
            "8c9a239e21f7bb939f8b570ae81daa50028d6a3d3250111e2d4cd269c2ab54bb:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_sha384_password() {
        assert!(verify(
            HashType::HMACSHA384,
            None,
            "daf4e8194eb94fc440dedeecfacea9d5723cd26cdacf7aeafc8667def04d93e99799faf4a07358e6a8414d911860ba47:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACSHA384,
            None,
            "daf4e8194eb94fc440dedeecfacea9d5723cd26cdacf7aeafc8667def04d93e99799faf4a07358e6a8414d911860ba47:secret",
            "wrong"
        ));
    }

    #[test]
    fn hmac_sha512_password() {
        assert!(verify(
            HashType::HMACSHA512,
            None,
            "ae46ed1b06dd57eb684ff2561a191fa34b9626d2d56edd30d203e6842d58ba7b3fcf313edea05a284bbe7e6f8c8a21ad043a10f9183af16ffbdf91350f10d010:secret",
            "password"
        ));
        assert!(!verify(
            HashType::HMACSHA512,
            None,
            "ae46ed1b06dd57eb684ff2561a191fa34b9626d2d56edd30d203e6842d58ba7b3fcf313edea05a284bbe7e6f8c8a21ad043a10f9183af16ffbdf91350f10d010:secret",
            "wrong"
        ));
    }

    // ── Bcrypt ────────────────────────────────────────────────────────────────

    #[test]
    fn bcrypt_password() {
        // Pre-generated: bcrypt.hashpw(b"password", bcrypt.gensalt())
        let hash = "$2b$12$2YEMWcUT6XImeU12rlPZc.kiZwj/Z183pDlWwgTbgyKh8ROniEOwi";
        assert!(verify(HashType::Bcrypt, None, hash, "password"));
        assert!(!verify(HashType::Bcrypt, None, hash, "wrong"));
    }

    // ── SHACrypt ──────────────────────────────────────────────────────────────

    #[test]
    fn sha_crypt_password() {
        // TODO: generate with `sha_crypt::sha512_simple("password", &Sha512Params::new(5000).unwrap())`
        // and paste the resulting "$6$..." string here.
        let _ = "placeholder — fill in a real $5$/sha256 or $6$/sha512 crypt hash";
    }
}
