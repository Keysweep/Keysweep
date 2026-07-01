use digest::Digest;
use hmac::{Hmac, KeyInit, Mac};
use md4::Md4;
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
