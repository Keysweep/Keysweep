use std::fmt;

use clap::Subcommand;

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum HashType {
    Bcrypt,

    MD4,
    MD5,

    HMACMD4,
    HMACMD5,

    Ntlm,
    NTLMV2,

    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,

    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,

    HMACSHA1,
    HMACSHA224,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512,

    SHACrypt,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashType::Bcrypt => "bcrypt",

            HashType::MD4 => "MD4",
            HashType::MD5 => "MD5",

            HashType::HMACMD4 => "HMAC-MD4",
            HashType::HMACMD5 => "HMAC-MD5",

            HashType::Ntlm => "NTLM",
            HashType::NTLMV2 => "NTLM v2",

            HashType::SHA1 => "SHA-1",
            HashType::SHA224 => "SHA-224",
            HashType::SHA256 => "SHA-256",
            HashType::SHA384 => "SHA-384",
            HashType::SHA512 => "SHA-512",

            HashType::SHA3_224 => "SHA3-224",
            HashType::SHA3_256 => "SHA3-256",
            HashType::SHA3_384 => "SHA3-384",
            HashType::SHA3_512 => "SHA3-512",

            HashType::HMACSHA1 => "HMAC-SHA-1",
            HashType::HMACSHA224 => "HMAC-SHA-224",
            HashType::HMACSHA256 => "HMAC-SHA-256",
            HashType::HMACSHA384 => "HMAC-SHA-384",
            HashType::HMACSHA512 => "HMAC-SHA-512",

            HashType::SHACrypt => "SHA-crypt",
        };
        write!(f, "{name}")
    }
}
