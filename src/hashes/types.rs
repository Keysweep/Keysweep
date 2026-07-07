use clap::Args;
use clap::Subcommand;
use std::fmt;

use crate::shared::args::GeneralArgs;

#[derive(Args, Debug)]
pub struct HashArgs {
    #[command(subcommand)]
    pub hash_type: HashType,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HashType {
    Bcrypt(HashCommonArgs),
    MD4(HashCommonArgs),
    MD5(HashCommonArgs),
    HMACMD4(HashCommonArgs),
    HMACMD5(HashCommonArgs),
    Ntlm(HashCommonArgs),
    NTLMV2(HashCommonArgs),
    SHA1(HashCommonArgs),
    SHA224(HashCommonArgs),
    SHA256(HashCommonArgs),
    SHA384(HashCommonArgs),
    SHA512(HashCommonArgs),
    SHA3_224(HashCommonArgs),
    SHA3_256(HashCommonArgs),
    SHA3_384(HashCommonArgs),
    SHA3_512(HashCommonArgs),
    HMACSHA1(HashCommonArgs),
    HMACSHA224(HashCommonArgs),
    HMACSHA256(HashCommonArgs),
    HMACSHA384(HashCommonArgs),
    HMACSHA512(HashCommonArgs),
    SHACrypt(HashCommonArgs),
}

#[derive(Args, Debug, Clone)]
pub struct HashCommonArgs {
    /// Hash to test
    #[arg(long = "hash", conflicts_with = "hash_list", value_name = "HASH")]
    pub(crate) hash: Option<String>,

    /// File containing hashes (one per line)
    #[arg(long = "hash_list", conflicts_with = "hash", value_name = "FILE")]
    pub(crate) hash_list: Option<String>,

    /// File containing words (one per line)
    #[arg(short = 'W', long = "word_list", value_name = "FILE")]
    pub(crate) word_list: String,

    #[command(flatten)]
    pub(crate) general: GeneralArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
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

impl HashType {
    pub fn common_args(&self) -> &HashCommonArgs {
        match self {
            HashType::Bcrypt(a)
            | HashType::MD4(a)
            | HashType::MD5(a)
            | HashType::HMACMD4(a)
            | HashType::HMACMD5(a)
            | HashType::Ntlm(a)
            | HashType::NTLMV2(a)
            | HashType::SHA1(a)
            | HashType::SHA224(a)
            | HashType::SHA256(a)
            | HashType::SHA384(a)
            | HashType::SHA512(a)
            | HashType::SHA3_224(a)
            | HashType::SHA3_256(a)
            | HashType::SHA3_384(a)
            | HashType::SHA3_512(a)
            | HashType::HMACSHA1(a)
            | HashType::HMACSHA224(a)
            | HashType::HMACSHA256(a)
            | HashType::HMACSHA384(a)
            | HashType::HMACSHA512(a)
            | HashType::SHACrypt(a) => a,
        }
    }

    pub fn kind(&self) -> HashKind {
        match self {
            HashType::Bcrypt(_) => HashKind::Bcrypt,
            HashType::MD4(_) => HashKind::MD4,
            HashType::MD5(_) => HashKind::MD5,
            HashType::HMACMD4(_) => HashKind::HMACMD4,
            HashType::HMACMD5(_) => HashKind::HMACMD5,
            HashType::Ntlm(_) => HashKind::Ntlm,
            HashType::NTLMV2(_) => HashKind::NTLMV2,
            HashType::SHA1(_) => HashKind::SHA1,
            HashType::SHA224(_) => HashKind::SHA224,
            HashType::SHA256(_) => HashKind::SHA256,
            HashType::SHA384(_) => HashKind::SHA384,
            HashType::SHA512(_) => HashKind::SHA512,
            HashType::SHA3_224(_) => HashKind::SHA3_224,
            HashType::SHA3_256(_) => HashKind::SHA3_256,
            HashType::SHA3_384(_) => HashKind::SHA3_384,
            HashType::SHA3_512(_) => HashKind::SHA3_512,
            HashType::HMACSHA1(_) => HashKind::HMACSHA1,
            HashType::HMACSHA224(_) => HashKind::HMACSHA224,
            HashType::HMACSHA256(_) => HashKind::HMACSHA256,
            HashType::HMACSHA384(_) => HashKind::HMACSHA384,
            HashType::HMACSHA512(_) => HashKind::HMACSHA512,
            HashType::SHACrypt(_) => HashKind::SHACrypt,
        }
    }
}

impl fmt::Display for HashKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashKind::Bcrypt => "bcrypt",
            HashKind::MD4 => "MD4",
            HashKind::MD5 => "MD5",
            HashKind::HMACMD4 => "HMAC-MD4",
            HashKind::HMACMD5 => "HMAC-MD5",
            HashKind::Ntlm => "NTLM",
            HashKind::NTLMV2 => "NTLM v2",
            HashKind::SHA1 => "SHA-1",
            HashKind::SHA224 => "SHA-224",
            HashKind::SHA256 => "SHA-256",
            HashKind::SHA384 => "SHA-384",
            HashKind::SHA512 => "SHA-512",
            HashKind::SHA3_224 => "SHA3-224",
            HashKind::SHA3_256 => "SHA3-256",
            HashKind::SHA3_384 => "SHA3-384",
            HashKind::SHA3_512 => "SHA3-512",
            HashKind::HMACSHA1 => "HMAC-SHA-1",
            HashKind::HMACSHA224 => "HMAC-SHA-224",
            HashKind::HMACSHA256 => "HMAC-SHA-256",
            HashKind::HMACSHA384 => "HMAC-SHA-384",
            HashKind::HMACSHA512 => "HMAC-SHA-512",
            HashKind::SHACrypt => "SHA-crypt",
        };
        write!(f, "{name}")
    }
}
