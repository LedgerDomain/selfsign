// TODO: Make a SignatureAlgorithm trait

use crate::{
    HashFunction, KERISignature, KeyType, SignatureBytes,
    ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER, ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER,
};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SignatureAlgorithm {
    Ed25519_SHA2_512,
}

impl SignatureAlgorithm {
    pub fn key_type(&self) -> KeyType {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => KeyType::Ed25519,
        }
    }
    /// Defines which hash function is used to generate the digest of the self-signing object.
    pub fn message_digest_hash_function(&self) -> HashFunction {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => HashFunction::SHA2_512,
        }
    }
    /// The prefix only identifies the SignatureAlgorithm.
    pub const fn keri_prefix(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => "0B",
        }
    }
    /// This only includes the signature bytes, not the SignatureAlgorithm.
    pub const fn signature_bytes_len(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => 64,
        }
    }
    /// This includes the prefix.
    pub const fn keri_signature_len(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => 88,
        }
    }
    /// Returns the KERISignature form of the signature to be used as the placeholder when generating
    /// the digest of the self-signing object.
    pub const fn placeholder_keri_signature(&self) -> KERISignature<'static> {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER,
        }
    }
    /// Returns the SignatureBytes form of the signature to be used as the placeholder when generating
    /// the digest of the self-signing object.
    pub const fn placeholder_signature_bytes(&self) -> SignatureBytes<'static> {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER,
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgorithm::Ed25519_SHA2_512 => write!(f, "{}", self.keri_prefix()),
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0B" => Ok(Self::Ed25519_SHA2_512),
            _ => Err("SignatureAlgorithm::from_str failed: unknown prefix"),
        }
    }
}
