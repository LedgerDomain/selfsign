use crate::{SignatureAlgorithm, ED25519_SHA_512, SECP256K1_SHA_256};

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
}

impl KeyType {
    /// The prefix used before the base64url-no-pad encoding of the key bytes.
    pub const fn keri_prefix(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "D",
            KeyType::Secp256k1 => "1AAB",
        }
    }
    /// Number of bytes needed to store an instance of this key type.
    pub const fn key_bytes_len(&self) -> usize {
        match self {
            KeyType::Ed25519 => 32,
            KeyType::Secp256k1 => 33,
        }
    }
    /// Each KeyType has a specified default SignatureAlgorithm so that the user doesn't need to
    /// make a choice and potentially weaken the crypto system.
    pub const fn default_signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        match self {
            KeyType::Ed25519 => &ED25519_SHA_512,
            KeyType::Secp256k1 => &SECP256K1_SHA_256,
        }
    }
}

impl std::str::FromStr for KeyType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "D" => Ok(Self::Ed25519),
            "1AAB" => Ok(Self::Secp256k1),
            _ => Err("KeyType::from_str failed: unknown prefix"),
        }
    }
}
