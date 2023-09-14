use crate::SignatureAlgorithm;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    Ed25519,
}

impl KeyType {
    /// The prefix used before the base64url-no-pad encoding of the key bytes.
    pub const fn keri_prefix(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "D",
        }
    }
    /// Number of bytes needed to store an instance of this key type.
    pub const fn key_bytes_len(&self) -> usize {
        match self {
            KeyType::Ed25519 => 32,
        }
    }
    /// Each KeyType has a specified default SignatureAlgorithm so that the user doesn't need to
    /// make a choice and potentially weaken the crypto system.
    pub const fn default_signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            KeyType::Ed25519 => SignatureAlgorithm::Ed25519_SHA2_512,
        }
    }
}

impl std::str::FromStr for KeyType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "D" => Ok(Self::Ed25519),
            _ => Err("KeyType::from_str failed: unknown prefix"),
        }
    }
}
