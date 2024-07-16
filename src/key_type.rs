use crate::NamedSignatureAlgorithm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum KeyType {
    Ed25519,
    Secp256k1,
}

impl KeyType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::Secp256k1 => "Secp256k1",
        }
    }
    pub fn from_keri_prefix(s: &str) -> Result<Self, &'static str> {
        match s {
            "D" => Ok(Self::Ed25519),
            "1AAB" => Ok(Self::Secp256k1),
            _ => Err("KeyType::from_keri_prefix failed: unknown prefix"),
        }
    }
    /// The prefix used before the base64url-no-pad encoding of the key bytes.
    pub const fn keri_prefix(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "D",
            KeyType::Secp256k1 => "1AAB",
        }
    }
    /// Number of bytes needed to store an instance of the public key for this key type.
    pub const fn public_key_bytes_len(&self) -> usize {
        match self {
            KeyType::Ed25519 => 32,
            // Compressed format for secp256k1 public keys.
            KeyType::Secp256k1 => 33,
        }
    }
    /// Number of bytes needed to store an instance of the private key for this key type.
    pub const fn private_key_bytes_len(&self) -> usize {
        match self {
            KeyType::Ed25519 => 32,
            KeyType::Secp256k1 => 32,
        }
    }
    /// Each KeyType has a specified default SignatureAlgorithm so that the user doesn't need to
    /// make a choice and potentially weaken the crypto system.
    pub const fn default_named_signature_algorithm(&self) -> NamedSignatureAlgorithm {
        match self {
            KeyType::Ed25519 => NamedSignatureAlgorithm::ED25519_SHA_512,
            KeyType::Secp256k1 => NamedSignatureAlgorithm::SECP256K1_SHA_256,
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519" => Ok(Self::Ed25519),
            "Secp256k1" => Ok(Self::Secp256k1),
            _ => Err("Unrecognized KeyType"),
        }
    }
}
