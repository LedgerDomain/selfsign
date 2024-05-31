use crate::{
    KERISignature, KeyType, SignatureAlgorithm, SignatureBytes, ED25519_SHA_512, SECP256K1_SHA_256,
};

/// A signature algorithm represented by its name, which consists of its key type and the message
/// digest hash function.  This isn't necessarily the same as some kind of "official" name.
#[derive(
    Clone, Debug, derive_more::Display, derive_more::Deref, Eq, derive_more::Into, PartialEq,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay)
)]
pub struct NamedSignatureAlgorithm(&'static str);

const ED25519_SHA_512_STR: &'static str = "Ed25519-SHA-512";
const SECP256K1_SHA_256_STR: &'static str = "Secp256k1-SHA-256";

impl NamedSignatureAlgorithm {
    /// See https://ed25519.cr.yp.to/
    pub const ED25519_SHA_512: NamedSignatureAlgorithm =
        NamedSignatureAlgorithm(ED25519_SHA_512_STR);
    /// The real name of this signature algorithm is ECDSA, but that by itself doesn't specify
    /// the curve or message digest hash function, so we specify that here. See
    /// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    pub const SECP256K1_SHA_256: NamedSignatureAlgorithm =
        NamedSignatureAlgorithm(SECP256K1_SHA_256_STR);

    /// Attempt to parse a JWS alg string into a NamedSignatureAlgorithm.
    /// See https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    pub fn try_from_jws_alg(jws_alg: &str) -> Result<Self, &'static str> {
        match jws_alg {
            "EdDSA" => Ok(Self::ED25519_SHA_512),
            "ES256K" => Ok(Self::SECP256K1_SHA_256),
            _ => Err("unrecognized JWS alg"),
        }
    }
    /// Convert this NamedSignatureAlgorithm into a JWS alg string.
    /// See https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    pub fn as_jws_alg(&self) -> &'static str {
        match self.0 {
            ED25519_SHA_512_STR => "EdDSA",
            SECP256K1_SHA_256_STR => "ES256K",
            _ => {
                panic!("programmer error: unrecognized signature algorithm name");
            }
        }
    }
    pub fn try_from_keri_prefix(keri_prefix: &str) -> Result<Self, &'static str> {
        match keri_prefix {
            "0B" => Ok(Self::ED25519_SHA_512),
            "0C" => Ok(Self::SECP256K1_SHA_256),
            _ => Err("unrecognized keri_prefix"),
        }
    }
    pub fn as_signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        match self.0 {
            ED25519_SHA_512_STR => &ED25519_SHA_512,
            SECP256K1_SHA_256_STR => &SECP256K1_SHA_256,
            _ => {
                panic!("programmer error: unrecognized signature algorithm name");
            }
        }
    }
}

impl std::str::FromStr for NamedSignatureAlgorithm {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ED25519_SHA_512_STR => Ok(NamedSignatureAlgorithm::ED25519_SHA_512),
            SECP256K1_SHA_256_STR => Ok(NamedSignatureAlgorithm::SECP256K1_SHA_256),
            _ => Err("unrecognized signature algorithm name"),
        }
    }
}

impl SignatureAlgorithm for NamedSignatureAlgorithm {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn equals(&self, other: &dyn SignatureAlgorithm) -> bool {
        *self == other.named_signature_algorithm()
    }
    fn named_signature_algorithm(&self) -> NamedSignatureAlgorithm {
        self.clone()
    }
    fn key_type(&self) -> KeyType {
        self.as_signature_algorithm().key_type()
    }
    fn message_digest_hash_function(&self) -> &'static dyn selfhash::HashFunction {
        self.as_signature_algorithm().message_digest_hash_function()
    }
    fn keri_prefix(&self) -> &'static str {
        self.as_signature_algorithm().keri_prefix()
    }
    fn signature_bytes_len(&self) -> usize {
        self.as_signature_algorithm().signature_bytes_len()
    }
    fn keri_signature_len(&self) -> usize {
        self.as_signature_algorithm().keri_signature_len()
    }
    fn placeholder_keri_signature(&self) -> KERISignature<'static> {
        self.as_signature_algorithm().placeholder_keri_signature()
    }
    fn placeholder_signature_bytes(&self) -> SignatureBytes<'static> {
        self.as_signature_algorithm().placeholder_signature_bytes()
    }
}
