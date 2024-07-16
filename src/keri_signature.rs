use std::borrow::Cow;

use crate::{
    NamedSignatureAlgorithm, Signature, SignatureAlgorithm, SignatureBytes, ED25519_SHA_512,
    SECP256K1_SHA_256,
};

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, derive_more::Display, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct KERISignature(pub(crate) String);

impl KERISignature {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn keri_prefix(&self) -> &str {
        &self.0[..2]
    }
    pub fn data(&self) -> &str {
        &self.0[2..]
    }
    pub fn to_signature_bytes(&self) -> SignatureBytes {
        let keri_prefix = self.keri_prefix();
        let data = self.data();
        let signature_algorithm: &'static dyn SignatureAlgorithm = match keri_prefix {
            "0B" => &ED25519_SHA_512,
            "0C" => &SECP256K1_SHA_256,
            _ => panic!("this should not be possible"),
        };
        match signature_algorithm.signature_bytes_len() {
            64 => {
                let mut buffer = [0u8; 66];
                let signature_byte_v = selfhash::base64_decode_512_bits(data, &mut buffer)
                    .expect("this should not fail because of the check done in the constructor");
                SignatureBytes {
                    named_signature_algorithm: signature_algorithm.named_signature_algorithm(),
                    signature_byte_v: Cow::Owned(signature_byte_v.to_vec()),
                }
            }
            _ => {
                panic!("this should not be possible");
            }
        }
    }
}

impl std::ops::Deref for KERISignature {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for KERISignature {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate_keri_signature_string(s)?;
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<&str> for KERISignature {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_keri_signature_string(value)?;
        Ok(Self(value.to_string()))
    }
}

impl<'a> TryFrom<String> for KERISignature {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_keri_signature_string(value.as_str())?;
        Ok(Self(value))
    }
}

fn validate_keri_signature_string(s: &str) -> Result<(), &'static str> {
    if s.len() < 2 {
        return Err("string too short to be a KERISignature");
    }
    if !s.is_ascii() {
        return Err("KERISignature strings must contain only ASCII chars");
    }
    let keri_prefix = &s[..2];
    let named_signature_algorithm = NamedSignatureAlgorithm::try_from_keri_prefix(keri_prefix)?;
    match named_signature_algorithm.signature_bytes_len() {
        64 => {
            let mut buffer = [0u8; 66];
            selfhash::base64_decode_512_bits(&s[2..], &mut buffer)?;
        }
        _ => {
            panic!("this should not be possible");
        }
    }
    Ok(())
}

impl Signature for KERISignature {
    /// This assumes the prefix is 2 chars.
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        match self.keri_prefix() {
            "0B" => &ED25519_SHA_512,
            "0C" => &SECP256K1_SHA_256,
            _ => panic!("this should not be possible"),
        }
    }
    /// This will allocate, because it must convert an ASCII string representation into bytes.
    fn to_signature_bytes(&self) -> SignatureBytes {
        self.to_signature_bytes()
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.clone()
    }
}
