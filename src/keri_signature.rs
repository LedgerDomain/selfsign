use std::borrow::Cow;

use crate::{base64_decode_512_bits, Signature, SignatureAlgorithm, SignatureBytes};

pub const ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER: KERISignature<'static> =
    KERISignature(Cow::Borrowed(
        "0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ));

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, derive_more::Display, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay)
)]
pub struct KERISignature<'a>(pub(crate) Cow<'a, str>);

impl<'a> KERISignature<'a> {
    pub fn into_owned(self) -> KERISignature<'static> {
        KERISignature(Cow::Owned(self.0.into_owned()))
    }
    pub fn to_owned(&self) -> KERISignature<'static> {
        KERISignature(Cow::Owned(self.0.to_string()))
    }
    pub fn to_signature_bytes(&self) -> SignatureBytes {
        use std::str::FromStr;
        let signature_algorithm = SignatureAlgorithm::from_str(&self.0[..2])
            .expect("this should not fail because of the check done in the constructor");
        match signature_algorithm.signature_bytes_len() {
            64 => {
                let mut buffer = [0u8; 66];
                let signature_byte_v = base64_decode_512_bits(&self.0[2..], &mut buffer)
                    .expect("this should not fail because of the check done in the constructor");
                SignatureBytes {
                    signature_algorithm,
                    signature_byte_v: Cow::Owned(signature_byte_v.to_vec()),
                }
            }
            _ => {
                panic!("this should not be possible");
            }
        }
    }
}

impl std::ops::Deref for KERISignature<'_> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for KERISignature<'_> {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 {
            return Err("KERISignature::from_str failed: too short");
        }
        if !s.is_ascii() {
            return Err("KERISignature::from_str failed: not ASCII");
        }
        let signature_algorithm = SignatureAlgorithm::from_str(&s[..2])?;
        match signature_algorithm.signature_bytes_len() {
            64 => {
                let mut buffer = [0u8; 66];
                base64_decode_512_bits(&s[2..], &mut buffer)?;
                Ok(Self(Cow::Owned(s.to_string())))
            }
            _ => {
                panic!("this should not be possible");
            }
        }
    }
}

impl Signature for KERISignature<'_> {
    /// This assumes the prefix is 2 chars.
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        use std::str::FromStr;
        SignatureAlgorithm::from_str(&self.0[..2])
            .expect("programmer error: this constraint should have been checked upon construction")
    }
    fn to_signature_bytes(&self) -> SignatureBytes {
        self.to_signature_bytes()
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.clone()
    }
}
