use std::borrow::Cow;

use crate::{
    NamedSignatureAlgorithm, Signature, SignatureAlgorithm, SignatureBytes, ED25519_SHA_512,
    SECP256K1_SHA_256,
};

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
    pub fn keri_prefix<'b: 'a>(&'b self) -> &'a str {
        &self.0[..2]
    }
    pub fn data<'b: 'a>(&'b self) -> &'a str {
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
        let keri_prefix = &s[..2];
        let named_signature_algorithm = NamedSignatureAlgorithm::try_from_keri_prefix(keri_prefix)?;
        match named_signature_algorithm.signature_bytes_len() {
            64 => {
                let mut buffer = [0u8; 66];
                selfhash::base64_decode_512_bits(&s[2..], &mut buffer)?;
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
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        match self.keri_prefix() {
            "0B" => &ED25519_SHA_512,
            "0C" => &SECP256K1_SHA_256,
            _ => panic!("this should not be possible"),
        }
    }
    fn to_signature_bytes(&self) -> SignatureBytes {
        self.to_signature_bytes()
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.clone()
    }
}
