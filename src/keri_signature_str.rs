use std::borrow::Cow;

use crate::{
    KERISignature, NamedSignatureAlgorithm, Signature, SignatureAlgorithm, SignatureBytes,
    ED25519_SHA_512, SECP256K1_SHA_256,
};

/// This is the str-based analog to KERISignature.
#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_str(deserialize))]
#[repr(transparent)]
pub struct KERISignatureStr(str);

impl KERISignatureStr {
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

impl pneutype::Validate for KERISignatureStr {
    type Data = str;
    type Error = &'static str;
    fn validate(s: &Self::Data) -> Result<(), Self::Error> {
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
}

impl Signature for KERISignatureStr {
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
        self.to_owned()
    }
}

impl Signature for &'static KERISignatureStr {
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
        (*self).to_signature_bytes()
    }
    fn to_keri_signature(&self) -> KERISignature {
        (*self).to_owned()
    }
}
