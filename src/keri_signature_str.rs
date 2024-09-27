use crate::{
    require, Error, NamedSignatureAlgorithm, PreferredSignatureFormat, Signature,
    SignatureAlgorithm, SignatureBytes, ED25519_SHA_512, SECP256K1_SHA_256,
};
use std::borrow::Cow;

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
    pub fn to_signature_bytes<'h>(&self) -> SignatureBytes<'h> {
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
    type Error = Error;
    fn validate(s: &Self::Data) -> std::result::Result<(), Self::Error> {
        require!(s.len() >= 2, "string too short to be a KERISignature");
        require!(
            s.is_ascii(),
            "KERISignature strings must contain only ASCII chars"
        );
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

impl<'a> Signature for &'a KERISignatureStr {
    /// This assumes the prefix is 2 chars.
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        // TODO: De-duplicate this with the others
        match self.keri_prefix() {
            "0B" => &ED25519_SHA_512,
            "0C" => &SECP256K1_SHA_256,
            _ => panic!("this should not be possible"),
        }
    }
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h> {
        PreferredSignatureFormat::KERISignature(Cow::Borrowed(self))
    }
}
