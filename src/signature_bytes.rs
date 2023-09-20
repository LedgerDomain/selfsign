use std::borrow::Cow;

use crate::{KERISignature, Signature, SignatureAlgorithm};

pub const ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER: SignatureBytes<'static> = SignatureBytes {
    signature_algorithm: SignatureAlgorithm::Ed25519_SHA2_512,
    signature_byte_v: Cow::Borrowed(&[0u8; 64]),
};
pub const SECP256K1_SHA2_256_SIGNATURE_BYTES_PLACEHOLDER: SignatureBytes<'static> =
    SignatureBytes {
        signature_algorithm: SignatureAlgorithm::Secp256k1_SHA2_256,
        signature_byte_v: Cow::Borrowed(&[0u8; 64]),
    };

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SignatureBytes<'a> {
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_byte_v: Cow<'a, [u8]>,
}

impl<'a> SignatureBytes<'a> {
    pub fn into_owned(self) -> SignatureBytes<'static> {
        SignatureBytes {
            signature_algorithm: self.signature_algorithm,
            signature_byte_v: Cow::Owned(self.signature_byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> SignatureBytes<'static> {
        SignatureBytes {
            signature_algorithm: self.signature_algorithm,
            signature_byte_v: Cow::Owned(self.signature_byte_v.to_vec()),
        }
    }
    pub fn to_keri_signature(&self) -> KERISignature<'static> {
        // TODO: Need to use different sizes based on SignatureAlgorithm.
        let mut buffer = [0u8; 86];
        let signature = crate::base64_encode_512_bits(
            self.signature_byte_v
                .as_ref()
                .try_into()
                .expect("temp hack"),
            &mut buffer,
        );
        let keri_signature_string =
            format!("{}{}", self.signature_algorithm.keri_prefix(), signature);
        KERISignature(Cow::Owned(keri_signature_string))
    }
}

impl std::ops::Deref for SignatureBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.signature_byte_v.as_ref()
    }
}

impl Signature for SignatureBytes<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
    fn to_signature_bytes(&self) -> SignatureBytes {
        self.clone()
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.to_keri_signature()
    }
}
