use std::borrow::Cow;

use crate::{
    KERISignature, NamedSignatureAlgorithm, PreferredSignatureFormat, Signature,
    SignatureAlgorithm, ED25519_SHA_512, SECP256K1_SHA_256,
};

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SignatureBytes<'a> {
    pub named_signature_algorithm: NamedSignatureAlgorithm,
    pub signature_byte_v: Cow<'a, [u8]>,
}

impl<'a> SignatureBytes<'a> {
    pub fn into_owned(self) -> SignatureBytes<'static> {
        SignatureBytes {
            named_signature_algorithm: self.named_signature_algorithm,
            signature_byte_v: Cow::Owned(self.signature_byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> SignatureBytes<'static> {
        SignatureBytes {
            named_signature_algorithm: self.named_signature_algorithm.clone(),
            signature_byte_v: Cow::Owned(self.signature_byte_v.to_vec()),
        }
    }
    pub fn to_keri_signature(&self) -> KERISignature {
        // TODO: Need to use different sizes based on SignatureAlgorithm.
        let mut buffer = [0u8; 86];
        let signature = selfhash::base64_encode_512_bits(
            self.signature_byte_v
                .as_ref()
                .try_into()
                .expect("temp hack"),
            &mut buffer,
        );
        let keri_signature_string = format!(
            "{}{}",
            self.named_signature_algorithm.keri_prefix(),
            signature
        );
        KERISignature::try_from(keri_signature_string)
            .expect("programmer error: should be a valid KERISignature by construction")
    }
}

impl AsRef<[u8]> for SignatureBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.signature_byte_v.as_ref()
    }
}

impl std::ops::Deref for SignatureBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.signature_byte_v.as_ref()
    }
}

impl Signature for SignatureBytes<'_> {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        match self.named_signature_algorithm {
            NamedSignatureAlgorithm::ED25519_SHA_512 => &ED25519_SHA_512,
            NamedSignatureAlgorithm::SECP256K1_SHA_256 => &SECP256K1_SHA_256,
            _ => {
                panic!("unrecognized signature algorithm");
            }
        }
    }
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h> {
        PreferredSignatureFormat::SignatureBytes(SignatureBytes {
            named_signature_algorithm: self.named_signature_algorithm.clone(),
            signature_byte_v: Cow::Borrowed(&self.signature_byte_v),
        })
    }
}
