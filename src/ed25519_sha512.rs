use std::borrow::Cow;

use crate::{KERISignature, KeyType, NamedSignatureAlgorithm, SignatureAlgorithm, SignatureBytes};

// This needs the str equivalent of KERISignature before it can work.
// pub const ED25519_SHA_512_KERI_SIGNATURE_PLACEHOLDER: KERISignature = KERISignature(
//     "0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
//         .to_string(),
// );

// TODO: Put this back into a const once the str equivalent of KERISignature is available, then remove the lazy_static depedendency.
lazy_static::lazy_static! {
    pub static ref ED25519_SHA_512_KERI_SIGNATURE_PLACEHOLDER: KERISignature = KERISignature(
        "0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
}

pub const ED25519_SHA_512_SIGNATURE_BYTES_PLACEHOLDER: SignatureBytes<'static> = SignatureBytes {
    named_signature_algorithm: NamedSignatureAlgorithm::ED25519_SHA_512,
    signature_byte_v: Cow::Borrowed(&[0u8; 64]),
};

/// This represents the Ed25519_SHA_512 signature algorithm itself.  Note that this is distinct from
/// the Signer or Signature.
#[allow(non_camel_case_types)]
pub struct Ed25519_SHA512;

pub const ED25519_SHA_512: Ed25519_SHA512 = Ed25519_SHA512;

impl SignatureAlgorithm for Ed25519_SHA512 {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn equals(&self, other: &dyn SignatureAlgorithm) -> bool {
        if other.as_any().is::<Self>() {
            // This SignatureAlgorithm has no parameters, so it is always equal to itself.
            true
        } else {
            false
        }
    }
    fn named_signature_algorithm(&self) -> NamedSignatureAlgorithm {
        NamedSignatureAlgorithm::ED25519_SHA_512
    }
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn message_digest_hash_function(&self) -> &'static dyn selfhash::HashFunction {
        &selfhash::SHA512
    }
    fn keri_prefix(&self) -> &'static str {
        "0B"
    }
    fn signature_bytes_len(&self) -> usize {
        64
    }
    fn keri_signature_len(&self) -> usize {
        88
    }
    fn placeholder_keri_signature(&self) -> &'static KERISignature {
        &ED25519_SHA_512_KERI_SIGNATURE_PLACEHOLDER
    }
    fn placeholder_signature_bytes(&self) -> SignatureBytes<'static> {
        ED25519_SHA_512_SIGNATURE_BYTES_PLACEHOLDER
    }
}
