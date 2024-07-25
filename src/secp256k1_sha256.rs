use std::borrow::Cow;

use crate::{
    KERISignatureStr, KeyType, NamedSignatureAlgorithm, SignatureAlgorithm, SignatureBytes,
};

const SECP256K1_SHA_256_KERI_SIGNATURE_PLACEHOLDER: &'static KERISignatureStr = unsafe {
    KERISignatureStr::new_ref_unchecked(
        "0CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
};

#[cfg(test)]
mod tests {
    use crate::secp256k1_sha256::SECP256K1_SHA_256_KERI_SIGNATURE_PLACEHOLDER;

    #[test]
    fn test_validity_of_keri_signature_placeholder_secp256k1_sha_256() {
        use pneutype::Validate;
        super::KERISignatureStr::validate(SECP256K1_SHA_256_KERI_SIGNATURE_PLACEHOLDER.as_str())
            .expect("pass");
    }
}

const SECP256K1_SHA_256_SIGNATURE_BYTES_PLACEHOLDER: SignatureBytes<'static> = SignatureBytes {
    named_signature_algorithm: NamedSignatureAlgorithm::SECP256K1_SHA_256,
    signature_byte_v: Cow::Borrowed(&[0u8; 64]),
};

/// This represents the Secp256k1SHA256 signature algorithm itself.  Note that this is distinct from
/// the Signer or Signature.
#[allow(non_camel_case_types)]
pub struct Secp256k1_SHA256;

pub const SECP256K1_SHA_256: Secp256k1_SHA256 = Secp256k1_SHA256;

impl SignatureAlgorithm for Secp256k1_SHA256 {
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
        NamedSignatureAlgorithm::SECP256K1_SHA_256
    }
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn message_digest_hash_function(&self) -> &'static dyn selfhash::HashFunction {
        &selfhash::SHA256
    }
    fn keri_prefix(&self) -> &'static str {
        "0C"
    }
    fn signature_bytes_len(&self) -> usize {
        64
    }
    fn keri_signature_len(&self) -> usize {
        88
    }
    fn placeholder_keri_signature(&self) -> &'static KERISignatureStr {
        SECP256K1_SHA_256_KERI_SIGNATURE_PLACEHOLDER
    }
    fn placeholder_signature_bytes(&self) -> SignatureBytes<'static> {
        SECP256K1_SHA_256_SIGNATURE_BYTES_PLACEHOLDER
    }
}
