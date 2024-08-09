use crate::{
    base64_decode_264_bits, KeyType, NamedSignatureAlgorithm, Signature, Verifier, VerifierBytes,
};
use std::borrow::Cow;

/// This is the str-based analog to KERIVerifier.
#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_str(deserialize))]
#[repr(transparent)]
pub struct KERIVerifierStr(str);

impl KERIVerifierStr {
    pub fn to_verifier_bytes(&self) -> VerifierBytes {
        match self.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                let mut buffer = [0u8; 33];
                let verifying_key_byte_v =
                    selfhash::base64_decode_256_bits(&self.0[1..], &mut buffer)
                        .expect("this should not fail because of check in from_str");
                VerifierBytes {
                    key_type: KeyType::from_keri_prefix(&self.0[..1])
                        .expect("this should not fail because of check in from_str"),
                    verifying_key_byte_v: Cow::Owned(verifying_key_byte_v.to_vec()),
                }
            }
            48 => {
                // NOTE: This assumes that 48 chars imply a 4-char prefix and a 44-char base64 string.
                let mut buffer = [0u8; 33];
                let verifying_key_byte_v = base64_decode_264_bits(&self.0[4..], &mut buffer)
                    .expect("this should not fail because of check in from_str");
                VerifierBytes {
                    key_type: KeyType::from_keri_prefix(&self.0[..4])
                        .expect("this should not fail because of check in from_str"),
                    verifying_key_byte_v: Cow::Owned(verifying_key_byte_v.to_vec()),
                }
            }
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
}

impl pneutype::Validate for KERIVerifierStr {
    type Data = str;
    type Error = &'static str;
    fn validate(s: &Self::Data) -> Result<(), Self::Error> {
        if !s.is_ascii() {
            return Err("KERIVerifier strings must contain only ASCII chars");
        }
        match s.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                KeyType::from_keri_prefix(&s[..1])?;
                let mut buffer = [0u8; 33];
                selfhash::base64_decode_256_bits(&s[1..], &mut buffer)?;
            }
            48 => {
                // NOTE: This assumes that 48 chars imply a 4-char prefix and a 44-char base64 string.
                KeyType::from_keri_prefix(&s[..4])?;
                let mut buffer = [0u8; 33];
                base64_decode_264_bits(&s[4..], &mut buffer)?;
            }
            _ => {
                return Err("invalid length for KERIVerifier string; expected 44 or 48 chars");
            }
        }
        Ok(())
    }
}

impl<'a> Verifier for &'a KERIVerifierStr {
    fn key_type(&self) -> KeyType {
        const ED25519_KERI_PREFIX: &'static str = KeyType::Ed25519.keri_prefix();
        const SECP256K1_KERI_PREFIX: &'static str = KeyType::Secp256k1.keri_prefix();
        match &self.0[..1] {
            ED25519_KERI_PREFIX => KeyType::from_keri_prefix(&self.0[..1])
                .expect("this should not be possible because of check in from_str"),
            "1" => match &self.0[..4] {
                SECP256K1_KERI_PREFIX => KeyType::from_keri_prefix(&self.0[..4])
                    .expect("this should not be possible because of check in from_str"),
                _ => {
                    panic!("this should not be possible because of check in from_str");
                }
            },
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
    /// This will allocate, because KERIVerifier is an ASCII string representation and must be converted into bytes.
    fn to_verifier_bytes<'s: 'h, 'h>(&'s self) -> VerifierBytes<'h> {
        (*self).to_verifier_bytes()
    }
    fn to_keri_verifier<'s: 'h, 'h>(&'s self) -> Cow<'h, KERIVerifierStr> {
        Cow::Borrowed(*self)
    }
    fn verify_digest(
        &self,
        message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        if !message_digest_b.hash_function().equals(
            signature
                .signature_algorithm()
                .message_digest_hash_function(),
        ) {
            panic!("programmer error: message_digest and verifier hash functions must match");
        }
        if self.key_type() != signature.signature_algorithm().key_type() {
            return Err("key_type must match that of signature_algorithm");
        }
        // TODO: It would be better if this dispatched to the specific verifiers instead of
        // invoking ed25519-dalek and k256 crates directly here.
        match signature.signature_algorithm().named_signature_algorithm() {
            NamedSignatureAlgorithm::ED25519_SHA_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let ed25519_dalek_verifying_key =
                        ed25519_dalek::VerifyingKey::try_from(&self.to_verifier_bytes())?;
                    let ed25519_dalek_signature =
                        ed25519_dalek::Signature::try_from(&signature.to_signature_bytes())?;
                    ed25519_dalek_verifying_key
                        .verify_prehashed(
                            *message_digest_b
                                .into_any()
                                .downcast::<sha2::Sha512>()
                                .expect("programmer error: message_digest must be sha2::Sha512"),
                            None,
                            &ed25519_dalek_signature,
                        )
                        .map_err(|_| "Ed25519_SHA_512 signature verification failed")
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            NamedSignatureAlgorithm::SECP256K1_SHA_256 => {
                #[cfg(feature = "k256")]
                {
                    let k256_verifying_key =
                        k256::ecdsa::VerifyingKey::try_from(&self.to_verifier_bytes())?;
                    let k256_signature =
                        k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;

                    k256::ecdsa::signature::DigestVerifier::verify_digest(
                        &k256_verifying_key,
                        *message_digest_b
                            .into_any()
                            .downcast::<sha2::Sha256>()
                            .expect("programmer error: message_digest must be sha2::Sha256"),
                        &k256_signature,
                    )
                    .map_err(|_| "Secp256k1_SHA_256 signature verification failed")
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("k256 feature not enabled");
                }
            }
            _ => {
                panic!("this should not be possible because of check in from_str");
            }
        }
    }
}
