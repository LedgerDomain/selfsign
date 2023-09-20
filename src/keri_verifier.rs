use std::{borrow::Cow, str::FromStr};

use crate::{
    base64_decode_256_bits, base64_decode_264_bits, Hasher, KeyType, Signature, SignatureAlgorithm,
    Verifier, VerifierBytes,
};

/// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, derive_more::Display, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay)
)]
pub struct KERIVerifier<'a>(pub(crate) Cow<'a, str>);

impl<'a> KERIVerifier<'a> {
    pub fn into_owned(self) -> KERIVerifier<'static> {
        KERIVerifier(Cow::Owned(self.0.into_owned()))
    }
    pub fn to_owned(&self) -> KERIVerifier<'static> {
        KERIVerifier(Cow::Owned(self.0.to_string()))
    }
    pub fn to_verifier_bytes(&self) -> VerifierBytes {
        match self.len() {
            44 => {
                // NOTE: This assumes that 44 chars imply a 1-char prefix and a 43-char base64 string.
                let mut buffer = [0u8; 33];
                let verifying_key_byte_v = base64_decode_256_bits(&self.0[1..], &mut buffer)
                    .expect("this should not fail because of check in from_str");
                VerifierBytes {
                    key_type: KeyType::from_str(&self.0[..1])
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
                    key_type: KeyType::from_str(&self.0[..4])
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

impl<'a> std::ops::Deref for KERIVerifier<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::str::FromStr for KERIVerifier<'_> {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 1 {
            return Err("KERISignature::from_str failed: too short");
        }
        if !s.is_ascii() {
            return Err("KERISignature::from_str failed: not ASCII");
        }
        let key_type = KeyType::from_str(&s[..1])?;
        match key_type.key_bytes_len() {
            32 => {
                let mut buffer = [0u8; 33];
                base64_decode_256_bits(&s[1..], &mut buffer)?;
                Ok(Self(Cow::Owned(s.to_string())))
            }
            _ => {
                panic!("this should not be possible");
            }
        }
    }
}

impl Verifier for KERIVerifier<'_> {
    fn key_type(&self) -> KeyType {
        const ED25519_KERI_PREFIX: &'static str = KeyType::Ed25519.keri_prefix();
        const SECP256K1_KERI_PREFIX: &'static str = KeyType::Secp256k1.keri_prefix();
        match &self.0[..1] {
            ED25519_KERI_PREFIX => KeyType::from_str(&self.0[..1])
                .expect("this should not be possible because of check in from_str"),
            "1" => match &self.0[..4] {
                SECP256K1_KERI_PREFIX => KeyType::from_str(&self.0[..4])
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
    fn to_verifier_bytes(&self) -> VerifierBytes {
        self.to_verifier_bytes()
    }
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.clone()
    }
    fn verify_digest(
        &self,
        message_digest: Hasher,
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        if message_digest.hash_function()
            != signature
                .signature_algorithm()
                .message_digest_hash_function()
        {
            panic!("programmer error: message_digest and verifier hash functions must match");
        }
        if self.key_type() != signature.signature_algorithm().key_type() {
            return Err("key_type must match that of signature_algorithm");
        }
        match signature.signature_algorithm() {
            SignatureAlgorithm::Ed25519_SHA2_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let ed25519_dalek_verifying_key =
                        ed25519_dalek::VerifyingKey::try_from(&self.to_verifier_bytes())?;
                    let ed25519_dalek_signature =
                        ed25519_dalek::Signature::try_from(&signature.to_signature_bytes())?;
                    ed25519_dalek_verifying_key
                        .verify_prehashed(
                            message_digest.into_sha2_512(),
                            None,
                            &ed25519_dalek_signature,
                        )
                        .map_err(|_| "Ed25519_SHA2_512 signature verification failed")
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            SignatureAlgorithm::Secp256k1_SHA2_256 => {
                #[cfg(feature = "k256")]
                {
                    let k256_verifying_key =
                        k256::ecdsa::VerifyingKey::try_from(&self.to_verifier_bytes())?;
                    let k256_signature =
                        k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;

                    k256::ecdsa::signature::DigestVerifier::verify_digest(
                        &k256_verifying_key,
                        message_digest.into_sha2_256(),
                        &k256_signature,
                    )
                    .map_err(|_| "Secp256k1_SHA2_256 signature verification failed")
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("k256 feature not enabled");
                }
            }
        }
    }
}
