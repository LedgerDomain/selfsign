use std::borrow::Cow;

use crate::{
    base64::{base64_encode_256_bits, base64_encode_512_bits},
    Hasher, KERIVerifier, Signature, SignatureAlgorithm, Verifier,
    ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER,
};

/// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct VerifierBytes<'a> {
    pub signature_algorithm: SignatureAlgorithm,
    pub verifying_key_byte_v: Cow<'a, [u8]>,
}

impl<'a> VerifierBytes<'a> {
    pub fn into_owned(self) -> VerifierBytes<'static> {
        VerifierBytes {
            signature_algorithm: self.signature_algorithm,
            verifying_key_byte_v: Cow::Owned(self.verifying_key_byte_v.into_owned()),
        }
    }
    pub fn to_keri_verifier(&self) -> Result<KERIVerifier<'static>, &'static str> {
        if self.verifying_key_byte_v.len() != self.signature_algorithm.key_type().key_bytes_len() {
            return Err(
                "verifying_key_byte_v length does not match expected bytes length of KeyType",
            );
        }
        // A buffer that can hold the base64-encoding of the longest possible signature bytes.
        let keri_verifier_string = match self.signature_algorithm.key_type().key_bytes_len() {
            32 => {
                let mut buffer = [0u8; 43];
                let verifying_key = base64_encode_256_bits(
                    self.verifying_key_byte_v
                        .as_ref()
                        .try_into()
                        .expect("temp hack"),
                    &mut buffer,
                );
                format!(
                    "{}{}",
                    self.signature_algorithm.key_type().keri_prefix(),
                    verifying_key
                )
            }
            64 => {
                let mut buffer = [0u8; 86];
                let verifying_key = base64_encode_512_bits(
                    self.verifying_key_byte_v
                        .as_ref()
                        .try_into()
                        .expect("temp hack"),
                    &mut buffer,
                );
                format!(
                    "{}{}",
                    self.signature_algorithm.key_type().keri_prefix(),
                    verifying_key
                )
            }
            _ => {
                panic!("this should not be possible");
            }
        };
        Ok(KERIVerifier(Cow::Owned(keri_verifier_string)))
    }
}

impl Verifier for VerifierBytes<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
    fn to_verifier_bytes(&self) -> VerifierBytes {
        self.clone()
    }
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.to_keri_verifier().expect("programmer error")
    }
    fn placeholder_signature(&self) -> &'static dyn Signature {
        match self.signature_algorithm {
            SignatureAlgorithm::Ed25519_SHA2_512 => &ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER,
        }
    }
    fn verify_digest(
        &self,
        message_digest: Hasher,
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        match self.signature_algorithm {
            SignatureAlgorithm::Ed25519_SHA2_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    // TODO: Use From traits between the various types.
                    let ed25519_dalek_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                        self.verifying_key_byte_v
                            .as_ref()
                            .try_into()
                            .map_err(|_| "malformed Ed25519 verifying key")?,
                    )
                    .map_err(|_| "malformed Ed25519 verifying key")?;
                    let ed25519_dalek_signature = ed25519_dalek::Signature::from_bytes(
                        signature
                            .to_signature_bytes()
                            .signature_byte_v
                            .as_ref()
                            .try_into()
                            .map_err(|_| "malformed Ed25519 signature")?,
                    );
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
        }
    }
}
