use crate::{
    base64_encode_264_bits, error, require, KERIVerifier, KeyType, NamedSignatureAlgorithm,
    PreferredVerifierFormat, Result, Signature, Verifier,
};
use std::borrow::Cow;

/// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct VerifierBytes<'a> {
    pub key_type: KeyType,
    pub verifying_key_byte_v: Cow<'a, [u8]>,
}

impl<'a> VerifierBytes<'a> {
    pub fn into_owned(self) -> VerifierBytes<'static> {
        VerifierBytes {
            key_type: self.key_type,
            verifying_key_byte_v: Cow::Owned(self.verifying_key_byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> VerifierBytes<'static> {
        VerifierBytes {
            key_type: self.key_type,
            verifying_key_byte_v: Cow::Owned(self.verifying_key_byte_v.to_vec()),
        }
    }
    pub fn to_keri_verifier(&self) -> Result<KERIVerifier> {
        require!(
            self.verifying_key_byte_v.len() == self.key_type.public_key_bytes_len(),
            "verifying_key_byte_v length ({}) does not match expected bytes length ({}) of KeyType {:?}",
            self.verifying_key_byte_v.len(),
            self.key_type.public_key_bytes_len(),
            self.key_type
        );
        let keri_verifier_string = match self.key_type.public_key_bytes_len() {
            32 => {
                let mut buffer = [0u8; 43];
                let verifying_key = selfhash::base64_encode_256_bits(
                    self.verifying_key_byte_v
                        .as_ref()
                        .try_into()
                        .expect("temp hack"),
                    &mut buffer,
                );
                format!("{}{}", self.key_type.keri_prefix(), verifying_key)
            }
            33 => {
                let mut buffer = [0u8; 44];
                let verifying_key = base64_encode_264_bits(
                    self.verifying_key_byte_v
                        .as_ref()
                        .try_into()
                        .expect("temp hack"),
                    &mut buffer,
                );
                format!("{}{}", self.key_type.keri_prefix(), verifying_key)
            }
            64 => {
                let mut buffer = [0u8; 86];
                let verifying_key = selfhash::base64_encode_512_bits(
                    self.verifying_key_byte_v
                        .as_ref()
                        .try_into()
                        .expect("temp hack"),
                    &mut buffer,
                );
                format!("{}{}", self.key_type.keri_prefix(), verifying_key)
            }
            _ => {
                panic!("this should not be possible");
            }
        };
        Ok(KERIVerifier::try_from(keri_verifier_string)
            .expect("programmer error: should be a valid KERIVerifier by construction"))
    }
}

impl AsRef<[u8]> for VerifierBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.verifying_key_byte_v.as_ref()
    }
}

impl std::ops::Deref for VerifierBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.verifying_key_byte_v.as_ref()
    }
}

impl Verifier for VerifierBytes<'_> {
    fn key_type(&self) -> KeyType {
        self.key_type
    }
    fn as_preferred_verifier_format<'s: 'h, 'h>(&'s self) -> PreferredVerifierFormat<'h> {
        PreferredVerifierFormat::VerifierBytes(VerifierBytes {
            key_type: self.key_type,
            verifying_key_byte_v: Cow::Borrowed(&self.verifying_key_byte_v),
        })
    }
    fn verify_digest(
        &self,
        _message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<()> {
        require!(
            self.key_type == signature.signature_algorithm().key_type(),
            "key_type ({:?}) must match that of signature_algorithm ({:?})",
            self.key_type,
            signature.signature_algorithm().key_type()
        );
        // TODO: It would be better if this dispatched to the specific verifiers instead of
        // invoking ed25519-dalek and k256 crates directly here.
        match signature.signature_algorithm().named_signature_algorithm() {
            NamedSignatureAlgorithm::ED25519_SHA_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let ed25519_dalek_verifying_key = ed25519_dalek::VerifyingKey::try_from(self)?;
                    let ed25519_dalek_signature =
                        ed25519_dalek::Signature::try_from(&signature.to_signature_bytes())?;
                    ed25519_dalek_verifying_key
                        .verify_prehashed(
                            *_message_digest_b
                                .into_any()
                                .downcast::<sha2::Sha512>()
                                .expect("programmer error: message digest must be sha2::Sha512"),
                            None,
                            &ed25519_dalek_signature,
                        )
                        .map_err(|e| error!("Ed25519_SHA_512 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            NamedSignatureAlgorithm::SECP256K1_SHA_256 => {
                #[cfg(feature = "k256")]
                {
                    let k256_verifying_key = k256::ecdsa::VerifyingKey::try_from(self)?;
                    let k256_signature =
                        k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;
                    k256::ecdsa::signature::DigestVerifier::verify_digest(
                        &k256_verifying_key,
                        *_message_digest_b
                            .into_any()
                            .downcast::<sha2::Sha256>()
                            .expect("programmer error: message digest must be sha2::Sha256"),
                        &k256_signature,
                    )
                    .map_err(|e| error!("Secp256k1_SHA_256 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("k256 feature not enabled");
                }
            }
            _ => {
                panic!("unrecognized signature algorithm");
            }
        }
    }
}
