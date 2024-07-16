use crate::{KeyType, NamedSignatureAlgorithm, Signature, SignatureAlgorithm, Signer, Verifier};
use std::borrow::Cow;

/// This is a generic data structure to represent private keys that doesn't require direct use of the underlying
/// cryptographic libraries.  This is useful for serialization and deserialization of private keys.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrivateKeyBytes<'a> {
    key_type: KeyType,
    private_key_byte_v: Cow<'a, [u8]>,
}

impl<'a> PrivateKeyBytes<'a> {
    pub fn new(key_type: KeyType, private_key_byte_v: Cow<'a, [u8]>) -> Result<Self, &'static str> {
        if private_key_byte_v.len() != key_type.private_key_bytes_len() {
            return Err(
                "private_key_byte_v length does not match expected private key bytes length of KeyType",
            );
        }
        Ok(Self {
            key_type,
            private_key_byte_v,
        })
    }
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    pub fn private_key_bytes(&self) -> &[u8] {
        self.private_key_byte_v.as_ref()
    }
    pub fn into_private_key_byte_v(self) -> Cow<'a, [u8]> {
        self.private_key_byte_v
    }
    pub fn into_owned(self) -> PrivateKeyBytes<'static> {
        PrivateKeyBytes {
            key_type: self.key_type,
            private_key_byte_v: Cow::Owned(self.private_key_byte_v.into_owned()),
        }
    }
    pub fn to_owned(&self) -> PrivateKeyBytes<'static> {
        PrivateKeyBytes {
            key_type: self.key_type.clone(),
            private_key_byte_v: Cow::Owned(self.private_key_byte_v.to_vec()),
        }
    }
    // NOTE: "KERISigner" doesn't exactly exist as a concept.  The closest thing is storing seeds
    // for generating private keys (see https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#section-4.2)
}

impl AsRef<[u8]> for PrivateKeyBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        self.private_key_byte_v.as_ref()
    }
}

impl std::ops::Deref for PrivateKeyBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.private_key_byte_v.as_ref()
    }
}

impl Signer for PrivateKeyBytes<'_> {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        self.key_type
            .default_named_signature_algorithm()
            .as_signature_algorithm()
    }
    fn to_private_key_bytes(&self) -> PrivateKeyBytes {
        self.clone()
    }
    fn verifier(&self) -> Box<dyn Verifier> {
        match self.key_type.default_named_signature_algorithm() {
            NamedSignatureAlgorithm::ED25519_SHA_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let secret_key =
                        ed25519_dalek::SecretKey::try_from(self.private_key_byte_v.as_ref())
                            .expect("this should not fail because of check in new");
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
                    Box::new(signing_key.verifying_key())
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            NamedSignatureAlgorithm::SECP256K1_SHA_256 => {
                #[cfg(feature = "k256")]
                {
                    let signing_key =
                        k256::ecdsa::SigningKey::from_slice(self.private_key_byte_v.as_ref())
                            .expect("this should not fail because of check in new");
                    Box::new(signing_key.verifying_key().clone())
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
    fn key_byte_len(&self) -> usize {
        self.key_type.private_key_bytes_len()
    }
    fn copy_key_bytes(&self, target: &mut [u8]) {
        target.copy_from_slice(self.private_key_byte_v.as_ref());
    }
    fn to_key_byte_v(&self) -> Vec<u8> {
        self.private_key_byte_v.to_vec()
    }
    fn sign_digest(
        &self,
        _hasher_b: Box<dyn selfhash::Hasher>,
    ) -> Result<Box<dyn Signature>, &'static str> {
        match self.key_type.default_named_signature_algorithm() {
            NamedSignatureAlgorithm::ED25519_SHA_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let secret_key =
                        ed25519_dalek::SecretKey::try_from(self.private_key_byte_v.as_ref())
                            .expect("this should not fail because of check in new");
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
                    signing_key.sign_digest(_hasher_b)
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            NamedSignatureAlgorithm::SECP256K1_SHA_256 => {
                #[cfg(feature = "k256")]
                {
                    let signing_key =
                        k256::ecdsa::SigningKey::from_slice(self.private_key_byte_v.as_ref())
                            .expect("this should not fail because of check in new");
                    signing_key.sign_digest(_hasher_b)
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
