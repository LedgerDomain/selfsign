use crate::{
    require, KeyType, NamedSignatureAlgorithm, Result, Signature, SignatureAlgorithm, Signer,
    Verifier,
};
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
    pub fn new(key_type: KeyType, private_key_byte_v: Cow<'a, [u8]>) -> Result<Self> {
        require!(
            private_key_byte_v.len() == key_type.private_key_bytes_len(),
            "private_key_byte_v length ({}) does not match expected private key bytes length ({}) of KeyType {:?}",
            private_key_byte_v.len(),
            key_type.private_key_bytes_len(),
            key_type
        );
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
    fn sign_digest(&self, _hasher_b: Box<dyn selfhash::Hasher>) -> Result<Box<dyn Signature>> {
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
    fn write_to_pkcs8_pem_file(&self, private_key_path: &std::path::Path) -> Result<()> {
        #[cfg(feature = "pkcs8")]
        {
            match self.key_type.default_named_signature_algorithm() {
                NamedSignatureAlgorithm::ED25519_SHA_512 => {
                    #[cfg(feature = "ed25519-dalek")]
                    {
                        let secret_key =
                            ed25519_dalek::SecretKey::try_from(self.private_key_byte_v.as_ref())
                                .expect("this should not fail because of check in new");
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
                        use ed25519_dalek::pkcs8::EncodePrivateKey;
                        signing_key
                            .write_pkcs8_pem_file(private_key_path, Default::default())
                            .map_err(|e| crate::Error::from(e.to_string()))?;
                        Ok(())
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
                        let secret_key = k256::elliptic_curve::SecretKey::from(signing_key);
                        use k256::pkcs8::EncodePrivateKey;
                        secret_key
                            .write_pkcs8_pem_file(private_key_path, Default::default())
                            .map_err(|e| crate::Error::from(e.to_string()))?;
                        Ok(())
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

        #[cfg(not(feature = "pkcs8"))]
        {
            let _ = private_key_path;
            panic!(
                "programmer error: `pkcs8` feature must be enabled in order to write private key"
            );
        }
    }
    fn read_from_pkcs8_pem_file(private_key_path: &std::path::Path) -> Result<Self>
    where
        Self: Sized,
    {
        #[cfg(feature = "pkcs8")]
        {
            // TODO: Better would be to detect what key type the file claims to represent, so that a single,
            // specific format can be used, instead of guessing and having incomplete information about if
            // there's a problem.
            for &key_type in crate::KEY_TYPE_V {
                match key_type {
                    KeyType::Ed25519 => {
                        #[cfg(feature = "ed25519-dalek")]
                        {
                            // use pkcs8::DecodePrivateKey;
                            if let Ok(signing_key) =
                                ed25519_dalek::SigningKey::read_from_pkcs8_pem_file(
                                    &private_key_path,
                                )
                            {
                                return Ok(signing_key.to_private_key_bytes().into_owned());
                            }
                        }
                    }
                    KeyType::Secp256k1 => {
                        #[cfg(feature = "k256")]
                        {
                            // use pkcs8::DecodePrivateKey;
                            if let Ok(signing_key) =
                                k256::ecdsa::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                            {
                                return Ok(signing_key.to_private_key_bytes().into_owned());
                            }
                        }
                    }
                }
            }
            return Err(crate::Error::from(format!("Private key at path {:?} was not in a recognized format.  The problem might be that the `ed25519-dalek` and/or the `k256` features haven't been enabled.", private_key_path)));
        }

        #[cfg(not(feature = "pkcs8"))]
        {
            let _ = private_key_path;
            panic!(
                "programmer error: `pkcs8` feature must be enabled in order to write private key"
            );
        }
    }
}
