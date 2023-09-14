use std::borrow::Cow;

use crate::{
    base64_decode_256_bits, Hasher, KeyType, Signature, SignatureAlgorithm, Verifier,
    VerifierBytes, ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER,
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
    pub fn to_verifier_bytes(&self) -> VerifierBytes {
        let mut buffer = [0u8; 33];
        // NOTE: This only works with 1-char prefixes.
        let verifying_key_byte_v = base64_decode_256_bits(&self.0[1..], &mut buffer)
            .expect("this should not fail because of check in from_str");
        use std::str::FromStr;
        VerifierBytes {
            signature_algorithm: KeyType::from_str(&self.0[0..1])
                .expect("this should not fail because of check in from_str")
                .default_signature_algorithm(),
            verifying_key_byte_v: Cow::Owned(verifying_key_byte_v.to_vec()),
        }
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
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        // This assumes that the prefix is 2 chars.  TODO: Real implementation
        use std::str::FromStr;
        KeyType::from_str(&self.0[0..1])
            .unwrap()
            .default_signature_algorithm()
    }
    fn to_verifier_bytes(&self) -> VerifierBytes {
        self.to_verifier_bytes()
    }
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.clone()
    }
    fn placeholder_signature(&self) -> &'static dyn Signature {
        match self.signature_algorithm() {
            SignatureAlgorithm::Ed25519_SHA2_512 => &ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER,
        }
    }
    fn verify_digest(
        &self,
        message_digest: Hasher,
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        if message_digest.hash_function()
            != self.signature_algorithm().message_digest_hash_function()
        {
            panic!("programmer error: message_digest and verifier hash functions must match");
        }
        match self.signature_algorithm() {
            SignatureAlgorithm::Ed25519_SHA2_512 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let mut buffer = [0u8; 33];
                    let verifying_key_byte_array =
                        base64_decode_256_bits(&self.0.as_ref()[1..], &mut buffer)?;
                    let verifying_key =
                        ed25519_dalek::VerifyingKey::from_bytes(verifying_key_byte_array)
                            .map_err(|_| "ed25519_dalek::VerifyingKey::from_bytes failed")?;

                    let signature_bytes = signature.to_signature_bytes();
                    let signature_byte_array: &[u8; 64] = signature_bytes
                        .signature_byte_v
                        .as_ref()
                        .try_into()
                        .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
                    let signature = ed25519_dalek::Signature::from_bytes(signature_byte_array);

                    verifying_key
                        .verify_prehashed(message_digest.into_sha2_512(), None, &signature)
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
