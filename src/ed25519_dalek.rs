use crate::{
    Ed25519_SHA512, KERISignature, KERIVerifier, KeyType, NamedSignatureAlgorithm, PrivateKeyBytes,
    Signature, SignatureAlgorithm, SignatureBytes, Signer, Verifier, VerifierBytes,
    ED25519_SHA_512,
};
use std::borrow::Cow;

impl Signer for ed25519_dalek::SigningKey {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        &Ed25519_SHA512
    }
    fn to_private_key_bytes(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::new(KeyType::Ed25519, Cow::Owned(self.to_bytes().to_vec()))
            .expect("programmer error")
    }
    fn verifier(&self) -> Box<dyn Verifier> {
        Box::new(self.verifying_key())
    }
    fn key_byte_len(&self) -> usize {
        32
    }
    fn copy_key_bytes(&self, target: &mut [u8]) {
        target.copy_from_slice(&self.to_bytes());
    }
    fn sign_digest(
        &self,
        hasher_b: Box<dyn selfhash::Hasher>,
    ) -> Result<Box<dyn Signature>, &'static str> {
        if !hasher_b
            .hash_function()
            .equals(self.signature_algorithm().message_digest_hash_function())
        {
            panic!("programmer error: hasher and signer hash functions must match");
        }
        let signature = ed25519_dalek::DigestSigner::sign_digest(
            self,
            *hasher_b
                .into_any()
                .downcast::<sha2::Sha512>()
                .expect("programmer error: hasher_b must be sha2::Sha512"),
        );
        Ok(Box::new(signature))
    }
}

impl Signature for ed25519_dalek::Signature {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        &ED25519_SHA_512
    }
    /// This will allocate, because of the way the ed25519_dalek crate returns the signature bytes.
    fn to_signature_bytes(&self) -> SignatureBytes {
        SignatureBytes {
            named_signature_algorithm: self.signature_algorithm().named_signature_algorithm(),
            signature_byte_v: Cow::Owned(self.to_bytes().to_vec()),
        }
    }
    /// This will allocate because it must convert from bytes to an ASCII string representation.
    fn to_keri_signature(&self) -> KERISignature {
        self.to_signature_bytes().to_keri_signature()
    }
}

impl TryFrom<&SignatureBytes<'_>> for ed25519_dalek::Signature {
    type Error = &'static str;
    fn try_from(signature_bytes: &SignatureBytes) -> Result<Self, Self::Error> {
        if !signature_bytes
            .named_signature_algorithm
            .equals(&NamedSignatureAlgorithm::ED25519_SHA_512)
        {
            return Err("signature_algorithm must be Ed25519_SHA_512");
        }
        let signature_byte_array: &[u8; 64] = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
        Ok(Self::from_bytes(signature_byte_array))
    }
}

impl From<&ed25519_dalek::Signature> for SignatureBytes<'_> {
    fn from(signature: &ed25519_dalek::Signature) -> Self {
        Self {
            named_signature_algorithm: NamedSignatureAlgorithm::ED25519_SHA_512,
            signature_byte_v: signature.to_bytes().to_vec().into(),
        }
    }
}

impl TryFrom<&VerifierBytes<'_>> for ed25519_dalek::VerifyingKey {
    type Error = &'static str;
    fn try_from(verifier_bytes: &VerifierBytes) -> Result<Self, Self::Error> {
        if verifier_bytes.key_type != KeyType::Ed25519 {
            return Err("key_type must be Ed25519");
        }
        let verifying_key_byte_array: &[u8; 32] = verifier_bytes
            .verifying_key_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "verifying_key_byte_v must be exactly 32 bytes long")?;
        Ok(Self::from_bytes(verifying_key_byte_array).map_err(|_| {
            "ed25519_dalek::VerifyingKey::from_bytes failed: malformed verifying_key_byte_v"
        })?)
    }
}

impl Verifier for ed25519_dalek::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    /// This will allocate, because of how ed25519_dalek crate returns the verifying key bytes.
    fn to_verifier_bytes(&self) -> VerifierBytes {
        VerifierBytes {
            key_type: self.key_type(),
            verifying_key_byte_v: Cow::Owned(self.to_bytes().to_vec()),
        }
    }
    /// This will allocate, because the verifier comes from a byte array and must be converted into a KERIVerifier.
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.to_verifier_bytes()
            .to_keri_verifier()
            .expect("programmer error")
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
        let signature_bytes = signature.to_signature_bytes();
        let signature_byte_array: &[u8; 64] = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
        let ed25519_dalek_signature = ed25519_dalek::Signature::from_bytes(signature_byte_array);
        let message_digest = *message_digest_b
            .into_any()
            .downcast::<sha2::Sha512>()
            .expect("programmer error: message_digest_b must be sha2::Sha512");
        self.verify_prehashed(message_digest, None, &ed25519_dalek_signature)
            .map_err(|_| "Ed25519_SHA_512 signature verification failed")
    }
}
