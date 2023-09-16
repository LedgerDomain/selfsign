use crate::{
    Hasher, KERISignature, KERIVerifier, KeyType, Signature, SignatureAlgorithm, SignatureBytes,
    Signer, Verifier, VerifierBytes,
};

impl Signer for ed25519_dalek::SigningKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519_SHA2_512
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
    fn sign_digest(&self, hasher: &Hasher) -> Result<Box<dyn Signature>, &'static str> {
        if hasher.hash_function() != self.signature_algorithm().message_digest_hash_function() {
            panic!("programmer error: hasher and signer hash functions must match");
        }
        let signature =
            ed25519_dalek::DigestSigner::sign_digest(self, hasher.as_sha2_512().clone());
        Ok(Box::new(signature))
    }
}

impl Signature for ed25519_dalek::Signature {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519_SHA2_512
    }
    fn to_signature_bytes(&self) -> SignatureBytes {
        SignatureBytes {
            signature_algorithm: self.signature_algorithm(),
            signature_byte_v: self.to_vec().into(),
        }
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.to_signature_bytes().to_keri_signature()
    }
}

impl TryFrom<SignatureBytes<'_>> for ed25519_dalek::Signature {
    type Error = &'static str;
    fn try_from(signature_bytes: SignatureBytes) -> Result<Self, Self::Error> {
        if signature_bytes.signature_algorithm != SignatureAlgorithm::Ed25519_SHA2_512 {
            return Err("signature_algorithm must be Ed25519_SHA2_512");
        }
        let signature_byte_array: &[u8; 64] = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
        Ok(Self::from_bytes(signature_byte_array))
    }
}

impl From<ed25519_dalek::Signature> for SignatureBytes<'_> {
    fn from(signature: ed25519_dalek::Signature) -> Self {
        Self {
            signature_algorithm: SignatureAlgorithm::Ed25519_SHA2_512,
            signature_byte_v: signature.to_bytes().to_vec().into(),
        }
    }
}

impl TryFrom<VerifierBytes<'_>> for ed25519_dalek::VerifyingKey {
    type Error = &'static str;
    fn try_from(verifier_bytes: VerifierBytes) -> Result<Self, Self::Error> {
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
    fn to_verifier_bytes(&self) -> VerifierBytes {
        VerifierBytes {
            key_type: self.key_type(),
            verifying_key_byte_v: self.to_bytes().to_vec().into(),
        }
    }
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.to_verifier_bytes()
            .to_keri_verifier()
            .expect("programmer error")
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
        let signature_bytes = signature.to_signature_bytes();
        let signature_byte_array: &[u8; 64] = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
        let signature = ed25519_dalek::Signature::from_bytes(signature_byte_array);
        self.verify_prehashed(message_digest.into_sha2_512(), None, &signature)
            .map_err(|_| "Ed25519_SHA2_512 signature verification failed")
    }
}
