use crate::{
    KERISignature, KERIVerifier, KeyType, NamedSignatureAlgorithm, Signature, SignatureAlgorithm,
    SignatureBytes, Signer, Verifier, VerifierBytes, SECP256K1_SHA_256,
};

impl Signer for k256::ecdsa::SigningKey {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        &SECP256K1_SHA_256
    }
    fn verifier(&self) -> Box<dyn Verifier> {
        Box::new(self.verifying_key().clone())
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
        let signature: k256::ecdsa::Signature = k256::ecdsa::signature::DigestSigner::sign_digest(
            self,
            *hasher_b
                .into_any()
                .downcast::<sha2::Sha256>()
                .expect("programmer error: hasher must be sha2::Sha256"),
        );
        Ok(Box::new(signature))
    }
}

impl Signature for k256::ecdsa::Signature {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        &SECP256K1_SHA_256
    }
    fn to_signature_bytes(&self) -> SignatureBytes {
        SignatureBytes {
            named_signature_algorithm: self.signature_algorithm().named_signature_algorithm(),
            signature_byte_v: self.to_bytes().to_vec().into(),
        }
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.to_signature_bytes().to_keri_signature()
    }
}

impl TryFrom<&SignatureBytes<'_>> for k256::ecdsa::Signature {
    type Error = &'static str;
    fn try_from(signature_bytes: &SignatureBytes) -> Result<Self, Self::Error> {
        if !signature_bytes
            .named_signature_algorithm
            .equals(&NamedSignatureAlgorithm::SECP256K1_SHA_256)
        {
            return Err("signature_algorithm must be Secp256k1_SHA_256");
        }
        let signature_byte_array = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| "signature_byte_v must be exactly 64 bytes long")?;
        Ok(Self::from_bytes(signature_byte_array).map_err(|_| "malformed k256 Signature")?)
    }
}

impl From<&k256::ecdsa::Signature> for SignatureBytes<'_> {
    fn from(signature: &k256::ecdsa::Signature) -> Self {
        Self {
            named_signature_algorithm: NamedSignatureAlgorithm::SECP256K1_SHA_256,
            signature_byte_v: signature.to_bytes().to_vec().into(),
        }
    }
}

impl TryFrom<&VerifierBytes<'_>> for k256::ecdsa::VerifyingKey {
    type Error = &'static str;
    fn try_from(verifier_bytes: &VerifierBytes) -> Result<Self, Self::Error> {
        if verifier_bytes.key_type != KeyType::Secp256k1 {
            return Err("key_type must be Secp256k1");
        }
        let k256_verifying_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&verifier_bytes.verifying_key_byte_v)
                .map_err(|_| "k256::ecdsa::VerifyingKey::from_bytes failed")?;
        Ok(k256_verifying_key)
    }
}

impl Verifier for k256::ecdsa::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn to_verifier_bytes(&self) -> VerifierBytes {
        let verifying_key_byte_v = self.to_sec1_bytes().to_vec();
        VerifierBytes {
            key_type: self.key_type(),
            verifying_key_byte_v: verifying_key_byte_v.into(),
        }
    }
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
        let k256_signature = k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())
            .map_err(|_| "malformed k256 Signature")?;
        let message_digest = *message_digest_b
            .into_any()
            .downcast::<sha2::Sha256>()
            .expect("programmer error: message_digest_b must be sha2::Sha256");
        k256::ecdsa::signature::DigestVerifier::verify_digest(self, message_digest, &k256_signature)
            .map_err(|_| "Secp256k1_SHA_256 signature verification failed")
    }
}
