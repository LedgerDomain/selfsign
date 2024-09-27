use crate::{
    error, require, Error, KeyType, NamedSignatureAlgorithm, PreferredSignatureFormat,
    PreferredVerifierFormat, PrivateKeyBytes, Result, Signature, SignatureAlgorithm,
    SignatureBytes, Signer, Verifier, VerifierBytes, SECP256K1_SHA_256,
};
use std::borrow::Cow;

impl Signer for k256::ecdsa::SigningKey {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        &SECP256K1_SHA_256
    }
    fn to_private_key_bytes(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::new(KeyType::Secp256k1, Cow::Owned(self.to_bytes().to_vec()))
            .expect("programmer error")
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
    fn sign_digest(&self, hasher_b: Box<dyn selfhash::Hasher>) -> Result<Box<dyn Signature>> {
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
    /// This will allocate, because of the way the k256 crate returns the signature bytes.
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h> {
        PreferredSignatureFormat::SignatureBytes(SignatureBytes {
            named_signature_algorithm: self.signature_algorithm().named_signature_algorithm(),
            signature_byte_v: Cow::Owned(self.to_bytes().to_vec()),
        })
    }
}

impl TryFrom<&SignatureBytes<'_>> for k256::ecdsa::Signature {
    type Error = Error;
    fn try_from(signature_bytes: &SignatureBytes) -> std::result::Result<Self, Self::Error> {
        require!(
            signature_bytes
                .named_signature_algorithm
                .equals(&NamedSignatureAlgorithm::SECP256K1_SHA_256),
            "signature_algorithm ({}) must be {}",
            signature_bytes.named_signature_algorithm,
            NamedSignatureAlgorithm::SECP256K1_SHA_256
        );
        let signature_byte_array = signature_bytes
            .signature_byte_v
            .as_ref()
            .try_into()
            .map_err(|_| {
                error!(
                    "signature_byte_v must be exactly 64 bytes long but it was {} bytes long",
                    signature_bytes.signature_byte_v.len()
                )
            })?;
        Ok(Self::from_bytes(signature_byte_array)
            .map_err(|e| error!("malformed k256 Signature: {}", e))?)
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
    type Error = Error;
    fn try_from(verifier_bytes: &VerifierBytes) -> std::result::Result<Self, Self::Error> {
        require!(
            verifier_bytes.key_type == KeyType::Secp256k1,
            "key_type ({}) must be {}",
            verifier_bytes.key_type,
            KeyType::Secp256k1
        );
        let k256_verifying_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&verifier_bytes.verifying_key_byte_v)
                .map_err(|e| error!("k256::ecdsa::VerifyingKey::from_bytes failed: {}", e))?;
        Ok(k256_verifying_key)
    }
}

impl Verifier for k256::ecdsa::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    /// This will allocate, because of how k256 crate returns the verifying key bytes.
    fn as_preferred_verifier_format<'s: 'h, 'h>(&'s self) -> PreferredVerifierFormat<'h> {
        let verifying_key_byte_v = self.to_sec1_bytes().to_vec();
        PreferredVerifierFormat::VerifierBytes(VerifierBytes {
            key_type: self.key_type(),
            verifying_key_byte_v: Cow::Owned(verifying_key_byte_v),
        })
    }
    fn verify_digest(
        &self,
        message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<()> {
        if !message_digest_b.hash_function().equals(
            signature
                .signature_algorithm()
                .message_digest_hash_function(),
        ) {
            panic!("programmer error: message_digest and verifier hash functions must match");
        }
        require!(
            self.key_type() == signature.signature_algorithm().key_type(),
            "key_type ({}) must match that of signature_algorithm ({})",
            self.key_type(),
            signature.signature_algorithm().key_type()
        );
        let k256_signature = k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())
            .map_err(|e| error!("malformed k256 Signature: {}", e))?;
        let message_digest = *message_digest_b
            .into_any()
            .downcast::<sha2::Sha256>()
            .expect("programmer error: message_digest_b must be sha2::Sha256");
        k256::ecdsa::signature::DigestVerifier::verify_digest(self, message_digest, &k256_signature)
            .map_err(|e| error!("Secp256k1_SHA_256 signature verification failed: {}", e))
    }
}
