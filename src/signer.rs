use crate::{Signature, SignatureAlgorithm, Verifier};

/// A trait meant to represent a signing key and the relevant actions.  For example,
/// private keys for asymmetric cryptography, or an HMAC key.
pub trait Signer {
    /// Returns the SignatureAlgorithm that this Signer uses.
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm;
    /// Returns the corresponding verifier which can verify Signature-s that this Signer
    /// produces.  SignerTrait is to a private key as SignatureVerifier is to a public key.
    fn verifier(&self) -> Box<dyn Verifier>;
    /// Returns the number of bytes in the byte representation of this SignerTrait.
    fn key_byte_len(&self) -> usize;
    /// Copies the key bytes into the given target byte slice.  target.len() must be exactly
    /// equal to self.key_byte_len(), or this method will panic.
    fn copy_key_bytes(&self, target: &mut [u8]);
    /// Convenience function that returns the key bytes as a Vec<u8>.
    fn to_key_byte_v(&self) -> Vec<u8> {
        let mut key_byte_v = vec![0u8; self.key_byte_len()];
        self.copy_key_bytes(key_byte_v.as_mut_slice());
        key_byte_v
    }
    /// This signs a message, i.e. hashes the message and then signs the digest.
    /// This is a convenience function that is equivalent to instantiating the
    /// appropriate Hasher for the Signer (the Hasher is defined by the SignatureAlgorithm)
    /// and then calling sign_digest on it.  For a long message, especially if it's not
    /// already in a contiguous byte array, it is more efficient to use the Hasher and
    /// then call sign_digest.
    fn sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn Signature>, &'static str> {
        let mut hasher_b = self
            .signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();
        hasher_b.update(message_byte_v);
        self.sign_digest(hasher_b)
    }
    /// This signs a pre-hashed message, i.e. signs the digest produced by the given hasher.
    fn sign_digest(
        &self,
        hasher_b: Box<dyn selfhash::Hasher>,
    ) -> Result<Box<dyn Signature>, &'static str>;
}
