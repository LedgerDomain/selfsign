use crate::{Hasher, KERIVerifier, Signature, SignatureAlgorithm, VerifierBytes};

pub trait Verifier {
    /// Returns the SignatureAlgorithm to be used to verify the signature.
    fn signature_algorithm(&self) -> SignatureAlgorithm;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the SignatureAlgorithm and the verifying key.
    fn to_verifier_bytes(&self) -> VerifierBytes;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the SignatureAlgorithm and the verifying key.
    fn to_keri_verifier(&self) -> KERIVerifier;
    /// Returns the signature to be used as the placeholder when generating the digest of the
    /// self-signing object.
    fn placeholder_signature(&self) -> &'static dyn Signature;
    /// This verifies a message, i.e. hashes the message and then verifies the signature using verify_digest.
    fn verify_message(
        &self,
        message_byte_v: &[u8],
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        let mut hasher = self
            .signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();
        hasher.update(message_byte_v);
        self.verify_digest(hasher, signature)
    }
    /// This verifies a pre-hashed message.  This is useful when the message is long, or is not already
    /// in a contiguous byte array.
    fn verify_digest(
        &self,
        message_digest: Hasher,
        signature: &dyn Signature,
    ) -> Result<(), &'static str>;
}
