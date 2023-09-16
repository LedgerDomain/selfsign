use crate::{Hasher, KERIVerifier, KeyType, Signature, VerifierBytes};

// Debug is probably a TEMP HACK
pub trait Verifier: std::fmt::Debug {
    /// Returns the KeyType for this Verifier (typically a public key, but could be e.g. an HMAC key).
    fn key_type(&self) -> KeyType;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the KeyType and the verifying key.
    fn to_verifier_bytes(&self) -> VerifierBytes;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the KeyType and the verifying key.
    fn to_keri_verifier(&self) -> KERIVerifier;
    // /// Returns the signature to be used as the placeholder when generating the digest of the
    // /// self-signing object.
    // fn placeholder_signature(&self) -> &'static dyn Signature;
    /// This verifies a message, i.e. hashes the message and then verifies the signature using verify_digest.
    fn verify_message(
        &self,
        message_byte_v: &[u8],
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        let mut hasher = signature
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
