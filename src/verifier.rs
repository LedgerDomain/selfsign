use crate::{KERIVerifierStr, KeyType, Signature, VerifierBytes};
use std::borrow::Cow;

pub trait Verifier: std::fmt::Debug {
    /// Returns the KeyType for this Verifier (typically a public key, but could be e.g. an HMAC key).
    fn key_type(&self) -> KeyType;
    /// Returns the VerifierBytes representation of this verifier.  If the native representation of this verifier is
    /// bytes, then the VerifierBytes can (and should) use Cow::Borrowed (see VerifierBytes), in which case no
    /// allocation is done.
    fn to_verifier_bytes<'s: 'h, 'h>(&'s self) -> VerifierBytes<'h>;
    /// Returns the KERIVerifier representation of this verifier.  Default impl is
    /// std::borrow::Cow::Owned(self.to_verifier_bytes().to_keri_verifier()), but if the native representation
    /// of this verifier is KERIVerifier, then it should return std::borrow::Cow::Borrowed(_).
    fn to_keri_verifier<'s: 'h, 'h>(&'s self) -> Cow<'h, KERIVerifierStr> {
        Cow::Owned(
            self.to_verifier_bytes()
                .to_keri_verifier()
                .expect("programmer error"),
        )
    }
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
        message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<(), &'static str>;
}
