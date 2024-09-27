use crate::{KERIVerifierStr, KeyType, PreferredVerifierFormat, Result, Signature, VerifierBytes};
use std::borrow::Cow;

pub trait Verifier: std::fmt::Debug {
    /// Returns the KeyType for this Verifier (typically a public key, but could be e.g. an HMAC key).
    fn key_type(&self) -> KeyType;
    /// Returns true iff self represents the same Verifier value as other.  Default impl checks if
    /// self.key_type() equals other.key_type().  If so, then compares the preferred
    /// verifier format values of each, avoiding allocation if possible.
    fn equals(&self, other: &dyn Verifier) -> bool {
        // Check the key type directly before resorting to converting.
        if self.key_type() != other.key_type() {
            return false;
        }
        match (
            self.as_preferred_verifier_format(),
            other.as_preferred_verifier_format(),
        ) {
            (
                PreferredVerifierFormat::VerifierBytes(self_verifier_bytes),
                PreferredVerifierFormat::VerifierBytes(other_verifier_bytes),
            ) => self_verifier_bytes == other_verifier_bytes,
            (
                PreferredVerifierFormat::VerifierBytes(self_verifier_bytes),
                PreferredVerifierFormat::KERIVerifier(other_keri_verifier),
            ) => {
                // Convert to VerifierBytes for comparison
                self_verifier_bytes == other_keri_verifier.to_verifier_bytes()
            }
            (
                PreferredVerifierFormat::KERIVerifier(self_keri_verifier),
                PreferredVerifierFormat::VerifierBytes(other_verifier_bytes),
            ) => {
                // Convert to VerifierBytes for comparison
                self_keri_verifier.to_verifier_bytes() == other_verifier_bytes
            }
            (
                PreferredVerifierFormat::KERIVerifier(self_keri_verifier),
                PreferredVerifierFormat::KERIVerifier(other_keri_verifier),
            ) => self_keri_verifier == other_keri_verifier,
        }
    }
    /// Returns the preferred concrete representation of this verifier, either VerifierBytes<'h>
    /// or Cow<'h, KERIVerifierStr>, chosen to minimize allocations.
    fn as_preferred_verifier_format<'s: 'h, 'h>(&'s self) -> PreferredVerifierFormat<'h>;
    /// Returns the VerifierBytes representation of this Verifier.  If the preferred representation is
    /// VerifierBytes, then the VerifierBytes will use Cow::Borrowed when possible, in which case
    /// no allocation is done.
    fn to_verifier_bytes<'s: 'h, 'h>(&'s self) -> VerifierBytes<'h> {
        match self.as_preferred_verifier_format() {
            PreferredVerifierFormat::VerifierBytes(verifier_bytes) => verifier_bytes,
            PreferredVerifierFormat::KERIVerifier(keri_verifier) => {
                keri_verifier.to_verifier_bytes()
            }
        }
    }
    /// Returns the KERIVerifier representation of this Verifier.  If the preferred representation is
    /// KERIVerifier, then it will use std::borrow::Cow::Borrowed(_), in which case no allocation is done.
    fn to_keri_verifier<'s: 'h, 'h>(&'s self) -> Cow<'h, KERIVerifierStr> {
        match self.as_preferred_verifier_format() {
            PreferredVerifierFormat::VerifierBytes(verifier_bytes) => {
                Cow::Owned(verifier_bytes.to_keri_verifier().expect("programmer error"))
            }
            PreferredVerifierFormat::KERIVerifier(keri_verifier) => keri_verifier,
        }
    }
    /// This verifies a message, i.e. hashes the message and then verifies the signature using verify_digest.
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn Signature) -> Result<()> {
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
    ) -> Result<()>;
}
