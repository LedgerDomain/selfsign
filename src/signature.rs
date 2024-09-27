use crate::{KERISignatureStr, PreferredSignatureFormat, SignatureAlgorithm, SignatureBytes};
use std::borrow::Cow;

pub trait Signature {
    /// Returns the SignatureAlgorithm to be used to produce the signature.
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm;
    /// Returns true iff self represents the same Signature value as other.  Default impl checks if
    /// self.signature_algorithm() equals other.signature_algorithm().  If so, then compares the preferred
    /// signature format values of each, avoiding allocation if possible.
    fn equals(&self, other: &dyn Signature) -> bool {
        // Check the signature algorithm directly before resorting to converting.
        if !self
            .signature_algorithm()
            .equals(other.signature_algorithm())
        {
            return false;
        }
        match (
            self.as_preferred_signature_format(),
            other.as_preferred_signature_format(),
        ) {
            (
                PreferredSignatureFormat::SignatureBytes(self_signature_bytes),
                PreferredSignatureFormat::SignatureBytes(other_signature_bytes),
            ) => self_signature_bytes == other_signature_bytes,
            (
                PreferredSignatureFormat::SignatureBytes(self_signature_bytes),
                PreferredSignatureFormat::KERISignature(other_keri_signature),
            ) => {
                // Convert to SignatureBytes for comparison
                self_signature_bytes == other_keri_signature.to_signature_bytes()
            }
            (
                PreferredSignatureFormat::KERISignature(self_keri_signature),
                PreferredSignatureFormat::SignatureBytes(other_signature_bytes),
            ) => {
                // Convert to SignatureBytes for comparison
                self_keri_signature.to_signature_bytes() == other_signature_bytes
            }
            (
                PreferredSignatureFormat::KERISignature(self_keri_signature),
                PreferredSignatureFormat::KERISignature(other_keri_signature),
            ) => self_keri_signature == other_keri_signature,
        }
    }
    /// Returns the preferred concrete representation of this signature, either SignatureBytes<'h>
    /// or Cow<'h, KERISignatureStr>, chosen to minimize allocations.
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h>;
    /// Returns the SignatureBytes representation of this Signature.  If the preferred representation is
    /// SignatureBytes, then the SignatureBytes will use Cow::Borrowed when possible, in which case
    /// no allocation is done.
    fn to_signature_bytes<'s: 'h, 'h>(&'s self) -> SignatureBytes<'h> {
        match self.as_preferred_signature_format() {
            PreferredSignatureFormat::SignatureBytes(signature_bytes) => signature_bytes,
            PreferredSignatureFormat::KERISignature(keri_signature) => {
                keri_signature.to_signature_bytes()
            }
        }
    }
    /// Returns the KERISignature representation of this Signature.  If the preferred representation is
    /// KERISignature, then it will use std::borrow::Cow::Borrowed(_), in which case no allocation is done.
    fn to_keri_signature<'s: 'h, 'h>(&'s self) -> Cow<'h, KERISignatureStr> {
        match self.as_preferred_signature_format() {
            PreferredSignatureFormat::SignatureBytes(signature_bytes) => {
                Cow::Owned(signature_bytes.to_keri_signature())
            }
            PreferredSignatureFormat::KERISignature(keri_signature) => keri_signature,
        }
    }
}
