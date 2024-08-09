use crate::{KERISignatureStr, SignatureAlgorithm, SignatureBytes};
use std::borrow::Cow;

pub trait Signature {
    /// Returns the SignatureAlgorithm to be used to produce the signature.
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm;
    /// Returns the SignatureBytes representation of this signature.  If the native representation of this signature is
    /// bytes, then the SignatureBytes can (and should) use Cow::Borrowed (see SignatureBytes), in which case no
    /// allocation is done.
    fn to_signature_bytes<'s: 'h, 'h>(&'s self) -> SignatureBytes<'h>;
    /// Returns the KERISignature representation of this signature.  Default impl is
    /// std::borrow::Cow::Owned(self.to_signature_bytes().to_keri_signature()), but if the native representation
    /// of this signature is KERISignature, then it should return std::borrow::Cow::Borrowed(_).
    fn to_keri_signature<'s: 'h, 'h>(&'s self) -> Cow<'h, KERISignatureStr> {
        Cow::Owned(self.to_signature_bytes().to_keri_signature())
    }
}
