use crate::{KERISignatureStr, SignatureBytes};
use std::borrow::Cow;

/// A type which allows a Signature impl to represent its value in its "preferred" format, chosen to minimize allocations.
pub enum PreferredSignatureFormat<'h> {
    SignatureBytes(SignatureBytes<'h>),
    KERISignature(Cow<'h, KERISignatureStr>),
}

impl<'h> From<SignatureBytes<'h>> for PreferredSignatureFormat<'h> {
    fn from(signature_bytes: SignatureBytes<'h>) -> Self {
        Self::SignatureBytes(signature_bytes)
    }
}

impl<'h> From<Cow<'h, KERISignatureStr>> for PreferredSignatureFormat<'h> {
    fn from(keri_signature: Cow<'h, KERISignatureStr>) -> Self {
        Self::KERISignature(keri_signature)
    }
}
