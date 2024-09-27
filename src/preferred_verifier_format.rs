use crate::{KERIVerifierStr, VerifierBytes};
use std::borrow::Cow;

/// A type which allows a Verifier impl to represent its value in its "preferred" format, chosen to minimize allocations.
pub enum PreferredVerifierFormat<'h> {
    VerifierBytes(VerifierBytes<'h>),
    KERIVerifier(Cow<'h, KERIVerifierStr>),
}

impl<'h> From<VerifierBytes<'h>> for PreferredVerifierFormat<'h> {
    fn from(verifier_bytes: VerifierBytes<'h>) -> Self {
        Self::VerifierBytes(verifier_bytes)
    }
}

impl<'h> From<Cow<'h, KERIVerifierStr>> for PreferredVerifierFormat<'h> {
    fn from(keri_verifier: Cow<'h, KERIVerifierStr>) -> Self {
        Self::KERIVerifier(keri_verifier)
    }
}
