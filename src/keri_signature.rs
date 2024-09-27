use crate::{KERISignatureStr, PreferredSignatureFormat, Signature};
use std::borrow::Cow;

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_keri_signature_str", borrow = "KERISignatureStr")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct KERISignature(String);

// TODO: Is there any way to automatically derive this from the impl on KERISignatureStr via Deref?
impl Signature for KERISignature {
    fn signature_algorithm(&self) -> &'static dyn crate::SignatureAlgorithm {
        use std::ops::Deref;
        self.deref().signature_algorithm()
    }
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h> {
        PreferredSignatureFormat::KERISignature(Cow::Borrowed(self.as_keri_signature_str()))
    }
}
