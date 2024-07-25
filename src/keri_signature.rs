use crate::{KERISignatureStr, Signature};

// This is meant to be used in end-use data structures that are self-signing.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(borrow = "KERISignatureStr", as_pneu_str = "as_keri_signature_str")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct KERISignature(String);

// TODO: Is there any way to automatically derive this from the impl on KERISignatureStr via Deref?
impl Signature for KERISignature {
    fn signature_algorithm(&self) -> &'static dyn crate::SignatureAlgorithm {
        use std::ops::Deref;
        self.deref().signature_algorithm()
    }
    fn to_signature_bytes(&self) -> crate::SignatureBytes {
        use std::ops::Deref;
        self.deref().to_signature_bytes()
    }
    fn to_keri_signature(&self) -> KERISignature {
        self.clone()
    }
}
