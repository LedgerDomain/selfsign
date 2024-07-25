use crate::{KERIVerifierStr, KeyType, Signature, Verifier, VerifierBytes};

/// This is a concise, ASCII-only representation of a public key value, which comes from the KERI spec.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(borrow = "KERIVerifierStr", as_pneu_str = "as_keri_verifier_str")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", pneu_string(deserialize))]
pub struct KERIVerifier(String);

// TODO: Is there any way to derive this from KERIVerifier via Deref?
impl Verifier for KERIVerifier {
    fn key_type(&self) -> KeyType {
        use std::ops::Deref;
        self.deref().key_type()
    }
    fn to_verifier_bytes(&self) -> VerifierBytes {
        use std::ops::Deref;
        self.deref().to_verifier_bytes()
    }
    fn to_keri_verifier(&self) -> KERIVerifier {
        self.clone()
    }
    fn verify_digest(
        &self,
        message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<(), &'static str> {
        use std::ops::Deref;
        self.deref().verify_digest(message_digest_b, signature)
    }
}
