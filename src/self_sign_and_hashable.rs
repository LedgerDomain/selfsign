use crate::{Result, SelfSignable, Signature, Signer};

/// SelfSignAndHashable is a trait for types that can be self-signed and then self-hashed.  This is
/// useful if the signature is very long, and you want to use the hash (which is typically shorter) as
/// the identifier for the document.
pub trait SelfSignAndHashable {
    fn self_sign_and_hash(
        &mut self,
        signer: &dyn Signer,
        hasher_b: Box<dyn selfhash::Hasher>,
    ) -> Result<(&dyn Signature, &dyn selfhash::Hash)>;
    fn verify_self_signatures_and_hashes<'a, 'b: 'a>(
        &'b self,
    ) -> Result<(&'a dyn Signature, &'a dyn selfhash::Hash)>;
}

/// If a type implements Clone, selfhash::SelfHashable, and selfsign::SelfSignable, then it has
/// a natural implementation of SelfSignAndHashable.
impl<T: Clone + selfhash::SelfHashable + SelfSignable> SelfSignAndHashable for T {
    fn self_sign_and_hash(
        &mut self,
        signer: &dyn Signer,
        hasher_b: Box<dyn selfhash::Hasher>,
    ) -> Result<(&dyn Signature, &dyn selfhash::Hash)> {
        self.set_self_hash_slots_to(hasher_b.hash_function().placeholder_hash())?;
        self.self_sign(signer)?;
        self.self_hash(hasher_b)?;
        let self_signature = self.self_signature_oi().next().unwrap().unwrap();
        let self_hash = self.self_hash_oi()?.next().unwrap().unwrap();
        Ok((self_signature, self_hash))
    }
    fn verify_self_signatures_and_hashes<'a, 'b: 'a>(
        &'b self,
    ) -> Result<(&'a dyn Signature, &'a dyn selfhash::Hash)> {
        let self_hash = self.verify_self_hashes()?;
        let placeholder_hash = self_hash.hash_function()?.placeholder_hash();
        let mut c = self.clone();
        c.set_self_hash_slots_to(placeholder_hash)?;
        c.verify_self_signatures()?;
        let self_signature = self.self_signature_oi().next().unwrap().unwrap();
        Ok((self_signature, self_hash))
    }
}
