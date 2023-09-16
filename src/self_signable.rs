use crate::{Hasher, Signature, SignatureAlgorithm, Signer, Verifier};

pub trait SelfSignable {
    /// This should feed the content of this object into the hasher in the order that it should be hashed,
    /// writing placeholders for any self-signature slots that have not yet been computed.
    fn write_digest_data(
        &self,
        signature_algorithm: SignatureAlgorithm,
        verifier: &dyn Verifier,
        hasher: &mut Hasher,
    );
    /// Returns an iterator over the self-signature slots in this object.
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Signature>> + 'a>;
    /// Sets all self-signature slots in this object (including any nested objects) to the given signature.
    fn set_self_signature_slots_to(&mut self, signature: &dyn Signature);
    /// Returns an iterator over the self-signature verifier slots slots in this object.
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Verifier>> + 'a>;
    /// Sets all self-signature verifier slots in this object (including any nested objects) to the given verifier.
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn Verifier);
    /// Checks that all the self-signature slots are equal, returning error if they aren't.  Otherwise returns
    /// Some(self_seal) if they are set, and None if they are not set.
    fn get_unverified_self_signature(&self) -> Result<Option<&dyn Signature>, &'static str> {
        let total_self_signature_count = self.self_signature_oi().count();
        // First, ensure that the self-signature slots are either all Some(_) or all None.
        match self
            .self_signature_oi()
            .map(|self_signature_o| {
                if self_signature_o.is_some() {
                    1usize
                } else {
                    0usize
                }
            })
            .reduce(|a, b| a + b)
        {
            Some(0) => {
                // All self-signature slots are None, which is valid.  We can return early here.
                return Ok(None);
            }
            Some(populated_self_signature_count)
                if populated_self_signature_count == total_self_signature_count =>
            {
                // All self-signature slots are populated, so we have to check them.
            }
            Some(_) => {
                return Err("This object is a malformed as SelfSigning because some but not all self-signature slots are populated -- it must be all or nothing.");
            }
            None => {
                return Err("This object has no self-signature slots, and therefore can't be self-signed or self-verified.");
            }
        }

        let first_self_signature = self.self_signature_oi().nth(0).unwrap().unwrap();
        // Now ensure all self-signature slots are equal.
        for self_signature in self
            .self_signature_oi()
            .map(|self_signature_o| self_signature_o.unwrap())
        {
            // TEMP HACK: Just use to_signature_bytes to have a concrete type to compare.
            if self_signature.to_signature_bytes() != first_self_signature.to_signature_bytes() {
                return Err("Object's self-signature slots do not all match.");
            }
        }
        // If it got this far, it's valid.
        Ok(Some(first_self_signature))
    }
    /// Checks that all the self-signature verifier slots are equal, returning error if they aren't.
    /// Otherwise returns Some(verifier) if they are set, and None if they are not set.
    fn get_self_signature_verifier(&self) -> Result<Option<&dyn Verifier>, &'static str> {
        let total_self_signature_verifier_count = self.self_signature_verifier_oi().count();
        // First, ensure that the self-signature verifier slots are either all Some(_) or all None.
        match self
            .self_signature_verifier_oi()
            .map(|self_signature_verifier_o| {
                if self_signature_verifier_o.is_some() {
                    1usize
                } else {
                    0usize
                }
            })
            .reduce(|a, b| a + b)
        {
            Some(0) => {
                // All self-signature verifier slots are None, which is valid.  We can return early here.
                return Ok(None);
            }
            Some(populated_self_signature_verifier_count)
                if populated_self_signature_verifier_count
                    == total_self_signature_verifier_count =>
            {
                // All self-signature verifier slots are populated, so we have to check them.
            }
            Some(_) => {
                return Err("This object is a malformed as SelfSigning because some but not all self-signature verifier slots are populated -- it must be all or nothing.");
            }
            None => {
                return Err("This object has no self-signature verifier slots slots, and therefore can't be self-signed or self-verified.");
            }
        }

        let first_self_signature_verifier =
            self.self_signature_verifier_oi().nth(0).unwrap().unwrap();
        // Now ensure all self-signature verifier slots are equal.
        for self_signature_verifier in self
            .self_signature_verifier_oi()
            .map(|verifier_o| verifier_o.unwrap())
        {
            // TEMP HACK: Just use to_verifier_bytes to have a concrete type to compare.
            if self_signature_verifier.to_verifier_bytes()
                != first_self_signature_verifier.to_verifier_bytes()
            {
                return Err("Object's self-signature verifier slots slots do not all match.");
            }
        }
        // If it got this far, it's valid.
        Ok(Some(first_self_signature_verifier))
    }
    /// Computes the self-signature for this object.  Note that this ignores any existing values in
    /// the self-signature slots and self-signature verifier slots.
    fn compute_self_signature(
        &self,
        signer: &dyn Signer,
    ) -> Result<Box<dyn Signature>, &'static str> {
        let mut hasher = signer
            .signature_algorithm()
            .message_digest_hash_function()
            .new_hasher();
        let verifier_b = signer.verifier();
        self.write_digest_data(
            signer.signature_algorithm(),
            verifier_b.as_ref(),
            &mut hasher,
        );
        Ok(signer.sign_digest(&hasher)?)
    }
    /// Computes the self-signature and writes it into all the self-signature slots, and writes the verifier
    /// that is derived from signer into all the self-signature verifier slots.
    fn self_sign(&mut self, signer: &dyn Signer) -> Result<&dyn Signature, &'static str> {
        let self_signature_b = self.compute_self_signature(signer)?;
        let verifier_b = signer.verifier();
        self.set_self_signature_slots_to(self_signature_b.as_ref());
        self.set_self_signature_verifier_slots_to(verifier_b.as_ref());
        let first_self_signature = self.self_signature_oi().nth(0).unwrap().unwrap();
        Ok(first_self_signature)
    }
    /// Verifies the self-signatures in this object using the self-signature verifier and returns a reference
    /// to the verified self-signature.
    fn verify_self_signatures<'a, 'b: 'a>(&'b self) -> Result<&'a dyn Signature, &'static str> {
        let unverified_self_signature = self.get_unverified_self_signature()?.ok_or_else(|| {
            "This object has no self-signature slots, and therefore can't be self-signed or self-verified."
        })?;
        let verifier = self.get_self_signature_verifier()?.ok_or("This object does not have populated self-signature verifier slots, and therefore can't be self-verified.")?;
        let signature_algorithm = unverified_self_signature.signature_algorithm();
        if signature_algorithm.key_type() != verifier.key_type() {
            panic!("programmer error: unverified_self_signature and verifier must have matching key type");
        }
        // Now compute the digest which will be used either as the direct hash value, or as the input
        // to the signature algorithm.
        let mut hasher = signature_algorithm
            .message_digest_hash_function()
            .new_hasher();
        self.write_digest_data(signature_algorithm, verifier, &mut hasher);
        verifier.verify_digest(hasher, unverified_self_signature)?;
        // If it got this far, it's valid.
        Ok(unverified_self_signature)
    }
}
