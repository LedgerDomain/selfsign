use crate::{
    write_digest_data_using_jcs, KERISignatureStr, KERIVerifierStr, KeyType,
    PreferredSignatureFormat, PreferredVerifierFormat, Result, SelfSignable, Signature,
    SignatureAlgorithm, Verifier,
};
use std::borrow::Cow;

impl Verifier for serde_json::Value {
    fn key_type(&self) -> KeyType {
        let value_str = self
            .as_str()
            .expect("expected selfSignatureVerifier to be a valid string");
        KERIVerifierStr::new_ref(value_str)
            .expect("expected selfSignatureVerifier to be a valid KERIVerifier")
            .key_type()
    }
    /// We assume that JSON always uses KERIVerifier, not VerifierBytes.
    fn as_preferred_verifier_format<'s: 'h, 'h>(&'s self) -> PreferredVerifierFormat<'h> {
        let value_str = self
            .as_str()
            .expect("expected selfSignatureVerifier to be a valid string");
        PreferredVerifierFormat::KERIVerifier(Cow::Borrowed(
            KERIVerifierStr::new_ref(value_str)
                .expect("expected selfSignatureVerifier to be a valid KERIVerifier"),
        ))
    }
    fn verify_digest(
        &self,
        message_digest_b: Box<dyn selfhash::Hasher>,
        signature: &dyn Signature,
    ) -> Result<()> {
        let value_str = self
            .as_str()
            .expect("expected selfSignatureVerifier to be a valid string");
        KERIVerifierStr::new_ref(value_str)
            .expect("expected selfSignatureVerifier to be a valid KERIVerifier")
            .verify_digest(message_digest_b, signature)
    }
}

impl Signature for serde_json::Value {
    fn signature_algorithm(&self) -> &'static dyn SignatureAlgorithm {
        let value_str = self
            .as_str()
            .expect("expected selfSignature to be a valid string");
        KERISignatureStr::new_ref(value_str)
            .expect("expected selfSignature to be a valid KERISignature")
            .signature_algorithm()
    }
    /// We assume that JSON always uses KERISignature, not SignatureBytes.
    fn as_preferred_signature_format<'s: 'h, 'h>(&'s self) -> PreferredSignatureFormat<'h> {
        let value_str = self
            .as_str()
            .expect("expected selfSignature to be a valid string");
        PreferredSignatureFormat::KERISignature(Cow::Borrowed(
            KERISignatureStr::new_ref(value_str)
                .expect("expected selfSignature to be a valid KERISignature"),
        ))
    }
}

impl SelfSignable for serde_json::Value {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn SignatureAlgorithm,
        verifier: &dyn Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher)
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Signature>> + 'a> {
        if !self.is_object() {
            panic!("self-signable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfSignature" field in this JSON object is considered a self-signature slot.
        let self_signature_o = self.get("selfSignature");
        match self_signature_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_signature_o.map(|self_signature| self_signature as &dyn crate::Signature),
            )),
            Some(_) => {
                panic!("selfSignature field must be a string or null.");
            }
        }
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn Signature) {
        let self_as_object_mut = self
            .as_object_mut()
            .expect("self-signable JSON value is expected to be a JSON object");
        self_as_object_mut.insert(
            "selfSignature".to_string(),
            serde_json::Value::String(signature.to_keri_signature().to_string()),
        );
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Verifier>> + 'a> {
        if !self.is_object() {
            panic!("self-signable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfSignatureVerifier" field in this JSON object is considered a self-signature slot.
        let self_signature_verifier_o = self.get("selfSignatureVerifier");
        match self_signature_verifier_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_signature_verifier_o
                    .map(|self_signature_verifier| self_signature_verifier as &dyn crate::Verifier),
            )),
            Some(_) => {
                panic!("selfSignatureVerifier field must be a string or null.");
            }
        }
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn Verifier) {
        let self_as_object_mut = self
            .as_object_mut()
            .expect("self-signable JSON value is expected to be a JSON object");
        self_as_object_mut.insert(
            "selfSignatureVerifier".to_string(),
            serde_json::Value::String(verifier.to_keri_verifier().to_string()),
        );
    }
}

impl SelfSignable for selfhash::SelfHashableJSON<'_, '_> {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn SignatureAlgorithm,
        verifier: &dyn Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        write_digest_data_using_jcs(self.value(), signature_algorithm, verifier, hasher)
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Signature>> + 'a> {
        if !self.value().is_object() {
            panic!("self-signable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfSignature" field in this JSON object is considered a self-signature slot.
        let self_signature_o = self.value().get("selfSignature");
        match self_signature_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_signature_o.map(|self_signature| self_signature as &dyn crate::Signature),
            )),
            Some(_) => {
                panic!("selfSignature field must be a string or null.");
            }
        }
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn Signature) {
        let self_as_object_mut = self
            .value_mut()
            .as_object_mut()
            .expect("self-signable JSON value is expected to be a JSON object");
        self_as_object_mut.insert(
            "selfSignature".to_string(),
            serde_json::Value::String(signature.to_keri_signature().to_string()),
        );
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn Verifier>> + 'a> {
        if !self.value().is_object() {
            panic!("self-signable JSON value is expected to be a JSON object");
        }
        // Only a top-level "selfSignatureVerifier" field in this JSON object is considered a self-signature slot.
        let self_signature_verifier_o = self.value().get("selfSignatureVerifier");
        match self_signature_verifier_o {
            Some(serde_json::Value::Null) | None => Box::new(std::iter::once(None)),
            Some(serde_json::Value::String(_)) => Box::new(std::iter::once(
                self_signature_verifier_o
                    .map(|self_signature_verifier| self_signature_verifier as &dyn crate::Verifier),
            )),
            Some(_) => {
                panic!("selfSignatureVerifier field must be a string or null.");
            }
        }
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn Verifier) {
        let self_as_object_mut = self
            .value_mut()
            .as_object_mut()
            .expect("self-signable JSON value is expected to be a JSON object");
        self_as_object_mut.insert(
            "selfSignatureVerifier".to_string(),
            serde_json::Value::String(verifier.to_keri_verifier().to_string()),
        );
    }
}
