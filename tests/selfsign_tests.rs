use std::collections::HashMap;

#[test]
#[serial_test::serial]
fn test_signer_verifier() {
    let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    let secp256k1_signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let secp256k1_verifying_key = k256::ecdsa::VerifyingKey::from(&secp256k1_signing_key);

    let signer_verifier_v: Vec<(&dyn selfsign::Signer, &dyn selfsign::Verifier)> = vec![
        (&ed25519_signing_key, &ed25519_verifying_key),
        (&secp256k1_signing_key, &secp256k1_verifying_key),
    ];
    for (signer, verifier) in signer_verifier_v.into_iter() {
        println!("---------------------------------------------------");
        println!(
            "signer with algorithm: {}",
            signer.signature_algorithm().named_signature_algorithm()
        );
        {
            let keri_verifier = verifier.to_keri_verifier();
            println!("keri_verifier: {}", keri_verifier);
            let verifier_bytes = keri_verifier.to_verifier_bytes();
            assert_eq!(
                keri_verifier,
                verifier_bytes.to_keri_verifier().expect("pass")
            );
        }
        {
            let verifier_bytes = verifier.to_verifier_bytes();
            println!("verifier_bytes: {:?}", verifier_bytes);
            let keri_verifier = verifier_bytes.to_keri_verifier().expect("pass");
            assert_eq!(verifier_bytes, keri_verifier.to_verifier_bytes());
        }
        {
            assert_eq!(
                verifier.to_keri_verifier(),
                verifier
                    .to_verifier_bytes()
                    .to_keri_verifier()
                    .expect("pass")
            );
            assert_eq!(
                verifier.to_verifier_bytes(),
                verifier.to_keri_verifier().to_verifier_bytes()
            );
        }
        let keri_verifier = verifier.to_keri_verifier();
        let verifier_bytes = verifier.to_verifier_bytes();

        let message = b"blah blah blah blah hippos again";
        let signature_b = signer.sign_message(message).expect("pass");
        {
            let keri_signature = signature_b.to_keri_signature();
            println!("keri_signature: {}", keri_signature);
            let signature_bytes = keri_signature.to_signature_bytes();
            assert_eq!(keri_signature, signature_bytes.to_keri_signature());
        }
        {
            let signature_bytes = signature_b.to_signature_bytes();
            println!("signature_bytes: {:?}", signature_bytes);
            let keri_signature = signature_bytes.to_keri_signature();
            assert_eq!(signature_bytes, keri_signature.to_signature_bytes());
        }
        {
            assert_eq!(
                signature_b.to_keri_signature(),
                signature_b.to_signature_bytes().to_keri_signature()
            );
            assert_eq!(
                signature_b.to_signature_bytes(),
                signature_b.to_keri_signature().to_signature_bytes()
            );
        }
        let keri_signature = signature_b.to_keri_signature();
        let signature_bytes = signature_b.to_signature_bytes();

        use selfsign::Verifier;

        verifier
            .verify_message(message, signature_b.as_ref())
            .expect("pass");
        keri_verifier
            .verify_message(message, signature_b.as_ref())
            .expect("pass");
        verifier_bytes
            .verify_message(message, signature_b.as_ref())
            .expect("pass");

        verifier
            .verify_message(message, &keri_signature)
            .expect("pass");
        keri_verifier
            .verify_message(message, &keri_signature)
            .expect("pass");
        verifier_bytes
            .verify_message(message, &keri_signature)
            .expect("pass");

        verifier
            .verify_message(message, &signature_bytes)
            .expect("pass");
        keri_verifier
            .verify_message(message, &signature_bytes)
            .expect("pass");
        verifier_bytes
            .verify_message(message, &signature_bytes)
            .expect("pass");
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FancyData {
    /// Self-signature of the previous FancyData.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "previous")]
    pub previous_o: Option<selfsign::KERISignature<'static>>,
    pub name: String,
    pub stuff_count: u32,
    pub data_byte_v: Vec<u8>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "self_signature_verifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    // pub self_signature_verifier_o: Option<selfsign::VerifierBytes<'static>>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "self_signature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    // pub self_signature_o: Option<selfsign::SignatureBytes<'static>>,
}

impl selfsign::SelfSignable for FancyData {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        selfsign::write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher);
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Signature>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_o
                .as_ref()
                .map(|s| -> &dyn selfsign::Signature { s }),
        ))
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        self.self_signature_o = Some(signature.to_keri_signature().into_owned());
        // self.self_signature_o = Some(signature.to_signature_bytes().into_owned());
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier().into_owned());
        // self.verifier_o = Some(verifier.to_verifier_bytes().into_owned());
    }
}

#[test]
#[serial_test::serial]
fn test_self_signable() {
    let mut csprng = rand::rngs::OsRng;
    let signer_bv: Vec<Box<dyn selfsign::Signer>> =
        vec![Box::new(ed25519_dalek::SigningKey::generate(&mut csprng))];
    for signer in signer_bv.iter().map(|signer_b| signer_b.as_ref()) {
        println!("---------------------------------------------------");
        println!(
            "signer.signature_algorithm(): {}",
            signer.signature_algorithm().named_signature_algorithm()
        );

        let mut fancy_data_0 = FancyData {
            previous_o: None,
            name: "hippodonkey".to_string(),
            stuff_count: 42,
            data_byte_v: vec![0x01, 0x02, 0x03],
            self_signature_verifier_o: None,
            self_signature_o: None,
        };
        // println!("fancy_data_0 before self-signature: {:#?}", fancy_data_0);
        println!(
            "fancy_data_0 before self-signature JSON: {}",
            serde_json::to_string_pretty(&fancy_data_0).expect("pass")
        );
        use selfsign::SelfSignable;
        fancy_data_0.self_sign(signer).expect("pass");
        // println!("fancy_data_0 after self-signature: {:#?}", fancy_data_0);
        println!(
            "fancy_data_0 after self-signature JSON: {}",
            serde_json::to_string_pretty(&fancy_data_0).expect("pass")
        );
        fancy_data_0.verify_self_signatures().expect("pass");
        println!("fancy_data_0 self self-signature verified!");
        // Let's make sure that altering the data causes the verification to fail.
        let mut altered_fancy_data_0 = fancy_data_0.clone();
        altered_fancy_data_0.name = "maaaaaaaaaa".to_string();
        assert!(altered_fancy_data_0.verify_self_signatures().is_err());

        let mut fancy_data_1 = FancyData {
            previous_o: fancy_data_0.self_signature_o.clone(),
            name: "grippoponkey".to_string(),
            stuff_count: 43,
            data_byte_v: vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
            self_signature_verifier_o: None,
            self_signature_o: None,
        };
        // println!("fancy_data_1 before self-signature: {:#?}", fancy_data_1);
        println!(
            "fancy_data_1 before self-signature JSON: {}",
            serde_json::to_string(&fancy_data_1).expect("pass")
        );
        fancy_data_1.self_sign(signer).expect("pass");
        // println!("fancy_data_1 after self-signature: {:#?}", fancy_data_1);
        println!(
            "fancy_data_1 after self-signature JSON: {}",
            serde_json::to_string(&fancy_data_1).expect("pass")
        );
        fancy_data_1.verify_self_signatures().expect("pass");
        println!("fancy_data_1 self self-signature verified!");
    }
}

// NOTE: This is not fully compliant with the URI spec, but it's good enough for a demonstration.
// NOTE: This doesn't deal with percent-encoding at all.
// The KERISignature is the last component of the path.
#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, serde_with::SerializeDisplay, PartialEq,
)]
pub struct URIWithSignature {
    pub scheme: String,
    pub authority_o: Option<String>,
    // This is the path before the signature, which includes the leading and trailing slash,
    // and therefore might just be equal to "/".
    pub pre_signature_path: String,
    pub signature: selfsign::KERISignature<'static>,
    pub query_o: Option<String>,
    pub fragment_o: Option<String>,
}

impl std::fmt::Display for URIWithSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(authority) = self.authority_o.as_deref() {
            write!(f, "//{}", authority)?;
        }
        write!(f, "{}{}", self.pre_signature_path, self.signature)?;
        if let Some(query) = self.query_o.as_deref() {
            write!(f, "?{}", query)?;
        }
        if let Some(fragment) = self.fragment_o.as_deref() {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for URIWithSignature {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Need to check for proper percent-encoding, etc.
        if !s.is_ascii() {
            return Err("URIWithSignature must be ASCII");
        }
        // Parse the scheme.
        let (scheme, after_scheme) = s
            .split_once(":")
            .ok_or("URIWithSignature must have a scheme")?;
        // Parse the authority.
        let (authority_o, after_authority) = if after_scheme.starts_with("//") {
            let path_start = after_scheme[2..]
                .find('/')
                .ok_or("URIWithSignature is missing path component")?;
            let (authority, after_authority) = after_scheme.split_at(path_start + 2);
            (Some(authority), after_authority)
        } else {
            (None, after_scheme)
        };
        // Parse the pre-signature path.
        let path_end = after_authority
            .rfind('/')
            .ok_or("URIWithSignature is missing path component")?
            + 1;
        let (pre_signature_path, signature_and_beyond) = after_authority.split_at(path_end);
        assert!(pre_signature_path.starts_with('/'));
        assert!(pre_signature_path.ends_with('/'));
        // Parse signature component of path (the last component).
        let signature_end = signature_and_beyond
            .find(|c| c == '?' || c == '#')
            .unwrap_or_else(|| signature_and_beyond.len());
        let (signature_str, after_signature) = signature_and_beyond.split_at(signature_end);
        let signature = selfsign::KERISignature::from_str(signature_str)?;
        // Parse query, if present.
        let (query_o, after_query) = if after_signature.starts_with('?') {
            let query_end = after_signature
                .find('#')
                .unwrap_or_else(|| after_signature.len());
            let (query, after_query) = after_signature[1..].split_at(query_end);
            (Some(query), after_query)
        } else {
            (None, after_signature)
        };
        // Parse fragment, if present
        let fragment_o = if after_query.starts_with('#') {
            Some(&after_query[1..])
        } else {
            None
        };

        Ok(URIWithSignature {
            scheme: scheme.to_string(),
            authority_o: authority_o.map(|s| s.to_string()),
            pre_signature_path: pre_signature_path.to_string(),
            signature,
            query_o: query_o.map(|s| s.to_string()),
            fragment_o: fragment_o.map(|s| s.to_string()),
        })
    }
}

/// This is meant to be a simplified version of the DID data model.
pub trait KeyMaterial: selfsign::SelfSignable {
    /// The URI contains the self-signature from the root KeyMaterial, and does not change
    /// when the KeyMaterial is updated.
    fn uri(&self) -> &URIWithSignature;
    /// The root KeyMaterial is the only KeyMaterial that does not have a previous KeyMaterial.
    fn is_root_key_material(&self) -> bool {
        self.previous_key_material_self_signature_o().is_none()
    }
    /// The root KeyMaterial returns None here.  A non-root KeyMaterial returns the self-signature
    /// of the previous KeyMaterial.
    fn previous_key_material_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>>;
    /// This is the version ID of this KeyMaterial.  It must start at 0 for the root KeyMaterial
    /// and increase by exactly one per KeyMaterial update.
    fn version_id(&self) -> u32;
    /// This is the timestamp at which this KeyMaterial becomes current and the previous one becomes
    /// no longer current.
    fn valid_from(&self) -> time::OffsetDateTime;
    /// List of verifiers for the authentication key purpose.
    fn authentication_v(&self) -> &[selfsign::KERIVerifier<'static>];
    /// List of verifiers for the assertion key purpose.
    fn assertion_v(&self) -> &[selfsign::KERIVerifier<'static>];
    /// List of verifiers for the key exchange key purpose.
    fn key_exchange_v(&self) -> &[selfsign::KERIVerifier<'static>];
    /// List of verifiers for the capability invocation key purpose.
    fn capability_invocation_v(&self) -> &[selfsign::KERIVerifier<'static>];
    /// List of verifiers for the capability delegation key purpose.
    fn capability_delegation_v(&self) -> &[selfsign::KERIVerifier<'static>];
    /// This verifies this KeyMaterial relative to its previous KeyMaterial, or to itself if it's the root.
    fn verify_nonrecursive(
        &self,
        key_material_m: &HashMap<selfsign::KERISignature<'static>, &dyn KeyMaterial>,
    ) -> Result<(), &'static str> {
        // First, verify that this KeyMaterial is properly self-signed.
        self.verify_self_signatures()?;
        // Now do checks that depend on if this is the root KeyMaterial or not.
        if let Some(previous_key_material_self_signature) =
            self.previous_key_material_self_signature_o()
        {
            let previous_key_material = key_material_m
                .get(previous_key_material_self_signature)
                .ok_or("previous_key_material_self_signature not found in key_material_m")?;
            // Check that the URI matches.
            if self.uri() != previous_key_material.uri() {
                return Err("URI does not match URI of previous KeyMaterial");
            }
            // Check that the version_id is exactly one greater than that of the previous KeyMaterial.
            if self.version_id() != previous_key_material.version_id() + 1 {
                return Err(
                    "version_id must be exactly one greater than that of previous KeyMaterial",
                );
            }
            // Check that the valid_from timestamps are monotonically increasing.
            if self.valid_from() <= previous_key_material.valid_from() {
                return Err("valid_from timestamp must be later than that of previous KeyMaterial");
            }
            // Check that the self-signature verifier is listed in the capability_invocation_v
            // of the previous KeyMaterial.
            if !previous_key_material.capability_invocation_v().contains(
                &self
                    .get_self_signature_verifier()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .to_keri_verifier(),
            ) {
                return Err("Unauthorized KeyMaterial update: self_signature_verifier_o is not in capability_invocation_v of previous KeyMaterial");
            }
        } else {
            // Check that the version_id is 0.
            if self.version_id() != 0 {
                return Err("version_id must be 0 for root KeyMaterial");
            }
            // Check that the self-signature verifier is listed in capability_invocation_v.
            if !self.capability_invocation_v().contains(
                &self
                    .get_self_signature_verifier()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .to_keri_verifier(),
            ) {
                return Err("self_signature_verifier_o is not in capability_invocation_v");
            }
        }

        Ok(())
    }
    fn verify_recursive(
        &self,
        key_material_m: &HashMap<selfsign::KERISignature<'static>, &dyn KeyMaterial>,
    ) -> Result<(), &'static str> {
        self.verify_nonrecursive(key_material_m)?;
        if let Some(previous_key_material_self_signature) =
            self.previous_key_material_self_signature_o()
        {
            let previous_key_material = key_material_m
                .get(previous_key_material_self_signature)
                .ok_or("previous_key_material_self_signature not found in key_material_m")?;
            previous_key_material.verify_recursive(key_material_m)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KeyMaterialRoot {
    pub uri: URIWithSignature,
    pub version_id: u32,
    pub valid_from: time::OffsetDateTime,
    pub authentication_v: Vec<selfsign::KERIVerifier<'static>>,
    pub assertion_v: Vec<selfsign::KERIVerifier<'static>>,
    pub key_exchange_v: Vec<selfsign::KERIVerifier<'static>>,
    pub capability_invocation_v: Vec<selfsign::KERIVerifier<'static>>,
    pub capability_delegation_v: Vec<selfsign::KERIVerifier<'static>>,
    #[serde(rename = "self_signature_verifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    #[serde(rename = "self_signature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
}

impl KeyMaterial for KeyMaterialRoot {
    fn uri(&self) -> &URIWithSignature {
        &self.uri
    }
    fn previous_key_material_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>> {
        None
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn valid_from(&self) -> time::OffsetDateTime {
        self.valid_from
    }
    fn authentication_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.authentication_v
    }
    fn assertion_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.assertion_v
    }
    fn key_exchange_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.key_exchange_v
    }
    fn capability_invocation_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.capability_invocation_v
    }
    fn capability_delegation_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.capability_delegation_v
    }
}

impl selfsign::SelfSignable for KeyMaterialRoot {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        selfsign::write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher);
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Signature>> + 'a> {
        Box::new(
            std::iter::once(Some(&self.uri.signature as &dyn selfsign::Signature)).chain(
                std::iter::once(
                    self.self_signature_o
                        .as_ref()
                        .map(|s| -> &dyn selfsign::Signature { s }),
                ),
            ),
        )
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        let keri_signature = signature.to_keri_signature().into_owned();
        self.uri.signature = keri_signature.clone();
        self.self_signature_o = Some(keri_signature);
        // self.self_signature_o = Some(signature.to_signature_bytes().into_owned());
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier().into_owned());
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KeyMaterialNonRoot {
    pub uri: URIWithSignature,
    pub previous_key_material_self_signature: selfsign::KERISignature<'static>,
    pub version_id: u32,
    pub valid_from: time::OffsetDateTime,
    pub authentication_v: Vec<selfsign::KERIVerifier<'static>>,
    pub assertion_v: Vec<selfsign::KERIVerifier<'static>>,
    pub key_exchange_v: Vec<selfsign::KERIVerifier<'static>>,
    pub capability_invocation_v: Vec<selfsign::KERIVerifier<'static>>,
    pub capability_delegation_v: Vec<selfsign::KERIVerifier<'static>>,
    #[serde(rename = "self_signature_verifier")]
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    #[serde(rename = "self_signature")]
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
}

impl KeyMaterial for KeyMaterialNonRoot {
    fn uri(&self) -> &URIWithSignature {
        &self.uri
    }
    fn previous_key_material_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>> {
        Some(&self.previous_key_material_self_signature)
    }
    fn version_id(&self) -> u32 {
        self.version_id
    }
    fn valid_from(&self) -> time::OffsetDateTime {
        self.valid_from
    }
    fn authentication_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.authentication_v
    }
    fn assertion_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.assertion_v
    }
    fn key_exchange_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.key_exchange_v
    }
    fn capability_invocation_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.capability_invocation_v
    }
    fn capability_delegation_v(&self) -> &[selfsign::KERIVerifier<'static>] {
        &self.capability_delegation_v
    }
}

impl selfsign::SelfSignable for KeyMaterialNonRoot {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        selfsign::write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher);
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Signature>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_o
                .as_ref()
                .map(|s| -> &dyn selfsign::Signature { s }),
        ))
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        let keri_signature = signature.to_keri_signature().into_owned();
        self.self_signature_o = Some(keri_signature);
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier().into_owned());
    }
}

#[test]
#[serial_test::serial]
fn test_multiple_self_signature_slots() {
    // This will hold each of the KeyMaterial values in the microledger, keyed by their self-signature.
    let mut key_material_m: HashMap<selfsign::KERISignature<'static>, &dyn KeyMaterial> =
        HashMap::new();

    let mut csprng = rand::rngs::OsRng;
    let authentication_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let assertion_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let key_exchange_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let capability_invocation_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let capability_delegation_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut csprng);

    use selfsign::SelfSignable;
    use selfsign::Signer;
    let key_material_0 = {
        let mut key_material_0 = KeyMaterialRoot {
            uri: URIWithSignature {
                scheme: "https".into(),
                authority_o: Some("example.com".into()),
                pre_signature_path: "/identity/".into(),
                signature: capability_invocation_signing_key_0
                    .signature_algorithm()
                    .placeholder_keri_signature(),
                // TODO: Include version_id and self_sig as query params
                query_o: None,
                fragment_o: None,
            },
            version_id: 0,
            valid_from: time::OffsetDateTime::now_utc(),
            authentication_v: vec![authentication_signing_key_0
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            assertion_v: vec![assertion_signing_key_0
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            key_exchange_v: vec![key_exchange_signing_key_0
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            capability_invocation_v: vec![capability_invocation_signing_key_0
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            capability_delegation_v: vec![capability_delegation_signing_key_0
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            self_signature_verifier_o: None,
            self_signature_o: None,
        };
        key_material_0
            .self_sign(&capability_invocation_signing_key_0)
            .expect("pass");
        key_material_0.verify_self_signatures().expect("pass");
        key_material_0
    };
    // println!("key_material_0: {:#?}", key_material_0);
    println!(
        "key_material_0 as JSON:\n{}\n",
        serde_json::to_string_pretty(&key_material_0).expect("pass")
    );

    key_material_m.insert(
        key_material_0.self_signature_o.as_ref().unwrap().clone(),
        &key_material_0,
    );

    // This is the full verification of the KeyMaterial microledger.
    key_material_0
        .verify_recursive(&key_material_m)
        .expect("pass");

    // Now generate new keys and rotate the key material.

    let authentication_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let assertion_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let key_exchange_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let capability_invocation_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let capability_delegation_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut csprng);

    let key_material_1 = {
        let mut key_material_1 = KeyMaterialNonRoot {
            uri: key_material_0.uri.clone(),
            previous_key_material_self_signature: key_material_0
                .self_signature_o
                .as_ref()
                .unwrap()
                .clone(),
            version_id: key_material_0.version_id + 1,
            valid_from: time::OffsetDateTime::now_utc(),
            authentication_v: vec![authentication_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            assertion_v: vec![assertion_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            key_exchange_v: vec![key_exchange_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            capability_invocation_v: vec![capability_invocation_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            capability_delegation_v: vec![capability_delegation_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            self_signature_verifier_o: None,
            self_signature_o: None,
        };
        key_material_1
            .self_sign(&capability_invocation_signing_key_0)
            .expect("pass");
        key_material_1.verify_self_signatures().expect("pass");
        key_material_1
    };
    // println!("key_material_1: {:#?}", key_material_1);
    println!(
        "key_material_1 as JSON:\n{}\n",
        serde_json::to_string_pretty(&key_material_1).expect("pass")
    );

    key_material_m.insert(
        key_material_1.self_signature_o.as_ref().unwrap().clone(),
        &key_material_1,
    );

    // This is the full verification of the KeyMaterial microledger.
    key_material_1
        .verify_recursive(&key_material_m)
        .expect("pass");

    // Do one more round of generation and rotation, to test verification of a non-root KeyMaterial
    // against a non-root previous KeyMaterial.

    let authentication_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let assertion_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);
    let key_exchange_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut csprng);

    let key_material_2 = {
        let mut key_material_2 = KeyMaterialNonRoot {
            uri: key_material_1.uri.clone(),
            previous_key_material_self_signature: key_material_1
                .self_signature_o
                .as_ref()
                .unwrap()
                .clone(),
            version_id: key_material_1.version_id + 1,
            valid_from: time::OffsetDateTime::now_utc(),
            authentication_v: vec![
                authentication_signing_key_1
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
                authentication_signing_key_2
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
            ],
            assertion_v: vec![
                assertion_signing_key_1
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
                assertion_signing_key_2
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
            ],
            key_exchange_v: vec![
                key_exchange_signing_key_1
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
                key_exchange_signing_key_2
                    .verifier()
                    .to_keri_verifier()
                    .into_owned(),
            ],
            capability_invocation_v: vec![capability_invocation_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            capability_delegation_v: vec![capability_delegation_signing_key_1
                .verifier()
                .to_keri_verifier()
                .into_owned()],
            self_signature_verifier_o: None,
            self_signature_o: None,
        };
        key_material_2
            .self_sign(&capability_invocation_signing_key_1)
            .expect("pass");
        key_material_2.verify_self_signatures().expect("pass");
        key_material_2
    };
    // println!("key_material_2: {:#?}", key_material_2);
    println!(
        "key_material_2 as JSON:\n{}\n",
        serde_json::to_string_pretty(&key_material_2).expect("pass")
    );

    key_material_m.insert(
        key_material_2.self_signature_o.as_ref().unwrap().clone(),
        &key_material_2,
    );

    // This is the full verification of the KeyMaterial microledger.
    key_material_2
        .verify_recursive(&key_material_m)
        .expect("pass");
}

#[test]
#[serial_test::serial]
fn test_stuff() {
    for _ in 0..20 {
        let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        use selfsign::Signer;
        let ed25519_verifier = ed25519_signing_key.verifier();
        let keri_verifier = ed25519_verifier.to_keri_verifier();
        println!("{}", keri_verifier);
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TestData {
    pub name: String,
    pub data: Vec<u8>,
    pub self_signature_verifier_o: Option<selfsign::KERIVerifier<'static>>,
    pub self_signature_o: Option<selfsign::KERISignature<'static>>,
    pub self_hash_o: Option<selfhash::KERIHash<'static>>,
}

impl selfsign::SelfSignable for TestData {
    fn write_digest_data(
        &self,
        signature_algorithm: &dyn selfsign::SignatureAlgorithm,
        verifier: &dyn selfsign::Verifier,
        hasher: &mut dyn selfhash::Hasher,
    ) {
        selfsign::write_digest_data_using_jcs(self, signature_algorithm, verifier, hasher);
    }
    fn self_signature_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Signature>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_o
                .as_ref()
                .map(|s| -> &dyn selfsign::Signature { s }),
        ))
    }
    fn set_self_signature_slots_to(&mut self, signature: &dyn selfsign::Signature) {
        let keri_signature = signature.to_keri_signature().into_owned();
        self.self_signature_o = Some(keri_signature);
    }
    fn self_signature_verifier_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfsign::Verifier>> + 'a> {
        Box::new(std::iter::once(
            self.self_signature_verifier_o
                .as_ref()
                .map(|v| -> &dyn selfsign::Verifier { v }),
        ))
    }
    fn set_self_signature_verifier_slots_to(&mut self, verifier: &dyn selfsign::Verifier) {
        self.self_signature_verifier_o = Some(verifier.to_keri_verifier().into_owned());
    }
}

impl selfhash::SelfHashable for TestData {
    fn write_digest_data(&self, hasher: &mut dyn selfhash::Hasher) {
        selfhash::write_digest_data_using_jcs(self, hasher);
    }
    fn self_hash_oi<'a, 'b: 'a>(
        &'b self,
    ) -> Box<dyn std::iter::Iterator<Item = Option<&dyn selfhash::Hash>> + 'a> {
        Box::new(std::iter::once(
            self.self_hash_o
                .as_ref()
                .map(|h| -> &dyn selfhash::Hash { h }),
        ))
    }
    fn set_self_hash_slots_to(&mut self, hash: &dyn selfhash::Hash) {
        let keri_hash = hash.to_keri_hash().into_owned();
        self.self_hash_o = Some(keri_hash);
    }
}

// Produces a Vec containing all the known hash functions (subject to what features are enabled).
fn hash_functions() -> Vec<&'static dyn selfhash::HashFunction> {
    #[allow(unused_mut)]
    let mut hash_function_v: Vec<&'static dyn selfhash::HashFunction> = Vec::new();
    hash_function_v.push(&selfhash::Blake3);
    hash_function_v.push(&selfhash::SHA256);
    hash_function_v.push(&selfhash::SHA512);
    hash_function_v
}

#[test]
#[serial_test::serial]
fn test_self_sign_and_hash() {
    let signer_v: Vec<Box<dyn selfsign::Signer>> = vec![
        Box::new(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)),
        Box::new(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)),
    ];
    for signer in signer_v.iter().map(|signer| signer.as_ref()) {
        for hash_function in hash_functions().into_iter() {
            println!("-------------------------------------------");
            println!(
                "test_self_sign_and_hash; testing hash function {} and signature algorithm {}",
                hash_function.named_hash_function(),
                signer.signature_algorithm().named_signature_algorithm()
            );
            let mut test_data = TestData {
                name: "test".into(),
                data: vec![1, 2, 3],
                self_signature_verifier_o: None,
                self_signature_o: None,
                self_hash_o: None,
            };
            println!("test_data before self-sign-and-hash:\n{:#?}", test_data);
            let hasher_b = hash_function.new_hasher();
            use selfsign::SelfSignAndHashable;
            test_data
                .self_sign_and_hash(signer, hasher_b)
                .expect("pass");
            println!("test_data after self-sign-and-hash:\n{:#?}", test_data);
        }
    }
}
