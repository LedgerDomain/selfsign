use pkcs8::DecodePrivateKey;
use selfhash::{Blake3, HashFunction, SelfHashableJSON};
use selfsign::SelfSignAndHashable;
use std::{
    borrow::Cow,
    collections::HashSet,
    io::{Read, Write},
};

/// Operate on JSON as self-sign-and-hashable data -- signed data which is self-validating.  In particular,
/// self-signable data is data which has at least one "self-signature slot" and "self-signature verifier slot"
/// which is used during the computation and verification of the data's self-signature.  During the computation
/// of the data's self-signatures, all the self-signature slots and self-hash slots, if present, are set to
/// appropriate placeholder values which encode the public key, the digital signature algorithm, and the hash
/// function that will be used in the self-signing and self-hashing procedure, the data is serialized into JCS
/// (JSON Canonicalization Scheme), signed, that signature is used to populate all self-signature slots, the
/// data is serialized into JCS again, hashed, then that hash is used to populate all self-hash slots, and
/// finally the data is serialized into JCS.  The data is then serialized into JCS again, and at this point
/// is self-signed-and-hashed, and is fully self-verifiable.
#[derive(clap::Parser)]
#[clap(version, about)]
enum CLI {
    /// Generate a private key, writing it in PEM format to a specified filename, which can be used to self-sign
    /// JSON blobs.  Print the public key corresponding to the generated private key to stdout.
    GenKey(GenKey),
    /// Read JSON from stdin, self-sign and self-hash the JSON, and output the resulting canonical JSON (JCS),
    /// overwriting any existing self-signature, self-signature verifier, and self-hash fields.
    Compute(Compute),
    /// Read JSON from stdin, verify its self-signature(s) and self-hash(es), and print the verified self-hash.
    Verify(Verify),
}

impl CLI {
    fn handle(self) {
        match self {
            Self::GenKey(x) => x.handle(),
            Self::Compute(x) => x.handle(),
            Self::Verify(x) => x.handle(),
        }
    }
}

#[derive(clap::Args)]
struct GenKey {
    /// Specify the type of key to be generated.  Must be one of Ed25519, Secp256k1
    // TODO: Figure out how to specify to use std::str::FromStr to parse
    #[arg(short, long)]
    key_type: String,
    /// Specify the path to write the generated private key to.  If the path exists already, it will not be
    /// overwritten, and this program will return an error.
    #[arg(short, long)]
    private_key_path: std::path::PathBuf,
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
}

impl GenKey {
    fn handle(self) {
        if self.private_key_path.exists() {
            panic!("Path {:?} specified by --private-key-path already exists -- refusing to overwrite.", self.private_key_path);
        }

        use selfsign::Signer;
        use std::str::FromStr;
        let key_type = selfsign::KeyType::from_str(&self.key_type).expect("unrecognized key type");
        let keri_verifier = match key_type {
            selfsign::KeyType::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
                use ed25519_dalek::pkcs8::EncodePrivateKey;
                signing_key
                    .write_pkcs8_pem_file(&self.private_key_path, Default::default())
                    .expect("failed to write generated key");
                signing_key.verifier().to_keri_verifier().into_owned()
            }
            selfsign::KeyType::Secp256k1 => {
                let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                let keri_verifier = signing_key.verifier().to_keri_verifier().into_owned();
                let secret_key = k256::elliptic_curve::SecretKey::from(signing_key);
                use k256::pkcs8::EncodePrivateKey;
                secret_key
                    .write_pkcs8_pem_file(&self.private_key_path, Default::default())
                    .expect("failed to write generated key");
                keri_verifier
            }
        };

        // Print the KERIVerifier (i.e. pub key) of the generated priv key.
        std::io::stdout().write(keri_verifier.as_bytes()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

#[derive(clap::Args)]
struct SelfHashArgs {
    /// Optionally specify a comma-delimited list of top-level field names that are considered self-hash slots.
    #[arg(short, long, default_value = "selfHash", value_name = "FIELD_NAME")]
    self_hash_field_names: String,
    /// Optionally specify a comma-delimited list of top-level field names that are considered self-hash URL slots.
    #[arg(short = 'u', long, default_value = "", value_name = "FIELD_NAME")]
    self_hash_url_field_names: String,
}

impl SelfHashArgs {
    fn parse_self_hash_field_names(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_field_names = self.self_hash_field_names.trim();
        if self_hash_field_names.is_empty() {
            maplit::hashset! {}
        } else {
            self_hash_field_names
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
    fn parse_self_hash_url_field_names(&self) -> HashSet<Cow<'_, str>> {
        let self_hash_url_field_names = self.self_hash_url_field_names.trim();
        if self_hash_url_field_names.is_empty() {
            maplit::hashset! {}
        } else {
            self_hash_url_field_names
                .split(',')
                .map(|s| Cow::Borrowed(s))
                .collect::<HashSet<_>>()
        }
    }
}

#[derive(clap::Args)]
struct Compute {
    /// Specify the path of the private key to be used for the self-signing operation.
    #[arg(short, long)]
    private_key_path: std::path::PathBuf,
    #[command(flatten)]
    self_hash_args: SelfHashArgs,
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
}

fn read_private_key_file(
    private_key_path: &std::path::Path,
) -> selfsign::Result<Box<dyn selfsign::Signer>> {
    for &key_type in selfsign::KEY_TYPE_V {
        match key_type {
            selfsign::KeyType::Ed25519 => {
                if let Ok(signing_key) =
                    ed25519_dalek::SigningKey::read_pkcs8_pem_file(private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            selfsign::KeyType::Secp256k1 => {
                if let Ok(signing_key) =
                    k256::ecdsa::SigningKey::read_pkcs8_pem_file(private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
        }
    }
    selfsign::bail!(
        "Private key at path {:?} was not in a recognized format.",
        private_key_path
    )
}

impl Compute {
    fn handle(self) {
        // Attempt to read the private key.
        let signer_b = read_private_key_file(&self.private_key_path).unwrap();

        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value = serde_json::from_str(&input).unwrap();

        let self_hash_field_name_s = self.self_hash_args.parse_self_hash_field_names();
        let self_hash_url_field_name_s = self.self_hash_args.parse_self_hash_url_field_names();

        let mut json = SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_field_name_s),
            Cow::Borrowed(&self_hash_url_field_name_s),
        )
        .unwrap();

        // Compute the self-signature(s) and self-hash(es).
        use selfsign::SelfSignAndHashable;
        json.self_sign_and_hash(signer_b.as_ref(), Blake3.new_hasher())
            .expect("self-sign-and-hash-ing failed");
        // Verify the self-signature(s) and self-hash(es).  This is mostly a sanity check.
        json.verify_self_signatures_and_hashes()
            .expect("programmer error: self-sign-and-hash verification failed");

        // Print the self-signed-and-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(json.value(), &mut std::io::stdout()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

#[derive(clap::Args)]
struct Verify {
    #[command(flatten)]
    self_hash_args: SelfHashArgs,
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
}

impl Verify {
    fn handle(&self) {
        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&input).unwrap();

        let self_hash_field_name_s = self.self_hash_args.parse_self_hash_field_names();
        let self_hash_url_field_name_s = self.self_hash_args.parse_self_hash_url_field_names();

        // Check for the existence of the self-hash [URL] field(s).  This is to produce a better error
        // message than the one that would be produced by verify_self_hashes.
        for self_hash_field_name in self_hash_field_name_s.iter().map(std::ops::Deref::deref) {
            if value.get(self_hash_field_name).is_none() {
                eprintln!("Input JSON has no {:?} field (expected because of argument --self-hash-field-names {:?}), and therefore can't be verified.", self_hash_field_name, self.self_hash_args.self_hash_field_names);
                std::process::exit(1);
            }
        }
        for self_hash_url_field_name in self_hash_url_field_name_s
            .iter()
            .map(std::ops::Deref::deref)
        {
            if value.get(self_hash_url_field_name).is_none() {
                eprintln!("Input JSON has no {:?} field (expected because of argument --self-hash-url-field-names {:?}), and therefore can't be verified.", self_hash_url_field_name, self.self_hash_args.self_hash_url_field_names);
                std::process::exit(1);
            }
        }

        let json = SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_field_name_s),
            Cow::Borrowed(&self_hash_url_field_name_s),
        )
        .unwrap();

        // Verify the self-signature(s) and self-hash(es).
        let (_self_signature, self_hash) = json
            .verify_self_signatures_and_hashes()
            .expect("self-signature and self-hash verification failed");
        let self_hash = self_hash.to_keri_hash();

        // Print the verified self-hash.
        std::io::stdout().write(self_hash.as_bytes()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

fn main() {
    use clap::Parser;
    CLI::parse().handle();
}
