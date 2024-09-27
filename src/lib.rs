mod base64;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
mod ed25519_sha512;
mod error;
#[cfg(feature = "k256")]
mod k256;
mod keri_signature;
mod keri_signature_str;
mod keri_verifier;
mod keri_verifier_str;
mod key_type;
mod named_signature_algorithm;
mod preferred_signature_format;
mod preferred_verifier_format;
mod private_key_bytes;
mod secp256k1_sha256;
mod self_sign_and_hashable;
mod self_signable;
mod signature;
mod signature_algorithm;
mod signature_bytes;
mod signer;
mod verifier;
mod verifier_bytes;

#[cfg(feature = "jcs")]
pub use crate::self_signable::write_digest_data_using_jcs;
pub use crate::{
    base64::{base64_decode_264_bits, base64_encode_264_bits},
    ed25519_sha512::{Ed25519_SHA512, ED25519_SHA_512},
    error::Error,
    keri_signature::KERISignature,
    keri_signature_str::KERISignatureStr,
    keri_verifier::KERIVerifier,
    keri_verifier_str::KERIVerifierStr,
    key_type::{KeyType, KEY_TYPE_V},
    named_signature_algorithm::NamedSignatureAlgorithm,
    preferred_signature_format::PreferredSignatureFormat,
    preferred_verifier_format::PreferredVerifierFormat,
    private_key_bytes::PrivateKeyBytes,
    secp256k1_sha256::{Secp256k1_SHA256, SECP256K1_SHA_256},
    self_sign_and_hashable::SelfSignAndHashable,
    self_signable::SelfSignable,
    signature::Signature,
    signature_algorithm::SignatureAlgorithm,
    signature_bytes::SignatureBytes,
    signer::Signer,
    verifier::Verifier,
    verifier_bytes::VerifierBytes,
};

pub type Result<T> = std::result::Result<T, Error>;
