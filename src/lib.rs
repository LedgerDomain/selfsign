mod base64;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
mod ed25519_sha512;
#[cfg(feature = "k256")]
mod k256;
mod keri_signature;
mod keri_verifier;
mod key_type;
mod named_signature_algorithm;
mod secp256k1_sha256;
mod self_sign_and_hashable;
mod self_signable;
mod signature;
mod signature_algorithm;
mod signature_bytes;
mod signer;
mod verifier;
mod verifier_bytes;

pub use crate::{
    base64::{base64_decode_264_bits, base64_encode_264_bits},
    ed25519_sha512::{Ed25519_SHA512, ED25519_SHA_512},
    keri_signature::KERISignature,
    keri_verifier::KERIVerifier,
    key_type::KeyType,
    named_signature_algorithm::NamedSignatureAlgorithm,
    secp256k1_sha256::{Secp256k1_SHA256, SECP256K1_SHA_256},
    self_sign_and_hashable::SelfSignAndHashable,
    self_signable::{write_digest_data_using_jcs, SelfSignable},
    signature::Signature,
    signature_algorithm::SignatureAlgorithm,
    signature_bytes::SignatureBytes,
    signer::Signer,
    verifier::Verifier,
    verifier_bytes::VerifierBytes,
};
