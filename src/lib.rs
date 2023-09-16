mod base64;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
mod hash;
mod hash_function;
mod hashable;
mod hasher;
mod keri_signature;
mod keri_verifier;
mod key_type;
mod self_signable;
mod signature;
mod signature_algorithm;
mod signature_bytes;
mod signer;
mod verifier;
mod verifier_bytes;

#[cfg(feature = "sha2")]
pub use crate::hash::SHA2_512_Hash;
pub(crate) use crate::keri_signature::ED25519_SHA2_512_KERI_SIGNATURE_PLACEHOLDER;
pub use crate::{
    base64::{
        base64_decode_256_bits, base64_decode_512_bits, base64_encode_256_bits,
        base64_encode_512_bits,
    },
    hash::Hash,
    hash_function::HashFunction,
    hashable::Hashable,
    hasher::Hasher,
    keri_signature::KERISignature,
    keri_verifier::KERIVerifier,
    key_type::KeyType,
    self_signable::SelfSignable,
    signature::Signature,
    signature_algorithm::SignatureAlgorithm,
    signature_bytes::{SignatureBytes, ED25519_SHA2_512_SIGNATURE_BYTES_PLACEHOLDER},
    signer::Signer,
    verifier::Verifier,
    verifier_bytes::VerifierBytes,
};
