use crate::{KERISignature, SignatureAlgorithm, SignatureBytes};

pub trait Signature {
    /// Returns the SignatureAlgorithm to be used to produce the signature.
    fn signature_algorithm(&self) -> SignatureAlgorithm;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the SignatureAlgorithm and the verifying key.
    fn to_signature_bytes(&self) -> SignatureBytes;
    /// This is one of two versions of the concrete value that goes into the end-use data
    /// structure, representing the SignatureAlgorithm and the verifying key.
    fn to_keri_signature(&self) -> KERISignature;
}
