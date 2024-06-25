use crate::{KERISignature, KeyType, NamedSignatureAlgorithm, SignatureBytes};

pub trait SignatureAlgorithm {
    fn as_any(&self) -> &dyn std::any::Any;
    fn equals(&self, other: &dyn SignatureAlgorithm) -> bool;
    /// Returns the NamedSignatureAlgorithm form of this signature algorithm.
    fn named_signature_algorithm(&self) -> NamedSignatureAlgorithm;
    /// Defines the KeyType used in this SignatureAlgorithm.
    fn key_type(&self) -> KeyType;
    /// Defines which hash function is used to generate the digest of the self-signing object.
    fn message_digest_hash_function(&self) -> &'static dyn selfhash::HashFunction;
    /// Returns the KERI prefix for this SignatureAlgorithm.  This does not include any signature data.
    fn keri_prefix(&self) -> &'static str;
    /// Returns the number of bytes in a signature produced by this SignatureAlgorithm.
    fn signature_bytes_len(&self) -> usize;
    /// Returns the length of the KERI representation of a signature produced by this SignatureAlgorithm,
    /// which consists of the KERI prefix and then the base64url-no-pad-encoding of the signature bytes.
    fn keri_signature_len(&self) -> usize;
    /// Returns the KERISignature form of the signature to be used as the placeholder when generating
    /// the digest of the self-signing object.
    fn placeholder_keri_signature(&self) -> &'static KERISignature;
    /// Returns the SignatureBytes form of the signature to be used as the placeholder when generating
    /// the digest of the self-signing object.
    fn placeholder_signature_bytes(&self) -> SignatureBytes<'static>;
}
