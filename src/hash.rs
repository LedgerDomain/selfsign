use crate::HashFunction;

#[allow(non_camel_case_types)]
#[cfg(feature = "sha2")]
pub type SHA2_512_Hash =
    digest::generic_array::GenericArray<u8, <sha2::Sha512 as digest::OutputSizeUser>::OutputSize>;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, derive_more::From, PartialEq)]
pub enum Hash {
    #[cfg(feature = "blake3")]
    BLAKE3_256_Hash(blake3::Hash),
    #[cfg(feature = "sha2")]
    SHA2_512_Hash(SHA2_512_Hash),
}

impl Hash {
    pub fn hash_function(&self) -> HashFunction {
        match self {
            #[cfg(feature = "blake3")]
            Hash::BLAKE3_256_Hash(_) => HashFunction::BLAKE3_256,
            #[cfg(feature = "sha2")]
            Hash::SHA2_512_Hash(_) => HashFunction::SHA2_512,
        }
    }
    #[cfg(feature = "blake3")]
    pub fn as_blake3_256_hash(&self) -> &blake3::Hash {
        match self {
            Hash::BLAKE3_256_Hash(hash) => hash,
            #[allow(unreachable_patterns)]
            _ => panic!("programmer error: hash is not BLAKE3_256_Hash"),
        }
    }
    #[cfg(feature = "sha2")]
    pub fn as_sha2_512_hash(&self) -> &SHA2_512_Hash {
        match self {
            Hash::SHA2_512_Hash(hash) => hash,
            #[allow(unreachable_patterns)]
            _ => panic!("programmer error: hash is not SHA2_512_Hash"),
        }
    }
    #[cfg(feature = "blake3")]
    pub fn into_blake3_256_hash(self) -> blake3::Hash {
        match self {
            Hash::BLAKE3_256_Hash(hash) => hash,
            #[allow(unreachable_patterns)]
            _ => panic!("programmer error: hash is not BLAKE3_256_Hash"),
        }
    }
    #[cfg(feature = "sha2")]
    pub fn into_sha2_512_hash(self) -> SHA2_512_Hash {
        match self {
            Hash::SHA2_512_Hash(hash) => hash,
            #[allow(unreachable_patterns)]
            _ => panic!("programmer error: hash is not SHA2_512_Hash"),
        }
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "blake3")]
            Hash::BLAKE3_256_Hash(hash) => {
                let mut buffer = [0u8; 43];
                write!(
                    f,
                    "{}{}",
                    self.hash_function().keri_prefix(),
                    crate::base64_encode_256_bits(hash.as_bytes(), &mut buffer)
                )
            }
            #[cfg(feature = "sha2")]
            Hash::SHA2_512_Hash(hash) => {
                let mut buffer = [0u8; 86];
                write!(
                    f,
                    "{}{}",
                    self.hash_function().keri_prefix(),
                    crate::base64_encode_512_bits(hash.as_ref(), &mut buffer)
                )
            }
        }
    }
}

impl std::str::FromStr for Hash {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err("Hash::from_str failed: not ASCII");
        }
        if s.len() < 2 {
            return Err("Hash::from_str failed: too short");
        }
        const BLAKE3_KERI_PREFIX: &str = HashFunction::BLAKE3_256.keri_prefix();
        const SHA2_512_KERI_PREFIX: &str = HashFunction::SHA2_512.keri_prefix();
        match &s[..1] {
            BLAKE3_KERI_PREFIX => {
                #[cfg(feature = "blake3")]
                {
                    let mut buffer = [0u8; 33];
                    let hash_byte_v = crate::base64_decode_256_bits(&s[1..], &mut buffer)?;
                    let hash = blake3::Hash::from(hash_byte_v.clone());
                    Ok(Self::BLAKE3_256_Hash(hash))
                }
                #[cfg(not(feature = "blake3"))]
                {
                    return Err("Hash::from_str failed: blake3 feature not enabled");
                }
            }
            "0" => match &s[0..2] {
                SHA2_512_KERI_PREFIX => {
                    #[cfg(feature = "sha2")]
                    {
                        let mut buffer = [0u8; 66];
                        let hash_byte_v = crate::base64_decode_512_bits(&s[2..], &mut buffer)?;
                        let hash = SHA2_512_Hash::clone_from_slice(hash_byte_v);
                        Ok(Self::SHA2_512_Hash(hash))
                    }
                    #[cfg(not(feature = "sha2"))]
                    {
                        return Err("Hash::from_str failed: sha2 feature not enabled");
                    }
                }
                _ => {
                    return Err("Hash::from_str failed: unknown prefix");
                }
            },
            _ => {
                return Err("Hash::from_str failed: unknown prefix");
            }
        }
    }
}
