use crate::{Hash, HashFunction};

// TODO: This would be better as a trait.
pub enum Hasher {
    #[cfg(feature = "blake3")]
    BLAKE3_256(blake3::Hasher),
    #[cfg(feature = "sha2")]
    SHA2_512(sha2::Sha512),
}

impl Hasher {
    pub fn hash_function(&self) -> HashFunction {
        match self {
            #[cfg(feature = "blake3")]
            Hasher::BLAKE3_256(_) => HashFunction::BLAKE3_256,
            #[cfg(feature = "sha2")]
            Hasher::SHA2_512(_) => HashFunction::SHA2_512,
        }
    }
    pub fn update(&mut self, byte_v: &[u8]) {
        match self {
            #[cfg(feature = "blake3")]
            Hasher::BLAKE3_256(blake3_256) => {
                blake3_256.update(byte_v);
            }
            #[cfg(feature = "sha2")]
            Hasher::SHA2_512(sha2_512) => {
                use sha2::Digest;
                sha2_512.update(byte_v);
            }
        }
    }
    pub fn finalize(self) -> Hash {
        match self {
            #[cfg(feature = "blake3")]
            Hasher::BLAKE3_256(blake3_256) => blake3_256.finalize().into(),
            #[cfg(feature = "sha2")]
            Hasher::SHA2_512(sha2_512) => {
                use sha2::Digest;
                sha2_512.finalize().into()
            }
        }
    }
    #[cfg(feature = "blake3")]
    pub fn as_blake3_256(&self) -> &blake3::Hasher {
        match self {
            Hasher::BLAKE3_256(blake3_256) => blake3_256,
            _ => panic!("programmer error: hasher is not BLAKE3_256"),
        }
    }
    #[cfg(feature = "blake3")]
    pub fn as_blake3_256_mut(&mut self) -> &mut blake3::Hasher {
        match self {
            Hasher::BLAKE3_256(blake3_256) => blake3_256,
            _ => panic!("programmer error: hasher is not BLAKE3_256"),
        }
    }
    #[cfg(feature = "blake3")]
    pub fn into_blake3_256(self) -> blake3::Hasher {
        match self {
            Hasher::BLAKE3_256(blake3_256) => blake3_256,
            _ => panic!("programmer error: hasher is not BLAKE3_256"),
        }
    }
    #[cfg(feature = "sha2")]
    pub fn as_sha2_512(&self) -> &sha2::Sha512 {
        match self {
            Hasher::SHA2_512(sha2_512) => sha2_512,
            _ => panic!("programmer error: hasher is not SHA2_512"),
        }
    }
    #[cfg(feature = "sha2")]
    pub fn as_sha2_512_mut(&mut self) -> &mut sha2::Sha512 {
        match self {
            Hasher::SHA2_512(sha2_512) => sha2_512,
            _ => panic!("programmer error: hasher is not SHA2_512"),
        }
    }
    #[cfg(feature = "sha2")]
    pub fn into_sha2_512(self) -> sha2::Sha512 {
        match self {
            Hasher::SHA2_512(sha2_512) => sha2_512,
            _ => panic!("programmer error: hasher is not SHA2_512"),
        }
    }
}

#[cfg(feature = "blake3")]
impl From<blake3::Hasher> for Hasher {
    fn from(blake3_256: blake3::Hasher) -> Self {
        Self::BLAKE3_256(blake3_256)
    }
}

#[cfg(feature = "sha2")]
impl From<sha2::Sha512> for Hasher {
    fn from(sha2_512: sha2::Sha512) -> Self {
        Self::SHA2_512(sha2_512)
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // Nothing needs to be done.
        Ok(())
    }
}
