use crate::Hasher;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub enum HashFunction {
    BLAKE3_256,
    SHA2_512,
}

impl HashFunction {
    pub const fn keri_prefix(&self) -> &'static str {
        match self {
            HashFunction::BLAKE3_256 => "E",
            HashFunction::SHA2_512 => "0G",
        }
    }
    pub fn new_hasher(&self) -> Hasher {
        match self {
            HashFunction::BLAKE3_256 => {
                #[cfg(feature = "blake3")]
                {
                    blake3::Hasher::new().into()
                }
                #[cfg(not(feature = "blake3"))]
                {
                    panic!("programmer error: blake3 feature not enabled");
                }
            }
            HashFunction::SHA2_512 => {
                #[cfg(feature = "sha2")]
                {
                    sha2::Sha512::default().into()
                }
                #[cfg(not(feature = "sha2"))]
                {
                    panic!("programmer error: sha2 feature not enabled");
                }
            }
        }
    }
    pub const fn placeholder_bytes(&self) -> &'static [u8] {
        match self {
            HashFunction::BLAKE3_256 => &[0u8; 32],
            HashFunction::SHA2_512 => &[0u8; 64],
        }
    }
}

/// This impl uses the KERI prefixes.
impl std::fmt::Display for HashFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.keri_prefix())
    }
}

impl std::str::FromStr for HashFunction {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "E" => Ok(Self::BLAKE3_256),
            "0G" => Ok(Self::SHA2_512),
            _ => Err("HashFunction::from_str failed: unknown prefix"),
        }
    }
}
