use crate::Hasher;

/// This is useful for defining specific hashing procedures for data structures, instead of
/// e.g. hashing a JSON serialization of a data structure.
pub trait Hashable {
    fn update_hasher(&self, hasher: &mut Hasher);
}

impl Hashable for &str {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"String");
        self.len().update_hasher(hasher);
        hasher.update(self.as_bytes());
    }
}

impl Hashable for String {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"String");
        self.len().update_hasher(hasher);
        hasher.update(self.as_bytes());
    }
}

impl Hashable for [u8] {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"Bytes");
        self.len().update_hasher(hasher);
        hasher.update(self);
    }
}

impl Hashable for Vec<u8> {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"Bytes");
        self.len().update_hasher(hasher);
        hasher.update(self.as_slice());
    }
}

impl<H: Hashable> Hashable for Option<H> {
    /// This particular definition makes None and Some([]) produce distinct hashes.
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"Option");
        if let Some(value) = self {
            hasher.update(b"\x01");
            value.update_hasher(hasher);
        } else {
            hasher.update(b"\x00");
        }
    }
}

/// Note that u8 does not implement Hashable.
impl<H: Hashable> Hashable for Vec<H> {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"Array");
        (self.len() as u64).update_hasher(hasher);
        for element in self.iter() {
            element.update_hasher(hasher);
        }
    }
}

/// Note that u8 does not implement Hashable.
impl<H: Hashable> Hashable for [H] {
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"Array");
        (self.len() as u64).update_hasher(hasher);
        for element in self.iter() {
            element.update_hasher(hasher);
        }
    }
}

impl Hashable for i32 {
    /// Generally all values that have an endianness are represented in little-endian order.
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"i32");
        hasher.update(&self.to_le_bytes());
    }
}

impl Hashable for i64 {
    /// Generally all values that have an endianness are represented in little-endian order.
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"i64");
        hasher.update(&self.to_le_bytes());
    }
}

impl Hashable for u32 {
    /// Generally all values that have an endianness are represented in little-endian order.
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"u32");
        hasher.update(&self.to_le_bytes());
    }
}

impl Hashable for u64 {
    /// Generally all values that have an endianness are represented in little-endian order.
    fn update_hasher(&self, hasher: &mut Hasher) {
        hasher.update(b"u64");
        hasher.update(&self.to_le_bytes());
    }
}

impl Hashable for usize {
    /// This always represents a usize as u64 (and therefore in little-endian order).
    fn update_hasher(&self, hasher: &mut Hasher) {
        (*self as u64).update_hasher(hasher);
    }
}
