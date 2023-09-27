/// This function is to assist in no-alloc base64 encoding of 264 bits (used in sec1-encoding of secp256k1 pub keys).
pub fn base64_encode_264_bits<'a>(input_byte_v: &[u8; 33], buffer: &'a mut [u8; 44]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 decoding of 264 bits.
/// 264 bits is exactly 44 base64 chars.
pub fn base64_decode_264_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 33],
) -> Result<&'a [u8; 33], &'static str> {
    if !input_str.is_ascii() {
        return Err("not ASCII");
    }
    if input_str.len() != 44 {
        return Err("expected 44 base64 chars");
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 264 bit value failed")?;
    Ok(buffer)
}
