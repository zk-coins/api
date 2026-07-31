//! Lowercase hex codecs for §7.1 wire values (32-byte digests, 64-byte sigs).

/// Decode a lowercase-or-uppercase hex string into exactly `byte_len` bytes.
///
/// Rejects wrong length, odd nibble count, and non-hex characters. No padding
/// and no silent truncation.
pub fn decode_hex_exact(input: &str, byte_len: usize) -> Result<Vec<u8>, HexError> {
    if input.len() != byte_len * 2 {
        return Err(HexError::Length {
            expected_chars: byte_len * 2,
            got_chars: input.len(),
        });
    }
    let mut out = Vec::with_capacity(byte_len);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Encode bytes as lowercase hex (no `0x` prefix).
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_nibble(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError::InvalidChar(b)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    Length {
        expected_chars: usize,
        got_chars: usize,
    },
    InvalidChar(u8),
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::Length {
                expected_chars,
                got_chars,
            } => write!(
                f,
                "hex length must be {expected_chars} characters, got {got_chars}"
            ),
            HexError::InvalidChar(b) => write!(f, "invalid hex character 0x{b:02x}"),
        }
    }
}

impl std::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_32() {
        let raw = [0u8; 32];
        let hex = encode_hex(&raw);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_hex_exact(&hex, 32).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = decode_hex_exact("ab", 32).unwrap_err();
        match err {
            HexError::Length {
                expected_chars,
                got_chars,
            } => {
                assert_eq!(expected_chars, 64);
                assert_eq!(got_chars, 2);
            }
            other => panic!("expected Length, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_hex() {
        let err = decode_hex_exact("zz", 1).unwrap_err();
        assert!(matches!(err, HexError::InvalidChar(_)));
    }
}
