//! Standard Base64 (RFC 4648 §4) **decoder** for Nostr `Authorization` events.
//!
//! Wire form per §7.4 / BUD-01: `Authorization: Nostr <base64(event JSON)>`.
//! That is the **standard** alphabet (`A–Z a–z 0–9 + /`) with `=` padding —
//! not base64url (`-` `_`, no pad) used by NIP44Binary in the node tree.
//!
//! Decode-only in production: the server never re-encodes the auth event.

/// Decode standard Base64 (with `=` padding). Rejects URL-safe alphabet and
/// non-alphabet characters.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if !input.len().is_multiple_of(4) {
        return Err(Base64Error::Length);
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let is_last = i + 4 >= bytes.len();
        let b0 = val(bytes[i])?;
        let b1 = val(bytes[i + 1])?;
        let (b2, pad2) = if bytes[i + 2] == b'=' {
            if !is_last || bytes[i + 3] != b'=' {
                return Err(Base64Error::Padding);
            }
            (0, true)
        } else {
            (val(bytes[i + 2])?, false)
        };
        let (b3, pad3) = if bytes[i + 3] == b'=' {
            if !is_last {
                return Err(Base64Error::Padding);
            }
            (0, true)
        } else {
            if pad2 {
                return Err(Base64Error::Padding);
            }
            (val(bytes[i + 3])?, false)
        };
        let n = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
        out.push((n >> 16) as u8);
        if !pad2 {
            out.push((n >> 8) as u8);
        }
        if !pad3 {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn val(b: u8) -> Result<u32, Base64Error> {
    match b {
        b'A'..=b'Z' => Ok((b - b'A') as u32),
        b'a'..=b'z' => Ok((b - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((b - b'0' + 52) as u32),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64Error::Char(b)),
    }
}

/// Distinct failure modes of standard Base64 decoding.
///
/// The enum name already carries the domain; variants name the cause only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base64Error {
    /// Byte outside the standard alphabet (`A–Z a–z 0–9 + /` and `=` only in pad positions).
    Char(u8),
    /// Input length is not a multiple of 4 (standard padded form).
    Length,
    /// `=` in a non-terminal position, missing trailing pad, or pad before a non-pad.
    Padding,
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Base64Error::Char(b) => write!(f, "invalid base64 character 0x{b:02x}"),
            Base64Error::Length => write!(f, "invalid base64 length"),
            Base64Error::Padding => write!(f, "invalid base64 padding"),
        }
    }
}

impl std::error::Error for Base64Error {}

/// Encode raw bytes as standard Base64 with `=` padding.
///
/// Test/helper only — production auth path is decode-only.
#[cfg(test)]
pub fn encode(input: &[u8]) -> String {
    const ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(ENCODE[((n >> 18) & 0x3f) as usize] as char);
        out.push(ENCODE[((n >> 12) & 0x3f) as usize] as char);
        out.push(ENCODE[((n >> 6) & 0x3f) as usize] as char);
        out.push(ENCODE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        0 => {}
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(ENCODE[((n >> 18) & 0x3f) as usize] as char);
            out.push(ENCODE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(ENCODE[((n >> 18) & 0x3f) as usize] as char);
            out.push(ENCODE[((n >> 12) & 0x3f) as usize] as char);
            out.push(ENCODE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn decode_rfc4648_vectors() {
        // RFC 4648 §10 — known standard-Base64 encodings (no encoder in prod path).
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn encode_round_trip_via_test_helper() {
        // Test-only encoder: produce and re-decode.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        for plain in [
            b"" as &[u8],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
        ] {
            assert_eq!(decode(&encode(plain)).unwrap(), plain);
        }
    }

    #[test]
    fn rejects_url_safe_alphabet() {
        // base64url would use `-`/`_`; standard decode must refuse them.
        let err = decode("Zm9v-g==").expect_err("url-safe char");
        assert!(matches!(err, Base64Error::Char(b'-')));
    }

    #[test]
    fn rejects_bad_length() {
        let err = decode("Zm9").expect_err("len % 4 != 0");
        assert_eq!(err, Base64Error::Length);
    }

    #[test]
    fn rejects_bad_padding() {
        let err = decode("Zg=A").expect_err("pad then non-pad");
        assert_eq!(err, Base64Error::Padding);

        let err = decode("Zm8=AAAA").expect_err("padding before final quartet");
        assert_eq!(err, Base64Error::Padding);
    }

    #[test]
    fn decodes_both_standard_alphabet_symbols() {
        assert_eq!(decode("+/8=").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn errors_have_stable_diagnostic_messages() {
        assert_eq!(
            Base64Error::Char(b'_').to_string(),
            "invalid base64 character 0x5f"
        );
        assert_eq!(Base64Error::Length.to_string(), "invalid base64 length");
        assert_eq!(Base64Error::Padding.to_string(), "invalid base64 padding");
    }
}
