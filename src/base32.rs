use crate::error::{GenOtpError, Result};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub fn encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data)
}

pub fn decode(data: &str) -> Result<Vec<u8>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, data)
        .ok_or(GenOtpError::InvalidSecret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = vec![0x31, 0x32, 0x33, 0x34, 0x35];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_encode_empty() {
        let data = vec![];
        let encoded = encode(&data);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_decode_invalid() {
        let result = decode("invalid!!!@#");
        assert!(result.is_err());
    }
}
