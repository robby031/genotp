use crate::error::{GenOtpError, Result};
use getrandom::fill;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub struct KeyGenerator;

impl KeyGenerator {
    pub fn generate_secret(bit_length: usize) -> Result<Vec<u8>> {
        if bit_length < 128 {
            return Err(GenOtpError::InvalidSecret);
        }

        if !bit_length.is_multiple_of(8) {
            return Err(GenOtpError::InvalidSecret);
        }

        let byte_length = bit_length / 8;
        let mut secret = vec![0u8; byte_length];
        // OS-backed cryptographically secure RNG. Kalau OS gagal supply
        // entropy (sangat jarang — biasanya container baru boot tanpa
        // /dev/urandom), kembalikan error daripada fallback ke PRNG lemah.
        fill(&mut secret).map_err(|_| GenOtpError::InvalidSecret)?;

        Ok(secret)
    }

    pub fn generate_default_secret() -> Result<Vec<u8>> {
        Self::generate_secret(160)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_secret() {
        let secret = KeyGenerator::generate_secret(160).unwrap();
        assert_eq!(secret.len(), 20);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_default_secret() {
        let secret = KeyGenerator::generate_default_secret().unwrap();
        assert_eq!(secret.len(), 20);
    }

    #[test]
    fn test_invalid_bit_length() {
        let result = KeyGenerator::generate_secret(64);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_multiple_of_8_rejected() {
        // 129 bukan kelipatan 8 — dulu dibulatkan ke bawah jadi 128 bit secara
        // diam-diam. Sekarang harus ditolak.
        let result = KeyGenerator::generate_secret(129);
        assert!(result.is_err());
    }
}
