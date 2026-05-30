use crate::algorithm::Algorithm;
use crate::constant_time::constant_time_eq;
use crate::error::{GenOtpError, Result};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::Zeroize;

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TOTP {
    #[cfg_attr(feature = "serde", serde(skip))]
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    mod_value: u32,
}

impl Drop for TOTP {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl TOTP {
    pub fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u32, period: u64) -> Result<Self> {
        if !(6..=8).contains(&digits) {
            return Err(GenOtpError::InvalidDigits);
        }

        if period == 0 {
            return Err(GenOtpError::InvalidTime);
        }

        if secret.is_empty() {
            return Err(GenOtpError::InvalidSecret);
        }

        let mod_value = 10u32.pow(digits);

        Ok(TOTP {
            secret,
            algorithm,
            digits,
            period,
            mod_value,
        })
    }

    #[cfg(feature = "std")]
    pub fn generate(&self, time: Option<u64>) -> Result<String> {
        let current_time = match time {
            Some(t) => t,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| GenOtpError::InvalidTime)?
                .as_secs(),
        };

        let counter = current_time / self.period;

        let hmac = self.compute_hmac(counter)?;
        let code = self.dynamic_truncate(&hmac);

        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    #[cfg(not(feature = "std"))]
    pub fn generate(&self, time: u64) -> Result<String> {
        let counter = time / self.period;

        let hmac = self.compute_hmac(counter)?;
        let code = self.dynamic_truncate(&hmac);

        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    #[cfg(feature = "std")]
    pub fn verify(&self, code: &str, time: Option<u64>, window: u64) -> Result<bool> {
        let current_time = match time {
            Some(t) => t,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| GenOtpError::InvalidTime)?
                .as_secs(),
        };

        let counter = current_time / self.period;
        let window_i64 = i64::try_from(window).map_err(|_| GenOtpError::InvalidTime)?;

        for i in -window_i64..=window_i64 {
            let test_counter = match counter.checked_add_signed(i) {
                Some(c) => c,
                None => continue,
            };
            let time = test_counter.saturating_mul(self.period);
            let expected = self.generate(Some(time))?;
            if constant_time_eq(code, &expected) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(not(feature = "std"))]
    pub fn verify(&self, code: &str, time: u64, window: u64) -> Result<bool> {
        let counter = time / self.period;
        let window_i64 = i64::try_from(window).map_err(|_| GenOtpError::InvalidTime)?;

        for i in -window_i64..=window_i64 {
            let test_counter = match counter.checked_add_signed(i) {
                Some(c) => c,
                None => continue,
            };
            let expected = self.generate(test_counter.saturating_mul(self.period))?;
            if constant_time_eq(code, &expected) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn compute_hmac(&self, counter: u64) -> Result<Vec<u8>> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha1::Sha1;
        use sha2::{Sha256, Sha512};

        let counter_bytes = counter.to_be_bytes();

        let hmac_result = match self.algorithm {
            Algorithm::SHA1 => {
                type HmacSha1 = Hmac<Sha1>;
                let mut mac = HmacSha1::new_from_slice(&self.secret)
                    .map_err(|_| GenOtpError::InvalidSecret)?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .map_err(|_| GenOtpError::InvalidSecret)?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(&self.secret)
                    .map_err(|_| GenOtpError::InvalidSecret)?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        Ok(hmac_result)
    }

    fn dynamic_truncate(&self, hmac: &[u8]) -> u32 {
        let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
        let binary = ((hmac[offset] & 0x7f) as u32) << 24
            | (hmac[offset + 1] as u32) << 16
            | (hmac[offset + 2] as u32) << 8
            | hmac[offset + 3] as u32;

        binary % self.mod_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
        let code = totp.generate(Some(1234567890)).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_verify() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
        let code = totp.generate(Some(1234567890)).unwrap();
        assert!(totp.verify(&code, Some(1234567890), 1).unwrap());
    }

    #[test]
    fn test_rfc6238_vectors_sha1() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 8, 30).unwrap();

        let test_cases = vec![
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];

        for (time, expected) in test_cases {
            let code = totp.generate(Some(time)).unwrap();
            assert_eq!(code, expected, "Time {}", time);
        }
    }

    #[test]
    fn test_rfc6238_vectors_sha256() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA256, 8, 30).unwrap();

        let code = totp.generate(Some(59)).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_rfc6238_vectors_sha512() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA512, 8, 30).unwrap();

        let code = totp.generate(Some(59)).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_verify_small_counter_no_underflow() {
        // Regression: counter kecil (=0) dengan window>=1 dulu menyebabkan
        // (counter as i64 + i) as u64 wrap ke u64::MAX. Sekarang harus aman.
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

        let code = totp.generate(Some(0)).unwrap();
        assert!(totp.verify(&code, Some(0), 5).unwrap());
        // Kode untuk time=0 juga harus diterima dengan window pada time=30.
        assert!(totp.verify(&code, Some(30), 1).unwrap());
    }

    #[test]
    fn test_verify_with_window() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

        let code = totp.generate(Some(59)).unwrap();
        assert!(totp.verify(&code, Some(59), 1).unwrap());
        assert!(totp.verify(&code, Some(89), 1).unwrap());
        assert!(!totp.verify(&code, Some(119), 1).unwrap());
    }

    #[test]
    fn test_different_periods() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];

        let totp_30 = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 30).unwrap();
        let code_30 = totp_30.generate(Some(59)).unwrap();
        assert_eq!(code_30.len(), 6);

        let totp_60 = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 60).unwrap();
        let code_60 = totp_60.generate(Some(59)).unwrap();
        assert_eq!(code_60.len(), 6);

        let totp_90 = TOTP::new(secret, Algorithm::SHA1, 6, 90).unwrap();
        let code_90 = totp_90.generate(Some(59)).unwrap();
        assert_eq!(code_90.len(), 6);
    }

    #[test]
    fn test_8_digits() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 8, 30).unwrap();

        let code = totp.generate(Some(59)).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_zeroize_on_drop() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
        drop(totp);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

        let json = serde_json::to_string(&totp).unwrap();
        assert!(json.contains("SHA1"));
        assert!(json.contains("6"));
        assert!(json.contains("30"));
        assert!(!json.contains("secret"));
    }
}
