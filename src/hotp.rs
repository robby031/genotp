use crate::algorithm::Algorithm;
use crate::constant_time::constant_time_eq;
use crate::error::{GenOtpError, Result};

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

const CONTEXT_BIND_TAG: &[u8] = b"genotp-ctx-v1\0";

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HOTP {
    #[cfg_attr(feature = "serde", serde(skip))]
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    mod_value: u32,
}

impl Drop for HOTP {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl HOTP {
    pub fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u32) -> Result<Self> {
        if !(6..=8).contains(&digits) {
            return Err(GenOtpError::InvalidDigits);
        }

        if secret.is_empty() {
            return Err(GenOtpError::InvalidSecret);
        }

        let mod_value = 10u32.pow(digits);

        Ok(HOTP {
            secret,
            algorithm,
            digits,
            mod_value,
        })
    }

    pub fn generate(&self, counter: u64) -> Result<String> {
        let hmac = self.compute_hmac(counter)?;
        let code = self.dynamic_truncate(&hmac);

        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    pub fn verify(&self, code: &str, counter: u64) -> Result<bool> {
        let expected = self.generate(counter)?;
        Ok(constant_time_eq(code, &expected))
    }

    /// Generate HOTP yang **terikat ke context**. Lihat dokumentasi
    /// [`crate::context::OtpContext`] untuk detail.
    #[cfg(feature = "std")]
    pub fn generate_bound(
        &self,
        counter: u64,
        context: &crate::context::OtpContext,
    ) -> Result<String> {
        let hmac = self.compute_hmac_bytes(counter, context.as_bytes())?;
        let code = self.dynamic_truncate(&hmac);
        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    /// Verifikasi HOTP yang terikat ke context.
    #[cfg(feature = "std")]
    pub fn verify_bound(
        &self,
        code: &str,
        counter: u64,
        context: &crate::context::OtpContext,
    ) -> Result<bool> {
        let expected = self.generate_bound(counter, context)?;
        Ok(constant_time_eq(code, &expected))
    }

    fn compute_hmac(&self, counter: u64) -> Result<Vec<u8>> {
        self.compute_hmac_bytes(counter, &[])
    }

    fn compute_hmac_bytes(&self, counter: u64, context: &[u8]) -> Result<Vec<u8>> {
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
                if !context.is_empty() {
                    mac.update(CONTEXT_BIND_TAG);
                    mac.update(context);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .map_err(|_| GenOtpError::InvalidSecret)?;
                mac.update(&counter_bytes);
                if !context.is_empty() {
                    mac.update(CONTEXT_BIND_TAG);
                    mac.update(context);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(&self.secret)
                    .map_err(|_| GenOtpError::InvalidSecret)?;
                mac.update(&counter_bytes);
                if !context.is_empty() {
                    mac.update(CONTEXT_BIND_TAG);
                    mac.update(context);
                }
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
    fn test_hotp_generation() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
        let code = hotp.generate(1).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_invalid_digits() {
        let secret = vec![0u8; 20];
        let result = HOTP::new(secret, Algorithm::SHA1, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc4226_vectors() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let expected = vec![
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, expected_code) in expected.iter().enumerate() {
            let code = hotp.generate(counter as u64).unwrap();
            assert_eq!(code, *expected_code, "Counter {}", counter);
        }
    }

    #[test]
    fn test_verify() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let code = hotp.generate(1).unwrap();
        assert!(hotp.verify(&code, 1).unwrap());
        assert!(!hotp.verify(&code, 2).unwrap());
    }

    #[test]
    fn test_large_counter() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let code = hotp.generate(1000000).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_different_algorithms() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];

        let hotp_sha256 = HOTP::new(secret.clone(), Algorithm::SHA256, 6).unwrap();
        let code_sha256 = hotp_sha256.generate(0).unwrap();
        assert_eq!(code_sha256.len(), 6);

        let hotp_sha512 = HOTP::new(secret, Algorithm::SHA512, 6).unwrap();
        let code_sha512 = hotp_sha512.generate(0).unwrap();
        assert_eq!(code_sha512.len(), 6);
    }

    #[test]
    fn test_zeroize_on_drop() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
        drop(hotp);
    }

    #[test]
    fn test_bound_empty_context_equals_standard_hotp() {
        use crate::context::OtpContext;
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
        let empty = OtpContext::empty();
        for c in 0u64..10 {
            assert_eq!(hotp.generate(c).unwrap(), hotp.generate_bound(c, &empty).unwrap());
        }
    }

    #[test]
    fn test_bound_verify_rejects_different_context() {
        use crate::context::OtpContext;
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
        let issued = OtpContext::builder().session("login-123").build();
        let attacker = OtpContext::builder().session("login-999").build();

        let code = hotp.generate_bound(42, &issued).unwrap();
        assert!(hotp.verify_bound(&code, 42, &issued).unwrap());
        assert!(!hotp.verify_bound(&code, 42, &attacker).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let json = serde_json::to_string(&hotp).unwrap();
        assert!(json.contains("SHA1"));
        assert!(json.contains("6"));
        assert!(!json.contains("secret"));
    }
}
