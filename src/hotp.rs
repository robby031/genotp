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

    /// Verifikasi HOTP dengan **look-ahead resynchronization** (RFC 4226 §7.4).
    ///
    /// Mencoba `counter`, `counter+1`, ..., `counter+look_ahead`. Kalau
    /// match, kembalikan `Ok(Some(matched_counter))` — caller **wajib**
    /// update counter yang disimpan ke `matched_counter + 1` agar kode
    /// tersebut tidak bisa di-replay.
    ///
    /// **Use case nyata:** user tidak sengaja menekan tombol generate di
    /// hardware token / authenticator app beberapa kali tanpa men-submit.
    /// Counter user maju (mis. ke 13), server masih di 10. Tanpa look-ahead,
    /// semua kode user akan ditolak sampai counter di-reset manual.
    /// Nilai `look_ahead` yang umum: 3-10. RFC 4226 merekomendasikan
    /// nilai kecil untuk menghindari menambah serangan brute-force.
    ///
    /// **Update counter wajib:** kalau caller TIDAK update counter
    /// tersimpan setelah match, attacker yang mengintercept satu kode
    /// bisa men-replay-nya berkali-kali dalam window look-ahead.
    ///
    /// **⚠️ Timing leak by design:** method ini early-return saat match
    /// dan total runtime memberi sinyal offset mana yang match. Itu memang
    /// data yang dibutuhkan caller (untuk update counter). Kalau Anda
    /// tidak butuh resync, pakai [`Self::verify`] yang strict exact-match.
    ///
    /// # Example
    ///
    /// ```
    /// use genotp::{Algorithm, HOTP};
    /// # let secret = vec![0u8; 20];
    /// let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
    /// let stored_counter: u64 = 10;
    /// let user_submitted = hotp.generate(13).unwrap(); // user 3 langkah di depan
    ///
    /// match hotp.verify_with_resync(&user_submitted, stored_counter, 5).unwrap() {
    ///     Some(matched) => {
    ///         // WAJIB: update counter tersimpan ke matched + 1.
    ///         let new_stored = matched + 1; // = 14
    ///         println!("Login OK, update counter ke {new_stored}");
    ///     }
    ///     None => {
    ///         println!("Kode invalid (di luar window look-ahead).");
    ///     }
    /// }
    /// ```
    pub fn verify_with_resync(
        &self,
        code: &str,
        counter: u64,
        look_ahead: u64,
    ) -> Result<Option<u64>> {
        for i in 0..=look_ahead {
            let test_counter = match counter.checked_add(i) {
                Some(c) => c,
                None => break,
            };
            let expected = self.generate(test_counter)?;
            if constant_time_eq(code, &expected) {
                return Ok(Some(test_counter));
            }
        }
        Ok(None)
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
            assert_eq!(
                hotp.generate(c).unwrap(),
                hotp.generate_bound(c, &empty).unwrap()
            );
        }
    }

    #[test]
    fn test_verify_with_resync_matches_in_lookahead_window() {
        // Skenario nyata: user tekan tombol generate 3x tanpa submit.
        // Counter user = 13, counter server = 10. Tanpa resync ditolak.
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let stored = 10u64;
        let user_code = hotp.generate(13).unwrap(); // user 3 langkah di depan

        // verify strict harus gagal.
        assert!(!hotp.verify(&user_code, stored).unwrap());

        // verify_with_resync(look_ahead=5) harus berhasil dan kembalikan 13.
        let result = hotp.verify_with_resync(&user_code, stored, 5).unwrap();
        assert_eq!(result, Some(13));

        // Look-ahead window terlalu kecil → tetap gagal.
        let result_short = hotp.verify_with_resync(&user_code, stored, 2).unwrap();
        assert_eq!(result_short, None);
    }

    #[test]
    fn test_verify_with_resync_match_at_current_counter() {
        // Kalau kode user persis di counter server, harus return Some(counter).
        let secret = vec![0x11u8; 20];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let code = hotp.generate(42).unwrap();
        assert_eq!(hotp.verify_with_resync(&code, 42, 5).unwrap(), Some(42));
    }

    #[test]
    fn test_verify_with_resync_returns_none_for_invalid_code() {
        let secret = vec![0x22u8; 20];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        assert_eq!(
            hotp.verify_with_resync("000000", 100, 10).unwrap(),
            None
        );
    }

    #[test]
    fn test_verify_with_resync_handles_counter_overflow() {
        // Edge case: counter mendekati u64::MAX, look_ahead bisa overflow.
        // Harus exit loop dengan aman tanpa panic, dan tetap match kalau code valid.
        let secret = vec![0x33u8; 20];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let near_max = u64::MAX - 2;
        let code = hotp.generate(near_max).unwrap();

        // look_ahead=100 jauh melebihi sisa range; harus tetap nemu match
        // di iterasi pertama tanpa overflow saat coba counter berikutnya.
        let result = hotp.verify_with_resync(&code, near_max, 100).unwrap();
        assert_eq!(result, Some(near_max));
    }

    #[test]
    fn test_verify_with_resync_caller_must_update_counter() {
        // Dokumentasi behavior: kalau caller tidak update stored counter
        // setelah match, kode yang sama BISA di-replay di window berikutnya.
        // Ini test bukan untuk validasi keamanan tapi untuk demonstrasi
        // pentingnya kontrak update counter.
        let secret = vec![0x44u8; 20];
        let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

        let mut stored = 10u64;
        let code = hotp.generate(12).unwrap();

        // Login pertama match di 12.
        let r1 = hotp.verify_with_resync(&code, stored, 5).unwrap();
        assert_eq!(r1, Some(12));

        // Caller LUPA update stored counter. Replay kode yang sama →
        // tetap diterima (BAD, makanya update wajib).
        let r2 = hotp.verify_with_resync(&code, stored, 5).unwrap();
        assert_eq!(r2, Some(12), "tanpa update counter, replay LOLOS — itulah kenapa update wajib");

        // Setelah update counter dengan benar:
        stored = 12 + 1; // = 13
        // Replay kode lama (di counter 12) di window [13..=18] → tidak match.
        let r3 = hotp.verify_with_resync(&code, stored, 5).unwrap();
        assert_eq!(r3, None, "setelah counter di-update, replay ditolak");
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
