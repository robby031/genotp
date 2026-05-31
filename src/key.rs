use crate::error::{GenOtpError, Result};
use getrandom::fill;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Panjang minimum secret OTP dalam byte (128-bit / 16 byte sesuai
/// rekomendasi RFC 4226 §4 R6).
pub const MIN_SECRET_BYTES: usize = 16;

/// Panjang default secret dalam byte (160-bit / 20 byte — rekomendasi
/// RFC 4226 §4 R6 untuk HMAC-SHA1).
pub const DEFAULT_SECRET_BYTES: usize = 20;

pub struct KeyGenerator;

impl KeyGenerator {
    /// **Stack-friendly secret generation** — isi buffer milik caller
    /// dengan random bytes dari OS CSPRNG. Tidak butuh heap allocation
    /// dan tidak butuh feature `alloc`.
    ///
    /// Cocok untuk **embedded / no_std** di mana setiap heap alloc adalah
    /// pemborosan dan menyebabkan fragmentasi:
    ///
    /// ```
    /// use genotp::KeyGenerator;
    ///
    /// // Stack-allocated buffer 20 byte (160-bit, rekomendasi RFC).
    /// let mut secret = [0u8; 20];
    /// KeyGenerator::fill_secret(&mut secret).unwrap();
    /// // ... pakai `secret` ...
    /// // Saat keluar scope, memory di stack reclaimed. Untuk zeroize
    /// // eksplisit, caller bisa pakai `zeroize` crate:
    /// //   use zeroize::Zeroize; secret.zeroize();
    /// ```
    ///
    /// Validasi panjang minimum [`MIN_SECRET_BYTES`] (16 byte = 128 bit).
    pub fn fill_secret(buf: &mut [u8]) -> Result<()> {
        if buf.len() < MIN_SECRET_BYTES {
            return Err(GenOtpError::InvalidSecret);
        }
        fill(buf).map_err(|_| GenOtpError::InvalidSecret)
    }

    /// **Heap allocation version** untuk std / hosted environment.
    ///
    /// ⚠️ **Kebersihan memory:** `Vec<u8>` yang di-return **tidak** otomatis
    /// di-zeroize saat drop. Dua skenario:
    ///
    /// - **Aman**: kalau Anda langsung pindahkan ke `HOTP::new` /
    ///   `TOTP::new` (ownership berpindah, struct itu Zeroize on drop).
    /// - **Bocor**: kalau Anda menyimpan Vec ini sebagai variable lokal
    ///   yang ke-drop normal tanpa di-pass ke HOTP/TOTP, sisa secret
    ///   bertahan di RAM sampai allocator menimpa memori tersebut.
    ///
    /// Untuk kasus kedua, bungkus dengan `zeroize::Zeroizing`:
    /// ```ignore
    /// use zeroize::Zeroizing;
    /// let secret = Zeroizing::new(KeyGenerator::generate_secret(160)?);
    /// // Pakai `&*secret` untuk akses. Auto-zeroize saat drop.
    /// ```
    ///
    /// Untuk embedded / no_std tanpa heap, pakai
    /// [`KeyGenerator::fill_secret`] dengan stack buffer.
    #[cfg(feature = "alloc")]
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

    /// Generate secret 160-bit (rekomendasi RFC 4226 §4 R6 untuk HMAC-SHA1).
    /// Lihat warning di [`Self::generate_secret`] tentang kebersihan memory.
    #[cfg(feature = "alloc")]
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

    // ====================================================================
    // fill_secret — stack-friendly API tanpa heap allocation
    // ====================================================================

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_fill_secret_default_size() {
        // Buffer di stack — tidak ada heap alloc.
        let mut buf = [0u8; DEFAULT_SECRET_BYTES];
        KeyGenerator::fill_secret(&mut buf).unwrap();
        // Sangat tidak mungkin semua-nol setelah random fill.
        assert_ne!(buf, [0u8; DEFAULT_SECRET_BYTES]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_fill_secret_custom_size() {
        // SHA-256 secret size (32 byte / 256 bit).
        let mut buf = [0u8; 32];
        KeyGenerator::fill_secret(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_fill_secret_rejects_undersized_buffer() {
        // Kurang dari MIN_SECRET_BYTES (16 byte) → tolak.
        let mut buf = [0u8; 8];
        assert!(KeyGenerator::fill_secret(&mut buf).is_err());

        // Buffer panjang 0 → tolak.
        let mut empty: [u8; 0] = [];
        assert!(KeyGenerator::fill_secret(&mut empty).is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_fill_secret_accepts_exactly_minimum() {
        // 16 byte = 128 bit, persis minimum yang diizinkan.
        let mut buf = [0u8; MIN_SECRET_BYTES];
        KeyGenerator::fill_secret(&mut buf).unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_fill_secret_produces_different_values_per_call() {
        // Konfirmasi CSPRNG bukan deterministic.
        let mut buf1 = [0u8; 20];
        let mut buf2 = [0u8; 20];
        KeyGenerator::fill_secret(&mut buf1).unwrap();
        KeyGenerator::fill_secret(&mut buf2).unwrap();
        assert_ne!(buf1, buf2, "dua call random harus produce hasil berbeda");
    }
}
