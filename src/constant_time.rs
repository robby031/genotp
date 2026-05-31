//! Constant-time comparison helpers.
//!
//! **Penting:** `subtle::ConstantTimeEq` untuk `[u8]` melakukan early return
//! kalau panjang dua slice berbeda — terdokumentasi di crate-nya. Akibatnya
//! attacker yang bisa mengontrol panjang input bisa men-deteksi panjang
//! referensi lewat timing.
//!
//! Modul ini menyediakan implementasi yang **tidak** short-circuit:
//! kedua slice di-loop sampai `max(len_a, len_b)` byte, dengan length
//! difference juga di-OR ke akumulator diff. Total runtime hanya bergantung
//! pada `max(len_a, len_b)`, tidak pada lokasi byte yang berbeda atau
//! pada perbedaan panjang itu sendiri (selama max-nya sama).
//!
//! Untuk genotp:
//! - **OTP code (6/7/8 digit)**: panjang sudah publik (di otpauth URI),
//!   leak panjang bukan masalah. Tapi defense-in-depth tetap berguna.
//! - **Context bytes**: panjang **tidak** boleh bocor karena bisa
//!   mengandung session ID, device hash, dll. Modul ini menutup gap itu.

/// Constant-time string comparison. Tidak short-circuit pada panjang berbeda.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte-slice comparison. Loop selalu jalan `max(a.len(),
/// b.len())` iterasi, dengan length difference juga di-OR ke diff supaya
/// dua slice dengan panjang berbeda selalu menghasilkan `false`.
///
/// Timing leak yang TERSISA: total runtime proportional ke
/// `max(a.len(), b.len())`. Untuk input dengan panjang bounded (OTP code
/// max 8 byte; context max biasanya < 256 byte), variansnya tidak
/// memberikan leak yang exploitable di praktik.
#[inline]
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    let len_a = a.len();
    let len_b = b.len();
    let max_len = len_a.max(len_b);

    // Mulai akumulator dengan length-difference. Kalau panjang berbeda,
    // diff sudah non-zero sebelum loop bahkan dimulai.
    let mut diff: u32 = (len_a as u32) ^ (len_b as u32);

    // Loop manual tanpa branch: ambil byte ke-i kalau ada, kalau tidak 0.
    // `get()` mengembalikan `Option<&u8>` yang tidak di-short-circuit
    // (cuma bounds check); jangan pakai indexing langsung karena bisa panic.
    for i in 0..max_len {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        diff |= (av ^ bv) as u32;
    }

    // Konversi diff != 0 jadi bool dengan cara constant-time:
    // kalau diff = 0, hasil = true; sebaliknya false. Tidak ada branch.
    let nonzero = (diff | diff.wrapping_neg()) >> 31;
    nonzero == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq("hello", "hello"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq("hello", "world"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq("hello", "helloworld"));
        assert!(!constant_time_eq("helloworld", "hello"));
        assert!(!constant_time_eq("", "x"));
        assert!(!constant_time_eq("x", ""));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_bytes_equal() {
        assert!(constant_time_eq_bytes(b"abc", b"abc"));
        assert!(constant_time_eq_bytes(b"", b""));
        assert!(constant_time_eq_bytes(&[0xFFu8; 256], &[0xFFu8; 256]));
    }

    #[test]
    fn test_bytes_not_equal_same_length() {
        assert!(!constant_time_eq_bytes(b"abc", b"abd"));
        assert!(!constant_time_eq_bytes(b"abc", b"zbc"));
        // Byte berbeda di posisi terakhir vs pertama harus sama-sama false
        // dan (idealnya) sama-sama lama.
    }

    #[test]
    fn test_bytes_not_equal_different_length() {
        assert!(!constant_time_eq_bytes(b"abc", b"abcd"));
        assert!(!constant_time_eq_bytes(b"abcd", b"abc"));
        assert!(!constant_time_eq_bytes(&[], b"abc"));
        assert!(!constant_time_eq_bytes(b"abc", &[]));
    }

    #[test]
    fn test_bytes_long_input() {
        // Pastikan tidak ada overflow/panic untuk input panjang.
        let a = vec![0x42u8; 10_000];
        let b = vec![0x42u8; 10_000];
        assert!(constant_time_eq_bytes(&a, &b));

        let mut c = a.clone();
        c[5_000] = 0x43;
        assert!(!constant_time_eq_bytes(&a, &c));
    }

    #[test]
    fn test_bytes_one_empty() {
        // Edge case: salah satu sisi kosong.
        assert!(!constant_time_eq_bytes(&[], b"\x00"));
        assert!(!constant_time_eq_bytes(b"\x00", &[]));
        // Empty vs empty: equal.
        assert!(constant_time_eq_bytes(&[], &[]));
    }
}
