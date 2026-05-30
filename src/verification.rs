use crate::constant_time::constant_time_eq;
use crate::context::OtpContext;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use subtle::ConstantTimeEq;

const DEFAULT_MAX_USED_CODES: usize = 10_000;

// Data di balik mutex (HashSet kode + counter u32) tidak menyimpan invariant
// yang bisa rusak kalau thread lain panic — pulihkan langsung dari poison
// alih-alih panic ulang.
fn unpoison<'a, T>(
    result: Result<MutexGuard<'a, T>, PoisonError<MutexGuard<'a, T>>>,
) -> MutexGuard<'a, T> {
    result.unwrap_or_else(|e| e.into_inner())
}

/// Bangun key replay set: gabungan code dan context bytes dengan separator
/// null sehingga (code, ctx) berbeda menghasilkan key berbeda. Memungkinkan
/// kode yang sama dipakai oleh user/session berbeda tanpa saling memblokir.
fn replay_key(code: &str, context: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(code.len() + 1 + context.len());
    k.extend_from_slice(code.as_bytes());
    k.push(0);
    k.extend_from_slice(context);
    k
}

pub struct Verifier {
    used_codes: Arc<Mutex<HashSet<Vec<u8>>>>,
    max_used_codes: usize,
    max_attempts: u32,
    attempts: Arc<Mutex<u32>>,
}

impl Verifier {
    pub fn new(max_attempts: u32) -> Self {
        Self::with_capacity(max_attempts, DEFAULT_MAX_USED_CODES)
    }

    pub fn with_capacity(max_attempts: u32, max_used_codes: usize) -> Self {
        Verifier {
            used_codes: Arc::new(Mutex::new(HashSet::new())),
            max_used_codes,
            max_attempts,
            attempts: Arc::new(Mutex::new(0)),
        }
    }

    pub fn verify_with_replay_protection(&self, code: &str, expected: &str) -> bool {
        self.verify_inner(code, expected, &[], &[])
    }

    /// Verifikasi dengan context binding (Mode 2).
    ///
    /// Cara pakai:
    ///
    /// - **Mode 1 (HMAC binding):** caller sudah komputasi `expected` lewat
    ///   [`crate::TOTP::generate_bound`] / [`crate::HOTP::generate_bound`]
    ///   menggunakan context. Pass context yang sama untuk `issued_context`
    ///   dan `request_context`. Replay protection akan terisolasi per
    ///   context.
    ///
    /// - **Mode 2 (Verifier-stored):** caller pakai TOTP standar (kompatibel
    ///   Google Authenticator). Server menyimpan context apa yang aktif
    ///   ketika OTP di-issue, dan men-passingnya sebagai `issued_context`.
    ///   `request_context` adalah context dari request saat ini. Library
    ///   melakukan **constant-time comparison** sebelum memverifikasi kode.
    ///
    /// Constant-time comparison memastikan attacker tidak dapat me-leak
    /// informasi context lewat timing side-channel.
    pub fn verify_with_context(
        &self,
        code: &str,
        expected: &str,
        issued_context: &OtpContext,
        request_context: &OtpContext,
    ) -> bool {
        self.verify_inner(
            code,
            expected,
            issued_context.as_bytes(),
            request_context.as_bytes(),
        )
    }

    fn verify_inner(
        &self,
        code: &str,
        expected: &str,
        issued_context: &[u8],
        request_context: &[u8],
    ) -> bool {
        // 1) Rate limit.
        {
            let attempts = unpoison(self.attempts.lock());
            if *attempts >= self.max_attempts {
                return false;
            }
        }

        // 2) Replay check pakai issued_context — supaya kode yang sama bisa
        //    dipakai paralel oleh user/session berbeda tanpa saling blokir.
        let key = replay_key(code, issued_context);
        let mut used = unpoison(self.used_codes.lock());
        if used.contains(&key) {
            return false;
        }

        // 3) Context match (constant-time) dan code match (constant-time).
        //    Dua-duanya dievaluasi sebelum branch supaya tidak ada timing
        //    side-channel yang ngeleak "context salah" vs "code salah".
        let ctx_match: bool = issued_context.ct_eq(request_context).into();
        let code_match = constant_time_eq(code, expected);

        if !(ctx_match && code_match) {
            let mut attempts = unpoison(self.attempts.lock());
            *attempts += 1;
            return false;
        }

        // 4) Mark used. Cegah memory leak dengan batasi kapasitas.
        if used.len() >= self.max_used_codes {
            used.clear();
        }
        used.insert(key);

        let mut attempts = unpoison(self.attempts.lock());
        *attempts = 0;
        true
    }

    pub fn is_rate_limited(&self) -> bool {
        let attempts = unpoison(self.attempts.lock());
        *attempts >= self.max_attempts
    }

    pub fn reset_attempts(&self) {
        let mut attempts = unpoison(self.attempts.lock());
        *attempts = 0;
    }

    pub fn clear_used_codes(&self) {
        let mut used = unpoison(self.used_codes.lock());
        used.clear();
    }
}

impl Clone for Verifier {
    fn clone(&self) -> Self {
        Verifier {
            used_codes: Arc::clone(&self.used_codes),
            max_used_codes: self.max_used_codes,
            max_attempts: self.max_attempts,
            attempts: Arc::clone(&self.attempts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_protection() {
        let verifier = Verifier::new(5);

        assert!(verifier.verify_with_replay_protection("123456", "123456"));
        assert!(!verifier.verify_with_replay_protection("123456", "123456"));
    }

    #[test]
    fn test_rate_limiting() {
        let verifier = Verifier::new(3);

        assert!(!verifier.is_rate_limited());
        verifier.verify_with_replay_protection("wrong", "123456");
        verifier.verify_with_replay_protection("wrong", "123456");
        verifier.verify_with_replay_protection("wrong", "123456");
        assert!(verifier.is_rate_limited());
    }

    #[test]
    fn test_reset_attempts() {
        let verifier = Verifier::new(3);

        verifier.verify_with_replay_protection("wrong", "123456");
        verifier.verify_with_replay_protection("wrong", "123456");
        verifier.reset_attempts();
        assert!(!verifier.is_rate_limited());
    }

    #[test]
    fn test_clear_used_codes() {
        let verifier = Verifier::new(5);

        verifier.verify_with_replay_protection("123456", "123456");
        verifier.clear_used_codes();
        assert!(verifier.verify_with_replay_protection("123456", "123456"));
    }

    #[test]
    fn test_used_codes_bounded() {
        // Kapasitas 3: kalau penuh, set dikosongkan otomatis sebelum entry ke-4.
        let verifier = Verifier::with_capacity(100, 3);

        assert!(verifier.verify_with_replay_protection("aaa", "aaa"));
        assert!(verifier.verify_with_replay_protection("bbb", "bbb"));
        assert!(verifier.verify_with_replay_protection("ccc", "ccc"));
        // Sebelum insert ke-4, set di-clear, jadi "aaa" boleh masuk lagi nanti.
        assert!(verifier.verify_with_replay_protection("ddd", "ddd"));

        let used = verifier.used_codes.lock().unwrap();
        assert!(used.len() <= 3);
    }

    #[test]
    fn test_verify_with_context_accepts_matching_context() {
        let verifier = Verifier::new(5);
        let ctx = OtpContext::builder().session("s1").ip("10.0.0.1").build();

        assert!(verifier.verify_with_context("123456", "123456", &ctx, &ctx));
        // Replay dengan context sama harus ditolak.
        assert!(!verifier.verify_with_context("123456", "123456", &ctx, &ctx));
    }

    #[test]
    fn test_verify_with_context_rejects_mismatched_context() {
        let verifier = Verifier::new(5);
        let issued = OtpContext::builder().ip("10.0.0.1").build();
        let attacker = OtpContext::builder().ip("203.0.113.5").build();

        // Walaupun kode dan expected benar, context berbeda → tolak.
        assert!(!verifier.verify_with_context("123456", "123456", &issued, &attacker));
        // Dan attempt counter naik.
        assert!(!verifier.verify_with_context("xxx", "yyy", &issued, &issued));
    }

    #[test]
    fn test_per_context_replay_isolation() {
        // Dua session berbeda menerima kode yang sama (mode 2: TOTP standar).
        // Replay-set harus per-context, jadi keduanya boleh sukses sekali.
        let verifier = Verifier::new(10);
        let ctx_user_a = OtpContext::builder().session("sess-A").build();
        let ctx_user_b = OtpContext::builder().session("sess-B").build();

        assert!(verifier.verify_with_context("987654", "987654", &ctx_user_a, &ctx_user_a));
        // User B pakai kode yang KEBETULAN sama — tetap diterima karena
        // context berbeda → replay key berbeda.
        assert!(verifier.verify_with_context("987654", "987654", &ctx_user_b, &ctx_user_b));
        // Tapi user A me-replay → ditolak.
        assert!(!verifier.verify_with_context("987654", "987654", &ctx_user_a, &ctx_user_a));
        // Dan user B me-replay → ditolak juga.
        assert!(!verifier.verify_with_context("987654", "987654", &ctx_user_b, &ctx_user_b));
    }

    #[test]
    fn test_empty_context_equivalent_to_non_context_verify() {
        // verify_with_context dengan empty context harus berperilaku setara
        // dengan verify_with_replay_protection (Mode 2 disabled).
        let v1 = Verifier::new(5);
        assert!(v1.verify_with_replay_protection("111111", "111111"));
        assert!(!v1.verify_with_replay_protection("111111", "111111"));

        let v2 = Verifier::new(5);
        let empty = OtpContext::empty();
        assert!(v2.verify_with_context("111111", "111111", &empty, &empty));
        assert!(!v2.verify_with_context("111111", "111111", &empty, &empty));
    }

    #[test]
    fn test_context_check_blocks_even_brute_force() {
        // Skenario channel OTP: attacker dapat kode dari intercept channel
        // delivery (SMS/email/WhatsApp/Telegram/dll) tapi dari IP berbeda.
        // Library harus menolak walaupun kode benar.
        let verifier = Verifier::new(10_000);
        let user_ctx = OtpContext::builder()
            .ip("10.0.0.1")
            .session("login-real")
            .build();
        let attacker_ctx = OtpContext::builder()
            .ip("203.0.113.9")
            .session("login-real")
            .build();

        let intercepted_code = "4829";
        // Attacker mencoba 10.000 kombinasi dari IP-nya — semua harus gagal.
        for guess in 0..10_000u32 {
            let attempt = format!("{guess:04}");
            assert!(
                !verifier.verify_with_context(&attempt, intercepted_code, &user_ctx, &attacker_ctx),
                "Brute force code {attempt} dari context attacker harus selalu gagal"
            );
        }
        // Dan rate-limit kena.
        assert!(verifier.is_rate_limited());
    }

    #[test]
    fn test_rate_limit_blocks_further_attempts() {
        let verifier = Verifier::new(2);

        verifier.verify_with_replay_protection("wrong", "right");
        verifier.verify_with_replay_protection("wrong", "right");
        assert!(verifier.is_rate_limited());

        // Setelah rate-limited, verifikasi kode benar pun harus ditolak.
        assert!(!verifier.verify_with_replay_protection("right", "right"));
    }
}
