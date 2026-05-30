use crate::constant_time::constant_time_eq;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

const DEFAULT_MAX_USED_CODES: usize = 10_000;

// Data di balik mutex (HashSet kode + counter u32) tidak menyimpan invariant
// yang bisa rusak kalau thread lain panic — pulihkan langsung dari poison
// alih-alih panic ulang.
fn unpoison<'a, T>(
    result: Result<MutexGuard<'a, T>, PoisonError<MutexGuard<'a, T>>>,
) -> MutexGuard<'a, T> {
    result.unwrap_or_else(|e| e.into_inner())
}

pub struct Verifier {
    used_codes: Arc<Mutex<HashSet<String>>>,
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
        {
            let attempts = unpoison(self.attempts.lock());
            if *attempts >= self.max_attempts {
                return false;
            }
        }

        let mut used = unpoison(self.used_codes.lock());

        if used.contains(code) {
            return false;
        }

        if !constant_time_eq(code, expected) {
            let mut attempts = unpoison(self.attempts.lock());
            *attempts += 1;
            return false;
        }

        // Cegah memory leak: kalau kapasitas penuh, kosongkan set.
        // OTP yang lama tidak relevan lagi (window TOTP/HOTP sudah lewat).
        if used.len() >= self.max_used_codes {
            used.clear();
        }
        used.insert(code.to_string());

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
    fn test_rate_limit_blocks_further_attempts() {
        let verifier = Verifier::new(2);

        verifier.verify_with_replay_protection("wrong", "right");
        verifier.verify_with_replay_protection("wrong", "right");
        assert!(verifier.is_rate_limited());

        // Setelah rate-limited, verifikasi kode benar pun harus ditolak.
        assert!(!verifier.verify_with_replay_protection("right", "right"));
    }
}
