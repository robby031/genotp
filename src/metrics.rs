use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    hotp_generations: AtomicU64,
    hotp_verifications: AtomicU64,
    totp_generations: AtomicU64,
    totp_verifications: AtomicU64,
    errors: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            hotp_generations: AtomicU64::new(0),
            hotp_verifications: AtomicU64::new(0),
            totp_generations: AtomicU64::new(0),
            totp_verifications: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn increment_hotp_generation(&self) {
        self.hotp_generations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_hotp_verification(&self) {
        self.hotp_verifications.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_totp_generation(&self) {
        self.totp_generations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_totp_verification(&self) {
        self.totp_verifications.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_hotp_generations(&self) -> u64 {
        self.hotp_generations.load(Ordering::Relaxed)
    }

    pub fn get_hotp_verifications(&self) -> u64 {
        self.hotp_verifications.load(Ordering::Relaxed)
    }

    pub fn get_totp_generations(&self) -> u64 {
        self.totp_generations.load(Ordering::Relaxed)
    }

    pub fn get_totp_verifications(&self) -> u64 {
        self.totp_verifications.load(Ordering::Relaxed)
    }

    pub fn get_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.hotp_generations.store(0, Ordering::Relaxed);
        self.hotp_verifications.store(0, Ordering::Relaxed);
        self.totp_generations.store(0, Ordering::Relaxed);
        self.totp_verifications.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let metrics = Metrics::new();

        metrics.increment_hotp_generation();
        metrics.increment_hotp_generation();
        metrics.increment_totp_generation();
        metrics.increment_error();

        assert_eq!(metrics.get_hotp_generations(), 2);
        assert_eq!(metrics.get_totp_generations(), 1);
        assert_eq!(metrics.get_errors(), 1);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = Metrics::new();

        metrics.increment_hotp_generation();
        metrics.increment_totp_generation();
        metrics.reset();

        assert_eq!(metrics.get_hotp_generations(), 0);
        assert_eq!(metrics.get_totp_generations(), 0);
    }
}
