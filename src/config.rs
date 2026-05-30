use crate::algorithm::Algorithm;

#[derive(Debug, Clone, Copy)]
pub struct HotpConfig {
    pub algorithm: Algorithm,
    pub digits: u32,
}

impl Default for HotpConfig {
    fn default() -> Self {
        HotpConfig {
            algorithm: Algorithm::SHA1,
            digits: 6,
        }
    }
}

impl HotpConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TotpConfig {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        TotpConfig {
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
        }
    }
}

impl TotpConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    pub fn with_period(mut self, period: u64) -> Self {
        self.period = period;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp_config_default() {
        let config = HotpConfig::new();
        assert_eq!(config.digits, 6);
    }

    #[test]
    fn test_hotp_config_custom() {
        let config = HotpConfig::new()
            .with_digits(8)
            .with_algorithm(Algorithm::SHA256);
        assert_eq!(config.digits, 8);
    }

    #[test]
    fn test_totp_config_default() {
        let config = TotpConfig::new();
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn test_totp_config_custom() {
        let config = TotpConfig::new().with_digits(8).with_period(60);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 60);
    }
}
