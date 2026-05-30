use crate::algorithm::Algorithm;
use crate::error::{GenOtpError, Result};
use crate::{HOTP, TOTP};

pub struct HotpBuilder {
    secret: Option<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
}

impl HotpBuilder {
    pub fn new() -> Self {
        HotpBuilder {
            secret: None,
            algorithm: Algorithm::default(),
            digits: 6,
        }
    }

    pub fn secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    pub fn build(self) -> Result<HOTP> {
        let secret = self.secret.ok_or(GenOtpError::InvalidSecret)?;
        HOTP::new(secret, self.algorithm, self.digits)
    }
}

impl Default for HotpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TotpBuilder {
    secret: Option<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl TotpBuilder {
    pub fn new() -> Self {
        TotpBuilder {
            secret: None,
            algorithm: Algorithm::default(),
            digits: 6,
            period: 30,
        }
    }

    pub fn secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    pub fn period(mut self, period: u64) -> Self {
        self.period = period;
        self
    }

    pub fn build(self) -> Result<TOTP> {
        let secret = self.secret.ok_or(GenOtpError::InvalidSecret)?;
        TOTP::new(secret, self.algorithm, self.digits, self.period)
    }
}

impl Default for TotpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp_builder() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let hotp = HotpBuilder::new()
            .secret(secret.clone())
            .algorithm(Algorithm::SHA1)
            .digits(6)
            .build()
            .unwrap();

        let code = hotp.generate(0).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_builder() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let totp = TotpBuilder::new()
            .secret(secret.clone())
            .algorithm(Algorithm::SHA1)
            .digits(6)
            .period(30)
            .build()
            .unwrap();

        let code = totp.generate(Some(1234567890)).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_builder_without_secret() {
        let result = HotpBuilder::new().build();
        assert!(result.is_err());
    }
}
