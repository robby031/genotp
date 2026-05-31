#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum GenOtpError {
    InvalidSecret,
    InvalidCode,
    InvalidDigits,
    InvalidAlgorithm,
    InvalidCounter,
    InvalidTime,
    VerificationFailed,
    RateLimited,
    ReplayAttack,
}

impl fmt::Display for GenOtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenOtpError::InvalidSecret => write!(f, "Invalid secret key"),
            GenOtpError::InvalidCode => write!(f, "Invalid OTP code"),
            GenOtpError::InvalidDigits => write!(f, "Invalid number of digits"),
            GenOtpError::InvalidAlgorithm => write!(f, "Invalid algorithm"),
            GenOtpError::InvalidCounter => write!(f, "Invalid counter value"),
            GenOtpError::InvalidTime => write!(f, "Invalid time value"),
            GenOtpError::VerificationFailed => write!(f, "OTP verification failed"),
            GenOtpError::RateLimited => write!(f, "Rate limited"),
            GenOtpError::ReplayAttack => write!(f, "Replay attack detected"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenOtpError {}

pub type Result<T> = core::result::Result<T, GenOtpError>;
