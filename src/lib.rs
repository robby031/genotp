#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod algorithm;
pub mod base32;
pub mod constant_time;
pub mod error;
pub mod hotp;
pub mod key;
pub mod totp;

#[cfg(feature = "std")]
pub mod provisioning;

#[cfg(feature = "std")]
pub mod verification;

#[cfg(feature = "std")]
pub mod builder;

#[cfg(feature = "std")]
pub mod helpers;

#[cfg(feature = "std")]
pub mod config;

#[cfg(feature = "std")]
pub mod metrics;

pub use algorithm::Algorithm;
pub use base32::{decode, encode};
pub use constant_time::constant_time_eq;
pub use error::{GenOtpError, Result};
pub use hotp::HOTP;
pub use key::KeyGenerator;
pub use totp::TOTP;

#[cfg(feature = "std")]
pub use provisioning::{OtpAuthUri, OtpType};

#[cfg(feature = "std")]
pub use verification::Verifier;

#[cfg(feature = "std")]
pub use builder::{HotpBuilder, TotpBuilder};

#[cfg(feature = "std")]
pub use helpers::{
    create_secret, generate_hotp_default, generate_totp_default, verify_hotp_default,
    verify_totp_default,
};

#[cfg(feature = "std")]
pub use config::{HotpConfig, TotpConfig};

#[cfg(feature = "std")]
pub use metrics::Metrics;
