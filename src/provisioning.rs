use crate::algorithm::Algorithm;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::fmt;

// Encode everything except unreserved characters per RFC 3986.
// Google Authenticator's otpauth URI spec requires label and parameter
// values to be percent-encoded.
const OTPAUTH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn encode(s: &str) -> String {
    utf8_percent_encode(s, OTPAUTH_ENCODE_SET).to_string()
}

pub struct OtpAuthUri {
    typ: OtpType,
    label: String,
    secret: String,
    issuer: Option<String>,
    algorithm: Option<Algorithm>,
    digits: Option<u32>,
    period: Option<u64>,
    counter: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum OtpType {
    HOTP,
    TOTP,
}

impl OtpAuthUri {
    pub fn new(typ: OtpType, label: String, secret: String) -> Self {
        OtpAuthUri {
            typ,
            label,
            secret,
            issuer: None,
            algorithm: None,
            digits: None,
            period: None,
            counter: None,
        }
    }

    pub fn issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = Some(digits);
        self
    }

    pub fn period(mut self, period: u64) -> Self {
        self.period = Some(period);
        self
    }

    pub fn counter(mut self, counter: u64) -> Self {
        self.counter = Some(counter);
        self
    }

    pub fn build(&self) -> String {
        let mut uri = String::new();

        let type_str = match self.typ {
            OtpType::HOTP => "hotp",
            OtpType::TOTP => "totp",
        };

        uri.push_str("otpauth://");
        uri.push_str(type_str);
        uri.push('/');
        uri.push_str(&encode(&self.label));
        uri.push_str("?secret=");
        uri.push_str(&encode(&self.secret));

        if let Some(ref issuer) = self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&encode(issuer));
        }

        if let Some(algo) = self.algorithm {
            uri.push_str("&algorithm=");
            uri.push_str(algo.as_str());
        }

        if let Some(digits) = self.digits {
            uri.push_str("&digits=");
            uri.push_str(&digits.to_string());
        }

        if let Some(period) = self.period {
            uri.push_str("&period=");
            uri.push_str(&period.to_string());
        }

        if let Some(counter) = self.counter {
            uri.push_str("&counter=");
            uri.push_str(&counter.to_string());
        }

        uri
    }
}

impl fmt::Display for OtpAuthUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_uri_basic() {
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "Example:alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        );

        let result = uri.build();
        assert!(result.contains("otpauth://totp/"));
        assert!(result.contains("secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_hotp_uri_with_counter() {
        let uri = OtpAuthUri::new(
            OtpType::HOTP,
            "Example:alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .counter(0);

        let result = uri.build();
        assert!(result.contains("otpauth://hotp/"));
        assert!(result.contains("counter=0"));
    }

    #[test]
    fn test_uri_with_all_params() {
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "Service:user@service.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("Service".to_string())
        .algorithm(Algorithm::SHA1)
        .digits(6)
        .period(30);

        let result = uri.build();
        assert!(result.contains("issuer=Service"));
        assert!(result.contains("algorithm=SHA1"));
        assert!(result.contains("digits=6"));
        assert!(result.contains("period=30"));
    }

    #[test]
    fn test_google_authenticator_totp_compatibility() {
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "ACME:alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("ACME".to_string())
        .algorithm(Algorithm::SHA1)
        .digits(6)
        .period(30);

        let result = uri.build();

        assert!(result.starts_with("otpauth://totp/"));
        // Label-nya ":" dan "@" sudah di-encode (sesuai RFC 3986 dan otpauth spec).
        assert!(result.contains("ACME%3Aalice%40example.com"));
        assert!(result.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(result.contains("issuer=ACME"));
        assert!(result.contains("algorithm=SHA1"));
        assert!(result.contains("digits=6"));
        assert!(result.contains("period=30"));

        let params: Vec<&str> = result.split('&').collect();
        assert!(params.len() >= 4);
    }

    #[test]
    fn test_google_authenticator_hotp_compatibility() {
        let uri = OtpAuthUri::new(
            OtpType::HOTP,
            "ACME:alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("ACME".to_string())
        .algorithm(Algorithm::SHA1)
        .digits(6)
        .counter(0);

        let result = uri.build();

        assert!(result.starts_with("otpauth://hotp/"));
        assert!(result.contains("ACME%3Aalice%40example.com"));
        assert!(result.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(result.contains("issuer=ACME"));
        assert!(result.contains("algorithm=SHA1"));
        assert!(result.contains("digits=6"));
        assert!(result.contains("counter=0"));
    }

    #[test]
    fn test_google_authenticator_sha256_compatibility() {
        // Test URI dengan SHA256 yang kompatibel dengan Google Authenticator
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "Service:user@service.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("Service".to_string())
        .algorithm(Algorithm::SHA256)
        .digits(6)
        .period(30);

        let result = uri.build();
        assert!(result.contains("algorithm=SHA256"));
    }

    #[test]
    fn test_google_authenticator_sha512_compatibility() {
        // Test URI dengan SHA512 yang kompatibel dengan Google Authenticator
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "Service:user@service.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("Service".to_string())
        .algorithm(Algorithm::SHA512)
        .digits(8)
        .period(30);

        let result = uri.build();
        assert!(result.contains("algorithm=SHA512"));
        assert!(result.contains("digits=8"));
    }

    #[test]
    fn test_uri_escaping() {
        // Karakter khusus pada label harus di-percent-encode:
        // ':' -> %3A, '+' -> %2B, '@' -> %40
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "Service:user+test@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        );

        let result = uri.build();
        assert!(result.contains("Service%3Auser%2Btest%40example.com"));
        assert!(!result.contains("user+test@example.com"));
    }

    #[test]
    fn test_uri_encoding_spaces_and_ampersand() {
        // Spasi dan & pada issuer/label akan merusak URI kalau tidak di-encode.
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "My Co:alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        )
        .issuer("My Co & Partners".to_string());

        let result = uri.build();
        assert!(result.contains("My%20Co%3Aalice%40example.com"));
        assert!(result.contains("issuer=My%20Co%20%26%20Partners"));
    }

    #[test]
    fn test_uri_without_issuer() {
        let uri = OtpAuthUri::new(
            OtpType::TOTP,
            "alice@example.com".to_string(),
            "JBSWY3DPEHPK3PXP".to_string(),
        );

        let result = uri.build();
        assert!(result.contains("otpauth://totp/"));
        assert!(result.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(!result.contains("issuer="));
    }
}
