use crate::{Algorithm, HOTP, KeyGenerator, Result, TOTP};

pub fn generate_hotp_default(secret: Vec<u8>, counter: u64) -> Result<String> {
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6)?;
    hotp.generate(counter)
}

pub fn generate_totp_default(secret: Vec<u8>) -> Result<String> {
    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30)?;
    totp.generate(None)
}

pub fn verify_hotp_default(secret: Vec<u8>, code: &str, counter: u64) -> Result<bool> {
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6)?;
    hotp.verify(code, counter)
}

pub fn verify_totp_default(secret: Vec<u8>, code: &str) -> Result<bool> {
    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30)?;
    totp.verify(code, None, 1)
}

pub fn create_secret() -> Result<Vec<u8>> {
    KeyGenerator::generate_default_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hotp_default() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let code = generate_hotp_default(secret, 0).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_totp_default() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let code = generate_totp_default(secret).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_verify_hotp_default() {
        let secret = vec![
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        ];
        let code = generate_hotp_default(secret.clone(), 0).unwrap();
        assert!(verify_hotp_default(secret, &code, 0).unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_secret() {
        let secret = create_secret().unwrap();
        assert_eq!(secret.len(), 20);
    }
}
