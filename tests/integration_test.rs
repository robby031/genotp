use genotp::{Algorithm, KeyGenerator, HOTP, TOTP};

#[test]
fn test_hotp_integration() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = HOTP::new(secret.clone(), Algorithm::SHA1, 6).unwrap();

    let code1 = hotp.generate(1).unwrap();
    let code2 = hotp.generate(2).unwrap();

    assert_ne!(code1, code2);
    assert_eq!(code1.len(), 6);
    assert_eq!(code2.len(), 6);

    assert!(hotp.verify(&code1, 1).unwrap());
    assert!(!hotp.verify(&code1, 2).unwrap());
}

#[test]
fn test_totp_integration() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 30).unwrap();

    let code = totp.generate(Some(1234567890)).unwrap();
    assert_eq!(code.len(), 6);

    assert!(totp.verify(&code, Some(1234567890), 1).unwrap());
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_key_generation() {
    let secret = KeyGenerator::generate_default_secret().unwrap();
    assert_eq!(secret.len(), 20);

    let secret_256 = KeyGenerator::generate_secret(256).unwrap();
    assert_eq!(secret_256.len(), 32);
}
