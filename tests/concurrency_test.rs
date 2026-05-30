use genotp::{Algorithm, HOTP, TOTP};
use std::sync::Arc;
use std::thread;

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_concurrent_generation() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = Arc::new(HOTP::new(secret, Algorithm::SHA1, 6).unwrap());

    let mut handles = vec![];

    for i in 0..10 {
        let hotp_clone = Arc::clone(&hotp);
        let handle = thread::spawn(move || {
            for j in 0..100 {
                let _ = hotp_clone.generate(i * 100 + j).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_totp_concurrent_generation() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = Arc::new(TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap());

    let mut handles = vec![];

    for _ in 0..10 {
        let totp_clone = Arc::clone(&totp);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _ = totp_clone.generate(None).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_concurrent_verification() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = Arc::new(HOTP::new(secret, Algorithm::SHA1, 6).unwrap());
    let code = hotp.generate(0).unwrap();

    let mut handles = vec![];

    for _ in 0..10 {
        let hotp_clone = Arc::clone(&hotp);
        let code_clone = code.clone();
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _ = hotp_clone.verify(&code_clone, 0).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
