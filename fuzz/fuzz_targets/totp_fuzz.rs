#![no_main]
use libfuzzer_sys::fuzz_target;
use genotp::{TOTP, Algorithm};

fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }
    
    let secret = data[0..20].to_vec();
    let time = if data.len() >= 24 {
        u64::from_be_bytes([data[20], data[21], data[22], data[23], 0, 0, 0, 0])
    } else {
        0
    };
    
    if let Ok(totp) = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 30) {
        let _ = totp.generate(Some(time));
        let _ = totp.verify("123456", Some(time), 1);
    }
    
    if let Ok(totp) = TOTP::new(secret.clone(), Algorithm::SHA256, 6, 30) {
        let _ = totp.generate(Some(time));
    }
    
    if let Ok(totp) = TOTP::new(secret.clone(), Algorithm::SHA512, 6, 30) {
        let _ = totp.generate(Some(time));
    }
});
