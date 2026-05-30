#![no_main]
use libfuzzer_sys::fuzz_target;
use genotp::{HOTP, Algorithm};

fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }
    
    let secret = data[0..20].to_vec();
    let counter = if data.len() >= 24 {
        u64::from_be_bytes([data[20], data[21], data[22], data[23], 0, 0, 0, 0])
    } else {
        0
    };
    
    if let Ok(hotp) = HOTP::new(secret.clone(), Algorithm::SHA1, 6) {
        let _ = hotp.generate(counter);
        let _ = hotp.verify("123456", counter);
    }
    
    if let Ok(hotp) = HOTP::new(secret.clone(), Algorithm::SHA256, 6) {
        let _ = hotp.generate(counter);
    }
    
    if let Ok(hotp) = HOTP::new(secret, Algorithm::SHA512, 6) {
        let _ = hotp.generate(counter);
    }
});
