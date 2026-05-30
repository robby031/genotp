#![no_main]
use libfuzzer_sys::fuzz_target;
use genotp::{OtpAuthUri, OtpType, Algorithm, encode};

fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }
    
    let secret = data[0..20].to_vec();
    let secret_b32 = encode(&secret);
    
    let label = if data.len() > 20 {
        format!("service:{}", String::from_utf8_lossy(&data[20..]))
    } else {
        "service:user@example.com".to_string()
    };
    
    let _ = OtpAuthUri::new(OtpType::TOTP, label.clone(), secret_b32.clone())
        .issuer("Service".to_string())
        .algorithm(Algorithm::SHA1)
        .digits(6)
        .period(30)
        .build();
    
    let _ = OtpAuthUri::new(OtpType::HOTP, label, secret_b32)
        .issuer("Service".to_string())
        .algorithm(Algorithm::SHA1)
        .digits(6)
        .counter(0)
        .build();
});
