use genotp::{Algorithm, KeyGenerator, OtpAuthUri, OtpType, encode};

fn main() {
    let secret = KeyGenerator::generate_default_secret().unwrap();
    let secret_b32 = encode(&secret);

    let totp_uri = OtpAuthUri::new(
        OtpType::TOTP,
        "MyService:user@example.com".to_string(),
        secret_b32.clone(),
    )
    .issuer("MyService".to_string())
    .algorithm(Algorithm::SHA1)
    .digits(6)
    .period(30);

    println!("TOTP URI: {}", totp_uri.build());

    let hotp_uri = OtpAuthUri::new(
        OtpType::HOTP,
        "MyService:user@example.com".to_string(),
        secret_b32,
    )
    .issuer("MyService".to_string())
    .algorithm(Algorithm::SHA1)
    .digits(6)
    .counter(0);

    println!("HOTP URI: {}", hotp_uri.build());
}
