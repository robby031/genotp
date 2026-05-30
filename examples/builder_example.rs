use genotp::{Algorithm, HotpBuilder, TotpBuilder};

fn main() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    let hotp = HotpBuilder::new()
        .secret(secret.clone())
        .algorithm(Algorithm::SHA256)
        .digits(8)
        .build()
        .unwrap();

    let code = hotp.generate(0).unwrap();
    println!("HOTP: {}", code);

    let totp = TotpBuilder::new()
        .secret(secret)
        .algorithm(Algorithm::SHA512)
        .digits(6)
        .period(60)
        .build()
        .unwrap();

    let code = totp.generate(None).unwrap();
    println!("TOTP: {}", code);
}
