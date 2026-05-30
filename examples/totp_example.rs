use genotp::{Algorithm, TOTP};

fn main() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

    let code = totp.generate(None).unwrap();
    println!("TOTP: {}", code);

    let is_valid = totp.verify(&code, None, 1).unwrap();
    println!("Valid: {}", is_valid);
}
