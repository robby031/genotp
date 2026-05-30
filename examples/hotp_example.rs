use genotp::{Algorithm, HOTP};

fn main() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

    for counter in 1..=5 {
        let code = hotp.generate(counter).unwrap();
        println!("Counter {}: {}", counter, code);
    }
}
