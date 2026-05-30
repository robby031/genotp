use genotp::{create_secret, generate_totp_default, verify_totp_default};

fn main() {
    let secret = create_secret().unwrap();

    let code = generate_totp_default(secret.clone()).unwrap();
    println!("TOTP Code: {}", code);

    let is_valid = verify_totp_default(secret, &code).unwrap();
    println!("Valid: {}", is_valid);
}
