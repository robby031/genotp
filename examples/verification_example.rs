use genotp::{constant_time_eq, Verifier};

fn main() {
    let verifier = Verifier::new(5);

    let code = "123456";
    let expected = "123456";

    let is_valid = verifier.verify_with_replay_protection(code, expected);
    println!("First verification: {}", is_valid);

    let is_valid = verifier.verify_with_replay_protection(code, expected);
    println!("Second verification (replay): {}", is_valid);

    println!("Rate limited: {}", verifier.is_rate_limited());

    verifier.reset_attempts();
    println!("After reset - Rate limited: {}", verifier.is_rate_limited());

    let is_equal = constant_time_eq("hello", "hello");
    println!("Constant time equal: {}", is_equal);
}
