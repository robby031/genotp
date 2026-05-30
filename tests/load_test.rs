use genotp::{Algorithm, HOTP, TOTP};
use std::time::Instant;

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_load() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

    let start = Instant::now();
    let iterations = 100_000;

    for i in 0..iterations {
        let _ = hotp.generate(i).unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();

    println!(
        "HOTP Load Test: {} operations in {:.2}s ({:.0} ops/sec)",
        iterations,
        duration.as_secs_f64(),
        ops_per_sec
    );

    assert!(
        ops_per_sec > 10_000.0,
        "Performance too low: {} ops/sec",
        ops_per_sec
    );
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_totp_load() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

    let start = Instant::now();
    let iterations = 100_000;

    for _ in 0..iterations {
        let _ = totp.generate(None).unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();

    println!(
        "TOTP Load Test: {} operations in {:.2}s ({:.0} ops/sec)",
        iterations,
        duration.as_secs_f64(),
        ops_per_sec
    );

    assert!(
        ops_per_sec > 10_000.0,
        "Performance too low: {} ops/sec",
        ops_per_sec
    );
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_verify_load() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
    let code = hotp.generate(0).unwrap();

    let start = Instant::now();
    let iterations = 100_000;

    for _ in 0..iterations {
        let _ = hotp.verify(&code, 0).unwrap();
    }

    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();

    println!(
        "HOTP Verify Load Test: {} operations in {:.2}s ({:.0} ops/sec)",
        iterations,
        duration.as_secs_f64(),
        ops_per_sec
    );

    assert!(
        ops_per_sec > 10_000.0,
        "Performance too low: {} ops/sec",
        ops_per_sec
    );
}
