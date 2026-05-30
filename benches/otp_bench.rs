use criterion::{criterion_group, criterion_main, Criterion};
use genotp::{decode, encode, Algorithm, KeyGenerator, Verifier, HOTP, TOTP};
use std::hint::black_box;
use std::sync::Arc;

fn bench_hotp_generate(c: &mut Criterion) {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

    c.bench_function("hotp_generate", |b| {
        b.iter(|| hotp.generate(black_box(0)).unwrap())
    });
}

fn bench_hotp_verify(c: &mut Criterion) {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
    let code = hotp.generate(0).unwrap();

    c.bench_function("hotp_verify", |b| {
        b.iter(|| hotp.verify(black_box(&code), black_box(0)).unwrap())
    });
}

fn bench_totp_generate(c: &mut Criterion) {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

    c.bench_function("totp_generate", |b| {
        b.iter(|| totp.generate(black_box(None)).unwrap())
    });
}

fn bench_totp_verify(c: &mut Criterion) {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
    let code = totp.generate(None).unwrap();

    c.bench_function("totp_verify", |b| {
        b.iter(|| {
            totp.verify(black_box(&code), black_box(None), black_box(1))
                .unwrap()
        })
    });
}

fn bench_generate_secret(c: &mut Criterion) {
    c.bench_function("generate_secret_default", |b| {
        b.iter(|| black_box(KeyGenerator::generate_default_secret().unwrap()))
    });

    c.bench_function("generate_secret_256", |b| {
        b.iter(|| black_box(KeyGenerator::generate_secret(256).unwrap()))
    });
}

fn bench_base32_encode(c: &mut Criterion) {
    let data = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];

    c.bench_function("base32_encode", |b| b.iter(|| encode(black_box(&data))));
}

fn bench_base32_decode(c: &mut Criterion) {
    let data = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let encoded = encode(&data);

    c.bench_function("base32_decode", |b| {
        b.iter(|| decode(black_box(&encoded)).unwrap())
    });
}

fn bench_provisioning_uri(c: &mut Criterion) {
    use genotp::{OtpAuthUri, OtpType};

    let secret = KeyGenerator::generate_default_secret().unwrap();
    let secret_b32 = encode(&secret);

    c.bench_function("provisioning_uri_totp", |b| {
        b.iter(|| {
            OtpAuthUri::new(
                OtpType::TOTP,
                "MyService:user@example.com".to_string(),
                secret_b32.clone(),
            )
            .issuer("MyService".to_string())
            .algorithm(Algorithm::SHA1)
            .digits(6)
            .period(30)
            .build()
        })
    });

    c.bench_function("provisioning_uri_hotp", |b| {
        b.iter(|| {
            OtpAuthUri::new(
                OtpType::HOTP,
                "MyService:user@example.com".to_string(),
                secret_b32.clone(),
            )
            .issuer("MyService".to_string())
            .algorithm(Algorithm::SHA1)
            .digits(6)
            .counter(0)
            .build()
        })
    });
}

fn bench_replay_protection(c: &mut Criterion) {
    let verifier = Verifier::new(5);
    let code = "123456";
    let expected = "123456";

    c.bench_function("replay_protection_verify", |b| {
        b.iter(|| verifier.verify_with_replay_protection(black_box(code), black_box(expected)))
    });
}

fn bench_rate_limiter_contention(c: &mut Criterion) {
    let verifier = Arc::new(Verifier::new(5));

    c.bench_function("rate_limiter_contention", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let verifier = Arc::clone(&verifier);
                    std::thread::spawn(move || {
                        for _ in 0..100 {
                            verifier.verify_with_replay_protection("wrong", "123456");
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

fn bench_concurrent_verification(c: &mut Criterion) {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = Arc::new(HOTP::new(secret, Algorithm::SHA1, 6).unwrap());
    let code = hotp.generate(0).unwrap();

    c.bench_function("concurrent_verification", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let hotp = Arc::clone(&hotp);
                    let code = code.clone();
                    std::thread::spawn(move || {
                        for _ in 0..100 {
                            hotp.verify(&code, 0).unwrap();
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    bench_hotp_generate,
    bench_hotp_verify,
    bench_totp_generate,
    bench_totp_verify,
    bench_generate_secret,
    bench_base32_encode,
    bench_base32_decode,
    bench_provisioning_uri,
    bench_replay_protection,
    bench_rate_limiter_contention,
    bench_concurrent_verification
);
criterion_main!(benches);
