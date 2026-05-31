use genotp::{Algorithm, HOTP, OtpContext, TOTP, Verifier};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_concurrent_generation() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = Arc::new(HOTP::new(secret, Algorithm::SHA1, 6).unwrap());

    let mut handles = vec![];

    for i in 0..10 {
        let hotp_clone = Arc::clone(&hotp);
        let handle = thread::spawn(move || {
            for j in 0..100 {
                let _ = hotp_clone.generate(i * 100 + j).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_totp_concurrent_generation() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = Arc::new(TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap());

    let mut handles = vec![];

    for _ in 0..10 {
        let totp_clone = Arc::clone(&totp);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _ = totp_clone.generate(None).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn test_hotp_concurrent_verification() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let hotp = Arc::new(HOTP::new(secret, Algorithm::SHA1, 6).unwrap());
    let code = hotp.generate(0).unwrap();

    let mut handles = vec![];

    for _ in 0..10 {
        let hotp_clone = Arc::clone(&hotp);
        let code_clone = code.clone();
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _ = hotp_clone.verify(&code_clone, 0).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// ===========================================================================
// Verifier — stress test untuk korektness di bawah concurrency.
// ===========================================================================

/// 100 thread × 50 percobaan verify code yang sama dengan context yang sama.
/// HARUS hanya 1 yang sukses. Sisanya (5000-1) HARUS ditolak karena replay.
/// Tidak boleh ada deadlock, panic, atau dua thread sukses bersamaan.
#[cfg_attr(miri, ignore)]
#[test]
fn verifier_replay_under_extreme_contention() {
    let verifier = Arc::new(Verifier::new(1_000_000));
    let success_counter = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];
    for _ in 0..100 {
        let v = Arc::clone(&verifier);
        let s = Arc::clone(&success_counter);
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                if v.verify_with_replay_protection("424242", "424242") {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        success_counter.load(Ordering::SeqCst),
        1,
        "tepat 1 thread harus sukses di bawah race"
    );
}

/// 100 thread, masing-masing dengan context UNIK, semuanya pakai kode yang sama.
/// HARUS semua 100 sukses karena replay-set per-context.
#[cfg_attr(miri, ignore)]
#[test]
fn verifier_per_context_isolation_under_contention() {
    let verifier = Arc::new(Verifier::new(1_000_000));
    let success_counter = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];
    for tid in 0..100u32 {
        let v = Arc::clone(&verifier);
        let s = Arc::clone(&success_counter);
        handles.push(thread::spawn(move || {
            let ctx = OtpContext::builder()
                .session(&format!("sess-{tid:03}"))
                .build();
            for attempt in 0..10 {
                let ok = v.verify_with_context("777777", "777777", &ctx, &ctx);
                if ok {
                    s.fetch_add(1, Ordering::SeqCst);
                }
                if attempt > 0 {
                    assert!(!ok, "thread {tid} replay attempt {attempt} harus ditolak");
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        success_counter.load(Ordering::SeqCst),
        100,
        "100 context unik harus semua sukses (1× tiap)"
    );
}

/// Rate limit HARUS triggered persis setelah `max_attempts` percobaan gagal,
/// bahkan ketika ratusan thread bersaing menaikkan counter bersamaan.
#[cfg_attr(miri, ignore)]
#[test]
fn verifier_rate_limit_triggers_under_concurrency() {
    let max_attempts = 50u32;
    let verifier = Arc::new(Verifier::new(max_attempts));

    let mut handles = vec![];
    for _ in 0..200 {
        let v = Arc::clone(&verifier);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let _ = v.verify_with_replay_protection("000000", "999999");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert!(
        verifier.is_rate_limited(),
        "setelah ribuan percobaan gagal, rate-limit harus aktif"
    );

    assert!(
        !verifier.verify_with_replay_protection("888888", "888888"),
        "kode benar yang masuk saat rate-limited harus ditolak"
    );
}

/// Mixed workload: campuran context-bound dan plain, dengan banyak thread.
/// Memastikan tidak ada cross-contamination antara dua jalur API.
#[cfg_attr(miri, ignore)]
#[test]
fn verifier_mixed_api_paths_no_cross_contamination() {
    let verifier = Arc::new(Verifier::new(1_000_000));
    let success_plain = Arc::new(AtomicU32::new(0));
    let success_bound = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];

    for _ in 0..50 {
        let v = Arc::clone(&verifier);
        let s = Arc::clone(&success_plain);
        handles.push(thread::spawn(move || {
            for _ in 0..20 {
                if v.verify_with_replay_protection("AAAAAA", "AAAAAA") {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for tid in 0..50u32 {
        let v = Arc::clone(&verifier);
        let s = Arc::clone(&success_bound);
        handles.push(thread::spawn(move || {
            let ctx = OtpContext::builder().session(&format!("t{tid:02}")).build();
            for _ in 0..20 {
                if v.verify_with_context("AAAAAA", "AAAAAA", &ctx, &ctx) {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        success_plain.load(Ordering::SeqCst),
        1,
        "plain API: hanya 1 sukses dari 50×20 percobaan"
    );
    assert_eq!(
        success_bound.load(Ordering::SeqCst),
        50,
        "bound API: 50 context unik harus semua sukses (1× tiap)"
    );
}

/// TOTP::verify_bound concurrent — tidak boleh ada data race atau corruption
/// pada secret yang di-share lewat Arc.
#[cfg_attr(miri, ignore)]
#[test]
fn totp_bound_concurrent_verify() {
    let secret = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30,
    ];
    let totp = Arc::new(TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap());

    let mut handles = vec![];
    for tid in 0..20u32 {
        let totp_clone = Arc::clone(&totp);
        handles.push(thread::spawn(move || {
            let ctx = OtpContext::builder()
                .session(&format!("sess-{tid}"))
                .ip(&format!("10.0.0.{}", tid % 256))
                .build();
            for t in (1_700_000_000u64..1_700_000_000 + 100 * 30).step_by(30) {
                let code = totp_clone.generate_bound(&ctx, Some(t)).unwrap();
                assert!(
                    totp_clone.verify_bound(&code, &ctx, Some(t), 0).unwrap(),
                    "round-trip gagal di tid={tid}, t={t}"
                );
                let other_ctx = OtpContext::builder()
                    .session(&format!("sess-{}", tid + 1000))
                    .build();
                assert!(
                    !totp_clone
                        .verify_bound(&code, &other_ctx, Some(t), 0)
                        .unwrap(),
                    "context lain seharusnya tidak match"
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
