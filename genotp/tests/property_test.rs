#[cfg(not(miri))]
mod property_tests {
    use genotp::{Algorithm, HOTP, KeyGenerator, OtpContext, TOTP, Verifier};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hotp_generate_always_correct_length(secret in prop::collection::vec(any::<u8>(), 20..=32), counter in 0u64..1_000_000u64) {
            let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
            let code = hotp.generate(counter).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }

        #[test]
        fn hotp_verify_correct_code(secret in prop::collection::vec(any::<u8>(), 20..=32), counter in 0u64..1_000_000u64) {
            let hotp = HOTP::new(secret.clone(), Algorithm::SHA1, 6).unwrap();
            let code = hotp.generate(counter).unwrap();
            assert!(hotp.verify(&code, counter).unwrap());
        }

        #[test]
        fn totp_generate_always_correct_length(secret in prop::collection::vec(any::<u8>(), 20..=32), time in 0u64..1_000_000_000u64) {
            let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
            let code = totp.generate(Some(time)).unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }

        #[test]
        fn totp_verify_correct_code(secret in prop::collection::vec(any::<u8>(), 20..=32), time in 0u64..1_000_000_000u64) {
            let totp = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 30).unwrap();
            let code = totp.generate(Some(time)).unwrap();
            assert!(totp.verify(&code, Some(time), 1).unwrap());
        }

        #[test]
        fn key_generate_always_correct_length(byte_length in 16usize..=64usize) {
            // generate_secret hanya menerima kelipatan 8 bit; pakai bytes
            // sebagai input lalu kalikan 8 supaya kondisinya selalu terpenuhi.
            let bit_length = byte_length * 8;
            let secret = KeyGenerator::generate_secret(bit_length).unwrap();
            assert_eq!(secret.len(), byte_length);
        }

        // ============================================================
        // Binding properties — claim cryptographic harus berlaku universal.
        // ============================================================

        /// Untuk SEMUA (secret, context, time) yang valid: kode yang dihasilkan
        /// `generate_bound` HARUS diverifikasi sukses oleh `verify_bound` dengan
        /// context yang sama. Round-trip property.
        #[test]
        fn totp_bound_roundtrip(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            ctx_bytes in prop::collection::vec(any::<u8>(), 0..64),
            time in 0u64..1_000_000_000u64,
        ) {
            let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
            let ctx = OtpContext::from_bytes(ctx_bytes);
            let code = totp.generate_bound(&ctx, Some(time)).unwrap();
            prop_assert!(totp.verify_bound(&code, &ctx, Some(time), 0).unwrap());
        }

        /// Untuk SEMUA (secret, ctx_a, ctx_b, time) DI MANA ctx_a != ctx_b:
        /// kode yang di-issue di ctx_a TIDAK BOLEH lulus verifikasi di ctx_b.
        /// Ini claim utama context binding — kalau ada satu input yang break,
        /// security claim runtuh.
        #[test]
        fn totp_bound_different_contexts_reject(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            ctx_a in prop::collection::vec(any::<u8>(), 1..64),
            ctx_b in prop::collection::vec(any::<u8>(), 1..64),
            time in 0u64..1_000_000_000u64,
        ) {
            prop_assume!(ctx_a != ctx_b);
            let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
            let oa = OtpContext::from_bytes(ctx_a);
            let ob = OtpContext::from_bytes(ctx_b);
            let code = totp.generate_bound(&oa, Some(time)).unwrap();
            prop_assert!(!totp.verify_bound(&code, &ob, Some(time), 0).unwrap(),
                "code dari ctx A diterima di ctx B — context isolation gagal");
        }

        /// `generate_bound(empty, t)` HARUS identik dengan `generate(t)` (RFC 6238).
        /// Backward compatibility absolute.
        #[test]
        fn empty_context_equals_standard_totp(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            time in 0u64..1_000_000_000u64,
        ) {
            let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
            let empty = OtpContext::empty();
            let standard = totp.generate(Some(time)).unwrap();
            let bound = totp.generate_bound(&empty, Some(time)).unwrap();
            prop_assert_eq!(standard, bound);
        }

        /// HOTP versi sama.
        #[test]
        fn hotp_bound_roundtrip(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            ctx_bytes in prop::collection::vec(any::<u8>(), 0..64),
            counter in 0u64..1_000_000u64,
        ) {
            let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
            let ctx = OtpContext::from_bytes(ctx_bytes);
            let code = hotp.generate_bound(counter, &ctx).unwrap();
            prop_assert!(hotp.verify_bound(&code, counter, &ctx).unwrap());
        }

        #[test]
        fn hotp_bound_different_contexts_reject(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            ctx_a in prop::collection::vec(any::<u8>(), 1..64),
            ctx_b in prop::collection::vec(any::<u8>(), 1..64),
            counter in 0u64..1_000_000u64,
        ) {
            prop_assume!(ctx_a != ctx_b);
            let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
            let code = hotp.generate_bound(counter, &OtpContext::from_bytes(ctx_a)).unwrap();
            prop_assert!(!hotp.verify_bound(&code, counter, &OtpContext::from_bytes(ctx_b)).unwrap());
        }

        /// Window acceptance: untuk semua `delta` antara `-window..=window`,
        /// kode yang di-generate di `t` HARUS diterima saat verifikasi di
        /// `t + delta*period`.
        #[test]
        fn totp_bound_window_accepts_within_range(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            ctx_bytes in prop::collection::vec(any::<u8>(), 0..32),
            // Pilih time aligned ke kelipatan period agar offset deterministik.
            base_window in 1_000u64..30_000_000u64,
            delta_steps in -2i64..=2i64,
            window in 2u64..=5u64,
        ) {
            let period = 30u64;
            let time = base_window * period;
            let totp = TOTP::new(secret, Algorithm::SHA1, 6, period).unwrap();
            let ctx = OtpContext::from_bytes(ctx_bytes);
            let code = totp.generate_bound(&ctx, Some(time)).unwrap();
            let abs_delta = delta_steps.unsigned_abs();
            if abs_delta <= window {
                let verify_time = (time as i64 + delta_steps * period as i64) as u64;
                prop_assert!(
                    totp.verify_bound(&code, &ctx, Some(verify_time), window).unwrap(),
                    "delta_steps={} dalam window={} seharusnya diterima",
                    delta_steps, window
                );
            }
        }

        // ============================================================
        // OtpContextBuilder properties.
        // ============================================================

        /// Builder canonicalization: dua builder dengan field sama tapi urutan
        /// setter berbeda HARUS menghasilkan bytes identik.
        #[test]
        fn context_builder_setter_order_invariant(
            ip in "[a-zA-Z0-9:.]{1,30}",
            device in "[a-zA-Z0-9-]{1,30}",
            session in "[a-zA-Z0-9_-]{1,30}",
        ) {
            let a = OtpContext::builder()
                .ip(&ip).device(&device).session(&session).build();
            let b = OtpContext::builder()
                .session(&session).ip(&ip).device(&device).build();
            let c = OtpContext::builder()
                .device(&device).session(&session).ip(&ip).build();
            prop_assert_eq!(&a, &b);
            prop_assert_eq!(&a, &c);
        }

        /// Verifier replay-set HARUS terisolasi per-context: kode yang sama
        /// di context berbeda tidak boleh saling memblokir.
        #[test]
        fn verifier_per_context_isolation(
            code in "[0-9]{6}",
            ctx_a in prop::collection::vec(any::<u8>(), 1..32),
            ctx_b in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            prop_assume!(ctx_a != ctx_b);
            let v = Verifier::new(100);
            let a = OtpContext::from_bytes(ctx_a);
            let b = OtpContext::from_bytes(ctx_b);

            prop_assert!(v.verify_with_context(&code, &code, &a, &a));
            prop_assert!(v.verify_with_context(&code, &code, &b, &b),
                "kode collision antar context tidak boleh saling block");
            // Replay di context masing-masing → ditolak.
            prop_assert!(!v.verify_with_context(&code, &code, &a, &a));
            prop_assert!(!v.verify_with_context(&code, &code, &b, &b));
        }

        /// Verifier dengan context mismatch HARUS selalu menolak.
        #[test]
        fn verifier_context_mismatch_always_rejects(
            code in "[0-9]{6}",
            issued in prop::collection::vec(any::<u8>(), 1..32),
            request in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            prop_assume!(issued != request);
            let v = Verifier::new(100_000);
            prop_assert!(!v.verify_with_context(
                &code, &code,
                &OtpContext::from_bytes(issued),
                &OtpContext::from_bytes(request),
            ));
        }
    }
}
