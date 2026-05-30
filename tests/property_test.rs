#[cfg(not(miri))]
mod property_tests {
    use genotp::{Algorithm, KeyGenerator, HOTP, TOTP};
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
    }
}
