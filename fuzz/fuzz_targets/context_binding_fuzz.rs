#![no_main]
//! Fuzz context binding (Mode 1 HMAC):
//! - `OtpContext::from_bytes(random)` tidak boleh panic.
//! - `generate_bound` + `verify_bound` dengan input random tidak boleh panic
//!   atau menghasilkan UB pada offset/index apapun di dynamic_truncate.
//! - Round-trip property: code yang baru di-generate dengan ctx pasti diverify
//!   sukses oleh ctx yang sama.

use genotp::{Algorithm, HOTP, OtpContext, TOTP};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Minimal layout: 20 byte secret + 4 byte counter/time + sisa = context.
    if data.len() < 24 {
        return;
    }

    let secret = data[0..20].to_vec();
    let counter = u64::from_be_bytes([
        data[20], data[21], data[22], data[23], 0, 0, 0, 0,
    ]);
    let ctx_bytes = &data[24..];
    let ctx = OtpContext::from_bytes(ctx_bytes.to_vec());

    // HOTP path: round-trip wajib sukses untuk semua input.
    //
    // Catatan: kita TIDAK mengassert "kode untuk ctx_A tidak bisa diterima
    // oleh ctx_B" karena kode 6-digit punya 10^6 kemungkinan, sehingga
    // collision antar HMAC output adalah pasti terjadi secara statistik
    // (1/10^6 per attempt). Mitigasi terhadap brute force baseline ini
    // adalah rate limit di Verifier, bukan binding itu sendiri.
    if let Ok(hotp) = HOTP::new(secret.clone(), Algorithm::SHA1, 6) {
        if let Ok(code) = hotp.generate_bound(counter, &ctx) {
            let ok = hotp.verify_bound(&code, counter, &ctx).unwrap_or(false);
            assert!(ok, "round-trip HOTP bound gagal");
        }
    }

    // TOTP path.
    if let Ok(totp) = TOTP::new(secret.clone(), Algorithm::SHA1, 6, 30) {
        if let Ok(code) = totp.generate_bound(&ctx, Some(counter)) {
            let ok = totp
                .verify_bound(&code, &ctx, Some(counter), 0)
                .unwrap_or(false);
            assert!(ok, "round-trip TOTP bound gagal");
        }
    }

    // Path SHA256 dan SHA512 — sekedar pastikan tidak panic.
    for algo in [Algorithm::SHA256, Algorithm::SHA512] {
        if let Ok(totp) = TOTP::new(secret.clone(), algo, 6, 30) {
            let _ = totp.generate_bound(&ctx, Some(counter));
        }
    }
});
