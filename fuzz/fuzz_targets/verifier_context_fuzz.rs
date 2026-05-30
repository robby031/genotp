#![no_main]
//! Fuzz Verifier::verify_with_context dengan input random:
//! - Tidak boleh panic / overflow / deadlock.
//! - Replay set per-context tetap konsisten: kalau pernah accept (code, ctx),
//!   maka panggilan kedua dengan (code, ctx) yang SAMA wajib reject.
//! - Context mismatch wajib reject (issued != request).

use genotp::{OtpContext, Verifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // 1 byte: panjang code (max 16 supaya tetap masuk akal).
    let code_len = (data[0] as usize % 16) + 1;
    if data.len() < 1 + code_len + 2 {
        return;
    }

    // Code dibatasi ke ASCII printable (mensimulasikan input user yang sah).
    let code: String = data[1..1 + code_len]
        .iter()
        .map(|b| ((b % 95) + 0x20) as char)
        .collect();

    let rest = &data[1 + code_len..];
    if rest.len() < 2 {
        return;
    }

    // 1 byte panjang issued_ctx, 1 byte panjang request_ctx.
    let issued_len = rest[0] as usize % 64;
    let request_len = rest[1] as usize % 64;
    let body = &rest[2..];
    if body.len() < issued_len + request_len {
        return;
    }

    let issued_bytes = body[..issued_len].to_vec();
    let request_bytes = body[issued_len..issued_len + request_len].to_vec();

    let issued = OtpContext::from_bytes(issued_bytes.clone());
    let request = OtpContext::from_bytes(request_bytes.clone());

    let verifier = Verifier::new(1_000_000);

    // Property 1: kalau context match dan code==expected, panggilan pertama
    // sukses, kedua harus ditolak (replay).
    if issued_bytes == request_bytes {
        let first = verifier.verify_with_context(&code, &code, &issued, &request);
        if first {
            let second = verifier.verify_with_context(&code, &code, &issued, &request);
            assert!(!second, "replay context-match diterima dua kali");
        }
    } else {
        // Property 2: kalau context BERBEDA, selalu reject walau code valid.
        let result = verifier.verify_with_context(&code, &code, &issued, &request);
        assert!(!result, "context mismatch diterima");
    }

    // Bonus: plain API tidak boleh terkontaminasi oleh state context API.
    let plain = verifier.verify_with_replay_protection(&code, &code);
    // Sah mau true atau false; yang penting tidak panic.
    let _ = plain;
});
