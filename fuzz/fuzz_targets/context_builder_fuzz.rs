#![no_main]
//! Fuzz OtpContextBuilder dengan field random:
//! - Tidak boleh panic untuk input UTF-8 apa pun.
//! - Canonicalization invariant: dua builder dengan field SAMA tapi urutan
//!   setter berbeda HARUS menghasilkan bytes identik.
//! - Field VALUE berbeda WAJIB menghasilkan bytes berbeda
//!   (mencegah delimiter spoofing).

use genotp::OtpContext;
use libfuzzer_sys::fuzz_target;

fn pick_str<'a>(data: &'a [u8], cur: &mut usize) -> Option<&'a str> {
    if *cur >= data.len() {
        return None;
    }
    let len = (data[*cur] as usize) % 32 + 1;
    *cur += 1;
    if *cur + len > data.len() {
        return None;
    }
    let slice = &data[*cur..*cur + len];
    *cur += len;
    // Hanya pakai kalau valid UTF-8.
    std::str::from_utf8(slice).ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let mut cur = 0;

    let ip = pick_str(data, &mut cur).unwrap_or("");
    let device = pick_str(data, &mut cur).unwrap_or("");
    let session = pick_str(data, &mut cur).unwrap_or("");
    let origin = pick_str(data, &mut cur).unwrap_or("");

    // Property A: urutan setter tidak memengaruhi hasil.
    let a = OtpContext::builder()
        .ip(ip)
        .device(device)
        .session(session)
        .origin(origin)
        .build();
    let b = OtpContext::builder()
        .session(session)
        .origin(origin)
        .ip(ip)
        .device(device)
        .build();
    assert_eq!(a, b, "urutan setter mempengaruhi output");

    // Property B: kalau salah satu value diubah, output WAJIB berbeda.
    let alt_ip = format!("{ip}x");
    let c = OtpContext::builder()
        .ip(&alt_ip)
        .device(device)
        .session(session)
        .origin(origin)
        .build();
    assert_ne!(a, c, "ip yang diubah tidak menghasilkan output berbeda");

    // Property C: empty context selalu bytes kosong.
    let empty = OtpContext::empty();
    assert!(empty.is_empty());

    // Property D: custom field tidak boleh bisa mensimulasikan field built-in.
    // Misal custom("p", "foo") yang oleh attacker mau "menyamar" sebagai "ip".
    // Karena di-prefix "x-", harusnya berbeda.
    let with_custom = OtpContext::builder().custom("ip", "foo").build();
    let with_builtin = OtpContext::builder().ip("foo").build();
    assert_ne!(
        with_custom, with_builtin,
        "custom() bisa mensimulasikan field built-in — prefix x- gagal"
    );
});
