# Panduan Penggunaan genotp

Library OTP (One-Time Password) untuk Rust yang menerapkan RFC 4226 (HOTP)
dan RFC 6238 (TOTP), ditambah fitur keamanan tingkat lanjut seperti context
binding dan clock-skew detection.

---

## Daftar Isi

- [Instalasi](#instalasi)
- [Feature Flags](#feature-flags)
- [Quick Start](#quick-start)
- [HOTP](#hotp)
- [TOTP](#totp)
- [Builder Pattern](#builder-pattern)
- [Helper Functions](#helper-functions)
- [KeyGenerator](#keygenerator)
- [Base32 Encoding](#base32-encoding)
- [Provisioning URI & QR Code](#provisioning-uri--qr-code)
- [Verifier — Replay & Rate Limit](#verifier--replay--rate-limit)
- [Context Binding (Fitur Unggulan)](#context-binding-fitur-unggulan)
  - [Mode 1 — HMAC Binding](#mode-1--hmac-binding)
  - [Mode 2 — Verifier-Stored](#mode-2--verifier-stored)
  - [OtpContextBuilder](#otpcontextbuilder)
  - [Anti-Phishing Origin Binding](#anti-phishing-origin-binding)
- [ClockSkewDetector](#clockskewdetector)
- [Metrics](#metrics)
- [Error Handling](#error-handling)
- [Penggunaan no_std](#penggunaan-no_std)

---

## Instalasi

Tambahkan ke `Cargo.toml`:

```toml
[dependencies]
genotp = "0.1"
```

## Feature Flags

| Feature | Default | Penjelasan |
|---|---|---|
| `std` | ✓ | Akses ke `SystemTime` (waktu sistem), `Verifier`, `OtpContext`, `ClockSkewDetector`, `Metrics`, `OtpAuthUri`, `Builder`, `Helper`. Wajib untuk sebagian besar penggunaan server. |
| `alloc` | ✓ | Tipe heap-allocated (`String`, `Vec`). Dibutuhkan oleh HOTP/TOTP. |
| `serde` | — | Implementasi `Serialize` untuk HOTP, TOTP, dan `Algorithm`. Berguna untuk konfigurasi/logging. Secret **tidak ikut diserialisasi** karena alasan keamanan. |

Untuk embedded / no_std:

```toml
[dependencies]
genotp = { version = "0.1", default-features = false, features = ["alloc"] }
```

---

## Quick Start

```rust
use genotp::{create_secret, generate_totp_default, verify_totp_default};

// 1. Generate secret 160-bit (panjang yang direkomendasikan RFC 6238)
let secret = create_secret().unwrap();

// 2. Generate TOTP 6 digit, period 30 detik, SHA1
let code = generate_totp_default(secret.clone()).unwrap();
println!("Kode TOTP: {code}");

// 3. Verifikasi dengan window ±1 step
let valid = verify_totp_default(secret, &code).unwrap();
assert!(valid);
```

---

## HOTP

HOTP (RFC 4226) — counter-based OTP.

```rust
use genotp::{Algorithm, HOTP};

let secret = vec![
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
];
let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

let code = hotp.generate(42).unwrap();   // counter = 42
let ok = hotp.verify(&code, 42).unwrap();
assert!(ok);
```

Parameter:
- `secret`: minimal panjang ≥ 1 byte. Direkomendasikan 160-bit (20 byte).
- `algorithm`: `Algorithm::SHA1`, `SHA256`, atau `SHA512`.
- `digits`: 6, 7, atau 8.

---

## TOTP

TOTP (RFC 6238) — time-based OTP. Counter dihitung dari `time / period`.

```rust
use genotp::{Algorithm, TOTP};

let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

// Generate menggunakan waktu sistem (None) atau timestamp eksplisit.
let code = totp.generate(None).unwrap();

// Verifikasi dengan window ±1 step (toleransi 30 detik di tiap arah).
let ok = totp.verify(&code, None, 1).unwrap();
```

Parameter:
- `period`: panjang window dalam detik (umum: 30).
- `window`: berapa step ke depan/belakang yang ditoleransi (umum: 1).

**Penting tentang zona waktu:** TOTP berbasis Unix epoch UTC. Apa pun zona
waktu user (WIB/WITA/WIT), perhitungan tetap pakai detik sejak `1970-01-01
00:00:00 UTC`. Kalau OTP gagal verifikasi, periksa jam server (NTP), bukan
zona waktu.

---

## Builder Pattern

Lebih nyaman dibanding konstruktor positional:

```rust
use genotp::{Algorithm, TotpBuilder, HotpBuilder};

let totp = TotpBuilder::new()
    .secret(secret.clone())
    .algorithm(Algorithm::SHA1)
    .digits(6)
    .period(30)
    .build()
    .unwrap();

let hotp = HotpBuilder::new()
    .secret(secret)
    .algorithm(Algorithm::SHA256)
    .digits(8)
    .build()
    .unwrap();
```

---

## Helper Functions

Shortcut untuk konfigurasi default (SHA1, 6 digit, period 30):

```rust
use genotp::{generate_hotp_default, verify_hotp_default,
             generate_totp_default, verify_totp_default,
             create_secret};

let secret = create_secret().unwrap();   // 160-bit random

let totp_code = generate_totp_default(secret.clone()).unwrap();
let ok = verify_totp_default(secret.clone(), &totp_code).unwrap();

let hotp_code = generate_hotp_default(secret.clone(), 0).unwrap();
let ok = verify_hotp_default(secret, &hotp_code, 0).unwrap();
```

---

## KeyGenerator

```rust
use genotp::KeyGenerator;

// 160-bit (rekomendasi RFC 4226)
let secret = KeyGenerator::generate_default_secret().unwrap();

// Custom bit length (harus kelipatan 8, minimal 128)
let secret_256 = KeyGenerator::generate_secret(256).unwrap();
```

Sumber entropi: `ax-rnd` (OS-backed CSPRNG).

---

## Base32 Encoding

Untuk QR code / display ke user:

```rust
use genotp::{encode, decode};

let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f];
let b32 = encode(&bytes);              // "JBSWY3DP"
let back = decode(&b32).unwrap();
assert_eq!(bytes, back);
```

Encoding standar RFC 4648, tanpa padding (kompatibel Google Authenticator).

---

## Provisioning URI & QR Code

Generate URI `otpauth://` untuk di-scan oleh authenticator app:

```rust
use genotp::{Algorithm, OtpAuthUri, OtpType, encode};

let secret = vec![/* ... */];
let secret_b32 = encode(&secret);

let uri = OtpAuthUri::new(
    OtpType::TOTP,
    "ACME Corp:alice@example.com".to_string(),
    secret_b32,
)
.issuer("ACME Corp".to_string())
.algorithm(Algorithm::SHA1)
.digits(6)
.period(30)
.build();

// uri = "otpauth://totp/ACME%20Corp%3Aalice%40example.com?secret=...&issuer=..."
```

Semua label, issuer, dan secret otomatis **percent-encoded** sesuai RFC 3986
sehingga karakter spesial (`:`, `@`, spasi, `&`, dll) tidak merusak URI.

Render ke QR code (dengan crate `qrcode`):

```rust
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

let qr = QrCode::new(uri.as_bytes()).unwrap();
let rendered = qr.render::<Dense1x2>().build();
println!("{rendered}");
```

---

## Verifier — Replay & Rate Limit

`Verifier` menangani dua serangan umum:

1. **Replay attack** — kode yang sudah pernah dipakai tidak boleh diterima lagi.
2. **Brute force** — setelah `max_attempts` percobaan gagal, sistem kunci.

```rust
use genotp::Verifier;

let verifier = Verifier::new(5);   // max 5 percobaan gagal

let user_submitted = "123456";
let expected = totp.generate(None).unwrap();

if verifier.verify_with_replay_protection(user_submitted, &expected) {
    println!("Login OK");
} else if verifier.is_rate_limited() {
    println!("Akun terkunci");
} else {
    println!("Kode salah");
}
```

Kontrol kapasitas memory untuk `used_codes`:

```rust
// Default: 10.000 kode terakhir. Ketika penuh, set dikosongkan otomatis
// (kode lama sudah tidak relevan setelah window TOTP lewat).
let verifier = Verifier::with_capacity(5, 1000);
```

Operasi tambahan:

```rust
verifier.is_rate_limited();      // cek status rate limit
verifier.reset_attempts();       // reset counter (mis. setelah admin verify)
verifier.clear_used_codes();     // bersihkan replay-set manual
```

`Verifier` mengimplementasikan `Clone` (shared state via `Arc`) sehingga
aman dipakai dari banyak thread.

---

## Context Binding (Fitur Unggulan)

**Masalah:** OTP standar (RFC 6238) hanya bergantung pada `(secret, counter)`.
Begitu kode 6 digit bocor — diintercept WhatsApp, di-phishing, di-brute-force
— siapa pun yang punya kode bisa pakai.

**Solusi genotp:** ikat OTP ke context tambahan (IP, device, session, origin
URL). Penyerang yang punya kode tapi context-nya berbeda otomatis ditolak.

Dua mode tersedia.

### Mode 1 — HMAC Binding

Kode OTP itu sendiri **secara kriptografis** berbeda untuk context berbeda.
Anti WhatsApp / SMS intercept.

```rust
use genotp::{Algorithm, HOTP, OtpContext};

let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

// Server side: bind ke session + IP user saat request login.
let issued_ctx = OtpContext::builder()
    .session("login-abc123")
    .ip(&sha256_hex(user_ip))     // hash IP supaya tidak bocor di log
    .build();

let code = hotp.generate_bound(counter, &issued_ctx).unwrap();
send_via_whatsapp(user_phone, &code);
```

Saat user submit form:

```rust
let request_ctx = OtpContext::builder()
    .session(&form.session_id)
    .ip(&sha256_hex(request_ip))
    .build();

if hotp.verify_bound(&form.code, counter, &request_ctx).unwrap() {
    // Sukses: kode benar DAN context cocok.
}
```

**Efek nyata:** attacker yang intercept kode dari WhatsApp, lalu coba submit
dari IP yang berbeda → server menghitung HMAC dengan context attacker → digit
hasil komputasi berbeda dari yang dicegat → tolak. Brute force 0000-9999
**dari context attacker** juga sia-sia.

Untuk TOTP:

```rust
let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
let code = totp.generate_bound(&ctx, None).unwrap();
let ok = totp.verify_bound(&code, &ctx, None, 1).unwrap();   // window=1
```

**Backward compatible:** kalau context kosong (`OtpContext::empty()`), hasil
identik dengan TOTP/HOTP standar RFC. Bisa dipakai dengan Google Authenticator.

### Mode 2 — Verifier-Stored

Untuk skenario di mana user pakai authenticator app standar (Google
Authenticator, Authy) — kode tetap RFC 6238, tapi server mengikat context
ke proses verifikasi.

```rust
use genotp::{OtpContext, Verifier};

let verifier = Verifier::new(5);

// Saat user request challenge / submit form:
let issued_ctx = OtpContext::builder()
    .session("browser-tab-X")
    .ip(&sha256_hex(user_ip))
    .build();

// Server simpan issued_ctx (mis. di Redis bersama nonce).
// User pakai authenticator app, dapat kode 6 digit, submit ke server.

let request_ctx = OtpContext::builder()
    .session(&form.session_id)
    .ip(&sha256_hex(request_ip))
    .build();

let expected = totp.generate(None).unwrap();   // TOTP standar

let ok = verifier.verify_with_context(
    &form.code,
    &expected,
    &issued_ctx,
    &request_ctx,
);
```

Perbandingan context dilakukan **constant-time** (lewat `subtle`) sehingga
attacker tidak bisa mengukur waktu untuk menebak nilai context.

**Per-context replay isolation:** kode yang sama bisa dipakai paralel oleh
user/session berbeda tanpa saling memblokir — fitur penting untuk sistem
multi-tenant. Lihat skenario 7 di `genotp-tester` untuk contoh.

### OtpContextBuilder

API ergonomis untuk konstruksi context yang **canonical** (dua sisi yang
memberikan field sama menghasilkan bytes yang sama persis tanpa peduli urutan):

```rust
use genotp::OtpContext;

let ctx = OtpContext::builder()
    .ip("hash_of_ip_address")
    .device("device-uuid")
    .session("session-token")
    .origin("https://app.example.com")
    .custom("tenant", "acme")     // field custom, otomatis di-prefix "x-"
    .build();
```

Internal serialization: alfabetis berdasarkan key, format `key=value\0`. Dua
field yang berbeda value tapi "kelihatan" mirip tetap menghasilkan bytes
berbeda — separator `\0` tidak bisa di-spoof.

Free-form context (bytes mentah) — caller bertanggung jawab canonicalization:

```rust
let raw_ctx = OtpContext::from_bytes(b"any-bytes-you-want");
let empty = OtpContext::empty();   // backward-compat dengan RFC 6238
```

### Anti-Phishing Origin Binding

Method `.origin(url)` otomatis menormalisasi URL:
- huruf kecil seluruhnya
- buang path, query, fragment
- buang trailing slash
- pertahankan port

```rust
let ctx = OtpContext::builder()
    .origin("https://BANK.example.com/login?ref=email")
    .build();
// → internal: "origin=https://bank.example.com"
```

Attacker yang melakukan phishing di `https://bank-evil.com` → origin
otomatis berbeda → kode ditolak walaupun digit-nya benar.

---

## ClockSkewDetector

Untuk mendeteksi drift jam server vs jam authenticator user.

### Mode Passive (default — aman)

Hanya merekam statistik, tidak mengubah perilaku verifikasi:

```rust
use genotp::{ClockSkewDetector, SkewRecommendation};

let detector = ClockSkewDetector::new(256);   // simpan 256 sample terakhir

// Pakai verify_tracking di tempat verify biasa:
let ok = totp.verify_tracking(&code, None, 1, &detector).unwrap();

// Setelah cukup banyak verifikasi:
let report = detector.report();
match report.recommendation {
    SkewRecommendation::NoActionNeeded => {}
    SkewRecommendation::ConsistentDrift { mean } => {
        warn!("Jam server miring {mean:+.2} window vs user");
    }
    SkewRecommendation::WidenWindowOrCheckNtp => {
        warn!("Banyak hit di edge window — periksa NTP sync");
    }
    SkewRecommendation::InsufficientData => {}
}
```

### Mode Active (auto-adjust)

Detector otomatis menambahkan offset koreksi ke setiap verifikasi:

```rust
let detector = ClockSkewDetector::new(256);
detector.enable_auto_adjust();

// Lakukan verifikasi seperti biasa. Setelah ≥16 sample, kalau drift
// konsisten, offset internal akan disesuaikan otomatis.
totp.verify_tracking(&code, None, 1, &detector).unwrap();

println!("offset koreksi: {}", detector.current_offset());
```

**⚠️ Risiko:** mode active hanya disarankan kalau Anda yakin sumber sample
bersih (mis. cuma dari user yang sudah ter-autentikasi). Kalau attacker bisa
mempengaruhi sampling, mereka bisa men-skew offset server. Default OFF.

Operasi lain:

```rust
detector.is_auto_adjust();
detector.disable_auto_adjust();
detector.reset();
```

---

## Metrics

Counter atomik untuk observability:

```rust
use genotp::Metrics;
use std::sync::Arc;

let metrics = Arc::new(Metrics::new());

metrics.increment_totp_generation();
metrics.increment_totp_verification();
metrics.increment_error();

println!("Total TOTP generation: {}", metrics.get_totp_generations());
println!("Total error: {}", metrics.get_errors());
```

Caller-call pattern: Anda yang increment sesuai jalur kode. Library tidak
otomatis memanggil ini supaya tidak ada overhead untuk yang tidak butuh.

---

## Error Handling

Semua API yang bisa gagal mengembalikan `Result<T, GenOtpError>`:

```rust
pub enum GenOtpError {
    InvalidSecret,         // secret kosong, terlalu pendek, atau salah format
    InvalidCode,           // kode bukan digit atau salah panjang
    InvalidDigits,         // bukan 6, 7, atau 8
    InvalidAlgorithm,
    InvalidCounter,
    InvalidTime,           // jam sistem invalid (mis. sebelum 1970) atau window overflow
    VerificationFailed,
    RateLimited,
    ReplayAttack,
}
```

Implementasi `std::error::Error` dan `Display` (dengan feature `std`).

---

## Penggunaan no_std

genotp mendukung embedded / `no_std` dengan feature `alloc`:

```toml
genotp = { version = "0.1", default-features = false, features = ["alloc"] }
```

Fitur yang tersedia:
- `HOTP::new` / `generate` / `verify`
- `TOTP::new` / `generate(t: u64)` / `verify(code, t: u64, window)`
- `encode` / `decode` (Base32)

Tidak tersedia di no_std:
- `SystemTime` access (Anda harus pass `t: u64` eksplisit)
- `Verifier` (butuh `HashSet` dari std, untuk replay state)
- `OtpContext`, `ClockSkewDetector`, `Metrics`, `Builder`, `Helper`,
  `OtpAuthUri` (semua std-only)
