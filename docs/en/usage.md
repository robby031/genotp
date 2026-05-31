# genotp Usage Guide

OTP (One-Time Password) library for Rust implementing RFC 4226 (HOTP)
and RFC 6238 (TOTP), plus advanced security features like context
binding and clock-skew detection.

---

## Table of Contents

- [Installation](#installation)
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
- [Context Binding (Flagship Feature)](#context-binding-flagship-feature)
  - [Mode 1 — HMAC Binding](#mode-1--hmac-binding)
  - [Mode 2 — Verifier-Stored](#mode-2--verifier-stored)
  - [OtpContextBuilder](#otpcontextbuilder)
  - [Anti-Phishing Origin Binding](#anti-phishing-origin-binding)
- [ClockSkewDetector](#clockskewdetector)
- [Metrics](#metrics)
- [Error Handling](#error-handling)
- [no_std Usage](#no_std-usage)

---

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
genotp = "0.1"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `std` | ✓ | Access to `SystemTime` (system time), `Verifier`, `OtpContext`, `ClockSkewDetector`, `Metrics`, `OtpAuthUri`, `Builder`, `Helper`. Required for most server usage. |
| `alloc` | ✓ | Heap-allocated types (`String`, `Vec`). Required by HOTP/TOTP. |
| `serde` | — | `Serialize` implementation for HOTP, TOTP, and `Algorithm`. Useful for configuration/logging. Secret **not serialized** for security reasons. |

For embedded / no_std:

```toml
[dependencies]
genotp = { version = "0.1", default-features = false, features = ["alloc"] }
```

---

## Quick Start

```rust
use genotp::{create_secret, generate_totp_default, verify_totp_default};

// 1. Generate 160-bit secret (RFC 6238 recommended length)
let secret = create_secret().unwrap();

// 2. Generate 6-digit TOTP, 30-second period, SHA1
let code = generate_totp_default(secret.clone()).unwrap();
println!("TOTP code: {code}");

// 3. Verify with ±1 step window
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

Parameters:
- `secret`: minimum length ≥ 1 byte. Recommended 160-bit (20 bytes).
- `algorithm`: `Algorithm::SHA1`, `SHA256`, or `SHA512`.
- `digits`: 6, 7, or 8.

### HOTP look-ahead resynchronization

Practical issue: users sometimes press the generate button on a hardware
token / app multiple times without submitting (accidentally, or misclick).
The user's counter advances ahead of the server's. Without look-ahead,
all subsequent codes would be rejected.

RFC 4226 §7.4 defines **look-ahead resynchronization**: the server tries
several future counters (`counter`, `counter+1`, ..., `counter+s`). The
`verify_with_resync` method implements this:

```rust
let mut stored_counter: u64 = 10;  // server's last stored counter
let user_code = "...";

match hotp.verify_with_resync(user_code, stored_counter, 5).unwrap() {
    Some(matched) => {
        // MUST: update stored counter to matched + 1 so this code
        // cannot be replayed.
        stored_counter = matched + 1;
        println!("Login OK, new counter: {stored_counter}");
    }
    None => {
        println!("Invalid code or outside look-ahead window");
    }
}
```

**Choosing `look_ahead`:**
- Too small → users who accidentally clicked multiple times get locked out
- Too large → widens the brute-force window (attacker gets `look_ahead+1`×
  chance per submission)
- Recommended **3-10** for most use cases

**Counter-update contract (mandatory):** if the caller does NOT update
the stored counter to `matched + 1`, an attacker who intercepts one code
can replay it multiple times within the look-ahead window. See
[`docs/design.md`](./design.md) for security trade-off details.

---

## TOTP

TOTP (RFC 6238) — time-based OTP. Counter calculated from `time / period`.

```rust
use genotp::{Algorithm, TOTP};

let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

// Generate using system time (None) or explicit timestamp.
let code = totp.generate(None).unwrap();

// Verify with ±1 step window (30-second tolerance each direction).
let ok = totp.verify(&code, None, 1).unwrap();
```

Parameters:
- `period`: window length in seconds (common: 30).
- `window`: how many steps forward/backward tolerated (common: 1).

**Important about time zones:** TOTP based on Unix epoch UTC. Whatever
user's time zone (WIB/WITA/WIT), calculation always uses seconds since
`1970-01-01 00:00:00 UTC`. If OTP verification fails, check server clock
(NTP), not time zone.

---

## Builder Pattern

More convenient than positional constructor:

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

Shortcut for default configuration (SHA1, 6 digits, period 30):

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

Two variants: **heap-allocated** (for std/hosted) and **stack-friendly**
(for embedded / no_std).

### Heap-allocated (std)

```rust
use genotp::KeyGenerator;

// 160-bit (RFC 4226 recommendation)
let secret = KeyGenerator::generate_default_secret().unwrap();

// Custom bit length (must be multiple of 8, minimum 128)
let secret_256 = KeyGenerator::generate_secret(256).unwrap();
```

⚠️ **Important about returned `Vec<u8>`:** the Vec is **not** automatically
zeroized on drop. Two scenarios:

- **Safe**: if you immediately move it into `HOTP::new` / `TOTP::new`
  (ownership transfers, those structs Zeroize on drop).
- **Leak**: if you keep the Vec as a local variable that drops normally
  without being passed to HOTP/TOTP, secret remnants persist in RAM
  until the allocator overwrites that memory.

For the latter case, wrap with `zeroize::Zeroizing`:

```rust
use zeroize::Zeroizing;
let secret = Zeroizing::new(KeyGenerator::generate_secret(160).unwrap());
// Access via &*secret. Auto-zeroize on drop, guaranteed no RAM remnants.
```

### Stack-friendly (no_std / embedded)

For embedded contexts where every heap alloc is waste and causes
fragmentation, use `fill_secret` with a buffer you allocate yourself
(stack or static):

```rust
use genotp::{KeyGenerator, DEFAULT_SECRET_BYTES};

// Stack buffer — zero heap alloc, no_std-friendly.
let mut secret = [0u8; DEFAULT_SECRET_BYTES];   // = 20 bytes
KeyGenerator::fill_secret(&mut secret).unwrap();

// ... use secret ...

// For explicit zeroize when done:
use zeroize::Zeroize;
secret.zeroize();
```

Validation: `fill_secret` rejects buffers < `MIN_SECRET_BYTES` (16 bytes / 128 bit).

Entropy source: `getrandom` (OS-backed CSPRNG: `getrandom(2)` on Linux,
`arc4random_buf` on macOS, `BCryptGenRandom` on Windows).

---

## Base32 Encoding

For QR code / display to user:

```rust
use genotp::{encode, decode};

let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f];
let b32 = encode(&bytes);              // "JBSWY3DP"
let back = decode(&b32).unwrap();
assert_eq!(bytes, back);
```

Standard RFC 4648 encoding, without padding (Google Authenticator compatible).

---

## Provisioning URI & QR Code

Generate `otpauth://` URI for scanning by authenticator app:

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

All labels, issuers, and secrets automatically **percent-encoded** per RFC 3986
so special characters (`:`, `@`, space, `&`, etc.) don't break URI.

Render to QR code (with `qrcode` crate):

```rust
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

let qr = QrCode::new(uri.as_bytes()).unwrap();
let rendered = qr.render::<Dense1x2>().build();
println!("{rendered}");
```

---

## Verifier — Replay & Rate Limit

`Verifier` handles two common attacks:

1. **Replay attack** — code already used cannot be accepted again.
2. **Brute force** — after `max_attempts` failed attempts, system locks.

```rust
use genotp::Verifier;

let verifier = Verifier::new(5);   // max 5 failed attempts

let user_submitted = "123456";
let expected = totp.generate(None).unwrap();

if verifier.verify_with_replay_protection(user_submitted, &expected) {
    println!("Login OK");
} else if verifier.is_rate_limited() {
    println!("Account locked");
} else {
    println!("Wrong code");
}
```

Memory capacity control for `used_codes`:

```rust
// Default: 10,000 last codes. When full, set automatically cleared
// (old codes irrelevant after TOTP window passes).
let verifier = Verifier::with_capacity(5, 1000);
```

Additional operations:

```rust
verifier.is_rate_limited();      // check rate limit status
verifier.reset_attempts();       // reset counter (e.g., after admin verify)
verifier.clear_used_codes();     // manually clear replay-set
```

`Verifier` implements `Clone` (shared state via `Arc`) so safe to use
from multiple threads.

---

## Context Binding (Flagship Feature)

**Problem:** Standard OTP (RFC 6238) only depends on `(secret, counter)`.
Once 6-digit code leaks — intercepted from channel delivery (SMS, email,
WhatsApp, Telegram, push notification), phished, brute-forced — anyone with
code can use it.

**genotp solution:** bind OTP to additional context (IP, device, session, origin
URL). Attacker with code but different context automatically rejected.

Two modes available.

### Mode 1 — HMAC Binding

OTP code itself **cryptographically** differs for different context.
Anti channel OTP intercept (SMS, email, WhatsApp, Telegram, push notification, etc.).

```rust
use genotp::{Algorithm, HOTP, OtpContext};

let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

// Server side: bind to session + user IP at login request time.
let issued_ctx = OtpContext::builder()
    .session("login-abc123")
    .ip(&sha256_hex(user_ip))     // hash IP so not leaked in logs
    .build();

let code = hotp.generate_bound(counter, &issued_ctx).unwrap();
// Deliver via any channel (SMS, email, WhatsApp, Telegram, push notification, ...).
send_via_channel(user_phone, &code);
```

When user submits form:

```rust
let request_ctx = OtpContext::builder()
    .session(&form.session_id)
    .ip(&sha256_hex(request_ip))
    .build();

if hotp.verify_bound(&form.code, counter, &request_ctx).unwrap() {
    // Success: code correct AND context matches.
}
```

**Real effect:** attacker who intercepts code from channel delivery (e.g.
SIM swap to read SMS, email/Telegram backup compromise, push intercept), then
tries to submit from different IP → server computes HMAC with attacker context
→ computed digits differ from intercepted → reject. Brute force 0000-9999
**from attacker context** also useless.

For TOTP:

```rust
let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
let code = totp.generate_bound(&ctx, None).unwrap();
let ok = totp.verify_bound(&code, &ctx, None, 1).unwrap();   // window=1
```

**Backward compatible:** if context empty (`OtpContext::empty()`), result
identical to standard RFC TOTP/HOTP. Can use with Google Authenticator.

### Mode 2 — Verifier-Stored

For scenarios where user uses standard authenticator app (Google
Authenticator, Authy) — code remains RFC 6238, but server binds context
to verification process.

```rust
use genotp::{OtpContext, Verifier};

let verifier = Verifier::new(5);

// When user requests challenge / submits form:
let issued_ctx = OtpContext::builder()
    .session("browser-tab-X")
    .ip(&sha256_hex(user_ip))
    .build();

// Server stores issued_ctx (e.g., in Redis with nonce).
// User uses authenticator app, gets 6-digit code, submits to server.

let request_ctx = OtpContext::builder()
    .session(&form.session_id)
    .ip(&sha256_hex(request_ip))
    .build();

let expected = totp.generate(None).unwrap();   // standard TOTP

let ok = verifier.verify_with_context(
    &form.code,
    &expected,
    &issued_ctx,
    &request_ctx,
);
```

Context comparison done **constant-time** (via `subtle`) so attacker
cannot measure time to guess context value.

**Per-context replay isolation:** same code can be used in parallel by
different user/session without blocking each other — important feature
for multi-tenant systems. See scenario 7 in `genotp-tester` for example.

### OtpContextBuilder

Ergonomic API for constructing **canonical** context (two sides providing
same fields produce exactly same bytes regardless of order):

```rust
use genotp::OtpContext;

let ctx = OtpContext::builder()
    .ip("hash_of_ip_address")
    .device("device-uuid")
    .session("session-token")
    .origin("https://app.example.com")
    .custom("tenant", "acme")     // custom field, auto-prefixed "x-"
    .build();
```

Internal serialization: alphabetical by key, format `key=value\0`. Two
fields with different values but "look" similar still produce different
bytes — separator `\0` cannot be spoofed.

Free-form context (raw bytes) — caller responsible for canonicalization:

```rust
let raw_ctx = OtpContext::from_bytes(b"any-bytes-you-want");
let empty = OtpContext::empty();   // backward-compat with RFC 6238
```

### Anti-Phishing Origin Binding

Method `.origin(url)` automatically normalizes URL:
- all lowercase
- remove path, query, fragment
- remove trailing slash
- preserve port

```rust
let ctx = OtpContext::builder()
    .origin("https://BANK.example.com/login?ref=email")
    .build();
// → internal: "origin=https://bank.example.com"
```

Attacker phishing at `https://bank-evil.com` → origin automatically
different → code rejected even if digits correct.

---

## ClockSkewDetector

To detect drift between server clock and user authenticator clock.

### Passive Mode (default — safe)

Only records statistics, doesn't change verification behavior:

```rust
use genotp::{ClockSkewDetector, SkewRecommendation};

let detector = ClockSkewDetector::new(256);   // store 256 last samples

// Use verify_tracking instead of regular verify:
let ok = totp.verify_tracking(&code, None, 1, &detector).unwrap();

// After enough verifications:
let report = detector.report();
match report.recommendation {
    SkewRecommendation::NoActionNeeded => {}
    SkewRecommendation::ConsistentDrift { mean } => {
        warn!("Server clock skewed {mean:+.2} window vs user");
    }
    SkewRecommendation::WidenWindowOrCheckNtp => {
        warn!("Many hits at window edge — check NTP sync");
    }
    SkewRecommendation::InsufficientData => {}
}
```

### Active Mode (auto-adjust)

Detector automatically adds correction offset to each verification:

```rust
let detector = ClockSkewDetector::new(256);
detector.enable_auto_adjust();

// Perform verification as usual. After ≥16 samples, if drift
// consistent, internal offset will auto-adjust.
totp.verify_tracking(&code, None, 1, &detector).unwrap();

println!("correction offset: {}", detector.current_offset());
```

**⚠️ Risk:** active mode only recommended if you're confident sample source
is clean (e.g., only from already authenticated users). If attacker can
influence sampling, they can skew server offset. Default OFF.

Other operations:

```rust
detector.is_auto_adjust();
detector.disable_auto_adjust();
detector.reset();
```

---

## Metrics

Atomic counters for observability:

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

Caller-call pattern: you increment according to code path. Library doesn't
automatically call this to avoid overhead for those who don't need it.

---

## Error Handling

All fallible APIs return `Result<T, GenOtpError>`:

```rust
pub enum GenOtpError {
    InvalidSecret,         // secret empty, too short, or wrong format
    InvalidCode,           // code not digits or wrong length
    InvalidDigits,         // not 6, 7, or 8
    InvalidAlgorithm,
    InvalidCounter,
    InvalidTime,           // system clock invalid (e.g., before 1970) or window overflow
    VerificationFailed,
    RateLimited,
    ReplayAttack,
}
```

Implements `std::error::Error` and `Display` (with `std` feature).

---

## no_std Usage

genotp supports embedded / `no_std` with `alloc` feature:

```toml
genotp = { version = "0.1", default-features = false, features = ["alloc"] }
```

Available features:
- `HOTP::new` / `generate` / `verify`
- `TOTP::new` / `generate(t: u64)` / `verify(code, t: u64, window)`
- `encode` / `decode` (Base32)

Not available in no_std:
- `SystemTime` access (you must pass explicit `t: u64`)
- `Verifier` (needs `HashSet` from std, for replay state)
- `OtpContext`, `ClockSkewDetector`, `Metrics`, `Builder`, `Helper`,
  `OtpAuthUri` (all std-only)
