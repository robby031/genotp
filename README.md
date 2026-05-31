# genotp

[![Crates.io](https://img.shields.io/crates/v/genotp.svg)](https://crates.io/crates/genotp)
[![Docs.rs](https://docs.rs/genotp/badge.svg)](https://docs.rs/genotp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security-focused OTP library.
Full implementation of **HOTP (RFC 4226)** and **TOTP (RFC 6238)** plus
advanced features: **context binding**, **per-context replay isolation**, and
**clock skew detection**.

## Highlights

- ✅ Passes all RFC 4226 & RFC 6238 test vectors (SHA1/256/512)
- ✅ Replay protection + rate limiting with bounded memory
- ✅ Constant-time comparison to prevent timing attacks
- ✅ Automatic zeroize for secrets on drop
- ✅ **Context binding** — OTP codes bound to (IP, device, session, origin)
- ✅ **Per-context replay isolation** — code collisions between users don't block each other
- ✅ **Anti-phishing origin binding** — origin URL automatically normalized
- ✅ **Clock skew detector** with opt-in auto-adjust
- ✅ Compatible with Google Authenticator / Authy / Microsoft Authenticator (default mode)
- ✅ `no_std + alloc` support for embedded
- ✅ 125+ tests (unit, integration, property-based thousands of random cases, concurrent stress)

## Documentation

- 📘 **[docs/en/usage.md](./docs/en/usage.md)** — complete usage guide, all APIs + examples
- 🧭 **[docs/en/design.md](./docs/en/design.md)** — threat model, architecture, design decisions

## Installation

```toml
[dependencies]
genotp = "0.1"
```

## Basic Usage

### Standard TOTP (Google Authenticator compatible)

```rust
use genotp::{create_secret, generate_totp_default, verify_totp_default};

let secret = create_secret().unwrap();              // 160-bit random
let code = generate_totp_default(secret.clone()).unwrap();
let ok = verify_totp_default(secret, &code).unwrap();
assert!(ok);
```

### Builder pattern (more ergonomic)

```rust
use genotp::{Algorithm, TotpBuilder};

let totp = TotpBuilder::new()
    .secret(secret)
    .algorithm(Algorithm::SHA1)
    .digits(6)
    .period(30)
    .build()
    .unwrap();

let code = totp.generate(None).unwrap();       // use system time
let ok = totp.verify(&code, None, 1).unwrap(); // window ±1
```

### QR code for authenticator app

```rust
use genotp::{Algorithm, OtpAuthUri, OtpType, encode};

let uri = OtpAuthUri::new(
    OtpType::TOTP,
    "ACME:alice@example.com".to_string(),
    encode(&secret),
)
.issuer("ACME".to_string())
.algorithm(Algorithm::SHA1)
.digits(6)
.period(30)
.build();
// Render `uri` to QR code (e.g., with `qrcode` crate).
```

### Context binding — anti channel OTP intercept (flagship feature)

```rust
use genotp::{Algorithm, HOTP, OtpContext};

let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

// Server binds code to (session + IP hash) of user at issue time:
let ctx = OtpContext::builder()
    .session("login-abc123")
    .ip("hash_of_user_ip")
    .build();
let code = hotp.generate_bound(counter, &ctx).unwrap();
// Send `code` via any channel (SMS, email, WhatsApp, Telegram, push notif, ...).

// When user submits:
if hotp.verify_bound(&form.code, counter, &ctx).unwrap() {
    // ✓ code correct AND context matches
}
// Attacker who intercepts code from different IP/session → automatically rejected.
```

Details and other scenarios (TOTP binding, Mode 2 Verifier-stored, anti-phishing
origin binding, clock skew) in **[docs/en/usage.md](./docs/en/usage.md)**.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `std` | ✓ | SystemTime, Verifier, context binding, etc |
| `alloc` | ✓ | Heap types (String, Vec) |
| `serde` | — | Serialize for HOTP/TOTP/Algorithm (secret skipped) |

For embedded / no_std:

```toml
genotp = { version = "0.1", default-features = false, features = ["alloc"] }
```

## Testing

```bash
cargo test --all-features              # 125+ tests (unit + integration + property + stress)
cargo audit                            # CVE scan dependency tree
cargo deny check                       # license & supply chain
cargo +nightly miri test --lib         # undefined behavior / memory safety
```

## License

MIT — see [`LICENSE`](./LICENSE) (or `Cargo.toml`).
