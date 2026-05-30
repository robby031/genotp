# genotp

Library OTP (One-Time Password) yang aman dan sesuai standar RFC 4226 (HOTP) dan RFC 6238 (TOTP).

## Fitur

- Implementasi HOTP (HMAC-based One-Time Password) sesuai RFC 4226
- Implementasi TOTP (Time-based One-Time Password) sesuai RFC 6238
- Dukungan algoritma hash: SHA1, SHA256, SHA512
- Konfigurasi jumlah digit (6-8)
- Toleransi drift waktu untuk TOTP
- Generasi kunci acak secara kriptografis (menggunakan ax-rnd)
- Encoding/decoding Base32 untuk kunci
- Generator URI otpauth:// untuk provisioning
- Perbandingan konstan-waktu untuk mencegah timing attacks
- Replay protection untuk mencegah penggunaan ulang kode
- Rate limiting untuk mencegah brute-force
- Builder pattern untuk konfigurasi yang mudah
- Helper functions untuk quick start
- Error handling yang detail dengan pesan
- Unit test dengan vektor uji RFC
- Property-based testing dengan proptest
- Performance benchmarking dengan criterion
- CI/CD pipeline untuk testing otomatis
- Thread-safe untuk concurrent usage
- Metrics untuk monitoring penggunaan
- Optimasi performa dengan caching
- Fuzz testing untuk security robustness
- Dynamic truncation sesuai standar

## Instalasi

Tambahkan ke `Cargo.toml`:

```toml
[dependencies]
genotp = "0.1.0"
```

### Feature Flags

Library ini mendukung feature flags untuk konfigurasi:

- `std` (default): Menggunakan standard library untuk SystemTime dan fitur lengkap
- `alloc` (default): Menggunakan alloc crate untuk Vec, String, dan format! macro
- `serde`: Mengaktifkan serialisasi/deserialisasi JSON untuk HOTP, TOTP, dan Algorithm
- `default`: Mengaktifkan `std` dan `alloc`

Untuk penggunaan no_std (embedded systems):

```toml
[dependencies]
genotp = { version = "0.1.0", default-features = false, features = ["alloc"] }
```

Untuk penggunaan dengan serde support:

```toml
[dependencies]
genotp = { version = "0.1.0", features = ["serde"] }
```

### no_std Support

Library ini mendukung `no_std` untuk embedded systems. Dalam mode no_std:

- **HOTP**: Berfungsi penuh tanpa std
- **TOTP**: Memerlukan parameter waktu secara eksplisit (tidak menggunakan SystemTime)
- **Modules yang di-disable**: provisioning, verification, builder, helpers, config, metrics (hanya tersedia dengan feature `std`)

Contoh penggunaan no_std:

```rust
use genotp::{HOTP, TOTP, Algorithm};

// HOTP berfungsi normal
let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35];
let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
let code = hotp.generate(0).unwrap();

// TOTP memerlukan waktu eksplisit
let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();
let code = totp.generate(1234567890).unwrap(); // Unix timestamp
let is_valid = totp.verify(&code, 1234567890, 1).unwrap();
```

## Quick Start

```rust
use genotp::{create_secret, generate_totp_default, verify_totp_default};

let secret = create_secret().unwrap();
let code = generate_totp_default(secret.clone()).unwrap();
println!("TOTP: {}", code);

let is_valid = verify_totp_default(secret, &code).unwrap();
println!("Valid: {}", is_valid);
```

## API

### Builder Pattern

```rust
use genotp::{HotpBuilder, TotpBuilder, Algorithm};

let hotp = HotpBuilder::new()
    .secret(vec
![0x31, 0x32, 0x33, 0x34, 0x35])
    .algorithm(Algorithm::SHA256)
    .digits(8)
    .build()
    .unwrap();

let totp = TotpBuilder::new()
    .secret(vec
![0x31, 0x32, 0x33, 0x34, 0x35])
    .algorithm(Algorithm::SHA512)
    .digits(6)
    .period(60)
    .build()
    .unwrap();
```

### HOTP

```rust
use genotp::{HOTP, Algorithm};

let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

let code = hotp.generate(0).unwrap();
println!("HOTP: {}", code);

let is_valid = hotp.verify(&code, 0).unwrap();
println!("Valid: {}", is_valid);
```

### TOTP

```rust
use genotp::{TOTP, Algorithm};

let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
let totp = TOTP::new(secret, Algorithm::SHA1, 6, 30).unwrap();

let code = totp.generate(None).unwrap();
println!("TOTP: {}", code);

let is_valid = totp.verify(&code, None, 1).unwrap();
println!("Valid: {}", is_valid);
```

### Helper Functions

```rust
use genotp::{generate_hotp_default, generate_totp_default, verify_hotp_default, verify_totp_default, create_secret};

let secret = create_secret().unwrap();
let code = generate_totp_default(secret.clone()).unwrap();
let is_valid = verify_totp_default(secret, &code).unwrap();
```

### Configuration

```rust
use genotp::{HotpConfig, TotpConfig, Algorithm};

let hotp_config = HotpConfig::new()
    .with_digits(8)
    .with_algorithm(Algorithm::SHA256);

let totp_config = TotpConfig::new()
    .with_digits(6)
    .with_period(60);
```

### Generasi Kunci

```rust
use genotp::KeyGenerator;

let secret = KeyGenerator::generate_default_secret().unwrap();
println!("Secret: {:?}", secret);

let secret_256 = KeyGenerator::generate_secret(256).unwrap();
println!("Secret 256-bit: {:?}", secret_256);
```

### Base32 Encoding

```rust
use genotp::{encode, decode};

let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35];
let encoded = encode(&secret);
println!("Encoded: {}", encoded);

let decoded = decode(&encoded).unwrap();
println!("Decoded: {:?}", decoded);
```

### Provisioning URI

```rust
use genotp::{OtpAuthUri, OtpType, Algorithm, KeyGenerator, encode};

let secret = KeyGenerator::generate_default_secret().unwrap();
let secret_b32 = encode(&secret);

let uri = OtpAuthUri::new(
    OtpType::TOTP,
    "MyService:user@example.com".to_string(),
    secret_b32,
)
.issuer("MyService".to_string())
.algorithm(Algorithm::SHA1)
.digits(6)
.period(30);

println!("URI: {}", uri.build());
```

**Google Authenticator Compatibility**

URI yang dihasilkan oleh library ini kompatibel dengan Google Authenticator dan aplikasi OTP lainnya:

- Format URI mengikuti standar `otpauth://`
- Mendukung parameter: `secret`, `issuer`, `algorithm`, `digits`, `period`, `counter`
- Mendukung algoritma: SHA1, SHA256, SHA512
- Label format: `Issuer:username` atau `username` saja
- Secret dalam format Base32 tanpa padding

Contoh URI yang dihasilkan:
```
otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30
```

### Verifikasi dengan Keamanan

```rust
use genotp::Verifier;

let verifier = Verifier::new(5);

let code = "123456";
let expected = "123456";

let is_valid = verifier.verify_with_replay_protection(code, expected);
println!("Valid: {}", is_valid);

let is_limited = verifier.is_rate_limited();
println!("Rate limited: {}", is_limited);
```

### Metrics

```rust
use genotp::Metrics;

let metrics = Metrics::new();
metrics.increment_hotp_generation();
metrics.increment_totp_generation();

println!("HOTP generations: {}", metrics.get_hotp_generations());
println!("TOTP generations: {}", metrics.get_totp_generations());
```

### Algoritma

```rust
use genotp::Algorithm;

let algo = Algorithm::SHA1;
let algo = Algorithm::SHA256;
let algo = Algorithm::SHA512;
```

### Serde Support

Dengan feature `serde`, struct HOTP, TOTP, dan Algorithm dapat diserialisasi/deserialisasi:

```rust
use genotp::{HOTP, TOTP, Algorithm};
use serde_json;

let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35];
let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();

// Serialize ke JSON
let json = serde_json::to_string(&hotp).unwrap();
println!("{}", json);

// Secret tidak disertakan dalam serialisasi untuk keamanan
```

## Parameter

- **digits**: 6-8 digit (default 6)
- **algorithm**: SHA1, SHA256, atau SHA512 (default SHA1)
- **period**: Periode waktu dalam detik untuk TOTP (default 30)
- **window**: Toleransi drift untuk verifikasi TOTP (default 1)
- **counter**: Counter awal untuk HOTP (default 0)
- **max_attempts**: Maksimal percobaan gagal sebelum rate limit (default 5)

## Keamanan

- Kunci dihasilkan menggunakan RNG kriptografis (ax-rnd)
- Menggunakan library HMAC yang teruji
- Dynamic truncation sesuai standar RFC
- Verifikasi dengan toleransi drift waktu
- Validasi input yang ketat
- Base32 encoding tanpa padding untuk URI
- Perbandingan konstan-waktu untuk mencegah timing attacks
- Replay protection untuk mencegah penggunaan ulang kode
- Rate limiting untuk mencegah brute-force attacks
- Error handling yang detail dengan pesan yang jelas
- Security audit dengan cargo-audit
- Thread-safe untuk concurrent usage
- **Zeroize**: Secret key otomatis di-zeroize saat struct di-drop untuk mencegah data bocor ke memory

## Performa

- HOTP generate: ~255 ns per operation
- HOTP verify: ~258 ns per operation
- TOTP generate: ~260 ns per operation
- TOTP verify: ~527 ns per operation
- Generate secret (default): ~19 ns per operation
- Generate secret (256-bit): ~21 ns per operation
- Base32 encode: ~62 ns per operation
- Base32 decode: ~55 ns per operation
- Provisioning URI (TOTP): ~256 ns per operation
- Provisioning URI (HOTP): ~256 ns per operation
- Replay protection verify: ~12 ns per operation
- Rate limiter contention (4 threads): ~38 µs per batch
- Concurrent verification (4 threads): ~63 µs per batch
- Load test: >10,000 ops/sec
- Thread-safe untuk concurrent operations

## Standar

- RFC 4226: HOTP Algorithm
- RFC 6238: TOTP Algorithm
- RFC 4648: Base32 Encoding

## Testing

```bash
# Unit tests
cargo test

# Property-based tests
cargo test --test property_test

# Concurrency tests
cargo test --test concurrency_test

# Load tests
cargo test --test load_test

# Performance benchmarks
cargo bench

# Fuzz testing
make fuzz
make fuzz-hotp
make fuzz-totp
make fuzz-base32
make fuzz-provisioning

# Security audit
cargo audit
```

## CI/CD

Library ini menggunakan GitHub Actions untuk:
- Unit testing otomatis
- Property-based testing
- Concurrency testing
- Load testing
- Performance benchmarking
- Security audit
- Code formatting check
- Clippy linting
- Fuzz testing untuk security

## Lisensi

MIT License