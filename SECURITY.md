# Security Considerations

This document outlines security considerations and best practices when using the genotp library.

## Table of Contents

- [Secret Key Management](#secret-key-management)
- [Memory Safety](#memory-safety)
- [Timing Attacks](#timing-attacks)
- [Replay Protection](#replay-protection)
- [Rate Limiting](#rate-limiting)
- [Algorithm Selection](#algorithm-selection)
- [URI Security](#uri-security)
- [Best Practices](#best-practices)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)

## Secret Key Management

### Generation

- **Cryptographically Secure RNG (OS-backed)**: The library uses `getrandom`,
  which calls the OS-provided CSPRNG directly: `getrandom(2)` on Linux,
  `arc4random_buf` on macOS / *BSD, `BCryptGenRandom` on Windows. This is the
  same primitive used by `rand::OsRng`, `ring`, `rustls`, and `argon2`.
  No userspace PRNG (fastrand, ax-rnd, SmallRng, etc.) is used — those are
  non-cryptographic and would let an attacker who knows roughly when the
  secret was generated brute-force the seed in milliseconds.
- **Minimum Key Length**: Use at least 128-bit (16 bytes) secrets for HOTP/TOTP
- **Recommended Key Length**: Use 256-bit (32 bytes) secrets for better security
- **Never Reuse Secrets**: Each user/service should have a unique secret

### Storage

- **Encrypt at Rest**: Store secrets encrypted in your database
- **Use Key Management Service**: Consider using a KMS for managing encryption keys
- **Access Control**: Restrict access to secrets to authorized personnel only
- **Audit Logs**: Log all access to secret keys

### Transmission

- **Use HTTPS**: Always transmit secrets over encrypted connections
- **Avoid Email**: Never send secrets via email or other insecure channels
- **Secure Channels**: Use secure channels for initial secret provisioning

## Memory Safety

### Zeroize

The library automatically zeroizes secret keys when structs are dropped:

```rust
use genotp::HOTP;

let secret = vec
![0x31, 0x32, 0x33, 0x34, 0x35];
let hotp = HOTP::new(secret, Algorithm::SHA1, 6).unwrap();
// Secret is automatically zeroized when hotp goes out of scope
```

### Implementation Details

- **Drop Trait**: HOTP and TOTP structs implement `Drop` to zeroize secrets
- **Zeroize Crate**: Uses the `zeroize` crate for secure memory clearing
- **No Persistence**: Secrets are never persisted to disk or logs

### Recommendations

- **Minimize Lifetime**: Keep secret lifetime as short as possible
- **Avoid Cloning**: Don't clone secret keys unnecessarily
- **Secure Containers**: Use secure containers for sensitive operations

## Timing Attacks

### Constant-Time Comparison

The library uses constant-time comparison for code verification:

```rust
use genotp::constant_time::constant_time_eq;

let is_valid = constant_time_eq(code, expected);
```

### Protection Against

- **Timing Side Channels**: Code comparison time is independent of input
- **Cache Timing**: Constant-time operations prevent cache timing attacks
- **Branch Prediction**: Avoids branches that could leak information

### Implementation

- **subtle Crate**: Uses the `subtle` crate for constant-time operations
- **No Early Returns**: Comparison completes even after mismatch detection
- **Fixed-Time Operations**: All operations take the same time regardless of input

## Replay Protection

### Built-in Features

The library provides replay protection through the `Verifier` struct:

```rust
use genotp::Verifier;

let verifier = Verifier::new(5);
let is_valid = verifier.verify_with_replay_protection(code, expected);
```

### How It Works

- **Code Tracking**: Tracks used codes to prevent reuse
- **Time Window**: Codes are only valid within a specific time window
- **Automatic Cleanup**: Old codes are automatically removed from tracking

### Best Practices

- **Enable Replay Protection**: Always use replay protection in production
- **Configure Window**: Set appropriate time window for your use case
- **Monitor Attempts**: Track and alert on replay attempts

## Rate Limiting

### Built-in Features

The `Verifier` struct includes rate limiting:

```rust
use genotp::Verifier;

let verifier = Verifier::new(5);
let is_limited = verifier.is_rate_limited();
```

### Protection Against

- **Brute Force**: Limits the number of failed verification attempts
- **DoS Attacks**: Prevents denial of service through excessive requests
- **Account Lockout**: Configurable lockout after failed attempts

### Configuration

- **Max Attempts**: Configure maximum allowed failed attempts
- **Lockout Duration**: Set appropriate lockout duration
- **Per-User Limits**: Implement per-user rate limiting

## Algorithm Selection

### Supported Algorithms

- **SHA1**: Default, widely supported, but consider deprecated for new systems
- **SHA256**: Recommended for new implementations
- **SHA512**: Highest security, but may not be supported by all clients

### Recommendations

- **Use SHA256+**: Prefer SHA256 or SHA512 for new implementations
- **Check Client Support**: Verify client supports chosen algorithm
- **Plan Migration**: Have a migration plan if using SHA1

### Performance Considerations

- **SHA1**: Fastest, but least secure
- **SHA256**: Good balance of speed and security
- **SHA512**: Slower, but most secure

## URI Security

### otpauth:// URIs

The library generates `otpauth://` URIs for provisioning:

```rust
use genotp::{OtpAuthUri, OtpType};

let uri = OtpAuthUri::new(
    OtpType::TOTP,
    "Service:user@example.com".to_string(),
    secret_b32,
);
```

### Security Considerations

- **Secret in URI**: The secret is included in the URI (required by standard)
- **Transmission**: Use QR codes or secure channels for URI transmission
- **Short Lifetime**: Generate URIs with short expiration when possible
- **Access Control**: Restrict who can generate and view URIs

### Best Practices

- **HTTPS Only**: Never transmit URIs over unencrypted connections
- **QR Code Security**: Display QR codes securely, not in public areas
- **One-Time Use**: Generate new URIs for each provisioning event
- **Audit Logging**: Log URI generation events

## Best Practices

### General

1. **Use Latest Version**: Always use the latest version of the library
2. **Keep Dependencies Updated**: Regularly update dependencies
3. **Security Audits**: Perform regular security audits
4. **Penetration Testing**: Conduct penetration testing
5. **Code Review**: Have code reviewed by security experts

### Implementation

1. **Validate Input**: Always validate user input
2. **Error Handling**: Implement proper error handling
3. **Logging**: Log security-relevant events
4. **Monitoring**: Monitor for suspicious activity
5. **Incident Response**: Have an incident response plan

### Deployment

1. **Environment Separation**: Separate development, staging, and production
2. **Access Control**: Implement proper access controls
3. **Network Security**: Use firewalls and network segmentation
4. **Regular Backups**: Maintain regular, secure backups
5. **Disaster Recovery**: Have a disaster recovery plan

## Reporting Vulnerabilities

### How to Report

If you discover a security vulnerability, please report it responsibly:

1. **Email**: Send details to security@example.com
2. **PGP Key**: Use the PGP key provided for encrypted communication
3. **Expected Response**: Expect a response within 48 hours
4. **Coordinated Disclosure**: We follow coordinated disclosure practices

### What to Include

- **Description**: Detailed description of the vulnerability
- **Impact**: Potential impact of the vulnerability
- **Reproduction**: Steps to reproduce the vulnerability
- **Proof of Concept**: Proof of concept (if applicable)
- **Suggested Fix**: Suggested fix or mitigation (if known)

### Disclosure Policy

- **Private Disclosure**: Vulnerabilities are disclosed privately first
- **Patch Timeline**: Patches are released within a reasonable timeframe
- **Public Disclosure**: Public disclosure after patch is available
- **Credit**: Credit is given to reporters in security advisories

## Additional Resources

- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4648 - Base32](https://tools.ietf.org/html/rfc4648)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

## Version History

- **0.1.0**: Initial release with security features
  - Zeroize support for memory safety
  - Constant-time comparison
  - Replay protection
  - Rate limiting
  - Google Authenticator compatibility
