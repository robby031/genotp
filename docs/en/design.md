# genotp Design & Security Model

This document explains **why** genotp is built this way —
architectural decisions, threat models addressed, and trade-offs chosen.

For **how to use it**, see [usage.md](./usage.md).

---

## Table of Contents

- [Goals & Non-Goals](#goals--non-goals)
- [Threat Model](#threat-model)
- [Module Architecture](#module-architecture)
- [Cryptographic Decisions](#cryptographic-decisions)
- [Context Binding — Design](#context-binding--design)
- [Replay Protection — Design](#replay-protection--design)
- [Rate Limiting](#rate-limiting)
- [ClockSkewDetector — Design](#clockskewdetector--design)
- [no_std Support Strategy](#no_std-support-strategy)
- [API Stability Promises](#api-stability-promises)
- [Trade-offs Not Taken](#trade-offs-not-taken)

---

## Goals & Non-Goals

### Goals

1. **Correct and proven RFC 4226 / 6238 implementation.**
   Passes all RFC test vectors + thousands of randomized property tests.

2. **Secure against real practical attacks** — not just theoretical.
   Real-world scenarios users face (channel OTP intercept, brute force
   short codes, phishing) must be handled by design, not documentation.

3. **Ergonomic API for idiomatic Rust.** Builder pattern, `Result` in
   all fallible operations, `Send + Sync` where relevant, no
   panic-by-default in library code.

4. **Absolute backward compatibility with popular authenticator apps**
   (Google Authenticator, Authy, Microsoft Authenticator).

5. **no_std + alloc support** for embedded.

### Non-Goals

- **Not a complete auth framework.** No user management, session tokens,
  database adapters. genotp is an OTP primitive — you compose the auth
  pipeline yourself.
- **Not an SMS/Email gateway.** The library does not send OTP via any
  channel. Caller is responsible for delivery.
- **Not a WebAuthn / FIDO2 replacement.** For highest security, use
  hardware keys. genotp is a practical layer for scenarios where TOTP
   /HOTP are still relevant.

---

## Threat Model

genotp is designed to withstand the following threats. Each defense
mentions its module.

### A. Active network / on-path attacker

- **Replay attack** — attacker captures valid code then resends it.
  → Verifier stores replay-set, code can only be used once.

- **Phishing** — attacker creates fake domain, user submits OTP there,
  attacker immediately uses it on real site.
  → Mode 1 binding with `.origin()` field — attacker's origin differs,
  HMAC produces different digits, real site rejects.

- **Channel intercept (SMS / email / WhatsApp / Telegram / push notification)**
  — attacker reads OTP message sent to victim (e.g., SIM swap, read
  notification, cloud backup access, mailbox compromise, etc.).
  → Mode 1 binding with `.ip()` + `.session()` — code only valid for
  context bound by server at issue time.

### B. Local / online brute force attacker

- **Brute force short codes (4 digits, 10,000 possibilities)** — especially
  for OTP channels (not TOTP).
  → Rate limit at Verifier; when combined with Mode 1 binding,
  brute force from attacker's context never succeeds even if all
  10,000 are tried.

- **Timing attack on code comparison** — attacker measures response time
  to guess digit per position.
  → `subtle::ConstantTimeEq` in all code and context comparisons.

### C. Attacker with memory / process access

- **Recover secret from heap** — after TOTP/HOTP is dropped, secret
  byte remnants can be taken from memory.
  → `zeroize` in `Drop` for `secret`.

- **Side-channel cache** — acknowledged as out-of-scope for general-purpose
  library; mitigation requires lower layer (hardware key, enclave, etc.).

### D. Internal system attacker (misconfig)

- **Wrong secret length causes silent downgrade** — `generate_secret(129)`
  used to round to 128-bit without warning.
  → Validation `bit_length % 8 != 0` + minimum 128-bit.

- **Wrong serde configuration** — secret gets serialized to JSON.
  → `#[serde(skip)]` on secret field + no `Deserialize` impl
  (preventing newly deserialized struct from having empty secret
  that produces wrong code silently).

### E. Passive attacker reading logs/errors

- **Leak secret or context via error messages.**
  → `GenOtpError` never contains secret or context. Error messages
  are categorical (`InvalidSecret`, not "secret X invalid").

---

## Module Architecture

```
genotp/
├── algorithm        — enum Algorithm (SHA1/256/512)
├── base32           — encode/decode RFC 4648 without padding
├── constant_time    — wrapper `subtle::ConstantTimeEq` for &str
├── error            — GenOtpError + Display + std::error::Error
├── key              — KeyGenerator (CSPRNG via getrandom / OS entropy)
├── hotp             — HOTP::{new, generate, verify, generate_bound, verify_bound}
├── totp             — TOTP::{new, generate, verify, *_bound, verify_tracking}
├── builder          — TotpBuilder, HotpBuilder
├── config           — TotpConfig, HotpConfig (configuration structs)
├── helpers          — generate_*_default, verify_*_default, create_secret
├── provisioning     — OtpAuthUri (otpauth:// URL generator)
├── verification     — Verifier (replay + rate limit + context-aware)
├── metrics          — Metrics (atomic counter observability)
├── context          — OtpContext + OtpContextBuilder ⭐
└── skew             — ClockSkewDetector + SkewReport ⭐
```

⭐ = modules that differentiate genotp from other Rust OTP libraries.

Module dependencies: arrow direction is one-way, no cycles.

```
helpers ──┐
builder ──┼──> hotp / totp ──> algorithm, base32, constant_time, error
config  ──┘                        │
                                    └──> context (if using *_bound)
verification ──> constant_time, error, context
provisioning ──> algorithm, percent-encoding
skew ──> (standalone)
metrics ──> (standalone)
```

---

## Cryptographic Decisions

### HMAC variants

Following RFC 6238: SHA1 must be supported, SHA256/SHA512 optional. genotp
supports all three. SHA1 remains default because Google Authenticator
and Authy default to SHA1.

**Note:** SHA1 in the context of HMAC-OTP is not affected by collision
attack on plain SHA1 (chosen-prefix). HMAC-SHA1 with secret key
remains secure for OTP — formal proof in [RFC 6151].

### Dynamic truncation

Implementation follows RFC 4226 §5.3 verbatim:

```
offset = hmac[len-1] & 0x0f
binary = (hmac[offset]   & 0x7f) << 24
       | (hmac[offset+1])        << 16
       | (hmac[offset+2])        << 8
       | (hmac[offset+3])
code   = binary % 10^digits
```

Bit `& 0x7f` is sign bit masking — RFC mandates this so conversion to
integer in other languages (which might be signed-only) remains consistent.

### Constant-time comparison

All comparisons touching secret or context are done with
`subtle::ConstantTimeEq`. Module `constant_time` wraps for `&str`.
Verifier also compares context bytes with `ct_eq`.

Important: branching after comparison still happens after both comparisons
complete to prevent short-circuit early-return that could leak
"wrong context" vs "wrong code":

```rust
let ctx_match  = issued_ctx.ct_eq(request_ctx).into();
let code_match = constant_time_eq(code, expected);
if !(ctx_match && code_match) { /* fail */ }
```

### Zeroize

`TOTP::secret` and `HOTP::secret` are `Vec<u8>` with `Drop` impl that
calls `zeroize::Zeroize`. Ensures secret in heap is zeroed when
struct is dropped, before allocator returns memory to pool.

### Entropy source

`getrandom::fill` (OS-backed CSPRNG: `getrandom(2)` on Linux, `arc4random_buf`
on macOS / *BSD, `BCryptGenRandom` on Windows). The `getrandom` crate is the
de-facto standard in Rust for cryptographic entropy — used by `rand::OsRng`,
`ring`, `rustls`, `argon2`, etc. No userspace PRNG (fastrand, SplitMix,
xoshiro) in the library — if the OS does not provide entropy, the library
fails (acceptable: no fallback weaker than OS RNG allowed).

---

## Context Binding — Design

genotp's flagship feature. Two modes with different trade-offs.

### Why two modes?

Comparison table:

| Aspect | Mode 1 (HMAC binding) | Mode 2 (Verifier-stored) |
|---|---|---|
| Code output | Different for different context | RFC 6238 standard |
| Google Auth compatible | No (server-only OTP) | Yes |
| Strength against intercept | Maximum (cryptographic) | Medium (server check) |
| Strength against context spoof | Maximum | Medium (caller must authenticate context) |
| Use case | Channel OTP (SMS/email/WA/Telegram/push) | TOTP app authenticator |

Mode 1 is stronger because context enters HMAC — attacker who knows
6-digit code from channel but doesn't know server context used cannot
derive valid code for their context. Mode 2 is more practical because
it still uses standard authenticator apps.

### HMAC binding format (Mode 1)

```
HMAC(secret, counter_be64 || "genotp-ctx-v1\0" || context_bytes)
```

If `context_bytes` is empty, tag and context are **not** updated to HMAC,
so result is identical to standard RFC 6238. This property is validated
with property test `empty_context_equals_standard_totp`.

**Why version tag `"genotp-ctx-v1\0"`?**

- Prevents cross-version forgery: if binding format ever changes
  (e.g., v2 adds HKDF in middle), v1-generated codes won't
  match v2 implementation.
- Null terminator (`\0`) prevents ambiguity if tag is ever extended.
- Included **between** counter and context, so (counter,
  context) different produce unambiguous HMAC input.

**Why not HKDF?**

Alternative approach: derive per-context key with HKDF, then HMAC
counter. More "clean" academically, but:
- 2× HMAC vs 1× HMAC per operation.
- No additional security benefit for our use case (HMAC with
  well-defined boundary input is already secure).
- Makes backward-compat with empty context harder.

Trade-off: we chose simple HMAC append. If future needs change,
version tag enables migration.

### Context serialization format (Builder)

`OtpContextBuilder` uses `BTreeMap<String, String>` (sorted) and
serializes to:

```
key1=value1\0key2=value2\0...\0
```

**Guaranteed properties:**

1. **Deterministic** — setter order doesn't affect output (BTreeMap
   sorted by key).
2. **Unambiguous** — separator `\0` cannot be spoofed by content
   because text input cannot contain `\0` in practice (if needed,
   user can use `OtpContext::from_bytes` for custom format).
3. **Built-in fields have fixed prefix** (`ip`, `device`, `session`,
   `origin`); custom prefixed with `x-` to prevent future version conflicts.

See property test `context_builder_setter_order_invariant` for proof.

### Origin normalization

`.origin(url)` performs:
1. trim whitespace, lowercase
2. remove fragment (`#...`)
3. remove query (`?...`)
4. remove path after host
5. remove trailing slash

Result: only `scheme://host[:port]`. Port preserved because considered
part of authority origin.

**Not done:**
- IDN normalization (Punycode) — out of scope, user expected to provide
  origin in consistent format.
- URL syntax validation — input assumed valid; library only normalizes
  commonly problematic parts.

---

## Replay Protection — Design

### Per-context replay key

Replay-set in Verifier stores key:

```
replay_key(code, context_bytes) = code_bytes || 0x00 || context_bytes
```

**Why per-context?**

Consider multi-user system with 100,000 active users. Probability of two
users getting same 6 digits in 30-second TOTP window is non-zero (collision
~1 in 10^6 per window per user pair). Without per-context isolation,
one successful user would **block another valid user** with same code.

With `replay_key(code, ctx_a) ≠ replay_key(code, ctx_b)`, both users can
succeed in parallel; their respective replay attempts still caught.

This property is validated:
- property test: `verifier_per_context_isolation`
- concurrent stress: `verifier_per_context_isolation_under_contention`
  (100 threads, 100 unique contexts, same code → all 100 succeed)

### Bounded memory

`used_codes: HashSet<Vec<u8>>` can grow unbounded in long-running systems.
Mitigation: `max_used_codes` (default 10,000). When set full, **clear
entire set** before next insert.

**Why clear-all and not LRU?**

- LRU needs additional insertion order tracking; doubled memory + complexity.
- OTP has natural TTL (TOTP window, or "challenge expiry" in channel OTP
  flow). Codes older than window seconds not relevant for replay check —
  already rejected by time check.
- Clear-all is simple and O(1) amortized.

Trade-off: in very short time window after clear, code that SHOULD be
replay could pass once more. Acceptable because overlap with TOTP window
makes it rare.

Callers needing strict per-OTP TTL can use `with_capacity` with
very high value + call `clear_used_codes()` periodically (timer).

### Rate limit + replay sequence check

Execution order in `verify_inner`:

```
1. Check rate-limit. If over → return false.
2. Build replay_key.
3. Check replay-set. If exists → return false.
4. Compute ctx_match (constant-time) and code_match (constant-time).
5. If either false → increment attempt counter, return false.
6. Bound check, insert to replay-set, reset attempt counter, return true.
```

Step 4 made non-short-circuit to prevent timing side-channel
"wrong context" vs "wrong code".

---

## Rate Limiting

Simple: counter `attempts` increments each time verify fails with
(ctx_mismatch ∨ code_mismatch); resets to 0 each time succeeds.
If `attempts >= max_attempts`, all verifications (including correct code)
are rejected.

**Not using:**

- **Exponential backoff** — first good implementation usually sufficient,
  caller free to wrap with own backoff if needed.
- **IP-based bucket** — out of scope; you compose at router/proxy layer.
- **Distributed rate limit (Redis)** — out of scope; library single-instance.
  Roadmap v0.2 considers `VerifierStorage` trait for pluggable backend.

`reset_attempts()` provided for caller (e.g., admin override, or
after cooldown period).

---

## ClockSkewDetector — Design

### Why standalone, not integrated?

Initially I considered mounting detector directly to `Verifier`.
Rejected because:
- Not all users need skew detection.
- Detector has different state (samples + offset) that should be
  owned by multiple `Verifier` or accessed across requests.
- Has separate lifecycle (admin can reset detector without resetting verifier).

Solution: `TOTP::verify_tracking(code, time, window, &detector)` —
verifier optionally accepts detector. Detector shared via `&` (Send +
Sync), can be Arc'd to many threads.

### Default passive mode

Active mode (auto-adjust) can be influenced by inauthentic sampling.
Threat example: attacker can create many failed requests that
"almost match" at window edge so detector learns wrong offset, then
real users get rejected.

Default passive ensures detector cannot be weaponized. Callers who
enable auto-adjust must explicitly think about trust source.

### Output recommendation

Four categories (as enum, not freeform string):

- `InsufficientData` (< 8 samples) — stay silent.
- `NoActionNeeded` — small drift, clock OK.
- `ConsistentDrift { mean: f64 }` — consistent drift in one direction. Caller
  can use for admin warning or call `enable_auto_adjust()`.
- `WidenWindowOrCheckNtp` — many hits at window edge. NTP signal needs
  sync or window needs increase for normal operation.

---

## no_std Support Strategy

Modules divided into two tiers:

**Tier 1 — `alloc` only (suitable for no_std embedded):**
- `algorithm`, `error`, `constant_time`, `base32`, `hotp`, `totp`

**Tier 2 — requires `std`:**
- `key` (needs `getrandom` which needs OS RNG)
- `verification` (needs `HashSet`, `Mutex`)
- `provisioning` (needs complex `String` formatting)
- `context`, `skew`, `metrics`, `builder`, `helpers`, `config`

Selection: TOTP/HOTP core code (HMAC, truncation) is lightweight and doesn't
need shared state, so safe in no_std. Rest needs allocator + OS service
not universal in embedded.

no_std users must pass explicit `time: u64` to `generate`/`verify`
(no `SystemTime`). Caller responsibility to supply correct time from RTC.

---

## API Stability Promises

Before `1.0.0`:
- Public API can change in minor version (e.g., `0.1.x → 0.2.0`).
- Patch (`0.1.x → 0.1.y`) only bug fix + non-breaking improvement.
- Version binding tag (`"genotp-ctx-v1\0"`) **will not change** for
  major version 0; changes held for `0.2.0`.

After `1.0.0`:
- All public API follows standard semver.
- Binding/context serialization format change = major version bump.
- Deprecation cycle minimum 1 minor version before removal.

---

## Trade-offs Not Taken

Considerations deliberately **not** implemented (reason + either in
backlog or not).

| Consideration | Reason not implemented | Backlog status |
|---|---|---|
| HKDF for per-context key derivation | 2× HMAC vs 1× HMAC; no additional security benefit | Backlog `0.2` if requested |
| `VerifierStorage` trait (pluggable Redis backend etc) | Maintain stable API first | Backlog `0.2` |
| Built-in exponential backoff | Caller can wrap themselves | No |
| Pluggable random source for testing | Cargo test already deterministic enough; randomized via proptest | No |
| Async API (`tokio::Mutex`) | std::sync::Mutex light enough for short verify operations | No |
| FIDO2 / WebAuthn | Different security model, different problem | No (see non-goals) |
| Argon2 in replay-key | No compromise scenario where this helps | No |
| Distributed clock skew via NTP-pair | Out of scope; detection sufficient, sync delegated to OS | No |

---

## References

- RFC 4226 — HOTP algorithm
- RFC 6238 — TOTP algorithm
- RFC 6151 — Updated security considerations for HMAC with SHA1
- RFC 3986 — URI generic syntax (for percent encoding)
- RFC 4648 — Base32 encoding
- [Key Uri Format — Google Authenticator wiki](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
