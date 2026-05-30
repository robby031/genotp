# Desain & Model Keamanan genotp

Dokumen ini menjelaskan **mengapa** genotp dibangun seperti ini —
keputusan arsitektur, model ancaman yang dijawab, dan trade-off yang dipilih.

Untuk **bagaimana memakainya**, lihat [usage.md](./usage.md).

---

## Daftar Isi

- [Tujuan & Non-Goals](#tujuan--non-goals)
- [Model Ancaman](#model-ancaman)
- [Arsitektur Modul](#arsitektur-modul)
- [Keputusan Kriptografi](#keputusan-kriptografi)
- [Context Binding — Desain](#context-binding--desain)
- [Replay Protection — Desain](#replay-protection--desain)
- [Rate Limiting](#rate-limiting)
- [ClockSkewDetector — Desain](#clockskewdetector--desain)
- [Strategi Dukungan no_std](#strategi-dukungan-no_std)
- [Janji Stabilitas API](#janji-stabilitas-api)
- [Trade-off yang Tidak Diambil](#trade-off-yang-tidak-diambil)

---

## Tujuan & Non-Goals

### Tujuan

1. **Implementasi RFC 4226 / 6238 yang benar dan terbukti.**
   Lulus semua RFC test vector + ribuan property test randomized.

2. **Aman terhadap serangan praktis yang nyata** — bukan hanya teoritis.
   Skenario nyata yang dialami pengguna (intercept WhatsApp OTP, brute force
   kode pendek, phishing) harus tertangani secara desain, bukan dokumen.

3. **API ergonomis untuk Rust idiomatik.** Builder pattern, `Result` di
   semua operasi yang bisa gagal, `Send + Sync` di mana relevan, no
   panic-by-default di library code.

4. **Backward compatibility absolut dengan authenticator app populer**
   (Google Authenticator, Authy, Microsoft Authenticator).

5. **Dukungan no_std + alloc** untuk embedded.

### Non-Goals

- **Bukan framework auth lengkap.** Tidak ada manajemen user, session token,
  database adapter. genotp adalah primitive OTP — Anda susun sendiri
  pipeline auth-nya.
- **Bukan SMS/Email gateway.** Library tidak mengirim OTP via channel
  apa pun. Caller bertanggung jawab atas delivery.
- **Bukan replacement WebAuthn / FIDO2.** Untuk security tertinggi, gunakan
  hardware key. genotp adalah lapisan praktis untuk skenario di mana TOTP
  /HOTP masih relevan.

---

## Model Ancaman

genotp dirancang untuk menahan ancaman-ancaman berikut. Setiap pertahanan
disebutkan modulnya.

### A. Penyerang aktif jaringan / on-path

- **Replay attack** — penyerang menangkap kode valid lalu mengirim ulang.
  → Verifier menyimpan replay-set, kode hanya bisa dipakai sekali.

- **Phishing** — penyerang membuat domain palsu, user submit OTP di sana,
  penyerang langsung pakai ke real site.
  → Mode 1 binding dengan field `.origin()` — origin attacker berbeda,
  HMAC menghasilkan digit berbeda, real site tolak.

- **Channel intercept (WhatsApp/SMS OTP)** — penyerang membaca pesan OTP
  yang dikirim ke korban (mis. SIM swap, baca notifikasi, akses cloud
  backup).
  → Mode 1 binding dengan `.ip()` + `.session()` — kode hanya berlaku
  untuk context yang server bind saat issue.

### B. Penyerang lokal / online brute force

- **Brute force kode pendek (4 digit, 10.000 kemungkinan)** — terutama
  untuk channel OTP (bukan TOTP).
  → Rate limit di Verifier; kalau dipadukan dengan Mode 1 binding,
  brute force dari context attacker tidak pernah berhasil walaupun
  semua 10.000 dicoba.

- **Timing attack pada perbandingan kode** — penyerang mengukur waktu
  respons untuk menebak digit per posisi.
  → `subtle::ConstantTimeEq` di semua perbandingan kode dan context.

### C. Penyerang dengan akses memory / proses

- **Recovery secret dari heap** — setelah TOTP/HOTP di-drop, sisa byte
  secret bisa diambil dari memory.
  → `zeroize` di `Drop` untuk `secret`.

- **Side-channel cache** — diakui sebagai out-of-scope untuk library
  general-purpose; mitigasi-nya butuh layer di bawah (hardware key,
  enclave, dll).

### D. Penyerang internal sistem (misconfig)

- **Salah panjang secret menyebabkan downgrade silent** — `generate_secret(129)`
  dulu dibulatkan ke 128-bit tanpa warning.
  → Validasi `bit_length % 8 != 0` + minimum 128-bit.

- **Salah konfigurasi serde** — secret ikut serialize ke JSON.
  → `#[serde(skip)]` di field secret + tidak ada `Deserialize` impl
  (mencegah struct yang baru di-deserialize memiliki secret kosong
  yang menghasilkan kode salah diam-diam).

### E. Penyerang pasif yang membaca log/error

- **Leak secret atau context lewat error message.**
  → `GenOtpError` tidak pernah memuat secret atau context. Pesan error
  bersifat kategorial (`InvalidSecret`, bukan "secret X invalid").

---

## Arsitektur Modul

```
genotp/
├── algorithm        — enum Algorithm (SHA1/256/512)
├── base32           — encode/decode RFC 4648 tanpa padding
├── constant_time    — wrapper `subtle::ConstantTimeEq` untuk &str
├── error            — GenOtpError + Display + std::error::Error
├── key              — KeyGenerator (CSPRNG via ax-rnd)
├── hotp             — HOTP::{new, generate, verify, generate_bound, verify_bound}
├── totp             — TOTP::{new, generate, verify, *_bound, verify_tracking}
├── builder          — TotpBuilder, HotpBuilder
├── config           — TotpConfig, HotpConfig (struct konfigurasi)
├── helpers          — generate_*_default, verify_*_default, create_secret
├── provisioning     — OtpAuthUri (otpauth:// URL generator)
├── verification     — Verifier (replay + rate limit + context-aware)
├── metrics          — Metrics (atomic counter observability)
├── context          — OtpContext + OtpContextBuilder ⭐
└── skew             — ClockSkewDetector + SkewReport ⭐
```

⭐ = modul yang menjadi pembeda dari library OTP Rust lain.

Dependensi modul: arah panah satu arah, tidak ada cycle.

```
helpers ──┐
builder ──┼──> hotp / totp ──> algorithm, base32, constant_time, error
config  ──┘                        │
                                    └──> context (kalau pakai *_bound)
verification ──> constant_time, error, context
provisioning ──> algorithm, percent-encoding
skew ──> (standalone)
metrics ──> (standalone)
```

---

## Keputusan Kriptografi

### HMAC variants

Mengikuti RFC 6238: SHA1 wajib didukung, SHA256/SHA512 opsional. genotp
mendukung ketiganya. SHA1 tetap default karena kompatibilitas Google
Authenticator dan Authy default ke SHA1.

**Catatan:** SHA1 dalam konteks HMAC-OTP tidak terpengaruh oleh collision
attack pada SHA1 plain (chosen-prefix). HMAC-SHA1 dengan secret rahasia
tetap aman untuk OTP — bukti formal di [RFC 6151].

### Dynamic truncation

Implementasi mengikuti RFC 4226 §5.3 verbatim:

```
offset = hmac[len-1] & 0x0f
binary = (hmac[offset]   & 0x7f) << 24
       | (hmac[offset+1])        << 16
       | (hmac[offset+2])        << 8
       | (hmac[offset+3])
code   = binary % 10^digits
```

Bit `& 0x7f` adalah masking sign bit — RFC mandates ini supaya konversi
ke integer di bahasa lain (yang mungkin signed-only) tetap konsisten.

### Constant-time comparison

Semua perbandingan yang menyentuh secret atau context dilakukan dengan
`subtle::ConstantTimeEq`. Modul `constant_time` membungkus untuk `&str`.
Verifier juga membandingkan context bytes dengan `ct_eq`.

Penting: branching setelah perbandingan tetap dilakukan setelah kedua
perbandingan selesai untuk mencegah short-circuit early-return yang bisa
ngeleak "context salah" vs "code salah":

```rust
let ctx_match  = issued_ctx.ct_eq(request_ctx).into();
let code_match = constant_time_eq(code, expected);
if !(ctx_match && code_match) { /* fail */ }
```

### Zeroize

`TOTP::secret` dan `HOTP::secret` adalah `Vec<u8>` dengan `Drop` impl yang
memanggil `zeroize::Zeroize`. Memastikan secret di heap dinolkan saat
struct di-drop, sebelum allocator mengembalikan memori ke pool.

### Sumber entropi

`ax-rnd::fill` (OS-backed CSPRNG: `getrandom` di Linux, `RtlGenRandom` di
Windows, `SecRandomCopyBytes` di macOS). Tidak ada PRNG userspace di
library — kalau OS tidak menyediakan, library gagal (acceptable: tidak
boleh ada fallback yang lebih lemah dari OS RNG).

---

## Context Binding — Desain

Fitur unggulan genotp. Dua mode dengan trade-off berbeda.

### Mengapa dua mode?

Tabel komparasi:

| Aspek | Mode 1 (HMAC binding) | Mode 2 (Verifier-stored) |
|---|---|---|
| Kode output | Berbeda untuk context berbeda | RFC 6238 standar |
| Kompatibel Google Auth | Tidak (server-only OTP) | Ya |
| Kekuatan terhadap intercept | Maksimal (cryptographic) | Sedang (server check) |
| Kekuatan terhadap context spoof | Maksimal | Sedang (caller harus authenticate context) |
| Use case | Channel OTP (WhatsApp/SMS) | TOTP app authenticator |

Mode 1 lebih kuat karena context masuk ke HMAC — attacker yang tahu kode
6-digit dari channel, tapi tidak tahu context server yang dipakai, tidak
bisa men-derive kode yang valid untuk context-nya. Mode 2 lebih praktis
karena tetap pakai authenticator app standar.

### Catatan: Residual Brute Force Probability

Penting dipahami: **context binding TIDAK menghilangkan probability brute
force baseline 1/10^digits**. Kode 6-digit hanya punya 10⁶ kemungkinan,
sehingga dua HMAC output yang sangat berbeda dapat **kebetulan** menghasilkan
6-digit yang sama setelah `% 10⁶` — probabilitas 1/10⁶ per attempt.

Akibatnya, attacker yang tidak punya kode valid tetap bisa "menang"
dengan probability ~1/10⁶ tiap submit. Yang **dicegah** oleh binding adalah
serangan **direct replay** — attacker yang mengintercept kode valid tidak
bisa langsung pakai dari context berbeda, karena kode yang dihasilkan
HMAC untuk context attacker hampir pasti berbeda.

Mitigasi terhadap baseline brute force adalah **rate limit di Verifier**.
Dengan `max_attempts=5`, probability menang per session ≈ 5×10⁻⁶ ≈ 0.0005%.
Pakai 8-digit (rate limit yang sama) menurunkan ke 5×10⁻⁸.

Properti ini ditemukan oleh fuzzer — sebelumnya kami assert deterministically
"context berbeda → kode berbeda", fuzzer membuktikan assertion-nya overstrong
setelah ~1 juta input. Lihat `fuzz/fuzz_targets/context_binding_fuzz.rs`
untuk detail.

### Format binding HMAC (Mode 1)

```
HMAC(secret, counter_be64 || "genotp-ctx-v1\0" || context_bytes)
```

Kalau `context_bytes` kosong, tag dan context **tidak** di-update ke HMAC,
sehingga hasil identik dengan RFC 6238 standar. Properti ini divalidasi
dengan property test `empty_context_equals_standard_totp`.

**Mengapa tag versi `"genotp-ctx-v1\0"`?**

- Mencegah cross-version forgery: kalau format binding pernah berubah
  (mis. v2 menambah HKDF di tengah), kode yang di-generate v1 tidak
  akan match dengan implementasi v2.
- Null terminator (`\0`) mencegah ambiguitas kalau tag pernah extended.
- Disertakan **di antara** counter dan context, sehingga (counter,
  context) berbeda menghasilkan input HMAC yang tidak ambigu.

**Mengapa tidak HKDF?**

Approach alternatif: turunkan key per-context dengan HKDF, lalu HMAC
counter. Lebih "rapi" secara akademik, tapi:
- 2× HMAC vs 1× HMAC per operasi.
- Tidak ada manfaat security tambahan untuk use case kita (HMAC dengan
  input yang well-defined boundary sudah aman).
- Membuat backward-compat dengan empty context lebih sulit.

Trade-off: kami pilih simple HMAC append. Kalau di future kebutuhan
berubah, tag versi memungkinkan migration.

### Format serialisasi context (Builder)

`OtpContextBuilder` menggunakan `BTreeMap<String, String>` (sorted) dan
serialize ke:

```
key1=value1\0key2=value2\0...\0
```

**Properti yang dijamin:**

1. **Deterministik** — urutan setter tidak memengaruhi output (BTreeMap
   sorted by key).
2. **Tidak ambigu** — separator `\0` tidak bisa di-spoof oleh content
   karena teks-input tidak boleh berisi `\0` di praktiknya (kalau perlu,
   user bisa pakai `OtpContext::from_bytes` untuk format custom).
3. **Field built-in punya prefix tetap** (`ip`, `device`, `session`,
   `origin`); custom di-prefix `x-` untuk mencegah konflik versi future.

Lihat property test `context_builder_setter_order_invariant` untuk bukti.

### Origin normalization

`.origin(url)` melakukan:
1. trim whitespace, lowercase
2. buang fragment (`#...`)
3. buang query (`?...`)
4. buang path setelah host
5. buang trailing slash

Hasil: `scheme://host[:port]` saja. Port dipertahankan karena dianggap
bagian dari authority origin.

**Tidak dilakukan:**
- IDN normalization (Punycode) — out of scope, user diharapkan menyediakan
  origin dalam format yang konsisten.
- Validasi syntax URL — input dianggap sudah valid; library hanya
  menormalisasi bagian-bagian yang umum bermasalah.

---

## Replay Protection — Desain

### Per-context replay key

Replay-set di Verifier menyimpan key:

```
replay_key(code, context_bytes) = code_bytes || 0x00 || context_bytes
```

**Mengapa per-context?**

Pertimbangkan sistem multi-user dengan 100.000 user aktif. Probabilitas dua
user dapat 6 digit yang sama di window TOTP 30 detik bukan nol (collision
~1 dari 10^6 per window per pasangan user). Tanpa per-context isolation,
satu user yang sukses akan **memblokir user lain yang valid** dengan kode
yang sama.

Dengan `replay_key(code, ctx_a) ≠ replay_key(code, ctx_b)`, kedua user bisa
sukses paralel; replay attempt mereka masing-masing tetap tertangkap.

Properti ini divalidasi:
- property test: `verifier_per_context_isolation`
- concurrent stress: `verifier_per_context_isolation_under_contention`
  (100 thread, 100 context unik, kode sama → semua 100 sukses)

### Bounded memory

`used_codes: HashSet<Vec<u8>>` bisa tumbuh tanpa batas di sistem long-running.
Mitigasi: `max_used_codes` (default 10.000). Ketika set penuh, **clear
seluruh set** sebelum insert berikutnya.

**Mengapa clear-all dan bukan LRU?**

- LRU butuh tracking insertion order tambahan; doubled memory + complexity.
- OTP punya TTL alami (window TOTP, atau "challenge expiry" di flow channel
  OTP). Kode yang sudah > window detik lama tidak relevan untuk dicek
  replay-nya — sudah ditolak oleh time check.
- Clear-all sederhana dan O(1) amortized.

Trade-off: dalam jendela waktu sangat singkat setelah clear, kode yang
SEHARUSNYA replay bisa lolos satu kali lagi. Bisa diterima karena
overlap dengan window TOTP membuatnya jarang.

Caller yang butuh strict per-OTP TTL bisa pakai `with_capacity` dengan
nilai sangat tinggi + panggil `clear_used_codes()` periodik (timer).

### Rate limit + replay urutan check

Urutan eksekusi di `verify_inner`:

```
1. Cek rate-limit. Kalau over → return false.
2. Bangun replay_key.
3. Cek replay-set. Kalau ada → return false.
4. Hitung ctx_match (constant-time) dan code_match (constant-time).
5. Kalau salah satu false → naikkan attempt counter, return false.
6. Bound check, insert ke replay-set, reset attempt counter, return true.
```

Step 4 dibuat tidak short-circuit untuk mencegah timing side-channel
"context salah" vs "code salah".

---

## Rate Limiting

Sederhana: counter `attempts` naik tiap kali verify gagal dengan
(ctx_mismatch ∨ code_mismatch); reset ke 0 setiap kali sukses.
Kalau `attempts >= max_attempts`, semua verifikasi (termasuk kode benar)
ditolak.

**Tidak menggunakan:**

- **Exponential backoff** — implementasi pertama yang baik biasanya cukup,
  caller bebas wrap dengan backoff sendiri kalau perlu.
- **IP-based bucket** — out of scope; Anda susun di layer router/proxy.
- **Distributed rate limit (Redis)** — out of scope; library single-instance.
  Roadmap v0.2 mempertimbangkan `VerifierStorage` trait untuk pluggable
  backend.

`reset_attempts()` disediakan untuk caller (mis. admin override, atau
setelah cooldown period).

---

## ClockSkewDetector — Desain

### Mengapa standalone, bukan terintegrasi?

Awalnya saya pertimbangkan memasang detector langsung ke `Verifier`.
Ditolak karena:
- Tidak semua user butuh skew detection.
- Detector punya state berbeda (samples + offset) yang sebaiknya bisa
  dimiliki banyak `Verifier` atau diakses lintas request.
- Punya lifecycle terpisah (admin bisa reset detector tanpa reset
  verifier).

Solusi: `TOTP::verify_tracking(code, time, window, &detector)` —
verifier opsional menerima detector. Detector di-share via `&` (Send +
Sync), bisa di-Arc ke banyak thread.

### Mode passive default

Mode active (auto-adjust) bisa di-influence oleh sampling yang tidak
otentik. Contoh ancaman: attacker bisa membuat banyak request gagal yang
"hampir match" di edge window agar detector belajar offset salah, lalu
real user-nya jadi ditolak.

Default passive memastikan detector tidak bisa di-weaponize. Caller yang
mengaktifkan auto-adjust harus secara eksplisit memikirkan source
trust-nya.

### Output recommendation

Empat kategori (sebagai enum, bukan freeform string):

- `InsufficientData` (< 8 sample) — diam saja.
- `NoActionNeeded` — drift kecil, jam OK.
- `ConsistentDrift { mean: f64 }` — bias konsisten ke satu arah. Caller
  bisa pakai untuk warning admin atau panggil `enable_auto_adjust()`.
- `WidenWindowOrCheckNtp` — banyak hit di edge window. Sinyal NTP perlu
  di-sync atau window perlu dinaikkan untuk operasi normal.

---

## Strategi Dukungan no_std

Module dibagi dua tier:

**Tier 1 — `alloc` saja (cocok untuk no_std embedded):**
- `algorithm`, `error`, `constant_time`, `base32`, `hotp`, `totp`

**Tier 2 — butuh `std`:**
- `key` (butuh `ax-rnd` yang butuh OS RNG)
- `verification` (butuh `HashSet`, `Mutex`)
- `provisioning` (butuh `String` formatting kompleks)
- `context`, `skew`, `metrics`, `builder`, `helpers`, `config`

Pemilihan: kode TOTP/HOTP core (HMAC, truncation) ringan dan tidak butuh
state shared, jadi aman di no_std. Sisanya butuh allocator + OS service
yang tidak universal di embedded.

Pengguna no_std harus pass `time: u64` eksplisit ke `generate`/`verify`
(tidak ada `SystemTime`). Tanggung jawab caller untuk supply waktu yang
benar dari RTC.

---

## Janji Stabilitas API

Sebelum `1.0.0`:
- Public API bisa berubah di minor version (mis. `0.1.x → 0.2.0`).
- Patch (`0.1.x → 0.1.y`) hanya bug fix + improvement non-breaking.
- Tag versi binding (`"genotp-ctx-v1\0"`) **tidak akan berubah** untuk
  major version 0; perubahan ditahan untuk `0.2.0`.

Setelah `1.0.0`:
- Semua public API mengikuti semver standar.
- Perubahan format binding/serialisasi context = major version bump.
- Deprecation cycle minimal 1 minor version sebelum removal.

---

## Trade-off yang Tidak Diambil

Pertimbangan yang sengaja **tidak** diimplementasi (alasan + ada di
backlog atau bukan).

| Pertimbangan | Alasan tidak diimplementasi | Status backlog |
|---|---|---|
| HKDF untuk key derivation per-context | 2× HMAC vs 1× HMAC; tidak ada manfaat security tambahan | Backlog `0.2` kalau ada permintaan |
| `VerifierStorage` trait (pluggable backend Redis dll) | Mempertahankan API stabil dulu | Backlog `0.2` |
| Exponential backoff bawaan | Caller bisa wrap sendiri | Tidak |
| Pluggable random source untuk testing | Cargo test sudah cukup deterministic; randomized via proptest | Tidak |
| Async API (`tokio::Mutex`) | std::sync::Mutex cukup ringan untuk operasi verify yang singkat | Tidak |
| FIDO2 / WebAuthn | Different security model, different problem | Tidak (lihat non-goals) |
| Argon2 di replay-key | Tidak ada compromise scenario di mana ini membantu | Tidak |
| Distributed clock skew via NTP-pair | Out of scope; deteksi cukup, sync diserahkan ke OS | Tidak |

---

## Referensi

- RFC 4226 — HOTP algorithm
- RFC 6238 — TOTP algorithm
- RFC 6151 — Updated security considerations for HMAC with SHA1
- RFC 3986 — URI generic syntax (untuk percent encoding)
- RFC 4648 — Base32 encoding
- [Key Uri Format — Google Authenticator wiki](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
