// Clippy: FFI functions with raw pointer args are conventionally NOT marked
// `unsafe fn` because they are called from C where the concept doesn't
// exist. Internal `unsafe { ... }` blocks document the dereferences. NULL
// checks at function entry mitigate the most common misuse. Suppress the
// blanket lint while keeping all *actual* dereferences explicitly in
// `unsafe` blocks for reviewer clarity.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! FFI bindings for the genotp library.
//!
//! Provides a C-compatible API for multi-language bindings.
//!
//! # Memory management
//!
//! - Opaque handles (`GenOtpHotp*`, `GenOtpTotp*`) must be freed with their
//!   respective `*_free` functions.
//! - `GenOtpString` / `GenOtpBytes` returned by this library must be freed
//!   with [`genotp_string_free`] / [`genotp_bytes_free`].
//! - **Strings returned are length-prefixed, NOT null-terminated.** Use
//!   `printf("%.*s", (int)s.len, s.data)` — `printf("%s", s.data)` is
//!   undefined behavior.
//! - Zero-length results are returned with `data = NULL, len = 0`. Calling
//!   the free function on those is a no-op.
//!
//! # Error handling
//!
//! - Functions return [`GenOtpErrorCode`] (0 = success). The enum is
//!   repr'd as `int32_t` for stable C ABI.
//! - Use [`genotp_error_message`] for a human-readable message.
//!
//! # Thread safety
//!
//! - `HOTP` / `TOTP` are immutable after construction. `generate()` and
//!   `verify()` take `&self` — safe to share across threads (use `&` from
//!   C via pointer sharing; do not pass the same opaque pointer to
//!   `*_free` concurrently).
//! - Free functions must run exactly once and must not race with any
//!   other call using the same pointer.

use genotp::algorithm::Algorithm;
use genotp::base32;
use genotp::context::{OtpContext, OtpContextBuilder};
use genotp::error::GenOtpError;
use genotp::hotp::HOTP;
use genotp::key::KeyGenerator;
use genotp::provisioning::{OtpAuthUri, OtpType};
use genotp::skew::ClockSkewDetector;
use genotp::totp::TOTP;
use genotp::verification::Verifier;
use std::alloc::{Layout, alloc, dealloc};
use std::ffi::{CStr, c_char};
use std::ptr;

/// Library semver, null-terminated. Useful for runtime ABI compatibility
/// check. C side sees this as `const uint8_t GENOTP_VERSION[6]`.
#[unsafe(no_mangle)]
pub static GENOTP_VERSION: [u8; 6] = *b"0.3.0\0";

/// Error codes for the FFI surface.
///
/// `#[repr(i32)]` to guarantee stable size across Rust / C platforms.
/// Default `#[repr(C)]` for enum lets Rust pick the smallest int that
/// fits, which can mismatch C's typical `int`-sized enum on the other
/// side of the boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenOtpErrorCode {
    Success = 0,
    InvalidSecret = 1,
    InvalidCode = 2,
    InvalidDigits = 3,
    InvalidAlgorithm = 4,
    InvalidCounter = 5,
    InvalidTime = 6,
    VerificationFailed = 7,
    RateLimited = 8,
    ReplayAttack = 9,
    NullPointer = 10,
    InvalidUtf8 = 11,
    AllocationFailed = 12,
}

impl From<GenOtpError> for GenOtpErrorCode {
    fn from(err: GenOtpError) -> Self {
        match err {
            GenOtpError::InvalidSecret => GenOtpErrorCode::InvalidSecret,
            GenOtpError::InvalidCode => GenOtpErrorCode::InvalidCode,
            GenOtpError::InvalidDigits => GenOtpErrorCode::InvalidDigits,
            GenOtpError::InvalidAlgorithm => GenOtpErrorCode::InvalidAlgorithm,
            GenOtpError::InvalidCounter => GenOtpErrorCode::InvalidCounter,
            GenOtpError::InvalidTime => GenOtpErrorCode::InvalidTime,
            GenOtpError::VerificationFailed => GenOtpErrorCode::VerificationFailed,
            GenOtpError::RateLimited => GenOtpErrorCode::RateLimited,
            GenOtpError::ReplayAttack => GenOtpErrorCode::ReplayAttack,
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenOtpAlgorithm {
    Sha1 = 0,
    Sha256 = 1,
    Sha512 = 2,
}

impl From<GenOtpAlgorithm> for Algorithm {
    fn from(alg: GenOtpAlgorithm) -> Self {
        match alg {
            GenOtpAlgorithm::Sha1 => Algorithm::SHA1,
            GenOtpAlgorithm::Sha256 => Algorithm::SHA256,
            GenOtpAlgorithm::Sha512 => Algorithm::SHA512,
        }
    }
}

/// OTP type discriminator for [`OtpAuthUri`] / provisioning.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenOtpOtpType {
    Hotp = 0,
    Totp = 1,
}

impl From<GenOtpOtpType> for OtpType {
    fn from(t: GenOtpOtpType) -> Self {
        match t {
            GenOtpOtpType::Hotp => OtpType::HOTP,
            GenOtpOtpType::Totp => OtpType::TOTP,
        }
    }
}

// Opaque handle types — Rust ZSTs that are "namespaced" pointers. The
// actual storage is the wrapped Rust type accessed via `Box::into_raw`.
#[repr(C)]
pub struct GenOtpHotp {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpTotp {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpVerifier {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpSkewDetector {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpOtpAuthUri {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GenOtpContextBuilder {
    _private: [u8; 0],
}

/// Internal storage for the [`OtpContextBuilder`]. The Rust builder
/// consumes `self` on each setter (returns `Self`), so we wrap in
/// `Option` and use take/restore to mutate in place via FFI.
///
/// `inner = None` means the builder was already consumed by `build()`
/// and can no longer be used (returns `InvalidSecret` on further calls).
struct ContextBuilderHandle {
    inner: Option<OtpContextBuilder>,
}

impl ContextBuilderHandle {
    fn new() -> Self {
        Self {
            inner: Some(OtpContext::builder()),
        }
    }

    /// Apply a builder transformation in place. Returns `InvalidSecret`
    /// if the builder was already consumed by `build()`.
    fn apply<F>(&mut self, f: F) -> GenOtpErrorCode
    where
        F: FnOnce(OtpContextBuilder) -> OtpContextBuilder,
    {
        match self.inner.take() {
            Some(b) => {
                self.inner = Some(f(b));
                GenOtpErrorCode::Success
            }
            None => GenOtpErrorCode::InvalidSecret,
        }
    }
}

/// Internal storage for OtpAuthUri builder state. The Rust `OtpAuthUri`
/// builder methods consume `self`, which is incompatible with FFI's
/// "mutate-in-place" pattern. We track components separately and assemble
/// the URI only at `genotp_otpauth_uri_build()` call.
struct UriHandle {
    typ: OtpType,
    label: String,
    secret: String,
    issuer: Option<String>,
    algorithm: Option<Algorithm>,
    digits: Option<u32>,
    period: Option<u64>,
    counter: Option<u64>,
}

impl UriHandle {
    fn assemble(&self) -> OtpAuthUri {
        let mut uri = OtpAuthUri::new(self.typ, self.label.clone(), self.secret.clone());
        if let Some(ref s) = self.issuer {
            uri = uri.issuer(s.clone());
        }
        if let Some(a) = self.algorithm {
            uri = uri.algorithm(a);
        }
        if let Some(d) = self.digits {
            uri = uri.digits(d);
        }
        if let Some(p) = self.period {
            uri = uri.period(p);
        }
        if let Some(c) = self.counter {
            uri = uri.counter(c);
        }
        uri
    }
}

/// Byte array with explicit length.
///
/// `data = NULL, len = 0` is the canonical "empty" representation.
/// Always check `len > 0` before dereferencing `data`.
#[repr(C)]
pub struct GenOtpBytes {
    pub data: *mut u8,
    pub len: usize,
}

/// String result with explicit length. **NOT null-terminated.**
///
/// `data = NULL, len = 0` is the canonical "empty" representation.
/// Use `printf("%.*s", (int)s.len, s.data)` — never `printf("%s", ...)`.
#[repr(C)]
pub struct GenOtpString {
    pub data: *mut u8,
    pub len: usize,
}

// ==================== Internal helpers ====================

/// Allocate `len` bytes from the global allocator.
///
/// **Safe for `len == 0`**: returns `null` instead of calling `alloc()`
/// with a zero-size layout (which is undefined behavior per `std::alloc`).
/// Caller should pair this with [`safe_dealloc`].
fn safe_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return ptr::null_mut();
    }
    // unwrap_or_else: Layout::array fails only on overflow, which means
    // len > isize::MAX / size_of::<u8>() — impossible with realistic input.
    let layout = match Layout::array::<u8>(len) {
        Ok(l) => l,
        Err(_) => return ptr::null_mut(),
    };
    // SAFETY: layout is non-zero (we checked len > 0). Return value can
    // be null which caller must handle.
    unsafe { alloc(layout) }
}

/// Free memory allocated by [`safe_alloc`]. No-op for `data == NULL` or
/// `len == 0`.
unsafe fn safe_dealloc(data: *mut u8, len: usize) {
    if data.is_null() || len == 0 {
        return;
    }
    let layout = match Layout::array::<u8>(len) {
        Ok(l) => l,
        Err(_) => return, // shouldn't happen if alloc succeeded
    };
    unsafe { dealloc(data, layout) }
}

/// Copy `src` bytes into a freshly-allocated buffer. Sets `out` to
/// `(data, len)`. Returns `AllocationFailed` if allocation fails.
fn copy_to_out_bytes(src: &[u8], out: *mut GenOtpBytes) -> GenOtpErrorCode {
    let len = src.len();
    if len == 0 {
        // SAFETY: out is guaranteed non-null by caller's check.
        unsafe {
            (*out).data = ptr::null_mut();
            (*out).len = 0;
        }
        return GenOtpErrorCode::Success;
    }
    let data = safe_alloc(len);
    if data.is_null() {
        return GenOtpErrorCode::AllocationFailed;
    }
    // SAFETY: data points to `len` allocated bytes; src is `len` bytes; no overlap.
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), data, len);
        (*out).data = data;
        (*out).len = len;
    }
    GenOtpErrorCode::Success
}

fn copy_to_out_string(src: &str, out: *mut GenOtpString) -> GenOtpErrorCode {
    let bytes = src.as_bytes();
    let len = bytes.len();
    if len == 0 {
        unsafe {
            (*out).data = ptr::null_mut();
            (*out).len = 0;
        }
        return GenOtpErrorCode::Success;
    }
    let data = safe_alloc(len);
    if data.is_null() {
        return GenOtpErrorCode::AllocationFailed;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), data, len);
        (*out).data = data;
        (*out).len = len;
    }
    GenOtpErrorCode::Success
}

/// Convert a nullable C string to `&str`. Returns error if null or non-UTF-8.
unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Result<&'a str, GenOtpErrorCode> {
    if ptr.is_null() {
        return Err(GenOtpErrorCode::NullPointer);
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().map_err(|_| GenOtpErrorCode::InvalidUtf8)
}

// ==================== Memory Management ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_string_free(s: GenOtpString) {
    unsafe { safe_dealloc(s.data, s.len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_bytes_free(b: GenOtpBytes) {
    unsafe { safe_dealloc(b.data, b.len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_free(hotp: *mut GenOtpHotp) {
    if !hotp.is_null() {
        unsafe {
            let _ = Box::from_raw(hotp as *mut HOTP);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_free(totp: *mut GenOtpTotp) {
    if !totp.is_null() {
        unsafe {
            let _ = Box::from_raw(totp as *mut TOTP);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_free(v: *mut GenOtpVerifier) {
    if !v.is_null() {
        unsafe {
            let _ = Box::from_raw(v as *mut Verifier);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_free(c: *mut GenOtpContext) {
    if !c.is_null() {
        unsafe {
            let _ = Box::from_raw(c as *mut OtpContext);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_skew_detector_free(d: *mut GenOtpSkewDetector) {
    if !d.is_null() {
        unsafe {
            let _ = Box::from_raw(d as *mut ClockSkewDetector);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_free(uri: *mut GenOtpOtpAuthUri) {
    if !uri.is_null() {
        unsafe {
            let _ = Box::from_raw(uri as *mut UriHandle);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_free(b: *mut GenOtpContextBuilder) {
    if !b.is_null() {
        unsafe {
            let _ = Box::from_raw(b as *mut ContextBuilderHandle);
        }
    }
}

// ==================== Key Generation ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_generate_secret(
    bit_length: usize,
    out_bytes: *mut GenOtpBytes,
) -> GenOtpErrorCode {
    if out_bytes.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    match KeyGenerator::generate_secret(bit_length) {
        Ok(secret) => copy_to_out_bytes(&secret, out_bytes),
        Err(e) => e.into(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_generate_default_secret(out_bytes: *mut GenOtpBytes) -> GenOtpErrorCode {
    genotp_generate_secret(160, out_bytes)
}

/// Stack-friendly RNG fill — writes to caller-provided buffer.
/// No heap allocation. Suitable for embedded use.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_fill_secret(buf: *mut u8, buf_len: usize) -> GenOtpErrorCode {
    if buf.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, buf_len) };
    match KeyGenerator::fill_secret(slice) {
        Ok(()) => GenOtpErrorCode::Success,
        Err(e) => e.into(),
    }
}

// ==================== Base32 ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_base32_encode(
    data: *const u8,
    data_len: usize,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    // Allow data == NULL iff data_len == 0 (empty input is legitimate).
    if data.is_null() && data_len > 0 {
        return GenOtpErrorCode::NullPointer;
    }
    let input = if data_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    };
    let encoded = base32::encode(input);
    copy_to_out_string(&encoded, out_string)
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_base32_decode(
    data: *const c_char,
    out_bytes: *mut GenOtpBytes,
) -> GenOtpErrorCode {
    if out_bytes.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let input = match unsafe { c_str_to_str(data) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match base32::decode(input) {
        Ok(decoded) => copy_to_out_bytes(&decoded, out_bytes),
        Err(_) => GenOtpErrorCode::InvalidSecret,
    }
}

// ==================== HOTP ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_new(
    secret: *const u8,
    secret_len: usize,
    algorithm: GenOtpAlgorithm,
    digits: u32,
    out_hotp: *mut *mut GenOtpHotp,
) -> GenOtpErrorCode {
    if out_hotp.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    if secret.is_null() && secret_len > 0 {
        return GenOtpErrorCode::NullPointer;
    }
    let secret_slice = if secret_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret, secret_len) }
    };
    let secret_vec = secret_slice.to_vec();
    match HOTP::new(secret_vec, algorithm.into(), digits) {
        Ok(hotp) => {
            let boxed = Box::new(hotp);
            unsafe {
                *out_hotp = Box::into_raw(boxed) as *mut GenOtpHotp;
            }
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_generate(
    hotp: *const GenOtpHotp,
    counter: u64,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if hotp.is_null() || out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let hotp = unsafe { &*(hotp as *const HOTP) };
    match hotp.generate(counter) {
        Ok(code) => copy_to_out_string(&code, out_string),
        Err(e) => e.into(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_verify(
    hotp: *const GenOtpHotp,
    code: *const c_char,
    counter: u64,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if hotp.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let hotp = unsafe { &*(hotp as *const HOTP) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match hotp.verify(code_str, counter) {
        Ok(valid) => {
            unsafe { *out_valid = valid };
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

/// HOTP look-ahead resynchronization (RFC 4226 §7.4).
///
/// `out_matched_counter` is set to the counter that matched, or 0 if no
/// match (check `out_valid` first). Caller MUST update their stored counter
/// to `matched + 1` after success to prevent replay.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_verify_with_resync(
    hotp: *const GenOtpHotp,
    code: *const c_char,
    counter: u64,
    look_ahead: u64,
    out_valid: *mut bool,
    out_matched_counter: *mut u64,
) -> GenOtpErrorCode {
    if hotp.is_null() || out_valid.is_null() || out_matched_counter.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let hotp = unsafe { &*(hotp as *const HOTP) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match hotp.verify_with_resync(code_str, counter, look_ahead) {
        Ok(Some(matched)) => {
            unsafe {
                *out_valid = true;
                *out_matched_counter = matched;
            }
            GenOtpErrorCode::Success
        }
        Ok(None) => {
            unsafe {
                *out_valid = false;
                *out_matched_counter = 0;
            }
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

// ==================== TOTP ====================

/// Sentinel for "use current system time" in TOTP generate/verify.
/// Using `u64::MAX` instead of `0` so `time = 0` (Unix epoch) remains a
/// valid explicit timestamp.
pub const GENOTP_TIME_NOW: u64 = u64::MAX;

#[inline]
fn time_to_option(time: u64) -> Option<u64> {
    if time == GENOTP_TIME_NOW {
        None
    } else {
        Some(time)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_new(
    secret: *const u8,
    secret_len: usize,
    algorithm: GenOtpAlgorithm,
    digits: u32,
    period: u64,
    out_totp: *mut *mut GenOtpTotp,
) -> GenOtpErrorCode {
    if out_totp.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    if secret.is_null() && secret_len > 0 {
        return GenOtpErrorCode::NullPointer;
    }
    let secret_slice = if secret_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret, secret_len) }
    };
    let secret_vec = secret_slice.to_vec();
    match TOTP::new(secret_vec, algorithm.into(), digits, period) {
        Ok(totp) => {
            let boxed = Box::new(totp);
            unsafe {
                *out_totp = Box::into_raw(boxed) as *mut GenOtpTotp;
            }
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

/// Generate TOTP code. Pass `time = GENOTP_TIME_NOW` (u64::MAX) for system time.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_generate(
    totp: *const GenOtpTotp,
    time: u64,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if totp.is_null() || out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let totp = unsafe { &*(totp as *const TOTP) };
    match totp.generate(time_to_option(time)) {
        Ok(code) => copy_to_out_string(&code, out_string),
        Err(e) => e.into(),
    }
}

/// Verify TOTP code. Pass `time = GENOTP_TIME_NOW` for system time.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_verify(
    totp: *const GenOtpTotp,
    code: *const c_char,
    time: u64,
    window: u64,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if totp.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let totp = unsafe { &*(totp as *const TOTP) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match totp.verify(code_str, time_to_option(time), window) {
        Ok(valid) => {
            unsafe { *out_valid = valid };
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

// ==================== OtpContext (binding) ====================

/// Construct an OtpContext from raw bytes.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_from_bytes(
    data: *const u8,
    data_len: usize,
    out_ctx: *mut *mut GenOtpContext,
) -> GenOtpErrorCode {
    if out_ctx.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    if data.is_null() && data_len > 0 {
        return GenOtpErrorCode::NullPointer;
    }
    let slice = if data_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    };
    let ctx = OtpContext::from_bytes(slice.to_vec());
    let boxed = Box::new(ctx);
    unsafe {
        *out_ctx = Box::into_raw(boxed) as *mut GenOtpContext;
    }
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_empty(out_ctx: *mut *mut GenOtpContext) -> GenOtpErrorCode {
    if out_ctx.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let ctx = OtpContext::empty();
    let boxed = Box::new(ctx);
    unsafe {
        *out_ctx = Box::into_raw(boxed) as *mut GenOtpContext;
    }
    GenOtpErrorCode::Success
}

// ==================== OtpContextBuilder ====================

/// Create a new context builder. Use the `_set_*` / `_set_custom` setters
/// to add fields, then call [`genotp_context_builder_build`] to produce
/// a canonicalized [`GenOtpContext`].
///
/// Field values are serialized in sorted order with `\0` separators
/// (alphabetical by key) so two builders with the same fields in
/// different setter order produce byte-identical context — critical for
/// binding determinism between issue-side and verify-side.
///
/// Builder MUST be freed with [`genotp_context_builder_free`] even after
/// `_build` is called.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_new(
    out_builder: *mut *mut GenOtpContextBuilder,
) -> GenOtpErrorCode {
    if out_builder.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let boxed = Box::new(ContextBuilderHandle::new());
    unsafe {
        *out_builder = Box::into_raw(boxed) as *mut GenOtpContextBuilder;
    }
    GenOtpErrorCode::Success
}

/// Set the IP component. Recommend hashing the IP (e.g., SHA-256 hex)
/// instead of the raw IP to avoid leaking it via error logs.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_set_ip(
    b: *mut GenOtpContextBuilder,
    ip: *const c_char,
) -> GenOtpErrorCode {
    if b.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let s = match unsafe { c_str_to_str(ip) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    handle.apply(|builder| builder.ip(&s))
}

/// Set the device identifier (fingerprint hash, UUID, etc.).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_set_device(
    b: *mut GenOtpContextBuilder,
    device: *const c_char,
) -> GenOtpErrorCode {
    if b.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let s = match unsafe { c_str_to_str(device) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    handle.apply(|builder| builder.device(&s))
}

/// Set the session token (stable across the login flow).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_set_session(
    b: *mut GenOtpContextBuilder,
    session: *const c_char,
) -> GenOtpErrorCode {
    if b.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let s = match unsafe { c_str_to_str(session) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    handle.apply(|builder| builder.session(&s))
}

/// Set the origin URL (anti-phishing). Automatically normalized to
/// `scheme://host[:port]` lowercase, with path/query/fragment stripped.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_set_origin(
    b: *mut GenOtpContextBuilder,
    origin: *const c_char,
) -> GenOtpErrorCode {
    if b.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let s = match unsafe { c_str_to_str(origin) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    handle.apply(|builder| builder.origin(&s))
}

/// Set a custom field. Key is prefixed with `x-` internally to avoid
/// collision with built-in fields in future versions.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_set_custom(
    b: *mut GenOtpContextBuilder,
    key: *const c_char,
    value: *const c_char,
) -> GenOtpErrorCode {
    if b.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let k = match unsafe { c_str_to_str(key) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let v = match unsafe { c_str_to_str(value) } {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    handle.apply(|builder| builder.custom(&k, &v))
}

/// Finalize the builder into a [`GenOtpContext`]. After this call, the
/// builder is consumed — subsequent setter calls return `InvalidSecret`.
/// The builder handle itself still MUST be freed with
/// [`genotp_context_builder_free`].
///
/// Output context is owned by the caller and must be freed via
/// [`genotp_context_free`].
#[unsafe(no_mangle)]
pub extern "C" fn genotp_context_builder_build(
    b: *mut GenOtpContextBuilder,
    out_ctx: *mut *mut GenOtpContext,
) -> GenOtpErrorCode {
    if b.is_null() || out_ctx.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &mut *(b as *mut ContextBuilderHandle) };
    let builder = match handle.inner.take() {
        Some(b) => b,
        // Already consumed — caller called build() twice.
        None => return GenOtpErrorCode::InvalidSecret,
    };
    let ctx = builder.build();
    let boxed = Box::new(ctx);
    unsafe {
        *out_ctx = Box::into_raw(boxed) as *mut GenOtpContext;
    }
    GenOtpErrorCode::Success
}

/// Generate TOTP bound to context.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_generate_bound(
    totp: *const GenOtpTotp,
    ctx: *const GenOtpContext,
    time: u64,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if totp.is_null() || ctx.is_null() || out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let totp = unsafe { &*(totp as *const TOTP) };
    let ctx = unsafe { &*(ctx as *const OtpContext) };
    match totp.generate_bound(ctx, time_to_option(time)) {
        Ok(code) => copy_to_out_string(&code, out_string),
        Err(e) => e.into(),
    }
}

/// Verify TOTP bound to context. Constant-time loop — does not early-return.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_totp_verify_bound(
    totp: *const GenOtpTotp,
    ctx: *const GenOtpContext,
    code: *const c_char,
    time: u64,
    window: u64,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if totp.is_null() || ctx.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let totp = unsafe { &*(totp as *const TOTP) };
    let ctx = unsafe { &*(ctx as *const OtpContext) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match totp.verify_bound(code_str, ctx, time_to_option(time), window) {
        Ok(valid) => {
            unsafe { *out_valid = valid };
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

/// Generate HOTP bound to context.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_generate_bound(
    hotp: *const GenOtpHotp,
    counter: u64,
    ctx: *const GenOtpContext,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if hotp.is_null() || ctx.is_null() || out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let hotp = unsafe { &*(hotp as *const HOTP) };
    let ctx = unsafe { &*(ctx as *const OtpContext) };
    match hotp.generate_bound(counter, ctx) {
        Ok(code) => copy_to_out_string(&code, out_string),
        Err(e) => e.into(),
    }
}

/// Verify HOTP bound to context.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_hotp_verify_bound(
    hotp: *const GenOtpHotp,
    code: *const c_char,
    counter: u64,
    ctx: *const GenOtpContext,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if hotp.is_null() || ctx.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let hotp = unsafe { &*(hotp as *const HOTP) };
    let ctx = unsafe { &*(ctx as *const OtpContext) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match hotp.verify_bound(code_str, counter, ctx) {
        Ok(valid) => {
            unsafe { *out_valid = valid };
            GenOtpErrorCode::Success
        }
        Err(e) => e.into(),
    }
}

// ==================== Verifier (replay + rate limit + context) ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_new(
    max_attempts: u32,
    out_verifier: *mut *mut GenOtpVerifier,
) -> GenOtpErrorCode {
    if out_verifier.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let verifier = Verifier::new(max_attempts);
    let boxed = Box::new(verifier);
    unsafe {
        *out_verifier = Box::into_raw(boxed) as *mut GenOtpVerifier;
    }
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_verify(
    v: *const GenOtpVerifier,
    code: *const c_char,
    expected: *const c_char,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if v.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let v = unsafe { &*(v as *const Verifier) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let expected_str = match unsafe { c_str_to_str(expected) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let valid = v.verify_with_replay_protection(code_str, expected_str);
    unsafe { *out_valid = valid };
    GenOtpErrorCode::Success
}

/// Verifier with context binding (Mode 2 — server-stored context check).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_verify_with_context(
    v: *const GenOtpVerifier,
    code: *const c_char,
    expected: *const c_char,
    issued_ctx: *const GenOtpContext,
    request_ctx: *const GenOtpContext,
    out_valid: *mut bool,
) -> GenOtpErrorCode {
    if v.is_null() || issued_ctx.is_null() || request_ctx.is_null() || out_valid.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let v = unsafe { &*(v as *const Verifier) };
    let issued = unsafe { &*(issued_ctx as *const OtpContext) };
    let request = unsafe { &*(request_ctx as *const OtpContext) };
    let code_str = match unsafe { c_str_to_str(code) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let expected_str = match unsafe { c_str_to_str(expected) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let valid = v.verify_with_context(code_str, expected_str, issued, request);
    unsafe { *out_valid = valid };
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_is_rate_limited(
    v: *const GenOtpVerifier,
    out_rate_limited: *mut bool,
) -> GenOtpErrorCode {
    if v.is_null() || out_rate_limited.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let v = unsafe { &*(v as *const Verifier) };
    unsafe { *out_rate_limited = v.is_rate_limited() };
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_verifier_reset_attempts(v: *const GenOtpVerifier) -> GenOtpErrorCode {
    if v.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let v = unsafe { &*(v as *const Verifier) };
    v.reset_attempts();
    GenOtpErrorCode::Success
}

// ==================== Clock Skew Detector ====================

#[unsafe(no_mangle)]
pub extern "C" fn genotp_skew_detector_new(
    capacity: usize,
    out_detector: *mut *mut GenOtpSkewDetector,
) -> GenOtpErrorCode {
    if out_detector.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let detector = ClockSkewDetector::new(capacity);
    let boxed = Box::new(detector);
    unsafe {
        *out_detector = Box::into_raw(boxed) as *mut GenOtpSkewDetector;
    }
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_skew_detector_enable_auto_adjust(
    d: *const GenOtpSkewDetector,
) -> GenOtpErrorCode {
    if d.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let d = unsafe { &*(d as *const ClockSkewDetector) };
    d.enable_auto_adjust();
    GenOtpErrorCode::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn genotp_skew_detector_current_offset(
    d: *const GenOtpSkewDetector,
    out_offset: *mut i64,
) -> GenOtpErrorCode {
    if d.is_null() || out_offset.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let d = unsafe { &*(d as *const ClockSkewDetector) };
    unsafe { *out_offset = d.current_offset() };
    GenOtpErrorCode::Success
}

// ==================== OtpAuthUri (provisioning) ====================

/// Construct an OtpAuthUri builder for generating `otpauth://` URIs
/// (suitable for QR code provisioning to Google Authenticator, Authy, etc.).
///
/// `label` and `secret` are required. Secret should be Base32-encoded
/// (use [`genotp_base32_encode`] to convert raw bytes). Padding `=` and
/// whitespace in the secret are stripped automatically per Google Key
/// URI Format spec.
///
/// Use the `_set_*` setters to add optional fields, then call
/// [`genotp_otpauth_uri_build`] to materialize the URI string.
/// Free with [`genotp_otpauth_uri_free`].
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_new(
    otp_type: GenOtpOtpType,
    label: *const c_char,
    secret: *const c_char,
    out_uri: *mut *mut GenOtpOtpAuthUri,
) -> GenOtpErrorCode {
    if out_uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let label_str = match unsafe { c_str_to_str(label) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let secret_str = match unsafe { c_str_to_str(secret) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let handle = UriHandle {
        typ: otp_type.into(),
        label: label_str.to_string(),
        secret: secret_str.to_string(),
        issuer: None,
        algorithm: None,
        digits: None,
        period: None,
        counter: None,
    };
    let boxed = Box::new(handle);
    unsafe {
        *out_uri = Box::into_raw(boxed) as *mut GenOtpOtpAuthUri;
    }
    GenOtpErrorCode::Success
}

/// Set the issuer (organization name shown in authenticator app).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_set_issuer(
    uri: *mut GenOtpOtpAuthUri,
    issuer: *const c_char,
) -> GenOtpErrorCode {
    if uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let issuer_str = match unsafe { c_str_to_str(issuer) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let handle = unsafe { &mut *(uri as *mut UriHandle) };
    handle.issuer = Some(issuer_str.to_string());
    GenOtpErrorCode::Success
}

/// Set the HMAC algorithm (default if unset: SHA1, matches Google
/// Authenticator default).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_set_algorithm(
    uri: *mut GenOtpOtpAuthUri,
    algorithm: GenOtpAlgorithm,
) -> GenOtpErrorCode {
    if uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &mut *(uri as *mut UriHandle) };
    handle.algorithm = Some(algorithm.into());
    GenOtpErrorCode::Success
}

/// Set the number of digits (6, 7, or 8). Default if unset: 6.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_set_digits(
    uri: *mut GenOtpOtpAuthUri,
    digits: u32,
) -> GenOtpErrorCode {
    if uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &mut *(uri as *mut UriHandle) };
    handle.digits = Some(digits);
    GenOtpErrorCode::Success
}

/// Set the TOTP period in seconds (only meaningful for TOTP).
/// Default if unset: 30.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_set_period(
    uri: *mut GenOtpOtpAuthUri,
    period: u64,
) -> GenOtpErrorCode {
    if uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &mut *(uri as *mut UriHandle) };
    handle.period = Some(period);
    GenOtpErrorCode::Success
}

/// Set the HOTP counter (only meaningful for HOTP, required for HOTP
/// per Google Key URI spec).
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_set_counter(
    uri: *mut GenOtpOtpAuthUri,
    counter: u64,
) -> GenOtpErrorCode {
    if uri.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &mut *(uri as *mut UriHandle) };
    handle.counter = Some(counter);
    GenOtpErrorCode::Success
}

/// Build the final `otpauth://` URI string from the configured fields.
/// Caller must free `out_string` with [`genotp_string_free`].
///
/// The output is ready to be fed into a QR code library (e.g. `libqrencode`).
/// Label, issuer, and secret are percent-encoded per RFC 3986 to handle
/// special characters safely.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_otpauth_uri_build(
    uri: *const GenOtpOtpAuthUri,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if uri.is_null() || out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let handle = unsafe { &*(uri as *const UriHandle) };
    let assembled = handle.assemble();
    let s = assembled.build();
    copy_to_out_string(&s, out_string)
}

// ==================== Error Message ====================

/// Returns a static error message. Always succeeds unless `out_string` is NULL.
#[unsafe(no_mangle)]
pub extern "C" fn genotp_error_message(
    error_code: GenOtpErrorCode,
    out_string: *mut GenOtpString,
) -> GenOtpErrorCode {
    if out_string.is_null() {
        return GenOtpErrorCode::NullPointer;
    }
    let message = match error_code {
        GenOtpErrorCode::Success => "Success",
        GenOtpErrorCode::InvalidSecret => "Invalid secret key",
        GenOtpErrorCode::InvalidCode => "Invalid OTP code",
        GenOtpErrorCode::InvalidDigits => "Invalid number of digits",
        GenOtpErrorCode::InvalidAlgorithm => "Invalid algorithm",
        GenOtpErrorCode::InvalidCounter => "Invalid counter value",
        GenOtpErrorCode::InvalidTime => "Invalid time value",
        GenOtpErrorCode::VerificationFailed => "OTP verification failed",
        GenOtpErrorCode::RateLimited => "Rate limited",
        GenOtpErrorCode::ReplayAttack => "Replay attack detected",
        GenOtpErrorCode::NullPointer => "Null pointer",
        GenOtpErrorCode::InvalidUtf8 => "Invalid UTF-8",
        GenOtpErrorCode::AllocationFailed => "Memory allocation failed",
    };
    copy_to_out_string(message, out_string)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    #[test]
    fn version_string_is_well_formed() {
        // Ensure version constant is null-terminated and parseable.
        let v = GENOTP_VERSION;
        assert!(v.ends_with(b"\0"));
    }

    #[test]
    fn error_enum_repr_matches_int32() {
        // Critical: C side declares `typedef enum {...} GenOtpErrorCode`
        // which is int-sized. Rust side now uses repr(i32). Verify size.
        assert_eq!(
            std::mem::size_of::<GenOtpErrorCode>(),
            std::mem::size_of::<i32>()
        );
        assert_eq!(
            std::mem::size_of::<GenOtpAlgorithm>(),
            std::mem::size_of::<i32>()
        );
    }

    #[test]
    fn base32_encode_empty_no_ub() {
        // Regression: alloc(zero-size) is UB. Must return null+0.
        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let dummy_data = [0u8; 1];
        let err = genotp_base32_encode(dummy_data.as_ptr(), 0, &mut out);
        assert_eq!(err, GenOtpErrorCode::Success);
        assert_eq!(out.len, 0);
        assert!(out.data.is_null());
        // Free should be no-op, not UB.
        genotp_string_free(out);
    }

    #[test]
    fn base32_encode_null_data_with_zero_len_ok() {
        // Empty input with NULL pointer is legitimate.
        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let err = genotp_base32_encode(ptr::null(), 0, &mut out);
        assert_eq!(err, GenOtpErrorCode::Success);
        genotp_string_free(out);
    }

    #[test]
    fn base32_encode_null_data_with_nonzero_len_rejected() {
        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let err = genotp_base32_encode(ptr::null(), 10, &mut out);
        assert_eq!(err, GenOtpErrorCode::NullPointer);
    }

    #[test]
    fn free_zero_length_is_safe() {
        // Regression: dealloc with zero-size layout is UB. Must be no-op.
        let s = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_string_free(s);
        let b = GenOtpBytes {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_bytes_free(b);
    }

    #[test]
    fn hotp_roundtrip() {
        let secret = b"12345678901234567890";
        let mut hotp_ptr: *mut GenOtpHotp = ptr::null_mut();
        let err = genotp_hotp_new(
            secret.as_ptr(),
            secret.len(),
            GenOtpAlgorithm::Sha1,
            6,
            &mut hotp_ptr,
        );
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(!hotp_ptr.is_null());

        let mut code = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let err = genotp_hotp_generate(hotp_ptr, 1, &mut code);
        assert_eq!(err, GenOtpErrorCode::Success);
        assert_eq!(code.len, 6);

        // Verify via C string round-trip.
        let code_slice = unsafe { std::slice::from_raw_parts(code.data, code.len) };
        let c_code = CString::new(code_slice).unwrap();
        let mut valid = false;
        let err = genotp_hotp_verify(hotp_ptr, c_code.as_ptr(), 1, &mut valid);
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(valid);

        genotp_string_free(code);
        genotp_hotp_free(hotp_ptr);
    }

    #[test]
    fn hotp_resync_finds_advanced_counter() {
        let secret = b"12345678901234567890";
        let mut hotp_ptr: *mut GenOtpHotp = ptr::null_mut();
        genotp_hotp_new(
            secret.as_ptr(),
            secret.len(),
            GenOtpAlgorithm::Sha1,
            6,
            &mut hotp_ptr,
        );

        // User counter ahead at 13, server at 10.
        let mut code = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_hotp_generate(hotp_ptr, 13, &mut code);
        let code_slice = unsafe { std::slice::from_raw_parts(code.data, code.len) };
        let c_code = CString::new(code_slice).unwrap();

        let mut valid = false;
        let mut matched = MaybeUninit::<u64>::uninit();
        let err = genotp_hotp_verify_with_resync(
            hotp_ptr,
            c_code.as_ptr(),
            10,
            5,
            &mut valid,
            matched.as_mut_ptr(),
        );
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(valid);
        assert_eq!(unsafe { matched.assume_init() }, 13);

        genotp_string_free(code);
        genotp_hotp_free(hotp_ptr);
    }

    #[test]
    fn totp_time_now_sentinel_distinct_from_epoch() {
        // Regression: previously time=0 meant "use system time", colliding
        // with valid Unix epoch. Now GENOTP_TIME_NOW = u64::MAX.
        assert_eq!(GENOTP_TIME_NOW, u64::MAX);
        assert_eq!(time_to_option(0), Some(0));
        assert_eq!(time_to_option(u64::MAX), None);
        assert_eq!(time_to_option(1_700_000_000), Some(1_700_000_000));
    }

    #[test]
    fn totp_bound_context_rejects_mismatch() {
        let secret = b"12345678901234567890";
        let mut totp_ptr: *mut GenOtpTotp = ptr::null_mut();
        genotp_totp_new(
            secret.as_ptr(),
            secret.len(),
            GenOtpAlgorithm::Sha1,
            6,
            30,
            &mut totp_ptr,
        );

        let mut ctx_a: *mut GenOtpContext = ptr::null_mut();
        let mut ctx_b: *mut GenOtpContext = ptr::null_mut();
        genotp_context_from_bytes(b"ctx-A".as_ptr(), 5, &mut ctx_a);
        genotp_context_from_bytes(b"ctx-B".as_ptr(), 5, &mut ctx_b);

        // Generate bound to ctx_a.
        let mut code = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_totp_generate_bound(totp_ptr, ctx_a, 1_700_000_010, &mut code);

        let code_slice = unsafe { std::slice::from_raw_parts(code.data, code.len) };
        let c_code = CString::new(code_slice).unwrap();

        // Verify with ctx_a → OK.
        let mut valid_a = false;
        genotp_totp_verify_bound(
            totp_ptr,
            ctx_a,
            c_code.as_ptr(),
            1_700_000_010,
            0,
            &mut valid_a,
        );
        assert!(valid_a);

        // Verify with ctx_b → reject.
        let mut valid_b = false;
        genotp_totp_verify_bound(
            totp_ptr,
            ctx_b,
            c_code.as_ptr(),
            1_700_000_010,
            0,
            &mut valid_b,
        );
        assert!(!valid_b);

        genotp_string_free(code);
        genotp_context_free(ctx_a);
        genotp_context_free(ctx_b);
        genotp_totp_free(totp_ptr);
    }

    #[test]
    fn fill_secret_stack_buffer_works() {
        let mut buf = [0u8; 20];
        let err = genotp_fill_secret(buf.as_mut_ptr(), buf.len());
        assert_eq!(err, GenOtpErrorCode::Success);
        assert_ne!(buf, [0u8; 20]);
    }

    #[test]
    fn fill_secret_rejects_short_buffer() {
        let mut buf = [0u8; 8];
        let err = genotp_fill_secret(buf.as_mut_ptr(), buf.len());
        assert_eq!(err, GenOtpErrorCode::InvalidSecret);
    }

    #[test]
    fn fill_secret_rejects_null() {
        let err = genotp_fill_secret(ptr::null_mut(), 20);
        assert_eq!(err, GenOtpErrorCode::NullPointer);
    }

    #[test]
    fn context_builder_setter_order_deterministic() {
        // Critical: two builders with same fields in different setter
        // order MUST produce byte-identical context bytes (sorted by key
        // internally). This is what makes binding deterministic between
        // issue-side and verify-side.
        let ip = CString::new("10.0.0.1").unwrap();
        let device = CString::new("dev-uuid-123").unwrap();
        let session = CString::new("sess-abc").unwrap();

        // Builder A: ip → device → session.
        let mut a: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut a);
        genotp_context_builder_set_ip(a, ip.as_ptr());
        genotp_context_builder_set_device(a, device.as_ptr());
        genotp_context_builder_set_session(a, session.as_ptr());
        let mut ctx_a: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(a, &mut ctx_a);

        // Builder B: session → ip → device (different order).
        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);
        genotp_context_builder_set_session(b, session.as_ptr());
        genotp_context_builder_set_ip(b, ip.as_ptr());
        genotp_context_builder_set_device(b, device.as_ptr());
        let mut ctx_b: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(b, &mut ctx_b);

        // Compare underlying bytes via OtpContext PartialEq.
        let ra = unsafe { &*(ctx_a as *const OtpContext) };
        let rb = unsafe { &*(ctx_b as *const OtpContext) };
        assert_eq!(ra, rb, "setter order must not affect output");

        genotp_context_free(ctx_a);
        genotp_context_free(ctx_b);
        genotp_context_builder_free(a);
        genotp_context_builder_free(b);
    }

    #[test]
    fn context_builder_origin_normalized() {
        // Origin URL with uppercase host + path + query + fragment must
        // normalize to scheme://host[:port] only, lowercased.
        let messy = CString::new("https://BANK.example.com/login?ref=email#top").unwrap();
        let clean = CString::new("https://bank.example.com").unwrap();

        let mut a: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut a);
        genotp_context_builder_set_origin(a, messy.as_ptr());
        let mut ctx_a: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(a, &mut ctx_a);

        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);
        genotp_context_builder_set_origin(b, clean.as_ptr());
        let mut ctx_b: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(b, &mut ctx_b);

        let ra = unsafe { &*(ctx_a as *const OtpContext) };
        let rb = unsafe { &*(ctx_b as *const OtpContext) };
        assert_eq!(ra, rb);

        genotp_context_free(ctx_a);
        genotp_context_free(ctx_b);
        genotp_context_builder_free(a);
        genotp_context_builder_free(b);
    }

    #[test]
    fn context_builder_custom_field_namespaced() {
        // custom("ip", ...) MUST NOT collide with set_ip(...) because
        // custom keys get `x-` prefix.
        let val = CString::new("foo").unwrap();
        let key_ip = CString::new("ip").unwrap();

        let mut a: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut a);
        genotp_context_builder_set_custom(a, key_ip.as_ptr(), val.as_ptr());
        let mut ctx_a: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(a, &mut ctx_a);

        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);
        genotp_context_builder_set_ip(b, val.as_ptr());
        let mut ctx_b: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(b, &mut ctx_b);

        let ra = unsafe { &*(ctx_a as *const OtpContext) };
        let rb = unsafe { &*(ctx_b as *const OtpContext) };
        assert_ne!(ra, rb, "custom(\"ip\") must differ from set_ip()");

        genotp_context_free(ctx_a);
        genotp_context_free(ctx_b);
        genotp_context_builder_free(a);
        genotp_context_builder_free(b);
    }

    #[test]
    fn context_builder_build_twice_returns_error() {
        // After build() consumes the builder, second build() must fail
        // gracefully (no panic, no UB).
        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);

        let mut ctx1: *mut GenOtpContext = ptr::null_mut();
        let r1 = genotp_context_builder_build(b, &mut ctx1);
        assert_eq!(r1, GenOtpErrorCode::Success);
        assert!(!ctx1.is_null());

        let mut ctx2: *mut GenOtpContext = ptr::null_mut();
        let r2 = genotp_context_builder_build(b, &mut ctx2);
        assert_eq!(r2, GenOtpErrorCode::InvalidSecret);
        assert!(ctx2.is_null());

        genotp_context_free(ctx1);
        genotp_context_builder_free(b);
    }

    #[test]
    fn context_builder_setter_after_build_returns_error() {
        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);

        let mut ctx: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(b, &mut ctx);

        // Setter on consumed builder.
        let s = CString::new("late").unwrap();
        let r = genotp_context_builder_set_ip(b, s.as_ptr());
        assert_eq!(r, GenOtpErrorCode::InvalidSecret);

        genotp_context_free(ctx);
        genotp_context_builder_free(b);
    }

    #[test]
    fn context_builder_end_to_end_with_totp_verify() {
        // Full flow: build context → generate_bound → verify_bound succeeds.
        let secret = b"12345678901234567890";
        let mut totp_ptr: *mut GenOtpTotp = ptr::null_mut();
        genotp_totp_new(
            secret.as_ptr(),
            secret.len(),
            GenOtpAlgorithm::Sha1,
            6,
            30,
            &mut totp_ptr,
        );

        let ip = CString::new("10.0.0.1").unwrap();
        let session = CString::new("login-abc").unwrap();

        let mut b: *mut GenOtpContextBuilder = ptr::null_mut();
        genotp_context_builder_new(&mut b);
        genotp_context_builder_set_ip(b, ip.as_ptr());
        genotp_context_builder_set_session(b, session.as_ptr());
        let mut ctx: *mut GenOtpContext = ptr::null_mut();
        genotp_context_builder_build(b, &mut ctx);

        let mut code = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_totp_generate_bound(totp_ptr, ctx, 1_700_000_010, &mut code);

        let code_slice = unsafe { std::slice::from_raw_parts(code.data, code.len) };
        let c_code = CString::new(code_slice).unwrap();

        let mut valid = false;
        genotp_totp_verify_bound(totp_ptr, ctx, c_code.as_ptr(), 1_700_000_010, 0, &mut valid);
        assert!(valid);

        genotp_string_free(code);
        genotp_context_free(ctx);
        genotp_context_builder_free(b);
        genotp_totp_free(totp_ptr);
    }

    #[test]
    fn context_builder_free_null_is_safe() {
        genotp_context_builder_free(ptr::null_mut());
    }

    #[test]
    fn otpauth_uri_totp_full() {
        let label = CString::new("ACME Corp:alice@example.com").unwrap();
        let secret = CString::new("JBSWY3DPEHPK3PXP").unwrap();
        let issuer = CString::new("ACME Corp").unwrap();

        let mut uri_ptr: *mut GenOtpOtpAuthUri = ptr::null_mut();
        let err = genotp_otpauth_uri_new(
            GenOtpOtpType::Totp,
            label.as_ptr(),
            secret.as_ptr(),
            &mut uri_ptr,
        );
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(!uri_ptr.is_null());

        assert_eq!(
            genotp_otpauth_uri_set_issuer(uri_ptr, issuer.as_ptr()),
            GenOtpErrorCode::Success
        );
        assert_eq!(
            genotp_otpauth_uri_set_algorithm(uri_ptr, GenOtpAlgorithm::Sha1),
            GenOtpErrorCode::Success
        );
        assert_eq!(
            genotp_otpauth_uri_set_digits(uri_ptr, 6),
            GenOtpErrorCode::Success
        );
        assert_eq!(
            genotp_otpauth_uri_set_period(uri_ptr, 30),
            GenOtpErrorCode::Success
        );

        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let err = genotp_otpauth_uri_build(uri_ptr, &mut out);
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(out.len > 0);

        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) };
        let s = std::str::from_utf8(bytes).unwrap();
        assert!(s.starts_with("otpauth://totp/"));
        // Label di-percent-encoded: ':' → %3A, '@' → %40, space → %20.
        assert!(s.contains("ACME%20Corp%3Aalice%40example.com"));
        assert!(s.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(s.contains("issuer=ACME%20Corp"));
        assert!(s.contains("algorithm=SHA1"));
        assert!(s.contains("digits=6"));
        assert!(s.contains("period=30"));

        genotp_string_free(out);
        genotp_otpauth_uri_free(uri_ptr);
    }

    #[test]
    fn otpauth_uri_hotp_with_counter() {
        let label = CString::new("svc:user").unwrap();
        let secret = CString::new("JBSWY3DPEHPK3PXP").unwrap();

        let mut uri_ptr: *mut GenOtpOtpAuthUri = ptr::null_mut();
        genotp_otpauth_uri_new(
            GenOtpOtpType::Hotp,
            label.as_ptr(),
            secret.as_ptr(),
            &mut uri_ptr,
        );
        genotp_otpauth_uri_set_counter(uri_ptr, 42);

        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_otpauth_uri_build(uri_ptr, &mut out);

        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) };
        let s = std::str::from_utf8(bytes).unwrap();
        assert!(s.starts_with("otpauth://hotp/"));
        assert!(s.contains("counter=42"));

        genotp_string_free(out);
        genotp_otpauth_uri_free(uri_ptr);
    }

    #[test]
    fn otpauth_uri_strips_padding_and_whitespace_from_secret() {
        // Regression: padding `=` and whitespace must be stripped from
        // secret BEFORE percent-encoding, else they become `%3D` / `%20`
        // and break Google Authenticator parsing.
        let label = CString::new("test").unwrap();
        let messy_secret = CString::new("  JBSWY3DP EHPK3PXP=  ").unwrap();

        let mut uri_ptr: *mut GenOtpOtpAuthUri = ptr::null_mut();
        genotp_otpauth_uri_new(
            GenOtpOtpType::Totp,
            label.as_ptr(),
            messy_secret.as_ptr(),
            &mut uri_ptr,
        );

        let mut out = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        genotp_otpauth_uri_build(uri_ptr, &mut out);

        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) };
        let s = std::str::from_utf8(bytes).unwrap();
        assert!(s.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(!s.contains("%3D"), "padding `=` leaked into URI");
        assert!(!s.contains("%20"), "whitespace leaked into URI");
    }

    #[test]
    fn otpauth_uri_null_label_rejected() {
        let secret = CString::new("ABCD").unwrap();
        let mut uri_ptr: *mut GenOtpOtpAuthUri = ptr::null_mut();
        let err = genotp_otpauth_uri_new(
            GenOtpOtpType::Totp,
            ptr::null(),
            secret.as_ptr(),
            &mut uri_ptr,
        );
        assert_eq!(err, GenOtpErrorCode::NullPointer);
        assert!(uri_ptr.is_null());
    }

    #[test]
    fn otpauth_uri_null_secret_rejected() {
        let label = CString::new("lbl").unwrap();
        let mut uri_ptr: *mut GenOtpOtpAuthUri = ptr::null_mut();
        let err = genotp_otpauth_uri_new(
            GenOtpOtpType::Totp,
            label.as_ptr(),
            ptr::null(),
            &mut uri_ptr,
        );
        assert_eq!(err, GenOtpErrorCode::NullPointer);
    }

    #[test]
    fn otpauth_uri_setters_on_null_handle_rejected() {
        let s = CString::new("x").unwrap();
        assert_eq!(
            genotp_otpauth_uri_set_issuer(ptr::null_mut(), s.as_ptr()),
            GenOtpErrorCode::NullPointer
        );
        assert_eq!(
            genotp_otpauth_uri_set_algorithm(ptr::null_mut(), GenOtpAlgorithm::Sha1),
            GenOtpErrorCode::NullPointer
        );
        assert_eq!(
            genotp_otpauth_uri_set_digits(ptr::null_mut(), 6),
            GenOtpErrorCode::NullPointer
        );
        assert_eq!(
            genotp_otpauth_uri_set_period(ptr::null_mut(), 30),
            GenOtpErrorCode::NullPointer
        );
        assert_eq!(
            genotp_otpauth_uri_set_counter(ptr::null_mut(), 0),
            GenOtpErrorCode::NullPointer
        );
    }

    #[test]
    fn otpauth_uri_free_null_is_safe() {
        // Idempotent and safe: free(NULL) is no-op.
        genotp_otpauth_uri_free(ptr::null_mut());
    }

    #[test]
    fn error_message_returns_string() {
        let mut s = GenOtpString {
            data: ptr::null_mut(),
            len: 0,
        };
        let err = genotp_error_message(GenOtpErrorCode::InvalidSecret, &mut s);
        assert_eq!(err, GenOtpErrorCode::Success);
        assert!(s.len > 0);
        genotp_string_free(s);
    }
}
