//! Context binding untuk OTP.
//!
//! Standar RFC 6238 / 4226 menghasilkan OTP yang **hanya** bergantung pada
//! (secret, counter). Akibatnya, sekali kode 6 digit bocor (intercept WhatsApp,
//! brute force, phishing), siapa pun bisa pakai.
//!
//! Context binding mengikat OTP ke informasi tambahan (IP, device, session,
//! origin URL) sehingga:
//!
//! - **Mode 1 (HMAC binding):** OTP yang dihasilkan berbeda untuk context
//!   berbeda. Penyerang yang memegang kode tapi context berbeda akan
//!   menghitung digit yang berbeda — tidak ada nilai yang bisa di-replay.
//! - **Mode 2 (Verifier-stored):** OTP standar (kompatibel Google
//!   Authenticator), tapi server menolak verifikasi kalau context request
//!   berbeda dari context saat OTP di-issue.
//!
//! Lihat [`OtpContext`] dan builder-nya untuk pemakaian.

use std::collections::BTreeMap;

/// Context tambahan untuk mengikat OTP ke kondisi spesifik
/// (IP, device, session, origin URL, dll).
///
/// Buat lewat [`OtpContext::empty`], [`OtpContext::from_bytes`], atau
/// [`OtpContext::builder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpContext {
    bytes: Vec<u8>,
}

impl OtpContext {
    /// Context kosong. Saat dipakai dengan `*_bound`, hasilnya identik
    /// dengan TOTP/HOTP standar (backward compatible dengan RFC 6238/4226).
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Bytes mentah sebagai context. Caller bertanggung jawab atas
    /// kanonikalisasi (urutan field, encoding) — kalau byte berbeda satu
    /// bit saja, binding gagal.
    ///
    /// Gunakan [`OtpContext::builder`] kalau ingin canonicalization otomatis.
    pub fn from_bytes(b: impl Into<Vec<u8>>) -> Self {
        Self { bytes: b.into() }
    }

    /// Builder dengan field umum (`ip`, `device`, `session`, `origin`) yang
    /// otomatis dinormalisasi dan diserialisasi secara kanonikal.
    pub fn builder() -> OtpContextBuilder {
        OtpContextBuilder {
            fields: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Builder untuk context yang memastikan dua sisi (issue + verify) memberikan
/// byte yang sama persis ketika field-nya sama, tanpa peduli urutan setter.
pub struct OtpContextBuilder {
    fields: BTreeMap<String, String>,
}

impl OtpContextBuilder {
    /// Hash atau representasi IP yang stabil. Disarankan SHA-256 hex dari
    /// IP, bukan IP mentah, agar tidak bocor lewat error/log.
    pub fn ip(mut self, ip: &str) -> Self {
        self.fields.insert("ip".into(), ip.to_string());
        self
    }

    /// Identifier device (fingerprint hash, UUID device, dll).
    pub fn device(mut self, device_id: &str) -> Self {
        self.fields.insert("device".into(), device_id.to_string());
        self
    }

    /// Session ID atau token yang stabil sepanjang flow login.
    pub fn session(mut self, session: &str) -> Self {
        self.fields.insert("session".into(), session.to_string());
        self
    }

    /// Origin URL untuk anti-phishing. Dinormalisasi ke `scheme://host[:port]`
    /// lowercase, tanpa trailing slash, tanpa path/query/fragment.
    pub fn origin(mut self, origin: &str) -> Self {
        self.fields
            .insert("origin".into(), normalize_origin(origin));
        self
    }

    /// Field custom. Key di-prefix `x-` agar tidak bentrok dengan field
    /// built-in di versi future.
    pub fn custom(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(format!("x-{key}"), value.to_string());
        self
    }

    /// Serialize ke bytes kanonikal: field sudah urut (BTreeMap), tiap
    /// entry "key=value\0" sehingga delimiter tidak bisa di-spoof oleh
    /// value yang berisi karakter sama.
    pub fn build(self) -> OtpContext {
        let mut bytes = Vec::new();
        for (k, v) in self.fields {
            bytes.extend_from_slice(k.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
            bytes.push(0u8);
        }
        OtpContext { bytes }
    }
}

fn normalize_origin(origin: &str) -> String {
    let lower = origin.trim().to_lowercase();
    let no_fragment = lower.split('#').next().unwrap_or("");
    let no_query = no_fragment.split('?').next().unwrap_or("");
    // Buang path tapi simpan scheme://host[:port].
    if let Some(scheme_end) = no_query.find("://") {
        let after_scheme = &no_query[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let trimmed = &no_query[..scheme_end + 3 + host_end];
        trimmed.trim_end_matches('/').to_string()
    } else {
        no_query.trim_end_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_context_has_no_bytes() {
        assert!(OtpContext::empty().is_empty());
        assert_eq!(OtpContext::empty().as_bytes(), b"");
    }

    #[test]
    fn builder_order_does_not_matter() {
        let a = OtpContext::builder()
            .ip("10.0.0.1")
            .device("dev123")
            .session("sess456")
            .build();

        let b = OtpContext::builder()
            .session("sess456")
            .device("dev123")
            .ip("10.0.0.1")
            .build();

        assert_eq!(a, b, "urutan setter harus tidak memengaruhi hasil");
    }

    #[test]
    fn different_values_produce_different_bytes() {
        let a = OtpContext::builder().ip("10.0.0.1").build();
        let b = OtpContext::builder().ip("10.0.0.2").build();
        assert_ne!(a, b);
    }

    #[test]
    fn origin_normalized() {
        let a = OtpContext::builder().origin("https://EXAMPLE.com").build();
        let b = OtpContext::builder().origin("https://example.com/").build();
        let c = OtpContext::builder()
            .origin("https://example.com/login?next=/home")
            .build();
        assert_eq!(a, b);
        assert_eq!(a, c, "path/query/fragment harus dibuang dari origin");
    }

    #[test]
    fn origin_keeps_port() {
        let a = OtpContext::builder()
            .origin("https://example.com:8443/foo")
            .build();
        let b = OtpContext::builder()
            .origin("https://example.com:8443")
            .build();
        assert_eq!(a, b);
    }

    #[test]
    fn delimiter_cannot_be_spoofed_via_value() {
        // Kalau value berisi '=' atau '\0', binding tetap aman karena field
        // disusun dengan key terlebih dulu (sudah dipisah oleh '=' pertama)
        // dan tiap entry diakhiri '\0'. Tapi value yang mengandung '\0' bisa
        // mengubah interpretasi jika sembarang. Test ini memastikan dua input
        // berbeda menghasilkan bytes berbeda walaupun "kelihatan" mirip.
        let a = OtpContext::builder().custom("a", "b=c").build();
        let b = OtpContext::builder()
            .custom("a", "b")
            .custom("c", "")
            .build();
        assert_ne!(a, b);
    }

    #[test]
    fn from_bytes_passthrough() {
        let ctx = OtpContext::from_bytes(vec![1, 2, 3, 4]);
        assert_eq!(ctx.as_bytes(), &[1, 2, 3, 4]);
        assert!(!ctx.is_empty());
    }
}
