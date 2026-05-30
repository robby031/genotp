//! Deteksi clock skew untuk TOTP.
//!
//! **Catatan zona waktu:** TOTP RFC 6238 selalu berbasis Unix epoch UTC.
//!
//! Mode:
//!
//! - **Passive (default):** detector hanya merekam offset window mana yang
//!   match. Tidak mengubah perilaku verifikasi. Caller memanggil
//!   [`ClockSkewDetector::report`] untuk dapat statistik.
//!
//! - **Active (opt-in):** kalau [`ClockSkewDetector::enable_auto_adjust`]
//!   dipanggil, detector akan menambahkan offset koreksi otomatis ke setiap
//!   verifikasi. Hanya disarankan kalau Anda yakin sumber sample bersih
//!   (cuma dari user yang sudah ter-autentikasi sebelumnya, bukan dari
//!   anonymous request) — jika tidak, attacker bisa skew offset.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

#[derive(Debug, Clone, PartialEq)]
pub struct SkewReport {
    /// Berapa sample yang sudah direkam (capped ke kapasitas).
    pub sample_count: usize,
    /// Rata-rata offset (dalam unit counter) dari sample. Positif = jam
    /// server tertinggal.
    pub mean_offset: f64,
    /// Berapa banyak sample yang nilai offset-nya ≠ 0 — sinyal bahwa user
    /// secara konsisten butuh window non-zero.
    pub non_zero_count: usize,
    /// Rasio sample yang offset-nya berada di edge window
    /// (`|offset| == window_used`). Tinggi = window kemungkinan terlalu
    /// sempit dan ada drift yang nyaris bikin gagal.
    pub edge_hit_ratio: f64,
    /// Rekomendasi berbasis sample.
    pub recommendation: SkewRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SkewRecommendation {
    /// Sample terlalu sedikit untuk simpulan apa pun.
    InsufficientData,
    /// Sebagian besar match di offset 0 — tidak ada drift signifikan.
    NoActionNeeded,
    /// Drift konsisten ke satu arah. Kalau active mode di-enable, offset
    /// koreksi akan otomatis diterapkan.
    ConsistentDrift { mean: f64 },
    /// Banyak hit di edge window — kemungkinan window perlu dinaikkan atau
    /// jam server perlu di-NTP-sync.
    WidenWindowOrCheckNtp,
}

pub struct ClockSkewDetector {
    samples: Mutex<Vec<i64>>,
    capacity: usize,
    auto_adjust: AtomicBool,
    offset: AtomicI64,
    last_window_used: AtomicI64,
}

impl ClockSkewDetector {
    /// `capacity` = berapa sample terakhir yang disimpan untuk statistik.
    /// Disarankan 100–1000.
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
            auto_adjust: AtomicBool::new(false),
            offset: AtomicI64::new(0),
            last_window_used: AtomicI64::new(0),
        }
    }

    /// Catat offset window yang berhasil match. `offset` 0 berarti verifikasi
    /// match di window saat ini, positif = harus mundur, negatif = harus maju.
    /// `window` = nilai parameter window yang dipakai saat verifikasi
    /// (untuk hitung edge-hit ratio).
    pub fn record(&self, matched_offset: i64, window_used: u64) {
        let mut s = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        if s.len() >= self.capacity {
            s.remove(0);
        }
        s.push(matched_offset);
        self.last_window_used
            .store(window_used as i64, Ordering::Relaxed);

        // Update offset hint kalau drift konsisten.
        if self.auto_adjust.load(Ordering::Relaxed) && s.len() >= 16 {
            let mean: f64 = s.iter().map(|&x| x as f64).sum::<f64>() / s.len() as f64;
            if mean.abs() >= 0.5 {
                self.offset.store(mean.round() as i64, Ordering::Relaxed);
            } else {
                self.offset.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Offset koreksi saat ini (dalam unit counter). Selalu 0 kalau auto
    /// adjust belum di-enable atau belum cukup sample.
    pub fn current_offset(&self) -> i64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Aktifkan mode auto-adjust. Hanya panggil ini kalau Anda percaya
    /// sumber sample bersih.
    pub fn enable_auto_adjust(&self) {
        self.auto_adjust.store(true, Ordering::Relaxed);
    }

    pub fn disable_auto_adjust(&self) {
        self.auto_adjust.store(false, Ordering::Relaxed);
        self.offset.store(0, Ordering::Relaxed);
    }

    pub fn is_auto_adjust(&self) -> bool {
        self.auto_adjust.load(Ordering::Relaxed)
    }

    /// Reset semua sample dan offset.
    pub fn reset(&self) {
        let mut s = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        s.clear();
        self.offset.store(0, Ordering::Relaxed);
    }

    /// Hitung laporan statistik atas sample yang ada.
    pub fn report(&self) -> SkewReport {
        let s = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        let sample_count = s.len();
        let window_used = self.last_window_used.load(Ordering::Relaxed);

        if sample_count < 8 {
            return SkewReport {
                sample_count,
                mean_offset: 0.0,
                non_zero_count: s.iter().filter(|&&x| x != 0).count(),
                edge_hit_ratio: 0.0,
                recommendation: SkewRecommendation::InsufficientData,
            };
        }

        let sum: i64 = s.iter().copied().sum();
        let mean_offset = sum as f64 / sample_count as f64;
        let non_zero_count = s.iter().filter(|&&x| x != 0).count();

        let edge_hits = if window_used > 0 {
            s.iter().filter(|&&x| x.abs() == window_used).count()
        } else {
            0
        };
        let edge_hit_ratio = edge_hits as f64 / sample_count as f64;

        let recommendation = if edge_hit_ratio >= 0.2 {
            SkewRecommendation::WidenWindowOrCheckNtp
        } else if mean_offset.abs() >= 0.5 {
            SkewRecommendation::ConsistentDrift { mean: mean_offset }
        } else {
            SkewRecommendation::NoActionNeeded
        };

        SkewReport {
            sample_count,
            mean_offset,
            non_zero_count,
            edge_hit_ratio,
            recommendation,
        }
    }
}

impl Default for ClockSkewDetector {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_data_yields_recommendation() {
        let d = ClockSkewDetector::new(100);
        for i in 0..5 {
            d.record(i, 1);
        }
        let r = d.report();
        assert_eq!(r.recommendation, SkewRecommendation::InsufficientData);
    }

    #[test]
    fn no_drift_yields_no_action() {
        let d = ClockSkewDetector::new(100);
        for _ in 0..50 {
            d.record(0, 1);
        }
        let r = d.report();
        assert_eq!(r.recommendation, SkewRecommendation::NoActionNeeded);
        assert_eq!(r.non_zero_count, 0);
        assert_eq!(r.mean_offset, 0.0);
    }

    #[test]
    fn consistent_drift_detected() {
        let d = ClockSkewDetector::new(100);
        // Server tertinggal 1 window dari user secara konsisten.
        for _ in 0..50 {
            d.record(1, 2);
        }
        let r = d.report();
        match r.recommendation {
            SkewRecommendation::ConsistentDrift { mean } => {
                assert!((mean - 1.0).abs() < 0.01);
            }
            other => panic!("expected ConsistentDrift, got {other:?}"),
        }
    }

    #[test]
    fn edge_hits_trigger_widen_window_recommendation() {
        let d = ClockSkewDetector::new(100);
        // Window=1, dan banyak match di offset ±1 → edge.
        for _ in 0..30 {
            d.record(1, 1);
        }
        for _ in 0..20 {
            d.record(-1, 1);
        }
        let r = d.report();
        assert_eq!(r.recommendation, SkewRecommendation::WidenWindowOrCheckNtp);
        assert!(r.edge_hit_ratio >= 0.2);
    }

    #[test]
    fn auto_adjust_updates_offset_after_enough_samples() {
        let d = ClockSkewDetector::new(100);
        d.enable_auto_adjust();
        // Initial offset = 0.
        assert_eq!(d.current_offset(), 0);
        // Drift konsisten +2.
        for _ in 0..20 {
            d.record(2, 3);
        }
        assert_eq!(d.current_offset(), 2);
    }

    #[test]
    fn passive_mode_does_not_change_offset() {
        let d = ClockSkewDetector::new(100);
        // auto-adjust DIBIARKAN off.
        for _ in 0..50 {
            d.record(5, 10);
        }
        assert_eq!(
            d.current_offset(),
            0,
            "passive mode tidak boleh ubah offset"
        );
    }

    #[test]
    fn reset_clears_everything() {
        let d = ClockSkewDetector::new(100);
        d.enable_auto_adjust();
        for _ in 0..20 {
            d.record(3, 5);
        }
        assert_ne!(d.current_offset(), 0);
        d.reset();
        assert_eq!(d.current_offset(), 0);
        assert_eq!(d.report().sample_count, 0);
    }

    #[test]
    fn capacity_caps_sample_buffer() {
        let d = ClockSkewDetector::new(10);
        for i in 0..100 {
            d.record(i, 1);
        }
        assert_eq!(d.report().sample_count, 10);
    }

    #[test]
    fn disable_auto_adjust_zeroes_offset() {
        let d = ClockSkewDetector::new(100);
        d.enable_auto_adjust();
        for _ in 0..20 {
            d.record(2, 3);
        }
        assert_ne!(d.current_offset(), 0);
        d.disable_auto_adjust();
        assert_eq!(d.current_offset(), 0);
        assert!(!d.is_auto_adjust());
    }
}
