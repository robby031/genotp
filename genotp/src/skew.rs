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

/// State internal ring buffer dengan cached aggregates.
///
/// Buffer pre-allocated dengan size = `capacity`. `write_idx` menunjuk ke
/// slot berikutnya yang akan ditulis (round-robin). Saat buffer penuh, kita
/// **overwrite** slot tertua secara O(1) — tidak ada shift array.
///
/// `sum` dan `non_zero_count` dipertahankan secara **incremental**: saat
/// menggantikan slot lama, kita kurangi nilai lama lalu tambahkan nilai
/// baru. Ini menjaga `record()` O(1) di semua kondisi.
struct SkewState {
    buffer: Vec<i64>,
    capacity: usize,
    write_idx: usize,
    len: usize,
    sum: i64,
    non_zero_count: usize,
}

impl SkewState {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
            write_idx: 0,
            len: 0,
            sum: 0,
            non_zero_count: 0,
        }
    }

    /// O(1) append/overwrite. Mengembalikan true kalau ini overwrite
    /// (buffer sudah penuh sebelumnya).
    fn push(&mut self, value: i64) {
        if self.len < self.capacity {
            // Append — buffer belum penuh.
            self.buffer.push(value);
            self.sum += value;
            if value != 0 {
                self.non_zero_count += 1;
            }
            self.len += 1;
            self.write_idx = self.len % self.capacity;
        } else {
            // Overwrite slot tertua di write_idx.
            let old = self.buffer[self.write_idx];
            self.buffer[self.write_idx] = value;

            // Update cached sum: subtract lama, add baru.
            self.sum = self.sum - old + value;

            // Update non_zero_count incremental.
            if old != 0 {
                self.non_zero_count -= 1;
            }
            if value != 0 {
                self.non_zero_count += 1;
            }

            self.write_idx = (self.write_idx + 1) % self.capacity;
        }
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.write_idx = 0;
        self.len = 0;
        self.sum = 0;
        self.non_zero_count = 0;
    }
}

pub struct ClockSkewDetector {
    inner: Mutex<SkewState>,
    auto_adjust: AtomicBool,
    offset: AtomicI64,
    last_window_used: AtomicI64,
}

impl ClockSkewDetector {
    /// `capacity` = berapa sample terakhir yang disimpan untuk statistik.
    /// Disarankan 100–1000. Buffer di-pre-allocate sekali; tidak ada heap
    /// allocation atau memmove di hot path.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(SkewState::new(capacity)),
            auto_adjust: AtomicBool::new(false),
            offset: AtomicI64::new(0),
            last_window_used: AtomicI64::new(0),
        }
    }

    /// Catat offset window yang berhasil match. `offset` 0 berarti verifikasi
    /// match di window saat ini, positif = harus mundur, negatif = harus maju.
    /// `window` = nilai parameter window yang dipakai saat verifikasi
    /// (untuk hitung edge-hit ratio).
    ///
    /// **Performa:** O(1) per call. Mutex hold time konstan — tidak ada
    /// memmove array atau iterasi sample. Aman di bawah load tinggi
    /// (10K+ verify/detik) tanpa jadi contention hotspot.
    pub fn record(&self, matched_offset: i64, window_used: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.push(matched_offset);
        self.last_window_used
            .store(window_used as i64, Ordering::Relaxed);

        // Update offset hint kalau drift konsisten. Pakai cached sum → O(1).
        if self.auto_adjust.load(Ordering::Relaxed) && state.len >= 16 {
            let mean = state.sum as f64 / state.len as f64;
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
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.clear();
        self.offset.store(0, Ordering::Relaxed);
    }

    /// Hitung laporan statistik atas sample yang ada.
    ///
    /// Sebagian besar field dibaca dari cached aggregate (O(1)). Hanya
    /// `edge_hit_ratio` yang masih O(N) karena `window_used` bisa berubah
    /// antar sample — tapi `report()` dimaksudkan untuk admin/debug call,
    /// bukan hot path.
    pub fn report(&self) -> SkewReport {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let sample_count = state.len;
        let non_zero_count = state.non_zero_count;
        let window_used = self.last_window_used.load(Ordering::Relaxed);

        if sample_count < 8 {
            return SkewReport {
                sample_count,
                mean_offset: 0.0,
                non_zero_count,
                edge_hit_ratio: 0.0,
                recommendation: SkewRecommendation::InsufficientData,
            };
        }

        let mean_offset = state.sum as f64 / sample_count as f64;

        let edge_hits = if window_used > 0 {
            state
                .buffer
                .iter()
                .filter(|&&x| x.abs() == window_used)
                .count()
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
    fn ring_buffer_wraparound_preserves_correct_aggregates() {
        // Setelah buffer wrap, cached sum dan non_zero_count harus
        // mencerminkan WINDOW saat ini (sample terakhir-N), bukan total
        // historis. Test ini memvalidasi incremental update.
        // Pakai capacity >= 8 supaya lewat threshold InsufficientData.
        let d = ClockSkewDetector::new(8);

        // Fase 1: isi 8 elemen, semua = 10.
        for _ in 0..8 {
            d.record(10, 1);
        }
        let r1 = d.report();
        assert!(
            (r1.mean_offset - 10.0).abs() < 0.001,
            "fase 1 mean: {}",
            r1.mean_offset
        );
        assert_eq!(r1.non_zero_count, 8);
        assert_eq!(r1.sample_count, 8);

        // Fase 2: overwrite 8 sample lama dengan nilai 0 (wrap penuh).
        for _ in 0..8 {
            d.record(0, 1);
        }
        // Buffer sekarang seharusnya [0,0,0,0,0,0,0,0]. Kalau cached sum
        // tidak update incremental dengan benar, mean masih akan 10.
        let r2 = d.report();
        assert!(
            r2.mean_offset.abs() < 0.001,
            "fase 2 mean salah: {}",
            r2.mean_offset
        );
        assert_eq!(
            r2.non_zero_count, 0,
            "non_zero salah: {}",
            r2.non_zero_count
        );
        assert_eq!(r2.sample_count, 8);
    }

    #[test]
    fn ring_buffer_partial_wrap_mixed_values() {
        // Edge case: buffer berisi mix dari sebelum & sesudah wrap.
        // Capacity 8, fill 8 lalu overwrite 3 → final buffer = [overwrite3 + old5].
        let d = ClockSkewDetector::new(8);

        // Isi awal: 1..=8 → sum awal = 36.
        for v in 1i64..=8 {
            d.record(v, 1);
        }
        assert_eq!(d.report().sample_count, 8);

        // Overwrite 3 slot tertua (yang berisi 1, 2, 3) dengan 100, 200, 300.
        // Buffer setelah ini: [100, 200, 300, 4, 5, 6, 7, 8].
        // sum = 100+200+300+4+5+6+7+8 = 630.
        for v in [100i64, 200, 300] {
            d.record(v, 1);
        }

        let r = d.report();
        assert_eq!(r.sample_count, 8);
        let expected_mean = 630.0 / 8.0; // = 78.75
        assert!(
            (r.mean_offset - expected_mean).abs() < 0.001,
            "expected mean {expected_mean}, got {}",
            r.mean_offset
        );
        assert_eq!(r.non_zero_count, 8);
    }

    #[test]
    fn ring_buffer_overwriting_zero_preserves_non_zero_count() {
        // Regression: pastikan ketika sample baru = 0 menggantikan sample
        // lama yang non-zero, non_zero_count berkurang dengan benar.
        let d = ClockSkewDetector::new(8);
        for _ in 0..8 {
            d.record(5, 1);
        }
        assert_eq!(d.report().non_zero_count, 8);

        // Overwrite semua dengan 0.
        for _ in 0..8 {
            d.record(0, 1);
        }
        assert_eq!(d.report().non_zero_count, 0);
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
