//! Forensic anomaly analysis for **trash / deleted-file artifacts**, layered on
//! the [`trash_core`] readers. Each platform's analyzer lives in its own module,
//! gated behind a same-named Cargo feature (all enabled by default):
//!
//! | Module | Feature | Scheme | Artifact |
//! |---|---|---|---|
//! | [`windows`] | `windows` | `RECYCLEBIN-*` | Recycle Bin `$I`/`$R` |
//! | [`linux`] | `linux` | `TRASH-*` | freedesktop.org / XDG `.trashinfo` |
//!
//! Every analyzer inspects a parsed reader record + its pairing and reports
//! anomalies as canonical [`forensicnomicon::report::Finding`]s, so trash
//! findings aggregate alongside every other `SecurityRonin` analyzer. Findings
//! are observations, never legal conclusions: the analyst concludes.
//!
//! ```no_run
//! # #[cfg(feature = "windows")]
//! # fn demo(dir: &std::path::Path) -> std::io::Result<()> {
//! use trash_core::{parse_index, scan_pairs};
//! use trash_forensic::audit_pair;
//! for pair in scan_pairs(dir)? {
//!     let bytes = std::fs::read(&pair.index_path)?;
//!     if let Ok(index) = parse_index(&bytes) {
//!         for finding in audit_pair(&index, &pair) {
//!             println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "windows")]
pub mod windows;

#[cfg(feature = "linux")]
pub mod linux;

#[cfg(feature = "macos")]
pub mod macos;

#[cfg(feature = "android")]
pub mod android;

#[cfg(feature = "ios")]
pub mod ios;

#[cfg(feature = "windows")]
pub use windows::{audit_pair, AnomalyKind};

#[cfg(feature = "linux")]
pub use linux::{audit_entry, TrashAnomaly};

#[cfg(feature = "macos")]
pub use macos::{audit_put_back, DsStoreAnomaly};

#[cfg(feature = "android")]
pub use android::{audit_trashed_name, TrashedNameAnomaly};

#[cfg(feature = "ios")]
pub use ios::{audit_trashed_asset, IosAssetAnomaly};

/// Analyzer name, recorded on every finding's [`forensicnomicon::report::Source`]
/// for reproducibility, shared across the per-OS analyzers.
pub const ANALYZER: &str = "trash-forensic";

/// Whether a stored path contains a parent-directory (`..`) component, treating
/// both Windows (`\`) and POSIX (`/`) separators. Matches `..` only as a whole
/// path component, so a filename like `my..notes.txt` is not flagged. Shared by
/// every platform analyzer (path traversal is a cross-platform concealment tell).
#[cfg(any(feature = "windows", feature = "linux", feature = "macos"))]
pub(crate) fn has_path_traversal(path: &str) -> bool {
    path.split(['\\', '/']).any(|component| component == "..")
}
