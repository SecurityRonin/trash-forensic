//! Read-only readers for **trash / deleted-file artifacts** across operating
//! systems. "Trash" is the umbrella term; each platform's native artifact lives
//! in its own module:
//!
//! | Module | Feature | Artifact |
//! |---|---|---|
//! | [`windows`] | `windows` | Recycle Bin `$I`/`$R` index + content files |
//! | [`linux`] | `linux` | freedesktop.org / XDG `info/*.trashinfo` + `files/` |
//!
//! Every module is gated behind a same-named Cargo feature; all are enabled by
//! default. A consumer that only needs one platform builds with
//! `--no-default-features --features <os>` to drop the others' dependencies.
//!
//! Each reader decodes its artifact into a typed record and pairs metadata with
//! content; none produces findings — the [`trash-forensic`] analyzer layers
//! anomaly detection on top. All readers treat their inputs as
//! attacker-controlled: bounds-checked, never panicking on hostile data.
//!
//! For backward compatibility the Windows reader's items are re-exported at the
//! crate root (`trash_core::parse_index`, [`RecycleBinIndex`], …) — that reader
//! was this crate's original sole contents.
//!
//! [`trash-forensic`]: https://docs.rs/trash-forensic

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "windows")]
pub mod windows;

#[cfg(feature = "linux")]
pub mod linux;

#[cfg(feature = "windows")]
pub use windows::{parse_index, scan_pairs, Error, IndexVersion, RecycleBinIndex, RecycleBinPair};
