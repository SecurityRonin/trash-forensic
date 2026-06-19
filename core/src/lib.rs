//! Read-only reader for the Windows Recycle Bin `$I` index file format.
//!
//! Stub: public API only — implementation lands in the GREEN commit.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Errors returned while parsing a `$I` index file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The file is shorter than the 24-byte fixed header.
    #[error("$I file truncated: {got} bytes")]
    TruncatedHeader {
        /// Bytes present.
        got: usize,
    },
    /// The version field is neither `1` nor `2`.
    #[error("unsupported $I version {version} (raw {raw:#018x})")]
    UnsupportedVersion {
        /// Version value.
        version: u64,
        /// Raw bytes.
        raw: u64,
    },
    /// Version-1 fixed name field truncated.
    #[error("$I v1 truncated: {got} bytes, need {needed}")]
    TruncatedV1Name {
        /// Bytes present.
        got: usize,
        /// Bytes required.
        needed: usize,
    },
    /// Version-2 name-length field missing.
    #[error("$I v2 truncated: {got} bytes, need {needed}")]
    TruncatedV2Length {
        /// Bytes present.
        got: usize,
        /// Bytes required.
        needed: usize,
    },
    /// Version-2 name length exceeds the safety cap.
    #[error("$I v2 name length {chars} too large")]
    NameLengthTooLarge {
        /// Offending count.
        chars: u32,
    },
    /// Version-2 name overflows the buffer.
    #[error("$I v2 name claims {needed} bytes, only {got} present")]
    TruncatedV2Name {
        /// Bytes present.
        got: usize,
        /// Bytes demanded.
        needed: usize,
    },
}

/// The format version recorded in a `$I` file's 8-byte version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IndexVersion {
    /// Pre-Windows 10.
    V1,
    /// Windows 10 and later.
    V2,
}

/// Decoded metadata from a single `$I` index file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecycleBinIndex {
    /// Format version.
    pub version: IndexVersion,
    /// Original file size in bytes.
    pub original_size: u64,
    /// Deletion timestamp (UTC), `None` when the `FILETIME` is zero.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Original full path of the deleted file.
    pub original_path: String,
}

/// Parse the raw bytes of a `$I` index file.
///
/// # Errors
/// Returns [`Error`] on malformed input. (Stub: always errors.)
pub fn parse_index(_data: &[u8]) -> Result<RecycleBinIndex, Error> {
    Err(Error::TruncatedHeader { got: 0 })
}

/// A matched `$I`/`$R` pair (or a lone `$I`) discovered by a directory scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecycleBinPair {
    /// The `$I` index file path.
    pub index_path: PathBuf,
    /// The paired `$R` content file path, if present.
    pub content_path: Option<PathBuf>,
}

/// Scan a directory for `$I` index files and pair each with its `$R` content
/// file.
///
/// # Errors
/// Propagates directory-read I/O errors. (Stub: always empty.)
pub fn scan_pairs(_dir: &Path) -> std::io::Result<Vec<RecycleBinPair>> {
    Ok(Vec::new())
}
