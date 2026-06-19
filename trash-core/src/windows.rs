//! Read-only reader for the Windows Recycle Bin `$I` index file format.
//!
//! When a file is sent to the Recycle Bin on Windows Vista and later, the shell
//! writes two files into `$Recycle.Bin\<SID>\`:
//!
//! * an **`$I…`** index file holding the deleted file's metadata (original path,
//!   original size, deletion time), and
//! * an **`$R…`** content file holding the deleted file's data.
//!
//! The two are paired by the trailing identifier + extension after the `$I` /
//! `$R` prefix (`$IAB12CD.docx` ⇄ `$RAB12CD.docx`).
//!
//! This module parses the `$I` metadata and pairs `$I`/`$R` files by a directory
//! scan. It produces no findings — the [`trash-forensic`] analyzer layers
//! anomaly detection on top.
//!
//! # Format
//!
//! The byte layout follows the libyal *Windows Recycle.Bin file formats*
//! specification (see `docs/validation.md` for the citation):
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | Format version (`1` = pre-Win10, `2` = Win10+), little-endian |
//! | 8 | 8 | Original file size, little-endian |
//! | 16 | 8 | Deletion time, Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) |
//!
//! For **version 1** the original filename is a fixed 520-byte UTF-16LE field at
//! offset 24 (260 `wchar_t`). For **version 2** offset 24 holds a 4-byte
//! little-endian filename length in characters (including the NUL terminator),
//! followed by the variable-length UTF-16LE path at offset 28.
//!
//! All integers are read through bounds-checked helpers: `$I` bytes are treated
//! as attacker-controlled, so a truncated or hostile file yields an [`Error`],
//! never a panic.
//!
//! [`trash-forensic`]: https://docs.rs/trash-forensic

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;

/// Fixed header size shared by both format versions: version (8) + size (8) +
/// FILETIME (8) = 24 bytes before any filename data.
const HEADER_LEN: usize = 24;

/// Version-1 fixed filename field: 260 `wchar_t` (UTF-16LE) = 520 bytes.
const V1_NAME_LEN: usize = 520;

/// Upper bound on a version-2 filename character count. Windows paths are capped
/// far below this; the cap defends the allocation against a hostile length field
/// (`u32::MAX` chars would request ~8 GiB). 32 768 chars (`\\?\` extended-path
/// ceiling) is generous and bounded.
const MAX_V2_NAME_CHARS: u32 = 32_768;

/// Errors returned while parsing a `$I` index file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The file is shorter than the 24-byte fixed header.
    #[error("$I file truncated: {got} bytes, need at least {HEADER_LEN} for the header")]
    TruncatedHeader {
        /// Number of bytes actually present.
        got: usize,
    },

    /// The 8-byte version field at offset 0 is neither `1` nor `2`.
    #[error("unsupported $I format version {version} (raw bytes {raw:#018x}); expected 1 or 2")]
    UnsupportedVersion {
        /// The version value as read.
        version: u64,
        /// The raw little-endian bytes, for the investigator.
        raw: u64,
    },

    /// A version-1 file does not contain the full fixed 520-byte name field.
    #[error("$I v1 truncated: {got} bytes, need {needed} for the fixed 520-byte name field")]
    TruncatedV1Name {
        /// Bytes present.
        got: usize,
        /// Bytes required (24 + 520).
        needed: usize,
    },

    /// A version-2 file is too short to hold the 4-byte name-length field.
    #[error("$I v2 truncated: {got} bytes, need at least {needed} for the name-length field")]
    TruncatedV2Length {
        /// Bytes present.
        got: usize,
        /// Bytes required (24 + 4).
        needed: usize,
    },

    /// The version-2 name-length field exceeds [`MAX_V2_NAME_CHARS`] — rejected
    /// before allocating to defend against a hostile length.
    #[error("$I v2 name length {chars} chars exceeds cap {MAX_V2_NAME_CHARS}")]
    NameLengthTooLarge {
        /// The offending character count.
        chars: u32,
    },

    /// The version-2 name-length field claims more bytes than the file holds.
    #[error("$I v2 name claims {needed} bytes but only {got} are present")]
    TruncatedV2Name {
        /// Bytes present after the length field.
        got: usize,
        /// Bytes the length field demands.
        needed: usize,
    },
}

/// The format version recorded in a `$I` file's 8-byte version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IndexVersion {
    /// Pre-Windows 10: fixed 520-byte UTF-16LE filename at offset 24.
    V1,
    /// Windows 10 and later: length-prefixed variable-length filename.
    V2,
}

/// Decoded metadata from a single `$I` index file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecycleBinIndex {
    /// Format version of the parsed `$I` file.
    pub version: IndexVersion,
    /// Original size of the deleted file, in bytes.
    pub original_size: u64,
    /// Deletion timestamp in UTC, or `None` when the `FILETIME` is zero
    /// (recorded but not set).
    pub deleted_at: Option<DateTime<Utc>>,
    /// Original full path of the deleted file (UTF-16LE in the source).
    pub original_path: String,
}

/// Parse the raw bytes of a `$I` index file.
///
/// # Errors
///
/// Returns [`Error`] when the data is truncated, carries an unsupported version,
/// or (version 2) declares a filename length that overflows the buffer or the
/// safety cap. Never panics on hostile input.
pub fn parse_index(data: &[u8]) -> Result<RecycleBinIndex, Error> {
    if data.len() < HEADER_LEN {
        return Err(Error::TruncatedHeader { got: data.len() });
    }

    let raw_version = read_u64_le(data, 0);
    let original_size = read_u64_le(data, 8);
    let filetime = read_u64_le(data, 16);
    let deleted_at = filetime_to_utc(filetime);

    match raw_version {
        1 => {
            let end = HEADER_LEN + V1_NAME_LEN;
            let name_bytes = data.get(HEADER_LEN..end).ok_or(Error::TruncatedV1Name {
                got: data.len(),
                needed: end,
            })?;
            let original_path = decode_utf16le_nul_terminated(name_bytes);
            Ok(RecycleBinIndex {
                version: IndexVersion::V1,
                original_size,
                deleted_at,
                original_path,
            })
        }
        2 => {
            // Length field is 4 bytes at offset 24.
            if data.len() < HEADER_LEN + 4 {
                return Err(Error::TruncatedV2Length {
                    got: data.len(),
                    needed: HEADER_LEN + 4,
                });
            }
            let chars = read_u32_le(data, HEADER_LEN);
            if chars > MAX_V2_NAME_CHARS {
                return Err(Error::NameLengthTooLarge { chars });
            }
            let name_bytes_len = chars as usize * 2;
            let start = HEADER_LEN + 4;
            let end = start + name_bytes_len;
            let name_bytes = data.get(start..end).ok_or(Error::TruncatedV2Name {
                got: data.len().saturating_sub(start),
                needed: name_bytes_len,
            })?;
            let original_path = decode_utf16le_nul_terminated(name_bytes);
            Ok(RecycleBinIndex {
                version: IndexVersion::V2,
                original_size,
                deleted_at,
                original_path,
            })
        }
        other => Err(Error::UnsupportedVersion {
            version: other,
            raw: raw_version,
        }),
    }
}

/// A matched `$I`/`$R` pair (or a lone `$I`) discovered by a directory scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecycleBinPair {
    /// The `$I` index file path.
    pub index_path: PathBuf,
    /// The paired `$R` content file path, if one exists in the directory.
    pub content_path: Option<PathBuf>,
}

/// Scan a directory for `$I` index files and pair each with its `$R` content
/// file by the trailing identifier + extension.
///
/// Files are paired by replacing the leading `$I` with `$R` in the filename
/// (`$IAB12CD.docx` ⇄ `$RAB12CD.docx`); a `$I` with no matching `$R` yields a
/// pair whose `content_path` is `None`.
///
/// # Errors
///
/// Propagates any I/O error from reading the directory.
pub fn scan_pairs(dir: &Path) -> std::io::Result<Vec<RecycleBinPair>> {
    let mut pairs = Vec::new();
    let entries = std::fs::read_dir(dir)?; // cov:unreachable: read_dir error arm needs a missing/denied dir
    for entry in entries {
        let entry = entry?; // cov:unreachable: per-entry `?` needs a mid-scan I/O fault tests cannot force
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue; // cov:unreachable: non-UTF-8 entry is OS-specific, not portably constructible
        };
        if !is_index_name(name) {
            continue;
        }
        let index_path = entry.path();
        let content_name = content_name_for(name);
        let candidate = dir.join(&content_name);
        let content_path = candidate.is_file().then_some(candidate);
        pairs.push(RecycleBinPair {
            index_path,
            content_path,
        });
    }
    Ok(pairs)
}

/// Whether a filename is a `$I` index file (`$I` prefix, case-sensitive as on
/// disk Windows stores it).
fn is_index_name(name: &str) -> bool {
    name.starts_with("$I")
}

/// Map a `$I…` filename to its paired `$R…` filename.
fn content_name_for(index_name: &str) -> String {
    // is_index_name guarantees the `$I` prefix, so this slice is in bounds.
    match index_name.strip_prefix("$I") {
        Some(rest) => format!("$R{rest}"),
        None => index_name.to_string(), // cov:unreachable: callers gate on is_index_name
    }
}

/// Read a little-endian `u64`, returning 0 if the range is out of bounds. The
/// caller has already length-checked the header, so out-of-range never happens
/// for the header reads; the guard keeps the helper panic-free for any caller.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    match data.get(offset..offset + 8) {
        Some(slice) => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(slice);
            u64::from_le_bytes(buf)
        }
        None => 0, // cov:unreachable: header length-checked before every call
    }
}

/// Read a little-endian `u32`, returning 0 if the range is out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    match data.get(offset..offset + 4) {
        Some(slice) => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(slice);
            u32::from_le_bytes(buf)
        }
        None => 0, // cov:unreachable: v2 length field length-checked before call
    }
}

/// `FILETIME` ticks per second (100 ns units).
const TICKS_PER_SECOND: u64 = 10_000_000;

/// Seconds between the `FILETIME` epoch (1601-01-01) and the Unix epoch
/// (1970-01-01).
const EPOCH_DIFF_SECONDS: i64 = 11_644_473_600;

/// Convert a Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) to a UTC
/// datetime. A zero `FILETIME` means "not set" and maps to `None`. An out-of-range
/// value (beyond chrono's representable span) also maps to `None` rather than
/// panicking.
fn filetime_to_utc(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let secs_since_filetime = (filetime / TICKS_PER_SECOND) as i64;
    let sub_tick = (filetime % TICKS_PER_SECOND) as u32;
    let nanos = sub_tick * 100;
    let unix_secs = secs_since_filetime - EPOCH_DIFF_SECONDS;
    match Utc.timestamp_opt(unix_secs, nanos) {
        chrono::LocalResult::Single(dt) => Some(dt),
        _ => None, // cov:unreachable: nanos < 1e9 by construction, secs in i64 range
    }
}

/// Decode a UTF-16LE byte slice up to the first NUL `wchar_t`, lossily replacing
/// invalid sequences with U+FFFD. Bytes after the NUL terminator (padding in the
/// fixed v1 field) are ignored.
fn decode_utf16le_nul_terminated(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A version-2 file with the 24-byte header but no 4-byte length field must
    /// report `TruncatedV2Length`, not panic.
    #[test]
    fn v2_missing_length_field_is_error() {
        let mut data = vec![0u8; HEADER_LEN];
        data[0] = 2;
        let err = parse_index(&data).unwrap_err();
        assert!(matches!(err, Error::TruncatedV2Length { got, needed }
            if got == HEADER_LEN && needed == HEADER_LEN + 4));
    }

    /// A version-2 length field claiming more name bytes than the file holds must
    /// report `TruncatedV2Name`, not index out of bounds.
    #[test]
    fn v2_name_overruns_buffer_is_error() {
        // header + length=10 chars (20 bytes) but only 4 name bytes present.
        let mut data = vec![0u8; HEADER_LEN + 4 + 4];
        data[0] = 2;
        data[HEADER_LEN] = 10; // 10 chars => 20 bytes demanded
        let err = parse_index(&data).unwrap_err();
        assert!(matches!(err, Error::TruncatedV2Name { got, needed }
            if got == 4 && needed == 20));
    }

    /// A non-`$I` filename maps to itself (defensive arm) without panic.
    #[test]
    fn content_name_for_non_index_is_identity() {
        assert_eq!(content_name_for("readme.txt"), "readme.txt");
    }

    /// `scan_pairs` over a temp directory matches `$I` to `$R` and leaves a lone
    /// `$I` unpaired, skipping non-index files.
    #[test]
    fn scan_pairs_directory_round_trip() {
        let dir = std::env::temp_dir().join(format!("rb-core-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("$IAAAAAA.txt"), b"i").unwrap();
        std::fs::write(dir.join("$RAAAAAA.txt"), b"r").unwrap();
        std::fs::write(dir.join("$IBBBBBB.txt"), b"i").unwrap(); // lone $I
        std::fs::write(dir.join("desktop.ini"), b"x").unwrap(); // ignored

        let mut pairs = scan_pairs(&dir).unwrap();
        pairs.sort_by_key(|p| p.index_path.clone());
        assert_eq!(pairs.len(), 2);

        let paired = pairs
            .iter()
            .find(|p| p.index_path.ends_with("$IAAAAAA.txt"))
            .unwrap();
        assert!(paired
            .content_path
            .as_ref()
            .unwrap()
            .ends_with("$RAAAAAA.txt"));

        let lone = pairs
            .iter()
            .find(|p| p.index_path.ends_with("$IBBBBBB.txt"))
            .unwrap();
        assert!(lone.content_path.is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
