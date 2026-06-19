//! Read-only reader for the Linux FreeDesktop / XDG **Trash** artifact.
//!
//! When a file is trashed on a freedesktop.org desktop (GNOME, KDE, XFCE, …) the
//! implementation moves the bytes into a trash directory's `files/` subdirectory
//! and writes a sibling **`info/<name>.trashinfo`** metadata file recording where
//! the file came from and when it was deleted.
//!
//! A trash directory therefore holds two sibling subdirectories:
//!
//! * **`info/`** — one `<name>.trashinfo` INI file per trashed item, and
//! * **`files/`** — the trashed bytes (a file *or* a directory), named `<name>`.
//!
//! The pairing is `info/<name>.trashinfo` ⇄ `files/<name>`, where `<name>` is
//! identical minus the `.trashinfo` extension. Per the spec the content name is
//! derived from the *trashinfo* name and **never** from any path stored inside
//! the file. This crate parses the `.trashinfo` metadata and pairs the two
//! subdirectories; it produces no findings — the [`trash-forensic`] analyzer
//! layers anomaly detection on top.
//!
//! # `.trashinfo` format
//!
//! Per the FreeDesktop **Trash Specification v1.0** (2014-01-02,
//! <https://specifications.freedesktop.org/trash/latest/>) the file is a
//! `.desktop`-like INI:
//!
//! ```text
//! [Trash Info]
//! Path=foo/bar/meow.bow-wow
//! DeletionDate=20040831T22:32:08
//! ```
//!
//! * The first line is the group header `[Trash Info]`.
//! * **`Path=`** holds the original location, percent-encoded per RFC 2396
//!   section 2 (<https://www.rfc-editor.org/rfc/rfc2396#section-2>). This is URI
//!   escaping, **not** form encoding: `+` is a literal plus, not a space.
//! * **`DeletionDate=`** holds the deletion time as `YYYY-MM-DDThh:mm:ss`. The
//!   spec's own example uses the *basic* form `20040831T22:32:08`; real writers
//!   emit the *extended* form `2024-01-15T13:45:09`. Both are accepted. The value
//!   carries **no timezone** — it is naive *local* time, so it is decoded into a
//!   [`NaiveDateTime`] and must never be treated as UTC.
//! * If `Path=` or `DeletionDate=` appears more than once, the **first**
//!   occurrence wins (spec footnote [8]).
//!
//! [`trash-forensic`]: https://docs.rs/trash-forensic

use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;
use percent_encoding::percent_decode_str;
use thiserror::Error;

/// Errors returned while parsing a `.trashinfo` file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrashInfoError {
    /// The first non-blank line was not the `[Trash Info]` group header. Carries
    /// the offending line verbatim so the examiner can see what was there.
    #[error("missing `[Trash Info]` group header; first non-blank line was {found:?}")]
    MissingHeader {
        /// The first non-blank line actually found (empty string if the file had
        /// no non-blank lines at all).
        found: String,
    },

    /// The file has a valid header but no `Path=` key — the original location is
    /// unrecoverable from metadata (the spec's "emergency case").
    #[error("`.trashinfo` has no `Path=` key")]
    MissingPath,
}

/// Decoded metadata from a single `.trashinfo` file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrashInfo {
    /// Original location of the trashed file, percent-decoded (RFC 2396) and then
    /// UTF-8 decoded lossily. Absolute (`/…`) or relative to the directory that
    /// holds the trash root. This is the **first** `Path=` value.
    pub original_path: String,
    /// Deletion timestamp as recorded — naive **local** time, with no timezone.
    /// `None` when `DeletionDate=` is absent or unparseable.
    pub deleted_at: Option<NaiveDateTime>,
}

/// Parse the raw bytes of a `.trashinfo` file.
///
/// # Errors
///
/// Returns [`TrashInfoError::MissingHeader`] when the first non-blank line is not
/// `[Trash Info]` (matched case-insensitively to tolerate the pre-1.0 `[Trash
/// info]` casing), and [`TrashInfoError::MissingPath`] when no `Path=` key is
/// present. A missing or unparseable `DeletionDate=` is **not** an error — it
/// yields `deleted_at == None`. Never panics on hostile input.
pub fn parse_trashinfo(data: &[u8]) -> Result<TrashInfo, TrashInfoError> {
    todo!("RED: parse_trashinfo not yet implemented")
}

/// A trashed item discovered by scanning a trash directory: its `info/` metadata
/// file paired with its `files/` content (if the content is still present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashEntry {
    /// The `info/<name>.trashinfo` metadata file path.
    pub info_path: PathBuf,
    /// The paired `files/<name>` content path, if it still exists. A trashed
    /// directory is a directory here, so existence — not file-ness — is checked.
    pub content_path: Option<PathBuf>,
}

/// Scan a trash directory (the parent of `info/` and `files/`) and pair every
/// `info/<name>.trashinfo` with its `files/<name>` content.
///
/// The content name is derived from the trashinfo basename, never from the
/// `Path=` stored inside it. A `.trashinfo` whose `files/<name>` is absent yields
/// an entry with `content_path == None`.
///
/// # Errors
///
/// Propagates any I/O error from reading the `info/` directory.
pub fn scan_trash(trash_dir: &Path) -> std::io::Result<Vec<TrashEntry>> {
    todo!("RED: scan_trash not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn naive(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, s)
            .unwrap()
    }

    /// The spec's own verbatim example, including its *basic* `YYYYMMDD` date.
    #[test]
    fn parses_spec_example() {
        let data = b"[Trash Info]\nPath=foo/bar/meow.bow-wow\nDeletionDate=20040831T22:32:08\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "foo/bar/meow.bow-wow");
        assert_eq!(info.deleted_at, Some(naive(2004, 8, 31, 22, 32, 8)));
    }

    /// Real-world extended date plus percent-encoded UTF-8 path.
    #[test]
    fn parses_extended_date_and_percent_decodes_path() {
        let data =
            b"[Trash Info]\nPath=/home/u/My%20Docs/r%C3%A9sum%C3%A9.pdf\nDeletionDate=2024-01-15T13:45:09\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/home/u/My Docs/résumé.pdf");
        assert_eq!(info.deleted_at, Some(naive(2024, 1, 15, 13, 45, 9)));
    }

    /// RFC 2396 percent-encoding, not form encoding: `+` stays a literal plus.
    #[test]
    fn plus_is_literal_not_space() {
        let data = b"[Trash Info]\nPath=/tmp/a+b.txt\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/tmp/a+b.txt");
    }

    /// Duplicate keys: the first `Path=` and first `DeletionDate=` win (footnote [8]).
    #[test]
    fn first_path_and_date_win() {
        let data = b"[Trash Info]\nPath=/first\nDeletionDate=2024-01-01T00:00:00\nPath=/second\nDeletionDate=2025-06-06T06:06:06\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/first");
        assert_eq!(info.deleted_at, Some(naive(2024, 1, 1, 0, 0, 0)));
    }

    /// The pre-1.0 `[Trash info]` lowercase casing is tolerated (matched
    /// case-insensitively); the analyzer flags the deviation, the reader decodes.
    #[test]
    fn case_insensitive_header_accepted() {
        let data = b"[Trash info]\nPath=/x\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/x");
    }

    /// No group header => `MissingHeader` carrying the offending first line.
    #[test]
    fn missing_header_is_error() {
        let data = b"Path=/x\n";
        let err = parse_trashinfo(data).unwrap_err();
        assert!(matches!(err, TrashInfoError::MissingHeader { found } if found == "Path=/x"));
    }

    /// Header present but no `Path=` => `MissingPath`.
    #[test]
    fn missing_path_is_error() {
        let data = b"[Trash Info]\nDeletionDate=2024-01-15T13:45:09\n";
        assert_eq!(
            parse_trashinfo(data).unwrap_err(),
            TrashInfoError::MissingPath
        );
    }

    /// A present-but-garbage date yields `None`, not an error.
    #[test]
    fn unparseable_date_is_none() {
        let data = b"[Trash Info]\nPath=/x\nDeletionDate=not-a-date\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/x");
        assert_eq!(info.deleted_at, None);
    }

    /// An absent date yields `None`.
    #[test]
    fn missing_date_is_none() {
        let data = b"[Trash Info]\nPath=/x\n";
        assert_eq!(parse_trashinfo(data).unwrap().deleted_at, None);
    }

    /// A leading UTF-8 BOM and CRLF line endings are tolerated.
    #[test]
    fn bom_and_crlf_tolerated() {
        let data = b"\xEF\xBB\xBF[Trash Info]\r\nPath=/x\r\nDeletionDate=2024-01-15T13:45:09\r\n";
        let info = parse_trashinfo(data).unwrap();
        assert_eq!(info.original_path, "/x");
        assert_eq!(info.deleted_at, Some(naive(2024, 1, 15, 13, 45, 9)));
    }

    /// `scan_trash` pairs `info/<name>.trashinfo` to `files/<name>` by name, and
    /// leaves an orphaned info file (no `files/<name>`) with `content_path` None.
    #[test]
    fn scan_trash_pairs_info_to_files() {
        let dir = std::env::temp_dir().join(format!("trash-core-linux-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("info")).unwrap();
        std::fs::create_dir_all(dir.join("files")).unwrap();
        // paired
        std::fs::write(
            dir.join("info/report.pdf.trashinfo"),
            b"[Trash Info]\nPath=/x\n",
        )
        .unwrap();
        std::fs::write(dir.join("files/report.pdf"), b"data").unwrap();
        // orphan info (content purged)
        std::fs::write(
            dir.join("info/gone.txt.trashinfo"),
            b"[Trash Info]\nPath=/y\n",
        )
        .unwrap();
        // a non-trashinfo file in info/ is ignored
        std::fs::write(dir.join("info/notes.md"), b"x").unwrap();

        let mut entries = scan_trash(&dir).unwrap();
        entries.sort_by_key(|e| e.info_path.clone());
        assert_eq!(entries.len(), 2);

        let paired = entries
            .iter()
            .find(|e| e.info_path.ends_with("report.pdf.trashinfo"))
            .unwrap();
        assert!(paired
            .content_path
            .as_ref()
            .unwrap()
            .ends_with("report.pdf"));

        let orphan = entries
            .iter()
            .find(|e| e.info_path.ends_with("gone.txt.trashinfo"))
            .unwrap();
        assert!(orphan.content_path.is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
