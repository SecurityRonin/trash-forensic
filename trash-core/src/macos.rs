//! Read-only reader for the macOS **Trash** put-back metadata stored in a
//! Trash folder's `.DS_Store` file.
//!
//! On modern macOS (Big Sur → Sequoia) there is no `$I`/`$R`-style sidecar and no
//! put-back extended attribute: the original location of a trashed item is
//! recorded only inside the Trash folder's `.DS_Store`, as two per-item B-tree
//! records keyed by the item's *current* name in the Trash:
//!
//! * **`ptbN`** — *Put-Back Name*: the item's original filename, and
//! * **`ptbL`** — *Put-Back Location*: the item's original parent directory,
//!
//! both of `.DS_Store` data type `ustr` (a length-prefixed UTF-16**BE** string).
//! `ptbL` is stored in the APFS firmlink form `System/Volumes/Data/…`;
//! [`PutBack::original_path`] normalises that to the user-visible `/…` while the
//! raw value stays available verbatim.
//!
//! Many legitimately trashed items have **no** put-back record (Finder writes
//! `.DS_Store` lazily, and `rm`/non-Finder deletes never write one), so the
//! absence of a record is normal, not evidence of tampering.
//!
//! # `.DS_Store` / `Bud1` format
//!
//! The container is a Finder "Desktop Services Store": a 4-byte `00 00 00 01`
//! prefix, the magic `Bud1`, then a **buddy allocator** whose table-of-contents
//! maps the key `DSDB` to a **B-tree** of records. The layout follows Wim Lewis's
//! reverse-engineered `Mac::Finder::DSStore` `DSStoreFormat.pod`
//! (<https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod>); the
//! `ptbN`/`ptbL` record types are newer Finder additions cross-checked against
//! al45tair's `ds_store` library, which also generated this crate's test fixture.
//!
//! All reads are bounds-checked: a truncated or hostile `.DS_Store` yields a
//! typed [`DsStoreError`], never a panic, and the B-tree walk is cycle-guarded.

use thiserror::Error;

/// Errors returned while parsing a `.DS_Store` put-back store.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DsStoreError {
    /// The file is shorter than the 36-byte `Bud1` header.
    #[error(".DS_Store truncated: {got} bytes, need at least {needed} for the Bud1 header")]
    TruncatedHeader {
        /// Bytes present.
        got: usize,
        /// Bytes required.
        needed: usize,
    },

    /// The leading `00 00 00 01` / `Bud1` magic is wrong. Carries the offending
    /// bytes for the investigator.
    #[error("bad .DS_Store magic: word0={word0:#010x}, magic={magic:?} (expected 1 / b\"Bud1\")")]
    BadMagic {
        /// The first 32-bit big-endian word (expected `1`).
        word0: u32,
        /// The 4 magic bytes (expected `Bud1`).
        magic: [u8; 4],
    },

    /// The two copies of the root-block offset in the header disagree — the
    /// allocator is inconsistent (Finder rejects such files).
    #[error(".DS_Store root offsets differ: {first:#x} vs {second:#x}")]
    RootOffsetMismatch {
        /// The first root-block offset.
        first: u32,
        /// The second (validation) copy.
        second: u32,
    },

    /// A block address points outside the file, or a structure overruns its
    /// block. Carries the operation for diagnosis.
    #[error(".DS_Store read out of bounds while reading {what}")]
    OutOfBounds {
        /// What was being read when the bound was exceeded.
        what: &'static str,
    },

    /// The allocator's table of contents has no `DSDB` B-tree entry.
    #[error(".DS_Store has no DSDB B-tree entry")]
    NoDsdb,

    /// A record carried a `.DS_Store` data-type code the format does not define,
    /// so the record stream cannot be safely advanced. Carries the bytes.
    #[error("unknown .DS_Store record data type {typecode:?}")]
    UnknownDataType {
        /// The offending 4-byte data-type code.
        typecode: [u8; 4],
    },
}

/// A recovered macOS put-back record: an item in the Trash together with where it
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PutBack {
    /// The item's current name inside the Trash (the `.DS_Store` record key).
    /// Finder de-duplicates colliding names, so this need not equal
    /// [`original_name`](Self::original_name).
    pub trash_name: String,
    /// The original filename at deletion time (`ptbN`), if recorded.
    pub original_name: Option<String>,
    /// The original parent directory (`ptbL`) **verbatim**, in the stored
    /// firmlink form (`System/Volumes/Data/…`), if recorded.
    pub original_location: Option<String>,
}

impl PutBack {
    /// The full original path, `ptbL` + `ptbN`, with the firmlink prefix
    /// normalised to the user-visible `/…`. `None` unless both `ptbN` and `ptbL`
    /// were recorded.
    #[must_use]
    pub fn original_path(&self) -> Option<String> {
        let location = self.original_location.as_deref()?;
        let name = self.original_name.as_deref()?;
        let dir = normalize_firmlink(location);
        Some(if dir.ends_with('/') {
            format!("{dir}{name}")
        } else {
            format!("{dir}/{name}")
        })
    }
}

/// Normalise an APFS firmlink `ptbL` value (`System/Volumes/Data/…` or
/// `/System/Volumes/Data/…`) to the user-visible absolute path (`/…`). A value
/// that is not in firmlink form is returned with a single leading slash.
fn normalize_firmlink(location: &str) -> String {
    let trimmed = location.strip_prefix('/').unwrap_or(location);
    let rest = trimmed
        .strip_prefix("System/Volumes/Data/")
        .unwrap_or(trimmed);
    format!("/{rest}")
}

/// Parse the raw bytes of a Trash `.DS_Store` file and return every put-back
/// record it carries, sorted by [`trash_name`](PutBack::trash_name).
///
/// # Errors
///
/// Returns [`DsStoreError`] when the header magic is wrong, the allocator/B-tree
/// is truncated or inconsistent, or a record carries an undefined data-type code.
/// Never panics on hostile input.
pub fn parse_put_back(data: &[u8]) -> Result<Vec<PutBack>, DsStoreError> {
    todo!(
        "RED: parse_put_back not yet implemented (len={})",
        data.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `.DS_Store` minted by al45tair's `ds_store` library (the oracle),
    /// carrying two put-back items plus one non-put-back (`Iloc` blob) record.
    const FIXTURE: &[u8] = include_bytes!("../tests/data/putback.DS_Store");

    fn get<'a>(records: &'a [PutBack], name: &str) -> &'a PutBack {
        records.iter().find(|r| r.trash_name == name).unwrap()
    }

    /// The two put-back items are recovered; the `Iloc` blob record is skipped.
    #[test]
    fn recovers_both_put_back_items() {
        let records = parse_put_back(FIXTURE).unwrap();
        assert_eq!(records.len(), 2);
    }

    /// A clean item: trash name == original name, firmlink location normalised,
    /// full original path reconstructed. Values match the oracle decode.
    #[test]
    fn clean_item_decodes_to_oracle_values() {
        let records = parse_put_back(FIXTURE).unwrap();
        let r = get(&records, "Reference Letter.png");
        assert_eq!(r.original_name.as_deref(), Some("Reference Letter.png"));
        assert_eq!(
            r.original_location.as_deref(),
            Some("System/Volumes/Data/Users/4n6h4x0r/Downloads/")
        );
        assert_eq!(
            r.original_path().as_deref(),
            Some("/Users/4n6h4x0r/Downloads/Reference Letter.png")
        );
    }

    /// A Finder-deduped item: the trash name (`report 2.pdf`) diverges from the
    /// original name (`report.pdf`) — the reader reports both faithfully.
    #[test]
    fn deduped_trash_name_diverges_from_original() {
        let records = parse_put_back(FIXTURE).unwrap();
        let r = get(&records, "report 2.pdf");
        assert_eq!(r.original_name.as_deref(), Some("report.pdf"));
        assert_eq!(
            r.original_path().as_deref(),
            Some("/Users/4n6h4x0r/Documents/report.pdf")
        );
    }

    /// Bad magic is a typed error carrying the offending bytes, not a panic.
    #[test]
    fn bad_magic_is_error() {
        let data = vec![0u8; 64];
        assert!(matches!(
            parse_put_back(&data).unwrap_err(),
            DsStoreError::BadMagic { .. }
        ));
    }

    /// A header-length-only / truncated file errors rather than panicking.
    #[test]
    fn truncated_is_error_not_panic() {
        assert!(parse_put_back(&FIXTURE[..20]).is_err());
        assert!(parse_put_back(&[]).is_err());
    }

    /// Firmlink normalisation is independent of the trailing slash and tolerates
    /// a non-firmlink absolute path.
    #[test]
    fn firmlink_normalisation() {
        assert_eq!(
            normalize_firmlink("System/Volumes/Data/Users/x/Desktop/"),
            "/Users/x/Desktop/"
        );
        assert_eq!(normalize_firmlink("/Users/x/Desktop/"), "/Users/x/Desktop/");
    }
}
