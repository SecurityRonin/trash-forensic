//! Read-only reader for the iOS **Photos "Recently Deleted"** trash state in
//! `Photos.sqlite`.
//!
//! iOS has no filesystem-level recycle bin; "Recently Deleted" is app-level
//! SQLite soft-delete. In the Photos library database
//! (`/private/var/mobile/Media/PhotoData/Photos.sqlite`) a trashed photo or video
//! keeps its row in the `ZASSET` table (named `ZGENERICASSET` on iOS 8–13) with:
//!
//! * `ZTRASHEDSTATE = 1` — the asset is in Recently Deleted, and
//! * `ZTRASHEDDATE` — when it was trashed, in **Mac Absolute Time** (the Cocoa /
//!   Core Data epoch, 2001-01-01; add 978 307 200 s to get a Unix timestamp).
//!
//! The asset survives a ~30-day retention window before the row is purged.
//! Recovery of *purged* rows (WAL, freelist, carving) is out of scope here — it is
//! the job of the underlying [`sqlite_core`] engine, which this module reuses for
//! all SQLite access (no `libsqlite3`).
//!
//! Sources: The Forensic Scooter, "Photos.sqlite Query Documentation"
//! (<https://theforensicscooter.com/2022/05/02/photos-sqlite-query-documentation-notable-artifacts/>);
//! kacos2000 `Photos_sqlite.sql`. This module reports the live trashed rows;
//! `trash-forensic` grades them.

use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;

/// Seconds between the Mac Absolute Time epoch (2001-01-01) and the Unix epoch.
const MAC_ABSOLUTE_EPOCH_OFFSET: i64 = 978_307_200;

/// Errors returned while reading trashed assets from a `Photos.sqlite`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IosError {
    /// The underlying SQLite engine could not open or read the database. Carries
    /// the engine's message.
    #[error("Photos.sqlite read failed: {0}")]
    Sqlite(String),

    /// Neither `ZASSET` nor `ZGENERICASSET` is present — not a Photos library DB.
    #[error("no ZASSET/ZGENERICASSET table found; not a Photos.sqlite")]
    NoAssetTable,

    /// The asset table has no `ZTRASHEDSTATE` column — an unexpected schema.
    #[error("asset table has no ZTRASHEDSTATE column")]
    NoTrashedColumn,
}

/// A single iOS Photos asset currently in "Recently Deleted".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrashedAsset {
    /// The asset's primary key (`Z_PK` / row id).
    pub rowid: i64,
    /// The on-disk filename (`ZFILENAME`), if recorded.
    pub filename: Option<String>,
    /// The asset's directory within the library (`ZDIRECTORY`), if recorded.
    pub directory: Option<String>,
    /// When the asset was trashed (`ZTRASHEDDATE` converted to UTC), or `None`
    /// when the column is NULL/zero.
    pub trashed_at: Option<DateTime<Utc>>,
}

/// Read every currently-trashed (`ZTRASHEDSTATE = 1`) asset from the bytes of a
/// `Photos.sqlite`, sorted by row id.
///
/// # Errors
///
/// Returns [`IosError`] when the bytes are not a readable SQLite database, carry
/// no `ZASSET`/`ZGENERICASSET` table, or that table lacks `ZTRASHEDSTATE`.
pub fn parse_trashed_assets(db_bytes: Vec<u8>) -> Result<Vec<TrashedAsset>, IosError> {
    todo!(
        "RED: parse_trashed_assets not yet implemented (len={})",
        db_bytes.len()
    )
}

/// As [`parse_trashed_assets`], but layering a `Photos.sqlite-wal` over the main
/// database so the trashed/restored state committed only in the WAL is seen.
///
/// # Errors
///
/// As [`parse_trashed_assets`].
pub fn parse_trashed_assets_with_wal(
    db_bytes: Vec<u8>,
    wal: &[u8],
) -> Result<Vec<TrashedAsset>, IosError> {
    todo!(
        "RED: parse_trashed_assets_with_wal not yet implemented ({}/{})",
        db_bytes.len(),
        wal.len()
    )
}

/// Convert a Mac Absolute Time value (Cocoa epoch seconds, possibly fractional)
/// to a UTC datetime. `None` for zero or out-of-range values.
#[must_use]
fn mac_absolute_to_utc(seconds: f64) -> Option<DateTime<Utc>> {
    if seconds == 0.0 {
        return None;
    }
    let whole = seconds.trunc() as i64;
    let nanos = (seconds.fract() * 1_000_000_000.0).round() as u32;
    let unix = whole.checked_add(MAC_ABSOLUTE_EPOCH_OFFSET)?;
    Utc.timestamp_opt(unix, nanos).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `Photos.sqlite` (Python `sqlite3`-minted) with two trashed assets
    /// and one live asset; oracle decode by the `sqlite3` CLI.
    const FIXTURE: &[u8] = include_bytes!("../tests/data/Photos.sqlite");

    fn at(unix: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(unix, 0).single().unwrap()
    }

    /// Only the two `ZTRASHEDSTATE = 1` assets are returned; the live one is not.
    #[test]
    fn returns_only_trashed_assets() {
        let assets = parse_trashed_assets(FIXTURE.to_vec()).unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(
            assets.iter().map(|a| a.rowid).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    /// Field decode matches the sqlite3 oracle (filename, dir, Mac-Absolute date).
    #[test]
    fn decodes_fields_to_oracle_values() {
        let assets = parse_trashed_assets(FIXTURE.to_vec()).unwrap();
        let a = &assets[0];
        assert_eq!(a.rowid, 1);
        assert_eq!(a.filename.as_deref(), Some("IMG_0001.HEIC"));
        assert_eq!(a.directory.as_deref(), Some("DCIM/100APPLE"));
        // 700000000 (Mac Absolute) + 978307200 = 1678307200 == 2023-03-08 20:26:40Z
        assert_eq!(a.trashed_at, Some(at(1_678_307_200)));
        assert_eq!(assets[1].trashed_at, Some(at(701_234_567 + 978_307_200)));
    }

    /// Non-SQLite bytes are a typed error, not a panic.
    #[test]
    fn invalid_database_is_error() {
        assert!(parse_trashed_assets(vec![0u8; 100]).is_err());
        assert!(parse_trashed_assets(Vec::new()).is_err());
    }

    /// Mac Absolute Time conversion: zero -> None, a known value -> the oracle UTC.
    #[test]
    fn mac_absolute_conversion() {
        assert_eq!(mac_absolute_to_utc(0.0), None);
        assert_eq!(mac_absolute_to_utc(700_000_000.0), Some(at(1_678_307_200)));
    }
}
