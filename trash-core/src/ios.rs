//! Read-only reader for the iOS **Photos "Recently Deleted"** trash state in
//! `Photos.sqlite`.
//!
//! iOS has no filesystem-level recycle bin; "Recently Deleted" is app-level
//! `SQLite` soft-delete. In the Photos library database
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
//! all `SQLite` access (no `libsqlite3`).
//!
//! Sources: The Forensic Scooter, "Photos.sqlite Query Documentation"
//! (<https://theforensicscooter.com/2022/05/02/photos-sqlite-query-documentation-notable-artifacts/>);
//! kacos2000 `Photos_sqlite.sql`. This module reports the live trashed rows;
//! `trash-forensic` grades them.

use chrono::{DateTime, TimeZone, Utc};
use sqlite_core::{Database, Value};
use thiserror::Error;

/// Seconds between the Mac Absolute Time epoch (2001-01-01) and the Unix epoch.
const MAC_ABSOLUTE_EPOCH_OFFSET: i64 = 978_307_200;

/// Errors returned while reading trashed assets from a `Photos.sqlite`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IosError {
    /// The underlying `SQLite` engine could not open or read the database. Carries
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
/// Returns [`IosError`] when the bytes are not a readable `SQLite` database, carry
/// no `ZASSET`/`ZGENERICASSET` table, or that table lacks `ZTRASHEDSTATE`.
pub fn parse_trashed_assets(db_bytes: Vec<u8>) -> Result<Vec<TrashedAsset>, IosError> {
    let db = Database::open(db_bytes).map_err(|e| IosError::Sqlite(format!("{e:?}")))?;
    extract_trashed(&db)
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
    let db =
        Database::open_with_wal(db_bytes, wal).map_err(|e| IosError::Sqlite(format!("{e:?}")))?;
    extract_trashed(&db)
}

/// Find the `ZASSET`/`ZGENERICASSET` table, map the trashed columns by name, and
/// return the live rows whose `ZTRASHEDSTATE` is 1.
fn extract_trashed(db: &Database) -> Result<Vec<TrashedAsset>, IosError> {
    // `sqlite_master` rows are `[type, name, tbl_name, rootpage, sql]`.
    let schema = db.live_schema_rows();
    let (root_page, sql) = find_asset_table(&schema).ok_or(IosError::NoAssetTable)?;
    let columns = parse_column_names(&sql);
    let idx_state = column_index(&columns, "ZTRASHEDSTATE").ok_or(IosError::NoTrashedColumn)?;
    let idx_date = column_index(&columns, "ZTRASHEDDATE");
    let idx_filename = column_index(&columns, "ZFILENAME");
    let idx_directory = column_index(&columns, "ZDIRECTORY");

    let rows = db
        .read_table(root_page, columns.len())
        .map_err(|e| IosError::Sqlite(format!("{e:?}")))?;

    let mut assets: Vec<TrashedAsset> = rows
        .into_iter()
        .filter(|row| matches!(row.values.get(idx_state), Some(Value::Integer(1))))
        .map(|row| TrashedAsset {
            rowid: row.rowid,
            filename: idx_filename.and_then(|i| text_at(&row.values, i)),
            directory: idx_directory.and_then(|i| text_at(&row.values, i)),
            trashed_at: idx_date.and_then(|i| date_at(&row.values, i)),
        })
        .collect();
    assets.sort_by_key(|a| a.rowid);
    Ok(assets)
}

/// Locate the Photos asset table in the schema rows, returning its root page and
/// `CREATE` SQL.
fn find_asset_table(schema: &[Vec<Value>]) -> Option<(u32, String)> {
    schema.iter().find_map(|row| {
        if row.first().and_then(value_text) != Some("table") {
            return None;
        }
        let name = row.get(1).and_then(value_text)?;
        if name != "ZASSET" && name != "ZGENERICASSET" {
            return None;
        }
        let root = row.get(3).and_then(value_int)?;
        let sql = row.get(4).and_then(value_text)?;
        Some((u32::try_from(root).ok()?, sql.to_string()))
    })
}

/// Extract the ordered column names from a `CREATE TABLE` statement, skipping
/// table-level constraints (`PRIMARY KEY(...)`, `FOREIGN KEY`, …).
fn parse_column_names(sql: &str) -> Vec<String> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    // The column list lies between the first `(` and the final `)`.
    let inner = &sql[open + 1..];
    let body = inner.rfind(')').map_or(inner, |close| &inner[..close]);

    let mut columns = Vec::new();
    for part in split_top_level(body) {
        let Some(first) = part.split_whitespace().next() else {
            continue;
        };
        let name = first.trim_matches(|c| matches!(c, '"' | '`' | '[' | ']' | '\''));
        if name.is_empty() {
            continue;
        }
        let is_constraint = matches!(
            name.to_ascii_uppercase().as_str(),
            "PRIMARY" | "FOREIGN" | "UNIQUE" | "CHECK" | "CONSTRAINT" | "KEY"
        );
        if !is_constraint {
            columns.push(name.to_string());
        }
    }
    columns
}

/// Split a string on commas that sit at parenthesis depth zero.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Case-insensitive column-name lookup.
fn column_index(columns: &[String], name: &str) -> Option<usize> {
    columns.iter().position(|c| c.eq_ignore_ascii_case(name))
}

/// The text value at `index`, or `None` if absent or not text.
fn text_at(values: &[Value], index: usize) -> Option<String> {
    match values.get(index) {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

/// The Mac-Absolute-Time value at `index` (`REAL` or `INTEGER`) as UTC.
fn date_at(values: &[Value], index: usize) -> Option<DateTime<Utc>> {
    let seconds = match values.get(index)? {
        Value::Real(r) => *r,
        Value::Integer(i) => *i as f64,
        _ => return None,
    };
    mac_absolute_to_utc(seconds)
}

/// Borrow a [`Value`] as text.
fn value_text(value: &Value) -> Option<&str> {
    match value {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

/// Borrow a [`Value`] as an integer.
fn value_int(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(i) => Some(*i),
        _ => None,
    }
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

    /// Non-`SQLite` bytes are a typed error, not a panic.
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

    /// The WAL-overlay entry point with an empty overlay decodes the same rows.
    #[test]
    fn with_empty_wal_matches_plain() {
        let assets = parse_trashed_assets_with_wal(FIXTURE.to_vec(), &[]).unwrap();
        assert_eq!(assets.len(), 2);
    }

    /// `find_asset_table` skips a non-table row and a non-matching table name.
    #[test]
    fn find_asset_table_skips_non_matches() {
        let row = |t: &str, n: &str, root: i64, sql: &str| {
            vec![
                Value::Text(t.into()),
                Value::Text(n.into()),
                Value::Text(n.into()),
                Value::Integer(root),
                Value::Text(sql.into()),
            ]
        };
        let schema = vec![
            row("index", "idx", 9, "CREATE INDEX idx ON ZASSET(x)"),
            row("table", "Other", 3, "CREATE TABLE Other ( a )"),
            row(
                "table",
                "ZASSET",
                4,
                "CREATE TABLE ZASSET ( ZTRASHEDSTATE INTEGER )",
            ),
        ];
        let (root, _sql) = find_asset_table(&schema).unwrap();
        assert_eq!(root, 4);
    }

    /// `parse_column_names` handles missing parens, nested parens (sized types),
    /// empty/quoted-empty parts, and table-level constraints.
    #[test]
    fn parse_column_names_edge_ddl() {
        assert!(parse_column_names("CREATE TABLE x").is_empty());
        let cols = parse_column_names(
            "CREATE TABLE x ( a INTEGER, '' TEXT, b VARCHAR(50), , PRIMARY KEY(a) )",
        );
        assert_eq!(cols, vec!["a".to_string(), "b".to_string()]);
    }

    /// Value accessors return `None` for the wrong variant; `date_at` reads `REAL`.
    #[test]
    fn value_accessors_reject_wrong_type() {
        assert_eq!(value_text(&Value::Integer(1)), None);
        assert_eq!(value_int(&Value::Text("x".into())), None);
        assert_eq!(text_at(&[Value::Null], 0), None);
        assert_eq!(
            date_at(&[Value::Real(700_000_000.0)], 0),
            Some(at(1_678_307_200))
        );
        assert_eq!(date_at(&[Value::Null], 0), None);
    }
}
