//! Read-only decoder for the Android **`MediaStore` trash** filename convention.
//!
//! On Android 11+ (API 30) the system-level, vendor-independent trash renames a
//! media file *in place* to a self-describing hidden name:
//!
//! ```text
//! .trashed-<dateExpires>-<originalDisplayName>
//! ```
//!
//! with a 7-day sibling mechanism using the `pending` prefix. Because the
//! `MediaProvider` rebuilds its `files`-table row *from this name* on rescan, the
//! name alone recovers the original filename and the expiry time **even if the
//! database is wiped**. This module decodes that name; correlating it with the
//! `external.db` `files` table is a separate (`SQLite`) concern.
//!
//! # Codec (authoritative)
//!
//! AOSP `packages/providers/MediaProvider` `util/FileUtils.java`
//! (<https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android11-release/src/com/android/providers/media/util/FileUtils.java>):
//!
//! ```text
//! PATTERN_EXPIRES_FILE = (?i)^\.(pending|trashed)-(\d+)-([^/]+)$
//! DEFAULT_DURATION_TRASHED = 30 days,  DEFAULT_DURATION_PENDING = 7 days
//! ```
//!
//! * `<dateExpires>` is **epoch SECONDS** (the source divides milliseconds by
//!   1000), not milliseconds.
//! * `<originalDisplayName>` is the original filename including extension; it may
//!   itself contain `-` and `.`, so it is everything after the *second* `-`.
//! * The prefix match is case-insensitive; the display name keeps its case.

use chrono::{DateTime, TimeZone, Utc};

/// Whether a `MediaStore` name encodes the 30-day **trashed** state or the 7-day
/// **pending** state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TrashState {
    /// `.trashed-…` — the 30-day deferred-deletion bin.
    Trashed,
    /// `.pending-…` — the 7-day pending mechanism.
    Pending,
}

impl TrashState {
    /// The default retention window AOSP applies for this state, in seconds
    /// (30 days trashed, 7 days pending).
    #[must_use]
    pub fn default_retention_secs(self) -> i64 {
        const SECONDS_PER_DAY: i64 = 86_400;
        match self {
            TrashState::Trashed => 30 * SECONDS_PER_DAY,
            TrashState::Pending => 7 * SECONDS_PER_DAY,
        }
    }
}

/// A decoded `MediaStore` `.trashed-`/`.pending-` filename.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrashedName {
    /// Trashed (30-day) vs pending (7-day).
    pub state: TrashState,
    /// The `dateExpires` field, as stored: **epoch seconds**.
    pub date_expires: i64,
    /// The original display name (filename incl. extension), case preserved.
    pub original_name: String,
}

impl TrashedName {
    /// The expiry instant encoded in the name (`dateExpires`), or `None` if the
    /// value is outside the representable range.
    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        Utc.timestamp_opt(self.date_expires, 0).single()
    }

    /// The **inferred** deletion instant: `dateExpires` minus the state's default
    /// retention window. This holds only for the default-case (the user did not
    /// override the duration), so it is an inference, not a recorded fact.
    #[must_use]
    pub fn inferred_deleted_at(&self) -> Option<DateTime<Utc>> {
        let secs = self
            .date_expires
            .checked_sub(self.state.default_retention_secs())?;
        Utc.timestamp_opt(secs, 0).single()
    }
}

/// Decode a single filename per AOSP `PATTERN_EXPIRES_FILE`. Returns `None` for
/// any name that is not a well-formed `.trashed-`/`.pending-` token (including a
/// plain, non-trashed filename) — the caller decides whether a `None` that still
/// carries a trashed/pending prefix is a malformed-token anomaly.
#[must_use]
pub fn parse_trashed_name(name: &str) -> Option<TrashedName> {
    let rest = name.strip_prefix('.')?;
    let (state, after) = strip_state_prefix(rest)?;
    // The display name is everything after the SECOND `-`, so split on the first
    // `-` of `after` (which holds `<digits>-<name>`).
    let (digits, original) = after.split_once('-')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let date_expires = digits.parse::<i64>().ok()?;
    if original.is_empty() || original.contains('/') {
        return None;
    }
    Some(TrashedName {
        state,
        date_expires,
        original_name: original.to_string(),
    })
}

/// Strip a case-insensitive `trashed-`/`pending-` prefix, returning the state and
/// the remainder. Boundary-safe: a leading multi-byte character yields `None`.
fn strip_state_prefix(rest: &str) -> Option<(TrashState, &str)> {
    for (prefix, state) in [
        ("trashed-", TrashState::Trashed),
        ("pending-", TrashState::Pending),
    ] {
        let Some(head) = rest.get(..prefix.len()) else {
            continue;
        };
        if head.eq_ignore_ascii_case(prefix) {
            return rest.get(prefix.len()..).map(|tail| (state, tail));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().unwrap()
    }

    /// The canonical trashed form decodes to state, epoch-seconds expiry, and name.
    #[test]
    fn decodes_trashed() {
        let t = parse_trashed_name(".trashed-1700000000-photo.jpg").unwrap();
        assert_eq!(t.state, TrashState::Trashed);
        assert_eq!(t.date_expires, 1_700_000_000);
        assert_eq!(t.original_name, "photo.jpg");
    }

    /// The 7-day sibling uses the `pending` prefix.
    #[test]
    fn decodes_pending() {
        let t = parse_trashed_name(".pending-1700000000-clip.mp4").unwrap();
        assert_eq!(t.state, TrashState::Pending);
    }

    /// The original name may contain `-` and `.`: split on the SECOND `-` only.
    #[test]
    fn original_name_keeps_dashes_and_dots() {
        let t = parse_trashed_name(".trashed-1700000000-my-holiday.2024-04.jpg").unwrap();
        assert_eq!(t.original_name, "my-holiday.2024-04.jpg");
    }

    /// The prefix is matched case-insensitively; the name keeps its case.
    #[test]
    fn prefix_is_case_insensitive() {
        let t = parse_trashed_name(".TrAsHeD-1700000000-IMG_0001.HEIC").unwrap();
        assert_eq!(t.state, TrashState::Trashed);
        assert_eq!(t.original_name, "IMG_0001.HEIC");
    }

    /// Non-trashed names are not decoded.
    #[test]
    fn ignores_non_trashed_names() {
        assert!(parse_trashed_name("photo.jpg").is_none());
        assert!(parse_trashed_name(".hidden").is_none());
        assert!(parse_trashed_name("invoice-2024-final.pdf").is_none());
    }

    /// A trashed prefix with a non-numeric expiry is not a valid token.
    #[test]
    fn rejects_non_numeric_expiry() {
        assert!(parse_trashed_name(".trashed-abc-photo.jpg").is_none());
    }

    /// A display name containing `/` is rejected (the codec is `[^/]+`).
    #[test]
    fn rejects_slash_in_name() {
        assert!(parse_trashed_name(".trashed-1700000000-a/b.jpg").is_none());
    }

    /// A missing expiry or missing name is rejected.
    #[test]
    fn rejects_missing_fields() {
        assert!(parse_trashed_name(".trashed-1700000000-").is_none());
        assert!(parse_trashed_name(".trashed--photo.jpg").is_none());
    }

    /// `expires_at` is the encoded instant; `inferred_deleted_at` subtracts the
    /// 30-day default window for a trashed item.
    #[test]
    fn timestamps_decode_and_infer() {
        let t = parse_trashed_name(".trashed-1700000000-photo.jpg").unwrap();
        assert_eq!(t.expires_at(), Some(at(1_700_000_000)));
        assert_eq!(
            t.inferred_deleted_at(),
            Some(at(1_700_000_000 - 30 * 86_400))
        );
    }
}
