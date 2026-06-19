//! Forensic anomaly analysis for Android `MediaStore` `.trashed-`/`.pending-`
//! filenames decoded by [`trash_core::android`].
//!
//! | Code | Category | Severity | Meaning |
//! |---|---|---|---|
//! | `TRASH-EXPIRED-RESIDUE` | Residue | Low | a `.trashed-` item still present though its `dateExpires` has passed (survived the idle sweep, still recoverable) |
//! | `TRASH-MALFORMED-NAME` | Structure | Low | a name with a `trashed`/`pending` prefix that does not parse as a valid token (raw name surfaced) |
//!
//! The expiry check needs a reference time, supplied by the caller, so the
//! analysis stays deterministic and testable. Findings are observations, never
//! legal conclusions: the analyst concludes.

use chrono::{DateTime, Utc};
use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use trash_core::android::parse_trashed_name;

use crate::ANALYZER;

/// An Android `MediaStore` trash-filename anomaly, with the offending name attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrashedNameAnomaly {
    /// A `.trashed-` item whose `dateExpires` is in the past but which is still
    /// present — it outlived the idle-maintenance sweep and remains recoverable.
    ExpiredResidue {
        /// The full `.trashed-…` filename, surfaced verbatim.
        name: String,
    },
    /// A name that carries a `trashed`/`pending` prefix yet does not parse as a
    /// valid token (non-numeric expiry, missing field, …).
    MalformedName {
        /// The offending filename, surfaced verbatim.
        name: String,
    },
}

/// Audit a single directory-entry name against the `MediaStore` trash codec.
/// `now` is the reference time the item's expiry is compared against (the caller
/// passes the acquisition/analysis time).
///
/// Flags an expired-but-present `.trashed-` item and a malformed trash token. A
/// well-formed, unexpired name — or a name that is not a trash token at all —
/// yields no findings.
#[must_use]
pub fn audit_trashed_name(name: &str, now: DateTime<Utc>) -> Vec<Finding> {
    todo!("RED: audit_trashed_name not yet implemented: {name} {now}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().unwrap()
    }

    /// A trashed item whose expiry is still in the future yields nothing.
    #[test]
    fn unexpired_item_has_no_findings() {
        // expires at 1_700_000_000; now is well before that.
        assert!(audit_trashed_name(".trashed-1700000000-photo.jpg", at(1_699_000_000)).is_empty());
    }

    /// A non-trash filename yields nothing.
    #[test]
    fn plain_name_has_no_findings() {
        assert!(audit_trashed_name("vacation.jpg", at(1_700_000_000)).is_empty());
    }

    /// A trashed item present past its expiry => Residue/Low expired residue.
    #[test]
    fn expired_item_flagged() {
        let findings = audit_trashed_name(".trashed-1700000000-photo.jpg", at(1_800_000_000));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-EXPIRED-RESIDUE");
        assert_eq!(findings[0].category, Category::Residue);
        assert_eq!(findings[0].severity, Some(Severity::Low));
        assert_eq!(
            findings[0].evidence[0].value,
            ".trashed-1700000000-photo.jpg"
        );
    }

    /// A `trashed`/`pending`-prefixed name that does not parse => Structure/Low.
    #[test]
    fn malformed_token_flagged() {
        let findings = audit_trashed_name(".trashed-not-a-number.png", at(1_700_000_000));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-MALFORMED-NAME");
        assert_eq!(findings[0].category, Category::Structure);
        assert_eq!(findings[0].severity, Some(Severity::Low));
    }

    /// Every finding is stamped with the analyzer name and the filename scope.
    #[test]
    fn source_carries_analyzer_and_scope() {
        let findings = audit_trashed_name(".trashed-1700000000-photo.jpg", at(1_800_000_000));
        assert_eq!(findings[0].source.analyzer, ANALYZER);
        assert_eq!(findings[0].source.scope, ".trashed-1700000000-photo.jpg");
    }
}
