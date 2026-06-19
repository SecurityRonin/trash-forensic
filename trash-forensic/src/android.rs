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

impl TrashedNameAnomaly {
    /// Stable, scheme-prefixed machine code (a published contract).
    fn code(&self) -> &'static str {
        match self {
            TrashedNameAnomaly::ExpiredResidue { .. } => "TRASH-EXPIRED-RESIDUE",
            TrashedNameAnomaly::MalformedName { .. } => "TRASH-MALFORMED-NAME",
        }
    }

    /// Analytical lens for the anomaly.
    fn category(&self) -> Category {
        match self {
            TrashedNameAnomaly::ExpiredResidue { .. } => Category::Residue,
            TrashedNameAnomaly::MalformedName { .. } => Category::Structure,
        }
    }

    /// The offending filename, common to both variants.
    fn name(&self) -> &str {
        match self {
            TrashedNameAnomaly::ExpiredResidue { name }
            | TrashedNameAnomaly::MalformedName { name } => name,
        }
    }

    /// Human-readable, consistent-with note.
    fn note(&self) -> String {
        match self {
            TrashedNameAnomaly::ExpiredResidue { name } => format!(
                "trashed item {name} is still present though its dateExpires has passed — \
                 consistent with the file having survived the idle-maintenance sweep and \
                 remaining recoverable"
            ),
            TrashedNameAnomaly::MalformedName { name } => format!(
                "name {name} carries a trashed/pending prefix but does not parse as a valid \
                 MediaStore trash token — surfaced verbatim for inspection"
            ),
        }
    }

    /// Convert this anomaly into a canonical [`Finding`]. Both variants are Low
    /// severity.
    fn to_finding(&self, source: Source) -> Finding {
        let name = self.name().to_string();
        Finding::observation(Severity::Low, self.category(), self.code())
            .note(self.note())
            .source(source)
            .evidence_item(Evidence {
                field: "name".to_string(),
                value: name.clone(),
                location: Some(Location::Path(name)),
            })
            .build()
    }
}

/// Whether a name carries a case-insensitive `.trashed-`/`.pending-` prefix
/// (each nine bytes). Boundary-safe: a leading multi-byte char yields `false`.
fn has_trashed_prefix(name: &str) -> bool {
    name.get(..9).is_some_and(|head| {
        let lower = head.to_ascii_lowercase();
        lower == ".trashed-" || lower == ".pending-"
    })
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
    let mut anomalies = Vec::new();
    match parse_trashed_name(name) {
        Some(parsed) => {
            if parsed.expires_at().is_some_and(|expires| expires < now) {
                anomalies.push(TrashedNameAnomaly::ExpiredResidue {
                    name: name.to_string(),
                });
            }
        }
        None if has_trashed_prefix(name) => {
            anomalies.push(TrashedNameAnomaly::MalformedName {
                name: name.to_string(),
            });
        }
        None => {}
    }

    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: name.to_string(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    anomalies
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
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
