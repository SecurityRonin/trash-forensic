//! Forensic anomaly analysis for iOS Photos "Recently Deleted" assets recovered
//! by [`trash_core::ios`] from `Photos.sqlite`.
//!
//! | Code | Category | Severity | Meaning |
//! |---|---|---|---|
//! | `TRASH-DELETION-TIME-MISSING` | Integrity | Medium | the asset is trashed (`ZTRASHEDSTATE=1`) but its `ZTRASHEDDATE` is NULL/zero |
//! | `TRASH-EXPIRED-RESIDUE` | Residue | Low | the asset is still trashed past the ~30-day retention window |
//!
//! The retention check needs a reference time, supplied by the caller, so the
//! analysis stays deterministic and testable. Findings are observations, never
//! legal conclusions: the analyst concludes.

use chrono::{DateTime, Duration, Utc};
use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use trash_core::ios::TrashedAsset;

use crate::ANALYZER;

/// The iOS Photos Recently-Deleted retention window (~30 days).
const RETENTION_DAYS: i64 = 30;

/// An iOS Photos trashed-asset anomaly, with the offending asset reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IosAssetAnomaly {
    /// The asset is flagged trashed but carries no `ZTRASHEDDATE` — the deletion
    /// time is unknown (broken/old-schema/tampered).
    DeletionTimeMissing {
        /// The asset reference (filename, or `Z_PK <rowid>`), surfaced verbatim.
        evidence: String,
    },
    /// The asset is still in Recently Deleted past its retention window — it
    /// outlived the nominal 30-day purge and remains recoverable.
    ExpiredResidue {
        /// The asset reference (filename, or `Z_PK <rowid>`), surfaced verbatim.
        evidence: String,
    },
}

impl IosAssetAnomaly {
    /// Stable, scheme-prefixed machine code (a published contract).
    fn code(&self) -> &'static str {
        match self {
            IosAssetAnomaly::DeletionTimeMissing { .. } => "TRASH-DELETION-TIME-MISSING",
            IosAssetAnomaly::ExpiredResidue { .. } => "TRASH-EXPIRED-RESIDUE",
        }
    }

    /// Analytical lens for the anomaly.
    fn category(&self) -> Category {
        match self {
            IosAssetAnomaly::DeletionTimeMissing { .. } => Category::Integrity,
            IosAssetAnomaly::ExpiredResidue { .. } => Category::Residue,
        }
    }

    /// Canonical severity for the anomaly.
    fn severity(&self) -> Severity {
        match self {
            IosAssetAnomaly::DeletionTimeMissing { .. } => Severity::Medium,
            IosAssetAnomaly::ExpiredResidue { .. } => Severity::Low,
        }
    }

    /// The asset reference (filename or `Z_PK <rowid>`), common to both variants.
    fn evidence(&self) -> &str {
        match self {
            IosAssetAnomaly::DeletionTimeMissing { evidence }
            | IosAssetAnomaly::ExpiredResidue { evidence } => evidence,
        }
    }

    /// Human-readable, consistent-with note.
    fn note(&self) -> String {
        match self {
            IosAssetAnomaly::DeletionTimeMissing { evidence } => format!(
                "Photos asset {evidence} is flagged trashed (ZTRASHEDSTATE=1) but carries no \
                 ZTRASHEDDATE — the deletion time is unknown"
            ),
            IosAssetAnomaly::ExpiredResidue { evidence } => format!(
                "Photos asset {evidence} is still in Recently Deleted past its ~30-day retention \
                 — consistent with the asset having outlived the nominal purge and remaining \
                 recoverable"
            ),
        }
    }

    /// Convert this anomaly into a canonical [`Finding`].
    fn to_finding(&self, source: Source) -> Finding {
        let value = self.evidence().to_string();
        Finding::observation(self.severity(), self.category(), self.code())
            .note(self.note())
            .source(source)
            .evidence_item(Evidence {
                field: "asset".to_string(),
                value: value.clone(),
                location: Some(Location::Path(value)),
            })
            .build()
    }
}

/// Audit one trashed Photos asset. `now` is the reference time the retention
/// window is measured against (the caller passes the acquisition/analysis time).
///
/// Flags a trashed asset with no deletion timestamp, and one still present past
/// its ~30-day retention. A normally-trashed, recently-deleted asset with a
/// timestamp yields no findings.
#[must_use]
pub fn audit_trashed_asset(asset: &TrashedAsset, now: DateTime<Utc>) -> Vec<Finding> {
    let reference = asset
        .filename
        .clone()
        .unwrap_or_else(|| format!("Z_PK {}", asset.rowid));

    let mut anomalies = Vec::new();
    match asset.trashed_at {
        None => anomalies.push(IosAssetAnomaly::DeletionTimeMissing {
            evidence: reference.clone(),
        }),
        Some(trashed_at) if now - trashed_at > Duration::days(RETENTION_DAYS) => {
            anomalies.push(IosAssetAnomaly::ExpiredResidue {
                evidence: reference.clone(),
            });
        }
        Some(_) => {}
    }

    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: reference,
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

    fn at(unix: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(unix, 0).single().unwrap()
    }

    fn asset(trashed_at: Option<DateTime<Utc>>) -> TrashedAsset {
        TrashedAsset {
            rowid: 7,
            filename: Some("IMG_0001.HEIC".to_string()),
            directory: Some("DCIM/100APPLE".to_string()),
            trashed_at,
        }
    }

    const DAY: i64 = 86_400;

    /// A recently-trashed asset with a timestamp yields nothing.
    #[test]
    fn recent_trashed_asset_has_no_findings() {
        let now = at(1_700_000_000);
        let a = asset(Some(at(1_700_000_000 - 5 * DAY)));
        assert!(audit_trashed_asset(&a, now).is_empty());
    }

    /// A trashed asset with no `ZTRASHEDDATE` => Integrity/Medium missing time.
    #[test]
    fn missing_trashed_date_flagged() {
        let findings = audit_trashed_asset(&asset(None), at(1_700_000_000));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-DELETION-TIME-MISSING");
        assert_eq!(findings[0].category, Category::Integrity);
        assert_eq!(findings[0].severity, Some(Severity::Medium));
        assert_eq!(findings[0].evidence[0].value, "IMG_0001.HEIC");
    }

    /// A trashed asset older than the 30-day window => Residue/Low expired residue.
    #[test]
    fn expired_asset_flagged() {
        let now = at(1_700_000_000);
        let a = asset(Some(at(1_700_000_000 - 40 * DAY)));
        let findings = audit_trashed_asset(&a, now);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-EXPIRED-RESIDUE");
        assert_eq!(findings[0].category, Category::Residue);
        assert_eq!(findings[0].severity, Some(Severity::Low));
    }

    /// An asset trashed exactly within the window is not yet expired.
    #[test]
    fn within_window_not_expired() {
        let now = at(1_700_000_000);
        let a = asset(Some(at(1_700_000_000 - 20 * DAY)));
        assert!(audit_trashed_asset(&a, now).is_empty());
    }

    /// Findings fall back to `Z_PK <rowid>` when no filename is recorded.
    #[test]
    fn evidence_falls_back_to_rowid() {
        let a = TrashedAsset {
            rowid: 42,
            filename: None,
            directory: None,
            trashed_at: None,
        };
        let findings = audit_trashed_asset(&a, at(1_700_000_000));
        assert_eq!(findings[0].evidence[0].value, "Z_PK 42");
        assert_eq!(findings[0].source.analyzer, ANALYZER);
        assert_eq!(findings[0].source.scope, "Z_PK 42");
    }
}
