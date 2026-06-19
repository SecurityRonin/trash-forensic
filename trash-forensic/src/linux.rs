//! Forensic anomaly analysis for the Linux freedesktop.org / XDG **Trash**
//! artifact.
//!
//! [`trash_core::linux`] is the reader: it parses a `.trashinfo` into a
//! [`TrashInfo`] and pairs `info/`↔`files/`. This module grades a parsed record +
//! its pairing into canonical [`forensicnomicon::report::Finding`]s.
//!
//! | Code | Category | Severity | Meaning |
//! |---|---|---|---|
//! | `TRASH-CONTENT-PURGED` | Residue | Medium | `info/<name>.trashinfo` survives but `files/<name>` is gone |
//! | `TRASH-PATH-TRAVERSAL` | Concealment | High | the stored `Path=` escapes its directory via `..` (spec-forbidden) |
//! | `TRASH-DELETION-TIME-MISSING` | Integrity | Medium | `DeletionDate=` was absent or unparseable |
//!
//! Findings are observations, never legal conclusions: the analyst concludes.

use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use trash_core::linux::{TrashEntry, TrashInfo};

use crate::{has_path_traversal, ANALYZER};

/// An XDG-trash anomaly, with the offending evidence attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrashAnomaly {
    /// A `.trashinfo` whose `files/<name>` content is absent: the metadata of a
    /// trashed file survives but its content has been purged.
    ContentPurged {
        /// The original path recorded in the surviving `.trashinfo`.
        original_path: String,
    },
    /// The stored `Path=` escapes its directory via a `..` component — forbidden
    /// by the spec for relative paths, consistent with a crafted entry.
    PathTraversal {
        /// The offending stored path, surfaced verbatim for the investigator.
        original_path: String,
    },
    /// `DeletionDate=` was absent or unparseable, so the deletion time is unknown.
    DeletionTimeMissing {
        /// The path of the record whose deletion time is missing.
        original_path: String,
    },
}

/// Audit a parsed `.trashinfo` record together with its `info/`↔`files/` pairing,
/// returning a canonical [`Finding`] for each anomaly detected.
///
/// Detects purged content (`info/` without `files/`), a path-traversal stored
/// `Path=`, and a missing/unparseable deletion time. A well-formed record with
/// content and a deletion time yields no findings.
#[must_use]
pub fn audit_entry(info: &TrashInfo, entry: &TrashEntry) -> Vec<Finding> {
    todo!("RED: audit_entry not yet implemented: {info:?} {entry:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use std::path::PathBuf;

    fn info(path: &str, dated: bool) -> TrashInfo {
        TrashInfo {
            original_path: path.to_string(),
            deleted_at: dated.then(|| {
                NaiveDate::from_ymd_opt(2024, 1, 15)
                    .unwrap()
                    .and_hms_opt(13, 45, 9)
                    .unwrap()
            }),
        }
    }

    fn entry(content: bool) -> TrashEntry {
        TrashEntry {
            info_path: PathBuf::from("/t/info/report.pdf.trashinfo"),
            content_path: content.then(|| PathBuf::from("/t/files/report.pdf")),
        }
    }

    /// A well-formed entry — content present, path clean, date set — yields nothing.
    #[test]
    fn clean_entry_has_no_findings() {
        assert!(audit_entry(&info("/home/u/report.pdf", true), &entry(true)).is_empty());
    }

    /// Missing `files/<name>` => one Residue/Medium `TRASH-CONTENT-PURGED`.
    #[test]
    fn content_purged_detected() {
        let findings = audit_entry(&info("/home/u/report.pdf", true), &entry(false));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.code, "TRASH-CONTENT-PURGED");
        assert_eq!(f.category, Category::Residue);
        assert_eq!(f.severity, Some(Severity::Medium));
        // The offending path is surfaced as evidence.
        assert_eq!(f.evidence[0].field, "original_path");
        assert_eq!(f.evidence[0].value, "/home/u/report.pdf");
    }

    /// A `..` component in `Path=` => Concealment/High `TRASH-PATH-TRAVERSAL`.
    #[test]
    fn path_traversal_detected() {
        let findings = audit_entry(&info("../../etc/shadow", true), &entry(true));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-PATH-TRAVERSAL");
        assert_eq!(findings[0].category, Category::Concealment);
        assert_eq!(findings[0].severity, Some(Severity::High));
    }

    /// A normal filename containing `..` (not a path component) is not flagged.
    #[test]
    fn embedded_dots_not_flagged() {
        assert!(audit_entry(&info("/home/u/my..notes.txt", true), &entry(true)).is_empty());
    }

    /// Absent/unparseable date => Integrity/Medium `TRASH-DELETION-TIME-MISSING`.
    #[test]
    fn deletion_time_missing_detected() {
        let findings = audit_entry(&info("/home/u/report.pdf", false), &entry(true));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-DELETION-TIME-MISSING");
        assert_eq!(findings[0].category, Category::Integrity);
        assert_eq!(findings[0].severity, Some(Severity::Medium));
    }

    /// Anomalies stack: a purged, traversal-pathed, undated entry yields all three.
    #[test]
    fn multiple_anomalies_stack() {
        let findings = audit_entry(&info("../../../secret", false), &entry(false));
        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();
        assert_eq!(findings.len(), 3);
        assert!(codes.contains(&"TRASH-CONTENT-PURGED"));
        assert!(codes.contains(&"TRASH-PATH-TRAVERSAL"));
        assert!(codes.contains(&"TRASH-DELETION-TIME-MISSING"));
    }

    /// Every finding is stamped with the analyzer name and the `.trashinfo` scope.
    #[test]
    fn source_carries_analyzer_and_scope() {
        let findings = audit_entry(&info("/home/u/report.pdf", true), &entry(false));
        let src = &findings[0].source;
        assert_eq!(src.analyzer, ANALYZER);
        assert_eq!(src.scope, "report.pdf.trashinfo");
    }
}
