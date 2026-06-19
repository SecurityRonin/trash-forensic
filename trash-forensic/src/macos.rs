//! Forensic anomaly analysis for the macOS **Trash** put-back metadata recovered
//! by [`trash_core::macos`] from a Trash folder's `.DS_Store`.
//!
//! | Code | Category | Severity | Meaning |
//! |---|---|---|---|
//! | `TRASH-ORPHAN-METADATA` | Residue | Medium | a `.DS_Store` put-back record survives but the named item is gone from the Trash |
//! | `TRASH-PUTBACK-TRAVERSAL` | Concealment | High | the stored `ptbN`/`ptbL` escapes its directory via `..` |
//!
//! A trashed item that simply has *no* put-back record is **not** anomalous —
//! Finder writes `.DS_Store` lazily and `rm` never writes one — so the absence of
//! a record is normal and is deliberately not flagged here. Findings are
//! observations, never legal conclusions: the analyst concludes.

use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use trash_core::macos::PutBack;

use crate::{has_path_traversal, ANALYZER};

/// A macOS Trash put-back anomaly, with the offending evidence attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsStoreAnomaly {
    /// A put-back record survives in `.DS_Store` but the named item is no longer
    /// present in the Trash directory: the content was emptied/removed while its
    /// metadata remained (analogous to a Windows `$I` without its `$R`).
    OrphanMetadata {
        /// The reconstructed original path, or the trash name when the original
        /// path could not be reconstructed.
        evidence: String,
    },
    /// The stored put-back name or location contains a `..` component — restoring
    /// it could escape the intended tree, consistent with a crafted record.
    PutBackTraversal {
        /// The offending `ptbN`/`ptbL` value, surfaced verbatim.
        offending: String,
    },
}

/// Audit a recovered macOS put-back record. `item_present` is whether the item
/// named by [`PutBack::trash_name`] still exists in the Trash directory (the
/// caller lists the directory; the `.DS_Store` itself does not).
///
/// Detects an orphaned put-back record (metadata without its item) and a
/// path-traversal stored name/location. A present item with clean paths yields no
/// findings.
#[must_use]
pub fn audit_put_back(record: &PutBack, item_present: bool) -> Vec<Finding> {
    todo!("RED: audit_put_back not yet implemented: {record:?} present={item_present}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_back(name: &str, original_name: Option<&str>, location: Option<&str>) -> PutBack {
        PutBack {
            trash_name: name.to_string(),
            original_name: original_name.map(str::to_string),
            original_location: location.map(str::to_string),
        }
    }

    fn clean() -> PutBack {
        put_back(
            "report.pdf",
            Some("report.pdf"),
            Some("System/Volumes/Data/Users/x/Downloads/"),
        )
    }

    /// A present item with clean paths yields nothing.
    #[test]
    fn present_clean_item_has_no_findings() {
        assert!(audit_put_back(&clean(), true).is_empty());
    }

    /// A record whose item is gone from the Trash => Residue/Medium orphan.
    #[test]
    fn orphan_metadata_detected() {
        let findings = audit_put_back(&clean(), false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-ORPHAN-METADATA");
        assert_eq!(findings[0].category, Category::Residue);
        assert_eq!(findings[0].severity, Some(Severity::Medium));
        // The reconstructed original path is surfaced as evidence.
        assert_eq!(
            findings[0].evidence[0].value,
            "/Users/x/Downloads/report.pdf"
        );
    }

    /// A `..` in the put-back location => Concealment/High traversal.
    #[test]
    fn traversal_in_location_detected() {
        let r = put_back(
            "p",
            Some("p"),
            Some("System/Volumes/Data/Users/x/../../etc/"),
        );
        let findings = audit_put_back(&r, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-PUTBACK-TRAVERSAL");
        assert_eq!(findings[0].category, Category::Concealment);
        assert_eq!(findings[0].severity, Some(Severity::High));
    }

    /// A `..` in the put-back *name* is also caught.
    #[test]
    fn traversal_in_name_detected() {
        let r = put_back("p", Some("../escape"), Some("System/Volumes/Data/Users/x/"));
        let findings = audit_put_back(&r, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "TRASH-PUTBACK-TRAVERSAL");
    }

    /// An item that is both orphaned and traversal-pathed yields both findings.
    #[test]
    fn orphan_and_traversal_stack() {
        let r = put_back("p", Some("p"), Some("System/Volumes/Data/Users/x/../etc/"));
        let findings = audit_put_back(&r, false);
        let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();
        assert_eq!(findings.len(), 2);
        assert!(codes.contains(&"TRASH-ORPHAN-METADATA"));
        assert!(codes.contains(&"TRASH-PUTBACK-TRAVERSAL"));
    }

    /// Every finding is stamped with the analyzer name and the item's trash name.
    #[test]
    fn source_carries_analyzer_and_scope() {
        let findings = audit_put_back(&clean(), false);
        assert_eq!(findings[0].source.analyzer, ANALYZER);
        assert_eq!(findings[0].source.scope, "report.pdf");
    }
}
