//! Forensic anomaly analysis for Windows Recycle Bin `$I`/`$R` artifacts.
//!
//! `recyclebin-core` is the lean reader: it parses a `$I` index file into a
//! [`RecycleBinIndex`] and pairs `$I`/`$R` files. This crate is the evidence-grade
//! layer on top — it inspects a parsed record + its pairing and reports anomalies
//! as canonical [`forensicnomicon::report::Finding`]s, so Recycle Bin findings
//! aggregate alongside every other `SecurityRonin` analyzer.
//!
//! The anomalies detected:
//!
//! | Code | Category | Meaning |
//! |---|---|---|
//! | `RECYCLEBIN-CONTENT-PURGED` | Residue | `$I` metadata survives but the `$R` content file is gone |
//! | `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | the stored original path escapes its directory (`..\`) |
//! | `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | the `FILETIME` deletion time is zero (unset / broken) |
//!
//! Findings are observations, never legal conclusions: the analyst concludes.
//!
//! ```no_run
//! use recyclebin_core::{parse_index, scan_pairs};
//! use recyclebin_forensic::audit_pair;
//! # fn demo(dir: &std::path::Path) -> std::io::Result<()> {
//! for pair in scan_pairs(dir)? {
//!     let bytes = std::fs::read(&pair.index_path)?;
//!     if let Ok(index) = parse_index(&bytes) {
//!         for finding in audit_pair(&index, &pair) {
//!             println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use recyclebin_core::{RecycleBinIndex, RecycleBinPair};

/// Analyzer name, recorded on every finding's [`Source`] for reproducibility.
pub const ANALYZER: &str = "recyclebin-forensic";

/// A Recycle Bin anomaly, with the offending evidence attached.
///
/// The reader keeps its typed reader output; this analyzer keeps its typed
/// anomaly kind (domain knowledge) and converts to canonical findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A `$I` index file with no paired `$R` content file: the metadata of a
    /// deleted file survives but its content has already been purged.
    ContentPurged {
        /// The original path recorded in the surviving `$I`.
        original_path: String,
    },
    /// The original path stored in the `$I` file escapes its directory via
    /// `..\` (or `../`) components — consistent with a crafted name rather than
    /// a normal shell deletion.
    PathTraversal {
        /// The offending stored path, surfaced verbatim for the investigator.
        original_path: String,
    },
    /// The `FILETIME` deletion timestamp is zero — recorded but never set.
    DeletionTimeMissing {
        /// The path of the record whose deletion time is missing.
        original_path: String,
    },
}

impl AnomalyKind {
    /// Stable, scheme-prefixed machine code (a published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::ContentPurged { .. } => "RECYCLEBIN-CONTENT-PURGED",
            AnomalyKind::PathTraversal { .. } => "RECYCLEBIN-PATH-TRAVERSAL",
            AnomalyKind::DeletionTimeMissing { .. } => "RECYCLEBIN-DELETION-TIME-MISSING",
        }
    }

    /// Canonical severity for the anomaly.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::ContentPurged { .. } => Severity::Medium,
            AnomalyKind::PathTraversal { .. } => Severity::High,
            AnomalyKind::DeletionTimeMissing { .. } => Severity::Low,
        }
    }

    /// Analytical lens for the anomaly.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::ContentPurged { .. } => Category::Residue,
            AnomalyKind::PathTraversal { .. } => Category::Concealment,
            AnomalyKind::DeletionTimeMissing { .. } => Category::Integrity,
        }
    }

    /// Human-readable, consistent-with note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::ContentPurged { original_path } => format!(
                "$I index for {original_path} survives but its $R content file is absent — \
                 consistent with the file's content having been purged while its metadata remains"
            ),
            AnomalyKind::PathTraversal { original_path } => format!(
                "stored original path {original_path} contains parent-directory ('..') \
                 components — consistent with a crafted name rather than a normal deletion"
            ),
            AnomalyKind::DeletionTimeMissing { original_path } => format!(
                "deletion FILETIME for {original_path} is zero (unset) — the deletion time \
                 was not recorded or has been cleared"
            ),
        }
    }

    /// Convert this anomaly into a canonical [`Finding`].
    fn to_finding(&self, source: Source) -> Finding {
        let path = match self {
            AnomalyKind::ContentPurged { original_path }
            | AnomalyKind::PathTraversal { original_path }
            | AnomalyKind::DeletionTimeMissing { original_path } => original_path.clone(),
        };
        Finding::observation(self.severity(), self.category(), self.code())
            .note(self.note())
            .source(source)
            .evidence_item(Evidence {
                field: "original_path".to_string(),
                value: path.clone(),
                location: Some(Location::Path(path)),
            })
            .build()
    }
}

/// Build the [`Source`] stamped on every finding (analyzer + version + scope).
fn source_for(pair: &RecycleBinPair) -> Source {
    let scope = pair
        .index_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("$I")
        .to_string();
    Source {
        analyzer: ANALYZER.to_string(),
        scope,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Audit a parsed `$I` record together with its `$I`/`$R` pairing, returning a
/// canonical [`Finding`] for each anomaly detected.
///
/// Detects a purged content file (`$I` without `$R`), a path-traversal stored
/// name, and a missing (zero) deletion time. A well-formed record with content
/// and a deletion time yields no findings.
#[must_use]
pub fn audit_pair(index: &RecycleBinIndex, pair: &RecycleBinPair) -> Vec<Finding> {
    let source = source_for(pair);
    let mut anomalies = Vec::new();

    if pair.content_path.is_none() {
        anomalies.push(AnomalyKind::ContentPurged {
            original_path: index.original_path.clone(),
        });
    }

    if has_path_traversal(&index.original_path) {
        anomalies.push(AnomalyKind::PathTraversal {
            original_path: index.original_path.clone(),
        });
    }

    if index.deleted_at.is_none() {
        anomalies.push(AnomalyKind::DeletionTimeMissing {
            original_path: index.original_path.clone(),
        });
    }

    anomalies
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

/// Whether a stored path contains a parent-directory (`..`) component, treating
/// both Windows (`\`) and POSIX (`/`) separators. Matches `..` only as a whole
/// path component, so a filename like `my..notes.txt` is not flagged.
fn has_path_traversal(path: &str) -> bool {
    path.split(['\\', '/']).any(|component| component == "..")
}
