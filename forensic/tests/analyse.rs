//! Analyzer tests: each anomaly maps to a canonical forensicnomicon Finding.
//!
//! Exercises the Windows analyzer, so it is gated to the `windows` feature; under
//! a feature set without `windows` (e.g. `--features ios`) the file compiles empty.

#![cfg(feature = "windows")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use forensicnomicon::report::{Category, Severity};
use trash_core::{parse_index, IndexVersion, RecycleBinIndex, RecycleBinPair};
use trash_forensic::audit_pair;

const V2_DOCX: &[u8] = include_bytes!("../../tests/data/$IAB12CD.docx");
const V2_TRAVERSAL: &[u8] = include_bytes!("../../tests/data/$ITRAVER.dll");
const V2_NODATE: &[u8] = include_bytes!("../../tests/data/$INODATE.bin");

fn idx(bytes: &[u8]) -> RecycleBinIndex {
    parse_index(bytes).expect("fixture parses")
}

#[test]
fn missing_content_file_is_a_finding() {
    // $I parsed, but the pair has no $R -> content already purged.
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$IAB12CD.docx"),
        content_path: None,
    };
    let findings = audit_pair(&idx(V2_DOCX), &pair);
    let f = findings
        .iter()
        .find(|f| f.code == "RECYCLEBIN-CONTENT-PURGED")
        .expect("purged-content finding present");
    assert_eq!(f.category, Category::Residue);
    assert_eq!(f.severity, Some(Severity::Medium));
}

#[test]
fn present_content_file_produces_no_purged_finding() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$IAB12CD.docx"),
        content_path: Some(PathBuf::from("$RAB12CD.docx")),
    };
    let findings = audit_pair(&idx(V2_DOCX), &pair);
    assert!(
        !findings
            .iter()
            .any(|f| f.code == "RECYCLEBIN-CONTENT-PURGED"),
        "no purged finding when $R exists"
    );
}

#[test]
fn path_traversal_in_stored_name_is_a_finding() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$ITRAVER.dll"),
        content_path: Some(PathBuf::from("$RTRAVER.dll")),
    };
    let findings = audit_pair(&idx(V2_TRAVERSAL), &pair);
    let f = findings
        .iter()
        .find(|f| f.code == "RECYCLEBIN-PATH-TRAVERSAL")
        .expect("path-traversal finding present");
    assert_eq!(f.category, Category::Concealment);
    assert_eq!(f.severity, Some(Severity::High));
    // The offending path must appear in the evidence (Show-the-value rule).
    assert!(
        f.evidence
            .iter()
            .any(|e| e.value.contains("..\\..\\..\\Windows")),
        "evidence must carry the offending path"
    );
}

#[test]
fn benign_path_produces_no_traversal_finding() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$IAB12CD.docx"),
        content_path: Some(PathBuf::from("$RAB12CD.docx")),
    };
    let findings = audit_pair(&idx(V2_DOCX), &pair);
    assert!(!findings
        .iter()
        .any(|f| f.code == "RECYCLEBIN-PATH-TRAVERSAL"));
}

#[test]
fn missing_deletion_time_is_a_finding() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$INODATE.bin"),
        content_path: Some(PathBuf::from("$RNODATE.bin")),
    };
    let findings = audit_pair(&idx(V2_NODATE), &pair);
    let f = findings
        .iter()
        .find(|f| f.code == "RECYCLEBIN-DELETION-TIME-MISSING")
        .expect("missing-deletion-time finding present");
    assert_eq!(f.category, Category::Integrity);
}

#[test]
fn well_formed_record_with_time_and_content_is_clean() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$IAB12CD.docx"),
        content_path: Some(PathBuf::from("$RAB12CD.docx")),
    };
    let findings = audit_pair(&idx(V2_DOCX), &pair);
    assert!(
        findings.is_empty(),
        "a normal record yields no findings, got {findings:?}"
    );
}

#[test]
fn findings_carry_trash_forensic_source_and_version() {
    let pair = RecycleBinPair {
        index_path: PathBuf::from("$ITRAVER.dll"),
        content_path: None,
    };
    let findings = audit_pair(&idx(V2_TRAVERSAL), &pair);
    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.source.analyzer, "trash-forensic");
        assert!(f.source.version.is_some());
    }
    // sanity: the traversal fixture really is v2
    assert_eq!(idx(V2_TRAVERSAL).version, IndexVersion::V2);
}
