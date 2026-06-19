//! Integration tests for the `$I` index parser, validated against fixtures whose
//! bytes were hand-built strictly per the libyal spec and cross-checked with the
//! independent `rifiuti-vista` oracle (see `tests/data/README.md`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{TimeZone, Utc};
use recyclebin_core::{parse_index, scan_pairs, Error, IndexVersion};

// Fixtures live in the single repo-root tests/data/; from core/tests/ the repo
// root is two levels up.
const V2_DOCX: &[u8] = include_bytes!("../../tests/data/$IAB12CD.docx");
const V1_TXT: &[u8] = include_bytes!("../../tests/data/$IZZ99YY.txt");
const V2_NODATE: &[u8] = include_bytes!("../../tests/data/$INODATE.bin");
const V2_TRAVERSAL: &[u8] = include_bytes!("../../tests/data/$ITRAVER.dll");

#[test]
fn parses_version2_index() {
    let idx = parse_index(V2_DOCX).expect("v2 fixture must parse");
    assert_eq!(idx.version, IndexVersion::V2);
    assert_eq!(idx.original_size, 1234);
    assert_eq!(
        idx.original_path,
        "C:\\Users\\victim\\Documents\\secret plan.docx"
    );
    // rifiuti-vista oracle: 2024-01-15T10:30:00Z
    assert_eq!(
        idx.deleted_at,
        Some(Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 0).unwrap())
    );
}

#[test]
fn parses_version1_index() {
    let idx = parse_index(V1_TXT).expect("v1 fixture must parse");
    assert_eq!(idx.version, IndexVersion::V1);
    assert_eq!(idx.original_size, 999);
    assert_eq!(idx.original_path, "C:\\temp\\oldfile.txt");
    // rifiuti-vista oracle: 2015-06-01T00:00:00Z
    assert_eq!(
        idx.deleted_at,
        Some(Utc.with_ymd_and_hms(2015, 6, 1, 0, 0, 0).unwrap())
    );
}

#[test]
fn zero_filetime_maps_to_none() {
    let idx = parse_index(V2_NODATE).expect("zero-filetime fixture must parse");
    assert_eq!(idx.original_size, 42);
    assert_eq!(idx.original_path, "C:\\Data\\nodate.bin");
    // FILETIME of 0 is "deletion time not set" — rifiuti-vista flags it broken.
    assert_eq!(idx.deleted_at, None);
}

#[test]
fn preserves_path_traversal_verbatim() {
    // The reader must NOT sanitize the stored name — that is the analyzer's job.
    let idx = parse_index(V2_TRAVERSAL).expect("traversal fixture must parse");
    assert_eq!(idx.original_path, "..\\..\\..\\Windows\\System32\\evil.dll");
}

#[test]
fn truncated_header_is_error_not_panic() {
    let err = parse_index(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, Error::TruncatedHeader { got: 10 }));
}

#[test]
fn unsupported_version_surfaces_raw_value() {
    let mut data = vec![0u8; 24];
    data[0] = 0x07; // version 7
    let err = parse_index(&data).unwrap_err();
    match err {
        Error::UnsupportedVersion { version, raw } => {
            assert_eq!(version, 7);
            assert_eq!(raw, 7);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn version2_name_length_overflow_is_rejected() {
    // A v2 header claiming a huge filename with no bytes to back it must be
    // rejected, never allocated or indexed out of bounds.
    let mut data = vec![0u8; 28];
    data[0] = 2; // version 2
                 // name-length field at offset 24 = 0xFFFF_FFFF chars
    data[24] = 0xFF;
    data[25] = 0xFF;
    data[26] = 0xFF;
    data[27] = 0xFF;
    let err = parse_index(&data).unwrap_err();
    assert!(matches!(err, Error::NameLengthTooLarge { .. }));
}

#[test]
fn version1_truncated_name_field_is_error() {
    let mut data = vec![0u8; 100]; // header + partial name, < 24+520
    data[0] = 1;
    let err = parse_index(&data).unwrap_err();
    assert!(matches!(err, Error::TruncatedV1Name { .. }));
}

#[test]
fn scan_pairs_matches_i_and_r() {
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data"));
    let pairs = scan_pairs(dir).expect("scan must succeed");
    // $IAB12CD.docx has a matching $RAB12CD.docx in the fixtures.
    let paired = pairs
        .iter()
        .find(|p| p.index_path.file_name().and_then(|n| n.to_str()) == Some("$IAB12CD.docx"))
        .expect("v2 index present");
    let content = paired
        .content_path
        .as_ref()
        .expect("$RAB12CD.docx should pair");
    assert_eq!(
        content.file_name().and_then(|n| n.to_str()),
        Some("$RAB12CD.docx")
    );

    // $IZZ99YY.txt has no $RZZ99YY.txt → unpaired.
    let lone = pairs
        .iter()
        .find(|p| p.index_path.file_name().and_then(|n| n.to_str()) == Some("$IZZ99YY.txt"))
        .expect("v1 index present");
    assert!(lone.content_path.is_none());
}
