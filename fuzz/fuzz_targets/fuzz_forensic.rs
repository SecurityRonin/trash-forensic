#![no_main]
//! Fuzz the full parse -> audit pipeline. Invariant: never panic.

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use recyclebin_core::RecycleBinPair;

fuzz_target!(|data: &[u8]| {
    if let Ok(index) = recyclebin_core::parse_index(data) {
        // Drive the analyzer over both pairing states (paired / purged) so the
        // path-traversal and missing-time arms are reached on crafted input.
        let purged = RecycleBinPair {
            index_path: PathBuf::from("$IFUZZ00.bin"),
            content_path: None,
        };
        let paired = RecycleBinPair {
            index_path: PathBuf::from("$IFUZZ00.bin"),
            content_path: Some(PathBuf::from("$RFUZZ00.bin")),
        };
        let _ = recyclebin_forensic::audit_pair(&index, &purged);
        let _ = recyclebin_forensic::audit_pair(&index, &paired);
    }
});
