#![no_main]
//! Fuzz the iOS `Photos.sqlite` trashed-asset reader over arbitrary bytes.
//! Invariant: never panic — the schema lookup, `CREATE TABLE` column parse, and
//! Mac-Absolute-Time decode must degrade to a typed error, not a crash.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = trash_core::ios::parse_trashed_assets(data.to_vec());
});
