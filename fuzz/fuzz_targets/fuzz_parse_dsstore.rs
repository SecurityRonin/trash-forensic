#![no_main]
//! Fuzz the macOS `.DS_Store` `Bud1` put-back parser. Invariant: never panic on
//! arbitrary bytes — the buddy-allocator walk, B-tree traversal (cycle-guarded),
//! and record decode must all stay bounds-checked.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = trash_core::macos::parse_put_back(data);
});
