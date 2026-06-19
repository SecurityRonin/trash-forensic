#![no_main]
//! Fuzz the Linux XDG `.trashinfo` parser. Invariant: never panic on arbitrary
//! bytes (percent-decode, INI scan, and date parse must all degrade gracefully).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = trash_core::linux::parse_trashinfo(data);
});
