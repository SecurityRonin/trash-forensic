#![no_main]
//! Fuzz the `$I` index parser. Invariant: never panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must return a typed result (Ok or Err) for any input, never
    // panic, read out of bounds, or over-allocate on a hostile length field.
    let _ = recyclebin_core::parse_index(data);
});
