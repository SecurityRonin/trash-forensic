#![no_main]
//! Fuzz the Android `MediaStore` `.trashed-`/`.pending-` filename codec.
//! Invariant: never panic on arbitrary (possibly non-UTF-8) name bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The codec works on a filename string; feed it any lossy-decoded input.
    let name = String::from_utf8_lossy(data);
    let _ = trash_core::android::parse_trashed_name(&name);
});
