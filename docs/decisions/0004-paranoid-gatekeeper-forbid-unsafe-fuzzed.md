# 4. Paranoid Gatekeeper: `forbid(unsafe)`, panic-free readers, per-reader fuzzing

Date: 2026-07-24
Status: Accepted

## Context

Every input this crate parses is attacker-controllable: a `$I` index file, a
`.trashinfo` INI, a `.DS_Store` buddy-allocator B-tree, a `MediaStore` filename,
and a `Photos.sqlite` database, all recovered from an untrusted image. A lying
length field, a truncated record, or a crafted `..` path must never crash the
tool or produce silently wrong output — a forensic reader that panics on a
crafted artifact is a denial-of-service on the investigation. Unlike the fleet's
mmap-backed container readers (`ewf`, `memory-forensic`), these readers need no
`unsafe` at all: they parse in-memory byte slices, so the strongest posture is
available.

The SecurityRonin constitution's "Security & Robustness Standard — Paranoid
Gatekeeper" governs every `*-core` / `*-forensic` crate.

## Decision

Enforce the posture statically and dynamically.

- **Static.** The workspace sets `unsafe_code = "forbid"` (`Cargo.toml`
  `[workspace.lints.rust]`) — the full ban, not the `deny` + bounded-allow
  downgrade, because no `unsafe` is needed here. It denies `clippy::unwrap_used`
  and `expect_used` in production, with tests exempted centrally
  (`#![cfg_attr(test, allow(...))]` in each `lib.rs`, and `clippy.toml`
  `allow-unwrap-in-tests`/`allow-expect-in-tests`). Binary parsers use
  bounds-checked reads, cap allocations against hostile length fields, and walk
  the `.DS_Store` B-tree with a cycle guard (`trash-core/src/macos.rs`),
  returning a typed error carrying the offending value rather than panicking.
- **Dynamic.** Every untrusted-input reader carries a `cargo-fuzz` target with a
  must-not-panic invariant — `fuzz_parse_index`, `fuzz_parse_trashinfo`,
  `fuzz_parse_dsstore`, `fuzz_parse_trashed_name`, `fuzz_ios_photos`, plus
  `fuzz_forensic` driving the full parse→audit pipeline (`fuzz/fuzz_targets/`;
  added in commit `caa68ce`).

## Consequences

- Malformed evidence degrades to a typed error or a partial result, never a
  crash or an out-of-bounds read.
- The `unsafe`-forbidden badge in the README is earned, not aspirational, and
  the differentiator is stated as "input-fuzzed" (measured) beside "panic-free
  by lint" (static), per the fleet robustness-wording rule.
- Bounds-checked code is more verbose than a quick `unwrap`, and the fuzz targets
  are maintained surface built and smoke-run in CI.
