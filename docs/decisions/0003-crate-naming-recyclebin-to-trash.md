# 3. Crate naming: `recyclebin-*` renamed to `trash-core` / `trash-forensic`

Date: 2026-07-24
Status: Accepted

## Context

Under the fleet Crate naming grammar, a single-format repo is Pattern A: exactly
two crates, `<x>-core` (reader) and `<x>-forensic` (analyzer). Once the scope
expanded from Windows-only to a five-OS genus (ADR 0002), the original
`recyclebin-core` / `recyclebin-forensic` names were wrong twice over: they named
one species (Windows Recycle Bin) for what is now the whole genus, and they read
on crates.io as a Windows-only tool.

The grammar also requires the crate name to be *self-describing when read bare*
(in search, `cargo add`, transitive dependency lists) with all repo context
stripped. "trash" is a distinctive-enough short prefix to stand alone as the
umbrella for deleted-file artifacts.

## Decision

Rename to `trash-core` (reader) and `trash-forensic` (analyzer) — Pattern A
applied with the genus as the `<x>`, keeping the `-core` / `-forensic` suffixes
(commit `1d2e0b8`; `Cargo.toml` members). The rename was landed as a single
`refactor!` with a `BREAKING CHANGE` note superseding the old names, moving
packages, import paths (`recyclebin_core` → `trash_core`), workspace deps, fuzz
paths, docs, and the analyzer identity stamped on findings (`ANALYZER =
"trash-forensic"`, `trash-forensic/src/lib.rs`).

Neither crate sets `[lib] name`, so the import paths are `trash_core` /
`trash_forensic` — the bare `trash` name is not hijacked, and there is no
collision to work around. Native leaf identifiers are preserved verbatim
(`RecycleBinIndex`, `RECYCLEBIN-*`), because the umbrella rename must not
mistranslate a platform's correct native term (ADR 0002).

## Consequences

- The published names describe the cross-platform reality, not the first
  backend.
- The `recyclebin-*` names are abandoned; any earlier reference to them is stale.
- Because the rename was a hard `BREAKING CHANGE`, downstream consumers pin the
  new names; there is no compatibility shim.
