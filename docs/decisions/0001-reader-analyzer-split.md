# 1. Two-crate reader/analyzer split (`trash-core` + `trash-forensic`)

Date: 2026-07-24
Status: Accepted

## Context

The repo has two distinct jobs: decode a trash artifact to a typed record, and
grade that record for anomalies. These have different audiences and different
stability contracts. A third-party Rust tool that only wants to recover the
original path and deletion time of a deleted file should not have to compile the
anomaly-detection layer or take a dependency on the fleet's finding model. A
reader is built to read *valid* data robustly; an auditor must see the raw,
possibly-broken structure — the two concerns pull in opposite directions.

The workspace declares exactly two members (`Cargo.toml` `members =
["trash-core", "trash-forensic"]`), and the SecurityRonin constitution's
Crate-structure standard mandates the `<x>-core` reader / `<x>-forensic` analyzer
split, with `ntfs-core`/`ntfs-forensic` as the reference.

## Decision

Ship two crates:

- **`trash-core`** — read-only readers. One module per OS decoding its native
  artifact to a typed record (`RecycleBinIndex`, `TrashInfo`, `PutBack`,
  `TrashedName`, `TrashedAsset`) and pairing metadata with content. It produces
  no findings (`trash-core/src/lib.rs`: "none produces findings").
- **`trash-forensic`** — analyzers. Each grades a parsed record + its pairing
  into canonical `forensicnomicon::report::Finding`s
  (`trash-forensic/src/lib.rs`).

`trash-forensic` depends on `trash-core` (`trash-forensic/Cargo.toml`:
`trash-core = { workspace = true }`), which is the default direction of the
fleet standard — the reader's record types already expose everything the trash
auditors need (original path, size, deletion time, the `$I`/`$R` and
`info/`/`files/` pairing), so the analyzers build on `-core` rather than
re-parsing the raw bytes.

## Consequences

- A downstream tool depends on `trash-core` alone for recovery and pulls no
  finding-model dependency.
- Anomaly grading lives in one place and emits the fleet-uniform finding type,
  so trash findings aggregate alongside every other analyzer.
- The two crates version in lockstep from `[workspace.package]`, so a reader
  change and its analyzer counterpart release together.
