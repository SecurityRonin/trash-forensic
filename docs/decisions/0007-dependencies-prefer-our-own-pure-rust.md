# 7. Dependency choices: pure-Rust `sqlite-core`, `forensicnomicon` report model, minimal parsing deps

Date: 2026-07-24
Status: Accepted

## Context

The iOS reader must read `Photos.sqlite`. The obvious dependency, `rusqlite`,
links the C `libsqlite3` — a C-FFI liability that breaks the workspace's
`forbid(unsafe)`, pure-Rust posture (ADR 0004). The analyzers must emit findings
that aggregate with the rest of the fleet. And the fleet's "Dependency Preference"
rule is a hard directive: always prefer our own SecurityRonin crates over
third-party equivalents.

## Decision

- **iOS SQLite access uses `sqlite-core`** — the fleet's pure-Rust (no
  `libsqlite3`) SQLite reader — not `rusqlite`
  (`trash-core/Cargo.toml`; `trash-core/src/ios.rs`: "no `libsqlite3`"). This is
  prefer-our-own and keeps `forbid(unsafe)` intact. Recovery of *purged* rows
  (WAL, freelist, carving) is left to the `sqlite-core` engine rather than
  reimplemented here.
- **Findings use `forensicnomicon::report`** — the fleet's normalized reporting
  model (`trash-forensic/Cargo.toml`; `trash-forensic/src/lib.rs`) — so trash
  findings are the union type every other analyzer emits, never a bespoke
  `TrashAnalysis` shape.
- **Parsing deps are kept minimal and purpose-scoped**: `chrono` (timestamp
  math), `thiserror` (typed errors), `percent-encoding` (Linux RFC 2396 decode
  only), and `serde` behind an optional `serde` feature.

The dependency graph is kept to a **single `forensicnomicon` version**: commit
`a5d3c06` widened `sqlite-core` `0.8` → `0.9` specifically to drop a transitive
`forensicnomicon 0.11`, so the tree carries no duplicate (`Cargo.toml`
`[workspace.dependencies]` comment). `[bans] multiple-versions = "deny"`
(`deny.toml`) enforces this.

## Consequences

- The pure-Rust, `forbid(unsafe)` posture holds even for SQLite-backed iOS
  reading.
- Trash findings render uniformly wherever the fleet aggregates
  `forensicnomicon` reports (`issen`, a future GUI).
- Dependency-version alignment is an active maintenance concern: a fleet crate's
  minor bump can reintroduce a duplicate, so widenings like the `sqlite-core 0.9`
  move must be repeated as the graph moves (Dependency Freshness).
