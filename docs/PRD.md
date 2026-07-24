# trash-forensic — Purpose & Scope

*A reverse-written intent document for a **library-tier** fleet repo. Every
current-state claim below is grounded in a same-session read of the workspace
(`Cargo.toml`, `trash-core/src/`, `trash-forensic/src/`, `docs/validation.md`) on
2026-07-24. The load-bearing decisions live as ADRs
[0001](decisions/0001-reader-analyzer-split.md)–[0008](decisions/0008-msrv-pinned-toolchain.md)
under [`docs/decisions/`](decisions/).*

## What this is

Two published Rust libraries that recover and grade **trash / deleted-file
artifacts** across the five major operating systems:

- **`trash-core`** — read-only readers. Decode each platform's native artifact to
  a typed record and pair metadata with content. No findings.
- **`trash-forensic`** — analyzers. Grade a parsed record + its pairing into
  canonical `forensicnomicon::report::Finding`s.

"Trash" is the genus; each OS keeps its native artifact and entry point
(ADR 0002):

| OS | Artifact | Reader |
|---|---|---|
| Windows | `$Recycle.Bin\<SID>\` `$I` index ⇄ `$R` content | `windows::parse_index` + `scan_pairs` |
| Linux | freedesktop.org / XDG `info/*.trashinfo` ⇄ `files/` | `linux::parse_trashinfo` + `scan_trash` |
| macOS | Trash `.DS_Store` put-back records (`ptbN`/`ptbL`) | `macos::parse_put_back` |
| Android | `MediaStore` `.trashed-<expiry>-<name>` filename codec | `android::parse_trashed_name` |
| iOS | `Photos.sqlite` Recently Deleted (`ZASSET.ZTRASHEDSTATE`) | `ios::parse_trashed_assets` |

## Who links it

These are libraries — there is no binary in this repo. Consumers are:

- **`issen`**, the SecurityRonin examiner front end, which wires trash findings
  into a cross-artifact timeline (the no-Rust path for an analyst).
- **Third-party Rust tools** that need deleted-file recovery for one or more
  platforms. A single-platform consumer builds `--no-default-features --features
  <os>` to drop the others' dependencies (ADR 0006).

## What it does

Per deleted item, `trash-core` recovers **where it came from** (original path),
**how big it was** (original size, where the artifact records it), and **when it
was deleted** (per-platform timestamp, normalized to UTC where applicable).
`trash-forensic` then grades the record, emitting findings as **observations**
("consistent with …"), never legal conclusions — the analyst concludes. The
finding codes are a stable, published contract:

| Code | Category | Severity | Platforms |
|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | Windows |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | Windows |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | Windows |
| `TRASH-CONTENT-PURGED` | Residue | Medium | Linux |
| `TRASH-PATH-TRAVERSAL` | Concealment | High | Linux |
| `TRASH-DELETION-TIME-MISSING` | Integrity | Medium | Linux, iOS |
| `TRASH-ORPHAN-METADATA` | Residue | Medium | macOS |
| `TRASH-PUTBACK-TRAVERSAL` | Concealment | High | macOS |
| `TRASH-EXPIRED-RESIDUE` | Residue | Low | Android, iOS |
| `TRASH-MALFORMED-NAME` | Structure | Low | Android |

## Scope

- Read-only decoding of the five artifacts above to typed records, with
  metadata↔content pairing where the platform has both.
- Cross-platform anomaly grading (purged content, path traversal, missing/absent
  deletion time, expired residue, malformed names) into `forensicnomicon`
  findings.
- Faithful per-platform format handling: endianness, timestamp epoch, and
  encoding are preserved per artifact (ADR 0005).

## Non-goals

- **No binary / CLI / GUI / MCP** — this repo ships libraries only; the
  examiner-facing surface is `issen`.
- **No recovery of purged rows** (SQLite WAL/freelist/carving) — left to the
  underlying `sqlite-core` engine for iOS (ADR 0007).
- **No writes, ever** — readers treat input as attacker-controlled and produce
  derived records only; they never modify evidence.
- **No database correlation** — decoding an Android `.trashed-` name recovers the
  filename and expiry from the name alone; joining it to `external.db` is a
  separate concern.
- **No legal conclusions** — findings are observations.

## Correctness & robustness approach

- Each reader is validated against an **independent oracle** (rifiuti2, Python
  `urllib`/`datetime`, al45tair's `ds_store` byte-for-byte across 62 records, the
  AOSP regex, the `sqlite3` CLI), documented in
  [`docs/validation.md`](validation.md) (ADR 0005).
- Untrusted parsing is **panic-free by lint** (`forbid(unsafe)`,
  `unwrap_used`/`expect_used = deny`, bounds-checked reads, cycle-guarded B-tree
  walk) and **input-fuzzed** (one `cargo-fuzz` target per reader plus a full
  parse→audit target), per ADR 0004.
