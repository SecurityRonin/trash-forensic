# 2. "Trash" as a cross-platform genus behind a per-OS Cargo feature matrix

Date: 2026-07-24
Status: Accepted

## Context

The repo began as a Windows-only Recycle Bin reader (`recyclebin-core` /
`recyclebin-forensic`; earliest commits are prefixed `feat(recyclebin)`). Every
major OS keeps an equivalent "deleted but recoverable" store, but each uses a
different native artifact and entry point: Windows `$Recycle.Bin` `$I`/`$R`,
Linux freedesktop.org `.trashinfo`, macOS Trash `.DS_Store` put-back records,
Android `MediaStore` `.trashed-` filenames, and iOS `Photos.sqlite` "Recently
Deleted" rows. An examiner wants one vocabulary across all five, but a
single-platform consumer should not pay for the four they do not use — the iOS
reader alone pulls a SQLite engine (`sqlite-core`), and the Linux reader pulls
`percent-encoding`.

The cross-platform expansion is explicit in the history: commit `1d2e0b8`
("Cross-platform rebrand: the crate becomes the umbrella 'trash'
reader/analyzer"), followed by the `refactor(...)!: per-OS modules + Cargo
feature matrix` commits (`678bb0d`, `23a22a0`) and the per-OS
RED/GREEN reader+analyzer pairs.

## Decision

Treat "trash" as the genus and each platform's artifact as a species in its own
module: `windows`, `linux`, `macos`, `android`, `ios` in both crates
(`trash-core/src/lib.rs`, `trash-forensic/src/lib.rs`). Each module is gated
behind a same-named Cargo feature, and each feature pulls only its own optional
dependencies (`trash-core/Cargo.toml`: `linux = ["dep:percent-encoding"]`,
`ios = ["dep:sqlite-core"]`; `trash-forensic` features chain to the matching
`trash-core/<os>` feature). A consumer builds `--no-default-features --features
<os>` to drop the rest.

Native leaf terms stay native rather than being homogenized: the Windows backend
keeps `RecycleBinIndex`/`RecycleBinPair` and the `RECYCLEBIN-*` finding codes
(the correct term on Windows), while cross-platform findings use the `TRASH-*`
scheme (commit `1d2e0b8`; `trash-forensic` finding-code table in `README.md`).

## Consequences

- One import surface and one finding vocabulary span five operating systems.
- A single-platform build compiles only its reader and drops the other
  platforms' dependency trees.
- Adding a sixth platform is a new module + feature, not a new crate.
- The `RECYCLEBIN-*` / `TRASH-*` code duality is deliberate; consumers matching
  on codes must handle both schemes.
