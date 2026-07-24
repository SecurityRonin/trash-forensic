# 5. Decode each artifact to its authoritative spec; validate against an independent oracle per platform

Date: 2026-07-24
Status: Accepted

## Context

The five trash artifacts share no byte layout, no endianness, and no timestamp
epoch. Coding any of them from a recollection of "how it probably works" is how
inverted bit-splits and wrong offsets ship green. Each needs its own authoritative
reference, and correctness must be checked against something we did not write —
self-consistent round-trips pass while both encoder and decoder are wrong.

## Decision

Decode each artifact strictly to its documented structure, preserving
per-platform format facts rather than forcing a common shape:

- **Windows `$I`** — little-endian: 8-byte version (`1` pre-Win10 / `2` Win10+),
  8-byte size, 8-byte `FILETIME` (100 ns ticks since 1601-01-01), then a fixed
  520-byte UTF-16**LE** name (v1) or a length-prefixed variable name (v2). Layout
  per the libyal *dtformats* "Windows Recycle.Bin file formats" spec
  (`trash-core/src/windows.rs` header table; `docs/validation.md`).
- **macOS `.DS_Store`** — a `Bud1` buddy allocator whose `DSDB` B-tree holds
  `ptbN`/`ptbL` records as length-prefixed UTF-16**BE** `ustr` values (opposite
  endianness to Windows), the firmlink `System/Volumes/Data/…` form normalized to
  the user-visible path. Per Wim Lewis's `DSStoreFormat.pod`
  (`trash-core/src/macos.rs`).
- **Linux `.trashinfo`** — a `.desktop`-style INI; `Path=` is percent-decoded per
  RFC 2396 (URI escaping, so `+` is a literal plus, not a space), per the
  freedesktop.org Trash Specification v1.0 (`trash-core/src/linux.rs`).
- **Android `MediaStore`** — the `PATTERN_EXPIRES_FILE`
  `^\.(pending|trashed)-(\d+)-([^/]+)$` codec, `dateExpires` in epoch **seconds**,
  display name after the *second* `-`. Per AOSP `FileUtils.java`
  (`trash-core/src/android.rs`).
- **iOS `Photos.sqlite`** — `ZASSET`/`ZGENERICASSET` rows with `ZTRASHEDSTATE = 1`
  and `ZTRASHEDDATE` in Mac Absolute Time (+978 307 200 s to Unix)
  (`trash-core/src/ios.rs`).

Each reader is validated against an **independent oracle**, documented in
`docs/validation.md`: Windows vs `rifiuti2`; Linux vs Python `urllib`/`datetime`;
macOS byte-for-byte across 62 put-back records vs al45tair's `ds_store`; Android
vs the AOSP regex run as an oracle; iOS vs the `sqlite3` CLI.

## Consequences

- Endianness, epoch, and encoding stay faithful to each platform — a genuine
  domain discontinuity, not a special case.
- Correctness rests on tier-1/tier-2 evidence (a third-party tool or the
  documented construction), not on fixtures we authored and answered ourselves.
- New Windows format versions get new handling keyed off the version field, never
  a hardcoded per-fixture branch.
