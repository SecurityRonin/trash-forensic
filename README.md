# trash-forensic

[![trash-core](https://img.shields.io/crates/v/trash-core.svg?label=trash-core)](https://crates.io/crates/trash-core)
[![trash-forensic](https://img.shields.io/crates/v/trash-forensic.svg?label=trash-forensic)](https://crates.io/crates/trash-forensic)
[![Docs.rs](https://img.shields.io/docsrs/trash-forensic)](https://docs.rs/trash-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/trash-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/trash-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![security advisories](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

**Who deleted what, when — recovered from the trash of every major OS, with the suspicious entries already graded for you.** Point it at a Windows `$Recycle.Bin`, a Linux XDG trash, a macOS Trash `.DS_Store`, an Android `.trashed-` file, or an iOS `Photos.sqlite` carved from an image, and get back, per deleted item: where it came from, when it was deleted, and a severity-graded finding for anything that looks tampered with.

## The results, in 12 lines

```toml
[dependencies]
trash-forensic = "0.2"   # pulls in trash-core; all five OS readers on by default
```

```rust
use trash_core::{parse_index, scan_pairs};
use trash_forensic::audit_pair;

for pair in scan_pairs(recycle_bin_dir)? {           // $Recycle.Bin\<SID>\
    let bytes = std::fs::read(&pair.index_path)?;
    if let Ok(index) = parse_index(&bytes) {
        // what was deleted, and when
        println!("{} ({} bytes) deleted {:?}",
            index.original_path, index.original_size, index.deleted_at);
        // …and anything suspicious about it, already graded
        for finding in audit_pair(&index, &pair) {
            println!("  [{:?}] {} — {}", finding.severity, finding.code, finding.note);
        }
    }
}
# Ok::<(), std::io::Error>(())
```

```text
C:\Users\victim\Documents\secret plan.docx (1234 bytes) deleted Some(2024-01-15T10:30:00Z)
  [High] RECYCLEBIN-PATH-TRAVERSAL — stored original path ..\..\Windows\…  contains parent-directory ('..') components — consistent with a crafted name rather than a normal deletion
```

Every reader follows the same shape — decode the artifact to a deleted-item record, then grade it. A clean record prints its line and no finding.

## Five operating systems, one vocabulary

"Trash" is the genus; each platform keeps its native artifact and entry point. Each reader module is gated behind a same-named Cargo feature (all on by default), so a single-platform consumer can `--no-default-features --features <os>` and drop the rest's dependencies.

| OS | Artifact | Reader |
|---|---|---|
| **Windows** | `$Recycle.Bin\<SID>\` `$I` index ⇄ `$R` content | [`windows::parse_index`] + [`scan_pairs`] |
| **Linux** | freedesktop.org / XDG `Trash/info/*.trashinfo` ⇄ `files/` | [`linux::parse_trashinfo`] + [`scan_trash`] |
| **macOS** | Trash `.DS_Store` put-back records (`ptbN`/`ptbL`) | [`macos::parse_put_back`] |
| **Android** | `MediaStore` `.trashed-<expiry>-<name>` filename codec | [`android::parse_trashed_name`] |
| **iOS** | `Photos.sqlite` Recently Deleted (`ZASSET.ZTRASHEDSTATE`) | [`ios::parse_trashed_assets`] |

[`windows::parse_index`]: https://docs.rs/trash-core/latest/trash_core/windows/fn.parse_index.html
[`scan_pairs`]: https://docs.rs/trash-core/latest/trash_core/windows/fn.scan_pairs.html
[`linux::parse_trashinfo`]: https://docs.rs/trash-core/latest/trash_core/linux/fn.parse_trashinfo.html
[`scan_trash`]: https://docs.rs/trash-core/latest/trash_core/linux/fn.scan_trash.html
[`macos::parse_put_back`]: https://docs.rs/trash-core/latest/trash_core/macos/fn.parse_put_back.html
[`android::parse_trashed_name`]: https://docs.rs/trash-core/latest/trash_core/android/fn.parse_trashed_name.html
[`ios::parse_trashed_assets`]: https://docs.rs/trash-core/latest/trash_core/ios/fn.parse_trashed_assets.html

## What gets flagged

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. The codes are a stable, published contract.

| Code | Category | Severity | Platforms | What it observes |
|---|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | Windows | `$I` metadata survives but the `$R` content file is gone |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | Windows | stored path escapes its directory via a `..` component |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | Windows | the deletion `FILETIME` is zero — never set or cleared |
| `TRASH-CONTENT-PURGED` | Residue | Medium | Linux | a `.trashinfo` survives but its `files/` content is gone |
| `TRASH-PATH-TRAVERSAL` | Concealment | High | Linux | the stored `Path=` contains a spec-forbidden `..` |
| `TRASH-DELETION-TIME-MISSING` | Integrity | Medium | Linux, iOS | the deletion timestamp is absent or unparseable |
| `TRASH-ORPHAN-METADATA` | Residue | Medium | macOS | a `.DS_Store` put-back record survives but its item is gone |
| `TRASH-PUTBACK-TRAVERSAL` | Concealment | High | macOS | the stored `ptbN`/`ptbL` escapes its directory via `..` |
| `TRASH-EXPIRED-RESIDUE` | Residue | Low | Android, iOS | the item is still present past its retention/expiry window |
| `TRASH-MALFORMED-NAME` | Structure | Low | Android | a `trashed`/`pending` name that does not parse to a token |

Findings carry the offending value as evidence and are stamped with the analyzer name, version, and per-item scope, so they aggregate uniformly with every other [`forensicnomicon`](https://crates.io/crates/forensicnomicon) analyzer in the fleet.

## No-Rust path

The two crates are the building blocks; for an end-to-end timeline that correlates trash evidence with the rest of an image, they feed [`issen`](https://github.com/SecurityRonin/issen) — the SecurityRonin examiner front end — so you get the findings without writing any Rust.

## The two-crate split

- **[`trash-core`](https://crates.io/crates/trash-core)** — the readers. One module per OS (`windows`, `linux`, `macos`, `android`, `ios`), each decoding its native artifact to a typed record and pairing metadata with content. No findings. The iOS reader builds on the pure-Rust [`sqlite-core`](https://crates.io/crates/sqlite-core) engine (no `libsqlite3`).
- **[`trash-forensic`](https://crates.io/crates/trash-forensic)** — the analyzers. Grade a parsed record + its pairing into canonical `forensicnomicon` findings. The split mirrors `ntfs-core`/`ntfs-forensic`.

## Trust, but verify

Every reader treats its input as attacker-controlled. The binary parsers (`$I`, `.DS_Store`) use bounds-checked reads, cap allocations against hostile length fields, walk the macOS B-tree with a cycle guard, and return a typed error — carrying the offending value — rather than panicking. `unsafe` is **forbidden** workspace-wide. Each untrusted-input reader has a `cargo fuzz` target with a *must-not-panic* invariant.

Correctness is checked against **independent oracles**, not only self-consistent round-trips:

- **Windows** — fixtures built from the libyal [*Windows Recycle.Bin file formats*](https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc) spec, cross-decoded with [rifiuti2](https://github.com/abelcheung/rifiuti2).
- **Linux** — the freedesktop.org [Trash Specification v1.0](https://specifications.freedesktop.org/trash/latest/); percent-decode and date parsing cross-checked against Python `urllib`/`datetime`.
- **macOS** — a `.DS_Store` minted by al45tair's [`ds_store`](https://pypi.org/project/ds_store/) library; decode of a real `~/.Trash/.DS_Store` agrees with that oracle **byte-for-byte across 62 put-back records**.
- **Android** — the codec's match/split decisions agree with AOSP `FileUtils.java` `PATTERN_EXPIRES_FILE` run as a regex oracle.
- **iOS** — a real `Photos.sqlite` decoded by both this reader and the `sqlite3` CLI, agreeing on filename and `ZTRASHEDDATE`.

See [`docs/validation.md`](docs/validation.md).

---

[Privacy Policy](https://securityronin.github.io/trash-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/trash-forensic/terms/) · © 2026 Security Ronin Ltd
