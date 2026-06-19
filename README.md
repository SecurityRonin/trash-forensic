# trash-forensic

[![trash-core](https://img.shields.io/crates/v/trash-core.svg?label=trash-core)](https://crates.io/crates/trash-core)
[![trash-forensic](https://img.shields.io/crates/v/trash-forensic.svg?label=trash-forensic)](https://crates.io/crates/trash-forensic)
[![Docs.rs](https://img.shields.io/docsrs/trash-forensic)](https://docs.rs/trash-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/trash-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/trash-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![security advisories](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

**Who deleted what, when — recovered straight from a Windows `$Recycle.Bin`, with the suspicious entries already graded for you.** Point it at a recycle-bin directory carved from an image and get back, per deleted file: the original path, the original size, the deletion time, and a severity-graded finding for anything that looks tampered with.

## The results, in 12 lines

```toml
[dependencies]
trash-forensic = "0.1"   # pulls in trash-core
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

That is the whole job: every `$I` index in the directory decoded to a deleted-file record, each one paired with its `$R` content and graded. A clean record prints its line and no finding.

## What gets flagged

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. The codes are a stable, published contract.

| Code | Category | Severity | What it observes |
|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | The `$I` metadata survives but the `$R` content file is gone — the deleted file's record outlived its data |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | The stored original path escapes its directory via a `..` component — consistent with a crafted name, not a normal shell deletion |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | The deletion `FILETIME` is zero — recorded but never set, or cleared |

Findings carry the offending `original_path` as evidence and are stamped with the analyzer name, version, and the `$I` filename, so they aggregate uniformly with every other [`forensicnomicon`](https://crates.io/crates/forensicnomicon) analyzer in the fleet.

## No-Rust path

The two crates are the building blocks; for an end-to-end timeline that correlates Recycle Bin evidence with the rest of an image, they feed [`issen`](https://github.com/SecurityRonin/issen) — the SecurityRonin examiner front end — so you get the findings without writing any Rust.

## The two-crate split

- **[`trash-core`](https://crates.io/crates/trash-core)** — the reader. Parses the `$I` index (version 1 pre-Win10 fixed 520-byte name; version 2 Win10+ length-prefixed) and pairs `$I`/`$R` by a directory scan. No findings.
- **[`trash-forensic`](https://crates.io/crates/trash-forensic)** — the analyzer. Grades a parsed record + its pairing into canonical `forensicnomicon` findings. The split mirrors `ntfs-core`/`ntfs-forensic`.

## Trust, but verify

`$I` bytes are treated as attacker-controlled: the reader is **panic-free**, with bounds-checked integer reads, a 32 768-char cap on the version-2 filename length before allocation, and a typed `Error` — carrying the offending value — for every truncation or hostile length. Never a panic, never an out-of-bounds read. Both the parser and the full parse → audit pipeline are **fuzzed** (`cargo fuzz`, *must not panic*).

Correctness is validated against an **independent oracle** — the C tool [rifiuti2](https://github.com/abelcheung/rifiuti2) — not only self-consistent round-trips: fixtures are hand-assembled strictly from the libyal [*Windows Recycle.Bin file formats*](https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc) spec and decoded with both this reader and `rifiuti-vista`, which must agree on path, size, and deletion time. See [`docs/validation.md`](docs/validation.md).

---

[Privacy Policy](https://securityronin.github.io/trash-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/trash-forensic/terms/) · © 2026 Security Ronin Ltd
