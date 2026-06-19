# trash-forensic

[![trash-forensic](https://img.shields.io/crates/v/trash-forensic.svg?label=trash-forensic)](https://crates.io/crates/trash-forensic)
[![trash-core](https://img.shields.io/crates/v/trash-core.svg?label=trash-core)](https://crates.io/crates/trash-core)
[![Docs.rs](https://img.shields.io/docsrs/trash-forensic)](https://docs.rs/trash-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/trash-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/trash-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Point it at a `$Recycle.Bin`, get back severity-graded Recycle Bin anomalies — content purged out from under its surviving metadata, path-traversal in a stored name, and missing deletion times — as `forensicnomicon::report::Finding`s.**

```toml
[dependencies]
trash-forensic = "0.1"   # pulls in trash-core
```

```rust
use trash_core::{parse_index, scan_pairs};
use trash_forensic::audit_pair;

for pair in scan_pairs(recycle_bin_dir)? {
    let bytes = std::fs::read(&pair.index_path)?;
    if let Ok(index) = parse_index(&bytes) {
        for finding in audit_pair(&index, &pair) {
            println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
        }
    }
}
# Ok::<(), std::io::Error>(())
```

`audit_pair` grades a parsed `$I` record together with its `$I`/`$R` pairing. A
well-formed record — content present, deletion time set, no traversal — yields no
findings. Damaged or hostile `$I` bytes surface from `parse_index` as a typed
error, never a panic.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Category | Severity | What it observes |
|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | A `$I` index survives but its `$R` content file is gone — consistent with the content having been purged while its metadata remains |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | The stored original path escapes its directory via a `..` component — consistent with a crafted name rather than a normal shell deletion |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | The deletion `FILETIME` is zero — recorded but never set, or cleared |

`audit_pair` returns one graded `report::Finding` per anomaly, each stamped with
the analyzer name, version, and the offending `$I` filename as scope, and
carrying the offending `original_path` as evidence. The typed `AnomalyKind` (with
`code`, `severity`, `category`, and `note`) is public for callers that want the
domain enum before conversion.

## The two-crate split

This crate is the **analyzer**; the **reader** is
[`trash-core`](https://crates.io/crates/trash-core) (parses the `$I`
index and pairs `$I`/`$R` by a directory scan). The split mirrors
`ntfs-core`/`ntfs-forensic`. Together they feed
[`issen`](https://github.com/SecurityRonin/issen) for cross-artifact correlation,
so Recycle Bin evidence aggregates uniformly with the rest of the forensic fleet.

## Trust, but verify

Built for `$Recycle.Bin` directories lifted from potentially hostile systems:
`#![forbid(unsafe_code)]`; panic-free on crafted input (the workspace denies
`clippy::unwrap_used` / `expect_used` in production code); both the reader and the
full parse → audit pipeline are fuzzed with `cargo-fuzz`, and `trash-core`
is cross-checked against the C tool
[rifiuti2](https://github.com/abelcheung/rifiuti2). See
[`docs/validation.md`](https://github.com/SecurityRonin/trash-forensic/blob/main/docs/validation.md).

---

[Privacy Policy](https://securityronin.github.io/trash-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/trash-forensic/terms/) · © 2026 Security Ronin Ltd
