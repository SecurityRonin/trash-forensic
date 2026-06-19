# recyclebin-forensic

[![Crates.io core](https://img.shields.io/crates/v/recyclebin-core?label=recyclebin-core)](https://crates.io/crates/recyclebin-core)
[![Crates.io forensic](https://img.shields.io/crates/v/recyclebin-forensic?label=recyclebin-forensic)](https://crates.io/crates/recyclebin-forensic)
[![Docs.rs](https://img.shields.io/docsrs/recyclebin-core?label=docs.rs)](https://docs.rs/recyclebin-core)
[![Rust 1.96+](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/recyclebin-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/recyclebin-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![security advisories](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

**Recover who deleted what, when — straight from the Windows Recycle Bin `$I`
index, and have the suspicious records flagged for you.**

When a file is sent to the Recycle Bin on Windows Vista and later, the shell
writes a `$I…` index file (the deleted file's original path, size, and deletion
time) and a `$R…` file (its content). `recyclebin-core` reads the `$I` metadata
and pairs `$I`/`$R`; `recyclebin-forensic` grades the anomalies.

```rust
use recyclebin_core::parse_index;

// raw bytes of a $I index file
let idx = parse_index(bytes)?;
println!("{} ({} bytes) deleted {:?}",
    idx.original_path, idx.original_size, idx.deleted_at);
// C:\Users\victim\Documents\secret plan.docx (1234 bytes) deleted Some(2024-01-15T10:30:00Z)
# Ok::<(), recyclebin_core::Error>(())
```

## The analyzer is the differentiator

`recyclebin-forensic::audit_pair` turns a parsed record + its `$I`/`$R` pairing
into graded [`forensicnomicon`](https://crates.io/crates/forensicnomicon)
findings, so Recycle Bin evidence aggregates alongside every other SecurityRonin
analyzer:

```rust
use recyclebin_core::{parse_index, scan_pairs};
use recyclebin_forensic::audit_pair;

for pair in scan_pairs(recycle_bin_dir)? {
    let bytes = std::fs::read(&pair.index_path)?;
    if let Ok(index) = parse_index(&bytes) {
        for f in audit_pair(&index, &pair) {
            println!("[{:?}] {} — {}", f.severity, f.code, f.note);
        }
    }
}
# Ok::<(), std::io::Error>(())
```

| Code | Category | Severity | Meaning |
|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | `$I` metadata survives but the `$R` content file is gone |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | the stored original path escapes its directory (`..\`) |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | the deletion `FILETIME` is zero (unset / cleared) |

Findings are observations, never legal conclusions — the analyst concludes.

## The two-crate split

- **`recyclebin-core`** — the reader. Parses the `$I` index (version 1 pre-Win10
  fixed 520-byte name; version 2 Win10+ length-prefixed) and pairs `$I`/`$R` by a
  directory scan. No findings.
- **`recyclebin-forensic`** — the analyzer. Emits canonical findings via
  `forensicnomicon::report`, depending on `recyclebin-core`.

## Trust, but verify

`$I` bytes are treated as attacker-controlled: the reader is **panic-free**, with
bounds-checked integer reads, a 32 768-char cap on the version-2 filename length
before allocation, and a typed `Error` for every truncation or hostile length —
never a panic, never an out-of-bounds read. Both the parser and the full
parse→audit pipeline are **fuzzed** (`cargo fuzz`, *must not panic*).

Correctness is validated against an **independent oracle** — the C tool
[rifiuti2](https://github.com/abelcheung/rifiuti2) — not only self-consistent
round-trips: fixtures are hand-assembled strictly from the libyal
[*Windows Recycle.Bin file formats*](https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc)
spec and decoded with both this reader and `rifiuti-vista`, which must agree on
path, size, and deletion time. See [`docs/validation.md`](docs/validation.md).

---

[Privacy Policy](https://securityronin.github.io/recyclebin-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/recyclebin-forensic/terms/) · © 2026 Security Ronin Ltd
