# recyclebin-core

[![recyclebin-core](https://img.shields.io/crates/v/recyclebin-core.svg?label=recyclebin-core)](https://crates.io/crates/recyclebin-core)
[![recyclebin-forensic](https://img.shields.io/crates/v/recyclebin-forensic.svg?label=recyclebin-forensic)](https://crates.io/crates/recyclebin-forensic)
[![Docs.rs](https://img.shields.io/docsrs/recyclebin-core)](https://docs.rs/recyclebin-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/recyclebin-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/recyclebin-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A from-scratch, read-only Windows Recycle Bin `$I` index reader — recovers a deleted file's original path, size, and deletion time, and pairs `$I`/`$R` files by a directory scan. Pure Rust, no `unsafe`, no Windows host required: reads a `$Recycle.Bin` lifted from any image.**

```toml
[dependencies]
recyclebin-core = "0.1"
```

```rust
use recyclebin_core::parse_index;

// raw bytes of a $I index file (e.g. $IAB12CD.docx)
let idx = parse_index(bytes)?;
println!("{} ({} bytes) deleted {:?}",
    idx.original_path, idx.original_size, idx.deleted_at);
// C:\Users\victim\Documents\secret plan.docx (1234 bytes) deleted Some(2024-01-15T10:30:00Z)
# Ok::<(), recyclebin_core::Error>(())
```

## What it parses

`parse_index(&[u8]) -> Result<RecycleBinIndex, Error>` decodes a single `$I`
file: the 8-byte format version, original size, `FILETIME` deletion time, and the
UTF-16LE original path — **version 1** (pre-Win10, fixed 520-byte name field) and
**version 2** (Win10+, length-prefixed name) alike. A zero `FILETIME` surfaces as
`deleted_at: None` rather than a bogus 1601 timestamp.

`scan_pairs(&Path) -> io::Result<Vec<RecycleBinPair>>` walks a `$Recycle.Bin\<SID>`
directory and matches each `$I` index to its `$R` content file by the trailing
identifier (`$IAB12CD.docx` ⇄ `$RAB12CD.docx`); a `$I` with no `$R` yields a pair
whose `content_path` is `None`.

The bare crate name `recyclebin` is not used; the reader publishes as
**`recyclebin-core`** and imports as **`recyclebin_core`**.

## Trust, but verify

`$I` bytes are treated as attacker-controlled. `#![forbid(unsafe_code)]`;
panic-free on crafted input (the workspace denies `clippy::unwrap_used` /
`expect_used` in production code, every integer read is bounds-checked, and a
hostile version-2 name length is rejected against a 32 768-char cap **before**
allocation); a truncated or hostile file returns a typed `Error` that carries the
offending value, never a panic or an out-of-bounds read. Fuzzed with `cargo-fuzz`
(*must not panic*), and decoded paths/sizes/times are cross-checked against the C
tool [rifiuti2](https://github.com/abelcheung/rifiuti2). See
[`docs/validation.md`](https://github.com/SecurityRonin/recyclebin-forensic/blob/main/docs/validation.md).

## Forensic analysis

Severity-graded anomaly auditing (purged content, path-traversal in the stored
name, missing deletion time) lives in the sibling
**[`recyclebin-forensic`](https://crates.io/crates/recyclebin-forensic)** crate,
built on this one — the reader/analyzer split mirrors `ntfs-core`/`ntfs-forensic`.

---

[Privacy Policy](https://securityronin.github.io/recyclebin-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/recyclebin-forensic/terms/) · © 2026 Security Ronin Ltd
