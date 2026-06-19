# trash-forensic

Windows Recycle Bin `$I` index reader + forensic analyzer.

When a file is sent to the Recycle Bin on Windows Vista and later, the shell
writes a `$I…` index file (the deleted file's original path, size, and deletion
time) and a `$R…` content file. This repo is two crates:

- **`trash-core`** — the reader. Parses the `$I` index format (version 1
  pre-Win10 fixed 520-byte name; version 2 Win10+ length-prefixed) and pairs
  `$I`/`$R` files by a directory scan. No findings.
- **`trash-forensic`** — the analyzer. Emits canonical
  [`forensicnomicon`](https://crates.io/crates/forensicnomicon) findings for
  purged content, path-traversal stored names, and missing deletion times.

## Quick start

```rust
use trash_core::{parse_index, scan_pairs};
use trash_forensic::audit_pair;

for pair in scan_pairs(recycle_bin_dir)? {
    let bytes = std::fs::read(&pair.index_path)?;
    if let Ok(index) = parse_index(&bytes) {
        println!("{} ({} bytes) deleted {:?}",
            index.original_path, index.original_size, index.deleted_at);
        for f in audit_pair(&index, &pair) {
            println!("  [{:?}] {} — {}", f.severity, f.code, f.note);
        }
    }
}
# Ok::<(), std::io::Error>(())
```

## Findings

| Code | Category | Severity | Meaning |
|---|---|---|---|
| `RECYCLEBIN-CONTENT-PURGED` | Residue | Medium | `$I` metadata survives but `$R` is gone |
| `RECYCLEBIN-PATH-TRAVERSAL` | Concealment | High | stored path escapes its directory (`..\`) |
| `RECYCLEBIN-DELETION-TIME-MISSING` | Integrity | Low | the deletion `FILETIME` is zero |

Findings are observations, never legal conclusions.

## Robustness

`$I` bytes are treated as attacker-controlled — the reader is panic-free,
bounds-checked, allocation-capped, and fuzzed. See [Validation](validation.md)
for the spec citation and the independent rifiuti2 oracle cross-check.
