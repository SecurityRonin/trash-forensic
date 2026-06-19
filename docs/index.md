# trash-forensic

Read-only readers + forensic analyzers for **trash / deleted-file artifacts
across Windows, Linux, macOS, Android, and iOS**.

Every major OS keeps a record of recently deleted files somewhere — a Windows
`$Recycle.Bin`, a Linux XDG trash, a macOS Trash `.DS_Store`, an Android
`.trashed-` rename, an iOS `Photos.sqlite` row. This repo decodes each of them to
a deleted-item record and grades it for tampering, in two crates:

- **`trash-core`** — the readers. One module per OS, each gated behind a
  same-named Cargo feature (all on by default), decoding its native artifact to a
  typed record and pairing metadata with content. No findings.
- **`trash-forensic`** — the analyzers. Emit canonical
  [`forensicnomicon`](https://crates.io/crates/forensicnomicon) findings for
  purged content, path-traversal stored names, missing deletion times, and
  expired residue.

## Coverage

| OS | Artifact | Reader |
|---|---|---|
| Windows | `$Recycle.Bin\<SID>\` `$I` ⇄ `$R` | `windows::parse_index` + `scan_pairs` |
| Linux | XDG `Trash/info/*.trashinfo` ⇄ `files/` | `linux::parse_trashinfo` + `scan_trash` |
| macOS | Trash `.DS_Store` put-back (`ptbN`/`ptbL`) | `macos::parse_put_back` |
| Android | `MediaStore` `.trashed-<expiry>-<name>` | `android::parse_trashed_name` |
| iOS | `Photos.sqlite` `ZASSET.ZTRASHEDSTATE` | `ios::parse_trashed_assets` |

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

Findings are observations, never legal conclusions.

## Robustness

Every reader treats its input as attacker-controlled — bounds-checked,
allocation-capped, cycle-guarded (the macOS B-tree walk), panic-free, and fuzzed.
`unsafe` is forbidden workspace-wide. See [Validation](validation.md) for each
platform's authoritative spec and independent-oracle cross-check.
