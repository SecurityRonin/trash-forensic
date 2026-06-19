# Validation

`recyclebin-core` is validated against an **independent oracle** — the C tool
[rifiuti2](https://github.com/abelcheung/rifiuti2) (`rifiuti-vista`, v0.8.2) — so
the parser is checked by a tool we did not write, not only by self-consistent
round-trips. This is the build-time front door to the Doer-Checker discipline.

## Authoritative specification

The byte layout follows the libyal *dtformats* reference:

> **The Windows Recycle.Bin file formats**, libyal/dtformats —
> <https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc>

The `$I` index record (the structure this crate parses):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Format version (`1` = pre-Win10, `2` = Win10+), little-endian |
| 8 | 8 | Original file size, little-endian |
| 16 | 8 | Deletion time — Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) |
| 24 | 520 | *(version 1 only)* Original filename — fixed 260-`wchar_t` UTF-16LE field |
| 24 | 4 | *(version 2 only)* Number of characters in the filename |
| 28 | … | *(version 2 only)* Original filename — variable UTF-16LE, NUL-terminated |

Byte order is little-endian; timestamps are UTC `FILETIME`; strings are UTF-16LE
with an end-of-string character.

## Oracle methodology

The fixtures under `tests/data/` were hand-assembled **strictly from the spec
above** (raw `struct.pack`, not round-tripped through any writer of ours), then
decoded with **both** `recyclebin-core::parse_index` **and** `rifiuti-vista`.
The two must agree on version, original path, original size, and deletion time.

```
rifiuti-vista -f json tests/data/<fixture>
```

### Cross-check results

| Fixture | Version | rifiuti-vista deletion time | size | path | reader agrees |
|---|---|---|---|---|---|
| `$IAB12CD.docx` | 2 | `2024-01-15T10:30:00Z` | 1234 | `C:\Users\victim\Documents\secret plan.docx` | ✅ |
| `$IZZ99YY.txt` | 1 | `2015-06-01T00:00:00Z` | 999 | `C:\temp\oldfile.txt` | ✅ |
| `$ITRAVER.dll` | 2 | `2023-03-03T03:03:03Z` | 4096 | `..\..\..\Windows\System32\evil.dll` | ✅ |
| `$INODATE.bin` | 2 | *(rifiuti reports "deletion time is suspicious or broken")* | 42 | `C:\Data\nodate.bin` | ✅ — reader maps the zero `FILETIME` to `deleted_at = None` |

The zero-`FILETIME` case is informative: rifiuti-vista rejects the record as
having a broken deletion time, which confirms the reader's choice to surface a
zero `FILETIME` as `None` ("recorded but not set") rather than as the 1601 epoch.

## Robustness (panic-free on hostile input)

`$I` bytes are treated as attacker-controlled. Unit + integration tests assert a
typed `Error` (never a panic) for:

- a file shorter than the 24-byte header (`TruncatedHeader`);
- an unsupported version field, with the raw value surfaced (`UnsupportedVersion`);
- a version-1 file missing the full fixed 520-byte name field (`TruncatedV1Name`);
- a version-2 file with no length field (`TruncatedV2Length`);
- a version-2 length that overflows the buffer (`TruncatedV2Name`) or exceeds the
  32 768-char allocation cap (`NameLengthTooLarge`).

Both the `parse_index` and the full parse→audit pipeline are fuzzed
(`cargo fuzz run fuzz_parse_index` / `fuzz_forensic`) with the invariant *must
not panic*; 100 000-run smoke jobs run in CI.

## Spec ambiguity resolved

The spec states the version-2 character count at offset 24 but does not state
whether it **includes** the trailing NUL. Both the libyal reference and
rifiuti-vista treat it as the full UTF-16LE string length **including** the NUL
terminator. The reader therefore reads `chars * 2` bytes and stops decoding at
the first NUL `wchar_t`, which is correct whether or not the producer counted the
NUL — a name shorter than the declared length simply terminates early.
