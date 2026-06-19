# Validation

Each `trash-core` reader is validated against an **independent oracle** — a tool
or specification we did not write — not only against self-consistent round-trips.
This is the build-time front door to the Doer-Checker discipline. The Windows `$I`
reader is documented in full first; the four other platforms follow under
[Cross-platform oracles](#cross-platform-oracles). The Windows oracle is the C
tool [rifiuti2](https://github.com/abelcheung/rifiuti2) (`rifiuti-vista`, v0.8.2).

## Windows — authoritative specification

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
decoded with **both** `trash-core::parse_index` **and** `rifiuti-vista`.
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

## Cross-platform oracles

Each non-Windows reader is checked the same way — against a primary spec and an
independent decoder.

### Linux — freedesktop.org / XDG `.trashinfo`

- **Spec**: freedesktop.org [Trash Specification v1.0](https://specifications.freedesktop.org/trash/latest/)
  (2014-01-02); `Path=` percent-encoding per [RFC 2396 §2](https://www.rfc-editor.org/rfc/rfc2396#section-2).
- **Oracle**: the two non-trivial transforms — RFC 2396 percent-decoding (where
  `+` stays a literal `+`, *not* a space) and the naive-local-time
  `DeletionDate` parse — are cross-checked against Python `urllib.parse.unquote`
  and `datetime.strptime`; outputs agree. The reader decodes the date into a
  `NaiveDateTime`, never a UTC instant, because the spec value carries no zone.
- **Cross-check tools** (forensic, run against captured Linux trees): trash-cli,
  Fox-IT [dissect.target](https://docs.dissect.tools/en/latest/plugins/recyclebin.html).

### macOS — Trash `.DS_Store` put-back records

- **Spec**: Wim Lewis's reverse-engineered [`DSStoreFormat.pod`](https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod)
  (Bud1 buddy allocator → `DSDB` B-tree → records); the `ptbN`/`ptbL` record
  types are newer Finder additions cross-checked against al45tair's
  [`ds_store`](https://pypi.org/project/ds_store/) library (v1.3.2).
- **Oracle**: the test fixture (`tests/data/putback.DS_Store`) is minted by
  `ds_store`, not hand-encoded. Beyond the fixture, decoding a **real live**
  `~/.Trash/.DS_Store` (62 put-back records) is **byte-for-byte identical** to
  the `ds_store` oracle — including Finder de-dup name divergence and
  `/Applications` firmlink normalisation. Absence of a put-back record is normal
  (Finder writes `.DS_Store` lazily) and is deliberately not flagged.

### Android — `MediaStore` `.trashed-` filename codec

- **Spec**: AOSP `MediaProvider` [`FileUtils.java`](https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android11-release/src/com/android/providers/media/util/FileUtils.java)
  `PATTERN_EXPIRES_FILE = (?i)^\.(pending|trashed)-(\d+)-([^/]+)$`, with
  `dateExpires` in epoch **seconds** and 30-day (trashed) / 7-day (pending)
  default windows.
- **Oracle**: the codec's match/reject and field-splitting decisions agree
  exactly with that regex run over the same inputs in Python.

### iOS — `Photos.sqlite` Recently Deleted

- **Spec**: `ZASSET.ZTRASHEDSTATE = 1` + `ZTRASHEDDATE` in Mac Absolute Time
  (Cocoa epoch, +978 307 200 s), per The Forensic Scooter's
  [Photos.sqlite documentation](https://theforensicscooter.com/2022/05/02/photos-sqlite-query-documentation-notable-artifacts/)
  and kacos2000's `Photos_sqlite.sql`.
- **Engine**: the pure-Rust [`sqlite-core`](https://crates.io/crates/sqlite-core)
  reader (no `libsqlite3`); purged-row recovery (WAL/freelist/carving) is left to
  that engine, not reimplemented here.
- **Oracle**: a real `Photos.sqlite` (`tests/data/Photos.sqlite`) is decoded by
  both this reader and the `sqlite3` CLI
  (`SELECT … datetime(ZTRASHEDDATE+978307200,'unixepoch') … WHERE ZTRASHEDSTATE=1`);
  the two agree row-for-row on filename and trashed date.

## Fuzzing

Every reader that consumes untrusted input has a `cargo fuzz` target with a
*must-not-panic* invariant: `fuzz_parse_index` and `fuzz_forensic` (Windows),
`fuzz_parse_trashinfo` (Linux), `fuzz_parse_dsstore` (the macOS Bud1 binary
parser), `fuzz_parse_trashed_name` (Android), and `fuzz_ios_photos` (iOS).
