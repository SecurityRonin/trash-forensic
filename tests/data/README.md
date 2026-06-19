# Test fixtures — `recyclebin-forensic`

All fixtures are **SYNTHETIC**, hand-assembled strictly from the libyal *Windows
Recycle.Bin file formats* specification (raw `struct.pack`, not round-tripped
through any writer in this repo) and cross-checked with the independent
`rifiuti-vista` (rifiuti2 v0.8.2) oracle. See [`../../docs/validation.md`](../../docs/validation.md)
for the oracle methodology and cross-check table, and the fleet machine-index at
`issen/docs/corpus-catalog.md`.

`tests/data/` is gitignored; this README + the generator below are the committed
record needed to reproduce the corpus. Regenerate with the Python script in the
catalog entry (same script that produced these bytes).

## Generator

The verbatim builder (Python 3) — offsets per the spec, FILETIME =
`(unix_seconds + 11_644_473_600) * 10_000_000`:

```python
import struct, datetime
def ft(dt): return int((dt.timestamp()+11644473600)*10_000_000)

# $IAB12CD.docx — version 2
p="C:\\Users\\victim\\Documents\\secret plan.docx"; n=p.encode("utf-16-le")+b"\x00\x00"
open("$IAB12CD.docx","wb").write(
  struct.pack("<q",2)+struct.pack("<q",1234)
  +struct.pack("<Q",ft(datetime.datetime(2024,1,15,10,30,0,tzinfo=datetime.timezone.utc)))
  +struct.pack("<I",len(n)//2)+n)

# $IZZ99YY.txt — version 1 (fixed 520-byte name field)
p="C:\\temp\\oldfile.txt"; nb=p.encode("utf-16-le")+b"\x00\x00"; nb=nb+b"\x00"*(520-len(nb))
open("$IZZ99YY.txt","wb").write(
  struct.pack("<q",1)+struct.pack("<q",999)
  +struct.pack("<Q",ft(datetime.datetime(2015,6,1,0,0,0,tzinfo=datetime.timezone.utc)))+nb)

# $RAB12CD.docx — paired content file for the v2 record (arbitrary bytes)
open("$RAB12CD.docx","wb").write(b"PK\x03\x04 fake docx content")

# $INODATE.bin — version 2, zero FILETIME (deletion time unset)
p="C:\\Data\\nodate.bin"; n=p.encode("utf-16-le")+b"\x00\x00"
open("$INODATE.bin","wb").write(
  struct.pack("<q",2)+struct.pack("<q",42)+struct.pack("<Q",0)
  +struct.pack("<I",len(n)//2)+n)

# $ITRAVER.dll — version 2, path-traversal stored name (hostile)
p="..\\..\\..\\Windows\\System32\\evil.dll"; n=p.encode("utf-16-le")+b"\x00\x00"
open("$ITRAVER.dll","wb").write(
  struct.pack("<q",2)+struct.pack("<q",4096)
  +struct.pack("<Q",ft(datetime.datetime(2023,3,3,3,3,3,tzinfo=datetime.timezone.utc)))
  +struct.pack("<I",len(n)//2)+n)
```

## Files

#### `$IAB12CD.docx`
- **Class:** SYNTHETIC · confidence ✓
- **Layout:** version 2; size 1234; deletion `2024-01-15T10:30:00Z`; path
  `C:\Users\victim\Documents\secret plan.docx`
- **Oracle:** `rifiuti-vista -f json` agrees (see validation.md)
- **MD5:** `dda869d9f129a549cf08ca3ed0d8a519`

#### `$RAB12CD.docx`
- **Class:** SYNTHETIC · confidence ✓
- **Role:** the `$R` content file paired with `$IAB12CD.docx` (arbitrary bytes;
  the reader only pairs by filename, it does not parse `$R` content)
- **MD5:** `94df00a44742d89223d05471efd623b2`

#### `$IZZ99YY.txt`
- **Class:** SYNTHETIC · confidence ✓
- **Layout:** version 1 (fixed 520-byte name); size 999; deletion
  `2015-06-01T00:00:00Z`; path `C:\temp\oldfile.txt`. No paired `$R` (lone `$I`).
- **Oracle:** `rifiuti-vista` agrees
- **MD5:** `6e1a61acc4970085ee519c6bf044c6ed`

#### `$INODATE.bin`
- **Class:** SYNTHETIC · confidence ✓
- **Layout:** version 2; size 42; **zero `FILETIME`**; path `C:\Data\nodate.bin`
- **Oracle:** `rifiuti-vista` reports "deletion time is suspicious or broken",
  confirming the reader's `deleted_at = None`
- **MD5:** `7eb6cd7794a3a1328df50c99db689e7d`

#### `$ITRAVER.dll`
- **Class:** SYNTHETIC · confidence ✓
- **Layout:** version 2; size 4096; deletion `2023-03-03T03:03:03Z`; path
  `..\..\..\Windows\System32\evil.dll` (path-traversal stored name)
- **Oracle:** `rifiuti-vista` agrees, preserving the traversal path verbatim
- **MD5:** `09698546d61c9f2d1e2ca59772642da4`

## Oracle build

`rifiuti-vista` is not in the default Homebrew tap; build from source:

```sh
git clone --depth 1 https://github.com/abelcheung/rifiuti2.git
cd rifiuti2 && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
# binary: build/rifiuti-vista  (requires glib-2.0 + pkg-config)
```
