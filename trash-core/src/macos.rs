//! Read-only reader for the macOS **Trash** put-back metadata stored in a
//! Trash folder's `.DS_Store` file.
//!
//! On modern macOS (Big Sur → Sequoia) there is no `$I`/`$R`-style sidecar and no
//! put-back extended attribute: the original location of a trashed item is
//! recorded only inside the Trash folder's `.DS_Store`, as two per-item B-tree
//! records keyed by the item's *current* name in the Trash:
//!
//! * **`ptbN`** — *Put-Back Name*: the item's original filename, and
//! * **`ptbL`** — *Put-Back Location*: the item's original parent directory,
//!
//! both of `.DS_Store` data type `ustr` (a length-prefixed UTF-16**BE** string).
//! `ptbL` is stored in the APFS firmlink form `System/Volumes/Data/…`;
//! [`PutBack::original_path`] normalises that to the user-visible `/…` while the
//! raw value stays available verbatim.
//!
//! Many legitimately trashed items have **no** put-back record (Finder writes
//! `.DS_Store` lazily, and `rm`/non-Finder deletes never write one), so the
//! absence of a record is normal, not evidence of tampering.
//!
//! # `.DS_Store` / `Bud1` format
//!
//! The container is a Finder "Desktop Services Store": a 4-byte `00 00 00 01`
//! prefix, the magic `Bud1`, then a **buddy allocator** whose table-of-contents
//! maps the key `DSDB` to a **B-tree** of records. The layout follows Wim Lewis's
//! reverse-engineered `Mac::Finder::DSStore` `DSStoreFormat.pod`
//! (<https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod>); the
//! `ptbN`/`ptbL` record types are newer Finder additions cross-checked against
//! al45tair's `ds_store` library, which also generated this crate's test fixture.
//!
//! All reads are bounds-checked: a truncated or hostile `.DS_Store` yields a
//! typed [`DsStoreError`], never a panic, and the B-tree walk is cycle-guarded.

use std::collections::{BTreeMap, HashSet};

use thiserror::Error;

/// Errors returned while parsing a `.DS_Store` put-back store.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DsStoreError {
    /// The file is shorter than the 36-byte `Bud1` header.
    #[error(".DS_Store truncated: {got} bytes, need at least {needed} for the Bud1 header")]
    TruncatedHeader {
        /// Bytes present.
        got: usize,
        /// Bytes required.
        needed: usize,
    },

    /// The leading `00 00 00 01` / `Bud1` magic is wrong. Carries the offending
    /// bytes for the investigator.
    #[error("bad .DS_Store magic: word0={word0:#010x}, magic={magic:?} (expected 1 / b\"Bud1\")")]
    BadMagic {
        /// The first 32-bit big-endian word (expected `1`).
        word0: u32,
        /// The 4 magic bytes (expected `Bud1`).
        magic: [u8; 4],
    },

    /// The two copies of the root-block offset in the header disagree — the
    /// allocator is inconsistent (Finder rejects such files).
    #[error(".DS_Store root offsets differ: {first:#x} vs {second:#x}")]
    RootOffsetMismatch {
        /// The first root-block offset.
        first: u32,
        /// The second (validation) copy.
        second: u32,
    },

    /// A block address points outside the file, or a structure overruns its
    /// block. Carries the operation for diagnosis.
    #[error(".DS_Store read out of bounds while reading {what}")]
    OutOfBounds {
        /// What was being read when the bound was exceeded.
        what: &'static str,
    },

    /// The allocator's table of contents has no `DSDB` B-tree entry.
    #[error(".DS_Store has no DSDB B-tree entry")]
    NoDsdb,

    /// A record carried a `.DS_Store` data-type code the format does not define,
    /// so the record stream cannot be safely advanced. Carries the bytes.
    #[error("unknown .DS_Store record data type {typecode:?}")]
    UnknownDataType {
        /// The offending 4-byte data-type code.
        typecode: [u8; 4],
    },
}

/// A recovered macOS put-back record: an item in the Trash together with where it
/// came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PutBack {
    /// The item's current name inside the Trash (the `.DS_Store` record key).
    /// Finder de-duplicates colliding names, so this need not equal
    /// [`original_name`](Self::original_name).
    pub trash_name: String,
    /// The original filename at deletion time (`ptbN`), if recorded.
    pub original_name: Option<String>,
    /// The original parent directory (`ptbL`) **verbatim**, in the stored
    /// firmlink form (`System/Volumes/Data/…`), if recorded.
    pub original_location: Option<String>,
}

impl PutBack {
    /// The full original path, `ptbL` + `ptbN`, with the firmlink prefix
    /// normalised to the user-visible `/…`. `None` unless both `ptbN` and `ptbL`
    /// were recorded.
    #[must_use]
    pub fn original_path(&self) -> Option<String> {
        let location = self.original_location.as_deref()?;
        let name = self.original_name.as_deref()?;
        let dir = normalize_firmlink(location);
        Some(if dir.ends_with('/') {
            format!("{dir}{name}")
        } else {
            format!("{dir}/{name}")
        })
    }
}

/// Normalise an APFS firmlink `ptbL` value (`System/Volumes/Data/…` or
/// `/System/Volumes/Data/…`) to the user-visible absolute path (`/…`). A value
/// that is not in firmlink form is returned with a single leading slash.
fn normalize_firmlink(location: &str) -> String {
    let trimmed = location.strip_prefix('/').unwrap_or(location);
    let rest = trimmed
        .strip_prefix("System/Volumes/Data/")
        .unwrap_or(trimmed);
    format!("/{rest}")
}

/// Parse the raw bytes of a Trash `.DS_Store` file and return every put-back
/// record it carries, sorted by [`trash_name`](PutBack::trash_name).
///
/// # Errors
///
/// Returns [`DsStoreError`] when the header magic is wrong, the allocator/B-tree
/// is truncated or inconsistent, or a record carries an undefined data-type code.
/// Never panics on hostile input.
pub fn parse_put_back(data: &[u8]) -> Result<Vec<PutBack>, DsStoreError> {
    /// `00 00 00 01` + `Bud1` + offset + size + offset-copy + 16 unknown.
    const HEADER_LEN: usize = 36;

    if data.len() < HEADER_LEN {
        return Err(DsStoreError::TruncatedHeader {
            got: data.len(),
            needed: HEADER_LEN,
        });
    }

    let mut head = Cursor::new(data);
    let word0 = head.u32("header word")?;
    let magic = head.array4("magic")?;
    if word0 != 1 || &magic != b"Bud1" {
        return Err(DsStoreError::BadMagic { word0, magic });
    }
    let root_offset = head.u32("root offset")?;
    let root_size = head.u32("root size")?;
    let root_offset_copy = head.u32("root offset copy")?;
    if root_offset != root_offset_copy {
        return Err(DsStoreError::RootOffsetMismatch {
            first: root_offset,
            second: root_offset_copy,
        });
    }

    // Root (allocator metadata) block: the block-address table then the table of
    // contents that names the `DSDB` B-tree.
    let root = block_slice(data, root_offset, root_size, "root block")?;
    let mut r = Cursor::new(root);
    let count = r.u32("offset count")? as usize;
    let _unknown = r.u32("offset count guard")?;
    // The on-disk table is padded up to a multiple of 256 entries; bound the
    // count by the block before allocating to defend against a hostile value.
    if count > root.len() / 4 {
        return Err(DsStoreError::OutOfBounds {
            what: "offset table count",
        });
    }
    let padded = count.div_ceil(256) * 256;
    let mut offsets = Vec::with_capacity(count);
    for i in 0..padded {
        let entry = r.u32("offset entry")?;
        if i < count {
            offsets.push(entry);
        }
    }

    let toc_count = r.u32("toc count")?;
    let mut dsdb: Option<u32> = None;
    for _ in 0..toc_count {
        let nlen = r.u8("toc name length")? as usize;
        let name = r.take(nlen, "toc name")?;
        let block_id = r.u32("toc block id")?;
        if name == b"DSDB" {
            dsdb = Some(block_id);
        }
    }
    let dsdb = dsdb.ok_or(DsStoreError::NoDsdb)?;

    // DSDB master block: root node id + tree node count.
    let master = block_by_id(data, &offsets, dsdb)?;
    let mut m = Cursor::new(master);
    let root_node = m.u32("dsdb root node")?;
    let _levels = m.u32("dsdb levels")?;
    let _records = m.u32("dsdb record count")?;
    let node_count = m.u32("dsdb node count")? as usize;

    // Walk the B-tree collecting `ptbN`/`ptbL` per item. A visited set plus a node
    // budget guard against malicious cyclic or over-long child pointers.
    let mut put_back: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut stack = vec![root_node];
    let budget = node_count.saturating_mul(2).max(1024);
    while let Some(node) = stack.pop() {
        if !visited.insert(node) {
            continue;
        }
        if visited.len() > budget {
            return Err(DsStoreError::OutOfBounds {
                what: "b-tree node budget",
            });
        }
        let block = block_by_id(data, &offsets, node)?;
        let mut c = Cursor::new(block);
        let next_node = c.u32("node next pointer")?;
        let record_count = c.u32("node record count")?;
        for _ in 0..record_count {
            // An internal node interleaves a child pointer before each record.
            if next_node != 0 {
                let child = c.u32("internal child pointer")?;
                stack.push(child);
            }
            read_record(&mut c, &mut put_back)?;
        }
        if next_node != 0 {
            stack.push(next_node);
        }
    }

    Ok(put_back
        .into_iter()
        .map(|(trash_name, (original_name, original_location))| PutBack {
            trash_name,
            original_name,
            original_location,
        })
        .collect())
}

/// A bounds-checked, big-endian cursor: every read returns a [`DsStoreError`]
/// rather than panicking when the underlying slice is too short.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DsStoreError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DsStoreError::OutOfBounds { what })?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(DsStoreError::OutOfBounds { what })?;
        self.pos = end;
        Ok(slice)
    }

    fn array4(&mut self, what: &'static str) -> Result<[u8; 4], DsStoreError> {
        let bytes = self.take(4, what)?;
        bytes
            .try_into()
            .map_err(|_| DsStoreError::OutOfBounds { what })
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, DsStoreError> {
        Ok(u32::from_be_bytes(self.array4(what)?))
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, DsStoreError> {
        Ok(self.take(1, what)?[0])
    }

    fn skip(&mut self, n: usize, what: &'static str) -> Result<(), DsStoreError> {
        self.take(n, what).map(|_| ())
    }
}

/// Slice a buddy-allocator block out of the file. Stored offsets skip the 4-byte
/// `00 00 00 01` prefix, so a stored offset `o` maps to file position `o + 4`.
fn block_slice<'a>(
    data: &'a [u8],
    offset: u32,
    size: u32,
    what: &'static str,
) -> Result<&'a [u8], DsStoreError> {
    let start = (offset as usize)
        .checked_add(4)
        .ok_or(DsStoreError::OutOfBounds { what })?;
    let end = start
        .checked_add(size as usize)
        .ok_or(DsStoreError::OutOfBounds { what })?;
    data.get(start..end)
        .ok_or(DsStoreError::OutOfBounds { what })
}

/// Look up a block by its allocator id: the offset-table entry packs the block's
/// offset in its high bits and the base-2 log of its size in its low 5 bits.
fn block_by_id<'a>(data: &'a [u8], offsets: &[u32], id: u32) -> Result<&'a [u8], DsStoreError> {
    let addr = *offsets
        .get(id as usize)
        .ok_or(DsStoreError::OutOfBounds { what: "block id" })?;
    let offset = addr & !0x1F;
    let size = 1u32 << (addr & 0x1F);
    block_slice(data, offset, size, "block")
}

/// Read one `.DS_Store` record, recording its value into `out` when it is a
/// `ptbN` (put-back name) or `ptbL` (put-back location). Every record is fully
/// consumed so the cursor lands on the next record.
fn read_record(
    c: &mut Cursor,
    out: &mut BTreeMap<String, (Option<String>, Option<String>)>,
) -> Result<(), DsStoreError> {
    let nlen = c.u32("record name length")? as usize;
    let name_bytes = c.take(2 * nlen, "record name")?;
    let filename = decode_utf16be(name_bytes);
    let code = c.array4("record code")?;
    let typecode = c.array4("record data type")?;
    let value = read_value(c, typecode)?;
    match &code {
        b"ptbN" => out.entry(filename).or_default().0 = value,
        b"ptbL" => out.entry(filename).or_default().1 = value,
        _ => {}
    }
    Ok(())
}

/// Consume a record's typed value, returning the decoded string for the
/// `ustr` type (the only type `ptbN`/`ptbL` use) and `None` for the others.
fn read_value(c: &mut Cursor, typecode: [u8; 4]) -> Result<Option<String>, DsStoreError> {
    match &typecode {
        b"bool" => c.skip(1, "bool value").map(|()| None),
        b"long" | b"shor" | b"type" => c.skip(4, "fixed value").map(|()| None),
        b"comp" | b"dutc" => c.skip(8, "8-byte value").map(|()| None),
        b"blob" => {
            let vlen = c.u32("blob length")? as usize;
            c.skip(vlen, "blob value").map(|()| None)
        }
        b"ustr" => {
            let vlen = c.u32("ustr length")? as usize;
            let bytes = c.take(2 * vlen, "ustr value")?;
            Ok(Some(decode_utf16be(bytes)))
        }
        other => Err(DsStoreError::UnknownDataType { typecode: *other }),
    }
}

/// Decode a UTF-16 big-endian byte slice, lossily replacing invalid sequences
/// with U+FFFD. A trailing odd byte is ignored.
fn decode_utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `.DS_Store` minted by al45tair's `ds_store` library (the oracle),
    /// carrying two put-back items plus one non-put-back (`Iloc` blob) record.
    const FIXTURE: &[u8] = include_bytes!("../tests/data/putback.DS_Store");

    fn get<'a>(records: &'a [PutBack], name: &str) -> &'a PutBack {
        records.iter().find(|r| r.trash_name == name).unwrap()
    }

    /// The two put-back items are recovered; the `Iloc` blob record is skipped.
    #[test]
    fn recovers_both_put_back_items() {
        let records = parse_put_back(FIXTURE).unwrap();
        assert_eq!(records.len(), 2);
    }

    /// A clean item: trash name == original name, firmlink location normalised,
    /// full original path reconstructed. Values match the oracle decode.
    #[test]
    fn clean_item_decodes_to_oracle_values() {
        let records = parse_put_back(FIXTURE).unwrap();
        let r = get(&records, "Reference Letter.png");
        assert_eq!(r.original_name.as_deref(), Some("Reference Letter.png"));
        assert_eq!(
            r.original_location.as_deref(),
            Some("System/Volumes/Data/Users/4n6h4x0r/Downloads/")
        );
        assert_eq!(
            r.original_path().as_deref(),
            Some("/Users/4n6h4x0r/Downloads/Reference Letter.png")
        );
    }

    /// A Finder-deduped item: the trash name (`report 2.pdf`) diverges from the
    /// original name (`report.pdf`) — the reader reports both faithfully.
    #[test]
    fn deduped_trash_name_diverges_from_original() {
        let records = parse_put_back(FIXTURE).unwrap();
        let r = get(&records, "report 2.pdf");
        assert_eq!(r.original_name.as_deref(), Some("report.pdf"));
        assert_eq!(
            r.original_path().as_deref(),
            Some("/Users/4n6h4x0r/Documents/report.pdf")
        );
    }

    /// Bad magic is a typed error carrying the offending bytes, not a panic.
    #[test]
    fn bad_magic_is_error() {
        let data = vec![0u8; 64];
        assert!(matches!(
            parse_put_back(&data).unwrap_err(),
            DsStoreError::BadMagic { .. }
        ));
    }

    /// A header-length-only / truncated file errors rather than panicking.
    #[test]
    fn truncated_is_error_not_panic() {
        assert!(parse_put_back(&FIXTURE[..20]).is_err());
        assert!(parse_put_back(&[]).is_err());
    }

    /// Firmlink normalisation is independent of the trailing slash and tolerates
    /// a non-firmlink absolute path.
    #[test]
    fn firmlink_normalisation() {
        assert_eq!(
            normalize_firmlink("System/Volumes/Data/Users/x/Desktop/"),
            "/Users/x/Desktop/"
        );
        assert_eq!(normalize_firmlink("/Users/x/Desktop/"), "/Users/x/Desktop/");
    }
}
