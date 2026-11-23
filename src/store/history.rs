//! The history index as built in bulk: for each script key, the numbers of
//! the outputs paying it, in a file written once and only read.
//!
//! Keys are split by their leading bits into buckets of a few hundred
//! entries, and a directory gives where each bucket starts. Within a bucket,
//! entries are grouped by key, in order:
//!
//! ```text
//! group = key delta:varint count:varint first output:varint (output delta:varint)*
//! ```
//!
//! where the key delta is from the previous group's key in the bucket (the
//! first from the bucket's lowest key), and output numbers rise within a
//! group. A script paid once costs its key's gap, about 5 bytes on mainnet,
//! a count and an output number; each further output, a few bytes more.
//!
//! The file holds history up to some depth below the tip; what's newer is in
//! LMDB, where it can be undone by a reorg, until it's next merged in.
//!
//! ```text
//! file = "BDXHIST1" bucket_bits:u32 0:u32 entries:u64 directory data
//! directory = (2^bucket_bits + 1) × offset:u64, into data
//! ```

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use memmap2::Mmap;

use crate::compact::{Reader, write_varint};

const MAGIC: &[u8; 8] = b"BDXHIST1";
const HEADER: usize = 24;
/// Entries a bucket holds, on average.
const BUCKET_ENTRIES: u64 = 256;

fn bucket_bits_for(entries: u64) -> u32 {
    (entries / BUCKET_ENTRIES).max(1).ilog2().clamp(4, 30)
}

pub struct StaticHistory {
    map: Option<Mmap>,
    bits: u32,
    entries: u64,
}

impl StaticHistory {
    pub fn empty() -> StaticHistory {
        StaticHistory { map: None, bits: 4, entries: 0 }
    }

    /// The history at `path`, or an empty one if there's none.
    pub fn open(path: &Path) -> std::io::Result<StaticHistory> {
        if !path.exists() {
            return Ok(StaticHistory::empty());
        }
        let file = File::open(path)?;
        // SAFETY: the file is only ever replaced, by renaming another over
        // it, never changed in place.
        let map = unsafe { Mmap::map(&file)? };
        if map.len() < HEADER || &map[..8] != MAGIC {
            return Err(std::io::Error::other(format!("{} isn't a history index", path.display())));
        }
        let bits = u32::from_le_bytes(map[8..12].try_into().unwrap());
        let entries = u64::from_le_bytes(map[16..24].try_into().unwrap());
        let corrupt = || std::io::Error::other(format!("{} is corrupt", path.display()));
        if !(1..=30).contains(&bits) || map.len() < HEADER + ((1usize << bits) + 1) * 8 {
            return Err(corrupt());
        }
        // Each bucket's start, at or after the one before, and within the file.
        let data = HEADER + ((1usize << bits) + 1) * 8;
        let mut last = 0;
        for at in (HEADER..data).step_by(8) {
            let offset = u64::from_le_bytes(map[at..at + 8].try_into().unwrap());
            if offset < last || offset > (map.len() - data) as u64 {
                return Err(corrupt());
            }
            last = offset;
        }
        Ok(StaticHistory { map: Some(map), bits, entries })
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }

    pub fn size(&self) -> u64 {
        self.map.as_ref().map_or(0, |m| m.len() as u64)
    }

    fn buckets(&self) -> u64 {
        1 << self.bits
    }

    fn bucket_of(&self, key: u64) -> u64 {
        key >> (64 - self.bits)
    }

    fn bucket_bytes(&self, bucket: u64) -> &[u8] {
        let Some(map) = &self.map else { return &[] };
        let dir = |n: u64| {
            let at = HEADER + n as usize * 8;
            u64::from_le_bytes(map[at..at + 8].try_into().unwrap()) as usize
        };
        let data = HEADER + (self.buckets() as usize + 1) * 8;
        &map[data + dir(bucket)..data + dir(bucket + 1)]
    }

    /// Calls `f` with each group of a bucket: its key and output numbers.
    fn decode_bucket(&self, bucket: u64, mut f: impl FnMut(u64, &[u64]) -> bool) {
        let base = bucket << (64 - self.bits);
        let mut r = Reader::new(self.bucket_bytes(bucket));
        let mut key = base;
        let mut first = true;
        let mut outs = Vec::new();
        while !r.is_empty() {
            let (Ok(delta), Ok(count)) = (r.varint(), r.varint()) else { return };
            key = if first { base.wrapping_add(delta) } else { key.wrapping_add(delta) };
            first = false;
            outs.clear();
            let mut out = 0u64;
            for i in 0..count {
                let Ok(n) = r.varint() else { return };
                out = if i == 0 { n } else { out.wrapping_add(n) };
                outs.push(out);
            }
            if !f(key, &outs) {
                return;
            }
        }
    }

    /// The numbers of the outputs paying the script with `key`.
    pub fn lookup(&self, key: u64) -> Vec<u64> {
        let mut found = Vec::new();
        if self.map.is_some() {
            self.decode_bucket(self.bucket_of(key), |k, outs| {
                if k == key {
                    found.extend_from_slice(outs);
                }
                k <= key
            });
        }
        found
    }

    /// Every entry, in order of key and output number.
    pub fn iter(&self) -> Iter<'_> {
        Iter { history: self, bucket: 0, buf: Vec::new(), pos: 0 }
    }
}

pub struct Iter<'a> {
    history: &'a StaticHistory,
    bucket: u64,
    buf: Vec<(u64, u64)>,
    pos: usize,
}

impl Iter<'_> {
    /// The next entry without taking it.
    pub fn peek(&mut self) -> Option<(u64, u64)> {
        while self.pos == self.buf.len() {
            if self.history.map.is_none() || self.bucket >= self.history.buckets() {
                return None;
            }
            self.buf.clear();
            self.pos = 0;
            let buf = &mut self.buf;
            self.history.decode_bucket(self.bucket, |key, outs| {
                buf.extend(outs.iter().map(|&out| (key, out)));
                true
            });
            self.bucket += 1;
        }
        Some(self.buf[self.pos])
    }
}

impl Iterator for Iter<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        let next = self.peek()?;
        self.pos += 1;
        Some(next)
    }
}

/// Writes a history index from entries in order of key and output number.
pub struct Builder {
    file: BufWriter<File>,
    bits: u32,
    offsets: Vec<u64>,
    written: u64,
    bucket: u64,
    /// The group being gathered: its key and output numbers.
    key: Option<u64>,
    outs: Vec<u64>,
    prev_key: Option<u64>,
    entries: u64,
    buf: Vec<u8>,
}

impl Builder {
    /// A builder for about `entries` entries.
    pub fn create(path: &Path, entries: u64) -> std::io::Result<Builder> {
        let bits = bucket_bits_for(entries);
        let mut file = BufWriter::with_capacity(1 << 20, File::create(path)?);
        file.write_all(MAGIC)?;
        file.write_all(&bits.to_le_bytes())?;
        file.write_all(&[0; 12])?;
        // The directory, filled in at the end.
        file.seek(SeekFrom::Start((HEADER + ((1usize << bits) + 1) * 8) as u64))?;
        Ok(Builder {
            file,
            bits,
            offsets: vec![0],
            written: 0,
            bucket: 0,
            key: None,
            outs: Vec::new(),
            prev_key: None,
            entries: 0,
            buf: Vec::new(),
        })
    }

    /// Adds an entry. Entries must come in order of key and output number;
    /// one the same as the last is skipped.
    pub fn push(&mut self, key: u64, out: u64) -> std::io::Result<()> {
        if self.key == Some(key) {
            match self.outs.last() {
                Some(&last) if out == last => return Ok(()),
                Some(&last) => debug_assert!(out > last, "outputs out of order"),
                None => {}
            }
            self.outs.push(out);
            return Ok(());
        }
        debug_assert!(self.key.is_none_or(|k| key > k), "keys out of order");
        self.write_group()?;
        self.key = Some(key);
        self.outs.push(out);
        Ok(())
    }

    fn write_group(&mut self) -> std::io::Result<()> {
        let Some(key) = self.key.take() else { return Ok(()) };
        let bucket = key >> (64 - self.bits);
        while self.bucket < bucket {
            self.bucket += 1;
            self.offsets.push(self.written);
            self.prev_key = None;
        }
        let base = bucket << (64 - self.bits);
        self.buf.clear();
        write_varint(&mut self.buf, key - self.prev_key.unwrap_or(base));
        write_varint(&mut self.buf, self.outs.len() as u64);
        let mut prev = 0;
        for (i, &out) in self.outs.iter().enumerate() {
            write_varint(&mut self.buf, if i == 0 { out } else { out - prev });
            prev = out;
        }
        self.file.write_all(&self.buf)?;
        self.written += self.buf.len() as u64;
        self.entries += self.outs.len() as u64;
        self.prev_key = Some(key);
        self.outs.clear();
        Ok(())
    }

    /// Writes the directory and syncs the file. Returns the entries written.
    pub fn finish(mut self) -> std::io::Result<u64> {
        self.write_group()?;
        let buckets = 1u64 << self.bits;
        while (self.offsets.len() as u64) < buckets + 1 {
            self.offsets.push(self.written);
        }
        let file = self.file.into_inner().map_err(|err| err.into_error())?;
        let mut directory = Vec::with_capacity(self.offsets.len() * 8);
        for offset in &self.offsets {
            directory.extend_from_slice(&offset.to_le_bytes());
        }
        file.write_all_at(&directory, HEADER as u64)?;
        file.write_all_at(&self.entries.to_le_bytes(), 16)?;
        file.sync_all()?;
        Ok(self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[test]
    fn builds_and_reads() {
        let dir = std::env::temp_dir().join(format!("bitdexter-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h");
        let mut entries: Vec<(u64, u64)> = Vec::new();
        for i in 0u64..20_000 {
            let key = u64::from_le_bytes(sha256(&(i % 7000).to_le_bytes())[..8].try_into().unwrap());
            entries.push((key, i * 3));
        }
        // Keys at the very ends.
        entries.push((0, 5));
        entries.push((u64::MAX, 6));
        entries.push((u64::MAX, 7));
        entries.sort_unstable();
        let mut builder = Builder::create(&path, entries.len() as u64).unwrap();
        for &(key, out) in &entries {
            builder.push(key, out).unwrap();
            builder.push(key, out).unwrap();
        }
        assert_eq!(builder.finish().unwrap(), entries.len() as u64);
        let history = StaticHistory::open(&path).unwrap();
        assert_eq!(history.entries(), entries.len() as u64);
        assert_eq!(history.iter().collect::<Vec<_>>(), entries);
        for &(key, _) in entries.iter().step_by(97) {
            let want: Vec<u64> = entries.iter().filter(|e| e.0 == key).map(|e| e.1).collect();
            assert_eq!(history.lookup(key), want);
        }
        assert_eq!(history.lookup(u64::MAX), vec![6, 7]);
        assert_eq!(history.lookup(0), vec![5]);
        assert!(history.lookup(12345).is_empty());
        assert!(StaticHistory::open(&dir.join("none")).unwrap().lookup(1).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
