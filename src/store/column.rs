//! A file of fixed-width records, numbered from 0, appended to in order.
//!
//! Records are read through a memory map that reserves far more address
//! space than the file holds, so it never needs remapping as the file
//! grows; only what's been written is ever read. The writer appends to a
//! buffer it writes out with [`ColumnWriter::flush`], and may change a
//! record in place, through the map, as a spend marks an output.
//!
//! Columns are read at random, a record or a transaction at a time, so the
//! map is advised so: the kernel reads only the page a read faults in, not
//! the hundred kilobytes or more around it it would otherwise. Reading
//! scripts to verify a block's inputs, on mainnet, that's the difference
//! between reading a gigabyte from disk a block and a few megabytes. Scans
//! in order read ahead a window at a time with [`ReadAhead`].
//!
//! Readers are bounded by the counts of the store's last commit, so they
//! never read past what's in the file. A column is shortened (on a reorg)
//! only in the count the writer keeps: the file itself is cut only when the
//! store is opened, before any reader can hold the map, as cutting a mapped
//! file under a reader would fault it.

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use memmap2::{MmapOptions, MmapRaw};

/// The address space reserved for each column's map: 4 TiB, more than any
/// will hold, and costing nothing until it's touched.
const RESERVE: usize = 1 << 42;

pub struct Map {
    raw: MmapRaw,
    width: usize,
}

impl Map {
    fn ptr(&self, offset: u64) -> *mut u8 {
        // SAFETY: offsets are bounded by the reservation by callers, who only
        // read what's been written.
        unsafe { self.raw.as_mut_ptr().add(offset as usize) }
    }

    /// The bytes at `offset`, which must have been written.
    pub fn slice(&self, offset: u64, len: usize) -> &[u8] {
        assert!(offset as usize + len <= RESERVE);
        // SAFETY: the range is within the map, and within the file, as
        // callers only read below the counts committed (see the module docs).
        unsafe { std::slice::from_raw_parts(self.ptr(offset), len) }
    }

    pub fn record(&self, index: u64) -> &[u8] {
        self.slice(index * self.width as u64, self.width)
    }

    /// Advises the kernel that a range will be read in order soon. It's
    /// asked a piece at a time: Linux reads no more of one request than the
    /// device's read-ahead, a few megabytes, and drops the rest.
    pub fn will_need(&self, offset: u64, len: usize) {
        const PIECE: u64 = 2 << 20;
        let page = 4096u64;
        let mut at = offset / page * page;
        let end = offset + len as u64;
        while at < end {
            let piece = PIECE.min(end - at);
            // SAFETY: madvise only advises; the range is within the reservation.
            unsafe {
                libc::madvise(self.ptr(at) as *mut libc::c_void, piece as usize, libc::MADV_WILLNEED);
            }
            at += piece;
        }
    }
}

/// How far ahead a scan in order asks for its column to be read.
const WINDOW: u64 = 64 << 20;

/// Reads a column ahead of a scan in order, a window at a time, so the
/// scan's faults find their pages read already. Asking for a whole column
/// at once would read more than memory holds on mainnet, evicting each page
/// before the scan got to it.
pub struct ReadAhead {
    map: Arc<Map>,
    /// The end of what's been asked for, and of the scan, in bytes.
    asked: u64,
    end: u64,
}

impl ReadAhead {
    /// Notes that the scan has reached record `index`.
    pub fn at(&mut self, index: u64) {
        let offset = index * self.map.width as u64;
        if self.asked < self.end && offset + WINDOW / 2 >= self.asked {
            let len = WINDOW.min(self.end - self.asked);
            self.map.will_need(self.asked, len as usize);
            self.asked += len;
        }
    }
}

/// Read access to a column, shared by every reader.
#[derive(Clone)]
pub struct Column(pub Arc<Map>);

impl Column {
    pub fn record(&self, index: u64) -> &[u8] {
        self.0.record(index)
    }

    pub fn slice(&self, offset: u64, len: usize) -> &[u8] {
        self.0.slice(offset, len)
    }
}

pub struct ColumnWriter {
    file: File,
    map: Arc<Map>,
    width: usize,
    /// How many records are in the file.
    flushed: u64,
    /// Records appended since, not yet written.
    pending: Vec<u8>,
}

impl ColumnWriter {
    /// Opens or makes the column at `path`, cutting it to `len` records.
    pub fn open(path: &Path, width: usize, len: u64) -> std::io::Result<(ColumnWriter, Column)> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let on_disk = file.metadata()?.len();
        let want = len * width as u64;
        if on_disk < want {
            return Err(std::io::Error::other(format!(
                "{} holds {on_disk} bytes, fewer than the {want} the store committed",
                path.display()
            )));
        }
        if on_disk > want {
            file.set_len(want)?;
        }
        let raw = MmapOptions::new().len(RESERVE).map_raw(&file)?;
        // SAFETY: madvise only advises; the range is the whole map.
        unsafe {
            libc::madvise(raw.as_mut_ptr() as *mut libc::c_void, RESERVE, libc::MADV_RANDOM);
        }
        let map = Arc::new(Map { raw, width });
        let writer = ColumnWriter { file, map: map.clone(), width, flushed: len, pending: Vec::new() };
        Ok((writer, Column(map)))
    }

    pub fn len(&self) -> u64 {
        self.flushed + (self.pending.len() / self.width) as u64
    }

    pub fn push(&mut self, record: &[u8]) {
        debug_assert_eq!(record.len() % self.width, 0);
        self.pending.extend_from_slice(record);
    }

    pub fn get(&self, index: u64) -> &[u8] {
        if index < self.flushed {
            self.map.record(index)
        } else {
            let at = (index - self.flushed) as usize * self.width;
            &self.pending[at..at + self.width]
        }
    }

    /// `len` bytes from byte `offset`, wherever they are.
    pub fn range(&self, offset: u64, len: usize) -> Cow<'_, [u8]> {
        let flushed = self.flushed * self.width as u64;
        let end = offset + len as u64;
        if end <= flushed {
            Cow::Borrowed(self.map.slice(offset, len))
        } else if offset >= flushed {
            let at = (offset - flushed) as usize;
            Cow::Borrowed(&self.pending[at..at + len])
        } else {
            let head = self.map.slice(offset, (flushed - offset) as usize);
            let tail = &self.pending[..(end - flushed) as usize];
            Cow::Owned([head, tail].concat())
        }
    }

    /// Overwrites part of a record, from byte `at` within it.
    pub fn set(&mut self, index: u64, at: usize, bytes: &[u8]) {
        assert!(at + bytes.len() <= self.width);
        if index < self.flushed {
            let offset = index * self.width as u64 + at as u64;
            // SAFETY: the record is in the file and within the map; readers
            // of it bound what they believe by the committed counts.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.map.ptr(offset), bytes.len()) }
        } else {
            let start = (index - self.flushed) as usize * self.width + at;
            self.pending[start..start + bytes.len()].copy_from_slice(bytes);
        }
    }

    /// Forgets every record from `len` on. The file keeps them until the
    /// next write over them, or until it's next opened.
    pub fn truncate(&mut self, len: u64) {
        if len <= self.flushed {
            self.flushed = len;
            self.pending.clear();
        } else {
            self.pending.truncate((len - self.flushed) as usize * self.width);
        }
    }

    /// Writes out what's been appended.
    pub fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            self.file.write_all_at(&self.pending, self.flushed * self.width as u64)?;
            self.flushed += (self.pending.len() / self.width) as u64;
            self.pending.clear();
        }
        Ok(())
    }

    /// Flushes, then waits until the file, changes made through the map
    /// too, is on disk.
    pub fn sync(&mut self) -> std::io::Result<()> {
        self.flush()?;
        self.file.sync_data()
    }

    pub fn map(&self) -> &Map {
        &self.map
    }

    /// Read-ahead for a scan of records `from..to`, in order.
    pub fn read_ahead(&self, from: u64, to: u64) -> ReadAhead {
        let width = self.width as u64;
        ReadAhead { map: self.map.clone(), asked: from * width, end: to.min(self.flushed) * width }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_set_truncate_reopen() {
        let dir = std::env::temp_dir().join(format!("bitdexter-col-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c");
        let (mut w, r) = ColumnWriter::open(&path, 4, 0).unwrap();
        for i in 0u32..10 {
            w.push(&i.to_le_bytes());
        }
        assert_eq!(w.get(3), &3u32.to_le_bytes());
        w.flush().unwrap();
        assert_eq!(r.record(9), &9u32.to_le_bytes());
        w.push(&10u32.to_le_bytes());
        w.set(2, 0, &[0xff, 0xff]);
        w.set(10, 2, &[0xee]);
        assert_eq!(w.get(2), &[0xff, 0xff, 0, 0]);
        assert_eq!(w.get(10), &[10, 0, 0xee, 0]);
        w.truncate(5);
        assert_eq!(w.len(), 5);
        w.push(&50u32.to_le_bytes());
        w.sync().unwrap();
        assert_eq!(r.record(5), &50u32.to_le_bytes());
        drop((w, r));
        let (w, r) = ColumnWriter::open(&path, 4, 6).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 24);
        assert_eq!(r.record(2), &[0xff, 0xff, 0, 0]);
        assert_eq!(w.range(4, 8).as_ref(), &[1, 0, 0, 0, 0xff, 0xff, 0, 0][..]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
