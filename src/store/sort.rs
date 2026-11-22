//! Sorting more than fits in memory: fixed-size records are spilled to a
//! file per partition, by a key's leading bits or a range of numbers, and
//! each partition read back and sorted on its own.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub struct Partitions {
    paths: Vec<PathBuf>,
    files: Vec<BufWriter<File>>,
    record: usize,
    counts: Vec<u64>,
}

impl Partitions {
    /// `count` partition files of `record`-byte records in `dir`, named
    /// after `name`.
    pub fn create(dir: &Path, name: &str, count: usize, record: usize) -> std::io::Result<Partitions> {
        std::fs::create_dir_all(dir)?;
        let mut paths = Vec::with_capacity(count);
        let mut files = Vec::with_capacity(count);
        for n in 0..count {
            let path = dir.join(format!("{name}.{n}"));
            files.push(BufWriter::with_capacity(256 << 10, File::create(&path)?));
            paths.push(path);
        }
        Ok(Partitions { paths, files, record, counts: vec![0; count] })
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn push(&mut self, partition: usize, record: &[u8]) -> std::io::Result<()> {
        debug_assert_eq!(record.len(), self.record);
        self.counts[partition] += 1;
        self.files[partition].write_all(record)
    }

    /// Flushes every partition, to be read back.
    pub fn finish(self) -> std::io::Result<Spilled> {
        for file in self.files {
            file.into_inner().map_err(|err| err.into_error())?;
        }
        Ok(Spilled { paths: self.paths, record: self.record, counts: self.counts })
    }
}

pub struct Spilled {
    paths: Vec<PathBuf>,
    record: usize,
    counts: Vec<u64>,
}

impl Spilled {
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Partition `n`'s records, packed; its file is removed.
    pub fn take(&self, n: usize) -> std::io::Result<Vec<u8>> {
        let bytes = std::fs::read(&self.paths[n])?;
        std::fs::remove_file(&self.paths[n])?;
        debug_assert_eq!(bytes.len() % self.record, 0);
        Ok(bytes)
    }
}

impl Drop for Spilled {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn read_u40(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..5].copy_from_slice(&bytes[..5]);
    u64::from_le_bytes(buf)
}

pub fn u40(n: u64) -> [u8; 5] {
    debug_assert!(n < 1 << 40);
    n.to_le_bytes()[..5].try_into().unwrap()
}
