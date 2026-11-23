//! From txid to transaction number: an open-addressing hash table on disk,
//! of 8-byte slots.
//!
//! A txid's key is its SipHash-1-3, under a secret made with the store
//! ([`Keyer`]): a txid's own bytes can be chosen, by grinding, to bunch
//! keys up where they'd overrun the table. A key's home slot is `key × capacity / 2⁶⁴`, which keeps keys in order:
//! sorted by key, entries are sorted by home slot, so a table can be built in
//! one pass from sorted entries, written in order ([`TableBuilder`]), at any
//! capacity. Each slot holds the transaction number plus one (0 is empty) in
//! 40 bits and the key's low 24 bits as a fingerprint, so a lookup reads one
//! slot, nearly always, and confirms the one txid whose fingerprint matches.
//! Collisions are probed forward, into a run of overflow slots past the end
//! rather than wrapping around, and entries are removed by shifting back
//! those after them, so the table needs no tombstones.
//!
//! Slots are read and written as atomics, so readers may probe while the
//! writer inserts. Entries for transactions past the store's last commit
//! may be found, and readers ignore them.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{MmapOptions, MmapRaw};

use crate::hash::Hash;

const NUM_BITS: u32 = 40;
const NUM_MASK: u64 = (1 << NUM_BITS) - 1;
const FP_MASK: u64 = (1 << 24) - 1;
/// Slots past the last home slot, for the probes of keys homed near it.
const OVERFLOW: u64 = 4096;
/// How full a table is built.
pub const BUILD_LOAD: f64 = 0.8;
/// How full a table may get before it's rebuilt bigger.
pub const MAX_LOAD: f64 = 0.92;

/// The most times a table is built bigger because keys bunched up past
/// its end, which, with keys secret, is as good as never once.
const MAX_BUILDS: u32 = 8;

/// Makes txids' keys, under a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keyer(pub [u64; 2]);

impl Keyer {
    pub fn random() -> Keyer {
        Keyer(rand::random())
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.0[0].to_le_bytes());
        out[8..].copy_from_slice(&self.0[1].to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Keyer> {
        let bytes: [u8; 16] = bytes.try_into().ok()?;
        Some(Keyer([
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        ]))
    }

    /// The key of `txid`: SipHash-1-3 of it.
    pub fn key(&self, txid: &Hash) -> u64 {
        let words = txid.as_chunks::<8>().0.iter().map(|w| u64::from_le_bytes(*w));
        siphash(self.0, words, 32 << 56, 1, 3)
    }
}

/// SipHash-c-d of a message given as its little-endian words, then its
/// last block: the bytes left over, and its length in the top byte.
fn siphash(key: [u64; 2], words: impl Iterator<Item = u64>, last: u64, c: usize, d: usize) -> u64 {
    let mut v = [
        key[0] ^ 0x736f6d6570736575,
        key[1] ^ 0x646f72616e646f6d,
        key[0] ^ 0x6c7967656e657261,
        key[1] ^ 0x7465646279746573,
    ];
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    let compress = |v: &mut [u64; 4], m: u64| {
        v[3] ^= m;
        for _ in 0..c {
            round(v);
        }
        v[0] ^= m;
    };
    for m in words {
        compress(&mut v, m);
    }
    compress(&mut v, last);
    v[2] ^= 0xff;
    for _ in 0..d {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

fn home(key: u64, capacity: u64) -> u64 {
    ((key as u128 * capacity as u128) >> 64) as u64
}

fn slot_value(key: u64, num: u64) -> u64 {
    ((key & FP_MASK) << NUM_BITS) | (num + 1)
}

/// The table's out of room past its end, and must be rebuilt bigger.
#[derive(Debug)]
pub struct Full;

pub struct TxidTable {
    file: File,
    raw: MmapRaw,
    keyer: Keyer,
    capacity: u64,
    /// Entries in it, about: an upper bound, for deciding when to grow.
    count: AtomicU64,
}

/// The capacity of a table to be built for `entries`.
pub fn capacity_for(entries: u64) -> u64 {
    ((entries as f64 / BUILD_LOAD) as u64).max(1024)
}

impl TxidTable {
    /// Opens the table at `path`, making an empty one with room for about
    /// `entries` if it isn't there.
    pub fn open(path: &Path, entries: u64, keyer: Keyer) -> std::io::Result<TxidTable> {
        if !path.exists() {
            TableBuilder::create(path, capacity_for(entries))?.finish()?;
        }
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        if len % 8 != 0 || len / 8 <= OVERFLOW {
            return Err(std::io::Error::other(format!("{} isn't a txid table", path.display())));
        }
        let raw = MmapOptions::new().len(len as usize).map_raw(&file)?;
        Ok(TxidTable { file, raw, keyer, capacity: len / 8 - OVERFLOW, count: AtomicU64::new(0) })
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn slots(&self) -> u64 {
        self.capacity + OVERFLOW
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn set_count(&self, count: u64) {
        self.count.store(count, Ordering::Relaxed);
    }

    /// Whether it's too full to take `more` entries.
    pub fn needs_growing(&self, more: u64) -> bool {
        (self.count() + more) as f64 > self.capacity as f64 * MAX_LOAD
    }

    fn slot(&self, index: u64) -> &AtomicU64 {
        assert!(index < self.slots());
        // SAFETY: the map is page-aligned and holds `slots` 8-byte slots, so
        // each is an aligned u64 within it, accessed only atomically.
        unsafe { &*(self.raw.as_ptr().add(index as usize * 8) as *const AtomicU64) }
    }

    /// The number of the transaction with `txid`, of those for which `is`
    /// confirms it.
    pub fn find(&self, txid: &Hash, mut is: impl FnMut(u64) -> bool) -> Option<u64> {
        let key = self.keyer.key(txid);
        let fp = key & FP_MASK;
        let mut index = home(key, self.capacity);
        while index < self.slots() {
            let slot = self.slot(index).load(Ordering::Acquire);
            if slot == 0 {
                return None;
            }
            if slot >> NUM_BITS == fp
                && let Some(num) = (slot & NUM_MASK).checked_sub(1)
                && is(num)
            {
                return Some(num);
            }
            index += 1;
        }
        None
    }

    /// Adds `txid` as transaction `num`, unless `is` confirms one already
    /// there for it: then that one's number is returned, and nothing added.
    pub fn insert(&self, txid: &Hash, num: u64, mut is: impl FnMut(u64) -> bool) -> Result<Option<u64>, Full> {
        assert!(num < NUM_MASK);
        let key = self.keyer.key(txid);
        let fp = key & FP_MASK;
        let mut index = home(key, self.capacity);
        while index < self.slots() {
            let slot = self.slot(index).load(Ordering::Acquire);
            if slot == 0 {
                self.slot(index).store(slot_value(key, num), Ordering::Release);
                self.count.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            if slot >> NUM_BITS == fp
                && let Some(existing) = (slot & NUM_MASK).checked_sub(1)
                && is(existing)
            {
                return Ok(Some(existing));
            }
            index += 1;
        }
        Err(Full)
    }

    /// Points the entry for `txid` at transaction `old` to `new` instead.
    pub fn replace(&self, txid: &Hash, old: u64, new: u64) {
        let key = self.keyer.key(txid);
        let mut index = home(key, self.capacity);
        loop {
            assert!(index < self.slots(), "replacing a txid that isn't in the table");
            let slot = self.slot(index).load(Ordering::Acquire);
            assert!(slot != 0, "replacing a txid that isn't in the table");
            if slot == slot_value(key, old) {
                self.slot(index).store(slot_value(key, new), Ordering::Release);
                return;
            }
            index += 1;
        }
    }

    /// Removes the entry for `txid` as transaction `num`, if it's there.
    /// `txid_of_num` gives each other entry's txid, to tell where it
    /// belongs.
    pub fn remove(&self, txid: &Hash, num: u64, mut txid_of_num: impl FnMut(u64) -> Hash) -> bool {
        let key = self.keyer.key(txid);
        let want = slot_value(key, num);
        let mut hole = home(key, self.capacity);
        loop {
            if hole >= self.slots() {
                return false;
            }
            let slot = self.slot(hole).load(Ordering::Acquire);
            if slot == 0 {
                return false;
            }
            if slot == want {
                break;
            }
            hole += 1;
        }
        // Shift back every entry after the hole whose home is at or before it.
        let mut at = hole + 1;
        while at < self.slots() {
            let slot = self.slot(at).load(Ordering::Acquire);
            if slot == 0 {
                break;
            }
            let Some(other) = (slot & NUM_MASK).checked_sub(1) else { break };
            if home(self.keyer.key(&txid_of_num(other)), self.capacity) <= hole {
                self.slot(hole).store(slot, Ordering::Release);
                hole = at;
            }
            at += 1;
        }
        self.slot(hole).store(0, Ordering::Release);
        self.count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    pub fn keyer(&self) -> Keyer {
        self.keyer
    }

    /// Waits until every change is on disk.
    pub fn sync(&self) -> std::io::Result<()> {
        self.raw.flush()?;
        self.file.sync_data()
    }
}

/// Writes a table in one pass, from entries in order of key.
pub struct TableBuilder {
    out: BufWriter<File>,
    capacity: u64,
    /// The next slot to write.
    next: u64,
    count: u64,
}

impl TableBuilder {
    pub fn create(path: &Path, capacity: u64) -> std::io::Result<TableBuilder> {
        let file = File::create(path)?;
        Ok(TableBuilder { out: BufWriter::with_capacity(1 << 20, file), capacity, next: 0, count: 0 })
    }

    /// Adds an entry; keys must come in order.
    /// Whether it's been built bigger as often as it may.
    pub fn max_builds() -> u32 {
        MAX_BUILDS
    }

    pub fn push(&mut self, key: u64, num: u64) -> Result<(), Full> {
        let at = home(key, self.capacity).max(self.next);
        if at >= self.capacity + OVERFLOW {
            return Err(Full);
        }
        self.zeros(at - self.next).map_err(|_| Full)?;
        self.out.write_all(&slot_value(key, num).to_le_bytes()).map_err(|_| Full)?;
        self.next = at + 1;
        self.count += 1;
        Ok(())
    }

    fn zeros(&mut self, mut n: u64) -> std::io::Result<()> {
        const ZEROS: [u8; 4096] = [0; 4096];
        while n > 0 {
            let chunk = n.min(512);
            self.out.write_all(&ZEROS[..chunk as usize * 8])?;
            n -= chunk;
        }
        Ok(())
    }

    /// Fills the rest with empty slots and syncs it. Returns the entries
    /// written.
    pub fn finish(mut self) -> std::io::Result<u64> {
        self.zeros(self.capacity + OVERFLOW - self.next)?;
        let file = self.out.into_inner().map_err(|err| err.into_error())?;
        file.sync_all()?;
        Ok(self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bitdexter-txt-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const KEYER: Keyer = Keyer([0x0706050403020100, 0x0f0e0d0c0b0a0908]);

    #[test]
    fn siphash_as_specified() {
        // SipHash-2-4's test vector, from its paper: key 00..0f, message
        // 00..0e; the 7 bytes past the first word, and the length, are the
        // last block.
        let key = [0x0706050403020100, 0x0f0e0d0c0b0a0908];
        let message: Vec<u8> = (0u8..15).collect();
        let first = u64::from_le_bytes(message[..8].try_into().unwrap());
        let mut tail = [0u8; 8];
        tail[..7].copy_from_slice(&message[8..]);
        let last = u64::from_le_bytes(tail) | (15 << 56);
        assert_eq!(siphash(key, [first].into_iter(), last, 2, 4), 0xa129ca6149be45e5);
        // Keys depend on the secret.
        let txid = sha256(b"txid");
        assert_ne!(KEYER.key(&txid), Keyer([1, 2]).key(&txid));
    }

    #[test]
    fn insert_find_remove() {
        let dir = tmp("ifr");
        let path = dir.join("t");
        // A small table, so probing and shifting back happen a lot.
        let table = TxidTable::open(&path, 700, KEYER).unwrap();
        let txids: Vec<Hash> = (0u32..800).map(|i| sha256(&i.to_le_bytes())).collect();
        for (n, txid) in txids.iter().enumerate() {
            assert_eq!(table.insert(txid, n as u64, |m| txids[m as usize] == *txid).unwrap(), None);
        }
        assert_eq!(table.insert(&txids[5], 999, |m| txids[m as usize] == txids[5]).unwrap(), Some(5));
        for (n, txid) in txids.iter().enumerate() {
            assert_eq!(table.find(txid, |m| txids[m as usize] == *txid), Some(n as u64));
        }
        for n in (0..800).step_by(2) {
            assert!(table.remove(&txids[n], n as u64, |m| txids[m as usize]));
        }
        for (n, txid) in txids.iter().enumerate() {
            let found = table.find(txid, |m| txids[m as usize] == *txid);
            assert_eq!(found, (n % 2 == 1).then_some(n as u64), "{n}");
        }
        table.replace(&txids[1], 1, 3);
        assert_eq!(table.find(&txids[1], |m| m == 3), Some(3));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn built_table_finds_everything() {
        let dir = tmp("build");
        let path = dir.join("t");
        let txids: Vec<Hash> = (0u32..10_000).map(|i| sha256(&i.to_le_bytes())).collect();
        let mut sorted: Vec<(u64, u64)> = txids.iter().enumerate().map(|(n, t)| (KEYER.key(t), n as u64)).collect();
        sorted.sort_unstable();
        let mut builder = TableBuilder::create(&path, capacity_for(10_000)).unwrap();
        for (key, num) in sorted {
            builder.push(key, num).unwrap();
        }
        assert_eq!(builder.finish().unwrap(), 10_000);
        let table = TxidTable::open(&path, 0, KEYER).unwrap();
        for (n, txid) in txids.iter().enumerate() {
            assert_eq!(table.find(txid, |m| txids[m as usize] == *txid), Some(n as u64));
        }
        // And it takes inserts and removals as one built by inserting does.
        let extra = sha256(b"extra");
        assert_eq!(table.insert(&extra, 10_000, |_| false).unwrap(), None);
        assert_eq!(table.find(&extra, |m| m == 10_000), Some(10_000));
        let all: Vec<Hash> = txids.iter().copied().chain([extra]).collect();
        assert!(table.remove(&txids[3], 3, |m| all[m as usize]));
        for (n, txid) in all.iter().enumerate().filter(|(n, _)| *n != 3) {
            assert_eq!(table.find(txid, |m| all[m as usize] == *txid), Some(n as u64));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
