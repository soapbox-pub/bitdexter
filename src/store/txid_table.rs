//! From txid to transaction number: an open-addressing hash table on disk,
//! of 8-byte slots.
//!
//! A txid is already uniformly random, so its first 8 bytes are the hash: the
//! low bits pick the slot, and 24 high bits are kept in it as a fingerprint
//! beside the transaction number (plus one, so that 0 is empty), in 40 bits.
//! A fingerprint that matches is confirmed against the txid column, so a
//! lookup reads one slot, nearly always, and one txid. Collisions are probed
//! linearly, and entries removed by shifting back those after them, so the
//! table needs no tombstones.
//!
//! Slots are read and written as atomics, so readers may probe while the
//! writer inserts. Entries for transactions past the store's last commit
//! may be found, and readers ignore them.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{MmapOptions, MmapRaw};

use crate::hash::Hash;

const NUM_BITS: u32 = 40;
const NUM_MASK: u64 = (1 << NUM_BITS) - 1;

pub fn key_of(txid: &Hash) -> u64 {
    u64::from_le_bytes(txid[..8].try_into().unwrap())
}

fn fingerprint(key: u64) -> u64 {
    key >> NUM_BITS
}

pub struct TxidTable {
    file: File,
    raw: MmapRaw,
    mask: u64,
    /// Entries in it, about: an upper bound, for deciding when to grow.
    count: AtomicU64,
}

impl TxidTable {
    /// Opens the table at `path`, making it with `capacity` slots (a power of
    /// two) if it isn't there.
    pub fn open(path: &Path, capacity: u64) -> std::io::Result<TxidTable> {
        assert!(capacity.is_power_of_two());
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut len = file.metadata()?.len();
        if len == 0 {
            len = capacity * 8;
            file.set_len(len)?;
        }
        let slots = len / 8;
        if len % 8 != 0 || !slots.is_power_of_two() {
            return Err(std::io::Error::other(format!("{} isn't a txid table", path.display())));
        }
        let raw = MmapOptions::new().len(len as usize).map_raw(&file)?;
        Ok(TxidTable { file, raw, mask: slots - 1, count: AtomicU64::new(0) })
    }

    pub fn capacity(&self) -> u64 {
        self.mask + 1
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn set_count(&self, count: u64) {
        self.count.store(count, Ordering::Relaxed);
    }

    fn slot(&self, index: u64) -> &AtomicU64 {
        debug_assert!(index <= self.mask);
        // SAFETY: the map is page-aligned and holds capacity 8-byte slots, so
        // each is an aligned u64 within it, accessed only atomically.
        unsafe { &*(self.raw.as_ptr().add(index as usize * 8) as *const AtomicU64) }
    }

    /// The number of the transaction with `txid`, of those for which `is`
    /// confirms it.
    pub fn find(&self, txid: &Hash, mut is: impl FnMut(u64) -> bool) -> Option<u64> {
        let key = key_of(txid);
        let fp = fingerprint(key);
        let mut index = key & self.mask;
        loop {
            let slot = self.slot(index).load(Ordering::Acquire);
            if slot == 0 {
                return None;
            }
            if fingerprint(slot) == fp {
                let num = (slot & NUM_MASK) - 1;
                if is(num) {
                    return Some(num);
                }
            }
            index = (index + 1) & self.mask;
        }
    }

    /// Adds `txid` as transaction `num`, unless `is` confirms one already
    /// there for it: then that one's number is returned, and nothing added.
    pub fn insert(&self, txid: &Hash, num: u64, mut is: impl FnMut(u64) -> bool) -> Option<u64> {
        assert!(num < NUM_MASK);
        let key = key_of(txid);
        let fp = fingerprint(key);
        let mut index = key & self.mask;
        loop {
            let slot = self.slot(index).load(Ordering::Acquire);
            if slot == 0 {
                self.slot(index).store((fp << NUM_BITS) | (num + 1), Ordering::Release);
                self.count.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if fingerprint(slot) == fp {
                let existing = (slot & NUM_MASK) - 1;
                if is(existing) {
                    return Some(existing);
                }
            }
            index = (index + 1) & self.mask;
        }
    }

    /// Points the entry for `txid` at transaction `old` to `new` instead.
    pub fn replace(&self, txid: &Hash, old: u64, new: u64) {
        let key = key_of(txid);
        let fp = fingerprint(key);
        let mut index = key & self.mask;
        loop {
            let slot = self.slot(index).load(Ordering::Acquire);
            assert!(slot != 0, "replacing a txid that isn't in the table");
            if slot == (fp << NUM_BITS) | (old + 1) {
                self.slot(index).store((fp << NUM_BITS) | (new + 1), Ordering::Release);
                return;
            }
            index = (index + 1) & self.mask;
        }
    }

    /// Removes the entry for `txid` as transaction `num`, if it's there.
    /// `key_of_num` gives the [`key_of`] each other entry's txid, to tell
    /// where it belongs.
    pub fn remove(&self, txid: &Hash, num: u64, mut key_of_num: impl FnMut(u64) -> u64) -> bool {
        let key = key_of(txid);
        let want = (fingerprint(key) << NUM_BITS) | (num + 1);
        let mut hole = key & self.mask;
        loop {
            let slot = self.slot(hole).load(Ordering::Acquire);
            if slot == 0 {
                return false;
            }
            if slot == want {
                break;
            }
            hole = (hole + 1) & self.mask;
        }
        // Shift back every entry after the hole that may move into it: those
        // whose home isn't cyclically within (hole, at].
        let mut at = hole;
        loop {
            at = (at + 1) & self.mask;
            let slot = self.slot(at).load(Ordering::Acquire);
            if slot == 0 {
                break;
            }
            let home = key_of_num((slot & NUM_MASK) - 1) & self.mask;
            let stays = if hole <= at { hole < home && home <= at } else { hole < home || home <= at };
            if !stays {
                self.slot(hole).store(slot, Ordering::Release);
                hole = at;
            }
        }
        self.slot(hole).store(0, Ordering::Release);
        self.count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Waits until every change is on disk.
    pub fn sync(&self) -> std::io::Result<()> {
        self.raw.flush()?;
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[test]
    fn insert_find_remove() {
        let dir = std::env::temp_dir().join(format!("bitdexter-txt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t");
        // A tiny table, so probing and shifting back happen a lot.
        let table = TxidTable::open(&path, 1 << 10).unwrap();
        let txids: Vec<Hash> = (0u32..700).map(|i| sha256(&i.to_le_bytes())).collect();
        // Force collisions: many share their low bits.
        let txids: Vec<Hash> = txids
            .into_iter()
            .enumerate()
            .map(|(i, mut t)| {
                if i % 3 == 0 {
                    t[0] = 7;
                    t[1] &= 0xfc;
                }
                t
            })
            .collect();
        for (n, txid) in txids.iter().enumerate() {
            assert_eq!(table.insert(txid, n as u64, |m| txids[m as usize] == *txid), None);
        }
        assert_eq!(table.insert(&txids[5], 999, |m| txids[m as usize] == txids[5]), Some(5));
        for (n, txid) in txids.iter().enumerate() {
            assert_eq!(table.find(txid, |m| txids[m as usize] == *txid), Some(n as u64));
        }
        for n in (0..700).step_by(2) {
            assert!(table.remove(&txids[n], n as u64, |m| key_of(&txids[m as usize])));
        }
        for (n, txid) in txids.iter().enumerate() {
            let found = table.find(txid, |m| txids[m as usize] == *txid);
            assert_eq!(found, (n % 2 == 1).then_some(n as u64), "{n}");
        }
        table.replace(&txids[1], 1, 3);
        assert_eq!(table.find(&txids[1], |_| true), Some(3));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
