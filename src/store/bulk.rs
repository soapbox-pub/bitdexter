//! Indexing in bulk, far behind the tip, appending and nothing more.
//!
//! The columns are appended to as ever, and so are two logs: `spends.log`,
//! of each input's spent output and spending transaction (10 bytes), and
//! `history.log`, of each spendable output's script key and number (13
//! bytes). Inputs are found without the txid table, in a map in memory of
//! the transactions that have outputs left to spend: from the first 8 bytes
//! of their txid to their number and how many are left. Which outputs are
//! spent is a bitmap, a bit an output, with those that can never be spent
//! set from the start. On mainnet, the map holds about a hundred million
//! transactions, a couple of gigabytes, and the bitmap a few hundred
//! megabytes. Both are rebuilt from the columns and logs when the store's
//! opened.
//!
//! Two transactions in the map can share their first 8 bytes. Then the
//! entry is marked ambiguous, and both are kept, by their whole txid, in a
//! second map. A txid looked up isn't checked against the txid column: in
//! a valid chain, every input spends a transaction that's in the map.
//!
//! Once caught up, [`Writer::finish_bulk`] merges the logs in, with
//! sequential passes: spends are split by output number into ranges of
//! `outs` and marked a range at a time; the txid table is built from the
//! txid column sorted by key; and the history log, sorted by key, is merged
//! with the history file into a new one. Each step can be run again if it's
//! interrupted, so the state stays `Finalizing` until they're all done.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;

use super::checks::Checks;
use super::column::ColumnWriter;
use super::history::{Builder, StaticHistory};
use super::sort::{Partitions, read_u40, u40};
use super::txid_table::{self, TableBuilder, key_of};
use super::writer::Writer;
use super::*;
use crate::block::Block;
use crate::validate::MAX_MONEY;

const SPEND_RECORD: usize = 10;
const HISTORY_RECORD: usize = 13;
/// Marks an entry in the map whose transactions are in the ambiguous map.
const AMBIGUOUS: u64 = u64::MAX;
const COUNT_BITS: u32 = 24;
/// Outputs whose spends are marked at a time, as `finish_bulk` applies
/// them: 64 million, a range of 768 MB of `outs`.
const SPEND_RANGE: u64 = 64 << 20;

/// Txids are random already: their first 8 bytes are the hash.
#[derive(Default)]
pub struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ b as u64;
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

type IdMap = HashMap<u64, u64, BuildHasherDefault<IdHasher>>;

fn entry(txnum: u64, left: u64) -> u64 {
    (txnum << COUNT_BITS) | left
}

/// A file of fixed-size records, appended to.
pub struct Log {
    out: BufWriter<File>,
    record: usize,
    len: u64,
}

impl Log {
    fn open(path: &Path, record: usize, len: u64) -> Result<Log> {
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let want = len * record as u64;
        let on_disk = file.metadata()?.len();
        anyhow::ensure!(on_disk >= want, "{} is shorter than the store committed", path.display());
        file.set_len(want)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Log { out: BufWriter::with_capacity(1 << 20, file), record, len })
    }

    fn push(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        debug_assert_eq!(bytes.len(), self.record);
        self.len += 1;
        self.out.write_all(bytes)
    }

    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.out.flush()?;
        let file = self.out.get_mut();
        file.set_len(len * self.record as u64)?;
        file.seek(SeekFrom::End(0))?;
        self.len = len;
        Ok(())
    }

    fn sync(&mut self) -> std::io::Result<u64> {
        self.out.flush()?;
        self.out.get_ref().sync_data()?;
        Ok(self.len)
    }
}

/// Reads a log's records, `record` bytes each, in order.
fn read_log(path: &Path, record: usize, len: u64, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut buf = vec![0u8; record * 4096];
    let mut left = len;
    while left > 0 {
        let n = left.min(4096) as usize;
        reader.read_exact(&mut buf[..n * record])?;
        for chunk in buf[..n * record].chunks_exact(record) {
            f(chunk)?;
        }
        left -= n as u64;
    }
    Ok(())
}

pub struct Bulk {
    live: IdMap,
    ambiguous: HashMap<Hash, u64>,
    /// A bit an output, set if it's spent or can't be.
    spent: Vec<u64>,
    spends: Log,
    history: Log,
}

impl Bulk {
    fn is_spent(&self, outnum: u64) -> bool {
        self.spent.get((outnum / 64) as usize).is_some_and(|word| word & (1 << (outnum % 64)) != 0)
    }

    fn word(&mut self, outnum: u64) -> &mut u64 {
        let word = (outnum / 64) as usize;
        if word >= self.spent.len() {
            self.spent.resize(word + 1, 0);
        }
        &mut self.spent[word]
    }

    fn set_spent(&mut self, outnum: u64) {
        *self.word(outnum) |= 1 << (outnum % 64);
    }

    fn unset_spent(&mut self, outnum: u64) {
        *self.word(outnum) &= !(1 << (outnum % 64));
    }

    /// The map's entry for `txid`.
    fn find(&self, txid: &Hash) -> Option<u64> {
        match self.live.get(&key_of(txid)) {
            Some(&AMBIGUOUS) => self.ambiguous.get(txid).copied(),
            other => other.copied(),
        }
    }

    /// Sets the entry for `txid`, or removes it with `None`.
    fn set(&mut self, txid: &Hash, value: Option<u64>) {
        let key = key_of(txid);
        if self.live.get(&key) == Some(&AMBIGUOUS) {
            match value {
                Some(value) => self.ambiguous.insert(*txid, value),
                None => self.ambiguous.remove(txid),
            };
        } else {
            match value {
                Some(value) => self.live.insert(key, value),
                None => self.live.remove(&key),
            };
        }
    }

    /// Adds `txid`, whose key may already be another's, as `other`'s.
    fn add(&mut self, txid: &Hash, value: u64, other: Option<(Hash, u64)>) {
        let key = key_of(txid);
        match other {
            Some((other_txid, other_value)) => {
                self.live.insert(key, AMBIGUOUS);
                self.ambiguous.insert(other_txid, other_value);
                self.ambiguous.insert(*txid, value);
            }
            None if self.live.get(&key) == Some(&AMBIGUOUS) => {
                self.ambiguous.insert(*txid, value);
            }
            None => {
                self.live.insert(key, value);
            }
        }
    }

    pub fn sync_logs(&mut self) -> std::io::Result<(u64, u64)> {
        Ok((self.spends.sync()?, self.history.sync()?))
    }

    /// The map and bitmap, from the columns and logs, which the writer has
    /// cut to the committed state.
    pub fn load(writer: &mut Writer) -> Result<Bulk> {
        let started = Instant::now();
        let counts = writer.counts();
        let state = writer.state;
        let spends = Log::open(&writer.paths.file("spends.log"), SPEND_RECORD, state.spends_logged)?;
        let history = Log::open(&writer.paths.file("history.log"), HISTORY_RECORD, state.history_logged)?;
        let mut bulk = Bulk {
            live: IdMap::default(),
            ambiguous: HashMap::new(),
            spent: vec![0; counts.outs.div_ceil(64) as usize],
            spends,
            history,
        };
        writer.outs.map().will_need(0, (counts.outs * OUT_WIDTH as u64) as usize);
        for outnum in 0..counts.outs {
            let out = decode_out(writer.outs.get(outnum));
            if !out.spendable || out.spent.is_some() {
                bulk.set_spent(outnum);
            }
        }
        read_log(&writer.paths.file("spends.log"), SPEND_RECORD, state.spends_logged, |record| {
            bulk.set_spent(read_u40(record));
            Ok(())
        })?;
        writer.txids.map().will_need(0, (counts.txs * 32) as usize);
        writer.txidx.map().will_need(0, (counts.txs * TXIDX_WIDTH as u64) as usize);
        // The genesis block's coinbase was never spendable.
        for txnum in 1..counts.txs {
            let (first, next) = writer.outputs_of(txnum);
            let left = (first..next).filter(|&outnum| !bulk.is_spent(outnum)).count() as u64;
            if left > 0 {
                let txid: Hash = writer.txids.get(txnum).try_into().unwrap();
                let other = bulk.other_with_key(writer, &txid);
                bulk.add(&txid, entry(txnum, left), other);
            }
        }
        tracing::info!(
            "loaded {} transactions with outputs left to spend, of {}, in {:.1?}",
            bulk.live.len() + bulk.ambiguous.len(),
            counts.txs,
            started.elapsed()
        );
        Ok(bulk)
    }

    /// Another transaction in the map whose txid shares `txid`'s key but
    /// isn't it, and its entry.
    fn other_with_key(&self, writer: &Writer, txid: &Hash) -> Option<(Hash, u64)> {
        let &value = self.live.get(&key_of(txid))?;
        if value == AMBIGUOUS {
            return None;
        }
        let other: Hash = writer.txids.get(value >> COUNT_BITS).try_into().unwrap();
        (other != *txid).then_some((other, value))
    }
}

impl Writer {
    /// Starts indexing in bulk, with what's indexed so far committed.
    pub fn begin_bulk(&mut self) -> Result<()> {
        if self.bulk.is_some() {
            return Ok(());
        }
        self.commit()?;
        tracing::info!("indexing in bulk from block {}", self.next_height());
        self.state.mode = Mode::Bulk;
        self.state.bulk_start = self.counts();
        self.state.spends_logged = 0;
        self.state.history_logged = 0;
        self.write_state()?;
        self.bulk = Some(Bulk::load(self)?);
        self.publish();
        Ok(())
    }

    /// Indexes a block in bulk, returning its fees. If it turns out to be
    /// invalid, what it appended is cut off and the map rebuilt.
    pub(super) fn connect_bulk(
        &mut self,
        block: &Block<'_>,
        height: u32,
        verify: bool,
    ) -> std::result::Result<u64, ConnectError> {
        let before = self.counts();
        let bulk = self.bulk.as_ref().unwrap();
        let logged = (bulk.spends.len, bulk.history.len);
        let result = self.connect_txs_bulk(block, height, verify);
        if result.is_err() {
            self.truncate_columns(before);
            let bulk = self.bulk.as_mut().unwrap();
            bulk.spends.truncate(logged.0)?;
            bulk.history.truncate(logged.1)?;
            self.sync_columns()?;
            self.state.spends_logged = logged.0;
            self.state.history_logged = logged.1;
            self.bulk = None;
            self.bulk = Some(Bulk::load(self)?);
        }
        result
    }

    fn connect_txs_bulk<'b>(
        &mut self,
        block: &Block<'b>,
        height: u32,
        verify: bool,
    ) -> std::result::Result<u64, ConnectError> {
        let block_first_tx = self.txids.len();
        let mut checks = Checks::new(self, block, height, verify);
        let mut fees = 0u64;
        let mut spent = Vec::new();
        let mut encoded = Vec::with_capacity(512);
        for tx in &block.txs {
            let txnum = self.txids.len();
            spent.clear();
            let mut value_in = 0u64;
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let bulk = self.bulk.as_ref().unwrap();
                    let Some(value) = bulk.find(&input.prev_txid) else {
                        return reject("bad-txns-inputs-missingorspent");
                    };
                    let prev = value >> COUNT_BITS;
                    let (first, next) = self.outputs_of(prev);
                    let outnum = first + input.prev_vout as u64;
                    if outnum >= next || bulk.is_spent(outnum) {
                        return reject("bad-txns-inputs-missingorspent");
                    }
                    if self.immature_coinbase(prev, height, block_first_tx) {
                        return reject("bad-txns-premature-spend-of-coinbase");
                    }
                    let out = decode_out(self.outs.get(outnum));
                    let script = checks
                        .wants_scripts()
                        .then(|| self.prevout_script(block, block_first_tx, prev, input.prev_vout));
                    checks.input(self.height_of_tx(prev, height, block_first_tx), out.class, out.value, script);
                    let bulk = self.bulk.as_mut().unwrap();
                    bulk.set_spent(outnum);
                    let left = (value & ((1 << COUNT_BITS) - 1)) - 1;
                    bulk.set(&input.prev_txid, (left > 0).then(|| entry(prev, left)));
                    let mut record = [0u8; SPEND_RECORD];
                    record[..5].copy_from_slice(&u40(outnum));
                    record[5..].copy_from_slice(&u40(txnum));
                    bulk.spends.push(&record)?;
                    spent.push(outnum);
                    value_in += out.value;
                    if value_in > MAX_MONEY {
                        return reject("bad-txns-inputvalues-outofrange");
                    }
                }
            }
            let value_out: u64 = tx.outputs.iter().map(|out| out.value).sum();
            if !tx.is_coinbase() {
                if value_in < value_out {
                    return reject("bad-txns-in-belowout");
                }
                fees += value_in - value_out;
            }
            checks.tx(self, tx)?;
            let first_out = self.outs.len();
            let left = self.append_tx(tx, &spent, &mut encoded);
            let bulk = self.bulk.as_mut().unwrap();
            for (vout, out) in tx.outputs.iter().enumerate() {
                let outnum = first_out + vout as u64;
                if is_spendable(out.script) {
                    bulk.unset_spent(outnum);
                } else {
                    bulk.set_spent(outnum);
                }
            }
            for &(key, outnum) in &self.tx_history {
                let mut record = [0u8; HISTORY_RECORD];
                record[..8].copy_from_slice(&key);
                record[8..].copy_from_slice(&u40(outnum));
                bulk.history.push(&record)?;
            }
            self.add_live(&tx.txid, txnum, left, height)?;
        }
        if block.txs[0].outputs.iter().map(|out| out.value).sum::<u64>() > self.store.chain.subsidy(height) + fees {
            return reject("bad-cb-amount");
        }
        checks.finish(block)?;
        Ok(fees)
    }

    /// Adds a transaction to the map, checking BIP30: one with the same
    /// txid may be there only if it has nothing left to spend, or in one of
    /// the two blocks Bitcoin Core lets break that rule, whose new
    /// transaction leaves the old one's outputs unspendable.
    fn add_live(&mut self, txid: &Hash, txnum: u64, left: u64, height: u32) -> std::result::Result<(), ConnectError> {
        let bulk = self.bulk.as_ref().unwrap();
        if let Some(old) = bulk.find(txid) {
            let old_num = old >> COUNT_BITS;
            let old_txid: Hash = self.txids.get(old_num).try_into().unwrap();
            if old_txid == *txid {
                if !self.store.chain.bip30_exceptions().contains(&height) {
                    return reject("bad-txns-BIP30");
                }
                let (first, next) = self.outputs_of(old_num);
                let bulk = self.bulk.as_mut().unwrap();
                for outnum in first..next {
                    bulk.set_spent(outnum);
                }
                bulk.set(txid, (left > 0).then(|| entry(txnum, left)));
                return Ok(());
            }
        }
        if left > 0 {
            let other = self.bulk.as_ref().unwrap().other_with_key(self, txid);
            self.bulk.as_mut().unwrap().add(txid, entry(txnum, left), other);
        }
        Ok(())
    }

    /// Merges the logs in, and goes on indexing in place. Readers see
    /// everything indexed once it's done.
    pub fn finish_bulk(&mut self) -> Result<()> {
        if self.bulk.is_some() {
            self.commit()?;
            self.state.mode = Mode::Finalizing;
            self.write_state()?;
            // The map and bitmap aren't needed, and take memory.
            self.bulk = None;
        }
        let started = Instant::now();
        let counts = self.state.counts;
        tracing::info!("merging what was indexed in bulk, to block {}", counts.blocks.saturating_sub(1));
        std::fs::create_dir_all(self.paths.sort_dir())?;

        self.apply_spends()?;
        tracing::info!("marked spent outputs, {:.1?} in", started.elapsed());

        let table = self.store.table();
        let new = counts.txs - self.state.bulk_start.txs;
        if self.state.bulk_start.txs == 0 || new > counts.txs / 20 || table.needs_growing(new) {
            self.rebuild_table(counts.txs)?;
        } else {
            self.insert_txids(self.state.bulk_start.txs, counts.txs)?;
        }
        tracing::info!("indexed txids, {:.1?} in", started.elapsed());

        self.merge_history()?;
        let _ = std::fs::remove_dir_all(self.paths.sort_dir());
        tracing::info!("merged the history index; done in {:.1?}", started.elapsed());
        self.publish();
        Ok(())
    }

    /// Marks the outputs the spend log says were spent, a range of `outs`
    /// at a time.
    fn apply_spends(&mut self) -> Result<()> {
        let outs = self.state.counts.outs;
        let ranges = outs.div_ceil(SPEND_RANGE).max(1) as usize;
        let mut parts = Partitions::create(&self.paths.sort_dir(), "spends", ranges, SPEND_RECORD)?;
        read_log(&self.paths.file("spends.log"), SPEND_RECORD, self.state.spends_logged, |record| {
            parts.push((read_u40(record) / SPEND_RANGE) as usize, record)?;
            Ok(())
        })?;
        let parts = parts.finish()?;
        for n in 0..parts.len() {
            let mut records: Vec<(u64, u64)> =
                parts.take(n)?.chunks_exact(SPEND_RECORD).map(|r| (read_u40(r), read_u40(&r[5..]))).collect();
            records.sort_unstable();
            for (outnum, txnum) in records {
                self.outs.set(outnum, VALUE_BYTES, &spent_bytes(txnum));
            }
        }
        self.outs.sync()?;
        Ok(())
    }

    /// Adds transactions `from..to` to the txid table in place.
    fn insert_txids(&mut self, from: u64, to: u64) -> Result<()> {
        let table = self.store.table();
        for txnum in from..to {
            let txid: Hash = self.txids.get(txnum).try_into().unwrap();
            match table.insert(&txid, txnum, |num| self.txids.get(num) == txid) {
                Ok(None) => {}
                // Indexed already, by a merge that was interrupted.
                Ok(Some(old)) if old == txnum => {}
                // An earlier transaction with this txid: BIP30 was checked.
                Ok(Some(old)) => table.replace(&txid, old, txnum),
                Err(_) => return self.rebuild_table(to),
            }
        }
        table.sync()?;
        table.set_count(to);
        Ok(())
    }

    /// Merges the history log, and LMDB's entries, into a new history file,
    /// all but the newest blocks', which go to LMDB, where a reorg can take
    /// them out. Then commits the state, indexing in place.
    fn merge_history(&mut self) -> Result<()> {
        let counts = self.state.counts;
        let safe_blocks = counts.blocks.saturating_sub(REORG_DEPTH);
        let safe_outs = if safe_blocks < counts.blocks {
            self.block(safe_blocks).first_out.max(self.state.static_outs)
        } else {
            counts.outs
        };
        let env = &self.store.env;
        let db = self.store.history;

        // LMDB's entries: the old enough are merged into the file.
        let mut stale = Vec::new();
        let mut parts = Partitions::create(&self.paths.sort_dir(), "history", 256, HISTORY_RECORD)?;
        {
            let txn = env.read_txn()?;
            txn.for_each(db, |key, value| {
                let outnum = outnum_from_value(value);
                if outnum < safe_outs {
                    let key: [u8; 8] = key.try_into().unwrap();
                    stale.push((key, outnum_value(outnum)));
                    let mut record = [0u8; HISTORY_RECORD];
                    record[..8].copy_from_slice(&key);
                    record[8..].copy_from_slice(&u40(outnum));
                    parts.push(key[0] as usize, &record)?;
                }
                Ok(())
            })?;
        }
        // The log's: the old enough are merged into the file, the rest go to
        // LMDB.
        let mut recent = Vec::new();
        read_log(&self.paths.file("history.log"), HISTORY_RECORD, self.state.history_logged, |record| {
            let outnum = read_u40(&record[8..]);
            if outnum < safe_outs {
                parts.push(record[0] as usize, record)?;
            } else {
                recent.push((<[u8; 8]>::try_from(&record[..8]).unwrap(), outnum_value(outnum)));
            }
            Ok(())
        })?;
        let parts = parts.finish()?;

        let old = self.store.static_history();
        let new_path = self.paths.file("history.new");
        let mut builder = Builder::create(&new_path, old.entries() + parts.total())?;
        let mut from_old = old.iter();
        for n in 0..parts.len() {
            let mut records: Vec<(u64, u64)> = parts
                .take(n)?
                .chunks_exact(HISTORY_RECORD)
                .map(|r| (u64::from_be_bytes(r[..8].try_into().unwrap()), read_u40(&r[8..])))
                .collect();
            records.sort_unstable();
            let mut records = records.into_iter().peekable();
            loop {
                let mine = records.peek().copied();
                let theirs = from_old.peek().filter(|&(key, _)| (key >> 56) as usize == n);
                let next = match (mine, theirs) {
                    (Some(a), Some(b)) if b < a => from_old.next(),
                    (Some(_), _) => records.next(),
                    (None, Some(_)) => from_old.next(),
                    (None, None) => break,
                };
                let (key, outnum) = next.unwrap();
                builder.push(key, outnum)?;
            }
        }
        let entries = builder.finish()?;
        std::fs::rename(&new_path, self.paths.history())?;
        let history = StaticHistory::open(&self.paths.history())?;
        *self.store.static_history.write().unwrap() = Arc::new(history);
        tracing::info!("the history index holds {entries} entries");

        recent.sort_unstable();
        let mut txn = env.write_txn()?;
        for (key, value) in &stale {
            txn.del(db, key, Some(value))?;
        }
        for (key, value) in &recent {
            txn.put(db, key, value, true)?;
        }
        self.state.mode = Mode::Tip;
        self.state.published = counts;
        self.state.static_outs = safe_outs;
        self.state.spends_logged = 0;
        self.state.history_logged = 0;
        self.state.dirty = false;
        txn.put(self.store.meta, b"state", &self.state.encode(), false)?;
        txn.commit()?;
        for log in ["spends.log", "history.log"] {
            let _ = std::fs::remove_file(self.paths.file(log));
        }
        Ok(())
    }
}

/// Builds a txid table at `path` for the first `count` transactions in
/// `txids`, by sorting their keys.
pub fn build_table(txids: &ColumnWriter, count: u64, path: &Path, sort_dir: &Path) -> Result<()> {
    let mut capacity = txid_table::capacity_for(count);
    // Keys bunched up near the end can overrun the overflow slots, as good
    // as never: then it's built again, bigger.
    while !try_build_table(txids, count, path, sort_dir, capacity)? {
        capacity += capacity / 4;
    }
    Ok(())
}

fn try_build_table(txids: &ColumnWriter, count: u64, path: &Path, sort_dir: &Path, capacity: u64) -> Result<bool> {
    txids.map().will_need(0, (count * 32) as usize);
    let mut parts = Partitions::create(sort_dir, "txids", 256, 13)?;
    for txnum in 0..count {
        let txid: Hash = txids.get(txnum).try_into().unwrap();
        let key = key_of(&txid);
        let mut record = [0u8; 13];
        record[..8].copy_from_slice(&key.to_le_bytes());
        record[8..].copy_from_slice(&u40(txnum));
        parts.push((key >> 56) as usize, &record)?;
    }
    let parts = parts.finish()?;
    let mut builder = TableBuilder::create(path, capacity)?;
    for n in 0..parts.len() {
        let mut records: Vec<(u64, u64)> = parts
            .take(n)?
            .chunks_exact(13)
            .map(|r| (u64::from_le_bytes(r[..8].try_into().unwrap()), read_u40(&r[8..])))
            .collect();
        records.sort_unstable();
        for (i, &(key, num)) in records.iter().enumerate() {
            // Of transactions with the same txid (BIP30's exceptions), only
            // the last is kept.
            let txid = txids.get(num);
            let replaced =
                records[i + 1..].iter().take_while(|r| r.0 == key).any(|&(_, later)| txids.get(later) == txid);
            if !replaced && builder.push(key, num).is_err() {
                return Ok(false);
            }
        }
    }
    builder.finish()?;
    Ok(true)
}
