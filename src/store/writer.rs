//! The store's one writer: indexing blocks in place, near the tip,
//! committing, and taking blocks off again in a reorg. Indexing in bulk is
//! in [`super::bulk`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};

use super::bulk::Bulk;
use super::checks::Checks;
use super::column::ColumnWriter;
use super::history::StaticHistory;
use super::txid_table::{TxidTable, key_of};
use super::*;
use crate::block::{Block, Tx};
use crate::validate::{COINBASE_MATURITY, MAX_MONEY};

pub struct Writer {
    pub store: Arc<Store>,
    pub(super) paths: Paths,
    pub(super) blocks: ColumnWriter,
    pub(super) txids: ColumnWriter,
    pub(super) txidx: ColumnWriter,
    pub(super) outs: ColumnWriter,
    pub(super) data: ColumnWriter,
    pub(super) state: State,
    pub(super) bulk: Option<Bulk>,
    /// History entries to add to LMDB at the next commit, indexing in place.
    history: Vec<([u8; 8], [u8; 5])>,
    /// History entries of the transaction being indexed.
    pub(super) tx_history: Vec<([u8; 8], u64)>,
    /// What's been indexed since the last commit.
    pub(super) uncommitted: u32,
    last_commit: Instant,
    /// Whether the txid table was rebuilt while indexing the block.
    rebuilt_in_block: bool,
}

impl Writer {
    pub fn open(dir: &Path, chain: Chain) -> Result<Writer> {
        std::fs::create_dir_all(dir.join("index")).with_context(|| format!("making {}", dir.display()))?;
        let paths = Paths { dir: dir.to_path_buf() };
        let env = lmdb::Env::open(&dir.join("index"), 1 << 40, 4)?;
        let history = env.create_db("history", true)?;
        let meta = env.create_db("meta", false)?;
        let state = {
            let txn = env.read_txn()?;
            match txn.get(meta, b"state")? {
                Some(bytes) => State::decode(bytes)?,
                None => State::default(),
            }
        };
        let counts = state.counts;
        let open = |name: &str, width: usize, len: u64| {
            ColumnWriter::open(&dir.join(name), width, len).with_context(|| format!("opening {name}"))
        };
        let (blocks_w, blocks) = open("blocks", BLOCK_WIDTH, counts.blocks as u64)?;
        let (txids_w, txids) = open("txids", 32, counts.txs)?;
        let (txidx_w, txidx) = open("txidx", TXIDX_WIDTH, counts.txs)?;
        let (outs_w, outs) = open("outs", OUT_WIDTH, counts.outs)?;
        let (data_w, data) = open("txdata", 1, counts.data)?;
        let table = TxidTable::open(&paths.table(), 0)?;
        table.set_count(state.published.txs);
        let static_history = StaticHistory::open(&paths.history())?;

        let mut first_txs = Vec::with_capacity(counts.blocks as usize);
        let mut heights = HashMap::with_capacity(counts.blocks as usize);
        for height in 0..counts.blocks {
            let record = BlockRecord::decode(blocks.record(height as u64));
            first_txs.push(record.first_tx);
            heights.insert(record.hash(), height);
        }

        let store = Arc::new(Store {
            chain,
            blocks,
            txids,
            txidx,
            outs,
            data,
            table: RwLock::new(Arc::new(table)),
            static_history: RwLock::new(Arc::new(static_history)),
            env,
            history,
            meta,
            snapshot: RwLock::new(state.published),
            syncing: AtomicBool::new(state.mode != Mode::Tip),
            first_txs: RwLock::new(first_txs),
            heights: RwLock::new(heights),
        });
        let mut writer = Writer {
            store,
            paths,
            blocks: blocks_w,
            txids: txids_w,
            txidx: txidx_w,
            outs: outs_w,
            data: data_w,
            state,
            bulk: None,
            history: Vec::new(),
            tx_history: Vec::new(),
            uncommitted: 0,
            last_commit: Instant::now(),
            rebuilt_in_block: false,
        };
        match state.mode {
            Mode::Tip if state.dirty => writer.recover()?,
            Mode::Tip => {}
            Mode::Bulk => writer.bulk = Some(Bulk::load(&mut writer)?),
            Mode::Finalizing => writer.finish_bulk()?,
        }
        Ok(writer)
    }

    pub fn next_height(&self) -> u32 {
        self.blocks.len() as u32
    }

    pub fn block(&self, height: u32) -> BlockRecord {
        BlockRecord::decode(self.blocks.get(height as u64))
    }

    /// The hash of the last block indexed, committed or not.
    pub fn tip_hash(&self) -> Option<Hash> {
        let next = self.next_height();
        (next > 0).then(|| self.block(next - 1).hash())
    }

    pub fn in_bulk(&self) -> bool {
        self.bulk.is_some()
    }

    pub(super) fn counts(&self) -> Snapshot {
        Snapshot {
            blocks: self.blocks.len() as u32,
            txs: self.txids.len(),
            outs: self.outs.len(),
            data: self.data.len(),
        }
    }

    pub(super) fn write_state(&self) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        txn.put(self.store.meta, b"state", &self.state.encode(), false)?;
        txn.commit()?;
        Ok(())
    }

    pub(super) fn publish(&self) {
        *self.store.snapshot.write().unwrap() = self.state.published;
        self.store.syncing.store(self.state.mode != Mode::Tip, Ordering::Relaxed);
    }

    /// Marks the state dirty before the first change in place since the
    /// last commit.
    fn mark_dirty(&mut self) -> Result<()> {
        if !self.state.dirty {
            self.state.dirty = true;
            self.write_state()?;
        }
        Ok(())
    }

    fn txnum_of(&self, txid: &Hash) -> Option<u64> {
        self.store.table().find(txid, |num| self.txids.get(num) == txid)
    }

    /// Whether transaction `txnum`, in a block before the one at `height`
    /// whose first transaction is `block_first_tx`, or in that block, is a
    /// coinbase too young to spend.
    pub(super) fn immature_coinbase(&self, txnum: u64, height: u32, block_first_tx: u64) -> bool {
        if txnum >= block_first_tx {
            return txnum == block_first_tx;
        }
        let first_txs = self.store.first_txs.read().unwrap();
        let prev_height = first_txs.partition_point(|&first| first <= txnum) - 1;
        first_txs[prev_height] == txnum && height - (prev_height as u32) < COINBASE_MATURITY
    }

    /// The range of output numbers of transaction `txnum`.
    pub(super) fn outputs_of(&self, txnum: u64) -> (u64, u64) {
        let (_, first) = decode_txidx(self.txidx.get(txnum));
        let next =
            if txnum + 1 < self.txidx.len() { decode_txidx(self.txidx.get(txnum + 1)).1 } else { self.outs.len() };
        (first, next)
    }

    /// The median time past of block `height`: the median of its time and
    /// the ten before.
    pub(super) fn mtp(&self, height: u32) -> u32 {
        let mut times: Vec<u32> = (height.saturating_sub(10)..=height).map(|h| self.block(h).time()).collect();
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// The height of the block holding transaction `txnum`, which is in the
    /// block at `height` being connected if it's from `block_first_tx` on.
    pub(super) fn height_of_tx(&self, txnum: u64, height: u32, block_first_tx: u64) -> u32 {
        if txnum >= block_first_tx {
            return height;
        }
        let first_txs = self.store.first_txs.read().unwrap();
        (first_txs.partition_point(|&first| first <= txnum) - 1) as u32
    }

    /// The script of output `vout` of transaction `txnum`, which is in
    /// `block` if it's from `block_first_tx` on.
    pub(super) fn prevout_script(&self, block: &Block<'_>, block_first_tx: u64, txnum: u64, vout: u32) -> Vec<u8> {
        if txnum >= block_first_tx {
            return block.txs[(txnum - block_first_tx) as usize].outputs[vout as usize].script.to_vec();
        }
        let (start, first_out) = decode_txidx(self.txidx.get(txnum));
        let end = decode_txidx(self.txidx.get(txnum + 1)).0;
        let bytes = self.data.range(start, (end - start) as usize);
        let tx = compact::decode(&bytes, first_out).expect("a stored transaction");
        tx.outputs.into_iter().nth(vout as usize).expect("an output that exists").script
    }

    /// Indexes `block` as the next, after checking what can be checked only
    /// with the outputs it spends, scripts too if `verify`. The block itself
    /// must already have passed [`crate::validate::check_block`].
    pub fn connect(&mut self, block: &Block<'_>, verify: bool) -> std::result::Result<(), ConnectError> {
        let height = self.next_height();
        let expected_prev = self.tip_hash().unwrap_or([0; 32]);
        if block.prev_hash() != expected_prev {
            return reject("prev-blk-not-tip");
        }
        let before = self.counts();
        let fees = if self.bulk.is_some() {
            self.connect_bulk(block, height, verify)?
        } else {
            self.connect_in_place(block, height, verify)?
        };
        let record = BlockRecord {
            header: *block.header,
            first_tx: before.txs,
            first_out: before.outs,
            size: block.size() as u32,
            weight: block.weight() as u32,
            fees,
        };
        self.blocks.push(&record.encode());
        self.flush_columns()?;
        self.store.first_txs.write().unwrap().push(before.txs);
        self.store.heights.write().unwrap().insert(block.hash(), height);
        self.uncommitted += 1;
        Ok(())
    }

    fn flush_columns(&mut self) -> std::io::Result<()> {
        for column in [&mut self.blocks, &mut self.txids, &mut self.txidx, &mut self.outs, &mut self.data] {
            column.flush()?;
        }
        Ok(())
    }

    pub(super) fn sync_columns(&mut self) -> std::io::Result<()> {
        for column in [&mut self.blocks, &mut self.txids, &mut self.txidx, &mut self.outs, &mut self.data] {
            column.sync()?;
        }
        Ok(())
    }

    /// Forgets everything appended past `counts`.
    pub(super) fn truncate_columns(&mut self, counts: Snapshot) {
        self.blocks.truncate(counts.blocks as u64);
        self.txids.truncate(counts.txs);
        self.txidx.truncate(counts.txs);
        self.outs.truncate(counts.outs);
        self.data.truncate(counts.data);
    }

    /// Appends a transaction to the columns, given the outputs its inputs
    /// spend, and gathers its history entries in `tx_history`. Returns how
    /// many of its outputs can be spent.
    pub(super) fn append_tx(&mut self, tx: &Tx<'_>, spent: &[u64], encoded: &mut Vec<u8>) -> u64 {
        let first_out = self.outs.len();
        let mut spendable = 0;
        self.tx_history.clear();
        for (vout, out) in tx.outputs.iter().enumerate() {
            let can = is_spendable(out.script);
            self.outs.push(&out_record(out.value, out.script));
            if can {
                spendable += 1;
                self.tx_history.push((script_key(out.script), first_out + vout as u64));
            }
        }
        encoded.clear();
        compact::encode(tx, first_out, spent, encoded);
        self.txidx.push(&txidx_record(self.data.len(), first_out));
        self.data.push(encoded);
        self.txids.push(&tx.txid);
        spendable
    }

    fn connect_in_place(
        &mut self,
        block: &Block<'_>,
        height: u32,
        verify: bool,
    ) -> std::result::Result<u64, ConnectError> {
        self.mark_dirty()?;
        let table = self.store.table();
        if table.needs_growing(block.txs.len() as u64) {
            let count = self.txids.len() + block.txs.len() as u64;
            self.rebuild_table(count)?;
        }
        let before = self.counts();
        let history_before = self.history.len();
        let mut spent_now = Vec::new();
        let mut inserted = Vec::new();
        self.rebuilt_in_block = false;
        let result = self.connect_txs_in_place(block, height, verify, &mut spent_now, &mut inserted);
        if result.is_err() {
            // Undo what the block changed in place, then forget the rest.
            for &outnum in &spent_now {
                self.outs.set(outnum, VALUE_BYTES, &[0; 5]);
            }
            let table = self.store.table();
            if !self.rebuilt_in_block {
                for &(txid, txnum, replaced) in inserted.iter().rev() {
                    match replaced {
                        Some(old) => table.replace(&txid, txnum, old),
                        None => {
                            table.remove(&txid, txnum, |num| key_of(self.txids.get(num).try_into().unwrap()));
                        }
                    }
                }
            }
            self.truncate_columns(before);
            self.history.truncate(history_before);
            if self.rebuilt_in_block {
                self.rebuild_table(before.txs)?;
            }
        }
        result
    }

    /// Indexes the block's transactions in place, returning their fees.
    fn connect_txs_in_place<'b>(
        &mut self,
        block: &Block<'b>,
        height: u32,
        verify: bool,
        spent_now: &mut Vec<u64>,
        inserted: &mut Vec<(Hash, u64, Option<u64>)>,
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
                    let Some(prev) = self.txnum_of(&input.prev_txid) else {
                        return reject("bad-txns-inputs-missingorspent");
                    };
                    let (first, next) = self.outputs_of(prev);
                    let outnum = first + input.prev_vout as u64;
                    if prev == 0 || outnum >= next {
                        return reject("bad-txns-inputs-missingorspent");
                    }
                    let out = decode_out(self.outs.get(outnum));
                    if out.spent.is_some() || !out.spendable {
                        return reject("bad-txns-inputs-missingorspent");
                    }
                    if self.immature_coinbase(prev, height, block_first_tx) {
                        return reject("bad-txns-premature-spend-of-coinbase");
                    }
                    let script = checks
                        .wants_scripts()
                        .then(|| self.prevout_script(block, block_first_tx, prev, input.prev_vout));
                    checks.input(self.height_of_tx(prev, height, block_first_tx), out.class, out.value, script);
                    self.outs.set(outnum, VALUE_BYTES, &spent_bytes(txnum));
                    spent_now.push(outnum);
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
            self.append_tx(tx, &spent, &mut encoded);
            for &(key, outnum) in &self.tx_history {
                self.history.push((key, outnum_value(outnum)));
            }
            self.insert_txid(tx, txnum, height, inserted)?;
        }
        if block.txs[0].outputs.iter().map(|out| out.value).sum::<u64>() > self.store.chain.subsidy(height) + fees {
            return reject("bad-cb-amount");
        }
        checks.finish(block)?;
        Ok(fees)
    }

    /// Adds a transaction's txid to the table. One already there is
    /// replaced only if it has nothing left to spend, as BIP30 has it, or
    /// it's one of the two blocks Bitcoin Core lets break that rule.
    fn insert_txid(
        &mut self,
        tx: &Tx<'_>,
        txnum: u64,
        height: u32,
        inserted: &mut Vec<(Hash, u64, Option<u64>)>,
    ) -> std::result::Result<(), ConnectError> {
        let table = self.store.table();
        if let Some(old) = table.find(&tx.txid, |num| self.txids.get(num) == tx.txid) {
            let (first, next) = self.outputs_of(old);
            let unspent = (first..next).any(|outnum| {
                let out = decode_out(self.outs.get(outnum));
                out.spendable && out.spent.is_none()
            });
            if unspent && !self.store.chain.bip30_exceptions().contains(&height) {
                return reject("bad-txns-BIP30");
            }
            table.replace(&tx.txid, old, txnum);
            inserted.push((tx.txid, txnum, Some(old)));
            return Ok(());
        }
        if table.insert(&tx.txid, txnum, |_| false).is_err() {
            // Out of room past its end: rebuilt bigger, it holds this
            // transaction and those before it.
            self.rebuild_table(self.txids.len())?;
            self.rebuilt_in_block = true;
            return Ok(());
        }
        inserted.push((tx.txid, txnum, None));
        Ok(())
    }

    /// Builds the txid table anew, for `count` transactions, from the first
    /// `count` indexed, and puts it in place of the old.
    pub(super) fn rebuild_table(&mut self, count: u64) -> Result<()> {
        self.flush_columns()?;
        let started = Instant::now();
        let path = self.paths.table();
        let new_path = self.paths.file("txid.table.new");
        bulk::build_table(&self.txids, count, &new_path, &self.paths.sort_dir())?;
        std::fs::rename(&new_path, &path)?;
        let table = TxidTable::open(&path, 0)?;
        table.set_count(count);
        tracing::info!(
            "built the txid table of {count} transactions, {} slots, in {:.1?}",
            table.slots(),
            started.elapsed()
        );
        *self.store.table.write().unwrap() = Arc::new(table);
        Ok(())
    }

    /// Recovers from a batch indexed in place that was never committed:
    /// every spend by a transaction past the state's counts is unmarked, and
    /// the txid table rebuilt.
    fn recover(&mut self) -> Result<()> {
        let counts = self.state.counts;
        tracing::warn!("the store wasn't committed cleanly; recovering it to block {}", counts.blocks);
        let started = Instant::now();
        self.outs.map().will_need(0, (counts.outs * OUT_WIDTH as u64) as usize);
        for outnum in 0..counts.outs {
            if decode_out(self.outs.get(outnum)).spent.is_some_and(|by| by >= counts.txs) {
                self.outs.set(outnum, VALUE_BYTES, &[0; 5]);
            }
        }
        self.outs.sync()?;
        self.rebuild_table(counts.txs)?;
        self.state.dirty = false;
        self.write_state()?;
        tracing::info!("recovered the store in {:.1?}", started.elapsed());
        Ok(())
    }

    /// Whether enough has been indexed since the last commit to make one.
    pub fn should_commit(&self) -> bool {
        let interval = if self.bulk.is_some() { 30 } else { 10 };
        self.uncommitted > 0 && (self.last_commit.elapsed().as_secs() >= interval || self.history.len() >= 20_000_000)
    }

    /// Writes out and syncs everything indexed, then commits it. Indexing in
    /// place, readers see it; in bulk, they see it once it's merged in.
    pub fn commit(&mut self) -> Result<()> {
        if self.uncommitted == 0 && !self.state.dirty {
            return Ok(());
        }
        let started = Instant::now();
        self.sync_columns()?;
        if let Some(bulk) = &mut self.bulk {
            let (spends, history) = bulk.sync_logs()?;
            self.state.spends_logged = spends;
            self.state.history_logged = history;
            self.state.counts = self.counts();
            self.write_state()?;
        } else {
            self.store.table().sync()?;
            self.state.counts = self.counts();
            self.state.published = self.state.counts;
            self.state.dirty = false;
            self.history.sort_unstable();
            let mut txn = self.store.env.write_txn()?;
            for (key, value) in self.history.drain(..) {
                txn.put(self.store.history, &key, &value, true)?;
            }
            txn.put(self.store.meta, b"state", &self.state.encode(), false)?;
            txn.commit()?;
            self.publish();
        }
        tracing::debug!("committed {} blocks in {:.1?}", self.uncommitted, started.elapsed());
        self.uncommitted = 0;
        self.last_commit = Instant::now();
        Ok(())
    }

    /// Takes the last block off the chain, undoing what it changed, and
    /// commits. Indexing in bulk, the logs are merged in first.
    pub fn disconnect_tip(&mut self) -> Result<()> {
        if self.bulk.is_some() {
            self.finish_bulk()?;
        }
        self.commit()?;
        let height = self.next_height().checked_sub(1).context("no block to disconnect")?;
        let record = self.block(height);
        anyhow::ensure!(
            record.first_out >= self.state.static_outs,
            "block {height} is more than {REORG_DEPTH} blocks deep, too deep to take off"
        );
        self.mark_dirty()?;
        let counts = self.counts();
        let table = self.store.table();
        let mut removals = Vec::new();
        for txnum in (record.first_tx..counts.txs).rev() {
            let (start, first_out) = decode_txidx(self.txidx.get(txnum));
            let end = if txnum + 1 < counts.txs { decode_txidx(self.txidx.get(txnum + 1)).0 } else { counts.data };
            let bytes = self.data.range(start, (end - start) as usize).into_owned();
            let tx = compact::decode(&bytes, first_out)?;
            for input in &tx.inputs {
                if let Some(outnum) = input.spent {
                    self.outs.set(outnum, VALUE_BYTES, &[0; 5]);
                }
            }
            for (vout, out) in tx.outputs.iter().enumerate() {
                if is_spendable(&out.script) {
                    removals.push((script_key(&out.script), outnum_value(first_out + vout as u64)));
                }
            }
            let txid: Hash = self.txids.get(txnum).try_into().unwrap();
            table.remove(&txid, txnum, |num| key_of(self.txids.get(num).try_into().unwrap()));
        }
        let data_start =
            if record.first_tx < counts.txs { decode_txidx(self.txidx.get(record.first_tx)).0 } else { counts.data };
        self.truncate_columns(Snapshot {
            blocks: height,
            txs: record.first_tx,
            outs: record.first_out,
            data: data_start,
        });
        self.outs.sync()?;
        table.sync()?;

        self.state.counts = self.counts();
        self.state.published = self.state.counts;
        self.state.dirty = false;
        let mut txn = self.store.env.write_txn()?;
        for (key, value) in &removals {
            txn.del(self.store.history, key, Some(value))?;
        }
        txn.put(self.store.meta, b"state", &self.state.encode(), false)?;
        txn.commit()?;
        self.publish();
        self.store.first_txs.write().unwrap().truncate(height as usize);
        self.store.heights.write().unwrap().remove(&record.hash());
        Ok(())
    }
}
