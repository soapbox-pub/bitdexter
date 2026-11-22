//! The chain as bitdexter keeps it.
//!
//! Every transaction and every output has a number, in chain order, and
//! most of what's stored is a column indexed by one of them:
//!
//! | File | Record per | Holds |
//! |---|---|---|
//! | `blocks` | block | header, first tx and output numbers, size, weight, fees (112 B) |
//! | `txids` | transaction | its txid (32 B) |
//! | `txidx` | transaction | where its compact form starts in `txdata`, its first output number (11 B) |
//! | `outs` | output | its value, and the number of the transaction that spent it, plus one (12 B) |
//! | `txdata` | byte | transactions in [compact form](crate::compact) |
//! | `txid.table` | — | txid → transaction number ([`TxidTable`]) |
//! | `index/` | — | LMDB: script → the outputs paying it, and the store's state |
//!
//! An address's history is the outputs paying its script, from the
//! `history` table, and the transactions that spent them, from `outs`, so
//! inputs needn't be indexed at all. A transaction's inputs name the outputs
//! they spend by number, and its prevouts are read from the transactions
//! that made them.
//!
//! # Commits and crashes
//!
//! Blocks are indexed in batches. Before a batch first changes anything in
//! place (marking outputs spent, filling the txid table), the state saved in
//! LMDB is marked dirty, in its own commit. A batch is committed by writing
//! out and syncing every file, then committing LMDB's history entries and the
//! state's new counts, clean, at once. Opening a store cuts every column to
//! the counts of the state, and if it's dirty, unmarks every spend by a
//! transaction past them and rebuilds the txid table.

pub mod column;
pub mod lmdb;
pub mod txid_table;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};

use crate::block::{Block, Tx};
use crate::compact::{self, CompactTx};
use crate::hash::{Hash, sha256, sha256d};
use crate::network::Chain;
use crate::validate::{COINBASE_MATURITY, Invalid, MAX_MONEY};
use column::{Column, ColumnWriter};
use txid_table::{TxidTable, key_of};

pub const BLOCK_WIDTH: usize = 112;
pub const TXIDX_WIDTH: usize = 11;
pub const OUT_WIDTH: usize = 12;
const VALUE_BYTES: usize = 7;

/// The format the files are in, bumped when it changes.
const FORMAT: u32 = 1;

fn le_bytes(n: u64, len: usize) -> [u8; 8] {
    debug_assert!(len == 8 || n < 1 << (len * 8));
    n.to_le_bytes()
}

fn read_le(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRecord {
    pub header: [u8; 80],
    pub first_tx: u64,
    pub first_out: u64,
    pub size: u32,
    pub weight: u32,
    pub fees: u64,
}

impl BlockRecord {
    fn encode(&self) -> [u8; BLOCK_WIDTH] {
        let mut out = [0u8; BLOCK_WIDTH];
        out[..80].copy_from_slice(&self.header);
        out[80..88].copy_from_slice(&self.first_tx.to_le_bytes());
        out[88..96].copy_from_slice(&self.first_out.to_le_bytes());
        out[96..100].copy_from_slice(&self.size.to_le_bytes());
        out[100..104].copy_from_slice(&self.weight.to_le_bytes());
        out[104..112].copy_from_slice(&self.fees.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> BlockRecord {
        BlockRecord {
            header: bytes[..80].try_into().unwrap(),
            first_tx: read_le(&bytes[80..88]),
            first_out: read_le(&bytes[88..96]),
            size: read_le(&bytes[96..100]) as u32,
            weight: read_le(&bytes[100..104]) as u32,
            fees: read_le(&bytes[104..112]),
        }
    }

    pub fn hash(&self) -> Hash {
        sha256d(&self.header)
    }

    pub fn prev_hash(&self) -> Hash {
        self.header[4..36].try_into().unwrap()
    }

    pub fn time(&self) -> u32 {
        read_le(&self.header[68..72]) as u32
    }
}

fn txidx_record(data_off: u64, first_out: u64) -> [u8; TXIDX_WIDTH] {
    let mut out = [0u8; TXIDX_WIDTH];
    out[..6].copy_from_slice(&le_bytes(data_off, 6)[..6]);
    out[6..].copy_from_slice(&le_bytes(first_out, 5)[..5]);
    out
}

fn decode_txidx(bytes: &[u8]) -> (u64, u64) {
    (read_le(&bytes[..6]), read_le(&bytes[6..11]))
}

fn out_record(value: u64) -> [u8; OUT_WIDTH] {
    let mut out = [0u8; OUT_WIDTH];
    out[..VALUE_BYTES].copy_from_slice(&le_bytes(value, VALUE_BYTES)[..VALUE_BYTES]);
    out
}

/// An output's value, and the number of the transaction that spent it.
fn decode_out(bytes: &[u8]) -> (u64, Option<u64>) {
    let spent = read_le(&bytes[VALUE_BYTES..]);
    (read_le(&bytes[..VALUE_BYTES]), spent.checked_sub(1))
}

/// The key a script's history is kept under.
pub fn script_key(script: &[u8]) -> [u8; 8] {
    sha256(script)[..8].try_into().unwrap()
}

/// Whether an output can ever be spent, as Bitcoin Core's `IsUnspendable`
/// decides: those that can't aren't indexed by script.
pub fn is_spendable(script: &[u8]) -> bool {
    script.first() != Some(&0x6a) && script.len() <= 10_000
}

fn outnum_value(outnum: u64) -> [u8; 5] {
    outnum.to_be_bytes()[3..].try_into().unwrap()
}

fn outnum_from_value(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[3..].copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

/// How much of the chain is committed: what readers may see.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub blocks: u32,
    pub txs: u64,
    pub outs: u64,
    pub data: u64,
}

impl Snapshot {
    pub fn tip_height(&self) -> Option<u32> {
        self.blocks.checked_sub(1)
    }

    fn encode(&self, dirty: bool) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[..4].copy_from_slice(&FORMAT.to_le_bytes());
        out[4..8].copy_from_slice(&self.blocks.to_le_bytes());
        out[8..16].copy_from_slice(&self.txs.to_le_bytes());
        out[16..24].copy_from_slice(&self.outs.to_le_bytes());
        out[24..32].copy_from_slice(&self.data.to_le_bytes());
        out[32] = dirty as u8;
        out
    }

    fn decode(bytes: &[u8]) -> Result<(Snapshot, bool)> {
        anyhow::ensure!(bytes.len() == 33, "the store's state is corrupt");
        let format = read_le(&bytes[..4]) as u32;
        anyhow::ensure!(format == FORMAT, "the store is in format {format}, not {FORMAT}: it must be rebuilt");
        let snapshot = Snapshot {
            blocks: read_le(&bytes[4..8]) as u32,
            txs: read_le(&bytes[8..16]),
            outs: read_le(&bytes[16..24]),
            data: read_le(&bytes[24..32]),
        };
        Ok((snapshot, bytes[32] != 0))
    }
}

pub enum ConnectError {
    Invalid(Invalid),
    Io(anyhow::Error),
}

impl From<anyhow::Error> for ConnectError {
    fn from(err: anyhow::Error) -> ConnectError {
        ConnectError::Io(err)
    }
}

impl From<std::io::Error> for ConnectError {
    fn from(err: std::io::Error) -> ConnectError {
        ConnectError::Io(err.into())
    }
}

impl From<lmdb::Error> for ConnectError {
    fn from(err: lmdb::Error) -> ConnectError {
        ConnectError::Io(err.into())
    }
}

fn reject<T>(reason: &str) -> std::result::Result<T, ConnectError> {
    Err(ConnectError::Invalid(Invalid(reason.to_string())))
}

pub struct Store {
    pub chain: Chain,
    blocks: Column,
    txids: Column,
    txidx: Column,
    outs: Column,
    data: Column,
    table: RwLock<Arc<TxidTable>>,
    env: lmdb::Env,
    history: lmdb::Db,
    meta: lmdb::Db,
    snapshot: RwLock<Snapshot>,
    /// Each block's first transaction number, by height, for finding a
    /// transaction's block. Holds blocks not yet committed too.
    first_txs: RwLock<Vec<u64>>,
    /// Height by block hash, for blocks not yet committed too.
    heights: RwLock<HashMap<Hash, u32>>,
}

/// The one writer of a store, which indexes blocks and commits them.
pub struct Writer {
    pub store: Arc<Store>,
    dir: PathBuf,
    blocks: ColumnWriter,
    txids: ColumnWriter,
    txidx: ColumnWriter,
    outs: ColumnWriter,
    data: ColumnWriter,
    /// History entries to add at the next commit: script key, output number.
    history: Vec<([u8; 8], [u8; 5])>,
    /// Whether the state in LMDB is marked dirty for the batch being indexed.
    dirty: bool,
    /// What's been indexed since the last commit.
    uncommitted: u32,
    last_commit: Instant,
}

fn initial_table_capacity(chain: Chain) -> u64 {
    match chain {
        Chain::Mainnet => 1 << 30,
        Chain::Testnet4 | Chain::Signet => 1 << 24,
        Chain::Regtest => 1 << 16,
    }
}

impl Store {
    /// Opens the store in `dir`, or makes one, and recovers it if it wasn't
    /// committed cleanly.
    pub fn open(dir: &Path, chain: Chain) -> Result<Writer> {
        std::fs::create_dir_all(dir.join("index")).with_context(|| format!("making {}", dir.display()))?;
        let env = lmdb::Env::open(&dir.join("index"), 1 << 40, 4)?;
        let history = env.create_db("history", true)?;
        let meta = env.create_db("meta", false)?;
        let (state, dirty) = {
            let txn = env.read_txn()?;
            match txn.get(meta, b"state")? {
                Some(bytes) => Snapshot::decode(bytes)?,
                None => (Snapshot::default(), false),
            }
        };
        let open = |name: &str, width: usize, len: u64| {
            ColumnWriter::open(&dir.join(name), width, len).with_context(|| format!("opening {name}"))
        };
        let (blocks_w, blocks) = open("blocks", BLOCK_WIDTH, state.blocks as u64)?;
        let (txids_w, txids) = open("txids", 32, state.txs)?;
        let (txidx_w, txidx) = open("txidx", TXIDX_WIDTH, state.txs)?;
        let (outs_w, outs) = open("outs", OUT_WIDTH, state.outs)?;
        let (data_w, data) = open("txdata", 1, state.data)?;
        let table = TxidTable::open(&dir.join("txid.table"), initial_table_capacity(chain))?;
        table.set_count(state.txs);

        let mut first_txs = Vec::with_capacity(state.blocks as usize);
        let mut heights = HashMap::with_capacity(state.blocks as usize);
        for height in 0..state.blocks {
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
            env,
            history,
            meta,
            snapshot: RwLock::new(state),
            first_txs: RwLock::new(first_txs),
            heights: RwLock::new(heights),
        });
        let mut writer = Writer {
            store,
            dir: dir.to_path_buf(),
            blocks: blocks_w,
            txids: txids_w,
            txidx: txidx_w,
            outs: outs_w,
            data: data_w,
            history: Vec::new(),
            dirty,
            uncommitted: 0,
            last_commit: Instant::now(),
        };
        if dirty {
            writer.recover(state)?;
        }
        Ok(writer)
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.snapshot.read().unwrap()
    }

    fn table(&self) -> Arc<TxidTable> {
        self.table.read().unwrap().clone()
    }

    pub fn block(&self, height: u32) -> Option<BlockRecord> {
        (height < self.snapshot().blocks).then(|| BlockRecord::decode(self.blocks.record(height as u64)))
    }

    pub fn height_of(&self, hash: &Hash) -> Option<u32> {
        let height = *self.heights.read().unwrap().get(hash)?;
        (height < self.snapshot().blocks).then_some(height)
    }

    pub fn tip(&self) -> Option<(u32, BlockRecord)> {
        let height = self.snapshot().tip_height()?;
        Some((height, self.block(height)?))
    }

    /// The block holding transaction `txnum`.
    pub fn tx_height(&self, txnum: u64) -> u32 {
        let first_txs = self.first_txs.read().unwrap();
        (first_txs.partition_point(|&first| first <= txnum) - 1) as u32
    }

    /// How many transactions block `height` holds.
    pub fn tx_count(&self, height: u32, snapshot: &Snapshot) -> u64 {
        let first = self.first_txs.read().unwrap()[height as usize];
        let next = if height + 1 < snapshot.blocks {
            self.first_txs.read().unwrap()[height as usize + 1]
        } else {
            snapshot.txs
        };
        next - first
    }

    pub fn txid(&self, txnum: u64) -> Hash {
        self.txids.record(txnum).try_into().unwrap()
    }

    pub fn txnum(&self, txid: &Hash) -> Option<u64> {
        let txs = self.snapshot().txs;
        self.table().find(txid, |num| num < txs && self.txids.record(num) == txid)
    }

    /// Where transaction `txnum`'s compact form starts, and its first
    /// output's number.
    fn txidx(&self, txnum: u64) -> (u64, u64) {
        decode_txidx(self.txidx.record(txnum))
    }

    /// Transaction `txnum` in compact form, and its first output's number.
    pub fn tx_bytes(&self, txnum: u64, snapshot: &Snapshot) -> (&[u8], u64) {
        let (start, first_out) = self.txidx(txnum);
        let end = if txnum + 1 < snapshot.txs { self.txidx(txnum + 1).0 } else { snapshot.data };
        (self.data.slice(start, (end - start) as usize), first_out)
    }

    pub fn tx(&self, txnum: u64, snapshot: &Snapshot) -> Result<CompactTx<'_>> {
        let (bytes, first_out) = self.tx_bytes(txnum, snapshot);
        compact::decode(bytes, first_out).with_context(|| format!("decoding transaction {txnum}"))
    }

    /// How many outputs transaction `txnum` has.
    pub fn output_count(&self, txnum: u64, snapshot: &Snapshot) -> u64 {
        let first = self.txidx(txnum).1;
        let next = if txnum + 1 < snapshot.txs { self.txidx(txnum + 1).1 } else { snapshot.outs };
        next - first
    }

    /// The transaction that made output `outnum`, and which of its outputs
    /// it is.
    pub fn outpoint(&self, outnum: u64, snapshot: &Snapshot) -> (u64, u32) {
        // The last transaction whose first output is at most `outnum`.
        let (mut lo, mut hi) = (0u64, snapshot.txs);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.txidx(mid).1 <= outnum { lo = mid } else { hi = mid }
        }
        // Transactions with no outputs share their first output number with
        // the next; the one that made it is the last of them.
        (lo, (outnum - self.txidx(lo).1) as u32)
    }

    /// Output `outnum`'s value, and the transaction that spent it, if one
    /// committed did.
    pub fn output(&self, outnum: u64, snapshot: &Snapshot) -> (u64, Option<u64>) {
        let (value, spent) = decode_out(self.outs.record(outnum));
        (value, spent.filter(|&txnum| txnum < snapshot.txs))
    }

    /// Output `outnum`'s value and script.
    pub fn output_script(&self, outnum: u64, snapshot: &Snapshot) -> Result<(u64, Vec<u8>)> {
        let (txnum, vout) = self.outpoint(outnum, snapshot);
        let tx = self.tx(txnum, snapshot)?;
        let out = tx.outputs.into_iter().nth(vout as usize).context("output past its transaction's")?;
        Ok((out.value, out.script))
    }

    /// The numbers of the outputs paying `script`, in chain order.
    pub fn history(&self, script: &[u8], snapshot: &Snapshot) -> Result<Vec<u64>> {
        self.history_by_hash(&sha256(script), snapshot)
    }

    /// The same, for the script whose SHA-256 is `hash`.
    pub fn history_by_hash(&self, hash: &Hash, snapshot: &Snapshot) -> Result<Vec<u64>> {
        let txn = self.env.read_txn()?;
        let packed = txn.get_dups(self.history, &hash[..8], 5)?;
        Ok(packed.chunks_exact(5).map(outnum_from_value).filter(|&outnum| outnum < snapshot.outs).collect())
    }

    /// How much space the store takes on disk, by part.
    pub fn disk_usage(&self) -> Vec<(&'static str, u64)> {
        let snapshot = self.snapshot();
        vec![
            ("blocks", snapshot.blocks as u64 * BLOCK_WIDTH as u64),
            ("txids", snapshot.txs * 32),
            ("txidx", snapshot.txs * TXIDX_WIDTH as u64),
            ("outs", snapshot.outs * OUT_WIDTH as u64),
            ("txdata", snapshot.data),
            ("txid table", self.table().capacity() * 8),
            ("history", self.env.used_bytes().unwrap_or(0)),
        ]
    }
}

impl Writer {
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

    fn counts(&self) -> Snapshot {
        Snapshot {
            blocks: self.blocks.len() as u32,
            txs: self.txids.len(),
            outs: self.outs.len(),
            data: self.data.len(),
        }
    }

    fn write_state(&self, state: Snapshot, dirty: bool) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        txn.put(self.store.meta, b"state", &state.encode(dirty), false)?;
        txn.commit()?;
        Ok(())
    }

    /// Marks the state dirty before the first change in place since the
    /// last commit.
    fn mark_dirty(&mut self) -> Result<()> {
        if !self.dirty {
            self.write_state(self.store.snapshot(), true)?;
            self.dirty = true;
        }
        Ok(())
    }

    fn txnum_of(&self, txid: &Hash) -> Option<u64> {
        let table = self.store.table();
        table.find(txid, |num| self.txids.get(num) == txid)
    }

    /// Indexes `block` as the next, after checking what can be checked only
    /// with the outputs it spends. The block itself must already have passed
    /// [`crate::validate::check_block`].
    pub fn connect(&mut self, block: &Block<'_>) -> std::result::Result<(), ConnectError> {
        let height = self.next_height();
        let expected_prev = self.tip_hash().unwrap_or([0; 32]);
        if block.prev_hash() != expected_prev {
            return reject("prev-blk-not-tip");
        }
        self.mark_dirty()?;
        self.grow_table_if_needed()?;

        let before = self.counts();
        let history_before = self.history.len();
        let mut spent_now = Vec::new();
        let mut inserted = Vec::new();
        let result = self.connect_txs(block, height, &mut spent_now, &mut inserted);
        match result {
            Ok(fees) => {
                let record = BlockRecord {
                    header: *block.header,
                    first_tx: before.txs,
                    first_out: before.outs,
                    size: block.size() as u32,
                    weight: block.weight() as u32,
                    fees,
                };
                self.blocks.push(&record.encode());
                for column in [&mut self.blocks, &mut self.txids, &mut self.txidx, &mut self.outs, &mut self.data] {
                    column.flush()?;
                }
                self.store.first_txs.write().unwrap().push(before.txs);
                self.store.heights.write().unwrap().insert(block.hash(), height);
                self.uncommitted += 1;
                Ok(())
            }
            Err(err) => {
                // Undo what the block changed in place, then forget the rest.
                for &outnum in &spent_now {
                    self.outs.set(outnum, VALUE_BYTES, &[0; 5]);
                }
                let table = self.store.table();
                for &(txid, txnum, replaced) in inserted.iter().rev() {
                    match replaced {
                        Some(old) => table.replace(&txid, txnum, old),
                        None => {
                            table.remove(&txid, txnum, |num| key_of(self.txids.get(num).try_into().unwrap()));
                        }
                    }
                }
                self.txids.truncate(before.txs);
                self.txidx.truncate(before.txs);
                self.outs.truncate(before.outs);
                self.data.truncate(before.data);
                self.history.truncate(history_before);
                Err(err)
            }
        }
    }

    /// Indexes the block's transactions, returning the fees they pay.
    fn connect_txs(
        &mut self,
        block: &Block<'_>,
        height: u32,
        spent_now: &mut Vec<u64>,
        inserted: &mut Vec<(Hash, u64, Option<u64>)>,
    ) -> std::result::Result<u64, ConnectError> {
        let chain = self.store.chain;
        let block_first_tx = self.txids.len();
        let mut fees = 0u64;
        let mut spent = Vec::new();
        let mut encoded = Vec::with_capacity(512);
        for tx in &block.txs {
            let txnum = self.txids.len();
            let first_out = self.outs.len();
            spent.clear();
            let mut value_in = 0u64;
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let outnum = self.spend(input.prev_txid, input.prev_vout, height, block_first_tx)?;
                    let (value, by) = decode_out(self.outs.get(outnum));
                    if by.is_some() {
                        return reject("bad-txns-inputs-missingorspent");
                    }
                    self.outs.set(outnum, VALUE_BYTES, &le_bytes(txnum + 1, 5)[..5]);
                    spent_now.push(outnum);
                    spent.push(outnum);
                    value_in += value;
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
            for (vout, out) in tx.outputs.iter().enumerate() {
                self.outs.push(&out_record(out.value));
                if is_spendable(out.script) {
                    self.history.push((script_key(out.script), outnum_value(first_out + vout as u64)));
                }
            }
            encoded.clear();
            compact::encode(tx, first_out, &spent, &mut encoded);
            self.txidx.push(&txidx_record(self.data.len(), first_out));
            self.data.push(&encoded);
            self.txids.push(&tx.txid);
            self.insert_txid(tx, txnum, height, inserted)?;
        }
        let coinbase_out: u64 = block.txs[0].outputs.iter().map(|out| out.value).sum();
        if coinbase_out > chain.subsidy(height) + fees {
            return reject("bad-cb-amount");
        }
        Ok(fees)
    }

    /// The number of the output an input spends, checking that it exists
    /// and, if a coinbase's, is mature.
    fn spend(&self, txid: Hash, vout: u32, height: u32, block_first_tx: u64) -> std::result::Result<u64, ConnectError> {
        let Some(prev) = self.txnum_of(&txid) else {
            return reject("bad-txns-inputs-missingorspent");
        };
        let (_, first_out) = decode_txidx(self.txidx.get(prev));
        let next_out =
            if prev + 1 < self.txidx.len() { decode_txidx(self.txidx.get(prev + 1)).1 } else { self.outs.len() };
        if vout as u64 >= next_out - first_out {
            return reject("bad-txns-inputs-missingorspent");
        }
        // The genesis block's coinbase was never spendable.
        if prev == 0 {
            return reject("bad-txns-inputs-missingorspent");
        }
        // A coinbase is the first transaction of its block.
        let first_txs = self.store.first_txs.read().unwrap();
        let prev_height = first_txs.partition_point(|&first| first <= prev);
        let is_coinbase =
            if prev >= block_first_tx { prev == block_first_tx } else { first_txs[prev_height - 1] == prev };
        if is_coinbase {
            let prev_height = if prev >= block_first_tx { height } else { prev_height as u32 - 1 };
            if height - prev_height < COINBASE_MATURITY {
                return reject("bad-txns-premature-spend-of-coinbase");
            }
        }
        Ok(first_out + vout as u64)
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
        let existing = table.insert(&tx.txid, txnum, |num| num != txnum && self.txids.get(num) == tx.txid);
        if let Some(old) = existing {
            let (_, first) = decode_txidx(self.txidx.get(old));
            let (_, next) = decode_txidx(self.txidx.get(old + 1));
            let unspent = (first..next).any(|outnum| decode_out(self.outs.get(outnum)).1.is_none());
            if unspent && !self.store.chain.bip30_exceptions().contains(&height) {
                return reject("bad-txns-BIP30");
            }
            table.replace(&tx.txid, old, txnum);
        }
        inserted.push((tx.txid, txnum, existing));
        Ok(())
    }

    /// Doubles the txid table once it's three quarters full.
    fn grow_table_if_needed(&mut self) -> Result<()> {
        let table = self.store.table();
        if table.count() * 4 < table.capacity() * 3 {
            return Ok(());
        }
        let capacity = table.capacity() * 2;
        tracing::info!("growing the txid table to {capacity} slots");
        let rebuilt = self.build_table(capacity)?;
        *self.store.table.write().unwrap() = Arc::new(rebuilt);
        Ok(())
    }

    /// Builds the txid table anew, with `capacity` slots, from every
    /// transaction indexed, and puts it in place of the old.
    fn build_table(&mut self, capacity: u64) -> Result<TxidTable> {
        let started = Instant::now();
        self.txids.flush()?;
        let path = self.dir.join("txid.table");
        let new_path = self.dir.join("txid.table.new");
        let _ = std::fs::remove_file(&new_path);
        let table = TxidTable::open(&new_path, capacity)?;
        let count = self.txids.len();
        self.txids.map().will_need(0, (count * 32) as usize);
        for num in 0..count {
            let txid: Hash = self.txids.get(num).try_into().unwrap();
            // Later transactions with the same txid replace earlier ones.
            if let Some(old) = table.insert(&txid, num, |m| self.txids.get(m) == txid) {
                table.replace(&txid, old, num);
            }
        }
        table.set_count(count);
        table.sync()?;
        std::fs::rename(&new_path, &path)?;
        tracing::info!("built the txid table of {count} transactions in {:.1?}", started.elapsed());
        Ok(table)
    }

    /// Recovers from a batch that was never committed: every spend by a
    /// transaction past `state` is unmarked, and the txid table rebuilt.
    fn recover(&mut self, state: Snapshot) -> Result<()> {
        tracing::warn!("the store wasn't committed cleanly; recovering it to block {}", state.blocks);
        let started = Instant::now();
        self.outs.map().will_need(0, (state.outs * OUT_WIDTH as u64) as usize);
        for outnum in 0..state.outs {
            if let (_, Some(by)) = decode_out(self.outs.get(outnum))
                && by >= state.txs
            {
                self.outs.set(outnum, VALUE_BYTES, &[0; 5]);
            }
        }
        self.outs.sync()?;
        let capacity = self.store.table().capacity();
        let rebuilt = self.build_table(capacity)?;
        *self.store.table.write().unwrap() = Arc::new(rebuilt);
        self.write_state(state, false)?;
        self.dirty = false;
        tracing::info!("recovered the store in {:.1?}", started.elapsed());
        Ok(())
    }

    /// Whether enough has been indexed since the last commit to make one.
    pub fn should_commit(&self) -> bool {
        self.uncommitted > 0 && (self.last_commit.elapsed().as_secs() >= 10 || self.history.len() >= 20_000_000)
    }

    pub fn has_uncommitted(&self) -> bool {
        self.uncommitted > 0
    }

    /// Writes out and syncs everything indexed, then commits it, so readers
    /// see it.
    pub fn commit(&mut self) -> Result<()> {
        if self.uncommitted == 0 && !self.dirty {
            return Ok(());
        }
        let started = Instant::now();
        for column in [&mut self.blocks, &mut self.txids, &mut self.txidx, &mut self.outs, &mut self.data] {
            column.sync()?;
        }
        self.store.table().sync()?;
        let state = self.counts();
        let entries = self.history.len();
        self.history.sort_unstable();
        let mut txn = self.store.env.write_txn()?;
        for (key, value) in self.history.drain(..) {
            txn.put(self.store.history, &key, &value, true)?;
        }
        txn.put(self.store.meta, b"state", &state.encode(false), false)?;
        txn.commit()?;
        *self.store.snapshot.write().unwrap() = state;
        self.dirty = false;
        tracing::debug!(
            "committed {} blocks, {entries} history entries, in {:.1?}",
            self.uncommitted,
            started.elapsed()
        );
        self.uncommitted = 0;
        self.last_commit = Instant::now();
        Ok(())
    }

    /// Takes the last block off the chain, undoing what it changed, and
    /// commits.
    pub fn disconnect_tip(&mut self) -> Result<()> {
        self.commit()?;
        let height = self.next_height().checked_sub(1).context("no block to disconnect")?;
        self.mark_dirty()?;
        let record = self.block(height);
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
        self.blocks.truncate(height as u64);
        self.txids.truncate(record.first_tx);
        self.txidx.truncate(record.first_tx);
        self.outs.truncate(record.first_out);
        self.data.truncate(data_start);
        self.outs.sync()?;
        table.sync()?;

        let state = self.counts();
        let mut txn = self.store.env.write_txn()?;
        for (key, value) in &removals {
            txn.del(self.store.history, key, Some(value))?;
        }
        txn.put(self.store.meta, b"state", &state.encode(false), false)?;
        txn.commit()?;
        *self.store.snapshot.write().unwrap() = state;
        self.store.first_txs.write().unwrap().truncate(height as usize);
        self.store.heights.write().unwrap().remove(&record.hash());
        self.dirty = false;
        Ok(())
    }
}
