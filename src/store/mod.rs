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
//! | `outs` | output | its value, its script's [`ScriptClass`], whether it can be spent, and the number of the transaction that spent it, plus one (12 B) |
//! | `txdata` | byte | transactions in [compact form](crate::compact) |
//! | `txid.table` | — | txid → transaction number ([`TxidTable`]) |
//! | `history` | — | script → the outputs paying it, up to 100 blocks below the tip ([`StaticHistory`]) |
//! | `index/` | — | LMDB: script → the outputs paying it, for the newest blocks; and the store's state |
//!
//! An address's history is the outputs paying its script, from `history`
//! and LMDB, and the transactions that spent them, from `outs`, so inputs
//! needn't be indexed at all. A transaction's inputs name the outputs they
//! spend by number, and its prevouts are read from the transactions that
//! made them.
//!
//! # Two ways of indexing
//!
//! Near the tip, each block is indexed in place: its outputs are marked
//! spent in `outs`, its txids added to the table, its history to LMDB (see
//! [`Writer`]). That's random writes all over files that grow to tens of
//! gigabytes, which is fine for a block every ten minutes and ruinous for
//! the whole chain. So when the index is far behind, it's built in bulk (see
//! [`bulk`]): the columns are only appended to, spends and history entries
//! are appended to logs, and inputs are found in a map in memory of the
//! transactions with outputs left to spend. Once caught up, the logs are
//! sorted and merged in with sequential passes, and indexing goes on in
//! place. Readers see only what's been merged.
//!
//! # Commits and crashes
//!
//! The state saved in LMDB says how much of each file is committed, what
//! readers may see, and which way the store is indexing. Opening a store
//! cuts every file to it. In bulk, nothing's changed in place, so there's
//! nothing more to undo. In place, before a batch first changes anything
//! there, the state is marked dirty, in its own commit; a batch is committed
//! by syncing every file, then committing LMDB's history entries and the new
//! state, clean, at once. A store opened dirty unmarks every spend by a
//! transaction past the state's counts and rebuilds the txid table.

pub mod bulk;
mod checks;
pub mod column;
pub mod history;
pub mod lmdb;
pub mod sort;
#[cfg(test)]
mod tests;
pub mod txid_table;
mod writer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};

use crate::compact::{self, CompactTx};
use crate::consensus::ScriptClass;
use crate::hash::{Hash, sha256, sha256d};
use crate::network::Chain;
use crate::validate::Invalid;
use column::Column;
use history::StaticHistory;
use txid_table::TxidTable;
pub use writer::Writer;

pub const BLOCK_WIDTH: usize = 112;
pub const TXIDX_WIDTH: usize = 11;
pub const OUT_WIDTH: usize = 12;
const VALUE_BYTES: usize = 7;
/// Amounts take 51 bits: 21 million bitcoin is less than 2⁵¹ satoshis.
const VALUE_MASK: u64 = (1 << 51) - 1;
/// Where an output's [`ScriptClass`] is kept, beside its value.
const CLASS_SHIFT: u32 = 51;
/// Set in an output's value when it can never be spent.
const UNSPENDABLE: u64 = 1 << 55;
/// How deep a reorg may go: history this far below the tip may be merged
/// into the file, from which it can't be taken out again.
pub const REORG_DEPTH: u32 = 100;

/// The format the files are in, bumped when it changes.
const FORMAT: u32 = 3;

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
    out[..6].copy_from_slice(&data_off.to_le_bytes()[..6]);
    out[6..].copy_from_slice(&first_out.to_le_bytes()[..5]);
    out
}

fn decode_txidx(bytes: &[u8]) -> (u64, u64) {
    (read_le(&bytes[..6]), read_le(&bytes[6..11]))
}

fn out_record(value: u64, script: &[u8]) -> [u8; OUT_WIDTH] {
    let mut value = value | (ScriptClass::of(script) as u64) << CLASS_SHIFT;
    if !is_spendable(script) {
        value |= UNSPENDABLE;
    }
    let mut out = [0u8; OUT_WIDTH];
    out[..VALUE_BYTES].copy_from_slice(&value.to_le_bytes()[..VALUE_BYTES]);
    out
}

/// An output as `outs` has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Out {
    pub value: u64,
    pub spendable: bool,
    pub class: ScriptClass,
    /// The transaction that spent it.
    pub spent: Option<u64>,
}

fn decode_out(bytes: &[u8]) -> Out {
    let value = read_le(&bytes[..VALUE_BYTES]);
    Out {
        value: value & VALUE_MASK,
        spendable: value & UNSPENDABLE == 0,
        class: ScriptClass::from_bits(((value >> CLASS_SHIFT) & 7) as u8),
        spent: read_le(&bytes[VALUE_BYTES..]).checked_sub(1),
    }
}

fn spent_bytes(txnum: u64) -> [u8; 5] {
    (txnum + 1).to_le_bytes()[..5].try_into().unwrap()
}

/// The key a script's history is kept under.
pub fn script_key(script: &[u8]) -> [u8; 8] {
    sha256(script)[..8].try_into().unwrap()
}

/// [`script_key`] as a number, ordered as the key's bytes are.
pub fn script_key_num(key: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*key)
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

/// How much of the chain is in each column.
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

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.blocks.to_le_bytes());
        out.extend_from_slice(&self.txs.to_le_bytes());
        out.extend_from_slice(&self.outs.to_le_bytes());
        out.extend_from_slice(&self.data.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Snapshot {
        Snapshot {
            blocks: read_le(&bytes[..4]) as u32,
            txs: read_le(&bytes[4..12]),
            outs: read_le(&bytes[12..20]),
            data: read_le(&bytes[20..28]),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Indexing in place.
    #[default]
    Tip,
    /// Indexing in bulk, appending to logs.
    Bulk,
    /// Merging the logs in.
    Finalizing,
}

/// What's saved of the store's state, in LMDB.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    pub mode: Mode,
    /// What's in the columns, committed.
    pub counts: Snapshot,
    /// What readers may see.
    pub published: Snapshot,
    /// Whether changes in place may have been made past `counts`.
    pub dirty: bool,
    /// The counts when indexing in bulk began.
    pub bulk_start: Snapshot,
    /// Records committed to the spend and history logs.
    pub spends_logged: u64,
    pub history_logged: u64,
    /// The history file holds outputs below this number; LMDB the rest.
    pub static_outs: u64,
}

impl State {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&FORMAT.to_le_bytes());
        out.push(match self.mode {
            Mode::Tip => 0,
            Mode::Bulk => 1,
            Mode::Finalizing => 2,
        });
        out.push(self.dirty as u8);
        self.counts.encode(&mut out);
        self.published.encode(&mut out);
        self.bulk_start.encode(&mut out);
        out.extend_from_slice(&self.spends_logged.to_le_bytes());
        out.extend_from_slice(&self.history_logged.to_le_bytes());
        out.extend_from_slice(&self.static_outs.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<State> {
        anyhow::ensure!(bytes.len() >= 4, "the store's state is corrupt");
        let format = read_le(&bytes[..4]) as u32;
        anyhow::ensure!(format == FORMAT, "the store is in format {format}, not {FORMAT}: it must be rebuilt");
        anyhow::ensure!(bytes.len() == 6 + 28 * 3 + 24, "the store's state is corrupt");
        let mode = match bytes[4] {
            0 => Mode::Tip,
            1 => Mode::Bulk,
            2 => Mode::Finalizing,
            _ => anyhow::bail!("the store's state is corrupt"),
        };
        Ok(State {
            mode,
            dirty: bytes[5] != 0,
            counts: Snapshot::decode(&bytes[6..34]),
            published: Snapshot::decode(&bytes[34..62]),
            bulk_start: Snapshot::decode(&bytes[62..90]),
            spends_logged: read_le(&bytes[90..98]),
            history_logged: read_le(&bytes[98..106]),
            static_outs: read_le(&bytes[106..114]),
        })
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
    static_history: RwLock<Arc<StaticHistory>>,
    env: lmdb::Env,
    history: lmdb::Db,
    meta: lmdb::Db,
    snapshot: RwLock<Snapshot>,
    /// Whether it's indexing in bulk, far behind the tip.
    syncing: AtomicBool,
    /// Each block's first transaction number, by height, for finding a
    /// transaction's block. Holds blocks not yet committed too.
    first_txs: RwLock<Vec<u64>>,
    /// Height by block hash, for blocks not yet committed too.
    heights: RwLock<HashMap<Hash, u32>>,
}

/// The paths of a store's files.
pub(crate) struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn table(&self) -> PathBuf {
        self.file("txid.table")
    }

    pub fn history(&self) -> PathBuf {
        self.file("history")
    }

    pub fn sort_dir(&self) -> PathBuf {
        self.file("sort")
    }
}

impl Store {
    /// Opens the store in `dir`, or makes one, recovering or finishing
    /// whatever it was doing.
    pub fn open(dir: &Path, chain: Chain) -> Result<Writer> {
        Writer::open(dir, chain)
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.snapshot.read().unwrap()
    }

    /// Whether it's indexing in bulk, so what readers see is behind.
    pub fn syncing(&self) -> bool {
        self.syncing.load(Ordering::Relaxed)
    }

    fn table(&self) -> Arc<TxidTable> {
        self.table.read().unwrap().clone()
    }

    fn static_history(&self) -> Arc<StaticHistory> {
        self.static_history.read().unwrap().clone()
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
        let first_txs = self.first_txs.read().unwrap();
        let first = first_txs[height as usize];
        let next = if height + 1 < snapshot.blocks { first_txs[height as usize + 1] } else { snapshot.txs };
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
        (lo, (outnum - self.txidx(lo).1) as u32)
    }

    /// Output `outnum`'s value, and the transaction that spent it, if one
    /// committed did.
    pub fn output(&self, outnum: u64, snapshot: &Snapshot) -> (u64, Option<u64>) {
        let out = decode_out(self.outs.record(outnum));
        (out.value, out.spent.filter(|&txnum| txnum < snapshot.txs))
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
        let key: [u8; 8] = hash[..8].try_into().unwrap();
        let mut outs = self.static_history().lookup(script_key_num(&key));
        let txn = self.env.read_txn()?;
        let packed = txn.get_dups(self.history, &key, 5)?;
        outs.extend(packed.chunks_exact(5).map(outnum_from_value));
        outs.retain(|&outnum| outnum < snapshot.outs);
        outs.sort_unstable();
        outs.dedup();
        Ok(outs)
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
            ("txid table", self.table().slots() * 8),
            ("history", self.static_history().size()),
            ("index", self.env.used_bytes().unwrap_or(0)),
        ]
    }
}
