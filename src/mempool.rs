//! Transactions not yet in a block: those peers relay, and those sent with
//! `POST /tx`.
//!
//! A transaction is accepted if it would be valid in the next block, given
//! the chain as committed and the transactions already here: its inputs
//! exist, unspent, coinbases mature; it makes no coins; its lock times have
//! passed; its sigops are few enough; and its scripts pass. Bitcoin Core's
//! policy is followed where it matters to relay: the minimum relay fee rate,
//! the largest standard transaction, and replace-by-fee (full RBF, as Core's
//! default since version 28): a transaction spending what one here spends
//! replaces it, and everything spending that, if it pays more in all, by
//! the incremental relay fee for its size, and at a higher rate than each.
//! A transaction whose inputs aren't known (an orphan) is kept aside for a
//! while, and its missing parents asked for from the peer that sent it; it's
//! tried again once they arrive. Peers announce only transactions new to
//! them, so the mempool is saved to `mempool.dat` every ten minutes and when
//! bitdexter stops, and loaded again when it starts.
//!
//! As blocks are committed, the transactions they confirm leave, and so do
//! those spending what they spend, and everything spending those. If the
//! chain reorganizes, every transaction is checked again. When it's over
//! its size, those paying the lowest rate leave first.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::block::{Tx, parse_tx};
use crate::consensus::{self, ScriptClass};
use crate::hash::Hash;
use crate::p2p::PeerId;
use crate::store::{Store, script_key};
use crate::validate::{COINBASE_MATURITY, MAX_MONEY};
use crate::verify::{TxCheck, verify_scripts};

/// The fewest satoshis per 1000 virtual bytes relayed, as Bitcoin Core's
/// default (0.1 sat/vB).
pub const MIN_RELAY_FEERATE: u64 = 100;
/// What a replacement must pay for its size on top of what it replaces.
pub const INCREMENTAL_FEERATE: u64 = 100;
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
const MAX_STANDARD_TX_SIGOPS_COST: u64 = 16_000;
/// The most bytes of transactions kept.
const MAX_BYTES: usize = 300 << 20;

/// Why a transaction was refused, with the error code Bitcoin Core's
/// `sendrawtransaction` gives for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub code: i32,
    pub reason: String,
}

impl Reject {
    fn new(code: i32, reason: impl Into<String>) -> Reject {
        Reject { code, reason: reason.into() }
    }

    fn invalid(reason: &str) -> Reject {
        Reject::new(-26, reason)
    }

    fn missing() -> Reject {
        Reject::new(-25, "bad-txns-inputs-missingorspent")
    }
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.reason, self.code)
    }
}

/// What an input spends.
#[derive(Debug, Clone)]
pub struct Prevout {
    pub txid: Hash,
    pub vout: u32,
    pub value: u64,
    pub script: Vec<u8>,
    /// Whether it's another transaction's here, not yet confirmed.
    pub unconfirmed: bool,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub txid: Hash,
    pub raw: Vec<u8>,
    pub fee: u64,
    pub vsize: u64,
    pub weight: u64,
    /// When it arrived, in seconds since 1970.
    pub time: u64,
    pub prevouts: Vec<Prevout>,
    /// Its outputs' values and scripts.
    pub outputs: Vec<(u64, Vec<u8>)>,
    /// The transactions here it spends, and those spending it.
    pub parents: HashSet<Hash>,
    pub children: HashSet<Hash>,
    /// The order it arrived in.
    seq: u64,
}

impl Entry {
    /// Satoshis per 1000 virtual bytes.
    pub fn feerate(&self) -> u64 {
        self.fee * 1000 / self.vsize.max(1)
    }

    pub fn tx(&self) -> Tx<'_> {
        parse_tx(&self.raw).expect("a transaction accepted")
    }
}

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, Entry>,
    /// What spends each outpoint.
    spends: HashMap<(Hash, u32), Hash>,
    /// The transactions paying, and spending, each script key.
    funding: HashMap<[u8; 8], HashSet<Hash>>,
    spending: HashMap<[u8; 8], HashSet<Hash>>,
    bytes: usize,
    vsize: u64,
    fees: u64,
    seq: u64,
    /// The block the transactions were last checked against.
    synced: Option<(u32, Hash)>,
    pub stats: Stats,
}

/// What's come of the transactions offered, since bitdexter started.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub accepted: u64,
    /// Transactions refused, by why.
    pub refused: std::collections::BTreeMap<String, u64>,
    /// Orphans kept aside, ever, and now.
    pub orphaned: u64,
    pub orphans: usize,
}

/// Seconds since 1970.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Mempool {
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn vsize(&self) -> u64 {
        self.vsize
    }

    pub fn fees(&self) -> u64 {
        self.fees
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash) -> Option<&Entry> {
        self.txs.get(txid)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.txs.values()
    }

    /// The transaction here spending an outpoint, and which of its inputs
    /// does.
    pub fn spender(&self, txid: &Hash, vout: u32) -> Option<(Hash, usize)> {
        let spender = *self.spends.get(&(*txid, vout))?;
        let entry = &self.txs[&spender];
        let vin = entry.prevouts.iter().position(|p| p.txid == *txid && p.vout == vout)?;
        Some((spender, vin))
    }

    /// The transactions here paying or spending the script with `key`,
    /// newest first.
    pub fn txs_of_script(&self, key: &[u8; 8]) -> Vec<&Entry> {
        let mut txids: HashSet<&Hash> = HashSet::new();
        txids.extend(self.funding.get(key).into_iter().flatten());
        txids.extend(self.spending.get(key).into_iter().flatten());
        let mut entries: Vec<&Entry> = txids.into_iter().map(|txid| &self.txs[txid]).collect();
        entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.seq));
        entries
    }

    /// The `n` transactions that arrived last.
    pub fn recent(&self, n: usize) -> Vec<&Entry> {
        let mut entries: Vec<&Entry> = self.txs.values().collect();
        entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.seq));
        entries.truncate(n);
        entries
    }

    /// Accepts a transaction, as of the chain `store` has committed.
    /// Returns its txid.
    pub fn accept(&mut self, store: &Store, raw: Vec<u8>) -> Result<Hash, Reject> {
        self.accept_at(store, raw, now())
    }

    /// Accepts a transaction that arrived at `time`, in seconds since 1970.
    pub fn accept_at(&mut self, store: &Store, raw: Vec<u8>, time: u64) -> Result<Hash, Reject> {
        let result = self.check_and_insert(store, raw, time);
        match &result {
            Ok(_) => self.stats.accepted += 1,
            Err(reject) => {
                let reason = reject.reason.split(" (").next().unwrap_or_default().to_string();
                *self.stats.refused.entry(reason).or_default() += 1;
            }
        }
        result
    }

    fn check_and_insert(&mut self, store: &Store, raw: Vec<u8>, time: u64) -> Result<Hash, Reject> {
        self.sync(store);
        let tx = parse_tx(&raw).map_err(|err| Reject::new(-22, format!("TX decode failed: {err}")))?;
        let txid = tx.txid;
        if self.txs.contains_key(&txid) {
            return Err(Reject::new(-26, "txn-already-in-mempool"));
        }
        let snapshot = store.snapshot();
        let Some(tip) = snapshot.tip_height() else { return Err(Reject::new(-28, "not synced")) };
        if store.coin(&txid, 0, &snapshot).is_some() {
            return Err(Reject::new(-27, "Transaction outputs already in utxo set"));
        }
        check_tx(&tx)?;
        let height = tip + 1;

        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        let mut parents = HashSet::new();
        let mut conflicts = HashSet::new();
        let mut heights = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let (value, script, coin_height) = match self.txs.get(&input.prev_txid) {
                Some(parent) => {
                    let (value, script) =
                        parent.outputs.get(input.prev_vout as usize).cloned().ok_or_else(Reject::missing)?;
                    parents.insert(input.prev_txid);
                    (value, script, height)
                }
                None => {
                    let coin = store.coin(&input.prev_txid, input.prev_vout, &snapshot).ok_or_else(Reject::missing)?;
                    if coin.spent || !coin.spendable {
                        return Err(Reject::missing());
                    }
                    if coin.coinbase && height - coin.height < COINBASE_MATURITY {
                        return Err(Reject::invalid("bad-txns-premature-spend-of-coinbase"));
                    }
                    (coin.value, coin.script, coin.height)
                }
            };
            if let Some(&other) = self.spends.get(&(input.prev_txid, input.prev_vout)) {
                conflicts.insert(other);
            }
            heights.push(coin_height);
            prevouts.push(Prevout {
                txid: input.prev_txid,
                vout: input.prev_vout,
                value,
                script,
                unconfirmed: parents.contains(&input.prev_txid),
            });
        }
        let value_in: u64 = prevouts.iter().map(|p| p.value).sum();
        let value_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if value_in > MAX_MONEY {
            return Err(Reject::invalid("bad-txns-inputvalues-outofrange"));
        }
        if value_in < value_out {
            return Err(Reject::invalid("bad-txns-in-belowout"));
        }
        let fee = value_in - value_out;

        let mtp = store.mtp(tip);
        let chain = store.chain;
        if !consensus::is_final(&tx, height, if height >= chain.csv_height() { mtp } else { now() as u32 }) {
            return Err(Reject::invalid("non-final"));
        }
        if height >= chain.csv_height() && !consensus::sequence_locks_pass(&tx, &heights, height, mtp, |h| store.mtp(h))
        {
            return Err(Reject::invalid("non-BIP68-final"));
        }
        let flags = consensus::script_flags(chain, height, &[0; 32]);
        let classes: Vec<ScriptClass> = prevouts.iter().map(|p| ScriptClass::of(&p.script)).collect();
        if consensus::sigop_cost(&tx, &classes, flags) > MAX_STANDARD_TX_SIGOPS_COST {
            return Err(Reject::invalid("bad-txns-too-many-sigops"));
        }

        let vsize = (tx.weight() as u64).div_ceil(4);
        if fee * 1000 < MIN_RELAY_FEERATE * vsize {
            return Err(Reject::new(-26, "min relay fee not met"));
        }
        let replaced = self.with_descendants(&conflicts);
        if !replaced.is_empty() {
            if parents.iter().any(|p| replaced.contains(p)) {
                return Err(Reject::invalid("bad-txns-spends-conflicting-tx"));
            }
            let replaced_fees: u64 = replaced.iter().map(|t| self.txs[t].fee).sum();
            if fee < replaced_fees + INCREMENTAL_FEERATE * vsize / 1000 {
                return Err(Reject::new(-26, "insufficient fee"));
            }
            if conflicts.iter().any(|t| self.txs[t].feerate() >= fee * 1000 / vsize) {
                return Err(Reject::new(-26, "insufficient fee"));
            }
        }

        let check = TxCheck { raw: &raw, spent: prevouts.iter().map(|p| (p.script.clone(), p.value)).collect() };
        if let Err((_, reason)) = verify_scripts(&[check], flags) {
            return Err(Reject::invalid(&format!("mandatory-script-verify-flag-failed ({reason})")));
        }

        for txid in &replaced {
            self.remove(txid);
        }
        let outputs = tx.outputs.iter().map(|o| (o.value, o.script.to_vec())).collect();
        let weight = tx.weight() as u64;
        drop(tx);
        self.seq += 1;
        let entry = Entry {
            txid,
            raw,
            fee,
            vsize,
            weight,
            time,
            prevouts,
            outputs,
            parents,
            children: HashSet::new(),
            seq: self.seq,
        };
        self.insert(entry);
        self.trim();
        if !self.txs.contains_key(&txid) {
            return Err(Reject::new(-26, "mempool full"));
        }
        Ok(txid)
    }

    fn insert(&mut self, entry: Entry) {
        let txid = entry.txid;
        for p in &entry.prevouts {
            self.spends.insert((p.txid, p.vout), txid);
            self.spending.entry(script_key(&p.script)).or_default().insert(txid);
        }
        for (_, script) in &entry.outputs {
            self.funding.entry(script_key(script)).or_default().insert(txid);
        }
        for parent in &entry.parents {
            if let Some(parent) = self.txs.get_mut(parent) {
                parent.children.insert(txid);
            }
        }
        self.bytes += entry.raw.len();
        self.vsize += entry.vsize;
        self.fees += entry.fee;
        self.txs.insert(txid, entry);
    }

    /// Removes one transaction, leaving those spending it.
    fn remove(&mut self, txid: &Hash) -> Option<Entry> {
        let entry = self.txs.remove(txid)?;
        for p in &entry.prevouts {
            if self.spends.get(&(p.txid, p.vout)) == Some(txid) {
                self.spends.remove(&(p.txid, p.vout));
            }
            unlink(&mut self.spending, &script_key(&p.script), txid);
        }
        for (_, script) in &entry.outputs {
            unlink(&mut self.funding, &script_key(script), txid);
        }
        for parent in &entry.parents {
            if let Some(parent) = self.txs.get_mut(parent) {
                parent.children.remove(txid);
            }
        }
        for child in &entry.children {
            if let Some(child) = self.txs.get_mut(child) {
                child.parents.remove(txid);
                for p in child.prevouts.iter_mut().filter(|p| p.txid == *txid) {
                    p.unconfirmed = false;
                }
            }
        }
        self.bytes -= entry.raw.len();
        self.vsize -= entry.vsize;
        self.fees -= entry.fee;
        Some(entry)
    }

    /// `txids` and everything here spending them, and spending those.
    fn with_descendants(&self, txids: &HashSet<Hash>) -> HashSet<Hash> {
        let mut all = HashSet::new();
        let mut todo: Vec<Hash> = txids.iter().copied().collect();
        while let Some(txid) = todo.pop() {
            if all.insert(txid)
                && let Some(entry) = self.txs.get(&txid)
            {
                todo.extend(entry.children.iter().copied());
            }
        }
        all
    }

    fn remove_with_descendants(&mut self, txid: &Hash) {
        for txid in self.with_descendants(&HashSet::from([*txid])) {
            self.remove(&txid);
        }
    }

    /// Evicts the transactions paying the lowest rate, with whatever spends
    /// them, while there are too many bytes of them.
    fn trim(&mut self) {
        if self.bytes <= MAX_BYTES {
            return;
        }
        let mut by_rate: Vec<(u64, Hash)> = self.txs.values().map(|e| (e.feerate(), e.txid)).collect();
        by_rate.sort_unstable();
        for (_, txid) in by_rate {
            if self.bytes <= MAX_BYTES {
                break;
            }
            self.remove_with_descendants(&txid);
        }
    }

    /// Catches up with the blocks `store` has committed since the last
    /// time: what they confirm, or conflict with, leaves.
    pub fn sync(&mut self, store: &Store) {
        let snapshot = store.snapshot();
        let Some((tip, record)) = store.tip() else { return };
        let tip_hash = record.hash();
        if self.synced == Some((tip, tip_hash)) {
            return;
        }
        let from = match self.synced {
            Some((height, hash)) if height <= tip && store.block(height).is_some_and(|b| b.hash() == hash) => {
                height + 1
            }
            Some(_) => {
                self.synced = Some((tip, tip_hash));
                self.recheck(store);
                return;
            }
            None => tip + 1,
        };
        self.synced = Some((tip, tip_hash));
        if self.txs.is_empty() {
            return;
        }
        for height in from..=tip {
            let first = store.block(height).unwrap().first_tx;
            for txnum in first..first + store.tx_count(height, &snapshot) {
                let txid = store.txid(txnum);
                self.remove(&txid);
                let Ok(tx) = store.tx(txnum, &snapshot) else { continue };
                for input in &tx.inputs {
                    let Some(outnum) = input.spent else { continue };
                    let (prev, vout) = store.outpoint(outnum, &snapshot);
                    if let Some(&other) = self.spends.get(&(store.txid(prev), vout))
                        && other != txid
                    {
                        self.remove_with_descendants(&other);
                    }
                }
            }
        }
    }

    /// Checks every transaction again, as after a reorg, in the order they
    /// arrived, so parents come before children.
    fn recheck(&mut self, store: &Store) {
        let mut entries: Vec<Entry> = std::mem::take(&mut self.txs).into_values().collect();
        entries.sort_unstable_by_key(|e| e.seq);
        let synced = self.synced;
        let stats = std::mem::take(&mut self.stats);
        *self = Mempool { synced, seq: self.seq, stats, ..Mempool::default() };
        let count = entries.len();
        let mut kept = 0;
        for entry in entries {
            if self.check_and_insert(store, entry.raw, entry.time).is_ok() {
                kept += 1;
            }
        }
        tracing::info!("the chain changed: kept {kept} of {count} unconfirmed transactions");
    }

    /// The transactions this spends that are neither here nor in a block:
    /// what it needs before it can be accepted.
    pub fn missing_parents(&self, store: &Store, raw: &[u8]) -> Vec<Hash> {
        let Ok(tx) = parse_tx(raw) else { return Vec::new() };
        let mut missing: Vec<Hash> = tx
            .inputs
            .iter()
            .map(|input| input.prev_txid)
            .filter(|txid| !self.txs.contains_key(txid) && store.txnum(txid).is_none())
            .collect();
        missing.sort_unstable();
        missing.dedup();
        missing
    }

    /// Writes every transaction, in the order they arrived, to `path`.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut entries: Vec<&Entry> = self.txs.values().collect();
        entries.sort_unstable_by_key(|e| e.seq);
        let tmp = path.with_extension("dat.new");
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        out.write_all(SAVED_MAGIC)?;
        for entry in entries {
            out.write_all(&entry.time.to_le_bytes())?;
            out.write_all(&(entry.raw.len() as u32).to_le_bytes())?;
            out.write_all(&entry.raw)?;
        }
        out.into_inner().map_err(|err| err.into_error())?.sync_all()?;
        std::fs::rename(tmp, path)
    }

    /// The fee rate, in sat/vB, a transaction needs to be in about `target`
    /// blocks, from how the transactions here would fill blocks, highest
    /// rate first; at least `floor`.
    pub fn fee_estimates(&self, targets: &[u32], floor: f64) -> Vec<(u32, f64)> {
        const BLOCK_VSIZE: u64 = 1_000_000 - 4_000;
        let mut by_rate: Vec<(u64, u64)> = self.txs.values().map(|e| (e.feerate(), e.vsize)).collect();
        by_rate.sort_unstable_by_key(|r| std::cmp::Reverse(r.0));
        // The lowest rate in each block, filled in turn.
        let mut lowest = Vec::new();
        let mut filled = 0;
        for (rate, vsize) in by_rate {
            if filled + vsize > BLOCK_VSIZE {
                lowest.push(rate);
                filled = 0;
            }
            filled += vsize;
        }
        targets
            .iter()
            .map(|&target| {
                let rate = lowest.get(target as usize - 1).map_or(floor, |&r| (r as f64 / 1000.0).max(floor));
                (target, (rate * 1000.0).round() / 1000.0)
            })
            .collect()
    }

    /// How many virtual bytes of transactions pay each range of fee rates,
    /// highest first, as electrs makes Electrum's `mempool.get_fee_histogram`
    /// and Esplora's `fee_histogram`: each entry is the lowest rate in its
    /// bin, in sat/vB, and the vsize of the bin, about 50,000 vbytes.
    pub fn fee_histogram(&self) -> Vec<(f64, u64)> {
        const BIN: u64 = 50_000;
        let mut by_rate: Vec<(f64, u64)> =
            self.txs.values().map(|e| (e.fee as f64 / e.vsize.max(1) as f64, e.vsize)).collect();
        by_rate.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
        let mut histogram = Vec::new();
        let mut bin = 0u64;
        let mut last_rate = 0.0;
        for (rate, vsize) in by_rate {
            if bin > BIN && last_rate != rate {
                histogram.push((last_rate, bin));
                bin = 0;
            }
            last_rate = rate;
            bin += vsize;
        }
        if bin > 0 {
            histogram.push((last_rate, bin));
        }
        histogram
    }
}

fn unlink(map: &mut HashMap<[u8; 8], HashSet<Hash>>, key: &[u8; 8], txid: &Hash) {
    if let Some(set) = map.get_mut(key) {
        set.remove(txid);
        if set.is_empty() {
            map.remove(key);
        }
    }
}

/// The checks of a transaction on its own, as Core's `CheckTransaction`,
/// and the standardness rules that matter.
fn check_tx(tx: &Tx<'_>) -> Result<(), Reject> {
    if tx.is_coinbase() {
        return Err(Reject::invalid("coinbase"));
    }
    if tx.inputs.is_empty() {
        return Err(Reject::invalid("bad-txns-vin-empty"));
    }
    if tx.outputs.is_empty() {
        return Err(Reject::invalid("bad-txns-vout-empty"));
    }
    if tx.weight() > MAX_STANDARD_TX_WEIGHT {
        return Err(Reject::invalid("tx-size"));
    }
    let mut total = 0u64;
    for out in &tx.outputs {
        if out.value > MAX_MONEY {
            return Err(Reject::invalid("bad-txns-vout-toolarge"));
        }
        total += out.value;
        if total > MAX_MONEY {
            return Err(Reject::invalid("bad-txns-txouttotal-toolarge"));
        }
    }
    let mut seen = HashSet::new();
    for input in &tx.inputs {
        if input.is_null_prevout() {
            return Err(Reject::invalid("bad-txns-prevout-null"));
        }
        if !seen.insert((input.prev_txid, input.prev_vout)) {
            return Err(Reject::invalid("bad-txns-inputs-duplicate"));
        }
    }
    Ok(())
}

/// The mempool shared between the node, the API and the thread checking
/// transactions.
pub type Shared = std::sync::Arc<std::sync::RwLock<Mempool>>;

/// Where a transaction to check came from.
pub enum Source {
    /// A peer, which can be asked for its parents if it's an orphan.
    Peer(Option<PeerId>),
    /// Sent to the API, which is told how it went.
    Api(tokio::sync::oneshot::Sender<Result<Hash, Reject>>),
}

/// Transactions to ask peers for: of the one given, or of any.
pub type Want = (Option<PeerId>, Vec<Hash>);

const SAVED_MAGIC: &[u8; 8] = b"BDXMEMP1";
/// How often the mempool is saved.
const SAVE_EVERY: Duration = Duration::from_secs(600);
/// Orphans kept, at most, and for how long.
const MAX_ORPHANS: usize = 5_000;
const MAX_ORPHAN_BYTES: usize = 50 << 20;
const MAX_ORPHAN_SIZE: usize = 100_000;
const ORPHAN_LIFE: Duration = Duration::from_secs(20 * 60);

/// The transactions saved at `path`, with when each arrived, in order.
pub fn load(path: &std::path::Path) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 8 || &bytes[..8] != SAVED_MAGIC {
        return Err(std::io::Error::other("not a saved mempool"));
    }
    let mut txs = Vec::new();
    let mut at = 8;
    while at < bytes.len() {
        let header = bytes.get(at..at + 12).ok_or_else(|| std::io::Error::other("truncated"))?;
        let time = u64::from_le_bytes(header[..8].try_into().unwrap());
        let len = u32::from_le_bytes(header[8..].try_into().unwrap()) as usize;
        let raw = bytes.get(at + 12..at + 12 + len).ok_or_else(|| std::io::Error::other("truncated"))?;
        txs.push((time, raw.to_vec()));
        at += 12 + len;
    }
    Ok(txs)
}

struct Orphan {
    raw: Vec<u8>,
    from: Option<PeerId>,
    added: Instant,
    parents: Vec<Hash>,
}

/// Transactions waiting for their parents.
#[derive(Default)]
struct Orphans {
    by_txid: HashMap<Hash, Orphan>,
    by_parent: HashMap<Hash, HashSet<Hash>>,
    /// In the order they were added, for evicting the oldest.
    order: VecDeque<Hash>,
    bytes: usize,
}

impl Orphans {
    fn len(&self) -> usize {
        self.by_txid.len()
    }

    /// Keeps a transaction until `parents` arrive. Returns whether it did.
    fn add(&mut self, txid: Hash, raw: Vec<u8>, from: Option<PeerId>, parents: Vec<Hash>) -> bool {
        if self.by_txid.contains_key(&txid) || raw.len() > MAX_ORPHAN_SIZE {
            return false;
        }
        while self.len() >= MAX_ORPHANS || self.bytes + raw.len() > MAX_ORPHAN_BYTES {
            let Some(oldest) = self.order.pop_front() else { break };
            self.remove(&oldest);
        }
        for parent in &parents {
            self.by_parent.entry(*parent).or_default().insert(txid);
        }
        self.bytes += raw.len();
        self.order.push_back(txid);
        self.by_txid.insert(txid, Orphan { raw, from, added: Instant::now(), parents });
        true
    }

    fn remove(&mut self, txid: &Hash) -> Option<Orphan> {
        let orphan = self.by_txid.remove(txid)?;
        self.bytes -= orphan.raw.len();
        for parent in &orphan.parents {
            if let Some(children) = self.by_parent.get_mut(parent) {
                children.remove(txid);
                if children.is_empty() {
                    self.by_parent.remove(parent);
                }
            }
        }
        Some(orphan)
    }

    /// Takes the orphans waiting on `parent`, to be tried again.
    fn take_children(&mut self, parent: &Hash) -> Vec<Orphan> {
        let children: Vec<Hash> = self.by_parent.get(parent).map(|c| c.iter().copied().collect()).unwrap_or_default();
        children.iter().filter_map(|txid| self.remove(txid)).collect()
    }

    fn take_all(&mut self) -> Vec<Orphan> {
        let txids: Vec<Hash> = self.order.drain(..).collect();
        txids.iter().filter_map(|txid| self.remove(txid)).collect()
    }

    fn expire(&mut self) {
        while let Some(oldest) = self.order.front() {
            match self.by_txid.get(oldest) {
                Some(orphan) if orphan.added.elapsed() < ORPHAN_LIFE => break,
                _ => {
                    let oldest = self.order.pop_front().unwrap();
                    self.remove(&oldest);
                }
            }
        }
    }
}

/// The thread checking transactions, and what it keeps.
struct Checker {
    mempool: Shared,
    store: std::sync::Arc<Store>,
    relay: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    wants: tokio::sync::mpsc::UnboundedSender<Want>,
    orphans: Orphans,
}

impl Checker {
    /// Checks a transaction, and then any orphans it lets in, and theirs.
    fn submit(&mut self, raw: Vec<u8>, source: Source, time: u64) {
        let mut queue = vec![(raw, source, time)];
        while let Some((raw, source, time)) = queue.pop() {
            let mut mempool = self.mempool.write().unwrap();
            let result = mempool.accept_at(&self.store, raw.clone(), time);
            let from = match source {
                Source::Api(reply) => {
                    if result.is_ok() {
                        let _ = self.relay.send(raw.clone());
                    }
                    let _ = reply.send(result.clone());
                    None
                }
                Source::Peer(from) => from,
            };
            match result {
                Ok(txid) => {
                    for orphan in self.orphans.take_children(&txid) {
                        queue.push((orphan.raw, Source::Peer(orphan.from), now()));
                    }
                }
                Err(reject) if reject.code == -25 => {
                    let parents = mempool.missing_parents(&self.store, &raw);
                    let Ok(tx) = parse_tx(&raw) else { continue };
                    if !parents.is_empty() && self.orphans.add(tx.txid, raw.clone(), from, parents.clone()) {
                        mempool.stats.orphaned += 1;
                        let _ = self.wants.send((from, parents));
                    }
                }
                Err(reject) => tracing::trace!("refused a transaction: {reject}"),
            }
            mempool.stats.orphans = self.orphans.len();
        }
    }
}

/// Checks transactions as they come, one at a time, on a thread of its own,
/// and catches the mempool up with the store every second. Returns the
/// channel to send it transactions; those accepted from the API are passed
/// to `relay`, to be sent to peers, and the parents of orphans to `wants`.
/// If `saved` is given, the mempool's loaded from it once the store's synced,
/// and saved to it every ten minutes.
pub fn spawn(
    mempool: Shared,
    store: std::sync::Arc<Store>,
    relay: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    wants: tokio::sync::mpsc::UnboundedSender<Want>,
    saved: Option<PathBuf>,
) -> std::sync::mpsc::Sender<(Vec<u8>, Source)> {
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, Source)>();
    let mut checker = Checker { mempool, store, relay, wants, orphans: Orphans::default() };
    std::thread::Builder::new()
        .name("mempool".into())
        .spawn(move || {
            let mut to_load = saved.clone().filter(|path| path.exists());
            let mut last_save = Instant::now();
            let mut tip = None;
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok((raw, source)) => {
                        // Not until the first sync is over: what's spent isn't known.
                        if checker.store.syncing() {
                            if let Source::Api(reply) = source {
                                let _ = reply.send(Err(Reject::new(-28, "still syncing")));
                            }
                            continue;
                        }
                        checker.submit(raw, source, now());
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if checker.store.syncing() {
                    continue;
                }
                if let Some(path) = to_load.take() {
                    match load(&path) {
                        Ok(txs) => {
                            let count = txs.len();
                            for (time, raw) in txs {
                                checker.submit(raw, Source::Peer(None), time);
                            }
                            let kept = checker.mempool.read().unwrap().len();
                            tracing::info!("loaded {kept} of {count} saved unconfirmed transactions");
                        }
                        Err(err) => tracing::warn!("couldn't load {}: {err}", path.display()),
                    }
                }
                checker.mempool.write().unwrap().sync(&checker.store);
                // A new block may hold an orphan's parents.
                let now_tip = checker.store.tip().map(|(height, record)| (height, record.hash()));
                if now_tip != tip {
                    tip = now_tip;
                    for orphan in checker.orphans.take_all() {
                        checker.submit(orphan.raw, Source::Peer(orphan.from), now());
                    }
                }
                checker.orphans.expire();
                if let Some(path) = &saved
                    && last_save.elapsed() >= SAVE_EVERY
                {
                    last_save = Instant::now();
                    if let Err(err) = checker.mempool.read().unwrap().save(path) {
                        tracing::warn!("couldn't save the mempool: {err}");
                    }
                }
            }
        })
        .expect("spawning the mempool thread");
    tx
}

/// Asks the Esplora server at `url` for the txids in its mempool, once the
/// first sync is over (and a saved mempool's had a minute to load), and
/// passes them to `wants`, to be fetched from peers. Then again ten minutes
/// later, for any a peer didn't have the first time.
pub async fn bootstrap(
    url: String,
    store: std::sync::Arc<Store>,
    wants: tokio::sync::mpsc::UnboundedSender<Want>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let client = match reqwest::Client::builder()
        .user_agent(concat!("bitdexter/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()
    {
        Ok(client) => client,
        Err(err) => return tracing::error!("can't fetch a mempool to start from: {err}"),
    };
    let url = format!("{}/mempool/txids", url.trim_end_matches('/'));
    let mut wait = Duration::from_secs(60);
    for _ in 0..2 {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            if !store.syncing() && store.snapshot().blocks > 0 {
                break;
            }
            wait = Duration::from_secs(10);
        }
        let txids: Result<Vec<String>, String> = async {
            let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
            let response = response.error_for_status().map_err(|e| e.to_string())?;
            serde_json::from_str(&response.text().await.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
        }
        .await;
        match txids {
            Ok(txids) => {
                let txids: Vec<Hash> = txids.iter().filter_map(|txid| crate::hash::from_hex_rev(txid)).collect();
                tracing::info!("{url} has {} unconfirmed transactions; asking peers for those missing", txids.len());
                let _ = wants.send((None, txids));
            }
            Err(err) => tracing::warn!("couldn't fetch {url}: {err}"),
        }
        wait = Duration::from_secs(600);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphans_wait_for_their_parents() {
        let mut orphans = Orphans::default();
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        assert!(orphans.add(a, vec![0; 10], Some(7), vec![b, c]));
        assert!(!orphans.add(a, vec![0; 10], None, vec![b]));
        assert!(!orphans.add([4; 32], vec![0; MAX_ORPHAN_SIZE + 1], None, vec![b]));
        let children = orphans.take_children(&b);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].from, Some(7));
        // Taken, it no longer waits on its other parent.
        assert!(orphans.take_children(&c).is_empty());
        assert_eq!((orphans.len(), orphans.bytes), (0, 0));
        // The oldest go first when it's full.
        for n in 0..MAX_ORPHANS as u32 + 3 {
            let mut txid = [0; 32];
            txid[..4].copy_from_slice(&n.to_le_bytes());
            orphans.add(txid, vec![0; 10], None, vec![b]);
        }
        assert_eq!(orphans.len(), MAX_ORPHANS);
        assert!(!orphans.by_txid.contains_key(&[0; 32]));
        assert_eq!(orphans.take_all().len(), MAX_ORPHANS);
        assert!(orphans.by_parent.is_empty());
    }

    #[test]
    fn saved_mempool_reads_back() {
        let dir = std::env::temp_dir().join(format!("bitdexter-mempool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        let mut mempool = Mempool::default();
        for (n, raw) in [vec![1u8, 2, 3], vec![4u8; 300]].into_iter().enumerate() {
            mempool.seq += 1;
            let txid = [n as u8; 32];
            mempool.txs.insert(
                txid,
                Entry {
                    txid,
                    raw,
                    fee: 0,
                    vsize: 1,
                    weight: 4,
                    time: 1000 + n as u64,
                    prevouts: Vec::new(),
                    outputs: Vec::new(),
                    parents: HashSet::new(),
                    children: HashSet::new(),
                    seq: mempool.seq,
                },
            );
        }
        mempool.save(&path).unwrap();
        assert_eq!(load(&path).unwrap(), vec![(1000, vec![1, 2, 3]), (1001, vec![4; 300])]);
        std::fs::write(&path, b"BDXMEMP1\x01").unwrap();
        assert!(load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
