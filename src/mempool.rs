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
//! Transactions whose inputs aren't known (orphans) are refused, not kept.
//!
//! As blocks are committed, the transactions they confirm leave, and so do
//! those spending what they spend, and everything spending those. If the
//! chain reorganizes, every transaction is checked again. When it's over
//! its size, those paying the lowest rate leave first.

use std::collections::{HashMap, HashSet};

use crate::block::{Tx, parse_tx};
use crate::consensus::{self, ScriptClass};
use crate::hash::Hash;
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
            time: now(),
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
        *self = Mempool { synced, seq: self.seq, ..Mempool::default() };
        let count = entries.len();
        let mut kept = 0;
        for entry in entries {
            if self.accept(store, entry.raw).is_ok() {
                kept += 1;
            }
        }
        tracing::info!("the chain changed: kept {kept} of {count} unconfirmed transactions");
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
    /// highest first, as Electrum's `mempool.get_fee_histogram`: each entry
    /// is a rate in sat/vB and the vsize of those paying more than it but
    /// less than the entry before.
    pub fn fee_histogram(&self) -> Vec<(f64, u64)> {
        let mut by_rate: Vec<(u64, u64)> = self.txs.values().map(|e| (e.feerate(), e.vsize)).collect();
        by_rate.sort_unstable_by_key(|r| std::cmp::Reverse(r.0));
        let mut histogram = Vec::new();
        let mut bin = 0u64;
        let mut bin_size = 100_000u64;
        for (rate, vsize) in by_rate {
            bin += vsize;
            if bin > bin_size {
                histogram.push((rate as f64 / 1000.0, bin));
                bin = 0;
                bin_size = bin_size * 11 / 10;
            }
        }
        if bin > 0 {
            histogram.push((0.0, bin));
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
    Peer,
    /// Sent to the API, which is told how it went.
    Api(tokio::sync::oneshot::Sender<Result<Hash, Reject>>),
}

/// Checks transactions as they come, one at a time, on a thread of its own,
/// and catches the mempool up with the store every second. Returns the
/// channel to send it transactions; those accepted from the API are passed
/// to `relay`, to be sent to peers.
pub fn spawn(
    mempool: Shared,
    store: std::sync::Arc<Store>,
    relay: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> std::sync::mpsc::Sender<(Vec<u8>, Source)> {
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, Source)>();
    std::thread::Builder::new()
        .name("mempool".into())
        .spawn(move || {
            loop {
                match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok((raw, source)) => {
                        // Not until the first sync is over: what's spent isn't known.
                        if store.syncing() {
                            if let Source::Api(reply) = source {
                                let _ = reply.send(Err(Reject::new(-28, "still syncing")));
                            }
                            continue;
                        }
                        let result = mempool.write().unwrap().accept(&store, raw.clone());
                        match source {
                            Source::Api(reply) => {
                                if result.is_ok() {
                                    let _ = relay.send(raw);
                                }
                                let _ = reply.send(result);
                            }
                            Source::Peer => {
                                if let Err(reject) = &result {
                                    tracing::trace!("refused a transaction: {reject}");
                                }
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if !store.syncing() {
                    mempool.write().unwrap().sync(&store);
                }
            }
        })
        .expect("spawning the mempool thread");
    tx
}
