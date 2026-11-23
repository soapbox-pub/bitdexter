//! Transactions not yet in a block: those peers relay, and those sent with
//! `POST /tx`.
//!
//! A transaction is accepted if it would be valid in the next block, given
//! the chain as committed and the transactions already here: its inputs
//! exist, unspent, coinbases mature; it makes no coins; its lock times have
//! passed; its sigops are few enough; and its scripts pass. Bitcoin Core's
//! policy is followed where it matters to relay and to what miners will
//! take: the minimum relay fee rate, and the mempool's own minimum once
//! it's been full; standard transactions only (versions, output scripts,
//! dust, input scripts); at most 25 unconfirmed ancestors and descendants;
//! and replace-by-fee (full RBF, as Core's default since version 28): a
//! transaction spending what one here spends replaces it, and everything
//! spending that, at most 100 of them, if it pays more in all, by the
//! incremental relay fee for its size, and at a higher rate than each.
//! A transaction whose inputs aren't known (an orphan) is kept aside for a
//! while, and its missing parents asked for from the peer that sent it; it's
//! tried again once they arrive. Peers announce only transactions new to
//! them, so the mempool is saved to `mempool.dat` every ten minutes and when
//! bitdexter stops, and loaded again when it starts.
//!
//! As blocks are committed, the transactions they confirm leave, and so do
//! those spending what they spend, and everything spending those. If the
//! chain reorganizes, every transaction is checked again. When it takes
//! more memory than it may, those paying the lowest rate leave first, and
//! after two weeks, any.
//!
//! Only the mempool's own thread changes it. It checks a transaction
//! holding only a read lock, which keeps no reader waiting, and takes the
//! write lock just to add it; readers never queue behind it either, as it
//! waits for the lock to be free rather than asking for it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
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
/// The rate dust is figured at, as Core's `-dustrelayfee`.
const DUST_RELAY_FEERATE: u64 = 3000;
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
const MAX_STANDARD_TX_SIGOPS_COST: u64 = 16_000;
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1650;
const MAX_P2SH_SIGOPS: usize = 15;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;
const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
/// The most unconfirmed ancestors, and descendants, a transaction may
/// have, itself counted, as Core's defaults.
const MAX_ANCESTORS: usize = 25;
const MAX_DESCENDANTS: usize = 25;
/// The most transactions one may replace, as Core's.
const MAX_REPLACEMENTS: usize = 100;
/// The most memory the transactions here may take, as figured by
/// [`Entry::footprint`].
const MAX_BYTES: usize = 300 << 20;
/// How long a transaction may stay unconfirmed, as Core's `-mempoolexpiry`.
const EXPIRY: u64 = 14 * 24 * 3600;
/// How long the minimum fee rate takes to halve once the mempool's no
/// longer full, as Core's.
const MIN_FEE_HALFLIFE: f64 = 12.0 * 3600.0;
/// The most changes kept for [`Mempool::changed_since`].
const MAX_CHANGES: usize = 200_000;
/// The most transactions waiting to be checked.
const QUEUE: usize = 1000;
/// The most refused transactions remembered, so as not to check them again.
const MAX_REFUSED: usize = 100_000;

/// Why a transaction was refused, with the error code Bitcoin Core's
/// `sendrawtransaction` gives for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub code: i32,
    pub reason: String,
}

impl Reject {
    pub fn new(code: i32, reason: impl Into<String>) -> Reject {
        Reject { code, reason: reason.into() }
    }

    fn invalid(reason: &str) -> Reject {
        Reject::new(-26, reason)
    }

    fn missing() -> Reject {
        Reject::new(-25, "bad-txns-inputs-missingorspent")
    }

    /// Whether the same transaction might be accepted later without the
    /// chain changing: if its inputs turn up, or there's room.
    fn may_pass_later(&self) -> bool {
        self.code == -25 || self.code == -28 || self.reason == "mempool full" || self.reason == "txn-already-in-mempool"
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

    /// About how many bytes of memory it takes, with its place in each
    /// index. It mustn't change while it's here.
    fn footprint(&self) -> usize {
        const ENTRY: usize = 512;
        const PER_INPUT: usize = 208;
        const PER_OUTPUT: usize = 96;
        ENTRY
            + self.raw.len()
            + self.prevouts.iter().map(|p| PER_INPUT + p.script.len()).sum::<usize>()
            + self.outputs.iter().map(|(_, s)| PER_OUTPUT + s.len()).sum::<usize>()
    }
}

/// A transaction checked and ready to be added.
pub struct Checked {
    entry: Entry,
    /// What it replaces.
    replaced: HashSet<Hash>,
    /// The mempool's generation when it was checked.
    generation: u64,
}

/// A transaction that arrived lately, for `/mempool/recent`.
#[derive(Debug, Clone)]
pub struct Recent {
    pub txid: Hash,
    pub fee: u64,
    pub vsize: u64,
    pub value: u64,
}

/// What's figured from the whole mempool, figured again at most once a
/// second rather than for every request.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    /// The lowest rate in each block the transactions here would fill,
    /// highest rate first, in sat/kvB.
    lowest: Vec<u64>,
    histogram: Vec<(f64, u64)>,
    recent: Vec<Recent>,
}

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, Entry>,
    /// What spends each outpoint.
    spends: HashMap<(Hash, u32), Hash>,
    /// The transactions paying, and spending, each script key.
    funding: HashMap<[u8; 8], HashSet<Hash>>,
    spending: HashMap<[u8; 8], HashSet<Hash>>,
    /// The transactions by fee rate, lowest first, and by arrival.
    by_rate: BTreeSet<(u64, Hash)>,
    by_seq: BTreeMap<u64, Hash>,
    bytes: usize,
    vsize: u64,
    fees: u64,
    seq: u64,
    /// The block the transactions were last checked against.
    synced: Option<(u32, Hash)>,
    /// Counts changes. Each change's script keys are kept, in
    /// `changes`, from generation `changes_from` on.
    generation: u64,
    changes: VecDeque<(u64, [u8; 8])>,
    changes_from: u64,
    /// The rate below which nothing's taken since the mempool was last
    /// full, in sat/kvB, and when it was set.
    min_feerate: (f64, u64),
    summary: Arc<Summary>,
    summary_generation: u64,
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

    /// Counts the changes made, for [`Mempool::changed_since`].
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The script keys paid or spent by transactions added or removed
    /// since `generation`, or `None` if that's too long ago to know.
    pub fn changed_since(&self, generation: u64) -> Option<HashSet<[u8; 8]>> {
        if generation < self.changes_from {
            return None;
        }
        Some(self.changes.iter().filter(|(g, _)| *g > generation).map(|(_, key)| *key).collect())
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

    /// The transactions that arrived last, as of the last summary.
    pub fn recent(&self) -> Vec<Recent> {
        self.summary.recent.clone()
    }

    /// The fee rate, in sat/kvB, below which nothing's taken now.
    fn min_feerate(&self, now: u64) -> u64 {
        let (rate, since) = self.min_feerate;
        let halvings = now.saturating_sub(since) as f64 / MIN_FEE_HALFLIFE;
        let rate = rate / 2f64.powf(halvings);
        // As Core, it drops to nothing once it's under half the increment.
        let rate = if rate < INCREMENTAL_FEERATE as f64 / 2.0 { 0 } else { rate.ceil() as u64 };
        rate.max(MIN_RELAY_FEERATE)
    }

    /// Checks a transaction, as of the chain `store` has committed, for
    /// [`Mempool::add`]. This is the slow part, scripts and all, and needs
    /// only a read lock.
    /// `time` is when it arrived, in seconds since 1970.
    pub fn check(&self, store: &Store, raw: Vec<u8>, time: u64) -> Result<Checked, Reject> {
        let tx = parse_tx(&raw).map_err(|err| Reject::new(-22, format!("TX decode failed: {err}")))?;
        let txid = tx.txid;
        if self.txs.contains_key(&txid) {
            return Err(Reject::new(-26, "txn-already-in-mempool"));
        }
        check_tx(&tx)?;
        check_standard(&tx)?;
        let snapshot = store.snapshot();
        let Some(tip) = snapshot.tip_height() else { return Err(Reject::new(-28, "not synced")) };
        if store.coin(&txid, 0, &snapshot).is_some() {
            return Err(Reject::new(-27, "Transaction outputs already in utxo set"));
        }
        let height = tip + 1;
        let vsize = (tx.weight() as u64).div_ceil(4);

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
        let feerate = fee * 1000 / vsize;
        if fee * 1000 < MIN_RELAY_FEERATE * vsize {
            return Err(Reject::new(-26, "min relay fee not met"));
        }
        if feerate < self.min_feerate(now()) {
            return Err(Reject::new(-26, "mempool min fee not met"));
        }
        check_inputs_standard(&tx, &prevouts)?;

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

        let replaced = self.with_descendants(&conflicts);
        if !replaced.is_empty() {
            if parents.iter().any(|p| replaced.contains(p)) {
                return Err(Reject::invalid("bad-txns-spends-conflicting-tx"));
            }
            if replaced.len() > MAX_REPLACEMENTS {
                return Err(Reject::new(-26, "too many potential replacements"));
            }
            let replaced_fees: u64 = replaced.iter().map(|t| self.txs[t].fee).sum();
            if fee < replaced_fees + INCREMENTAL_FEERATE * vsize / 1000 {
                return Err(Reject::new(-26, "insufficient fee"));
            }
            if conflicts.iter().any(|t| self.txs[t].feerate() >= feerate) {
                return Err(Reject::new(-26, "insufficient fee"));
            }
        }
        self.check_chain_limits(&parents, &replaced)?;

        let check = TxCheck { raw: &raw, spent: prevouts.iter().map(|p| (p.script.clone(), p.value)).collect() };
        if let Err((_, reason)) = verify_scripts(&[check], flags) {
            return Err(Reject::invalid(&format!("mandatory-script-verify-flag-failed ({reason})")));
        }

        let outputs = tx.outputs.iter().map(|o| (o.value, o.script.to_vec())).collect();
        let weight = tx.weight() as u64;
        drop(tx);
        let entry =
            Entry { txid, raw, fee, vsize, weight, time, prevouts, outputs, parents, children: HashSet::new(), seq: 0 };
        Ok(Checked { entry, replaced, generation: self.generation })
    }

    /// Whether a transaction spending `parents` would have too many
    /// ancestors, or give one of them too many descendants, once what it
    /// replaces is gone.
    fn check_chain_limits(&self, parents: &HashSet<Hash>, replaced: &HashSet<Hash>) -> Result<(), Reject> {
        let ancestors = self.ancestors(parents);
        if ancestors.len() + 1 > MAX_ANCESTORS {
            return Err(Reject::new(-26, "too-long-mempool-chain"));
        }
        for ancestor in &ancestors {
            let descendants = self.with_descendants(&HashSet::from([*ancestor]));
            if descendants.difference(replaced).count() + 1 > MAX_DESCENDANTS {
                return Err(Reject::new(-26, "too-long-mempool-chain"));
            }
        }
        Ok(())
    }

    /// `parents` and every transaction here they spend, and those spend.
    fn ancestors(&self, parents: &HashSet<Hash>) -> HashSet<Hash> {
        let mut all = HashSet::new();
        let mut todo: Vec<Hash> = parents.iter().copied().collect();
        while let Some(txid) = todo.pop() {
            if all.insert(txid)
                && let Some(entry) = self.txs.get(&txid)
            {
                todo.extend(entry.parents.iter().copied());
            }
        }
        all
    }

    /// Adds a transaction [`Mempool::check`] passed, removing what it
    /// replaces and, if there's no room, what pays least, which mustn't
    /// be it or anything it needs. Returns its txid, or `None` if the
    /// mempool's changed since it was checked, and it must be again.
    pub fn add(&mut self, checked: Checked) -> Option<Result<Hash, Reject>> {
        if checked.generation != self.generation {
            return None;
        }
        let Checked { mut entry, replaced, .. } = checked;
        let txid = entry.txid;
        let feerate = entry.feerate();

        // What would be evicted to make room, without removing anything yet.
        let freed: usize = replaced.iter().map(|t| self.txs[t].footprint()).sum();
        let over = (self.bytes + entry.footprint()).saturating_sub(freed + MAX_BYTES);
        let mut evict: HashSet<Hash> = HashSet::new();
        let mut evicted_rate = 0;
        if over > 0 {
            let ancestors = self.ancestors(&entry.parents);
            let mut evicting = 0;
            for &(rate, candidate) in &self.by_rate {
                if evicting >= over {
                    break;
                }
                if replaced.contains(&candidate) || evict.contains(&candidate) {
                    continue;
                }
                if rate >= feerate {
                    return Some(Err(Reject::new(-26, "mempool full")));
                }
                let set = self.with_descendants(&HashSet::from([candidate]));
                if set.iter().any(|t| ancestors.contains(t)) {
                    return Some(Err(Reject::new(-26, "mempool full")));
                }
                for t in set {
                    if !replaced.contains(&t) && evict.insert(t) {
                        evicting += self.txs[&t].footprint();
                    }
                }
                evicted_rate = rate;
            }
        }

        for txid in &replaced {
            self.remove(txid);
        }
        for txid in &evict {
            self.remove(txid);
        }
        if !evict.is_empty() {
            // Nothing paying less than what was evicted is taken for a while.
            let rate = (evicted_rate + INCREMENTAL_FEERATE) as f64;
            let current = self.min_feerate(now()) as f64;
            self.min_feerate = (rate.max(current), now());
            tracing::debug!("mempool full: evicted {} transactions", evict.len());
        }
        self.seq += 1;
        entry.seq = self.seq;
        self.insert(entry);
        Some(Ok(txid))
    }

    fn note_change(&mut self, keys: impl Iterator<Item = [u8; 8]>) {
        self.generation += 1;
        let generation = self.generation;
        self.changes.extend(keys.map(|key| (generation, key)));
        while self.changes.len() > MAX_CHANGES {
            let (g, _) = self.changes.pop_front().unwrap();
            self.changes_from = self.changes_from.max(g);
        }
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
        let keys: Vec<[u8; 8]> = entry
            .prevouts
            .iter()
            .map(|p| script_key(&p.script))
            .chain(entry.outputs.iter().map(|(_, s)| script_key(s)))
            .collect();
        self.note_change(keys.into_iter());
        self.bytes += entry.footprint();
        self.vsize += entry.vsize;
        self.fees += entry.fee;
        self.by_rate.insert((entry.feerate(), txid));
        self.by_seq.insert(entry.seq, txid);
        self.txs.insert(txid, entry);
    }

    /// Removes one transaction, leaving those spending it.
    fn remove(&mut self, txid: &Hash) -> Option<Entry> {
        let entry = self.txs.remove(txid)?;
        self.bytes -= entry.footprint();
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
        let mut keys: Vec<[u8; 8]> = entry
            .prevouts
            .iter()
            .map(|p| script_key(&p.script))
            .chain(entry.outputs.iter().map(|(_, s)| script_key(s)))
            .collect();
        for child in &entry.children {
            if let Some(child) = self.txs.get_mut(child) {
                child.parents.remove(txid);
                for p in child.prevouts.iter_mut().filter(|p| p.txid == *txid) {
                    p.unconfirmed = false;
                }
                // Whether it spends unconfirmed outputs is in its scripts' statuses.
                keys.extend(child.prevouts.iter().map(|p| script_key(&p.script)));
                keys.extend(child.outputs.iter().map(|(_, s)| script_key(s)));
            }
        }
        self.note_change(keys.into_iter());
        self.vsize -= entry.vsize;
        self.fees -= entry.fee;
        self.by_rate.remove(&(entry.feerate(), *txid));
        self.by_seq.remove(&entry.seq);
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

    /// Removes what's been here longer than it may.
    fn expire(&mut self, now: u64) {
        while let Some((_, txid)) = self.by_seq.first_key_value().map(|(s, t)| (*s, *t)) {
            if self.txs[&txid].time + EXPIRY > now {
                break;
            }
            self.remove_with_descendants(&txid);
        }
    }

    /// Catches up with the blocks `store` has committed since the last
    /// time: what they confirm, or conflict with, leaves. If the chain's
    /// reorganized, empties the mempool and returns what was in it, in the
    /// order it arrived, with when, to be checked again.
    pub fn sync(&mut self, store: &Store) -> Option<Vec<(u64, Vec<u8>)>> {
        self.expire(now());
        let snapshot = store.snapshot();
        let (tip, record) = store.tip()?;
        let tip_hash = record.hash();
        if self.synced == Some((tip, tip_hash)) {
            return None;
        }
        let from = match self.synced {
            Some((height, hash)) if height <= tip && store.block(height).is_some_and(|b| b.hash() == hash) => {
                height + 1
            }
            Some(_) => {
                let mut entries: Vec<Entry> = std::mem::take(&mut self.txs).into_values().collect();
                entries.sort_unstable_by_key(|e| e.seq);
                let generation = self.generation + 1;
                *self = Mempool {
                    synced: Some((tip, tip_hash)),
                    seq: self.seq,
                    generation,
                    changes_from: generation,
                    min_feerate: self.min_feerate,
                    stats: std::mem::take(&mut self.stats),
                    ..Mempool::default()
                };
                return Some(entries.into_iter().map(|e| (e.time, e.raw)).collect());
            }
            None => tip + 1,
        };
        self.synced = Some((tip, tip_hash));
        if self.txs.is_empty() {
            return None;
        }
        for height in from..=tip {
            let Some(block) = store.block(height) else { break };
            let first = block.first_tx;
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
        None
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
        let tmp = path.with_extension("dat.new");
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        out.write_all(SAVED_MAGIC)?;
        for txid in self.by_seq.values() {
            let entry = &self.txs[txid];
            out.write_all(&entry.time.to_le_bytes())?;
            out.write_all(&(entry.raw.len() as u32).to_le_bytes())?;
            out.write_all(&entry.raw)?;
        }
        out.into_inner().map_err(|err| err.into_error())?.sync_all()?;
        std::fs::rename(tmp, path)
    }

    /// Figures the summary afresh, if anything's changed.
    fn summarize(&self) -> Option<Summary> {
        if self.summary_generation == self.generation {
            return None;
        }
        const BLOCK_VSIZE: u64 = 1_000_000 - 4_000;
        let mut lowest = Vec::new();
        let mut filled = 0;
        for &(rate, txid) in self.by_rate.iter().rev() {
            let vsize = self.txs[&txid].vsize;
            if filled + vsize > BLOCK_VSIZE {
                lowest.push(rate);
                filled = 0;
            }
            filled += vsize;
        }

        // As electrs makes Electrum's `mempool.get_fee_histogram` and
        // Esplora's `fee_histogram`: each entry is the lowest rate in its
        // bin, in sat/vB, and the vsize of the bin, about 50,000 vbytes.
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

        let recent = self
            .by_seq
            .values()
            .rev()
            .take(10)
            .map(|txid| {
                let e = &self.txs[txid];
                Recent { txid: e.txid, fee: e.fee, vsize: e.vsize, value: e.outputs.iter().map(|(v, _)| v).sum() }
            })
            .collect();
        Some(Summary { lowest, histogram, recent })
    }

    /// The fee rate, in sat/vB, a transaction needs to be in about `target`
    /// blocks, from how the transactions here would fill blocks, highest
    /// rate first; at least `floor`. As of the last summary.
    pub fn fee_estimates(&self, targets: &[u32], floor: f64) -> Vec<(u32, f64)> {
        targets
            .iter()
            .map(|&target| {
                let lowest = target.checked_sub(1).and_then(|i| self.summary.lowest.get(i as usize));
                let rate = lowest.map_or(floor, |&r| (r as f64 / 1000.0).max(floor));
                (target, (rate * 1000.0).round() / 1000.0)
            })
            .collect()
    }

    /// How many virtual bytes of transactions pay each range of fee rates,
    /// highest first, as of the last summary.
    pub fn fee_histogram(&self) -> Vec<(f64, u64)> {
        self.summary.histogram.clone()
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

/// The checks of a transaction on its own, as Core's `CheckTransaction`.
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

/// Whether an output script is one Core relays: a standard template, a
/// witness program, or data after `OP_RETURN`.
fn is_standard_output(script: &[u8]) -> bool {
    let s = bitcoin::Script::from_bytes(script);
    if s.is_op_return() || s.is_p2pk() || s.is_p2pkh() || s.is_p2sh() || s.witness_version().is_some() {
        return true;
    }
    // Bare multisig, of at most three keys.
    if s.is_multisig() {
        let n = script[script.len() - 2];
        return (0x51..=0x53).contains(&n);
    }
    false
}

/// The least an output may pay not to be dust, as Core's `GetDustThreshold`.
fn dust_threshold(script: &[u8]) -> u64 {
    let s = bitcoin::Script::from_bytes(script);
    if s.is_op_return() {
        return 0;
    }
    let size = 8 + crate::block::compact_size_len(script.len() as u64) + script.len();
    let spend = if s.witness_version().is_some() { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
    (size + spend) as u64 * DUST_RELAY_FEERATE / 1000
}

/// Core's `IsStandardTx`, as far as it goes without the outputs spent.
fn check_standard(tx: &Tx<'_>) -> Result<(), Reject> {
    if !(1..=3).contains(&tx.version) {
        return Err(Reject::invalid("version"));
    }
    for input in &tx.inputs {
        if input.script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(Reject::invalid("scriptsig-size"));
        }
        if !bitcoin::Script::from_bytes(input.script_sig).is_push_only() {
            return Err(Reject::invalid("scriptsig-not-pushonly"));
        }
    }
    for out in &tx.outputs {
        if !is_standard_output(out.script) {
            return Err(Reject::invalid("scriptpubkey"));
        }
        if out.value < dust_threshold(out.script) {
            return Err(Reject::invalid("dust"));
        }
    }
    Ok(())
}

/// Core's `AreInputsStandard` and `IsWitnessStandard`, much as they go:
/// the outputs spent are standard, P2SH redeem scripts have few sigops,
/// P2WSH spends are within its limits, and no taproot spend has an annex.
fn check_inputs_standard(tx: &Tx<'_>, prevouts: &[Prevout]) -> Result<(), Reject> {
    for (input, prevout) in tx.inputs.iter().zip(prevouts) {
        let prev = bitcoin::Script::from_bytes(&prevout.script);
        if !is_standard_output(&prevout.script) || prev.is_op_return() {
            return Err(Reject::invalid("bad-txns-nonstandard-inputs"));
        }
        let witness = crate::compact::witness_items(input.witness);
        let mut program = prev.to_owned();
        if prev.is_p2sh() {
            let Some(redeem) = crate::script::last_push(input.script_sig) else {
                return Err(Reject::invalid("bad-txns-nonstandard-inputs"));
            };
            if bitcoin::Script::from_bytes(&redeem).count_sigops() > MAX_P2SH_SIGOPS {
                return Err(Reject::invalid("bad-txns-nonstandard-inputs"));
            }
            program = bitcoin::ScriptBuf::from_bytes(redeem);
        }
        if program.is_p2wsh() {
            let Some((script, stack)) = witness.split_last() else { continue };
            if script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE
                || stack.len() > MAX_STANDARD_P2WSH_STACK_ITEMS
                || stack.iter().any(|item| item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
            {
                return Err(Reject::invalid("bad-witness-nonstandard"));
            }
        } else if program.is_p2tr() && !prev.is_p2sh() {
            if witness.len() >= 2 && witness.last().is_some_and(|annex| annex.first() == Some(&0x50)) {
                return Err(Reject::invalid("bad-witness-nonstandard"));
            }
        } else if program.witness_version().is_some_and(|v| v.to_num() > 1) && !witness.is_empty() {
            // Spending a witness version yet to be defined.
            return Err(Reject::invalid("bad-witness-nonstandard"));
        }
    }
    Ok(())
}

/// The mempool shared between the node, the API and the thread checking
/// transactions.
pub type Shared = Arc<std::sync::RwLock<Mempool>>;

/// Where to send transactions to be checked.
pub type Submit = std::sync::mpsc::SyncSender<(Vec<u8>, Source)>;

/// Where a transaction to check came from.
pub enum Source {
    /// A peer, which can be asked for its parents if it's an orphan.
    Peer(Option<PeerId>),
    /// Sent to the API, which is told how it went.
    Api(tokio::sync::oneshot::Sender<Result<Hash, Reject>>),
}

/// Sends a transaction sent to the API to be checked, and waits to hear
/// how it went.
pub async fn submit(submit: &Submit, raw: Vec<u8>) -> Result<Hash, Reject> {
    let (reply_tx, reply) = tokio::sync::oneshot::channel();
    match submit.try_send((raw, Source::Api(reply_tx))) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(_)) => return Err(Reject::new(-28, "too busy, try again")),
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Err(Reject::new(-28, "shutting down")),
    }
    reply.await.unwrap_or_else(|_| Err(Reject::new(-28, "shutting down")))
}

/// Takes the write lock once it's free, without waiting in line for it,
/// which would keep readers waiting behind.
fn write(shared: &Shared) -> std::sync::RwLockWriteGuard<'_, Mempool> {
    loop {
        match shared.try_write() {
            Ok(guard) => return guard,
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
            Err(std::sync::TryLockError::Poisoned(err)) => panic!("the mempool's lock is poisoned: {err}"),
        }
    }
}

/// Checks and adds a transaction that arrived at `time`, counting how it
/// went.
fn accept(shared: &Shared, store: &Store, raw: Vec<u8>, time: u64) -> Result<Hash, Reject> {
    let result = loop {
        let checked = shared.read().unwrap().check(store, raw.clone(), time);
        match checked {
            Ok(checked) => {
                if let Some(result) = write(shared).add(checked) {
                    break result;
                }
            }
            Err(reject) => break Err(reject),
        }
    };
    count(shared, &result);
    result
}

fn count(shared: &Shared, result: &Result<Hash, Reject>) {
    let mut mempool = write(shared);
    match result {
        Ok(_) => mempool.stats.accepted += 1,
        Err(reject) => {
            let reason = reject.reason.split(" (").next().unwrap_or_default().to_string();
            *mempool.stats.refused.entry(reason).or_default() += 1;
        }
    }
}

/// Transactions to ask peers for: of the one given, or of any.
pub type Want = (Option<PeerId>, Vec<Hash>);

const SAVED_MAGIC: &[u8; 8] = b"BDXMEMP1";
/// How often the mempool is saved.
const SAVE_EVERY: Duration = Duration::from_secs(600);
/// Orphans kept, at most, and for how long: enough for a whole mempool's
/// chains, fetched in no particular order, as a bootstrap fetches them.
const MAX_ORPHANS: usize = 100_000;
const MAX_ORPHAN_BYTES: usize = 100 << 20;
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
    store: Arc<Store>,
    relay: tokio::sync::mpsc::Sender<Vec<u8>>,
    wants: tokio::sync::mpsc::UnboundedSender<Want>,
    orphans: Orphans,
    /// Transactions refused, by wtxid, until the chain moves on.
    refused: HashSet<Hash>,
    refused_at: Option<Hash>,
}

impl Checker {
    /// Checks a transaction, and then any orphans it lets in, and theirs.
    fn submit(&mut self, raw: Vec<u8>, source: Source, time: u64) {
        let mut queue = vec![(raw, source, time)];
        while let Some((raw, source, time)) = queue.pop() {
            let tip = self.store.tip().map(|(_, record)| record.hash());
            if self.refused_at != tip || self.refused.len() >= MAX_REFUSED {
                self.refused.clear();
                self.refused_at = tip;
            }
            let wtxid = crate::hash::sha256d(&raw);
            let result = if self.refused.contains(&wtxid) {
                let result = Err(Reject::new(-26, "refused already"));
                count(&self.mempool, &result);
                result
            } else {
                let result = accept(&self.mempool, &self.store, raw.clone(), time);
                if let Err(reject) = &result
                    && !reject.may_pass_later()
                {
                    self.refused.insert(wtxid);
                }
                result
            };
            let from = match source {
                Source::Api(reply) => {
                    if result.is_ok() {
                        let _ = self.relay.try_send(raw.clone());
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
                    let parents = self.mempool.read().unwrap().missing_parents(&self.store, &raw);
                    let Ok(tx) = parse_tx(&raw) else { continue };
                    if !parents.is_empty() && self.orphans.add(tx.txid, raw.clone(), from, parents.clone()) {
                        write(&self.mempool).stats.orphaned += 1;
                        let _ = self.wants.send((from, parents));
                    }
                }
                Err(reject) => tracing::trace!("refused a transaction: {reject}"),
            }
            write(&self.mempool).stats.orphans = self.orphans.len();
        }
    }

    /// Catches up with the store, checking everything again after a reorg.
    fn sync(&mut self) {
        let Some(txs) = write(&self.mempool).sync(&self.store) else { return };
        let count = txs.len();
        let kept = txs
            .into_iter()
            .filter(|(time, raw)| accept(&self.mempool, &self.store, raw.clone(), *time).is_ok())
            .count();
        tracing::info!("the chain changed: kept {kept} of {count} unconfirmed transactions");
    }

    /// Figures the summary again, if the mempool's changed.
    fn summarize(&self) {
        let summary = {
            let mempool = self.mempool.read().unwrap();
            mempool.summarize().map(|s| (s, mempool.generation))
        };
        if let Some((summary, generation)) = summary {
            let mut mempool = write(&self.mempool);
            mempool.summary = Arc::new(summary);
            mempool.summary_generation = generation;
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
    store: Arc<Store>,
    relay: tokio::sync::mpsc::Sender<Vec<u8>>,
    wants: tokio::sync::mpsc::UnboundedSender<Want>,
    saved: Option<PathBuf>,
) -> Submit {
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, Source)>(QUEUE);
    let mut checker = Checker {
        mempool,
        store,
        relay,
        wants,
        orphans: Orphans::default(),
        refused: HashSet::new(),
        refused_at: None,
    };
    std::thread::Builder::new()
        .name("mempool".into())
        .spawn(move || {
            let mut to_load = saved.clone().filter(|path| path.exists());
            let mut last_save = Instant::now();
            let mut last_summary = Instant::now();
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
                        checker.sync();
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
                checker.sync();
                // A new block may hold an orphan's parents.
                let now_tip = checker.store.tip().map(|(height, record)| (height, record.hash()));
                if now_tip != tip {
                    tip = now_tip;
                    for orphan in checker.orphans.take_all() {
                        checker.submit(orphan.raw, Source::Peer(orphan.from), now());
                    }
                }
                checker.orphans.expire();
                if last_summary.elapsed() >= Duration::from_secs(1) {
                    last_summary = Instant::now();
                    checker.summarize();
                }
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
    fn standard_outputs_and_dust() {
        let p2pkh = hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap();
        let p2wpkh = hex::decode("00140000000000000000000000000000000000000000").unwrap();
        assert_eq!(dust_threshold(&p2pkh), 546);
        assert_eq!(dust_threshold(&p2wpkh), 294);
        assert_eq!(dust_threshold(&[0x6a, 0x01, 0x00]), 0);
        assert!(is_standard_output(&p2pkh));
        assert!(is_standard_output(&p2wpkh));
        assert!(is_standard_output(&[0x51, 0x02, 0x4e, 0x73]));
        assert!(is_standard_output(&[0x6a]));
        assert!(!is_standard_output(&[0x51]));
        assert!(!is_standard_output(&[]));
    }

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
            mempool.by_seq.insert(mempool.seq, txid);
        }
        mempool.save(&path).unwrap();
        assert_eq!(load(&path).unwrap(), vec![(1000, vec![1, 2, 3]), (1001, vec![4; 300])]);
        std::fs::write(&path, b"BDXMEMP1\x01").unwrap();
        assert!(load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
