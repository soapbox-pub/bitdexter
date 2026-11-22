//! Every block header bitdexter has accepted, forks too, and which chain of
//! them has the most work.
//!
//! A header is accepted only if it connects to one already known and is
//! valid in its place: it has the proof of work its difficulty requires,
//! the difficulty the chain before it calls for, a time after the median of
//! the eleven before it and not more than two hours ahead, and a version
//! the soft forks of its height allow. Accepted headers are appended to a
//! file, and checked again as they're read back.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Target};

use crate::network::Chain;

const NONE: u32 = u32::MAX;
const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;
/// How far before its parent the first block of a period may be, on
/// networks that rule out the timewarp attack (BIP94).
const MAX_TIMEWARP: u32 = 600;

pub struct Entry {
    pub header: Header,
    pub hash: BlockHash,
    pub height: u32,
    parent: u32,
    /// The chain's work up to and including this header.
    pub work: u128,
    invalid: bool,
}

#[derive(Debug)]
pub enum HeaderError {
    /// It doesn't connect to any header known.
    Orphan,
    /// It's invalid, and the peer that sent it misbehaved.
    Invalid(&'static str),
    /// It's too far ahead of the clock, for now.
    TooNew,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::Orphan => f.write_str("doesn't connect to a known header"),
            HeaderError::Invalid(reason) => f.write_str(reason),
            HeaderError::TooNew => f.write_str("time-too-new"),
        }
    }
}

pub struct HeaderChain {
    chain: Chain,
    entries: Vec<Entry>,
    by_hash: HashMap<BlockHash, u32>,
    /// The best chain, by height.
    best: Vec<u32>,
    file: Option<File>,
}

fn work_of(header: &Header) -> u128 {
    let bytes = header.work().to_le_bytes();
    u128::from_le_bytes(bytes[..16].try_into().unwrap())
}

fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

impl HeaderChain {
    pub fn new(chain: Chain) -> HeaderChain {
        let genesis = bitcoin::constants::genesis_block(chain.network()).header;
        let hash = genesis.block_hash();
        let entry = Entry { header: genesis, hash, height: 0, parent: NONE, work: work_of(&genesis), invalid: false };
        HeaderChain { chain, entries: vec![entry], by_hash: HashMap::from([(hash, 0)]), best: vec![0], file: None }
    }

    /// The headers saved at `path`, checked again, and saving those
    /// accepted from now on there.
    pub fn open(chain: Chain, path: &Path) -> Result<HeaderChain> {
        let mut headers = HeaderChain::new(chain);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut good = 0;
        for raw in bytes.as_chunks::<80>().0 {
            let header: Header = deserialize(raw)?;
            match headers.accept_one(header, false) {
                Ok(_) => good += 80,
                Err(err) => {
                    tracing::warn!("dropping saved headers from {} on: {err}", headers.entries.len());
                    break;
                }
            }
        }
        if good != bytes.len() {
            file.set_len(good as u64)?;
        }
        headers.file = Some(file);
        Ok(headers)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn tip_height(&self) -> u32 {
        (self.best.len() - 1) as u32
    }

    pub fn tip(&self) -> &Entry {
        &self.entries[*self.best.last().unwrap() as usize]
    }

    /// The best chain's header at `height`.
    pub fn at(&self, height: u32) -> Option<&Entry> {
        self.best.get(height as usize).map(|&id| &self.entries[id as usize])
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&Entry> {
        self.by_hash.get(hash).map(|&id| &self.entries[id as usize])
    }

    pub fn is_best(&self, hash: &BlockHash) -> bool {
        self.get(hash).is_some_and(|entry| self.at(entry.height).is_some_and(|best| best.hash == *hash))
    }

    /// Hashes of the best chain going back, densely and then
    /// exponentially, to the genesis block, for `getheaders`.
    pub fn locator(&self) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let mut height = self.tip_height() as i64;
        let mut step = 1;
        while height > 0 {
            hashes.push(self.at(height as u32).unwrap().hash);
            if hashes.len() >= 10 {
                step *= 2;
            }
            height -= step;
        }
        hashes.push(self.at(0).unwrap().hash);
        hashes
    }

    /// Entry `id`'s ancestor at `height`.
    fn ancestor(&self, mut id: u32, height: u32) -> u32 {
        loop {
            let entry = &self.entries[id as usize];
            if entry.height == height {
                return id;
            }
            if self.best.get(entry.height as usize) == Some(&id) {
                return self.best[height as usize];
            }
            id = entry.parent;
        }
    }

    /// The median time of entry `id` and the ten before it.
    fn median_time_past(&self, mut id: u32) -> u32 {
        let mut times = Vec::with_capacity(11);
        while id != NONE && times.len() < 11 {
            let entry = &self.entries[id as usize];
            times.push(entry.header.time);
            id = entry.parent;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// The difficulty a block after entry `parent_id` at `time` must have,
    /// as Bitcoin Core's `GetNextWorkRequired` decides it.
    fn next_bits(&self, parent_id: u32, time: u32) -> CompactTarget {
        let params = self.chain.params();
        let parent = &self.entries[parent_id as usize];
        let interval = (params.pow_target_timespan / params.pow_target_spacing) as u32;
        let height = parent.height + 1;
        let pow_limit = params.max_attainable_target.to_compact_lossy();
        if !height.is_multiple_of(interval) {
            if params.allow_min_difficulty_blocks {
                // A block more than twice the spacing after the last may be
                // at the lowest difficulty; others have that of the last block
                // that wasn't.
                if time as u64 > parent.header.time as u64 + 2 * params.pow_target_spacing {
                    return pow_limit;
                }
                let mut id = parent_id;
                loop {
                    let entry = &self.entries[id as usize];
                    if entry.parent == NONE || entry.height.is_multiple_of(interval) || entry.header.bits != pow_limit {
                        return entry.header.bits;
                    }
                    id = entry.parent;
                }
            }
            return parent.header.bits;
        }
        if params.no_pow_retargeting {
            return parent.header.bits;
        }
        let first = &self.entries[self.ancestor(parent_id, height - interval) as usize];
        let timespan = parent.header.time.saturating_sub(first.header.time) as u64;
        let base = if self.chain.enforces_bip94() { first.header.bits } else { parent.header.bits };
        CompactTarget::from_next_work_required(base, timespan, params)
    }

    fn check(&self, header: &Header, parent_id: u32, check_clock: bool) -> Result<(), HeaderError> {
        let params = self.chain.params();
        let parent = &self.entries[parent_id as usize];
        if parent.invalid {
            return Err(HeaderError::Invalid("bad-prevblk"));
        }
        let height = parent.height + 1;
        if header.bits != self.next_bits(parent_id, header.time) {
            return Err(HeaderError::Invalid("bad-diffbits"));
        }
        let target = Target::from_compact(header.bits);
        if target > params.max_attainable_target || target == Target::ZERO {
            return Err(HeaderError::Invalid("bad-diffbits"));
        }
        if !target.is_met_by(header.block_hash()) {
            return Err(HeaderError::Invalid("high-hash"));
        }
        if header.time <= self.median_time_past(parent_id) {
            return Err(HeaderError::Invalid("time-too-old"));
        }
        let interval = (params.pow_target_timespan / params.pow_target_spacing) as u32;
        if self.chain.enforces_bip94()
            && height.is_multiple_of(interval)
            && header.time < parent.header.time.saturating_sub(MAX_TIMEWARP)
        {
            return Err(HeaderError::Invalid("time-timewarp-attack"));
        }
        if check_clock && header.time > now() + MAX_FUTURE_BLOCK_TIME {
            return Err(HeaderError::TooNew);
        }
        let version = header.version.to_consensus();
        if (version < 2 && height >= params.bip34_height)
            || (version < 3 && height >= params.bip66_height)
            || (version < 4 && height >= params.bip65_height)
        {
            return Err(HeaderError::Invalid("bad-version"));
        }
        Ok(())
    }

    /// Accepts one header, returning whether it's new.
    fn accept_one(&mut self, header: Header, check_clock: bool) -> Result<bool, HeaderError> {
        let hash = header.block_hash();
        if let Some(&id) = self.by_hash.get(&hash) {
            return if self.entries[id as usize].invalid {
                Err(HeaderError::Invalid("duplicate-invalid"))
            } else {
                Ok(false)
            };
        }
        let &parent_id = self.by_hash.get(&header.prev_blockhash).ok_or(HeaderError::Orphan)?;
        self.check(&header, parent_id, check_clock)?;
        let parent = &self.entries[parent_id as usize];
        let entry = Entry {
            header,
            hash,
            height: parent.height + 1,
            parent: parent_id,
            work: parent.work + work_of(&header),
            invalid: false,
        };
        let id = self.entries.len() as u32;
        let better = entry.work > self.tip().work;
        self.entries.push(entry);
        self.by_hash.insert(hash, id);
        if better {
            self.set_best(id);
        }
        Ok(true)
    }

    /// Makes the chain ending at `id` the best.
    fn set_best(&mut self, id: u32) {
        let height = self.entries[id as usize].height as usize;
        self.best.truncate(height + 1);
        self.best.resize(height + 1, NONE);
        let mut at = id;
        loop {
            let entry = &self.entries[at as usize];
            let h = entry.height as usize;
            if self.best[h] == at {
                break;
            }
            self.best[h] = at;
            if entry.parent == NONE {
                break;
            }
            at = entry.parent;
        }
    }

    /// Accepts headers in order, saving those that are new. Returns how
    /// many were, and stops at the first that isn't valid.
    pub fn accept(&mut self, headers: &[Header]) -> Result<usize, HeaderError> {
        let mut new = 0;
        let mut result = Ok(());
        for header in headers {
            match self.accept_one(*header, true) {
                Ok(true) => {
                    new += 1;
                    if let Some(file) = &mut self.file
                        && let Err(err) = file.write_all(&serialize(header))
                    {
                        tracing::error!("saving a header failed: {err}");
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }
        result.map(|()| new)
    }

    /// Marks the header `hash` and every header after it invalid, as a
    /// block that's turned out to be, and finds the best chain left.
    pub fn mark_invalid(&mut self, hash: &BlockHash) {
        let Some(&bad) = self.by_hash.get(hash) else { return };
        // Children always come after their parents, so one pass finds every
        // descendant.
        self.entries[bad as usize].invalid = true;
        for id in bad as usize + 1..self.entries.len() {
            let parent = self.entries[id].parent;
            if parent != NONE && self.entries[parent as usize].invalid {
                self.entries[id].invalid = true;
            }
        }
        let best = (0..self.entries.len())
            .filter(|&id| !self.entries[id].invalid)
            .max_by(|&a, &b| self.entries[a].work.cmp(&self.entries[b].work).then(b.cmp(&a)))
            .unwrap_or(0);
        self.best.clear();
        self.set_best(best as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    /// Mines a regtest header on `prev`, at the lowest difficulty.
    fn mine(prev: &Header, time: u32) -> Header {
        let mut header = Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([7; 32]),
            time,
            bits: prev.bits,
            nonce: 0,
        };
        let target = Target::from_compact(header.bits);
        while !target.is_met_by(header.block_hash()) {
            header.nonce += 1;
        }
        header
    }

    #[test]
    fn follows_most_work_and_marks_invalid() {
        let mut chain = HeaderChain::new(Chain::Regtest);
        let genesis = chain.tip().header;
        let mut a = vec![mine(&genesis, genesis.time + 1)];
        for i in 0..5 {
            let next = mine(a.last().unwrap(), genesis.time + 2 + i);
            a.push(next);
        }
        assert_eq!(chain.accept(&a).unwrap(), 6);
        assert_eq!(chain.tip_height(), 6);
        // A shorter fork doesn't win; a longer one does.
        let mut b = vec![mine(&a[1], genesis.time + 100)];
        for i in 0..5 {
            let next = mine(b.last().unwrap(), genesis.time + 101 + i);
            b.push(next);
        }
        chain.accept(&b[..3]).unwrap();
        assert_eq!(chain.tip().hash, a[5].block_hash());
        chain.accept(&b[3..]).unwrap();
        assert_eq!(chain.tip_height(), 8);
        assert_eq!(chain.tip().hash, b[5].block_hash());
        assert!(chain.is_best(&a[1].block_hash()));
        assert!(!chain.is_best(&a[2].block_hash()));
        // Invalidating the fork goes back to the first chain.
        chain.mark_invalid(&b[0].block_hash());
        assert_eq!(chain.tip().hash, a[5].block_hash());
        assert!(matches!(chain.accept(&[mine(&b[5], genesis.time + 200)]), Err(HeaderError::Invalid(_))));
        // Locators start at the tip and end at genesis.
        let locator = chain.locator();
        assert_eq!(locator[0], a[5].block_hash());
        assert_eq!(*locator.last().unwrap(), genesis.block_hash());
    }

    #[test]
    fn refuses_bad_headers() {
        let mut chain = HeaderChain::new(Chain::Regtest);
        let genesis = chain.tip().header;
        let mut early = mine(&genesis, genesis.time);
        early.time = genesis.time;
        assert!(matches!(chain.accept(&[early]), Err(HeaderError::Invalid(_))));
        let mut orphan = mine(&genesis, genesis.time + 1);
        orphan.prev_blockhash = BlockHash::from_byte_array([9; 32]);
        assert!(matches!(chain.accept(&[orphan]), Err(HeaderError::Orphan)));
    }

    #[test]
    fn mainnet_retarget_matches() {
        // The first retarget on mainnet, at height 32256, from bits 1d00ffff
        // to 1d00d86a; between 30240 and 32255 the period took this long.
        let params = Chain::Mainnet.params();
        let first_time = 1_261_130_161u32; // block 30240
        let last_time = 1_262_152_739u32; // block 32255
        let bits = CompactTarget::from_next_work_required(
            CompactTarget::from_consensus(0x1d00ffff),
            (last_time - first_time) as u64,
            params,
        );
        assert_eq!(bits.to_consensus(), 0x1d00d86a);
    }
}
