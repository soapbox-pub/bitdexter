//! The checks on a block that need nothing but the block, its height and
//! its network: Bitcoin Core's `CheckBlock`, and the parts of
//! `ContextualCheckBlock` that don't need the chain's state. What needs the
//! outputs being spent (that they exist, are unspent and mature, and that
//! no coins are made) is checked as the block is indexed, in the store.

use std::collections::HashSet;

use crate::block::Block;
use crate::hash::{Hash, merkle_root, sha256d_parts};
use crate::network::Chain;

pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
pub const COINBASE_MATURITY: u32 = 100;

/// Why a block is invalid, in Bitcoin Core's words where it has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

fn invalid<T>(reason: &str) -> Result<T, Invalid> {
    Err(Invalid(reason.to_string()))
}

/// The push of a block's height that BIP34 requires a coinbase's script
/// to begin with, as `CScript() << height` writes it.
pub fn height_push(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut num = Vec::new();
            let mut n = height;
            while n > 0 {
                num.push((n & 0xff) as u8);
                n >>= 8;
            }
            if num.last().unwrap() & 0x80 != 0 {
                num.push(0);
            }
            let mut push = vec![num.len() as u8];
            push.extend_from_slice(&num);
            push
        }
    }
}

/// The witness commitment a coinbase carries, if it has one: the last of
/// its outputs whose script begins `OP_RETURN 0xaa21a9ed`.
fn witness_commitment(block: &Block<'_>) -> Option<Hash> {
    block.txs[0]
        .outputs
        .iter()
        .rev()
        .find(|out| out.script.len() >= 38 && out.script[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
        .map(|out| out.script[6..38].try_into().unwrap())
}

/// Checks a block, in Bitcoin Core's order: first that its transactions
/// and their witnesses are the ones its header commits to, so that a peer
/// can't make a good block look bad by sending it with transactions added,
/// left out or padded (those are all "mutations", which say nothing about
/// the block itself), and only then everything else.
pub fn check_block(block: &Block<'_>, height: u32, chain: Chain) -> Result<(), Invalid> {
    let txs = &block.txs;
    // No transactions give a root of zeros, which no header commits to.
    let (root, mutated) = merkle_root(txs.iter().map(|tx| tx.txid).collect());
    if root != block.merkle_root() {
        return invalid("bad-txnmrklroot");
    }
    if mutated {
        return invalid("bad-txns-duplicate");
    }
    if txs.is_empty() || block.base_size() * 4 > MAX_BLOCK_WEIGHT {
        return invalid("bad-blk-length");
    }

    if !txs[0].is_coinbase() {
        return invalid("bad-cb-missing");
    }
    if txs[1..].iter().any(|tx| tx.is_coinbase()) {
        return invalid("bad-cb-multiple");
    }
    let script_sig = txs[0].inputs[0].script_sig;
    if script_sig.len() < 2 || script_sig.len() > 100 {
        return invalid("bad-cb-length");
    }
    if height >= chain.params().bip34_height && !script_sig.starts_with(&height_push(height)) {
        return invalid("bad-cb-height");
    }

    for tx in txs {
        if tx.inputs.is_empty() {
            return invalid("bad-txns-vin-empty");
        }
        if tx.outputs.is_empty() {
            return invalid("bad-txns-vout-empty");
        }
        if tx.base_size * 4 > MAX_BLOCK_WEIGHT {
            return invalid("bad-txns-oversize");
        }
        let mut total = 0u64;
        for out in &tx.outputs {
            if out.value > MAX_MONEY {
                return invalid("bad-txns-vout-toolarge");
            }
            total += out.value;
            if total > MAX_MONEY {
                return invalid("bad-txns-txouttotal-toolarge");
            }
        }
        if tx.inputs.len() > 1 {
            let mut seen = HashSet::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                if !seen.insert((input.prev_txid, input.prev_vout)) {
                    return invalid("bad-txns-inputs-duplicate");
                }
            }
        }
        if !tx.is_coinbase() && tx.inputs.iter().any(|input| input.is_null_prevout()) {
            return invalid("bad-txns-prevout-null");
        }
    }

    let has_witness = txs.iter().any(|tx| tx.segwit);
    let commitment = if height >= chain.segwit_height() { witness_commitment(block) } else { None };
    match commitment {
        Some(commitment) => {
            let reserved = txs[0].inputs[0].witness;
            // One item of 32 bytes: its count, its length, then it.
            if reserved.len() != 34 || reserved[0] != 1 || reserved[1] != 32 {
                return invalid("bad-witness-nonce-size");
            }
            let mut wtxids: Vec<Hash> = txs.iter().map(|tx| tx.wtxid).collect();
            wtxids[0] = [0; 32];
            let (witness_root, _) = merkle_root(wtxids);
            if sha256d_parts(&[&witness_root, &reserved[2..]]) != commitment {
                return invalid("bad-witness-merkle-match");
            }
        }
        None if has_witness => return invalid("unexpected-witness"),
        None => {}
    }
    // Only now are the witnesses known to be the block's own.
    if block.weight() > MAX_BLOCK_WEIGHT {
        return invalid("bad-blk-weight");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::parse_block;

    #[test]
    fn height_pushes_like_core() {
        assert_eq!(height_push(1), vec![0x51]);
        assert_eq!(height_push(16), vec![0x60]);
        assert_eq!(height_push(17), vec![0x01, 0x11]);
        assert_eq!(height_push(127), vec![0x01, 0x7f]);
        assert_eq!(height_push(128), vec![0x02, 0x80, 0x00]);
        // Block 227931, where BIP34 activated on mainnet.
        assert_eq!(height_push(227_931), vec![0x03, 0x5b, 0x7a, 0x03]);
    }

    #[test]
    fn genesis_passes() {
        for chain in [Chain::Mainnet, Chain::Testnet4, Chain::Signet, Chain::Regtest] {
            let block = bitcoin::constants::genesis_block(chain.network());
            let raw = bitcoin::consensus::serialize(&block);
            check_block(&parse_block(&raw).unwrap(), 0, chain).unwrap();
        }
    }

    /// A good block sent with its transactions left out or padded past the
    /// size limit fails as mutated, not as too small or too big, which
    /// would mark the block itself invalid.
    #[test]
    fn emptied_or_padded_blocks_are_mutated() {
        use bitcoin::hashes::Hash as _;
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin);
        let raw = bitcoin::consensus::serialize(&block);

        let mut empty = raw[..80].to_vec();
        empty.push(0);
        let err = check_block(&parse_block(&empty).unwrap(), 0, Chain::Mainnet).unwrap_err();
        assert_eq!(err.0, "bad-txnmrklroot");

        let mut padded = block.clone();
        let junk = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([1; 32]), vout: 0 },
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x6a; 500_000]),
            }],
        };
        padded.txdata.extend(std::iter::repeat_n(junk, 3));
        let raw = bitcoin::consensus::serialize(&padded);
        let err = check_block(&parse_block(&raw).unwrap(), 0, Chain::Mainnet).unwrap_err();
        assert_eq!(err.0, "bad-txnmrklroot");
    }
}
