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

/// Which of a coinbase's outputs is its witness commitment, if it has one:
/// the last whose script begins `OP_RETURN 0xaa21a9ed`.
fn witness_commitment_index(block: &Block<'_>) -> Option<usize> {
    block.txs[0]
        .outputs
        .iter()
        .rposition(|out| out.script.len() >= 38 && out.script[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
}

/// The witness commitment a coinbase carries, if it has one.
fn witness_commitment(block: &Block<'_>) -> Option<Hash> {
    witness_commitment_index(block).map(|i| block.txs[0].outputs[i].script[6..38].try_into().unwrap())
}

/// The challenge the default signet's blocks are signed to.
const SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
/// What a signet block's solution, in its witness commitment's script,
/// begins with.
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// A script push as Bitcoin Core's `CScript << vector` writes it.
fn push(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        n if n < 0x4c => script.push(n as u8),
        n if n <= 0xff => script.extend_from_slice(&[0x4c, n as u8]),
        n if n <= 0xffff => {
            script.push(0x4d);
            script.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n => {
            script.push(0x4e);
            script.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

/// Whether a signet block is signed to the signet's challenge, as BIP325
/// and Bitcoin Core's `CheckSignetBlockSolution` have it: its solution,
/// a scriptSig and witness in its witness commitment's script, must spend
/// an output paying the challenge, in a transaction committing to the
/// block's header but for its nonce, and to its transactions but for the
/// solution itself.
fn check_signet(block: &Block<'_>) -> Result<(), Invalid> {
    use bitcoin::consensus::{deserialize, deserialize_partial, serialize};
    use bitcoin::hashes::Hash as _;
    let bad = || Invalid("bad-signet-blksig".into());
    let challenge = hex::decode(SIGNET_CHALLENGE).unwrap();
    let index = witness_commitment_index(block).ok_or_else(bad)?;
    let mut coinbase: bitcoin::Transaction = deserialize(block.txs[0].raw).map_err(|_| bad())?;

    // The commitment's script with the solution taken out, but its header.
    let script = coinbase.output[index].script_pubkey.clone();
    let mut cleared = Vec::with_capacity(script.len());
    let mut solution = None;
    for instruction in script.instructions() {
        match instruction {
            Ok(bitcoin::script::Instruction::PushBytes(data)) if !data.is_empty() => {
                let data = data.as_bytes();
                if solution.is_none() && data.len() > 4 && data[..4] == SIGNET_HEADER {
                    solution = Some(data[4..].to_vec());
                    push(&mut cleared, &SIGNET_HEADER);
                } else {
                    push(&mut cleared, data);
                }
            }
            Ok(bitcoin::script::Instruction::PushBytes(_)) => cleared.push(0x00),
            Ok(bitcoin::script::Instruction::Op(op)) => cleared.push(op.to_u8()),
            // As Core's `GetOp`, which stops at what it can't read.
            Err(_) => break,
        }
    }
    let (script_sig, witness) = match &solution {
        Some(solution) => {
            coinbase.output[index].script_pubkey = bitcoin::ScriptBuf::from_bytes(cleared);
            let (script_sig, read): (bitcoin::ScriptBuf, usize) = deserialize_partial(solution).map_err(|_| bad())?;
            let witness: bitcoin::Witness = deserialize(&solution[read..]).map_err(|_| bad())?;
            (script_sig, witness)
        }
        // No solution: a challenge of OP_TRUE needs none.
        None => (bitcoin::ScriptBuf::new(), bitcoin::Witness::new()),
    };
    let mut txids: Vec<Hash> = vec![coinbase.compute_txid().to_byte_array()];
    txids.extend(block.txs[1..].iter().map(|tx| tx.txid));
    let (root, _) = merkle_root(txids);

    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&block.header[..36]);
    block_data.extend_from_slice(&root);
    block_data.extend_from_slice(&block.header[68..72]);
    let mut to_spend_sig = vec![0x00];
    push(&mut to_spend_sig, &block_data);
    let version = bitcoin::transaction::Version(0);
    let to_spend = bitcoin::Transaction {
        version,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(to_spend_sig),
            sequence: bitcoin::Sequence(0),
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(challenge.clone()),
        }],
    };
    let to_sign = bitcoin::Transaction {
        version,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid: to_spend.compute_txid(), vout: 0 },
            script_sig,
            sequence: bitcoin::Sequence(0),
            witness,
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x6a]),
        }],
    };
    use bitcoinkernel::{VERIFY_DERSIG, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_WITNESS};
    let raw = serialize(&to_sign);
    let check = crate::verify::TxCheck { raw: &raw, spent: vec![(challenge, 0)] };
    crate::verify::verify_scripts(&[check], VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DERSIG | VERIFY_NULLDUMMY)
        .map_err(|_| bad())
}

/// Whether a block's transactions, and their witnesses if it has any, are
/// the ones its header commits to: what can be checked of a block as it
/// arrives, before its height is known. A block that isn't was mutated by
/// whoever sent it, which says nothing of the block itself.
pub fn check_commitments(block: &Block<'_>) -> Result<(), Invalid> {
    let txs = &block.txs;
    let (root, mutated) = merkle_root(txs.iter().map(|tx| tx.txid).collect());
    if root != block.merkle_root() {
        return invalid("bad-txnmrklroot");
    }
    if mutated {
        return invalid("bad-txns-duplicate");
    }
    if txs.iter().any(|tx| tx.segwit) {
        let Some(commitment) = witness_commitment(block) else { return invalid("unexpected-witness") };
        check_witness_commitment(block, &commitment)?;
    }
    Ok(())
}

/// Whether a block's witnesses are the ones its coinbase commits to.
fn check_witness_commitment(block: &Block<'_>, commitment: &Hash) -> Result<(), Invalid> {
    let txs = &block.txs;
    let reserved = txs[0].inputs[0].witness;
    // One item of 32 bytes: its count, its length, then it.
    if reserved.len() != 34 || reserved[0] != 1 || reserved[1] != 32 {
        return invalid("bad-witness-nonce-size");
    }
    let mut wtxids: Vec<Hash> = txs.iter().map(|tx| tx.wtxid).collect();
    wtxids[0] = [0; 32];
    let (witness_root, _) = merkle_root(wtxids);
    if sha256d_parts(&[&witness_root, &reserved[2..]]) != *commitment {
        return invalid("bad-witness-merkle-match");
    }
    Ok(())
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
        Some(commitment) => check_witness_commitment(block, &commitment)?,
        None if has_witness => return invalid("unexpected-witness"),
        None => {}
    }
    // Only now are the witnesses known to be the block's own.
    if block.weight() > MAX_BLOCK_WEIGHT {
        return invalid("bad-blk-weight");
    }
    if chain == Chain::Signet && height > 0 {
        check_signet(block)?;
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

    #[test]
    fn signet_blocks_are_signed() {
        // Signet's block 320000.
        let hex = "000000202d51e000d104850303b6f93c5370fd55b17d5d6bbfe8c20d39b5579a090000000e5d287f01635babb099fe5e3b930eb6a25774831124a9f49b914a5c7e54f2927f38946ac2c0131dd6b76b1301020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0f0300e2040a2f7369676e65743a332ffeffffff0200f90295000000001600141ebfbc64c4d28f44c7afac95df51b1281986e6de0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa249004730440220195df67cbc3b424d9e982888aab19e01e03ae7b45ae0b239a165fd2ca034b3360220345cca661f703a205de0c905eb6355b610c2f1c295a23f0ae3c34833720b6759010001200000000000000000000000000000000000000000000000000000000000000000ffe10400";
        let raw = hex::decode(hex).unwrap();
        check_block(&parse_block(&raw).unwrap(), 320_000, Chain::Signet).unwrap();
        // The signature covers the header's time; not its nonce, which the
        // signer grinds afterwards.
        let mut nonce = raw.clone();
        nonce[76] ^= 1;
        check_signet(&parse_block(&nonce).unwrap()).unwrap();
        let mut time = raw.clone();
        time[68] ^= 1;
        assert_eq!(check_signet(&parse_block(&time).unwrap()).unwrap_err().0, "bad-signet-blksig");
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
