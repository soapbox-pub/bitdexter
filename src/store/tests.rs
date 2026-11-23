//! Connecting blocks built here, valid and not, to a store, both ways of
//! indexing.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Witness,
};

use super::*;
use crate::block::parse_block;
use crate::validate::check_block;

/// `OP_2 OP_EQUAL`: spent by a script pushing 2.
fn puzzle() -> ScriptBuf {
    Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_2)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script()
}

struct TestChain {
    blocks: Vec<Block>,
}

impl TestChain {
    fn new() -> TestChain {
        TestChain { blocks: vec![bitcoin::constants::genesis_block(bitcoin::Network::Regtest)] }
    }

    fn coinbase(&self, height: u32) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(height as i64).push_int(0).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: puzzle() }],
        }
    }

    /// A block on the tip with these transactions after its coinbase.
    fn block(&self, txs: Vec<Transaction>) -> Block {
        let height = self.blocks.len() as u32;
        let prev = self.blocks.last().unwrap();
        let mut txdata = vec![self.coinbase(height)];
        txdata.extend(txs);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: prev.header.time + 600,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    /// A transaction spending block `height`'s coinbase with `script_sig`.
    fn spend(&self, height: usize, script_sig: ScriptBuf, lock_time: u32) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: OutPoint { txid: self.blocks[height].txdata[0].compute_txid(), vout: 0 },
                script_sig,
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(49 * 100_000_000), script_pubkey: puzzle() }],
        }
    }
}

fn connect(writer: &mut Writer, block: &Block, verify: bool) -> std::result::Result<(), String> {
    let raw = serialize(block);
    let parsed = parse_block(&raw).unwrap();
    check_block(&parsed, writer.next_height(), Chain::Regtest).map_err(|e| e.0)?;
    writer.connect(&parsed, verify).map_err(|err| match err {
        ConnectError::Invalid(invalid) => invalid.0,
        ConnectError::Io(err) => panic!("{err:#}"),
    })
}

fn rejects_bad_scripts(bulk: bool) {
    let dir = std::env::temp_dir().join(format!("bitdexter-store-{}-{bulk}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut writer = Store::open(&dir, Chain::Regtest).unwrap();
    let mut chain = TestChain::new();
    connect(&mut writer, &chain.blocks[0], true).unwrap();
    if bulk {
        writer.begin_bulk().unwrap();
    }
    for _ in 0..101 {
        let block = chain.block(vec![]);
        connect(&mut writer, &block, true).unwrap();
        chain.blocks.push(block);
    }
    let two = Builder::new().push_int(2).into_script();
    let three = Builder::new().push_int(3).into_script();

    // A spend whose script fails is refused when scripts are verified (and
    // taken when they aren't, as below the assumevalid block: see below).
    let bad = chain.block(vec![chain.spend(1, three.clone(), 0)]);
    assert_eq!(connect(&mut writer, &bad, true).unwrap_err(), "mandatory-script-verify-flag-failed");
    assert_eq!(writer.next_height(), 102);
    // A spend that isn't final yet is refused either way.
    let locked = chain.block(vec![chain.spend(1, two.clone(), 1000)]);
    assert_eq!(connect(&mut writer, &locked, false).unwrap_err(), "bad-txns-nonfinal");
    // A coinbase too young to spend.
    let young = chain.block(vec![chain.spend(100, two.clone(), 0)]);
    assert_eq!(connect(&mut writer, &young, true).unwrap_err(), "bad-txns-premature-spend-of-coinbase");
    // After all that, a good spend goes in, and a double spend of it doesn't.
    let good = chain.block(vec![chain.spend(1, two.clone(), 0)]);
    connect(&mut writer, &good, true).unwrap();
    chain.blocks.push(good);
    let double = chain.block(vec![chain.spend(1, two.clone(), 0)]);
    assert_eq!(connect(&mut writer, &double, true).unwrap_err(), "bad-txns-inputs-missingorspent");
    let unverified = chain.block(vec![chain.spend(2, three, 0)]);
    connect(&mut writer, &unverified, false).unwrap();
    chain.blocks.push(unverified);

    if bulk {
        writer.finish_bulk().unwrap();
    }
    writer.commit().unwrap();
    let store = writer.store.clone();
    let snapshot = store.snapshot();
    assert_eq!(snapshot.blocks, 104);
    let spent = chain.blocks[1].txdata[0].compute_txid();
    let txnum = store.txnum(&spent.to_byte_array()).unwrap();
    let outnum = store.tx_bytes(txnum, &snapshot).1;
    let spender = store.output(outnum, &snapshot).1.unwrap();
    assert_eq!(store.txid(spender), chain.blocks[102].txdata[1].compute_txid().to_byte_array());
    assert_eq!(BlockHash::from_byte_array(store.block(103).unwrap().hash()), chain.blocks[103].block_hash());
    drop(writer);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rejects_bad_blocks_in_place() {
    rejects_bad_scripts(false);
}

#[test]
fn rejects_bad_blocks_in_bulk() {
    rejects_bad_scripts(true);
}

/// A store is opened by one process at a time; and one left dirty while
/// its last block was being taken off, with that block's spends unmarked
/// but the block still committed, has them marked again when reopened.
#[test]
fn locks_and_recovers_a_disconnect_cut_short() {
    let dir = std::env::temp_dir().join(format!("bitdexter-store-{}-recover", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut writer = Store::open(&dir, Chain::Regtest).unwrap();
    assert!(Store::open(&dir, Chain::Regtest).is_err(), "opened twice");
    let mut chain = TestChain::new();
    connect(&mut writer, &chain.blocks[0], true).unwrap();
    for _ in 0..101 {
        let block = chain.block(vec![]);
        connect(&mut writer, &block, true).unwrap();
        chain.blocks.push(block);
    }
    let good = chain.block(vec![chain.spend(1, Builder::new().push_int(2).into_script(), 0)]);
    connect(&mut writer, &good, true).unwrap();
    writer.commit().unwrap();

    let store = writer.store.clone();
    let snapshot = store.snapshot();
    let spent = store.txnum(&chain.blocks[1].txdata[0].compute_txid().to_byte_array()).unwrap();
    let outnum = store.tx_bytes(spent, &snapshot).1;
    assert!(store.output(outnum, &snapshot).1.is_some());
    // What `disconnect_tip` does before it commits, then a crash.
    writer.mark_dirty().unwrap();
    writer.outs.set(outnum, VALUE_BYTES, &[0; 5]);
    writer.outs.sync().unwrap();
    drop((writer, store));

    let writer = Store::open(&dir, Chain::Regtest).unwrap();
    let snapshot = writer.store.snapshot();
    assert_eq!(snapshot.blocks, 103);
    let spender = writer.store.output(outnum, &snapshot).1.expect("the spend marked again");
    assert_eq!(writer.store.txid(spender), good.txdata[1].compute_txid().to_byte_array());
    drop(writer);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A store in format 3, whose txid table was keyed by txids' first bytes,
/// is brought up to date as it's opened: the table's built again, under
/// a secret, and everything's found as before.
#[test]
fn brings_format_3_up_to_date() {
    let dir = std::env::temp_dir().join(format!("bitdexter-store-{}-format3", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut writer = Store::open(&dir, Chain::Regtest).unwrap();
    let mut chain = TestChain::new();
    connect(&mut writer, &chain.blocks[0], true).unwrap();
    for _ in 0..5 {
        let block = chain.block(vec![]);
        connect(&mut writer, &block, true).unwrap();
        chain.blocks.push(block);
    }
    writer.commit().unwrap();
    drop(writer);

    // As format 3 left it: its state says so, and there's no secret.
    {
        let env = lmdb::Env::open(&dir.join("index"), 1 << 30, 4).unwrap();
        let meta = env.create_db("meta", false).unwrap();
        let mut txn = env.write_txn().unwrap();
        let mut state = txn.get(meta, b"state").unwrap().unwrap().to_vec();
        state[..4].copy_from_slice(&FORMAT_UNKEYED.to_le_bytes());
        txn.put(meta, b"state", &state, false).unwrap();
        txn.del(meta, b"txid key", None).unwrap();
        txn.commit().unwrap();
    }

    let writer = Store::open(&dir, Chain::Regtest).unwrap();
    for (height, block) in chain.blocks.iter().enumerate() {
        let txid = block.txdata[0].compute_txid().to_byte_array();
        let txnum = writer.store.txnum(&txid).expect("found after the table's built again");
        assert_eq!(writer.store.tx_height(txnum), height as u32);
    }
    let keyer = writer.store.table().keyer();
    drop(writer);
    // Reopened, it's format 4, with the same secret.
    let writer = Store::open(&dir, Chain::Regtest).unwrap();
    assert_eq!(writer.store.table().keyer(), keyer);
    assert_eq!(writer.state.encode()[..4], FORMAT.to_le_bytes());
    drop(writer);
    std::fs::remove_dir_all(&dir).unwrap();
}
