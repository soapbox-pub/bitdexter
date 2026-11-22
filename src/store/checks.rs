//! The checks of a block that need what its inputs spend, gathered as its
//! inputs are resolved, either way of indexing: lock times, relative lock
//! times, sigop cost, and, above the assumevalid block, scripts.

use super::writer::Writer;
use super::{ConnectError, reject};
use crate::block::{Block, Tx};
use crate::consensus::{self, MAX_BLOCK_SIGOPS_COST, ScriptClass};
use crate::verify::{TxCheck, verify_scripts};

pub(super) struct Checks<'b> {
    height: u32,
    flags: u32,
    /// Whether relative lock times, and BIP113's lock time cutoff, apply.
    csv: bool,
    /// The previous block's median time past.
    mtp: u32,
    /// What a lock time that's a time is compared with.
    cutoff: u32,
    sigops: u64,
    verify: bool,
    scripts: Vec<TxCheck<'b>>,
    heights: Vec<u32>,
    classes: Vec<ScriptClass>,
    spent: Vec<(Vec<u8>, u64)>,
}

impl<'b> Checks<'b> {
    pub fn new(writer: &Writer, block: &Block<'b>, height: u32, verify: bool) -> Checks<'b> {
        let chain = writer.store.chain;
        let csv = height >= chain.csv_height();
        let mtp = if height > 0 { writer.mtp(height - 1) } else { 0 };
        Checks {
            height,
            flags: consensus::script_flags(chain, height, &block.hash()),
            csv,
            mtp,
            cutoff: if csv { mtp } else { block.time() },
            sigops: 0,
            verify,
            scripts: Vec::new(),
            heights: Vec::new(),
            classes: Vec::new(),
            spent: Vec::new(),
        }
    }

    /// Whether the scripts of the outputs spent are needed.
    pub fn wants_scripts(&self) -> bool {
        self.verify
    }

    /// Notes what an input of the transaction being connected spends: the
    /// height of its block, its class, value, and, if wanted, script.
    pub fn input(&mut self, height: u32, class: ScriptClass, value: u64, script: Option<Vec<u8>>) {
        self.heights.push(height);
        self.classes.push(class);
        if let Some(script) = script {
            self.spent.push((script, value));
        }
    }

    /// Checks a transaction whose inputs have all been noted.
    pub fn tx(&mut self, writer: &Writer, tx: &Tx<'b>) -> Result<(), ConnectError> {
        let result = self.check_tx(writer, tx);
        self.heights.clear();
        self.classes.clear();
        self.spent.clear();
        result
    }

    fn check_tx(&mut self, writer: &Writer, tx: &Tx<'b>) -> Result<(), ConnectError> {
        if !consensus::is_final(tx, self.height, self.cutoff) {
            return reject("bad-txns-nonfinal");
        }
        if !tx.is_coinbase()
            && self.csv
            && !consensus::sequence_locks_pass(tx, &self.heights, self.height, self.mtp, |h| writer.mtp(h))
        {
            return reject("bad-txns-nonfinal");
        }
        self.sigops += consensus::sigop_cost(tx, &self.classes, self.flags);
        if self.sigops > MAX_BLOCK_SIGOPS_COST {
            return reject("bad-blk-sigops");
        }
        if self.verify && !tx.is_coinbase() {
            self.scripts.push(TxCheck { raw: tx.raw, spent: std::mem::take(&mut self.spent) });
        }
        Ok(())
    }

    /// Verifies the scripts of every transaction checked.
    pub fn finish(self, block: &Block<'b>) -> Result<(), ConnectError> {
        if let Err((index, reason)) = verify_scripts(&self.scripts, self.flags) {
            // The coinbase isn't verified, so the index is one off.
            let txid = crate::hash::to_hex_rev(&block.txs[index + 1].txid);
            tracing::warn!("transaction {txid} fails script verification: {reason}");
            return reject("mandatory-script-verify-flag-failed");
        }
        Ok(())
    }
}
