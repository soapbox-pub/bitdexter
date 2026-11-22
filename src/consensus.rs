//! The consensus rules checked as a block is connected that need the outputs
//! it spends but not their scripts: sigop cost (BIP141), lock times (BIP113)
//! and relative lock times (BIP68). Bitcoin Core checks these on every
//! block, even below its assumevalid block, and so does bitdexter.
//!
//! What sigops an input costs depends on the kind of script it spends, so
//! each output's [`ScriptClass`] is kept with it, rather than its script.

use bitcoin::Script;

use crate::block::Tx;
use crate::network::Chain;

pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
const WITNESS_SCALE: u64 = 4;
const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const SEQUENCE_DISABLE: u32 = 1 << 31;
const SEQUENCE_TYPE_TIME: u32 = 1 << 22;
const SEQUENCE_MASK: u32 = 0xffff;

/// The script verification flags Bitcoin Core applies to a block, as its
/// `GetBlockScriptFlags` decides them, in libbitcoinkernel's terms.
pub fn script_flags(chain: Chain, height: u32, hash: &[u8; 32]) -> u32 {
    use bitcoinkernel::{
        VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY,
        VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
    };
    let params = chain.params();
    let mut flags = match chain.script_flag_exception(hash) {
        Some(ScriptException::None) => VERIFY_NONE,
        Some(ScriptException::P2shWitness) => VERIFY_P2SH | VERIFY_WITNESS,
        None => VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT,
    };
    if height >= params.bip66_height {
        flags |= VERIFY_DERSIG;
    }
    if height >= params.bip65_height {
        flags |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= chain.csv_height() {
        flags |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= chain.segwit_height() {
        flags |= VERIFY_NULLDUMMY;
    }
    flags
}

/// The two blocks that broke rules enforced on every block now, and the
/// rules they're held to instead.
pub enum ScriptException {
    None,
    P2shWitness,
}

/// What kind of script an output has, as far as sigops go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScriptClass {
    Other = 0,
    P2sh = 1,
    /// Witness version 0, a 20-byte program.
    P2wpkh = 2,
    /// Witness version 0, a 32-byte program.
    P2wsh = 3,
    /// Any other witness program.
    Witness = 4,
}

impl ScriptClass {
    pub fn of(script: &[u8]) -> ScriptClass {
        let script = Script::from_bytes(script);
        if script.is_p2sh() {
            ScriptClass::P2sh
        } else if let Some(class) = witness_class(script) {
            class
        } else {
            ScriptClass::Other
        }
    }

    pub fn from_bits(bits: u8) -> ScriptClass {
        match bits {
            1 => ScriptClass::P2sh,
            2 => ScriptClass::P2wpkh,
            3 => ScriptClass::P2wsh,
            4 => ScriptClass::Witness,
            _ => ScriptClass::Other,
        }
    }
}

/// The class of a witness program, if `script` is one.
fn witness_class(script: &Script) -> Option<ScriptClass> {
    let version = script.witness_version()?;
    let program_len = script.len() - 2;
    Some(match (version.to_num(), program_len) {
        (0, 20) => ScriptClass::P2wpkh,
        (0, 32) => ScriptClass::P2wsh,
        _ => ScriptClass::Witness,
    })
}

/// The sigops a witness program costs to spend, as Core's `WitnessSigOps`.
fn witness_sigops(class: ScriptClass, witness: &[&[u8]]) -> u64 {
    match class {
        ScriptClass::P2wpkh => 1,
        ScriptClass::P2wsh => witness.last().map_or(0, |script| Script::from_bytes(script).count_sigops() as u64),
        _ => 0,
    }
}

/// The last data a push-only script pushes, as Core reads a P2SH redeem
/// script; `None` if it isn't push-only.
fn last_push(script_sig: &[u8]) -> Option<Vec<u8>> {
    let script = Script::from_bytes(script_sig);
    if !script.is_push_only() {
        return None;
    }
    Some(crate::script::last_push(script_sig).unwrap_or_default())
}

/// A transaction's sigop cost, as Core's `GetTransactionSigOpCost`, given
/// the class of each output its inputs spend.
pub fn sigop_cost(tx: &Tx<'_>, spent: &[ScriptClass], flags: u32) -> u64 {
    use bitcoinkernel::{VERIFY_P2SH, VERIFY_WITNESS};
    let legacy: usize = tx.inputs.iter().map(|i| Script::from_bytes(i.script_sig).count_sigops_legacy()).sum::<usize>()
        + tx.outputs.iter().map(|o| Script::from_bytes(o.script).count_sigops_legacy()).sum::<usize>();
    let mut cost = legacy as u64 * WITNESS_SCALE;
    if tx.is_coinbase() {
        return cost;
    }
    for (input, &class) in tx.inputs.iter().zip(spent) {
        let redeem = if class == ScriptClass::P2sh { last_push(input.script_sig) } else { None };
        if flags & VERIFY_P2SH != 0
            && let Some(redeem) = &redeem
        {
            cost += Script::from_bytes(redeem).count_sigops() as u64 * WITNESS_SCALE;
        }
        if flags & VERIFY_WITNESS != 0 {
            let witness = crate::compact::witness_items(input.witness);
            let program = match class {
                ScriptClass::P2sh => redeem.as_deref().and_then(|r| witness_class(Script::from_bytes(r))),
                ScriptClass::Other => None,
                class => Some(class),
            };
            if let Some(program) = program {
                cost += witness_sigops(program, &witness);
            }
        }
    }
    cost
}

/// Whether a transaction is final in a block at `height`, its lock time
/// compared with `cutoff` if it's a time (BIP113's median time past, once
/// it's active).
pub fn is_final(tx: &Tx<'_>, height: u32, cutoff: u32) -> bool {
    if tx.locktime == 0 {
        return true;
    }
    let limit = if tx.locktime < LOCKTIME_THRESHOLD { height } else { cutoff };
    tx.locktime < limit || tx.inputs.iter().all(|i| i.sequence == SEQUENCE_FINAL)
}

/// Whether a transaction's relative lock times (BIP68) have passed in a
/// block at `height` whose previous block's median time past is `mtp`.
/// `spent_heights` are the heights of the blocks holding the outputs it
/// spends, and `mtp_at` gives any block's median time past.
pub fn sequence_locks_pass(
    tx: &Tx<'_>,
    spent_heights: &[u32],
    height: u32,
    mtp: u32,
    mut mtp_at: impl FnMut(u32) -> u32,
) -> bool {
    if tx.version < 2 {
        return true;
    }
    let mut min_height: i64 = -1;
    let mut min_time: i64 = -1;
    for (input, &coin_height) in tx.inputs.iter().zip(spent_heights) {
        if input.sequence & SEQUENCE_DISABLE != 0 {
            continue;
        }
        let value = (input.sequence & SEQUENCE_MASK) as i64;
        if input.sequence & SEQUENCE_TYPE_TIME != 0 {
            let coin_time = mtp_at(coin_height.saturating_sub(1)) as i64;
            min_time = min_time.max(coin_time + (value << 9) - 1);
        } else {
            min_height = min_height.max(coin_height as i64 + value - 1);
        }
    }
    min_height < height as i64 && min_time < mtp as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::parse_tx;

    #[test]
    fn classes() {
        assert_eq!(
            ScriptClass::of(&[0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87]),
            ScriptClass::P2sh
        );
        assert_eq!(ScriptClass::of(&[&[0x00, 0x14][..], &[7; 20]].concat()), ScriptClass::P2wpkh);
        assert_eq!(ScriptClass::of(&[&[0x00, 0x20][..], &[7; 32]].concat()), ScriptClass::P2wsh);
        assert_eq!(ScriptClass::of(&[&[0x51, 0x20][..], &[7; 32]].concat()), ScriptClass::Witness);
        assert_eq!(ScriptClass::of(&[0x51, 0x02, 0x4e, 0x73]), ScriptClass::Witness);
        assert_eq!(ScriptClass::of(&[0x76, 0xa9]), ScriptClass::Other);
        for class in
            [ScriptClass::Other, ScriptClass::P2sh, ScriptClass::P2wpkh, ScriptClass::P2wsh, ScriptClass::Witness]
        {
            assert_eq!(ScriptClass::from_bits(class as u8), class);
        }
    }

    #[test]
    fn sigops_of_a_p2wpkh_spend() {
        // BIP143's P2WPKH example: one legacy P2PK input, one P2WPKH input,
        // two P2PKH outputs.
        let hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
        let raw = hex::decode(hex).unwrap();
        let tx = parse_tx(&raw).unwrap();
        let flags = script_flags(Chain::Mainnet, 900_000, &[0; 32]);
        // Two P2PKH outputs, a sigop each, times four, and the P2WPKH spend's one.
        assert_eq!(sigop_cost(&tx, &[ScriptClass::Other, ScriptClass::P2wpkh], flags), 2 * 4 + 1);
    }

    #[test]
    fn finality_and_sequence_locks() {
        let hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
        let raw = hex::decode(hex).unwrap();
        let mut tx = parse_tx(&raw).unwrap();
        // Lock time 17, one input not final: final from block 18.
        assert!(!is_final(&tx, 17, 0));
        assert!(is_final(&tx, 18, 0));
        // Version 1 has no relative lock times.
        assert!(sequence_locks_pass(&tx, &[100, 100], 101, 0, |_| 0));
        tx.version = 2;
        // The first input's sequence, 0xffffffee, has the disable bit set;
        // the second's, 0xffffffff, too.
        assert!(sequence_locks_pass(&tx, &[100, 100], 101, 0, |_| 0));
        tx.inputs[0].sequence = 10;
        assert!(!sequence_locks_pass(&tx, &[100, 100], 109, 0, |_| 0));
        assert!(sequence_locks_pass(&tx, &[100, 100], 110, 0, |_| 0));
        tx.inputs[0].sequence = SEQUENCE_TYPE_TIME | 2;
        // Two 512-second units after the coin's block's predecessor's MTP.
        assert!(!sequence_locks_pass(&tx, &[100, 100], 200, 1000 + 1023, |_| 1000));
        assert!(sequence_locks_pass(&tx, &[100, 100], 200, 1000 + 1024, |_| 1000));
    }
}
