//! Verifying a block's scripts with libbitcoinkernel, Bitcoin Core's own
//! script interpreter, on several threads.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitcoinkernel::{PrecomputedTransactionData, ScriptPubkey, Transaction, TxOut, verify};

/// A transaction to verify: its raw bytes, and the script and value of each
/// output its inputs spend.
pub struct TxCheck<'a> {
    pub raw: &'a [u8],
    pub spent: Vec<(Vec<u8>, u64)>,
}

fn check_tx(check: &TxCheck<'_>, flags: u32) -> Result<(), String> {
    let tx = Transaction::new(check.raw).map_err(|err| format!("parsing: {err}"))?;
    let scripts: Vec<ScriptPubkey> = check
        .spent
        .iter()
        .map(|(script, _)| ScriptPubkey::new(script).map_err(|err| format!("{err}")))
        .collect::<Result<_, _>>()?;
    let outs: Vec<TxOut> =
        scripts.iter().zip(&check.spent).map(|(script, (_, value))| TxOut::new(script, *value as i64)).collect();
    let data = PrecomputedTransactionData::new(&tx, &outs).map_err(|err| format!("{err}"))?;
    for (index, (script, (_, value))) in scripts.iter().zip(&check.spent).enumerate() {
        verify(script, Some(*value as i64), &tx, index, Some(flags), &data)
            .map_err(|err| format!("input {index}: {err}"))?;
    }
    Ok(())
}

/// How many threads verify scripts.
pub fn threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(8)
}

/// Verifies every input of every transaction, with `flags`. On failure,
/// says which transaction (by its index in `checks`) and why.
pub fn verify_scripts(checks: &[TxCheck<'_>], flags: u32) -> Result<(), (usize, String)> {
    if checks.is_empty() {
        return Ok(());
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let failure = Mutex::new(None);
    let workers = threads().min(checks.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while !failed.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(check) = checks.get(i) else { break };
                    if let Err(reason) = check_tx(check, flags) {
                        failed.store(true, Ordering::Relaxed);
                        let mut failure = failure.lock().unwrap();
                        if failure.as_ref().is_none_or(|(j, _)| i < *j) {
                            *failure = Some((i, reason));
                        }
                    }
                }
            });
        }
    });
    match failure.into_inner().unwrap() {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP143's native P2WPKH example: its second input spends a P2WPKH
    /// output of 6 BTC; its first, a P2PK output of 6.25 BTC.
    const TX: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    const P2PK: &str = "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac";
    const P2WPKH: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";

    #[test]
    fn verifies_bip143_example() {
        let raw = hex::decode(TX).unwrap();
        let spent = vec![(hex::decode(P2PK).unwrap(), 625_000_000), (hex::decode(P2WPKH).unwrap(), 600_000_000)];
        let flags = bitcoinkernel::VERIFY_ALL_PRE_TAPROOT;
        let result = verify_scripts(&[TxCheck { raw: &raw, spent: spent.clone() }], flags);
        assert!(result.is_ok(), "{result:?}");
        // The wrong amount for the segwit input fails its signature.
        let mut wrong = spent.clone();
        wrong[1].1 += 1;
        let err =
            verify_scripts(&[TxCheck { raw: &raw, spent: spent.clone() }, TxCheck { raw: &raw, spent: wrong }], flags)
                .unwrap_err();
        assert_eq!(err.0, 1);
        assert!(err.1.starts_with("input 1"), "{}", err.1);
    }
}
