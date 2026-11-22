//! Silent payments (BIP352): the public tweak data of a transaction, which
//! a light wallet combines with its own scan key to find payments to it,
//! without giving the server anything that would reveal them.
//!
//! A transaction's tweak is `input_hash · A`, where `A` is the sum of the
//! public keys its eligible inputs reveal, and `input_hash` a tagged hash of
//! its smallest outpoint and `A`. Only transactions with a taproot output can
//! pay a silent payment address, so only theirs are computed.

use std::sync::OnceLock;

use bitcoin::hashes::{Hash as _, hash160, sha256};
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, VerifyOnly, XOnlyPublicKey};

use crate::hash::Hash;
use crate::network::Chain;
use crate::store::{Snapshot, Store};

/// The first block that could hold a silent payment: taproot's activation.
pub fn first_height(chain: Chain) -> u32 {
    match chain {
        Chain::Mainnet => 709_632,
        _ => 0,
    }
}

/// The tweaks of block `height`'s transactions that have them, with their
/// numbers. Computed once and cached by block hash.
pub fn block_tweaks(store: &Store, height: u32, snapshot: &Snapshot) -> anyhow::Result<Vec<(u64, [u8; 33])>> {
    let record = store.block(height).ok_or_else(|| anyhow::anyhow!("no block {height}"))?;
    if height < first_height(store.chain) {
        return Ok(Vec::new());
    }
    let hash = record.hash();
    let decode = |bytes: &[u8]| {
        bytes
            .chunks_exact(37)
            .map(|c| {
                (record.first_tx + u32::from_le_bytes(c[..4].try_into().unwrap()) as u64, c[4..].try_into().unwrap())
            })
            .collect()
    };
    if let Some(cached) = store.cached_tweaks(&hash)? {
        return Ok(decode(&cached));
    }
    let mut packed = Vec::new();
    let count = store.tx_count(height, snapshot);
    // The coinbase can't have one.
    for txnum in record.first_tx + 1..record.first_tx + count {
        let tx = store.tx(txnum, snapshot)?;
        if !tx.outputs.iter().any(|out| is_p2tr(&out.script)) {
            continue;
        }
        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let outnum = input.spent.expect("a transaction past the coinbase spends outputs");
            let (prev, vout) = store.outpoint(outnum, snapshot);
            prevouts.push((store.txid(prev), vout, store.output_script(outnum, snapshot)?.1));
        }
        let inputs: Vec<Input<'_>> = tx
            .inputs
            .iter()
            .zip(&prevouts)
            .map(|(input, (txid, vout, script))| Input {
                prev_txid: *txid,
                prev_vout: *vout,
                script_sig: input.script_sig,
                witness: input.witness_items(),
                prevout: script,
            })
            .collect();
        if let Some(tweak) = tweak(&inputs) {
            packed.extend_from_slice(&((txnum - record.first_tx) as u32).to_le_bytes());
            packed.extend_from_slice(&tweak);
        }
    }
    store.cache_tweaks(&hash, &packed)?;
    Ok(decode(&packed))
}

/// The taproot internal key with no known private key, which a script-path
/// spend uses to show there's no key path.
const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a,
    0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn secp() -> &'static Secp256k1<VerifyOnly> {
    static SECP: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::verification_only)
}

/// An input, with what it spends.
pub struct Input<'a> {
    pub prev_txid: Hash,
    pub prev_vout: u32,
    pub script_sig: &'a [u8],
    pub witness: Vec<&'a [u8]>,
    /// The script of the output it spends.
    pub prevout: &'a [u8],
}

pub fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// The public key an input reveals for silent payments, if it reveals one.
/// `Err` if it makes the whole transaction ineligible, by spending a
/// witness program of a version above 1.
fn input_key(input: &Input<'_>) -> Result<Option<PublicKey>, ()> {
    let spk = input.prevout;
    let compressed = |key: &[u8]| {
        (key.len() == 33 && (key[0] == 2 || key[0] == 3)).then(|| PublicKey::from_slice(key).ok()).flatten()
    };
    if is_p2tr(spk) {
        let mut items = input.witness.as_slice();
        if items.len() > 1 && items.last().is_some_and(|annex| annex.first() == Some(&0x50)) {
            items = &items[..items.len() - 1];
        }
        // A script-path spend from the provably unspendable internal key.
        if items.len() > 1 && items.last().is_some_and(|control| control.len() >= 33 && control[1..33] == NUMS) {
            return Ok(None);
        }
        let key = XOnlyPublicKey::from_slice(&spk[2..]).map_err(|_| ())?;
        return Ok(Some(key.public_key(Parity::Even)));
    }
    match spk {
        // P2WPKH: the key is the witness's last item.
        [0x00, 0x14, ..] if spk.len() == 22 => Ok(input.witness.last().and_then(|key| compressed(key))),
        // P2SH-P2WPKH: likewise, if the redeem script is a P2WPKH program.
        [0xa9, 0x14, .., 0x87] if spk.len() == 23 => {
            let wrapped = input.script_sig.len() == 23 && input.script_sig[..3] == [0x16, 0x00, 0x14];
            Ok(if wrapped { input.witness.last().and_then(|key| compressed(key)) } else { None })
        }
        // P2PKH: the last 33-byte push in the script whose hash is the one paid.
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if spk.len() == 25 => {
            let script_sig = input.script_sig;
            if script_sig.len() < 34 {
                return Ok(None);
            }
            for i in (0..=script_sig.len() - 34).rev() {
                if script_sig[i] == 33 {
                    let key = &script_sig[i + 1..i + 34];
                    if hash160::Hash::hash(key).as_byte_array()[..] == spk[3..23] {
                        return Ok(compressed(key));
                    }
                }
            }
            Ok(None)
        }
        // A witness program of version 2 to 16.
        [0x52..=0x60, len, ..] if (2..=40).contains(len) && spk.len() == *len as usize + 2 => Err(()),
        _ => Ok(None),
    }
}

/// A BIP340-style tagged hash.
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    bitcoin::hashes::HashEngine::input(&mut engine, tag.as_byte_array());
    bitcoin::hashes::HashEngine::input(&mut engine, tag.as_byte_array());
    bitcoin::hashes::HashEngine::input(&mut engine, data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// A transaction's tweak, compressed, from all its inputs; `None` if it has
/// none (no eligible inputs, or keys that cancel out).
pub fn tweak(inputs: &[Input<'_>]) -> Option<[u8; 33]> {
    let mut keys = Vec::with_capacity(inputs.len());
    for input in inputs {
        match input_key(input) {
            Ok(Some(key)) => keys.push(key),
            Ok(None) => {}
            Err(()) => return None,
        }
    }
    if keys.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let sum = PublicKey::combine_keys(&refs).ok()?;
    let smallest = inputs
        .iter()
        .map(|i| {
            let mut outpoint = [0u8; 36];
            outpoint[..32].copy_from_slice(&i.prev_txid);
            outpoint[32..].copy_from_slice(&i.prev_vout.to_le_bytes());
            outpoint
        })
        .min()?;
    let mut data = [0u8; 69];
    data[..36].copy_from_slice(&smallest);
    data[36..].copy_from_slice(&sum.serialize());
    let input_hash = Scalar::from_be_bytes(tagged_hash("BIP0352/Inputs", &data)).ok()?;
    Some(sum.mul_tweak(secp(), &input_hash).ok()?.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::from_hex_rev;

    /// BIP352's own test vectors: every receiving case's expected tweak.
    #[test]
    fn matches_bip352_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip352_send_and_receive_test_vectors.json")).unwrap();
        let mut checked = 0;
        for case in vectors.as_array().unwrap() {
            for receiving in case["receiving"].as_array().unwrap() {
                let vin = receiving["given"]["vin"].as_array().unwrap();
                type Parts = (Hash, u32, Vec<u8>, Vec<u8>, Vec<u8>);
                let parts: Vec<Parts> = vin
                    .iter()
                    .map(|i| {
                        (
                            from_hex_rev(i["txid"].as_str().unwrap()).unwrap(),
                            i["vout"].as_u64().unwrap() as u32,
                            hex::decode(i["scriptSig"].as_str().unwrap()).unwrap(),
                            hex::decode(i["txinwitness"].as_str().unwrap()).unwrap(),
                            hex::decode(i["prevout"]["scriptPubKey"]["hex"].as_str().unwrap()).unwrap(),
                        )
                    })
                    .collect();
                let inputs: Vec<Input<'_>> = parts
                    .iter()
                    .map(|(txid, vout, script_sig, witness, prevout)| Input {
                        prev_txid: *txid,
                        prev_vout: *vout,
                        script_sig,
                        witness: crate::compact::witness_items(witness),
                        prevout,
                    })
                    .collect();
                let expected = receiving["expected"]["tweak"].as_str().filter(|t| !t.is_empty());
                let ours = tweak(&inputs).map(hex::encode);
                assert_eq!(ours.as_deref(), expected, "{}", case["comment"]);
                checked += 1;
            }
        }
        assert!(checked >= 25, "{checked}");
    }
}
