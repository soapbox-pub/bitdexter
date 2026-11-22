//! The Esplora HTTP API, as Blockstream's electrs serves it and
//! mempool.space extends it: see
//! <https://github.com/Blockstream/esplora/blob/master/API.md>.

use std::collections::{HashMap, HashSet};
use std::sync::RwLockReadGuard;

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bitcoin::Network;
use serde_json::{Value, json};

use super::{ApiError, AppState, blocking};
use crate::compact::CompactTx;
use crate::hash::{Hash, from_hex_rev, merkle_branch, to_hex_rev};
use crate::mempool::{Entry, Mempool, Source};
use crate::script;
use crate::store::{Snapshot, Store};

/// Transactions in a page of a block's or an address's.
const PAGE: usize = 25;
/// Blocks in a page of `/blocks`.
const BLOCKS_PAGE: u32 = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/blocks/tip/height", get(tip_height))
        .route("/blocks/tip/hash", get(tip_hash))
        .route("/blocks", get(blocks_latest))
        .route("/blocks/{start}", get(blocks_from))
        .route("/block-height/{height}", get(block_at_height))
        .route("/block/{hash}", get(block))
        .route("/block/{hash}/header", get(block_header))
        .route("/block/{hash}/status", get(block_status))
        .route("/block/{hash}/txids", get(block_txids))
        .route("/block/{hash}/txs", get(block_txs_first))
        .route("/block/{hash}/txs/{start}", get(block_txs))
        .route("/block/{hash}/txid/{index}", get(block_txid))
        .route("/block/{hash}/raw", get(block_raw))
        .route("/tx/{txid}", get(tx))
        .route("/tx/{txid}/hex", get(tx_hex))
        .route("/tx/{txid}/raw", get(tx_raw))
        .route("/tx/{txid}/status", get(tx_status))
        .route("/tx/{txid}/outspend/{vout}", get(tx_outspend))
        .route("/tx/{txid}/outspends", get(tx_outspends))
        .route("/tx/{txid}/merkle-proof", get(tx_merkle_proof))
        .route("/tx/{txid}/merkleblock-proof", get(tx_merkleblock_proof))
        .route("/address/{address}", get(address_stats))
        .route("/address/{address}/txs", get(address_txs))
        .route("/address/{address}/txs/chain", get(address_txs_chain_first))
        .route("/address/{address}/txs/chain/{last}", get(address_txs_chain))
        .route("/address/{address}/txs/mempool", get(address_txs_mempool))
        .route("/address/{address}/utxo", get(address_utxo))
        .route("/scripthash/{hash}", get(address_stats))
        .route("/scripthash/{hash}/txs", get(address_txs))
        .route("/scripthash/{hash}/txs/chain", get(address_txs_chain_first))
        .route("/scripthash/{hash}/txs/chain/{last}", get(address_txs_chain))
        .route("/scripthash/{hash}/txs/mempool", get(address_txs_mempool))
        .route("/scripthash/{hash}/utxo", get(address_utxo))
        .route("/tx", axum::routing::post(broadcast))
        .route("/mempool", get(mempool_info))
        .route("/mempool/txids", get(mempool_txids))
        .route("/mempool/recent", get(mempool_recent))
        .route("/fee-estimates", get(fee_estimates))
        .route("/v1/fees/recommended", get(fees_recommended))
}

/// The confirmation targets `/fee-estimates` gives rates for, as Esplora's.
const FEE_TARGETS: [u32; 28] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 144, 504, 1008];
/// The lowest rate, in sat/vB, a fee estimate gives.
pub(super) const FEE_FLOOR: f64 = 1.0;
/// Unconfirmed transactions in a page of an address's.
const MEMPOOL_PAGE: usize = 50;

/// A transaction, confirmed or not.
pub(super) enum Found<'m> {
    Confirmed(u64),
    Unconfirmed(&'m Entry),
}

/// What a request reads: the store as of one commit.
pub(super) struct Ctx<'a> {
    pub store: &'a Store,
    pub snap: Snapshot,
    pub network: Network,
    pub mempool: RwLockReadGuard<'a, Mempool>,
}

impl<'a> Ctx<'a> {
    pub fn new(state: &'a AppState) -> Ctx<'a> {
        Ctx {
            store: &state.store,
            snap: state.store.snapshot(),
            network: state.store.chain.network(),
            mempool: state.mempool.read().unwrap(),
        }
    }

    /// The transaction with `txid`, in a block or the mempool.
    pub fn find(&self, txid: &str) -> Result<Found<'_>, ApiError> {
        let hash = from_hex_rev(txid).ok_or_else(|| ApiError::bad_request("Invalid hex string"))?;
        if let Some(txnum) = self.store.txnum(&hash) {
            return Ok(Found::Confirmed(txnum));
        }
        self.mempool.get(&hash).map(Found::Unconfirmed).ok_or_else(|| ApiError::not_found("Transaction not found"))
    }

    pub fn tip(&self) -> Result<u32, ApiError> {
        self.snap.tip_height().ok_or_else(|| ApiError::not_found("No blocks indexed yet"))
    }

    pub fn block_height(&self, hash: &str) -> Result<u32, ApiError> {
        let hash = from_hex_rev(hash).ok_or_else(|| ApiError::bad_request("Invalid hex string"))?;
        self.store.height_of(&hash).ok_or_else(|| ApiError::not_found("Block not found"))
    }

    fn txnum(&self, txid: &str) -> Result<u64, ApiError> {
        let txid = from_hex_rev(txid).ok_or_else(|| ApiError::bad_request("Invalid hex string"))?;
        self.store.txnum(&txid).ok_or_else(|| ApiError::not_found("Transaction not found"))
    }

    pub fn tx(&self, txnum: u64) -> Result<CompactTx<'a>, ApiError> {
        Ok(self.store.tx(txnum, &self.snap)?)
    }

    /// The outpoint each input spends.
    pub fn prevouts(&self, tx: &CompactTx<'_>) -> Vec<(Hash, u32)> {
        tx.inputs
            .iter()
            .map(|input| match input.spent {
                Some(outnum) => {
                    let (txnum, vout) = self.store.outpoint(outnum, &self.snap);
                    (self.store.txid(txnum), vout)
                }
                None => ([0; 32], u32::MAX),
            })
            .collect()
    }

    pub fn raw_tx(&self, txnum: u64) -> Result<Vec<u8>, ApiError> {
        let tx = self.tx(txnum)?;
        Ok(tx.to_raw(&self.prevouts(&tx)))
    }

    pub fn mediantime(&self, height: u32) -> u32 {
        let mut times: Vec<u32> =
            (height.saturating_sub(10)..=height).filter_map(|h| self.store.block(h)).map(|b| b.time()).collect();
        times.sort_unstable();
        times[times.len() / 2]
    }

    fn status(&self, height: u32) -> Value {
        let block = self.store.block(height).expect("a block below the tip");
        json!({
            "confirmed": true,
            "block_height": height,
            "block_hash": to_hex_rev(&block.hash()),
            "block_time": block.time(),
        })
    }

    fn block_json(&self, height: u32) -> Value {
        let block = self.store.block(height).expect("a block below the tip");
        let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&block.header).expect("a header");
        let mut value = json!({
            "id": to_hex_rev(&block.hash()),
            "height": height,
            "version": header.version.to_consensus(),
            "timestamp": header.time,
            "tx_count": self.store.tx_count(height, &self.snap),
            "size": block.size,
            "weight": block.weight,
            "merkle_root": header.merkle_root.to_string(),
            "previousblockhash": header.prev_blockhash.to_string(),
            "mediantime": self.mediantime(height),
            "nonce": header.nonce,
            "bits": header.bits.to_consensus(),
            "difficulty": header.target().difficulty_float(),
        });
        if height == 0 {
            value["previousblockhash"] = Value::Null;
        }
        value
    }

    fn output_json(&self, value: u64, script_bytes: &[u8]) -> Value {
        let mut out = json!({
            "scriptpubkey": hex::encode(script_bytes),
            "scriptpubkey_asm": script::asm(script_bytes),
            "scriptpubkey_type": script::script_type(script_bytes),
            "scriptpubkey_address": null,
            "value": value,
        });
        match script::address(script_bytes, self.network) {
            Some(address) => out["scriptpubkey_address"] = json!(address),
            None => {
                out.as_object_mut().unwrap().remove("scriptpubkey_address");
            }
        }
        out
    }

    fn input_json(
        &self,
        prev_txid: &Hash,
        prev_vout: u32,
        script_sig: &[u8],
        witness: &[&[u8]],
        sequence: u32,
        prevout: Option<(u64, &[u8])>,
    ) -> Value {
        let mut item = json!({
            "txid": to_hex_rev(prev_txid),
            "vout": prev_vout,
            "prevout": null,
            "scriptsig": hex::encode(script_sig),
            "scriptsig_asm": script::asm(script_sig),
            "witness": witness.iter().map(hex::encode).collect::<Vec<_>>(),
            "is_coinbase": prevout.is_none(),
            "sequence": sequence,
        });
        if witness.is_empty() {
            item.as_object_mut().unwrap().remove("witness");
        }
        if let Some((value, script)) = prevout {
            item["prevout"] = self.output_json(value, script);
            inner_scripts(&mut item, script, script_sig, witness);
        }
        item
    }

    /// An unconfirmed transaction, as `tx_json` gives a confirmed one.
    fn entry_json(&self, entry: &Entry) -> Value {
        let tx = entry.tx();
        let vin: Vec<Value> = tx
            .inputs
            .iter()
            .zip(&entry.prevouts)
            .map(|(input, prevout)| {
                let witness = crate::compact::witness_items(input.witness);
                self.input_json(
                    &input.prev_txid,
                    input.prev_vout,
                    input.script_sig,
                    &witness,
                    input.sequence,
                    Some((prevout.value, &prevout.script)),
                )
            })
            .collect();
        let vout: Vec<Value> = tx.outputs.iter().map(|out| self.output_json(out.value, out.script)).collect();
        json!({
            "txid": to_hex_rev(&entry.txid),
            "version": tx.version,
            "locktime": tx.locktime,
            "vin": vin,
            "vout": vout,
            "size": entry.raw.len(),
            "weight": entry.weight,
            "fee": entry.fee,
            "status": { "confirmed": false },
        })
    }

    fn found_json(&self, found: &Found<'_>) -> Result<Value, ApiError> {
        match found {
            Found::Confirmed(txnum) => self.tx_json(*txnum),
            Found::Unconfirmed(entry) => Ok(self.entry_json(entry)),
        }
    }

    fn found_raw(&self, found: &Found<'_>) -> Result<Vec<u8>, ApiError> {
        match found {
            Found::Confirmed(txnum) => self.raw_tx(*txnum),
            Found::Unconfirmed(entry) => Ok(entry.raw.clone()),
        }
    }

    fn tx_json(&self, txnum: u64) -> Result<Value, ApiError> {
        let tx = self.tx(txnum)?;
        let prevouts = self.prevouts(&tx);
        let mut decoded: HashMap<u64, CompactTx<'a>> = HashMap::new();
        let mut value_in = 0u64;
        let mut vin = Vec::with_capacity(tx.inputs.len());
        for (input, (prev_txid, prev_vout)) in tx.inputs.iter().zip(&prevouts) {
            let witness = input.witness_items();
            let prevout = match input.spent {
                Some(outnum) => {
                    let (prev_txnum, vout) = self.store.outpoint(outnum, &self.snap);
                    if let std::collections::hash_map::Entry::Vacant(slot) = decoded.entry(prev_txnum) {
                        slot.insert(self.tx(prev_txnum)?);
                    }
                    let prev = &decoded[&prev_txnum].outputs[vout as usize];
                    value_in += prev.value;
                    Some((prev.value, prev.script.as_slice()))
                }
                None => None,
            };
            vin.push(self.input_json(prev_txid, *prev_vout, input.script_sig, &witness, input.sequence, prevout));
        }
        let vout: Vec<Value> = tx.outputs.iter().map(|out| self.output_json(out.value, &out.script)).collect();
        let value_out: u64 = tx.outputs.iter().map(|out| out.value).sum();
        let raw = tx.to_raw(&prevouts);
        let witness_bytes: usize = tx.inputs.iter().map(|input| input.witness.len()).sum();
        let base_size = if tx.segwit { raw.len() - 2 - witness_bytes } else { raw.len() };
        Ok(json!({
            "txid": to_hex_rev(&self.store.txid(txnum)),
            "version": tx.version,
            "locktime": tx.locktime,
            "vin": vin,
            "vout": vout,
            "size": raw.len(),
            "weight": base_size * 3 + raw.len(),
            "fee": if tx.coinbase { 0 } else { value_in - value_out },
            "status": self.status(self.store.tx_height(txnum)),
        }))
    }
}

/// The scripts an input reveals, beside its prevout's: a P2SH redeem
/// script, and a witness script (or tapscript).
fn inner_scripts(item: &mut Value, prevout: &[u8], script_sig: &[u8], witness: &[&[u8]]) {
    let prev = bitcoin::Script::from_bytes(prevout);
    let mut witness_script = None;
    if prev.is_p2sh()
        && let Some(redeem) = script::last_push(script_sig)
    {
        item["inner_redeemscript_asm"] = json!(script::asm(&redeem));
        if bitcoin::Script::from_bytes(&redeem).is_p2wsh() {
            witness_script = witness.last().copied();
        }
    } else if prev.is_p2wsh() {
        witness_script = witness.last().copied();
    } else if prev.is_p2tr() {
        // A script-path spend: the script, then the control block, then an
        // annex if the last item starts with 0x50.
        let mut items = witness;
        if items.len() >= 2 && items.last().is_some_and(|annex| annex.first() == Some(&0x50)) {
            items = &items[..items.len() - 1];
        }
        if items.len() >= 2 {
            witness_script = Some(items[items.len() - 2]);
        }
    }
    if let Some(witness_script) = witness_script {
        item["inner_witnessscript_asm"] = json!(script::asm(witness_script));
    }
}

fn text(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

fn binary(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response()
}

async fn tip_height(State(state): State<AppState>) -> Result<Response, ApiError> {
    blocking(move || Ok(text(Ctx::new(&state).tip()?.to_string()))).await
}

async fn tip_hash(State(state): State<AppState>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let tip = ctx.tip()?;
        Ok(text(to_hex_rev(&ctx.store.block(tip).unwrap().hash())))
    })
    .await
}

fn blocks_page(state: AppState, start: Option<u32>) -> Result<Response, ApiError> {
    let ctx = Ctx::new(&state);
    let tip = ctx.tip()?;
    let start = start.unwrap_or(tip).min(tip);
    let blocks: Vec<Value> = (0..=start).rev().take(BLOCKS_PAGE as usize).map(|h| ctx.block_json(h)).collect();
    Ok(Json(blocks).into_response())
}

async fn blocks_latest(State(state): State<AppState>) -> Result<Response, ApiError> {
    blocking(move || blocks_page(state, None)).await
}

async fn blocks_from(State(state): State<AppState>, Path(start): Path<String>) -> Result<Response, ApiError> {
    let start: u32 = start.parse().map_err(|_| ApiError::bad_request("Invalid height"))?;
    blocking(move || blocks_page(state, Some(start))).await
}

async fn block_at_height(State(state): State<AppState>, Path(height): Path<String>) -> Result<Response, ApiError> {
    let height: u32 = height.parse().map_err(|_| ApiError::bad_request("Invalid height"))?;
    blocking(move || {
        let ctx = Ctx::new(&state);
        let block = ctx.store.block(height).ok_or_else(|| ApiError::not_found("Block not found"))?;
        Ok(text(to_hex_rev(&block.hash())))
    })
    .await
}

async fn block(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let height = ctx.block_height(&hash)?;
        Ok(Json(ctx.block_json(height)).into_response())
    })
    .await
}

async fn block_header(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let height = ctx.block_height(&hash)?;
        Ok(text(hex::encode(ctx.store.block(height).unwrap().header)))
    })
    .await
}

async fn block_status(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let Ok(height) = ctx.block_height(&hash) else {
            return Ok(Json(json!({ "in_best_chain": false })).into_response());
        };
        let mut status = json!({ "in_best_chain": true, "height": height });
        if let Some(next) = ctx.store.block(height + 1) {
            status["next_best"] = json!(to_hex_rev(&next.hash()));
        }
        Ok(Json(status).into_response())
    })
    .await
}

/// The transaction numbers block `height` holds.
fn block_txnums(ctx: &Ctx<'_>, height: u32) -> std::ops::Range<u64> {
    let first = ctx.store.block(height).unwrap().first_tx;
    first..first + ctx.store.tx_count(height, &ctx.snap)
}

async fn block_txids(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let height = ctx.block_height(&hash)?;
        let txids: Vec<String> = block_txnums(&ctx, height).map(|n| to_hex_rev(&ctx.store.txid(n))).collect();
        Ok(Json(txids).into_response())
    })
    .await
}

fn block_txs_page(state: AppState, hash: String, start: usize) -> Result<Response, ApiError> {
    let ctx = Ctx::new(&state);
    let height = ctx.block_height(&hash)?;
    let txnums = block_txnums(&ctx, height);
    if !start.is_multiple_of(PAGE) {
        return Err(ApiError::bad_request("start index must be a multiple of 25"));
    }
    if start as u64 >= txnums.end - txnums.start {
        return Err(ApiError::bad_request("start index out of range"));
    }
    let txs = txnums.skip(start).take(PAGE).map(|n| ctx.tx_json(n)).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(txs).into_response())
}

async fn block_txs_first(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || block_txs_page(state, hash, 0)).await
}

async fn block_txs(
    State(state): State<AppState>,
    Path((hash, start)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let start: usize = start.parse().map_err(|_| ApiError::bad_request("Invalid start index"))?;
    blocking(move || block_txs_page(state, hash, start)).await
}

async fn block_txid(
    State(state): State<AppState>,
    Path((hash, index)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let index: u64 = index.parse().map_err(|_| ApiError::bad_request("Invalid index"))?;
    blocking(move || {
        let ctx = Ctx::new(&state);
        let height = ctx.block_height(&hash)?;
        let txnums = block_txnums(&ctx, height);
        if index >= txnums.end - txnums.start {
            return Err(ApiError::not_found("Transaction not found"));
        }
        Ok(text(to_hex_rev(&ctx.store.txid(txnums.start + index))))
    })
    .await
}

async fn block_raw(State(state): State<AppState>, Path(hash): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let height = ctx.block_height(&hash)?;
        let txnums = block_txnums(&ctx, height);
        let mut raw = ctx.store.block(height).unwrap().header.to_vec();
        crate::block::write_compact_size(&mut raw, txnums.end - txnums.start);
        for n in txnums {
            raw.extend_from_slice(&ctx.raw_tx(n)?);
        }
        Ok(binary(raw))
    })
    .await
}

async fn tx(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let found = ctx.find(&txid)?;
        Ok(Json(ctx.found_json(&found)?).into_response())
    })
    .await
}

async fn tx_hex(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let found = ctx.find(&txid)?;
        Ok(text(hex::encode(ctx.found_raw(&found)?)))
    })
    .await
}

async fn tx_raw(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let found = ctx.find(&txid)?;
        Ok(binary(ctx.found_raw(&found)?))
    })
    .await
}

async fn tx_status(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        match ctx.find(&txid)? {
            Found::Confirmed(txnum) => Ok(Json(ctx.status(ctx.store.tx_height(txnum))).into_response()),
            Found::Unconfirmed(_) => Ok(Json(json!({ "confirmed": false })).into_response()),
        }
    })
    .await
}

/// Whether output `vout` of the transaction with `txid` is spent by one in
/// the mempool, and which.
fn mempool_outspend(ctx: &Ctx<'_>, txid: &Hash, vout: u32) -> Value {
    match ctx.mempool.spender(txid, vout) {
        Some((spender, vin)) => json!({
            "spent": true,
            "txid": to_hex_rev(&spender),
            "vin": vin,
            "status": { "confirmed": false },
        }),
        None => json!({ "spent": false }),
    }
}

fn found_outspends(ctx: &Ctx<'_>, found: &Found<'_>) -> Result<Vec<Value>, ApiError> {
    match found {
        Found::Confirmed(txnum) => {
            let n = ctx.store.output_count(*txnum, &ctx.snap) as u32;
            (0..n).map(|vout| outspend(ctx, *txnum, vout)).collect()
        }
        Found::Unconfirmed(entry) => {
            Ok((0..entry.outputs.len() as u32).map(|vout| mempool_outspend(ctx, &entry.txid, vout)).collect())
        }
    }
}

/// Whether output `vout` of transaction `txnum` is spent, and by what.
fn outspend(ctx: &Ctx<'_>, txnum: u64, vout: u32) -> Result<Value, ApiError> {
    let first_out = ctx.store.tx_bytes(txnum, &ctx.snap).1;
    let outnum = first_out + vout as u64;
    let Some(spender) = ctx.store.output(outnum, &ctx.snap).1 else {
        return Ok(mempool_outspend(ctx, &ctx.store.txid(txnum), vout));
    };
    let tx = ctx.tx(spender)?;
    let vin = tx.inputs.iter().position(|input| input.spent == Some(outnum)).unwrap_or(0);
    Ok(json!({
        "spent": true,
        "txid": to_hex_rev(&ctx.store.txid(spender)),
        "vin": vin,
        "status": ctx.status(ctx.store.tx_height(spender)),
    }))
}

async fn tx_outspend(
    State(state): State<AppState>,
    Path((txid, vout)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let vout: u32 = vout.parse().map_err(|_| ApiError::bad_request("Invalid vout"))?;
    blocking(move || {
        let ctx = Ctx::new(&state);
        let found = ctx.find(&txid)?;
        let spends = found_outspends(&ctx, &found)?;
        let spend = spends.into_iter().nth(vout as usize).ok_or_else(|| ApiError::not_found("Output not found"))?;
        Ok(Json(spend).into_response())
    })
    .await
}

async fn tx_outspends(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let found = ctx.find(&txid)?;
        Ok(Json(found_outspends(&ctx, &found)?).into_response())
    })
    .await
}

async fn tx_merkle_proof(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        let height = ctx.store.tx_height(txnum);
        let txnums = block_txnums(&ctx, height);
        let pos = (txnum - txnums.start) as usize;
        let txids: Vec<Hash> = txnums.map(|n| ctx.store.txid(n)).collect();
        let merkle: Vec<String> = merkle_branch(txids, pos).iter().map(to_hex_rev).collect();
        Ok(Json(json!({ "block_height": height, "merkle": merkle, "pos": pos })).into_response())
    })
    .await
}

async fn tx_merkleblock_proof(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    use bitcoin::hashes::Hash as _;
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        let height = ctx.store.tx_height(txnum);
        let header: bitcoin::block::Header =
            bitcoin::consensus::deserialize(&ctx.store.block(height).unwrap().header).expect("a header");
        let target = bitcoin::Txid::from_byte_array(ctx.store.txid(txnum));
        let txids: Vec<bitcoin::Txid> =
            block_txnums(&ctx, height).map(|n| bitcoin::Txid::from_byte_array(ctx.store.txid(n))).collect();
        let block = bitcoin::MerkleBlock::from_header_txids_with_predicate(&header, &txids, |t| *t == target);
        Ok(text(hex::encode(bitcoin::consensus::serialize(&block))))
    })
    .await
}

/// The script an `/address/{address}` or `/scripthash/{hash}` path names,
/// and how to name it in a reply.
fn script_of(ctx: &Ctx<'_>, param: &str, by_hash: bool) -> Result<ScriptRef, ApiError> {
    if by_hash {
        let hash: Hash = hex::decode(param)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ApiError::bad_request("Invalid scripthash"))?;
        Ok(ScriptRef::Hash(hash))
    } else {
        let script = script::parse_address(param, ctx.network)
            .ok_or_else(|| ApiError::bad_request("Invalid Bitcoin address"))?;
        Ok(ScriptRef::Script(script))
    }
}

pub(super) enum ScriptRef {
    Script(Vec<u8>),
    Hash(Hash),
}

impl ScriptRef {
    pub fn key(&self) -> [u8; 8] {
        match self {
            ScriptRef::Script(script) => crate::store::script_key(script),
            ScriptRef::Hash(hash) => hash[..8].try_into().unwrap(),
        }
    }
}

/// An address's unconfirmed transactions, newest first, and what they pay
/// it and spend of it.
pub(super) fn mempool_activity<'m>(ctx: &'m Ctx<'_>, key: &[u8; 8]) -> (Vec<&'m Entry>, Value) {
    let entries = ctx.mempool.txs_of_script(key);
    let (mut funded, mut funded_sum, mut spent, mut spent_sum) = (0u64, 0u64, 0u64, 0u64);
    for entry in &entries {
        for (value, script) in &entry.outputs {
            if crate::store::script_key(script) == *key {
                funded += 1;
                funded_sum += value;
            }
        }
        for prevout in &entry.prevouts {
            if crate::store::script_key(&prevout.script) == *key {
                spent += 1;
                spent_sum += prevout.value;
            }
        }
    }
    let stats = json!({
        "funded_txo_count": funded,
        "funded_txo_sum": funded_sum,
        "spent_txo_count": spent,
        "spent_txo_sum": spent_sum,
        "tx_count": entries.len(),
    });
    (entries, stats)
}

/// Whether the request's path is under `/scripthash`.
fn is_scripthash(uri: &axum::http::Uri) -> bool {
    uri.path().contains("/scripthash/")
}

/// Everything an address has been paid and has spent.
pub(super) struct History {
    /// Outputs paying it: number, value, the transaction that made it and
    /// the one that spent it.
    pub funded: Vec<(u64, u64, u64, Option<u64>)>,
}

impl History {
    pub fn load(ctx: &Ctx<'_>, script: &ScriptRef) -> Result<History, ApiError> {
        let outnums = match script {
            ScriptRef::Script(script) => ctx.store.history(script, &ctx.snap)?,
            ScriptRef::Hash(hash) => ctx.store.history_by_hash(hash, &ctx.snap)?,
        };
        let funded = outnums
            .into_iter()
            .map(|outnum| {
                let (value, spent) = ctx.store.output(outnum, &ctx.snap);
                let (txnum, _) = ctx.store.outpoint(outnum, &ctx.snap);
                (outnum, value, txnum, spent)
            })
            .collect();
        Ok(History { funded })
    }

    /// Every transaction it's in, newest first.
    pub fn txnums(&self) -> Vec<u64> {
        let mut all: HashSet<u64> = HashSet::new();
        for &(_, _, txnum, spent) in &self.funded {
            all.insert(txnum);
            if let Some(spender) = spent {
                all.insert(spender);
            }
        }
        let mut all: Vec<u64> = all.into_iter().collect();
        all.sort_unstable_by(|a, b| b.cmp(a));
        all
    }

    fn stats(&self) -> Value {
        let spent: Vec<_> = self.funded.iter().filter(|f| f.3.is_some()).collect();
        json!({
            "funded_txo_count": self.funded.len(),
            "funded_txo_sum": self.funded.iter().map(|f| f.1).sum::<u64>(),
            "spent_txo_count": spent.len(),
            "spent_txo_sum": spent.iter().map(|f| f.1).sum::<u64>(),
            "tx_count": self.txnums().len(),
        })
    }
}

async fn address_stats(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path(param): Path<String>,
) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let by_hash = is_scripthash(&uri);
        let script = script_of(&ctx, &param, by_hash)?;
        let history = History::load(&ctx, &script)?;
        let (_, mempool_stats) = mempool_activity(&ctx, &script.key());
        let key = if by_hash { "scripthash" } else { "address" };
        Ok(Json(json!({
            key: param,
            "chain_stats": history.stats(),
            "mempool_stats": mempool_stats,
        }))
        .into_response())
    })
    .await
}

/// A page of an address's confirmed transactions, after `last` if given,
/// after its unconfirmed ones if `with_mempool`.
fn address_txs_page(
    state: AppState,
    uri: axum::http::Uri,
    param: String,
    last: Option<String>,
    with_mempool: bool,
) -> Result<Response, ApiError> {
    let ctx = Ctx::new(&state);
    let script = script_of(&ctx, &param, is_scripthash(&uri))?;
    let mut txs = Vec::new();
    if with_mempool {
        let (entries, _) = mempool_activity(&ctx, &script.key());
        txs.extend(entries.into_iter().take(MEMPOOL_PAGE).map(|entry| ctx.entry_json(entry)));
    }
    let history = History::load(&ctx, &script)?;
    let mut txnums = history.txnums();
    if let Some(last) = last {
        let last = ctx.txnum(&last)?;
        txnums.retain(|&n| n < last);
    }
    for txnum in txnums.into_iter().take(PAGE) {
        txs.push(ctx.tx_json(txnum)?);
    }
    Ok(Json(txs).into_response())
}

async fn address_txs(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path(param): Path<String>,
) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, None, true)).await
}

async fn address_txs_chain_first(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path(param): Path<String>,
) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, None, false)).await
}

async fn address_txs_chain(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path((param, last)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, Some(last), false)).await
}

async fn address_txs_mempool(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path(param): Path<String>,
) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let script = script_of(&ctx, &param, is_scripthash(&uri))?;
        let (entries, _) = mempool_activity(&ctx, &script.key());
        let txs: Vec<Value> = entries.into_iter().take(MEMPOOL_PAGE).map(|entry| ctx.entry_json(entry)).collect();
        Ok(Json(txs).into_response())
    })
    .await
}

async fn address_utxo(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path(param): Path<String>,
) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let script = script_of(&ctx, &param, is_scripthash(&uri))?;
        let history = History::load(&ctx, &script)?;
        let key = script.key();
        // Unconfirmed outputs paying it, then confirmed ones, newest first;
        // none spent by an unconfirmed transaction.
        let mut utxos: Vec<Value> = Vec::new();
        for entry in ctx.mempool.txs_of_script(&key) {
            for (vout, (value, script)) in entry.outputs.iter().enumerate() {
                if crate::store::script_key(script) == key && ctx.mempool.spender(&entry.txid, vout as u32).is_none() {
                    utxos.push(json!({
                        "txid": to_hex_rev(&entry.txid),
                        "vout": vout,
                        "status": { "confirmed": false },
                        "value": value,
                    }));
                }
            }
        }
        for &(outnum, value, txnum, spent) in history.funded.iter().rev() {
            let (_, vout) = ctx.store.outpoint(outnum, &ctx.snap);
            let txid = ctx.store.txid(txnum);
            if spent.is_some() || ctx.mempool.spender(&txid, vout).is_some() {
                continue;
            }
            utxos.push(json!({
                "txid": to_hex_rev(&txid),
                "vout": vout,
                "status": ctx.status(ctx.store.tx_height(txnum)),
                "value": value,
            }));
        }
        Ok(Json(utxos).into_response())
    })
    .await
}

/// `POST /tx`: broadcasts a raw transaction, in hex, returning its txid.
/// Errors are given as electrs gives bitcoind's.
async fn broadcast(State(state): State<AppState>, body: String) -> Result<Response, ApiError> {
    let raw = hex::decode(body.trim()).map_err(|_| ApiError::bad_request("Invalid hex string"))?;
    let (reply_tx, reply) = tokio::sync::oneshot::channel();
    state
        .mempool_tx
        .send((raw, Source::Api(reply_tx)))
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into()))?;
    match reply.await {
        Ok(Ok(txid)) => Ok(text(to_hex_rev(&txid))),
        Ok(Err(reject)) => {
            let error = json!({ "code": reject.code, "message": reject.reason });
            Err(ApiError::bad_request(&format!("sendrawtransaction RPC error: {error}")))
        }
        Err(_) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into())),
    }
}

async fn mempool_info(State(state): State<AppState>) -> Json<Value> {
    let mempool = state.mempool.read().unwrap();
    let histogram: Vec<Value> = mempool.fee_histogram().into_iter().map(|(rate, vsize)| json!([rate, vsize])).collect();
    Json(json!({
        "count": mempool.len(),
        "vsize": mempool.vsize(),
        "total_fee": mempool.fees(),
        "fee_histogram": histogram,
    }))
}

async fn mempool_txids(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.mempool.read().unwrap().entries().map(|e| to_hex_rev(&e.txid)).collect())
}

async fn mempool_recent(State(state): State<AppState>) -> Json<Vec<Value>> {
    let mempool = state.mempool.read().unwrap();
    Json(
        mempool
            .recent(10)
            .into_iter()
            .map(|e| {
                json!({
                    "txid": to_hex_rev(&e.txid),
                    "fee": e.fee,
                    "vsize": e.vsize,
                    "value": e.outputs.iter().map(|(v, _)| v).sum::<u64>(),
                })
            })
            .collect(),
    )
}

async fn fee_estimates(State(state): State<AppState>) -> Json<Value> {
    let estimates = state.mempool.read().unwrap().fee_estimates(&FEE_TARGETS, FEE_FLOOR);
    let map: serde_json::Map<String, Value> =
        estimates.into_iter().map(|(target, rate)| (target.to_string(), json!(rate))).collect();
    Json(Value::Object(map))
}

/// mempool.space's recommended fees, in whole sat/vB.
async fn fees_recommended(State(state): State<AppState>) -> Json<Value> {
    let estimates = state.mempool.read().unwrap().fee_estimates(&[1, 3, 6, 144], FEE_FLOOR);
    let rate = |i: usize| estimates[i].1.ceil() as u64;
    Json(json!({
        "fastestFee": rate(0),
        "halfHourFee": rate(1),
        "hourFee": rate(2),
        "economyFee": rate(3),
        "minimumFee": FEE_FLOOR as u64,
    }))
}
