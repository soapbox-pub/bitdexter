//! The Esplora HTTP API, as Blockstream's electrs serves it and
//! mempool.space extends it: see
//! <https://github.com/Blockstream/esplora/blob/master/API.md>.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bitcoin::Network;
use serde_json::{json, Value};

use super::{blocking, ApiError, AppState};
use crate::compact::CompactTx;
use crate::hash::{from_hex_rev, merkle_branch, to_hex_rev, Hash};
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
}

/// What a request reads: the store as of one commit.
struct Ctx<'a> {
    store: &'a Store,
    snap: Snapshot,
    network: Network,
}

impl<'a> Ctx<'a> {
    fn new(state: &'a AppState) -> Ctx<'a> {
        Ctx { store: &state.store, snap: state.store.snapshot(), network: state.store.chain.network() }
    }

    fn tip(&self) -> Result<u32, ApiError> {
        self.snap.tip_height().ok_or_else(|| ApiError::not_found("No blocks indexed yet"))
    }

    fn block_height(&self, hash: &str) -> Result<u32, ApiError> {
        let hash = from_hex_rev(hash).ok_or_else(|| ApiError::bad_request("Invalid hex string"))?;
        self.store.height_of(&hash).ok_or_else(|| ApiError::not_found("Block not found"))
    }

    fn txnum(&self, txid: &str) -> Result<u64, ApiError> {
        let txid = from_hex_rev(txid).ok_or_else(|| ApiError::bad_request("Invalid hex string"))?;
        self.store.txnum(&txid).ok_or_else(|| ApiError::not_found("Transaction not found"))
    }

    fn tx(&self, txnum: u64) -> Result<CompactTx<'a>, ApiError> {
        Ok(self.store.tx(txnum, &self.snap)?)
    }

    /// The outpoint each input spends.
    fn prevouts(&self, tx: &CompactTx<'_>) -> Vec<(Hash, u32)> {
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

    fn raw_tx(&self, txnum: u64) -> Result<Vec<u8>, ApiError> {
        let tx = self.tx(txnum)?;
        Ok(tx.to_raw(&self.prevouts(&tx)))
    }

    fn mediantime(&self, height: u32) -> u32 {
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
            value.as_object_mut().unwrap().remove("previousblockhash");
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

    fn tx_json(&self, txnum: u64) -> Result<Value, ApiError> {
        let tx = self.tx(txnum)?;
        let prevouts = self.prevouts(&tx);
        let mut decoded: HashMap<u64, CompactTx<'a>> = HashMap::new();
        let mut value_in = 0u64;
        let mut vin = Vec::with_capacity(tx.inputs.len());
        for (input, (prev_txid, prev_vout)) in tx.inputs.iter().zip(&prevouts) {
            let witness = input.witness_items();
            let mut item = json!({
                "txid": to_hex_rev(prev_txid),
                "vout": prev_vout,
                "prevout": null,
                "scriptsig": hex::encode(input.script_sig),
                "scriptsig_asm": script::asm(input.script_sig),
                "witness": witness.iter().map(hex::encode).collect::<Vec<_>>(),
                "is_coinbase": tx.coinbase,
                "sequence": input.sequence,
            });
            if witness.is_empty() {
                item.as_object_mut().unwrap().remove("witness");
            }
            if let Some(outnum) = input.spent {
                let (prev_txnum, vout) = self.store.outpoint(outnum, &self.snap);
                if let std::collections::hash_map::Entry::Vacant(slot) = decoded.entry(prev_txnum) {
                    slot.insert(self.tx(prev_txnum)?);
                }
                let prev = &decoded[&prev_txnum].outputs[vout as usize];
                value_in += prev.value;
                item["prevout"] = self.output_json(prev.value, &prev.script);
                inner_scripts(&mut item, &prev.script, input.script_sig, &witness);
            }
            vin.push(item);
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
    if start % PAGE != 0 {
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

async fn block_txs(State(state): State<AppState>, Path((hash, start)): Path<(String, String)>) -> Result<Response, ApiError> {
    let start: usize = start.parse().map_err(|_| ApiError::bad_request("Invalid start index"))?;
    blocking(move || block_txs_page(state, hash, start)).await
}

async fn block_txid(State(state): State<AppState>, Path((hash, index)): Path<(String, String)>) -> Result<Response, ApiError> {
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
        let txnum = ctx.txnum(&txid)?;
        Ok(Json(ctx.tx_json(txnum)?).into_response())
    })
    .await
}

async fn tx_hex(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        Ok(text(hex::encode(ctx.raw_tx(txnum)?)))
    })
    .await
}

async fn tx_raw(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        Ok(binary(ctx.raw_tx(txnum)?))
    })
    .await
}

async fn tx_status(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        Ok(Json(ctx.status(ctx.store.tx_height(txnum))).into_response())
    })
    .await
}

/// Whether output `vout` of transaction `txnum` is spent, and by what.
fn outspend(ctx: &Ctx<'_>, txnum: u64, vout: u32) -> Result<Value, ApiError> {
    let first_out = ctx.store.tx_bytes(txnum, &ctx.snap).1;
    let outnum = first_out + vout as u64;
    let Some(spender) = ctx.store.output(outnum, &ctx.snap).1 else {
        return Ok(json!({ "spent": false }));
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

async fn tx_outspend(State(state): State<AppState>, Path((txid, vout)): Path<(String, String)>) -> Result<Response, ApiError> {
    let vout: u32 = vout.parse().map_err(|_| ApiError::bad_request("Invalid vout"))?;
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        if vout as u64 >= ctx.store.output_count(txnum, &ctx.snap) {
            return Err(ApiError::not_found("Output not found"));
        }
        Ok(Json(outspend(&ctx, txnum, vout)?).into_response())
    })
    .await
}

async fn tx_outspends(State(state): State<AppState>, Path(txid): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let txnum = ctx.txnum(&txid)?;
        let n = ctx.store.output_count(txnum, &ctx.snap) as u32;
        let spends = (0..n).map(|vout| outspend(&ctx, txnum, vout)).collect::<Result<Vec<_>, _>>()?;
        Ok(Json(spends).into_response())
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

enum ScriptRef {
    Script(Vec<u8>),
    Hash(Hash),
}

/// Whether the request's path is under `/scripthash`.
fn is_scripthash(uri: &axum::http::Uri) -> bool {
    uri.path().contains("/scripthash/")
}

/// Everything an address has been paid and has spent.
struct History {
    /// Outputs paying it: number, value, the transaction that made it and
    /// the one that spent it.
    funded: Vec<(u64, u64, u64, Option<u64>)>,
}

impl History {
    fn load(ctx: &Ctx<'_>, script: &ScriptRef) -> Result<History, ApiError> {
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
    fn txnums(&self) -> Vec<u64> {
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

fn empty_stats() -> Value {
    json!({ "funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0 })
}

async fn address_stats(State(state): State<AppState>, uri: axum::http::Uri, Path(param): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let by_hash = is_scripthash(&uri);
        let script = script_of(&ctx, &param, by_hash)?;
        let history = History::load(&ctx, &script)?;
        let key = if by_hash { "scripthash" } else { "address" };
        Ok(Json(json!({
            key: param,
            "chain_stats": history.stats(),
            "mempool_stats": empty_stats(),
        }))
        .into_response())
    })
    .await
}

fn address_txs_page(state: AppState, uri: axum::http::Uri, param: String, last: Option<String>) -> Result<Response, ApiError> {
    let ctx = Ctx::new(&state);
    let script = script_of(&ctx, &param, is_scripthash(&uri))?;
    let history = History::load(&ctx, &script)?;
    let mut txnums = history.txnums();
    if let Some(last) = last {
        let last = ctx.txnum(&last)?;
        txnums.retain(|&n| n < last);
    }
    let txs = txnums.into_iter().take(PAGE).map(|n| ctx.tx_json(n)).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(txs).into_response())
}

async fn address_txs(State(state): State<AppState>, uri: axum::http::Uri, Path(param): Path<String>) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, None)).await
}

async fn address_txs_chain_first(State(state): State<AppState>, uri: axum::http::Uri, Path(param): Path<String>) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, None)).await
}

async fn address_txs_chain(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    Path((param, last)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    blocking(move || address_txs_page(state, uri, param, Some(last))).await
}

async fn address_txs_mempool(State(state): State<AppState>, uri: axum::http::Uri, Path(param): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        script_of(&ctx, &param, is_scripthash(&uri))?;
        Ok(Json(Vec::<Value>::new()).into_response())
    })
    .await
}

async fn address_utxo(State(state): State<AppState>, uri: axum::http::Uri, Path(param): Path<String>) -> Result<Response, ApiError> {
    blocking(move || {
        let ctx = Ctx::new(&state);
        let script = script_of(&ctx, &param, is_scripthash(&uri))?;
        let history = History::load(&ctx, &script)?;
        let utxos: Vec<Value> = history
            .funded
            .iter()
            .rev()
            .filter(|f| f.3.is_none())
            .map(|&(outnum, value, txnum, _)| {
                let (_, vout) = ctx.store.outpoint(outnum, &ctx.snap);
                json!({
                    "txid": to_hex_rev(&ctx.store.txid(txnum)),
                    "vout": vout,
                    "status": ctx.status(ctx.store.tx_height(txnum)),
                    "value": value,
                })
            })
            .collect();
        Ok(Json(utxos).into_response())
    })
    .await
}

#[allow(dead_code)]
fn not_implemented() -> ApiError {
    ApiError(StatusCode::NOT_IMPLEMENTED, "Not implemented yet".into())
}
