//! Silent payment tweaks, optionally, as BlindBit Oracle serves them, under
//! `/blindbit`: `/info`, `/tweaks/:height` and `/utxos/:height`. A light
//! wallet asks for a block's tweaks, completes each with its scan key, and
//! looks for the outputs that gives among the block's taproot outputs.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::{ApiError, AppState, blocking};
use crate::hash::to_hex_rev;
use crate::silent;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/blindbit/info", get(info))
        .route("/blindbit/tweaks/{height}", get(tweaks))
        .route("/blindbit/utxos/{height}", get(utxos))
}

async fn info(State(state): State<AppState>) -> Json<Value> {
    let network = match state.store.chain {
        crate::network::Chain::Mainnet => "main",
        crate::network::Chain::Testnet4 => "testnet4",
        crate::network::Chain::Signet => "signet",
        crate::network::Chain::Regtest => "regtest",
    };
    Json(json!({
        "network": network,
        "height": state.store.snapshot().tip_height().unwrap_or(0),
        "tweaks_only": false,
        "tweaks_full_basic": true,
        "tweaks_full_with_dust_filter": false,
        "tweaks_cut_through_with_dust_filter": false,
    }))
}

fn parse_height(height: &str) -> Result<u32, ApiError> {
    height.parse().map_err(|_| ApiError::bad_request("Invalid height"))
}

async fn tweaks(State(state): State<AppState>, Path(height): Path<String>) -> Result<Response, ApiError> {
    let height = parse_height(&height)?;
    blocking(move || {
        let snapshot = state.store.snapshot();
        if state.store.block(height).is_none() {
            return Err(ApiError::not_found("Block not found"));
        }
        let tweaks = silent::block_tweaks(&state.store, height, &snapshot)?;
        let hex: Vec<String> = tweaks.iter().map(|(_, tweak)| hex::encode(tweak)).collect();
        Ok(Json(hex).into_response())
    })
    .await
}

async fn utxos(State(state): State<AppState>, Path(height): Path<String>) -> Result<Response, ApiError> {
    let height = parse_height(&height)?;
    blocking(move || {
        let store = &state.store;
        let snapshot = store.snapshot();
        let Some(record) = store.block(height) else { return Err(ApiError::not_found("Block not found")) };
        let block_hash = to_hex_rev(&record.hash());
        let mut utxos = Vec::new();
        for (txnum, _) in silent::block_tweaks(store, height, &snapshot)? {
            let tx = store.tx(txnum, &snapshot)?;
            let (_, first_out) = store.tx_bytes(txnum, &snapshot);
            let txid = to_hex_rev(&store.txid(txnum));
            for (vout, out) in tx.outputs.iter().enumerate() {
                if !silent::is_p2tr(&out.script) {
                    continue;
                }
                let spent = store.output(first_out + vout as u64, &snapshot).1.is_some();
                utxos.push(json!({
                    "txid": txid,
                    "vout": vout,
                    "value": out.value,
                    "scriptpubkey": hex::encode(&out.script),
                    "block_height": height,
                    "block_hash": block_hash,
                    "timestamp": record.time(),
                    "spent": spent,
                }));
            }
        }
        Ok(Json(utxos).into_response())
    })
    .await
}
