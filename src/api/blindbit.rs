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

/// Block `height`'s tweaks. Those not cached yet are computed one block at
/// a time: a request for another block meanwhile is told to try again,
/// rather than taking more of the machine, or waiting while holding a
/// request's turn to read the store.
fn block_tweaks(
    store: &crate::store::Store,
    height: u32,
    snapshot: &crate::store::Snapshot,
) -> Result<Vec<(u64, [u8; 33])>, ApiError> {
    static COMPUTING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let record = store.block_in(height, snapshot).ok_or_else(|| ApiError::not_found("Block not found"))?;
    if height < silent::first_height(store.chain) || store.cached_tweaks(&record.hash())?.is_some() {
        return Ok(silent::block_tweaks(store, height, snapshot)?);
    }
    let Ok(_computing) = COMPUTING.try_lock() else {
        return Err(ApiError(axum::http::StatusCode::SERVICE_UNAVAILABLE, "Busy computing tweaks: try again".into()));
    };
    Ok(silent::block_tweaks(store, height, snapshot)?)
}

async fn tweaks(State(state): State<AppState>, Path(height): Path<String>) -> Result<Response, ApiError> {
    let height = parse_height(&height)?;
    blocking(move || {
        let snapshot = state.store.snapshot();
        let tweaks = block_tweaks(&state.store, height, &snapshot)?;
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
        let Some(record) = store.block_in(height, &snapshot) else {
            return Err(ApiError::not_found("Block not found"));
        };
        let block_hash = to_hex_rev(&record.hash());
        let mut utxos = Vec::new();
        for (txnum, _) in block_tweaks(store, height, &snapshot)? {
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
