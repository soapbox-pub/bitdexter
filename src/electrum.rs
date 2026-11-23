//! The Electrum protocol, version 1.4, optionally: newline-delimited JSON-RPC
//! over TCP, as Electrum, Sparrow and other wallets speak it to an Electrum
//! server. See <https://electrum-protocol.readthedocs.io>.
//!
//! A script is named by its "script hash": its SHA-256, byte-reversed. A
//! client subscribes to its scripts and to new blocks, and is notified when
//! a script's status changes: the hash of its history, `txid:height:` for
//! each transaction, confirmed ones in chain order, then unconfirmed ones,
//! at height 0, or -1 if they spend unconfirmed outputs.
//!
//! Only plain TCP is served; put TLS in front of it if it's to be reached
//! from elsewhere.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::api::{Ctx, History, ScriptRef, is_script, mempool_activity};
use crate::hash::{Hash, from_hex_rev, merkle_branch, sha256, to_hex_rev};
use crate::mempool;
use crate::store::Store;

const PROTOCOL: &str = "1.4";
/// The most headers `blockchain.block.headers` gives at once.
const MAX_HEADERS: u32 = 2016;
/// The most bytes a request may be.
const MAX_LINE: usize = 1 << 20;

#[derive(Clone)]
pub struct Server {
    pub store: Arc<Store>,
    pub mempool: mempool::Shared,
    pub mempool_tx: mempool::Submit,
}

struct RpcError(i32, String);

fn bad(message: impl Into<String>) -> RpcError {
    RpcError(1, message.into())
}

/// The key a script's history is kept under, from its script hash.
fn key_of_scripthash(scripthash: &str) -> Result<Hash, RpcError> {
    from_hex_rev(scripthash).ok_or_else(|| bad("invalid script hash"))
}

/// A script's history, as Electrum gives it: each transaction's txid,
/// height (0 or -1 for unconfirmed ones) and, if unconfirmed, fee.
fn history(ctx: &Ctx<'_>, hash: &Hash) -> Result<Vec<(Hash, i64, Option<u64>)>, RpcError> {
    let script = ScriptRef::Hash(*hash);
    let loaded = History::load(ctx, &script).map_err(|e| bad(e.1))?;
    let mut txnums = loaded.txnums();
    txnums.reverse();
    let mut items: Vec<(Hash, i64, Option<u64>)> =
        txnums.into_iter().map(|n| (ctx.store.txid(n), ctx.store.tx_height(n) as i64, None)).collect();
    let (entries, _) = mempool_activity(ctx, hash);
    let mut unconfirmed: Vec<(Hash, i64, Option<u64>)> =
        entries.into_iter().map(|e| (e.txid, if e.parents.is_empty() { 0 } else { -1 }, Some(e.fee))).collect();
    // Unconfirmed: those with confirmed inputs first, then by txid, so the
    // order, and so the status, doesn't depend on when they arrived.
    unconfirmed.sort_by(|a, b| b.1.cmp(&a.1).then(to_hex_rev(&a.0).cmp(&to_hex_rev(&b.0))));
    items.extend(unconfirmed);
    Ok(items)
}

/// A script's status: the hash of its history, or null if it has none.
fn status(ctx: &Ctx<'_>, hash: &Hash) -> Result<Value, RpcError> {
    let items = history(ctx, hash)?;
    if items.is_empty() {
        return Ok(Value::Null);
    }
    let mut text = String::new();
    for (txid, height, _) in items {
        text.push_str(&format!("{}:{height}:", to_hex_rev(&txid)));
    }
    Ok(json!(hex::encode(sha256(text.as_bytes()))))
}

fn header_hex(ctx: &Ctx<'_>, height: u32) -> Option<String> {
    ctx.block(height).map(|b| hex::encode(b.header))
}

fn tip_header(ctx: &Ctx<'_>) -> Value {
    let height = ctx.snap.tip_height().unwrap_or(0);
    json!({ "height": height, "hex": header_hex(ctx, height).unwrap_or_default() })
}

fn param(params: &Value, i: usize) -> &Value {
    match params {
        Value::Array(items) => items.get(i).unwrap_or(&Value::Null),
        _ => &Value::Null,
    }
}

fn param_str(params: &Value, i: usize) -> Result<&str, RpcError> {
    param(params, i).as_str().ok_or_else(|| bad(format!("parameter {i} must be a string")))
}

fn param_u32(params: &Value, i: usize) -> Result<u32, RpcError> {
    param(params, i).as_u64().map(|n| n as u32).ok_or_else(|| bad(format!("parameter {i} must be a number")))
}

/// A connection's subscriptions.
#[derive(Default)]
struct Session {
    headers: bool,
    last_tip: Option<u32>,
    /// Each script subscribed to, by script hash, and its last status.
    scripts: HashMap<String, Value>,
}

impl Server {
    fn ctx(&self) -> Ctx<'_> {
        Ctx::from_parts(&self.store, &self.mempool)
    }

    /// Answers a request, other than a broadcast, which needs waiting on.
    fn answer(&self, session: &mut Session, method: &str, params: &Value) -> Result<Value, RpcError> {
        let ctx = self.ctx();
        match method {
            "server.version" => Ok(json!([format!("bitdexter {}", env!("CARGO_PKG_VERSION")), PROTOCOL])),
            "server.banner" => Ok(json!(format!("bitdexter {}", env!("CARGO_PKG_VERSION")))),
            "server.donation_address" => Ok(json!("")),
            "server.ping" => Ok(Value::Null),
            "server.peers.subscribe" => Ok(json!([])),
            "server.features" => Ok(json!({
                "genesis_hash": ctx.block(0).map(|b| to_hex_rev(&b.hash())),
                "hosts": {},
                "protocol_max": PROTOCOL,
                "protocol_min": PROTOCOL,
                "pruning": null,
                "server_version": format!("bitdexter {}", env!("CARGO_PKG_VERSION")),
                "hash_function": "sha256",
            })),
            "blockchain.headers.subscribe" => {
                session.headers = true;
                session.last_tip = ctx.snap.tip_height();
                Ok(tip_header(&ctx))
            }
            "blockchain.block.header" => {
                let height = param_u32(params, 0)?;
                header_hex(&ctx, height).map(Value::from).ok_or_else(|| bad(format!("no block at height {height}")))
            }
            "blockchain.block.headers" => {
                let start = param_u32(params, 0)?;
                let count = param_u32(params, 1)?.min(MAX_HEADERS);
                let mut hex = String::new();
                let mut n = 0;
                for height in start..start.saturating_add(count) {
                    let Some(header) = header_hex(&ctx, height) else { break };
                    hex.push_str(&header);
                    n += 1;
                }
                Ok(json!({ "count": n, "hex": hex, "max": MAX_HEADERS }))
            }
            "blockchain.estimatefee" => {
                let target = param_u32(params, 0)?.max(1);
                let rate = ctx.mempool.fee_estimates(&[target], crate::api::esplora::FEE_FLOOR)[0].1;
                // BTC per 1000 bytes.
                Ok(json!(rate * 1000.0 / 1e8))
            }
            "blockchain.relayfee" => Ok(json!(mempool::MIN_RELAY_FEERATE as f64 / 1e8)),
            "mempool.get_fee_histogram" => {
                Ok(json!(ctx.mempool.fee_histogram().into_iter().map(|(r, v)| json!([r, v])).collect::<Vec<_>>()))
            }
            "blockchain.scripthash.subscribe" => {
                let scripthash = param_str(params, 0)?.to_string();
                let status = status(&ctx, &key_of_scripthash(&scripthash)?)?;
                session.scripts.insert(scripthash, status.clone());
                Ok(status)
            }
            "blockchain.scripthash.unsubscribe" => Ok(json!(session.scripts.remove(param_str(params, 0)?).is_some())),
            "blockchain.scripthash.get_history" => {
                let items = history(&ctx, &key_of_scripthash(param_str(params, 0)?)?)?;
                Ok(json!(
                    items
                        .into_iter()
                        .map(|(txid, height, fee)| {
                            let mut item = json!({ "tx_hash": to_hex_rev(&txid), "height": height });
                            if let Some(fee) = fee {
                                item["fee"] = json!(fee);
                            }
                            item
                        })
                        .collect::<Vec<_>>()
                ))
            }
            "blockchain.scripthash.get_mempool" => {
                let items = history(&ctx, &key_of_scripthash(param_str(params, 0)?)?)?;
                Ok(json!(
                    items
                        .into_iter()
                        .filter(|i| i.1 <= 0)
                        .map(
                            |(txid, height, fee)| json!({ "tx_hash": to_hex_rev(&txid), "height": height, "fee": fee })
                        )
                        .collect::<Vec<_>>()
                ))
            }
            "blockchain.scripthash.get_balance" | "blockchain.scripthash.listunspent" => {
                let hash = key_of_scripthash(param_str(params, 0)?)?;
                let script = ScriptRef::Hash(hash);
                let loaded = History::load(&ctx, &script).map_err(|e| bad(e.1))?;
                let mut confirmed = 0u64;
                let mut unconfirmed = 0i64;
                let mut utxos = Vec::new();
                for &(outnum, value, txnum, spent) in &loaded.funded {
                    if spent.is_some() {
                        continue;
                    }
                    confirmed += value;
                    let (_, vout) = ctx.store.outpoint(outnum, &ctx.snap);
                    let txid = ctx.store.txid(txnum);
                    if ctx.mempool.spender(&txid, vout).is_none() {
                        utxos.push(json!({
                            "tx_hash": to_hex_rev(&txid),
                            "tx_pos": vout,
                            "height": ctx.store.tx_height(txnum),
                            "value": value,
                        }));
                    }
                }
                let (entries, _) = mempool_activity(&ctx, &hash);
                for entry in entries {
                    for (vout, (value, script)) in entry.outputs.iter().enumerate() {
                        if is_script(script, &hash) {
                            unconfirmed += *value as i64;
                            if ctx.mempool.spender(&entry.txid, vout as u32).is_none() {
                                utxos.push(json!({
                                    "tx_hash": to_hex_rev(&entry.txid),
                                    "tx_pos": vout,
                                    "height": 0,
                                    "value": value,
                                }));
                            }
                        }
                    }
                    for prevout in &entry.prevouts {
                        if is_script(&prevout.script, &hash) {
                            unconfirmed -= prevout.value as i64;
                        }
                    }
                }
                if method == "blockchain.scripthash.get_balance" {
                    Ok(json!({ "confirmed": confirmed, "unconfirmed": unconfirmed }))
                } else {
                    Ok(json!(utxos))
                }
            }
            "blockchain.transaction.get" => {
                if param(params, 1).as_bool() == Some(true) {
                    return Err(bad("verbose transactions aren't supported"));
                }
                let found = ctx.find(param_str(params, 0)?).map_err(|e| bad(e.1))?;
                let raw = match &found {
                    crate::api::Found::Confirmed(txnum) => ctx.raw_tx(*txnum).map_err(|e| bad(e.1))?,
                    crate::api::Found::Unconfirmed(entry) => entry.raw.clone(),
                };
                Ok(json!(hex::encode(raw)))
            }
            "blockchain.transaction.get_merkle" => {
                let txid = from_hex_rev(param_str(params, 0)?).ok_or_else(|| bad("invalid txid"))?;
                let txnum = ctx.txnum_of(&txid).ok_or_else(|| bad("transaction not found in a block"))?;
                let height = ctx.store.tx_height(txnum);
                let first = ctx.block(height).unwrap().first_tx;
                let txids: Vec<Hash> =
                    (first..first + ctx.store.tx_count(height, &ctx.snap)).map(|n| ctx.store.txid(n)).collect();
                let pos = (txnum - first) as usize;
                let merkle: Vec<String> = merkle_branch(txids, pos).iter().map(to_hex_rev).collect();
                Ok(json!({ "block_height": height, "merkle": merkle, "pos": pos }))
            }
            "blockchain.transaction.id_from_pos" => {
                let height = param_u32(params, 0)?;
                let pos = param_u32(params, 1)? as u64;
                let block = ctx.block(height).ok_or_else(|| bad(format!("no block at height {height}")))?;
                let count = ctx.store.tx_count(height, &ctx.snap);
                if pos >= count {
                    return Err(bad("no transaction at that position"));
                }
                let txid = to_hex_rev(&ctx.store.txid(block.first_tx + pos));
                if param(params, 2).as_bool() == Some(true) {
                    let txids: Vec<Hash> =
                        (block.first_tx..block.first_tx + count).map(|n| ctx.store.txid(n)).collect();
                    let merkle: Vec<String> = merkle_branch(txids, pos as usize).iter().map(to_hex_rev).collect();
                    Ok(json!({ "tx_hash": txid, "merkle": merkle }))
                } else {
                    Ok(json!(txid))
                }
            }
            _ => Err(RpcError(-32601, format!("unknown method {method}"))),
        }
    }

    async fn broadcast(&self, params: &Value) -> Result<Value, RpcError> {
        let raw = hex::decode(param_str(params, 0)?).map_err(|_| bad("invalid hex"))?;
        match mempool::submit(&self.mempool_tx, raw).await {
            Ok(txid) => Ok(json!(to_hex_rev(&txid))),
            Err(reject) => Err(bad(reject.reason)),
        }
    }

    async fn call(&self, session: &mut Session, request: &Value) -> Value {
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or_default();
        let params = &request["params"];
        let result = if method == "blockchain.transaction.broadcast" {
            self.broadcast(params).await
        } else {
            let server = self.clone();
            let method = method.to_string();
            let params = params.clone();
            let mut taken = std::mem::take(session);
            let (result, back) = tokio::task::spawn_blocking(move || {
                let result = server.answer(&mut taken, &method, &params);
                (result, taken)
            })
            .await
            .unwrap_or_else(|err| (Err(bad(err.to_string())), Session::default()));
            *session = back;
            result
        };
        match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(RpcError(code, message)) => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
            }
        }
    }

    /// Notifications for a session's subscriptions that have changed.
    fn notifications(&self, session: &mut Session) -> Vec<Value> {
        let ctx = self.ctx();
        let mut out = Vec::new();
        if session.headers && session.last_tip != ctx.snap.tip_height() {
            session.last_tip = ctx.snap.tip_height();
            out.push(
                json!({ "jsonrpc": "2.0", "method": "blockchain.headers.subscribe", "params": [tip_header(&ctx)] }),
            );
        }
        for (scripthash, last) in session.scripts.iter_mut() {
            let Ok(hash) = key_of_scripthash(scripthash) else { continue };
            let Ok(now) = status(&ctx, &hash) else { continue };
            if now != *last {
                *last = now.clone();
                out.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.scripthash.subscribe",
                    "params": [scripthash, now],
                }));
            }
        }
        out
    }

    async fn serve_connection(self, stream: TcpStream) -> std::io::Result<()> {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read);
        let mut session = Session::default();
        let mut line = String::new();
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            line.clear();
            tokio::select! {
                n = lines.read_line(&mut line) => {
                    if n? == 0 || line.len() > MAX_LINE {
                        return Ok(());
                    }
                    let Ok(request) = serde_json::from_str::<Value>(line.trim()) else {
                        let error = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } });
                        write.write_all(format!("{error}\n").as_bytes()).await?;
                        continue;
                    };
                    let reply = match &request {
                        Value::Array(batch) => {
                            let mut replies = Vec::with_capacity(batch.len());
                            for request in batch {
                                replies.push(self.call(&mut session, request).await);
                            }
                            Value::Array(replies)
                        }
                        request => self.call(&mut session, request).await,
                    };
                    write.write_all(format!("{reply}\n").as_bytes()).await?;
                }
                _ = tick.tick() => {
                    if !session.headers && session.scripts.is_empty() {
                        continue;
                    }
                    let server = self.clone();
                    let mut taken = std::mem::take(&mut session);
                    let (notes, back) = tokio::task::spawn_blocking(move || {
                        let notes = server.notifications(&mut taken);
                        (notes, taken)
                    })
                    .await
                    .unwrap_or_default();
                    session = back;
                    for note in notes {
                        write.write_all(format!("{note}\n").as_bytes()).await?;
                    }
                }
            }
        }
    }
}

/// Serves the Electrum protocol on `addr` until shut down.
pub async fn serve(
    addr: SocketAddr,
    server: Server,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("serving the Electrum protocol on tcp://{addr}");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(err) = server.serve_connection(stream).await {
                        tracing::debug!("electrum client {peer}: {err}");
                    }
                });
            }
            _ = shutdown.changed() => return Ok(()),
        }
    }
}
