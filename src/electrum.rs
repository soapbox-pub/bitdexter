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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
/// The most requests in a batch.
const MAX_BATCH: usize = 1000;
/// The most connections at once.
const MAX_CONNECTIONS: usize = 512;
/// The most scripts one connection may subscribe to, and all together.
const MAX_SUBSCRIPTIONS: usize = 20_000;
const MAX_ALL_SUBSCRIPTIONS: usize = 1_000_000;
/// How long a connection may send nothing before it's closed. Wallets
/// ping every few minutes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How many blocks' worth of scripts touched are kept, and how many new
/// blocks are looked through for them rather than every subscription
/// being checked again.
const TOUCHED_BLOCKS: usize = 32;
const MAX_NEW_BLOCKS: u32 = 10;

/// The script keys a block pays or spends.
type Touched = Arc<HashSet<[u8; 8]>>;

#[derive(Clone)]
pub struct Server {
    pub store: Arc<Store>,
    pub mempool: mempool::Shared,
    pub mempool_tx: mempool::Submit,
    /// Subscriptions, all together.
    subscriptions: Arc<AtomicUsize>,
    connections: Arc<tokio::sync::Semaphore>,
    /// The script keys each recent block pays or spends, by block hash.
    touched: Arc<Mutex<VecDeque<(Hash, Touched)>>>,
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
    last_tip: Option<(u32, Hash)>,
    /// Each script subscribed to, by its decoded script hash, as it was
    /// named, and its last status.
    scripts: HashMap<Hash, (String, Value)>,
    /// The tip and the mempool's generation the statuses are as of.
    seen_tip: Option<(u32, Hash)>,
    seen_mempool: u64,
}

fn tip_of(ctx: &Ctx<'_>) -> Option<(u32, Hash)> {
    let height = ctx.snap.tip_height()?;
    Some((height, ctx.block(height)?.hash()))
}

impl Server {
    pub fn new(store: Arc<Store>, mempool: mempool::Shared, mempool_tx: mempool::Submit) -> Server {
        Server {
            store,
            mempool,
            mempool_tx,
            subscriptions: Arc::new(AtomicUsize::new(0)),
            connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            touched: Arc::default(),
        }
    }

    /// The script keys block `height` pays or spends.
    fn block_keys(&self, ctx: &Ctx<'_>, height: u32) -> Option<Touched> {
        let block = ctx.block(height)?;
        let hash = block.hash();
        if let Some((_, keys)) = self.touched.lock().unwrap().iter().find(|(h, _)| *h == hash) {
            return Some(keys.clone());
        }
        let mut keys = HashSet::new();
        for txnum in block.first_tx..block.first_tx + ctx.store.tx_count(height, &ctx.snap) {
            let tx = ctx.store.tx(txnum, &ctx.snap).ok()?;
            keys.extend(tx.outputs.iter().map(|out| crate::store::script_key(&out.script)));
            for input in &tx.inputs {
                if let Some(outnum) = input.spent {
                    let (_, script) = ctx.store.output_script(outnum, &ctx.snap).ok()?;
                    keys.insert(crate::store::script_key(&script));
                }
            }
        }
        let keys = Arc::new(keys);
        let mut touched = self.touched.lock().unwrap();
        touched.push_back((hash, keys.clone()));
        if touched.len() > TOUCHED_BLOCKS {
            touched.pop_front();
        }
        Some(keys)
    }

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
                session.last_tip = tip_of(&ctx);
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
                let hash = key_of_scripthash(&scripthash)?;
                if !session.scripts.contains_key(&hash) {
                    if session.scripts.len() >= MAX_SUBSCRIPTIONS {
                        return Err(bad("too many subscriptions"));
                    }
                    if self.subscriptions.fetch_add(1, Ordering::Relaxed) >= MAX_ALL_SUBSCRIPTIONS {
                        self.subscriptions.fetch_sub(1, Ordering::Relaxed);
                        return Err(bad("too many subscriptions"));
                    }
                }
                if session.scripts.is_empty() {
                    session.seen_tip = tip_of(&ctx);
                    session.seen_mempool = ctx.mempool.generation();
                }
                let status = status(&ctx, &hash);
                if status.is_err() && !session.scripts.contains_key(&hash) {
                    self.subscriptions.fetch_sub(1, Ordering::Relaxed);
                }
                let status = status?;
                session.scripts.insert(hash, (scripthash, status.clone()));
                Ok(status)
            }
            "blockchain.scripthash.unsubscribe" => {
                let removed = session.scripts.remove(&key_of_scripthash(param_str(params, 0)?)?).is_some();
                if removed {
                    self.subscriptions.fetch_sub(1, Ordering::Relaxed);
                }
                Ok(json!(removed))
            }
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
            // A panic answers this request with an error, and keeps the session.
            let (result, back) = tokio::task::spawn_blocking(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    server.answer(&mut taken, &method, &params)
                }))
                .unwrap_or_else(|_| Err(RpcError(-32603, "internal error".into())));
                (result, taken)
            })
            .await
            .expect("answering doesn't panic past catch_unwind");
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

    /// Notifications for a session's subscriptions that have changed:
    /// those of scripts paid or spent in new blocks or by transactions
    /// added to or removed from the mempool, or every one if that can't
    /// be known.
    fn notifications(&self, session: &mut Session) -> Vec<Value> {
        let ctx = self.ctx();
        let mut out = Vec::new();
        let tip = tip_of(&ctx);
        if session.headers && session.last_tip != tip {
            session.last_tip = tip;
            out.push(
                json!({ "jsonrpc": "2.0", "method": "blockchain.headers.subscribe", "params": [tip_header(&ctx)] }),
            );
        }
        if session.scripts.is_empty() {
            return out;
        }
        let mut all = false;
        let mut keys: HashSet<[u8; 8]> = HashSet::new();
        if session.seen_tip != tip {
            match (session.seen_tip, tip) {
                (Some((old, old_hash)), Some((new, _)))
                    if new >= old
                        && new - old <= MAX_NEW_BLOCKS
                        && ctx.block(old).is_some_and(|b| b.hash() == old_hash) =>
                {
                    for height in old + 1..=new {
                        match self.block_keys(&ctx, height) {
                            Some(touched) => keys.extend(touched.iter()),
                            None => all = true,
                        }
                    }
                }
                _ => all = true,
            }
            session.seen_tip = tip;
        }
        match ctx.mempool.changed_since(session.seen_mempool) {
            Some(changed) => keys.extend(changed),
            None => all = true,
        }
        session.seen_mempool = ctx.mempool.generation();
        if !all && keys.is_empty() {
            return out;
        }
        for (hash, (scripthash, last)) in session.scripts.iter_mut() {
            if !all && !keys.contains(&<[u8; 8]>::try_from(&hash[..8]).unwrap()) {
                continue;
            }
            let Ok(now) = status(&ctx, hash) else { continue };
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

    async fn handle_line(&self, session: &mut Session, line: &[u8]) -> Value {
        let Ok(request) = serde_json::from_slice::<Value>(line) else {
            return json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } });
        };
        match &request {
            Value::Array(batch) if batch.len() > MAX_BATCH => {
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "batch too big" } })
            }
            Value::Array(batch) => {
                let mut replies = Vec::with_capacity(batch.len());
                for request in batch {
                    replies.push(self.call(session, request).await);
                }
                Value::Array(replies)
            }
            request => self.call(session, request).await,
        }
    }

    async fn serve_connection(&self, stream: TcpStream, session: &mut Session) -> std::io::Result<()> {
        let (mut read, mut write) = stream.into_split();
        // Read a chunk at a time, which is safe to interrupt, into a buffer
        // kept across ticks, and never more than a request may be.
        let mut buf: Vec<u8> = Vec::new();
        let mut scanned = 0;
        let mut chunk = vec![0u8; 64 << 10];
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut last_request = Instant::now();
        loop {
            if let Some(i) = buf[scanned..].iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=scanned + i).collect();
                scanned = 0;
                last_request = Instant::now();
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let reply = self.handle_line(session, &line).await;
                write.write_all(format!("{reply}\n").as_bytes()).await?;
                continue;
            }
            scanned = buf.len();
            if buf.len() > MAX_LINE {
                return Ok(());
            }
            tokio::select! {
                n = read.read(&mut chunk) => {
                    let n = n?;
                    if n == 0 {
                        return Ok(());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                _ = tick.tick() => {
                    if last_request.elapsed() > IDLE_TIMEOUT {
                        return Ok(());
                    }
                    if !session.headers && session.scripts.is_empty() {
                        continue;
                    }
                    let server = self.clone();
                    let mut taken = std::mem::take(session);
                    let (notes, back) = tokio::task::spawn_blocking(move || {
                        let notes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            server.notifications(&mut taken)
                        }))
                        .unwrap_or_default();
                        (notes, taken)
                    })
                    .await
                    .expect("notifying doesn't panic past catch_unwind");
                    *session = back;
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
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // Out of file descriptors, most likely: wait for some to close.
                        tracing::warn!("accepting an Electrum connection: {err}");
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        continue;
                    }
                };
                let Ok(permit) = server.connections.clone().try_acquire_owned() else {
                    tracing::debug!("too many Electrum connections: closing {peer}'s");
                    continue;
                };
                let server = server.clone();
                tokio::spawn(async move {
                    let mut session = Session::default();
                    if let Err(err) = server.serve_connection(stream, &mut session).await {
                        tracing::debug!("electrum client {peer}: {err}");
                    }
                    server.subscriptions.fetch_sub(session.scripts.len(), Ordering::Relaxed);
                    drop(permit);
                });
            }
            _ = shutdown.changed() => return Ok(()),
        }
    }
}
