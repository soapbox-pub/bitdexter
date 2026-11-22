//! Blockbook's API, optionally: the WebSocket API at `/websocket`, and its
//! REST equivalents under `/api/v2`, as Trezor's Blockbook serves them. See
//! <https://github.com/trezor/blockbook/blob/master/docs/api.md>.
//!
//! What sets it apart from Esplora is accounts: an extended public key, or
//! an output descriptor of one (`tr(xpub…)`, `wpkh(…)`, `sh(wpkh(…))`,
//! `pkh(…)`), is scanned server-side, deriving the receive and change
//! addresses in turn until 20 in a row are unused, so a wallet gets its
//! whole history and its UTXOs in one call.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::{Address, Network, NetworkKind};
use serde_json::{Value, json};

use super::esplora::{Ctx, FEE_FLOOR, Found, History, ScriptRef, mempool_activity};
use super::{AppState, blocking};
use crate::hash::{Hash, to_hex_rev};
use crate::mempool::{Entry, Source};
use crate::script;

/// Unused addresses in a row that end a scan of a chain.
const GAP_LIMIT: u32 = 20;
const DEFAULT_PAGE_SIZE: usize = 1000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/websocket", get(websocket))
        .route("/api/v2", get(rest_info))
        .route("/api/v2/xpub/{descriptor}", get(rest_xpub))
        .route("/api/v2/address/{address}", get(rest_xpub))
        .route("/api/v2/utxo/{descriptor}", get(rest_utxo))
        .route("/api/v2/tx/{txid}", get(rest_tx))
        .route("/api/v2/block/{id}", get(rest_block))
        .route("/api/v2/estimatefee/{blocks}", get(rest_estimatefee))
        .route("/api/v2/sendtx/{hex}", get(rest_sendtx_get))
        .route("/api/v2/sendtx/", axum::routing::post(rest_sendtx_post))
}

fn secp() -> &'static Secp256k1<VerifyOnly> {
    static SECP: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::verification_only)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pkh,
    ShWpkh,
    Wpkh,
    Tr,
}

impl Kind {
    fn purpose(self) -> u32 {
        match self {
            Kind::Pkh => 44,
            Kind::ShWpkh => 49,
            Kind::Wpkh => 84,
            Kind::Tr => 86,
        }
    }
}

/// An account: an extended public key, how its addresses are made, and the
/// chains (receive, change) to scan.
struct Account {
    kind: Kind,
    xpub: Xpub,
    /// The key's origin path, if the descriptor gave one, like `86'/0'/0'`.
    origin: Option<String>,
    chains: Vec<u32>,
}

/// What a `descriptor` parameter names.
enum Target {
    Address { script: Vec<u8>, address: String },
    Account(Account),
}

/// The version bytes of an extended public key, as xpub or tpub, and the
/// kind of address its prefix implies.
fn key_version(prefix: &[u8]) -> Option<(NetworkKind, Kind)> {
    Some(match u32::from_be_bytes(prefix.try_into().ok()?) {
        0x0488_b21e => (NetworkKind::Main, Kind::Pkh),
        0x049d_7cb2 => (NetworkKind::Main, Kind::ShWpkh),
        0x04b2_4746 => (NetworkKind::Main, Kind::Wpkh),
        0x0435_87cf => (NetworkKind::Test, Kind::Pkh),
        0x044a_5262 => (NetworkKind::Test, Kind::ShWpkh),
        0x045f_1cf6 => (NetworkKind::Test, Kind::Wpkh),
        _ => return None,
    })
}

/// Parses an extended public key in any of its prefixes (xpub, ypub, zpub
/// and their testnet forms).
fn parse_xpub(s: &str, network: Network) -> Result<(Xpub, Kind), String> {
    let mut bytes = bitcoin::base58::decode_check(s).map_err(|_| "Invalid xpub".to_string())?;
    if bytes.len() != 78 {
        return Err("Invalid xpub".into());
    }
    let (kind_of_network, kind) = key_version(&bytes[..4]).ok_or("Invalid xpub version")?;
    if kind_of_network != NetworkKind::from(network) {
        return Err("xpub is for another network".into());
    }
    let version: u32 = if kind_of_network == NetworkKind::Main { 0x0488_b21e } else { 0x0435_87cf };
    bytes[..4].copy_from_slice(&version.to_be_bytes());
    Ok((Xpub::decode(&bytes).map_err(|err| err.to_string())?, kind))
}

/// Parses an address, an extended public key, or an output descriptor of
/// one: `[origin]key/<0;1>/*` inside `pkh()`, `wpkh()`, `sh(wpkh())` or
/// `tr()`, with or without its checksum.
fn parse_target(s: &str, network: Network) -> Result<Target, String> {
    let s = s.split('#').next().unwrap_or(s).trim();
    let (kind, inner) = if let Some(inner) = s.strip_prefix("tr(") {
        (Some(Kind::Tr), inner.strip_suffix(')'))
    } else if let Some(inner) = s.strip_prefix("wpkh(") {
        (Some(Kind::Wpkh), inner.strip_suffix(')'))
    } else if let Some(inner) = s.strip_prefix("sh(wpkh(") {
        (Some(Kind::ShWpkh), inner.strip_suffix("))"))
    } else if let Some(inner) = s.strip_prefix("pkh(") {
        (Some(Kind::Pkh), inner.strip_suffix(')'))
    } else {
        (None, Some(s))
    };
    let inner = inner.ok_or("Invalid descriptor")?;
    if kind.is_none()
        && let Some(script) = script::parse_address(inner, network)
    {
        return Ok(Target::Address { script, address: inner.to_string() });
    }
    let (origin, key_expr) = match inner.strip_prefix('[') {
        Some(rest) => {
            let (origin, key) = rest.split_once(']').ok_or("Invalid key origin")?;
            let path = origin.split_once('/').map(|(_, path)| path.replace('h', "'"));
            (path, key)
        }
        None => (None, inner),
    };
    let (key, derivation) = key_expr.split_once('/').unwrap_or((key_expr, ""));
    let (xpub, implied) = parse_xpub(key, network)?;
    let chains = match derivation {
        "" | "<0;1>/*" => vec![0, 1],
        "0/*" => vec![0],
        "1/*" => vec![1],
        _ => return Err("Unsupported derivation in descriptor".into()),
    };
    Ok(Target::Account(Account { kind: kind.unwrap_or(implied), xpub, origin, chains }))
}

impl Account {
    /// The address at `chain/index`, and its script.
    fn derive(&self, chain: u32, index: u32, network: Network) -> Result<(String, Vec<u8>), String> {
        let path = [
            ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?,
            ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?,
        ];
        let child = self.xpub.derive_pub(secp(), &path).map_err(|e| e.to_string())?;
        let key = CompressedPublicKey(child.public_key);
        let address = match self.kind {
            Kind::Pkh => Address::p2pkh(key, network),
            Kind::ShWpkh => Address::p2shwpkh(&key, network),
            Kind::Wpkh => Address::p2wpkh(&key, network),
            Kind::Tr => Address::p2tr(secp(), child.public_key.x_only_public_key().0, None, network),
        };
        Ok((address.to_string(), address.script_pubkey().into_bytes()))
    }

    fn path(&self, chain: u32, index: u32, network: Network) -> String {
        match &self.origin {
            Some(origin) => format!("m/{origin}/{chain}/{index}"),
            None => {
                let coin = if network == Network::Bitcoin { 0 } else { 1 };
                format!("m/{}'/{coin}'/0'/{chain}/{index}", self.kind.purpose())
            }
        }
    }
}

/// An address of an account, and its history.
struct Scanned<'m> {
    address: String,
    path: Option<String>,
    history: History,
    mempool: Vec<&'m Entry>,
    key: [u8; 8],
}

impl Scanned<'_> {
    fn used(&self) -> bool {
        !self.history.funded.is_empty() || !self.mempool.is_empty()
    }

    fn received(&self) -> u64 {
        self.history.funded.iter().map(|f| f.1).sum()
    }

    fn sent(&self) -> u64 {
        self.history.funded.iter().filter(|f| f.3.is_some()).map(|f| f.1).sum()
    }

    /// What its unconfirmed transactions pay it, less what they spend of it.
    fn unconfirmed(&self) -> i64 {
        let mut delta = 0i64;
        for entry in &self.mempool {
            for (value, script) in &entry.outputs {
                if crate::store::script_key(script) == self.key {
                    delta += *value as i64;
                }
            }
            for prevout in &entry.prevouts {
                if crate::store::script_key(&prevout.script) == self.key {
                    delta -= prevout.value as i64;
                }
            }
        }
        delta
    }

    fn txnums(&self) -> HashSet<u64> {
        self.history.txnums().into_iter().collect()
    }
}

/// Every address a target names: the one, or an account's, scanned up to
/// the gap limit on each chain.
fn scan<'m>(ctx: &'m Ctx<'_>, target: &Target) -> Result<Vec<Scanned<'m>>, String> {
    let load = |address: String, script: Vec<u8>, path: Option<String>| -> Result<Scanned<'m>, String> {
        let script = ScriptRef::Script(script);
        let history = History::load(ctx, &script).map_err(|err| err.1)?;
        let key = script.key();
        let (mempool, _) = mempool_activity(ctx, &key);
        Ok(Scanned { address, path, history, mempool, key })
    };
    match target {
        Target::Address { script, address } => Ok(vec![load(address.clone(), script.clone(), None)?]),
        Target::Account(account) => {
            let mut all = Vec::new();
            for &chain in &account.chains {
                let mut unused = 0;
                let mut index = 0;
                while unused < GAP_LIMIT {
                    let (address, script) = account.derive(chain, index, ctx.network)?;
                    let scanned = load(address, script, Some(account.path(chain, index, ctx.network)))?;
                    unused = if scanned.used() { 0 } else { unused + 1 };
                    all.push(scanned);
                    index += 1;
                }
            }
            Ok(all)
        }
    }
}

/// An input's outpoint, sequence, what it spends (value and script) unless
/// it's a coinbase's, and its scriptSig.
type InputParts = (Hash, u32, u32, Option<(u64, Vec<u8>)>, Vec<u8>);

/// A query of the store, to be run where it may block.
type StoreQuery = Box<dyn FnOnce(&Ctx<'_>) -> Result<Value, String> + Send>;

/// A transaction as Blockbook gives it.
fn tx_json(ctx: &Ctx<'_>, found: &Found<'_>) -> Result<Value, String> {
    let err = |e: super::ApiError| e.1;
    let tip = ctx.snap.tip_height().unwrap_or(0);
    // Each input's outpoint, value, script and scriptSig; each output's.
    let (txid, raw, inputs, outputs, block): (Hash, Vec<u8>, Vec<InputParts>, _, _) = match found {
        Found::Confirmed(txnum) => {
            let tx = ctx.tx(*txnum).map_err(err)?;
            let prevouts = ctx.prevouts(&tx);
            let raw = tx.to_raw(&prevouts);
            let mut inputs = Vec::new();
            for (input, (prev_txid, prev_vout)) in tx.inputs.iter().zip(&prevouts) {
                let prevout = match input.spent {
                    Some(outnum) => Some(ctx.store.output_script(outnum, &ctx.snap).map_err(|e| e.to_string())?),
                    None => None,
                };
                inputs.push((*prev_txid, *prev_vout, input.sequence, prevout, input.script_sig.to_vec()));
            }
            let outputs: Vec<(u64, Vec<u8>)> = tx.outputs.into_iter().map(|o| (o.value, o.script)).collect();
            let height = ctx.store.tx_height(*txnum);
            let record = ctx.store.block(height).unwrap();
            (ctx.store.txid(*txnum), raw, inputs, outputs, Some((height, record.hash(), record.time())))
        }
        Found::Unconfirmed(entry) => {
            let tx = entry.tx();
            let inputs = tx
                .inputs
                .iter()
                .zip(&entry.prevouts)
                .map(|(i, p)| {
                    (i.prev_txid, i.prev_vout, i.sequence, Some((p.value, p.script.clone())), i.script_sig.to_vec())
                })
                .collect();
            (entry.txid, entry.raw.clone(), inputs, entry.outputs.clone(), None)
        }
    };
    let parsed = crate::block::parse_tx(&raw).map_err(|e| e.to_string())?;
    let addresses = |script: &[u8]| match script::address(script, ctx.network) {
        Some(address) => (vec![address], true),
        None => (vec![script::asm(script)], false),
    };
    let mut value_in = 0u64;
    let vin: Vec<Value> = inputs
        .iter()
        .enumerate()
        .map(|(n, (prev_txid, prev_vout, sequence, prevout, script_sig))| match prevout {
            Some((value, script)) => {
                value_in += value;
                let (addresses, is_address) = addresses(script);
                json!({
                    "txid": to_hex_rev(prev_txid),
                    "vout": prev_vout,
                    "sequence": sequence,
                    "n": n,
                    "addresses": addresses,
                    "isAddress": is_address,
                    "value": value.to_string(),
                    "hex": hex::encode(script_sig),
                })
            }
            None => json!({
                "sequence": sequence,
                "n": n,
                "isAddress": false,
                "coinbase": hex::encode(script_sig),
            }),
        })
        .collect();
    let mut vout = Vec::with_capacity(outputs.len());
    for (n, (value, script)) in outputs.iter().enumerate() {
        let (addresses, is_address) = addresses(script);
        let mut out = json!({
            "value": value.to_string(),
            "n": n,
            "hex": hex::encode(script),
            "addresses": addresses,
            "isAddress": is_address,
        });
        if let Some((spender, vin, height)) = spender(ctx, found, &txid, n as u32)? {
            out["spent"] = json!(true);
            out["spentTxId"] = json!(to_hex_rev(&spender));
            out["spentIndex"] = json!(vin);
            out["spentHeight"] = json!(height.map_or(-1, |h| h as i64));
        }
        vout.push(out);
    }
    let value_out: u64 = outputs.iter().map(|(v, _)| v).sum();
    let coinbase = inputs.first().is_some_and(|i| i.3.is_none());
    let mut tx = json!({
        "txid": to_hex_rev(&txid),
        "version": parsed.version,
        "vin": vin,
        "vout": vout,
        "blockHeight": -1,
        "confirmations": 0,
        "blockTime": 0,
        "size": raw.len(),
        "vsize": (parsed.weight() as u64).div_ceil(4),
        "value": value_out.to_string(),
        "valueIn": value_in.to_string(),
        "fees": if coinbase { "0".to_string() } else { (value_in - value_out).to_string() },
        "hex": hex::encode(&raw),
    });
    if parsed.locktime != 0 {
        tx["lockTime"] = json!(parsed.locktime);
    }
    match (found, block) {
        (_, Some((height, hash, time))) => {
            tx["blockHash"] = json!(to_hex_rev(&hash));
            tx["blockHeight"] = json!(height);
            tx["confirmations"] = json!(tip - height + 1);
            tx["blockTime"] = json!(time);
        }
        (Found::Unconfirmed(entry), None) => tx["blockTime"] = json!(entry.time),
        _ => {}
    }
    Ok(tx)
}

/// What spends output `vout` of a transaction: its txid, the input that
/// does, and its block's height if it's confirmed.
fn spender(
    ctx: &Ctx<'_>,
    found: &Found<'_>,
    txid: &Hash,
    vout: u32,
) -> Result<Option<(Hash, usize, Option<u32>)>, String> {
    if let Found::Confirmed(txnum) = found {
        let outnum = ctx.store.tx_bytes(*txnum, &ctx.snap).1 + vout as u64;
        if let Some(by) = ctx.store.output(outnum, &ctx.snap).1 {
            let tx = ctx.tx(by).map_err(|e| e.1)?;
            let vin = tx.inputs.iter().position(|i| i.spent == Some(outnum)).unwrap_or(0);
            return Ok(Some((ctx.store.txid(by), vin, Some(ctx.store.tx_height(by)))));
        }
    }
    Ok(ctx.mempool.spender(txid, vout).map(|(by, vin)| (by, vin, None)))
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct AccountParams {
    descriptor: String,
    details: Option<String>,
    tokens: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
}

/// `getAccountInfo`, or `/api/v2/xpub` and `/api/v2/address`.
fn account_info(ctx: &Ctx<'_>, params: &AccountParams) -> Result<Value, String> {
    let target = parse_target(&params.descriptor, ctx.network)?;
    let scanned = scan(ctx, &target)?;
    let details = params.details.as_deref().unwrap_or("txids");
    let page_size = params.page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, DEFAULT_PAGE_SIZE);
    let page = params.page.unwrap_or(1).max(1);

    let mut confirmed: HashSet<u64> = HashSet::new();
    let mut unconfirmed: HashMap<Hash, &Entry> = HashMap::new();
    let (mut balance, mut received, mut sent, mut pending) = (0u64, 0u64, 0u64, 0i64);
    for s in &scanned {
        confirmed.extend(s.txnums());
        unconfirmed.extend(s.mempool.iter().map(|e| (e.txid, *e)));
        received += s.received();
        sent += s.sent();
        balance += s.received() - s.sent();
        pending += s.unconfirmed();
    }
    let mut txnums: Vec<u64> = confirmed.iter().copied().collect();
    txnums.sort_unstable_by(|a, b| b.cmp(a));
    let mut mempool: Vec<&Entry> = unconfirmed.into_values().collect();
    mempool.sort_unstable_by(|a, b| b.time.cmp(&a.time).then(b.txid.cmp(&a.txid)));
    let total = mempool.len() + txnums.len();
    let mut info = json!({
        "page": page,
        "totalPages": total.div_ceil(page_size).max(1),
        "itemsOnPage": page_size,
        "address": params.descriptor,
        "balance": balance.to_string(),
        "totalReceived": received.to_string(),
        "totalSent": sent.to_string(),
        "unconfirmedBalance": pending.to_string(),
        "unconfirmedTxs": mempool.len(),
        "txs": txnums.len(),
    });
    let mut found: Vec<Found<'_>> = mempool.iter().map(|e| Found::Unconfirmed(e)).collect();
    found.extend(txnums.iter().map(|&n| Found::Confirmed(n)));
    let paged: Vec<&Found<'_>> = found.iter().skip((page - 1) * page_size).take(page_size).collect();
    match details {
        "txids" => {
            let txids: Vec<String> = paged
                .iter()
                .map(|f| match f {
                    Found::Confirmed(n) => to_hex_rev(&ctx.store.txid(*n)),
                    Found::Unconfirmed(e) => to_hex_rev(&e.txid),
                })
                .collect();
            info["txids"] = json!(txids);
        }
        "txs" => {
            let txs = paged.iter().map(|f| tx_json(ctx, f)).collect::<Result<Vec<_>, _>>()?;
            info["transactions"] = json!(txs);
        }
        _ => {}
    }
    if matches!(target, Target::Account(_)) {
        let used = scanned.iter().filter(|s| s.used()).count();
        info["usedTokens"] = json!(used);
        if details != "basic" {
            let which = params.tokens.as_deref().unwrap_or("nonzero");
            let tokens: Vec<Value> = scanned
                .iter()
                .filter(|s| match which {
                    "derived" => true,
                    "used" => s.used(),
                    _ => s.received() > s.sent(),
                })
                .map(|s| {
                    let mut transfers: HashSet<Hash> = s.mempool.iter().map(|e| e.txid).collect();
                    transfers.extend(s.txnums().into_iter().map(|n| ctx.store.txid(n)));
                    let mut token = json!({
                        "type": "XPUBAddress",
                        "name": s.address,
                        "path": s.path,
                        "transfers": transfers.len(),
                        "decimals": 8,
                    });
                    if details != "tokens" {
                        token["balance"] = json!((s.received() - s.sent()).to_string());
                        token["totalReceived"] = json!(s.received().to_string());
                        token["totalSent"] = json!(s.sent().to_string());
                    }
                    token
                })
                .collect();
            info["tokens"] = json!(tokens);
        }
    }
    Ok(info)
}

/// `getAccountUtxo`, or `/api/v2/utxo`.
fn account_utxo(ctx: &Ctx<'_>, descriptor: &str) -> Result<Value, String> {
    let target = parse_target(descriptor, ctx.network)?;
    let scanned = scan(ctx, &target)?;
    let tip = ctx.snap.tip_height().unwrap_or(0);
    let mut utxos = Vec::new();
    for s in &scanned {
        let with_address = |mut utxo: Value| {
            if let Some(path) = &s.path {
                utxo["address"] = json!(s.address);
                utxo["path"] = json!(path);
            }
            utxo
        };
        for entry in &s.mempool {
            for (vout, (value, script)) in entry.outputs.iter().enumerate() {
                if crate::store::script_key(script) == s.key && ctx.mempool.spender(&entry.txid, vout as u32).is_none()
                {
                    utxos.push(with_address(json!({
                        "txid": to_hex_rev(&entry.txid),
                        "vout": vout,
                        "value": value.to_string(),
                        "confirmations": 0,
                    })));
                }
            }
        }
        for &(outnum, value, txnum, spent) in s.history.funded.iter().rev() {
            let (_, vout) = ctx.store.outpoint(outnum, &ctx.snap);
            let txid = ctx.store.txid(txnum);
            if spent.is_some() || ctx.mempool.spender(&txid, vout).is_some() {
                continue;
            }
            let height = ctx.store.tx_height(txnum);
            let confirmations = tip - height + 1;
            let mut utxo = json!({
                "txid": to_hex_rev(&txid),
                "vout": vout,
                "value": value.to_string(),
                "height": height,
                "confirmations": confirmations,
            });
            let coinbase = ctx.store.block(height).is_some_and(|b| b.first_tx == txnum);
            if coinbase && confirmations < crate::validate::COINBASE_MATURITY {
                utxo["coinbase"] = json!(true);
            }
            utxos.push(with_address(utxo));
        }
    }
    Ok(json!(utxos))
}

/// `getBlock`, or `/api/v2/block`: a block, by height or hash, and a page
/// of its transactions.
fn block_info(ctx: &Ctx<'_>, id: &str, page: usize, page_size: usize) -> Result<Value, String> {
    let height = match id.parse::<u32>() {
        Ok(height) => height,
        Err(_) => ctx.block_height(id).map_err(|e| e.1)?,
    };
    let record = ctx.store.block(height).ok_or("Block not found")?;
    let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&record.header).map_err(|e| e.to_string())?;
    let tip = ctx.snap.tip_height().unwrap_or(0);
    let count = ctx.store.tx_count(height, &ctx.snap);
    let page_size = page_size.clamp(1, DEFAULT_PAGE_SIZE);
    let page = page.max(1);
    let txs = (record.first_tx..record.first_tx + count)
        .skip((page - 1) * page_size)
        .take(page_size)
        .map(|n| tx_json(ctx, &Found::Confirmed(n)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut block = json!({
        "page": page,
        "totalPages": (count as usize).div_ceil(page_size).max(1),
        "itemsOnPage": page_size,
        "hash": to_hex_rev(&record.hash()),
        "previousBlockHash": header.prev_blockhash.to_string(),
        "height": height,
        "confirmations": tip - height + 1,
        "size": record.size,
        "time": header.time,
        "version": header.version.to_consensus(),
        "merkleRoot": header.merkle_root.to_string(),
        "nonce": header.nonce.to_string(),
        "bits": format!("{:08x}", header.bits.to_consensus()),
        "difficulty": header.target().difficulty_float().to_string(),
        "txCount": count,
        "txs": txs,
    });
    if let Some(next) = ctx.store.block(height + 1) {
        block["nextBlockHash"] = json!(to_hex_rev(&next.hash()));
    }
    Ok(block)
}

fn info(state: &AppState) -> Value {
    let ctx = Ctx::new(state);
    let tip = ctx.snap.tip_height().unwrap_or(0);
    let best = ctx.store.block(tip).map(|b| to_hex_rev(&b.hash())).unwrap_or_default();
    let genesis = ctx.store.block(0).map(|b| to_hex_rev(&b.hash())).unwrap_or_default();
    let headers = state.status.lock().unwrap().headers;
    json!({
        "name": "Bitcoin",
        "shortcut": if ctx.network == Network::Bitcoin { "BTC" } else { "TEST" },
        "decimals": 8,
        "version": env!("CARGO_PKG_VERSION"),
        "bestHeight": tip,
        "bestHash": best,
        "block0Hash": genesis,
        "testnet": ctx.network != Network::Bitcoin,
        "backend": {
            "chain": state.store.chain.name(),
            "blocks": tip,
            "headers": headers,
            "bestBlockHash": best,
            "subversion": format!("/bitdexter:{}/", env!("CARGO_PKG_VERSION")),
        },
    })
}

/// Fee rates for `targets`, in satoshis per 1000 virtual bytes.
fn estimates(state: &AppState, targets: &[u32]) -> Vec<u64> {
    let mempool = state.mempool.read().unwrap();
    mempool.fee_estimates(targets, FEE_FLOOR).into_iter().map(|(_, rate)| (rate * 1000.0).round() as u64).collect()
}

async fn send_tx(state: &AppState, hex_tx: &str) -> Result<String, String> {
    let raw = hex::decode(hex_tx.trim()).map_err(|_| "Invalid hex".to_string())?;
    let (reply_tx, reply) = tokio::sync::oneshot::channel();
    state.mempool_tx.send((raw, Source::Api(reply_tx))).map_err(|_| "shutting down".to_string())?;
    match reply.await {
        Ok(Ok(txid)) => Ok(to_hex_rev(&txid)),
        Ok(Err(reject)) => Err(format!("-{}: {}", reject.code.unsigned_abs(), reject.reason)),
        Err(_) => Err("shutting down".into()),
    }
}

/// Answers one WebSocket request.
async fn handle(state: &AppState, method: &str, params: Value) -> Result<Value, String> {
    let blocking_with = |f: StoreQuery| {
        let state = state.clone();
        async move {
            blocking(move || {
                let ctx = Ctx::new(&state);
                Ok(f(&ctx))
            })
            .await
            .map_err(|e| e.1)?
        }
    };
    match method {
        "getInfo" => Ok(info(state)),
        "ping" => Ok(json!({})),
        "getAccountInfo" => {
            let params: AccountParams = serde_json::from_value(params).map_err(|e| e.to_string())?;
            blocking_with(Box::new(move |ctx| account_info(ctx, &params))).await
        }
        "getAccountUtxo" => {
            let descriptor = params["descriptor"].as_str().unwrap_or_default().to_string();
            blocking_with(Box::new(move |ctx| account_utxo(ctx, &descriptor))).await
        }
        "getTransaction" => {
            let txid = params["txid"].as_str().unwrap_or_default().to_string();
            blocking_with(Box::new(move |ctx| {
                let found = ctx.find(&txid).map_err(|e| e.1)?;
                tx_json(ctx, &found)
            }))
            .await
        }
        "getBlock" => {
            let id = match &params["id"] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let page = params["page"].as_u64().unwrap_or(1) as usize;
            let page_size = params["pageSize"].as_u64().unwrap_or(DEFAULT_PAGE_SIZE as u64) as usize;
            blocking_with(Box::new(move |ctx| block_info(ctx, &id, page, page_size))).await
        }
        "getBlockHash" => {
            let height = params["height"].as_u64().ok_or("height is required")? as u32;
            let ctx = Ctx::new(state);
            let block = ctx.store.block(height).ok_or("Block not found")?;
            Ok(json!({ "hash": to_hex_rev(&block.hash()) }))
        }
        "estimateFee" => {
            let blocks: Vec<u32> = params["blocks"]
                .as_array()
                .map_or_else(Vec::new, |b| b.iter().filter_map(|v| v.as_u64()).map(|v| (v as u32).max(1)).collect());
            Ok(json!(
                estimates(state, &blocks)
                    .into_iter()
                    .map(|rate| json!({ "feePerUnit": rate.to_string() }))
                    .collect::<Vec<_>>()
            ))
        }
        "sendTransaction" => {
            let hex_tx = params["hex"].as_str().unwrap_or_default();
            Ok(json!({ "result": send_tx(state, hex_tx).await? }))
        }
        "getCurrentFiatRates" => {
            let prices = crate::prices::current(&state.prices).ok_or("Fiat rates aren't available")?;
            let wanted: Vec<String> = params["currencies"]
                .as_array()
                .map(|c| c.iter().filter_map(|c| c.as_str()).map(str::to_lowercase).collect())
                .unwrap_or_default();
            let rates: serde_json::Map<String, Value> = prices
                .rates
                .iter()
                .map(|(currency, rate)| (currency.to_lowercase(), json!(rate)))
                .filter(|(currency, _)| wanted.is_empty() || wanted.contains(currency))
                .collect();
            Ok(json!({ "ts": prices.time, "rates": rates }))
        }
        "getFiatRatesForTimestamps" | "getFiatRatesTickersList" => Err("Historical fiat rates aren't available".into()),
        _ => Err(format!("Unknown method {method}")),
    }
}

async fn websocket(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| serve_socket(state, socket))
}

async fn serve_socket(state: AppState, mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        let Message::Text(text) = message else { continue };
        let Ok(request) = serde_json::from_str::<Value>(&text) else { continue };
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or_default().to_string();
        let data = match handle(&state, &method, request["params"].clone()).await {
            Ok(data) => data,
            Err(message) => json!({ "error": { "message": message } }),
        };
        let reply = json!({ "id": id, "data": data }).to_string();
        if socket.send(Message::Text(reply.into())).await.is_err() {
            break;
        }
    }
}

fn rest_result(result: Result<Value, String>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response(),
    }
}

async fn rest_info(State(state): State<AppState>) -> Json<Value> {
    Json(info(&state))
}

async fn rest_xpub(
    State(state): State<AppState>,
    Path(descriptor): Path<String>,
    Query(mut params): Query<AccountParams>,
) -> Response {
    params.descriptor = descriptor;
    let result = blocking(move || {
        let ctx = Ctx::new(&state);
        Ok(account_info(&ctx, &params))
    })
    .await;
    rest_result(result.unwrap_or_else(|e| Err(e.1)))
}

async fn rest_utxo(State(state): State<AppState>, Path(descriptor): Path<String>) -> Response {
    let result = blocking(move || {
        let ctx = Ctx::new(&state);
        Ok(account_utxo(&ctx, &descriptor))
    })
    .await;
    rest_result(result.unwrap_or_else(|e| Err(e.1)))
}

async fn rest_tx(State(state): State<AppState>, Path(txid): Path<String>) -> Response {
    let result = blocking(move || {
        let ctx = Ctx::new(&state);
        Ok(ctx.find(&txid).map_err(|e| e.1).and_then(|found| tx_json(&ctx, &found)))
    })
    .await;
    rest_result(result.unwrap_or_else(|e| Err(e.1)))
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct PageParams {
    page: Option<usize>,
    page_size: Option<usize>,
}

async fn rest_block(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<PageParams>,
) -> Response {
    let result = blocking(move || {
        let ctx = Ctx::new(&state);
        Ok(block_info(&ctx, &id, params.page.unwrap_or(1), params.page_size.unwrap_or(DEFAULT_PAGE_SIZE)))
    })
    .await;
    rest_result(result.unwrap_or_else(|e| Err(e.1)))
}

/// The fee rate for a target, in BTC per 1000 virtual bytes, as Blockbook's
/// REST API gives it.
async fn rest_estimatefee(State(state): State<AppState>, Path(blocks): Path<String>) -> Response {
    let blocks: u32 = blocks.parse().unwrap_or(1).max(1);
    let rate = estimates(&state, &[blocks])[0];
    Json(json!({ "result": format!("{:.8}", rate as f64 / 1e8) })).into_response()
}

async fn rest_sendtx_get(State(state): State<AppState>, Path(hex_tx): Path<String>) -> Response {
    rest_result(send_tx(&state, &hex_tx).await.map(|txid| json!({ "result": txid })))
}

async fn rest_sendtx_post(State(state): State<AppState>, body: String) -> Response {
    rest_result(send_tx(&state, &body).await.map(|txid| json!({ "result": txid })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_descriptors_and_derives() {
        // BIP84's test vector: zpub for "abandon … about", first receive
        // address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu.
        let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        let Target::Account(account) = parse_target(zpub, Network::Bitcoin).unwrap() else { panic!() };
        assert_eq!(account.kind, Kind::Wpkh);
        assert_eq!(account.derive(0, 0, Network::Bitcoin).unwrap().0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(account.path(0, 0, Network::Bitcoin), "m/84'/0'/0'/0/0");
        // BIP86's: the same mnemonic's first taproot receive address.
        let xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
        let descriptor = format!("tr([73c5da0a/86h/0h/0h]{xpub}/<0;1>/*)#abcdefgh");
        let Target::Account(account) = parse_target(&descriptor, Network::Bitcoin).unwrap() else { panic!() };
        assert_eq!(account.kind, Kind::Tr);
        assert_eq!(
            account.derive(0, 0, Network::Bitcoin).unwrap().0,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(account.path(1, 2, Network::Bitcoin), "m/86'/0'/0'/1/2");
        assert!(matches!(
            parse_target("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Network::Bitcoin).unwrap(),
            Target::Address { .. }
        ));
        assert!(parse_target(zpub, Network::Testnet4).is_err());
    }
}
