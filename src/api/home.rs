//! The page at `/`: what this server is, how far it's synced, and the APIs it
//! serves, for someone who opens it in a browser.

use std::fmt::Write;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::esplora::Ctx;
use super::{ApiError, AppState, Extras, blocking};
use crate::hash::to_hex_rev;

/// The first transaction ever, there to try `/tx/{txid}` on.
const GENESIS_TXID: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

/// What the page shows of the chain.
struct Tip {
    height: u32,
    hash: String,
    time: u32,
}

pub async fn home(State(state): State<AppState>, extras: Extras) -> Result<Response, ApiError> {
    let status = state.status.lock().unwrap().clone();
    let network = state.store.chain.name();
    let syncing = state.store.syncing();
    let mempool = state.mempool.read().unwrap().len();
    let tip = blocking({
        let state = state.clone();
        move || {
            let ctx = Ctx::new(&state);
            let Ok(height) = ctx.tip() else { return Ok(None) };
            let block = ctx.block(height).ok_or_else(|| anyhow::anyhow!("no record of tip block {height}"))?;
            Ok(Some(Tip { height, hash: to_hex_rev(&block.hash()), time: block.time() }))
        }
    })
    .await?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());

    let mut rows = String::new();
    let mut row = |name: &str, value: String| {
        let _ = write!(rows, "<tr><th>{name}</th><td>{value}</td></tr>");
    };
    row("Network", network.to_string());
    match &tip {
        Some(tip) => {
            row("Height", format!("<a href=\"/block/{}\">{}</a>", tip.hash, group(tip.height.into())));
            row("Tip", format!("<code>{}</code>", tip.hash));
            row("Mined", ago(now.saturating_sub(tip.time.into())));
        }
        None => row("Height", "nothing indexed yet".into()),
    }
    let indexed = status.indexed.unwrap_or(0);
    if syncing || indexed < status.headers {
        row("Syncing", format!("indexed to block {} of {}", group(indexed.into()), group(status.headers.into())));
    }
    row("Mempool", format!("<a href=\"/mempool\">{} transactions</a>", group(mempool as u64)));
    row("Peers", status.peers.to_string());
    row("Version", env!("CARGO_PKG_VERSION").into());

    let block = tip.as_ref().map(|tip| tip.hash.as_str());
    let mut apis = String::new();
    section(
        &mut apis,
        "Esplora",
        "https://github.com/Blockstream/esplora/blob/master/API.md",
        "Served at the root and under <code>/api</code>.",
        &[
            ("/blocks/tip/height", Some("/blocks/tip/height")),
            ("/blocks/tip/hash", Some("/blocks/tip/hash")),
            ("/blocks[/{start}]", Some("/blocks")),
            ("/block-height/{height}", Some("/block-height/0")),
            ("/block/{hash}", block.map(|hash| format!("/block/{hash}")).as_deref()),
            ("/block/{hash}/txids", block.map(|hash| format!("/block/{hash}/txids")).as_deref()),
            ("/tx/{txid}", Some(&format!("/tx/{GENESIS_TXID}"))),
            ("/tx/{txid}/status", Some(&format!("/tx/{GENESIS_TXID}/status"))),
            ("/address/{address}", None),
            ("/address/{address}/txs", None),
            ("/address/{address}/utxo", None),
            ("/scripthash/{hash}", None),
            ("POST /tx", None),
            ("/mempool", Some("/mempool")),
            ("/mempool/recent", Some("/mempool/recent")),
            ("/fee-estimates", Some("/fee-estimates")),
            ("/v1/fees/recommended", Some("/v1/fees/recommended")),
            ("/v1/prices", Some("/v1/prices")),
        ],
    );
    if extras.blockbook {
        section(
            &mut apis,
            "Blockbook",
            "https://github.com/trezor/blockbook/blob/master/docs/api.md",
            "Its REST API, and its WebSocket API at <code>/websocket</code>.",
            &[
                ("/api/v2", Some("/api/v2")),
                ("/api/v2/address/{address}", None),
                ("/api/v2/xpub/{descriptor}", None),
                ("/api/v2/utxo/{descriptor}", None),
                ("/api/v2/tx/{txid}", Some(&format!("/api/v2/tx/{GENESIS_TXID}"))),
                ("/api/v2/block/{height or hash}", Some("/api/v2/block/0")),
                ("/api/v2/estimatefee/{blocks}", Some("/api/v2/estimatefee/6")),
            ],
        );
    }
    if extras.blindbit {
        section(
            &mut apis,
            "BlindBit",
            "https://github.com/setavenger/blindbit-oracle",
            "Silent payment tweaks, for light wallets.",
            &[
                ("/blindbit/info", Some("/blindbit/info")),
                (
                    "/blindbit/tweaks/{height}",
                    tip.as_ref().map(|tip| format!("/blindbit/tweaks/{}", tip.height)).as_deref(),
                ),
                (
                    "/blindbit/utxos/{height}",
                    tip.as_ref().map(|tip| format!("/blindbit/utxos/{}", tip.height)).as_deref(),
                ),
            ],
        );
    }

    let page = format!(include_str!("home.html"), network = network, rows = rows, apis = apis,);
    Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], page)
        .into_response())
}

/// A list of endpoints, each linked to an example of it if it has one.
fn section(out: &mut String, name: &str, docs: &str, about: &str, endpoints: &[(&str, Option<&str>)]) {
    let _ = write!(out, "<h2><a href=\"{docs}\">{name}</a></h2><p>{about}</p><ul>");
    for (endpoint, example) in endpoints {
        match example {
            Some(href) => {
                let _ = write!(out, "<li><a href=\"{href}\"><code>{}</code></a></li>", escape(endpoint));
            }
            None => {
                let _ = write!(out, "<li><code>{}</code></li>", escape(endpoint));
            }
        }
    }
    out.push_str("</ul>");
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// `977431` as `977,431`.
fn group(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// How long ago something was, `seconds` ago, roughly.
fn ago(seconds: u64) -> String {
    let (n, unit) = match seconds {
        0..60 => return "just now".into(),
        60..3600 => (seconds / 60, "minute"),
        3600..86400 => (seconds / 3600, "hour"),
        _ => (seconds / 86400, "day"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_digits() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(977431), "977,431");
        assert_eq!(group(1234567), "1,234,567");
    }

    #[test]
    fn says_how_long_ago() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(60), "1 minute ago");
        assert_eq!(ago(600), "10 minutes ago");
        assert_eq!(ago(7200), "2 hours ago");
        assert_eq!(ago(86400 * 3), "3 days ago");
    }
}
