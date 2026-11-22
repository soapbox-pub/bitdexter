//! The price of bitcoin, optionally: polled from exchanges' public tickers
//! every minute, the median of those that answer, for the currencies
//! mempool.space's `/v1/prices` gives. Exchanges see bitdexter asking, never
//! the people using it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::Value;

/// The currencies priced, as mempool.space's `/v1/prices` has them.
pub const CURRENCIES: [&str; 7] = ["USD", "EUR", "GBP", "CAD", "CHF", "AUD", "JPY"];
const INTERVAL: Duration = Duration::from_secs(60);
/// How old prices may get before they're not given at all.
const STALE: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct Prices {
    /// When they were fetched, in seconds since 1970.
    pub time: u64,
    /// The price of a bitcoin in each currency.
    pub rates: BTreeMap<&'static str, f64>,
}

pub type Shared = Arc<RwLock<Option<Prices>>>;

/// The latest prices, if they're recent enough.
pub fn current(shared: &Shared) -> Option<Prices> {
    let prices = shared.read().unwrap().clone()?;
    (crate::mempool::now().saturating_sub(prices.time) <= STALE).then_some(prices)
}

/// Coinbase's rates for BTC, from `/v2/exchange-rates`.
fn coinbase(body: &Value) -> BTreeMap<&'static str, f64> {
    CURRENCIES.iter().filter_map(|&c| Some((c, body["data"]["rates"][c].as_str()?.parse().ok()?))).collect()
}

/// Kraken's last trade prices, from `/0/public/Ticker`, whose pairs are
/// named like `XXBTZUSD` or `XBTAUD`.
fn kraken(body: &Value) -> BTreeMap<&'static str, f64> {
    let mut rates = BTreeMap::new();
    if let Some(result) = body["result"].as_object() {
        for (pair, ticker) in result {
            let Some(&currency) = CURRENCIES.iter().find(|c| pair.ends_with(**c)) else { continue };
            if let Some(price) = ticker["c"][0].as_str().and_then(|p| p.parse().ok()) {
                rates.insert(currency, price);
            }
        }
    }
    rates
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    values.retain(|v| v.is_finite() && *v > 0.0);
    values.sort_by(f64::total_cmp);
    match values.len() {
        0 => None,
        n if n % 2 == 1 => Some(values[n / 2]),
        n => Some((values[n / 2 - 1] + values[n / 2]) / 2.0),
    }
}

/// Combines each source's rates into one, the median for each currency.
fn combine(sources: &[BTreeMap<&'static str, f64>]) -> BTreeMap<&'static str, f64> {
    CURRENCIES
        .iter()
        .filter_map(|&c| Some((c, median(sources.iter().filter_map(|s| s.get(c).copied()).collect())?)))
        .collect()
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<Value> {
    let response = client.get(url).send().await.ok()?.error_for_status().ok()?;
    serde_json::from_str(&response.text().await.ok()?).ok()
}

/// Polls the exchanges until shut down, keeping the latest in `shared`.
pub async fn poll(shared: Shared, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let client = match reqwest::Client::builder()
        .user_agent(concat!("bitdexter/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            tracing::error!("can't fetch prices: {err}");
            return;
        }
    };
    let mut interval = tokio::time::interval(INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => return,
        }
        let (cb, kr) = tokio::join!(
            fetch(&client, "https://api.coinbase.com/v2/exchange-rates?currency=BTC"),
            fetch(
                &client,
                "https://api.kraken.com/0/public/Ticker?pair=XBTUSD,XBTEUR,XBTGBP,XBTCAD,XBTCHF,XBTAUD,XBTJPY"
            ),
        );
        let sources: Vec<_> = [cb.map(|b| coinbase(&b)), kr.map(|b| kraken(&b))].into_iter().flatten().collect();
        let rates = combine(&sources);
        if rates.is_empty() {
            tracing::warn!("no exchange answered for prices");
            continue;
        }
        *shared.write().unwrap() = Some(Prices { time: crate::mempool::now(), rates });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn combines_sources() {
        let cb = coinbase(&json!({ "data": { "rates": { "USD": "100.5", "EUR": "90", "XYZ": "1" } } }));
        let kr = kraken(&json!({ "result": {
            "XXBTZUSD": { "c": ["99.5", "1"] },
            "XBTAUD": { "c": ["150", "1"] },
        } }));
        let rates = combine(&[cb, kr]);
        assert_eq!(rates["USD"], 100.0);
        assert_eq!(rates["EUR"], 90.0);
        assert_eq!(rates["AUD"], 150.0);
        assert!(!rates.contains_key("JPY"));
    }
}
