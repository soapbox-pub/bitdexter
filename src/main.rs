use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;

use bitdexter::config::Config;
use bitdexter::network::Chain;
use bitdexter::node::{Node, NodeConfig, Status};
use bitdexter::store::Store;

/// A Bitcoin indexer that syncs over P2P and serves an Esplora-compatible
/// API.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The config file; by default ~/.config/bitdexter/bitdexter.toml, if
    /// it's there.
    #[arg(long)]
    config: Option<PathBuf>,
    /// mainnet, testnet4, signet or regtest.
    #[arg(long)]
    network: Option<Chain>,
    /// Where the index is kept, in a directory per network.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Where the HTTP API listens.
    #[arg(long)]
    http: Option<std::net::SocketAddr>,
    /// A peer to keep connected, as host:port. May be given more than once.
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Connect only to the peers given.
    #[arg(long)]
    connect_only: bool,
    /// Stop indexing at this height.
    #[arg(long)]
    stop_height: Option<u32>,
    /// Index in bulk when more than this many blocks behind.
    #[arg(long)]
    bulk_threshold: Option<u32>,
    /// Verify every block's scripts, even below the assumevalid block.
    #[arg(long)]
    verify_all: bool,
    /// Serve Blockbook's API too.
    #[arg(long)]
    blockbook: bool,
    /// Serve silent payment tweaks too, as BlindBit Oracle does.
    #[arg(long)]
    blindbit: bool,
    /// Fetch the price of bitcoin from exchanges, for `/v1/prices`.
    #[arg(long)]
    prices: bool,
    /// Serve the Electrum protocol here, as host:port.
    #[arg(long)]
    electrum: Option<std::net::SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let mut config = Config::load(args.config.as_deref())?;
    if let Some(network) = args.network {
        config.network = network;
    }
    if let Some(dir) = args.data_dir {
        config.data_dir = Some(dir);
    }
    if let Some(http) = args.http {
        config.http = http;
    }
    config.p2p.peers.extend(args.peers);
    config.p2p.connect_only |= args.connect_only;
    if args.stop_height.is_some() {
        config.p2p.stop_height = args.stop_height;
    }
    if let Some(threshold) = args.bulk_threshold {
        config.bulk_threshold = threshold;
    }
    if args.verify_all {
        config.assume_valid = false;
    }
    config.blockbook |= args.blockbook;
    config.blindbit |= args.blindbit;
    config.prices |= args.prices;
    if args.electrum.is_some() {
        config.electrum = args.electrum;
    }

    let dir = config.network_dir();
    tracing::info!("bitdexter {} on {}, in {}", env!("CARGO_PKG_VERSION"), config.network, dir.display());
    let writer = Store::open(&dir, config.network)?;
    let store = writer.store.clone();
    let status = Arc::new(Mutex::new(Status::default()));
    let node_config = NodeConfig {
        chain: config.network,
        peers: config.resolve_peers()?,
        connect_only: config.p2p.connect_only,
        max_peers: config.p2p.max_peers,
        stop_height: config.p2p.stop_height,
        bulk_threshold: config.bulk_threshold,
        assume_valid: config.assume_valid,
    };
    let mempool = bitdexter::mempool::Shared::default();
    let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel();
    let mempool_tx = bitdexter::mempool::spawn(mempool.clone(), store.clone(), relay_tx);
    let node = Node::new(node_config, &dir, writer, status.clone(), mempool.clone(), mempool_tx.clone(), relay_rx)?;

    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let prices = bitdexter::prices::Shared::default();
    if config.prices {
        tokio::spawn(bitdexter::prices::poll(prices.clone(), shutdown.clone()));
    }
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        let _ = shutdown_tx.send(true);
    });
    if let Some(addr) = config.electrum {
        let server = bitdexter::electrum::Server {
            store: store.clone(),
            mempool: mempool.clone(),
            mempool_tx: mempool_tx.clone(),
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(err) = bitdexter::electrum::serve(addr, server, shutdown).await {
                tracing::error!("serving the Electrum protocol: {err:#}");
            }
        });
    }
    let api = tokio::spawn(bitdexter::api::serve(
        config.http,
        bitdexter::api::AppState { store, status, mempool, mempool_tx, prices: prices.clone() },
        bitdexter::api::Extras { blockbook: config.blockbook, blindbit: config.blindbit },
        shutdown.clone(),
    ));
    node.run(shutdown).await?;
    api.abort();
    Ok(())
}
