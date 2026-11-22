//! Following the chain: keeping peers connected, syncing headers, and
//! downloading blocks from many peers at once to hand to the indexer in
//! order.
//!
//! Headers are synced first, from one peer at a time, and the chain with
//! the most work is followed. Blocks are requested along it, up to a window
//! ahead of what's been handed to the indexer, spread across every peer
//! that has them, and buffered until they can be handed over in order. A
//! peer holding up the block the indexer needs next while the window is
//! full is dropped, and the block asked of another. When the best chain
//! changes under the blocks already handed over, the indexer is told to
//! rewind to where they part.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use tokio::sync::mpsc;

use crate::chain::{HeaderChain, HeaderError};
use crate::indexer;
use crate::mempool::{self, Source};
use crate::network::Chain;
use crate::p2p::addrman::AddrMan;
use crate::p2p::{PeerEvent, PeerId, PeerInfo, run_peer};
use crate::store::Writer;

/// Blocks asked of one peer at a time: enough for about this many bytes,
/// between these bounds, so that small blocks don't leave the link idle.
const IN_FLIGHT_BYTES: f64 = 8e6;
const MIN_IN_FLIGHT: usize = 16;
const MAX_IN_FLIGHT: usize = 512;
/// How far past the last block handed to the indexer blocks are requested.
const WINDOW: u32 = 8192;
/// The most bytes of blocks held waiting for those before them.
const MAX_BUFFERED: usize = 512 << 20;
/// Blocks handed to the indexer and not yet indexed, at most.
const MAX_HANDED: u32 = 64;
/// How long the block the indexer needs next may be waited on while the
/// window is full, before the peer asked for it is dropped.
const STALL_TIMEOUT: Duration = Duration::from_secs(8);
/// How long any block may be waited on.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(90);
const HEADERS_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a peer is asked for headers anyway, in case an announcement
/// was missed.
const HEADERS_POLL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub chain: Chain,
    /// Peers always kept connected.
    pub peers: Vec<SocketAddr>,
    /// Connect only to `peers`.
    pub connect_only: bool,
    pub max_peers: usize,
    /// Don't index past this height.
    pub stop_height: Option<u32>,
    /// Index in bulk when more than this many blocks behind.
    pub bulk_threshold: u32,
    /// Skip verifying the scripts of blocks up to the network's assumevalid
    /// block, if it's in the best chain.
    pub assume_valid: bool,
}

/// What the node's doing, for whoever asks.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Status {
    pub peers: usize,
    pub headers: u32,
    pub indexed: Option<u32>,
}

struct Peer {
    info: PeerInfo,
    commands: mpsc::UnboundedSender<NetworkMessage>,
    in_flight: HashSet<BlockHash>,
    /// The best height it's said or shown it has.
    height: u32,
    headers_asked: Option<Instant>,
    last_headers_poll: Instant,
}

struct Request {
    peer: PeerId,
    height: u32,
    at: Instant,
}

pub struct Node {
    config: NodeConfig,
    headers: HeaderChain,
    addrman: AddrMan,
    peers: HashMap<PeerId, Peer>,
    /// Addresses being connected or connected to.
    busy: HashSet<SocketAddr>,
    next_id: PeerId,
    events_tx: mpsc::Sender<PeerEvent>,
    events: mpsc::Receiver<PeerEvent>,
    addrs_tx: mpsc::UnboundedSender<Vec<SocketAddr>>,
    addrs: mpsc::UnboundedReceiver<Vec<SocketAddr>>,
    indexer_tx: mpsc::UnboundedSender<indexer::Command>,
    indexer: mpsc::UnboundedReceiver<indexer::Event>,
    /// Hashes of the blocks handed to the indexer, by height.
    sent: Vec<BlockHash>,
    /// The peer each block handed over and not yet indexed came from.
    sent_from: BTreeMap<u32, PeerId>,
    indexed: Option<u32>,
    requested: HashMap<BlockHash, Request>,
    received: BTreeMap<u32, (BlockHash, PeerId, Vec<u8>)>,
    received_bytes: usize,
    header_sync: Option<PeerId>,
    seeding: bool,
    last_seed: Option<Instant>,
    status: Arc<Mutex<Status>>,
    last_log: Instant,
    best_changed: bool,
    /// The lowest height that may not have been requested yet.
    request_from: u32,
    /// A moving average of the size of blocks received.
    avg_block: f64,
    last_upkeep: Instant,
    mempool: mempool::Shared,
    /// Where transactions from peers go to be checked.
    mempool_tx: std::sync::mpsc::Sender<(Vec<u8>, Source)>,
    /// Transactions sent to the API and accepted, to send to peers.
    relay: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Those, until they're confirmed, to send again now and then.
    ours: HashMap<crate::hash::Hash, (Vec<u8>, Instant)>,
    /// Transactions asked of peers, and when.
    tx_requests: HashMap<crate::hash::Hash, Instant>,
    store: std::sync::Arc<crate::store::Store>,
    indexer_thread: Option<std::thread::JoinHandle<()>>,
}

impl Node {
    pub fn new(
        config: NodeConfig,
        data_dir: &Path,
        writer: Writer,
        status: Arc<Mutex<Status>>,
        mempool: mempool::Shared,
        mempool_tx: std::sync::mpsc::Sender<(Vec<u8>, Source)>,
        relay: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Result<Node> {
        let store = writer.store.clone();
        let mut headers = HeaderChain::open(config.chain, &data_dir.join("headers"))?;
        // What's indexed is in the header chain, even if the file lost it.
        let mut sent = Vec::with_capacity(writer.next_height() as usize);
        let mut missing = Vec::new();
        for height in 0..writer.next_height() {
            let record = writer.block(height);
            let header: Header = bitcoin::consensus::deserialize(&record.header)?;
            if height > 0 && headers.get(&header.block_hash()).is_none() {
                missing.push(header);
            }
            sent.push(header.block_hash());
        }
        if !missing.is_empty() {
            headers.accept(&missing).map_err(|err| anyhow::anyhow!("indexed headers don't check out: {err}"))?;
        }
        let indexed = writer.next_height().checked_sub(1);
        let (events_tx, events) = mpsc::channel(1024);
        let (addrs_tx, addrs) = mpsc::unbounded_channel();
        let (indexer_tx, indexer_rx) = mpsc::unbounded_channel();
        let (indexer_events_tx, indexer_events) = mpsc::unbounded_channel();
        let indexer_thread = indexer::spawn(writer, config.bulk_threshold, indexer_rx, indexer_events_tx);
        let addrman = AddrMan::load(data_dir.join("peers.txt"));
        tracing::info!("{} headers known, to height {}; {} indexed", headers.len(), headers.tip_height(), sent.len());
        // The genesis block needn't be downloaded.
        let mut received = BTreeMap::new();
        let mut received_bytes = 0;
        if sent.is_empty() {
            let genesis = bitcoin::constants::genesis_block(config.chain.network());
            let bytes = bitcoin::consensus::serialize(&genesis);
            received_bytes = bytes.len();
            received.insert(0, (genesis.block_hash(), PeerId::MAX, bytes));
        }
        Ok(Node {
            config,
            headers,
            addrman,
            peers: HashMap::new(),
            busy: HashSet::new(),
            next_id: 0,
            events_tx,
            events,
            addrs_tx,
            addrs,
            indexer_tx,
            indexer: indexer_events,
            sent,
            sent_from: BTreeMap::new(),
            indexed,
            requested: HashMap::new(),
            received,
            received_bytes,
            header_sync: None,
            seeding: false,
            last_seed: None,
            status,
            last_log: Instant::now(),
            best_changed: true,
            request_from: 0,
            avg_block: 1000.0,
            last_upkeep: Instant::now() - Duration::from_secs(1),
            mempool,
            mempool_tx,
            relay,
            ours: HashMap::new(),
            tx_requests: HashMap::new(),
            store,
            indexer_thread: Some(indexer_thread),
        })
    }

    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                Some(event) = self.events.recv() => self.on_peer_event(event),
                Some(event) = self.indexer.recv() => self.on_indexer_event(event)?,
                Some(raw) = self.relay.recv() => self.broadcast(raw),
                Some(addrs) = self.addrs.recv() => {
                    self.seeding = false;
                    for addr in addrs {
                        self.addrman.add(addr);
                    }
                }
                _ = tick.tick() => {}
                _ = shutdown.changed() => break,
            }
            self.step();
        }
        self.addrman.save();
        // Closing the indexer's channel lets it commit and finish.
        let thread = self.indexer_thread.take();
        drop(self);
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join()).await.ok();
        }
        Ok(())
    }

    fn on_peer_event(&mut self, event: PeerEvent) {
        match event {
            PeerEvent::Connected { id, info, commands } => {
                tracing::info!(
                    "connected to {} ({}, height {}), {} peers",
                    info.addr,
                    info.user_agent,
                    info.start_height,
                    self.peers.len() + 1
                );
                self.addrman.succeeded(info.addr);
                if self.addrman.len() < 1000 && !self.config.connect_only {
                    let _ = commands.send(NetworkMessage::GetAddr);
                }
                let height = info.start_height.max(0) as u32;
                self.peers.insert(
                    id,
                    Peer {
                        info,
                        commands,
                        in_flight: HashSet::new(),
                        height,
                        headers_asked: None,
                        last_headers_poll: Instant::now(),
                    },
                );
            }
            PeerEvent::Message { id, message } => self.on_message(id, message),
            PeerEvent::Block { id, bytes } => self.on_block(id, bytes),
            PeerEvent::Disconnected { id, addr, reason, connected } => {
                self.busy.remove(&addr);
                if connected {
                    tracing::info!("disconnected from {addr}: {reason}");
                } else {
                    tracing::debug!("couldn't connect to {addr}: {reason}");
                    self.addrman.failed(addr);
                }
                if let Some(peer) = self.peers.remove(&id) {
                    for hash in peer.in_flight {
                        self.requested.remove(&hash);
                    }
                    self.request_from = 0;
                }
                if self.header_sync == Some(id) {
                    self.header_sync = None;
                }
            }
        }
    }

    fn disconnect(&mut self, id: PeerId, why: &str) {
        if let Some(peer) = self.peers.remove(&id) {
            tracing::info!("dropping {}: {why}", peer.info.addr);
            for hash in peer.in_flight {
                self.requested.remove(&hash);
            }
            self.request_from = 0;
            // Dropping its command channel ends its task, which reports it.
        }
        if self.header_sync == Some(id) {
            self.header_sync = None;
        }
    }

    fn send(&self, id: PeerId, message: NetworkMessage) {
        if let Some(peer) = self.peers.get(&id) {
            let _ = peer.commands.send(message);
        }
    }

    fn ask_headers(&mut self, id: PeerId) {
        let locator = self.headers.locator();
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.headers_asked = Some(Instant::now());
            peer.last_headers_poll = Instant::now();
            let _ =
                peer.commands.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, BlockHash::all_zeros())));
        }
    }

    fn on_message(&mut self, id: PeerId, message: NetworkMessage) {
        match message {
            NetworkMessage::Headers(headers) => self.on_headers(id, headers),
            NetworkMessage::Inv(inventory) => {
                let unknown = inventory.iter().any(|inv| match inv {
                    Inventory::Block(hash) | Inventory::WitnessBlock(hash) => self.headers.get(hash).is_none(),
                    _ => false,
                });
                if unknown {
                    self.ask_headers(id);
                }
                self.ask_txs(id, &inventory);
            }
            NetworkMessage::Tx(tx) => {
                let txid = tx.compute_txid().to_byte_array();
                self.tx_requests.remove(&txid);
                let _ = self.mempool_tx.send((bitcoin::consensus::serialize(&tx), Source::Peer));
            }
            NetworkMessage::GetData(inventory) => {
                // Peers may ask for the transactions sent them.
                for inv in inventory {
                    if let Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) = inv
                        && let Some((raw, _)) = self.ours.get(&txid.to_byte_array())
                        && let Ok(tx) = bitcoin::consensus::deserialize(raw)
                    {
                        self.send(id, NetworkMessage::Tx(tx));
                    }
                }
            }
            NetworkMessage::Addr(addrs) => {
                for (_, addr) in addrs {
                    if let Ok(addr) = addr.socket_addr() {
                        self.addrman.add(addr);
                    }
                }
            }
            NetworkMessage::AddrV2(addrs) => {
                for addr in addrs {
                    if let Ok(addr) = addr.socket_addr() {
                        self.addrman.add(addr);
                    }
                }
            }
            NetworkMessage::NotFound(inventory) => {
                for inv in inventory {
                    if let Inventory::WitnessBlock(hash) | Inventory::Block(hash) = inv
                        && let Some(request) = self.requested.remove(&hash)
                    {
                        if let Some(peer) = self.peers.get_mut(&request.peer) {
                            peer.in_flight.remove(&hash);
                            // It doesn't have it, so it's not as far along as it said.
                            peer.height = peer.height.min(request.height.saturating_sub(1));
                        }
                        self.request_from = 0;
                    }
                }
            }
            _ => {}
        }
    }

    fn on_headers(&mut self, id: PeerId, headers: Vec<Header>) {
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.headers_asked = None;
        }
        if headers.is_empty() {
            if self.header_sync == Some(id) {
                self.header_sync = None;
            }
            return;
        }
        let before = self.headers.tip().hash;
        match self.headers.accept(&headers) {
            Ok(new) => {
                let last = headers.last().unwrap().block_hash();
                if let Some(entry) = self.headers.get(&last) {
                    let height = entry.height;
                    if let Some(peer) = self.peers.get_mut(&id) {
                        peer.height = peer.height.max(height);
                    }
                }
                if self.headers.tip().hash != before {
                    self.best_changed = true;
                }
                if headers.len() == 2000 {
                    self.header_sync = Some(id);
                    self.ask_headers(id);
                } else if self.header_sync == Some(id) {
                    self.header_sync = None;
                }
                if new > 0 && self.last_log.elapsed() >= Duration::from_secs(5) {
                    self.last_log = Instant::now();
                    tracing::info!("headers to height {}", self.headers.tip_height());
                }
            }
            Err(HeaderError::Orphan) => self.ask_headers(id),
            Err(HeaderError::TooNew) => {}
            Err(HeaderError::Invalid(reason)) => self.disconnect(id, &format!("sent an invalid header: {reason}")),
        }
    }

    fn on_block(&mut self, id: PeerId, bytes: Vec<u8>) {
        if bytes.len() < 80 {
            return self.disconnect(id, "sent a block too short to be one");
        }
        let hash = BlockHash::from_byte_array(crate::hash::sha256d(&bytes[..80]));
        let Some(request) = self.requested.remove(&hash) else {
            // Unasked, or asked again of another after this one was slow.
            return;
        };
        if let Some(peer) = self.peers.get_mut(&request.peer) {
            peer.in_flight.remove(&hash);
        }
        self.avg_block = self.avg_block * 0.95 + bytes.len() as f64 * 0.05;
        let next = self.sent.len() as u32;
        if request.height >= next && self.headers.at(request.height).is_some_and(|e| e.hash == hash) {
            self.received_bytes += bytes.len();
            self.received.insert(request.height, (hash, id, bytes));
        }
    }

    fn on_indexer_event(&mut self, event: indexer::Event) -> Result<()> {
        match event {
            indexer::Event::Connected { height } => {
                self.indexed = Some(height);
                self.sent_from.remove(&height);
            }
            indexer::Event::Rewound { height } => {
                self.indexed = Some(height);
            }
            indexer::Event::Rejected { height, hash, reason, mutated } => {
                let from = self.sent_from.remove(&height);
                if mutated {
                    if let Some(from) = from {
                        self.disconnect(from, &format!("sent a mutated block {height}: {reason}"));
                    }
                } else {
                    self.headers.mark_invalid(&hash);
                    self.best_changed = true;
                }
                self.sent.truncate(height as usize);
                self.sent_from.retain(|&h, _| h < height);
                self.request_from = 0;
            }
            indexer::Event::Failed(err) => anyhow::bail!("the indexer failed: {err}"),
        }
        let mut status = self.status.lock().unwrap();
        status.indexed = self.indexed;
        Ok(())
    }

    /// Everything the node does between events.
    fn step(&mut self) {
        if self.last_upkeep.elapsed() >= Duration::from_millis(250) {
            self.last_upkeep = Instant::now();
            self.maintain_peers();
            self.sync_headers();
            self.time_out_requests();
            self.rebroadcast();
        }
        if self.best_changed {
            self.best_changed = false;
            self.follow_best_chain();
            self.request_from = 0;
        }
        self.request_blocks();
        self.hand_over();
        let mut status = self.status.lock().unwrap();
        status.peers = self.peers.len();
        status.headers = self.headers.tip_height();
    }

    fn maintain_peers(&mut self) {
        let start_height = self.headers.tip_height() as i32;
        let mut wanted: Vec<SocketAddr> =
            self.config.peers.iter().filter(|addr| !self.busy.contains(addr)).copied().collect();
        if !self.config.connect_only {
            let open = self.config.max_peers.saturating_sub(self.busy.len() + wanted.len());
            for _ in 0..open.min(4) {
                match self.addrman.pick(&self.busy) {
                    Some(addr) => wanted.push(addr),
                    None => break,
                }
            }
            let few = self.addrman.len() < 100;
            let seeded_lately = self.last_seed.is_some_and(|at| at.elapsed() < Duration::from_secs(60));
            if few && !self.seeding && !seeded_lately && self.peers.len() < self.config.max_peers {
                self.seed();
            }
        }
        for addr in wanted {
            self.busy.insert(addr);
            let id = self.next_id;
            self.next_id += 1;
            tokio::spawn(run_peer(id, addr, self.config.chain, start_height, self.events_tx.clone()));
        }
    }

    /// Asks the network's DNS seeds for peers.
    fn seed(&mut self) {
        let seeds = self.config.chain.dns_seeds();
        if seeds.is_empty() {
            return;
        }
        self.seeding = true;
        self.last_seed = Some(Instant::now());
        let port = self.config.chain.default_port();
        let tx = self.addrs_tx.clone();
        tokio::spawn(async move {
            let mut found = Vec::new();
            for seed in seeds {
                match tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((*seed, port))).await {
                    Ok(Ok(addrs)) => found.extend(addrs),
                    Ok(Err(err)) => tracing::debug!("seed {seed}: {err}"),
                    Err(_) => tracing::debug!("seed {seed} timed out"),
                }
            }
            tracing::info!("{} addresses from DNS seeds", found.len());
            let _ = tx.send(found);
        });
    }

    fn sync_headers(&mut self) {
        let tip = self.headers.tip_height();
        if let Some(id) = self.header_sync {
            let stalled =
                self.peers.get(&id).is_none_or(|p| p.headers_asked.is_some_and(|at| at.elapsed() > HEADERS_TIMEOUT));
            if stalled {
                self.disconnect(id, "too slow to send headers");
            } else {
                return;
            }
        }
        // One peer at a time while catching up; then ask each now and then,
        // in case an announcement was missed.
        let ahead =
            self.peers.iter().filter(|(_, p)| p.height > tip && p.headers_asked.is_none()).map(|(&id, _)| id).next();
        if let Some(id) = ahead {
            self.header_sync = Some(id);
            self.ask_headers(id);
            return;
        }
        let due: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, p)| p.headers_asked.is_none() && p.last_headers_poll.elapsed() > HEADERS_POLL)
            .map(|(&id, _)| id)
            .collect();
        for id in due {
            self.ask_headers(id);
        }
    }

    /// Rewinds the indexer to where what it's been handed leaves the best
    /// chain, if it does, and forgets blocks off the best chain.
    fn follow_best_chain(&mut self) {
        let mut common = self.sent.len().min(self.headers.tip_height() as usize + 1);
        while common > 0 && self.headers.at(common as u32 - 1).is_none_or(|e| e.hash != self.sent[common - 1]) {
            common -= 1;
        }
        if common < self.sent.len() {
            let height = common.checked_sub(1).expect("the genesis block is in every chain") as u32;
            tracing::info!("reorganizing: rewinding to block {height}");
            let _ = self.indexer_tx.send(indexer::Command::Rewind { height });
            self.sent.truncate(common);
            self.sent_from.retain(|&h, _| h <= height);
        }
        let headers = &self.headers;
        let mut dropped = 0;
        self.received.retain(|&height, (hash, _, bytes)| {
            let keep = headers.at(height).is_some_and(|e| e.hash == *hash);
            if !keep {
                dropped += bytes.len();
            }
            keep
        });
        self.received_bytes -= dropped;
    }

    fn time_out_requests(&mut self) {
        let next = self.sent.len() as u32;
        let window_full =
            self.received_bytes >= MAX_BUFFERED || self.requested.len() + self.received.len() >= WINDOW as usize;
        let mut slow = Vec::new();
        for (hash, request) in &self.requested {
            let age = request.at.elapsed();
            if age > BLOCK_TIMEOUT || (request.height == next && window_full && age > STALL_TIMEOUT) {
                slow.push((*hash, request.peer));
            }
        }
        for (_, peer) in slow {
            self.disconnect(peer, "too slow to send a block");
        }
    }

    fn request_blocks(&mut self) {
        let next = self.sent.len() as u32;
        let mut last = self.headers.tip_height().min(next.saturating_add(WINDOW));
        if let Some(stop) = self.config.stop_height {
            last = last.min(stop);
        }
        if next > last {
            return;
        }
        // With the buffer full, only the blocks the indexer needs soonest
        // are asked for: they must be, or nothing would ever free it.
        let in_flight_bytes = self.requested.len() as f64 * self.avg_block;
        let full = self.received_bytes as f64 + in_flight_bytes >= MAX_BUFFERED as f64;
        let max_in_flight = ((IN_FLIGHT_BYTES / self.avg_block) as usize).clamp(MIN_IN_FLIGHT, MAX_IN_FLIGHT);
        let mut asks: HashMap<PeerId, Vec<Inventory>> = HashMap::new();
        let start = if full { next } else { self.request_from.max(next) };
        for height in start..=last {
            if full && height >= next + MIN_IN_FLIGHT as u32 {
                break;
            }
            self.request_from = self.request_from.max(height);
            if self.received.contains_key(&height) {
                continue;
            }
            let hash = self.headers.at(height).unwrap().hash;
            if self.requested.contains_key(&hash) {
                continue;
            }
            let peer = self
                .peers
                .iter()
                .filter(|(_, p)| p.height >= height && p.in_flight.len() < max_in_flight)
                .min_by_key(|(_, p)| p.in_flight.len())
                .map(|(&id, _)| id);
            let Some(id) = peer else { break };
            self.peers.get_mut(&id).unwrap().in_flight.insert(hash);
            self.requested.insert(hash, Request { peer: id, height, at: Instant::now() });
            asks.entry(id).or_default().push(Inventory::WitnessBlock(hash));
            if !full {
                self.request_from = height + 1;
            }
        }
        for (id, inventory) in asks {
            self.send(id, NetworkMessage::GetData(inventory));
        }
    }

    /// Asks a peer for the transactions it announced that aren't known,
    /// once the first sync is over.
    fn ask_txs(&mut self, id: PeerId, inventory: &[Inventory]) {
        if self.store.syncing() || self.store.snapshot().blocks == 0 {
            return;
        }
        let mempool = self.mempool.read().unwrap();
        let mut wanted = Vec::new();
        for inv in inventory {
            if let Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) = inv {
                let txid = txid.to_byte_array();
                if !mempool.contains(&txid) && !self.tx_requests.contains_key(&txid) {
                    self.tx_requests.insert(txid, Instant::now());
                    wanted.push(Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(txid)));
                }
            }
        }
        drop(mempool);
        if !wanted.is_empty() {
            self.send(id, NetworkMessage::GetData(wanted));
        }
    }

    /// Sends a transaction sent to the API to every peer.
    fn broadcast(&mut self, raw: Vec<u8>) {
        let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw) else { return };
        let txid = tx.compute_txid();
        tracing::info!("broadcasting {txid} to {} peers", self.peers.len());
        for peer in self.peers.values() {
            let _ = peer.commands.send(NetworkMessage::Tx(tx.clone()));
        }
        self.ours.insert(txid.to_byte_array(), (raw, Instant::now()));
    }

    /// Sends our transactions again every ten minutes until they're
    /// confirmed, and forgets requests for transactions never sent.
    fn rebroadcast(&mut self) {
        self.tx_requests.retain(|_, at| at.elapsed() < Duration::from_secs(60));
        let mempool = self.mempool.read().unwrap();
        self.ours.retain(|txid, _| mempool.contains(txid));
        drop(mempool);
        let due: Vec<Vec<u8>> = self
            .ours
            .values()
            .filter(|(_, at)| at.elapsed() > Duration::from_secs(600))
            .map(|(raw, _)| raw.clone())
            .collect();
        for raw in due {
            self.broadcast(raw);
        }
    }

    /// Whether the scripts of the block at `height` on the best chain must be
    /// verified: unless the assumevalid block is on it, at or above it.
    fn needs_scripts_verified(&self, height: u32) -> bool {
        if !self.config.assume_valid {
            return true;
        }
        let Some((av_height, av_hash)) = self.config.chain.assume_valid() else { return true };
        let on_best = self.headers.at(av_height).is_some_and(|entry| entry.hash.to_string() == av_hash);
        !(on_best && height <= av_height)
    }

    /// Hands blocks to the indexer, in order, as far as they've arrived.
    fn hand_over(&mut self) {
        loop {
            let next = self.sent.len() as u32;
            let handed = next.saturating_sub(self.indexed.map_or(0, |h| h + 1));
            if handed >= MAX_HANDED {
                return;
            }
            let Some((hash, from, bytes)) = self.received.remove(&next) else { return };
            self.received_bytes -= bytes.len();
            self.sent.push(hash);
            self.sent_from.insert(next, from);
            let mut target = self.headers.tip_height();
            if let Some(stop) = self.config.stop_height {
                target = target.min(stop);
            }
            let verify = self.needs_scripts_verified(next);
            let _ = self.indexer_tx.send(indexer::Command::Connect { height: next, hash, bytes, target, verify });
        }
    }
}
