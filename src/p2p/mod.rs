//! Speaking Bitcoin's peer-to-peer protocol: one task per connection.
//!
//! Each peer's task does the version handshake, answers pings, and passes
//! every other message to the node as a [`PeerEvent`]. Blocks are passed as
//! the bytes they came in, once they're known to hold the transactions,
//! and witnesses, their header commits to (they're checked in full as
//! they're indexed), and everything else as rust-bitcoin's
//! [`NetworkMessage`]. What's sent to a peer waits in a queue of its own,
//! and a peer that lets it fill, not reading, is dropped.

pub mod addrman;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::network::Chain;

/// Version 70016: `wtxidrelay` (BIP339) and everything before it.
const PROTOCOL_VERSION: u32 = 70016;
/// The largest message Bitcoin Core sends or accepts.
const MAX_MESSAGE: usize = 4_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const PING_INTERVAL: Duration = Duration::from_secs(120);
/// How long a peer may say nothing at all before it's dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// The most messages waiting to be sent to a peer.
pub const MAX_QUEUED: usize = 1024;
/// The most headers a `headers` message may hold.
const MAX_HEADERS: usize = 2000;

pub type PeerId = u64;

/// A peer broke the protocol, as an honest one wouldn't: it's banned.
#[derive(Debug)]
pub struct Misbehaved(pub String);

impl std::fmt::Display for Misbehaved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Misbehaved {}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub services: ServiceFlags,
    pub start_height: i32,
    pub user_agent: String,
    pub version: u32,
}

pub enum PeerEvent {
    Connected { id: PeerId, info: PeerInfo, commands: mpsc::Sender<NetworkMessage> },
    Message { id: PeerId, message: NetworkMessage },
    Block { id: PeerId, bytes: Vec<u8> },
    Disconnected { id: PeerId, addr: SocketAddr, reason: String, connected: bool, misbehaved: bool },
}

struct Frame {
    command: [u8; 12],
    header: [u8; 24],
    payload: Vec<u8>,
}

impl Frame {
    fn command(&self) -> &[u8] {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(12);
        &self.command[..end]
    }

    fn decode(self) -> Result<NetworkMessage> {
        let mut raw = Vec::with_capacity(24 + self.payload.len());
        raw.extend_from_slice(&self.header);
        raw.extend_from_slice(&self.payload);
        let message: RawNetworkMessage =
            deserialize(&raw).with_context(|| format!("decoding {}", String::from_utf8_lossy(self.command())))?;
        Ok(message.into_payload())
    }
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin), chain: Chain) -> Result<Frame> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header).await?;
    if header[..4] != chain.magic().to_bytes() {
        bail!("wrong network magic");
    }
    let command: [u8; 12] = header[4..16].try_into().unwrap();
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE {
        bail!("message of {len} bytes is too big");
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Frame { command, header, payload })
}

fn encode(chain: Chain, message: NetworkMessage) -> Vec<u8> {
    serialize(&RawNetworkMessage::new(chain.magic(), message))
}

fn version_message(addr: SocketAddr, start_height: i32) -> VersionMessage {
    let timestamp =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let unspecified: SocketAddr = ([0, 0, 0, 0], 0).into();
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: ServiceFlags::NONE,
        timestamp,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&unspecified, ServiceFlags::NONE),
        nonce: rand::random(),
        user_agent: format!("/bitdexter:{}/", env!("CARGO_PKG_VERSION")),
        start_height,
        // Transactions are relayed to us, for the mempool.
        relay: true,
    }
}

/// Connects to `addr` and runs the connection until it ends, reporting it
/// to `events`.
pub async fn run_peer(id: PeerId, addr: SocketAddr, chain: Chain, start_height: i32, events: mpsc::Sender<PeerEvent>) {
    let mut connected = false;
    let (reason, misbehaved) = match connect(id, addr, chain, start_height, &events, &mut connected).await {
        Ok(()) => ("closed".to_string(), false),
        Err(err) => (format!("{err:#}"), err.downcast_ref::<Misbehaved>().is_some()),
    };
    let _ = events.send(PeerEvent::Disconnected { id, addr, reason, connected, misbehaved }).await;
}

async fn connect(
    id: PeerId,
    addr: SocketAddr,
    chain: Chain,
    start_height: i32,
    events: &mpsc::Sender<PeerEvent>,
    connected: &mut bool,
) -> Result<()> {
    let stream =
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await.context("connect timed out")??;
    stream.set_nodelay(true)?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::with_capacity(1 << 20, read);

    write.write_all(&encode(chain, NetworkMessage::Version(version_message(addr, start_height)))).await?;
    let info = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut version = None;
        let mut verack = false;
        while version.is_none() || !verack {
            let frame = read_frame(&mut read, chain).await?;
            match frame.decode()? {
                NetworkMessage::Version(v) if version.is_none() => {
                    if v.version < 70015 {
                        bail!("protocol version {} is too old", v.version);
                    }
                    if !v.services.has(ServiceFlags::NETWORK) || !v.services.has(ServiceFlags::WITNESS) {
                        bail!("doesn't serve every witness block (services {})", v.services);
                    }
                    // BIP155: addrv2 messages, asked for before verack.
                    write.write_all(&encode(chain, NetworkMessage::SendAddrV2)).await?;
                    write.write_all(&encode(chain, NetworkMessage::Verack)).await?;
                    version = Some(v);
                }
                NetworkMessage::Verack => verack = true,
                _ => {}
            }
        }
        let v = version.unwrap();
        Ok::<_, anyhow::Error>(PeerInfo {
            addr,
            services: v.services,
            start_height: v.start_height,
            user_agent: v.user_agent,
            version: v.version,
        })
    })
    .await
    .context("handshake timed out")??;

    write.write_all(&encode(chain, NetworkMessage::SendHeaders)).await?;
    let (commands_tx, mut commands) = mpsc::channel::<NetworkMessage>(MAX_QUEUED);
    events.send(PeerEvent::Connected { id, info, commands: commands_tx }).await?;
    *connected = true;

    // Messages are written by a task of their own, so that a slow reader
    // on the other end can't stall reading from it, and another passes on
    // the node's commands and pings now and then. Reading is never
    // interrupted part way through a message, which would lose its place
    // in the stream, except to end the connection.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(MAX_QUEUED);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    let (closed_tx, mut closed) = tokio::sync::oneshot::channel::<()>();
    let commander = tokio::spawn({
        let out_tx = out_tx.clone();
        async move {
            let mut ping = tokio::time::interval(PING_INTERVAL);
            ping.tick().await;
            loop {
                let message = tokio::select! {
                    command = commands.recv() => match command {
                        Some(message) => message,
                        None => break,
                    },
                    _ = ping.tick() => NetworkMessage::Ping(rand::random()),
                };
                if out_tx.send(encode(chain, message)).await.is_err() {
                    break;
                }
            }
            let _ = closed_tx.send(());
        }
    });
    let result = async {
        loop {
            let frame = tokio::select! {
                frame = tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut read, chain)) => {
                    frame.context("idle too long")??
                }
                _ = &mut closed => return Ok(()),
            };
            if frame.command() == b"block" {
                // Only the block its header names, not one padded or cut,
                // which could be kept a long while before it's indexed.
                let (checked, payload) = tokio::task::spawn_blocking(move || {
                    let checked = crate::block::parse_block(&frame.payload)
                        .map_err(|err| err.to_string())
                        .and_then(|block| crate::validate::check_commitments(&block).map_err(|err| err.0));
                    (checked, frame.payload)
                })
                .await?;
                if let Err(reason) = checked {
                    return Err(Misbehaved(format!("sent a block that isn't its header's: {reason}")).into());
                }
                events.send(PeerEvent::Block { id, bytes: payload }).await?;
                continue;
            }
            match frame.decode() {
                Ok(NetworkMessage::Ping(nonce)) => {
                    if out_tx.try_send(encode(chain, NetworkMessage::Pong(nonce))).is_err() {
                        bail!("isn't reading what's sent it");
                    }
                }
                Ok(NetworkMessage::Headers(headers)) if headers.len() > MAX_HEADERS => {
                    return Err(Misbehaved(format!("sent {} headers at once", headers.len())).into());
                }
                Ok(NetworkMessage::Pong(_)) => {}
                Ok(message) => events.send(PeerEvent::Message { id, message }).await?,
                // Messages rust-bitcoin can't read are skipped.
                Err(err) => tracing::trace!("peer {id}: {err:#}"),
            }
        }
    }
    .await;
    writer.abort();
    commander.abort();
    result
}
