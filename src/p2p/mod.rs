//! Speaking Bitcoin's peer-to-peer protocol: one task per connection.
//!
//! Each peer's task does the version handshake, answers pings, and passes
//! every other message to the node as a [`PeerEvent`]. Blocks are passed as
//! the bytes they came in, unparsed and unhashed (their merkle root is
//! checked as they're indexed), and everything else as rust-bitcoin's
//! [`NetworkMessage`].

pub mod addrman;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
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

pub type PeerId = u64;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub services: ServiceFlags,
    pub start_height: i32,
    pub user_agent: String,
    pub version: u32,
}

pub enum PeerEvent {
    Connected { id: PeerId, info: PeerInfo, commands: mpsc::UnboundedSender<NetworkMessage> },
    Message { id: PeerId, message: NetworkMessage },
    Block { id: PeerId, bytes: Vec<u8> },
    Disconnected { id: PeerId, addr: SocketAddr, reason: String, connected: bool },
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
        // Transactions aren't relayed to us until there's a mempool to keep.
        relay: false,
    }
}

/// Connects to `addr` and runs the connection until it ends, reporting it
/// to `events`.
pub async fn run_peer(
    id: PeerId,
    addr: SocketAddr,
    chain: Chain,
    start_height: i32,
    events: mpsc::Sender<PeerEvent>,
) {
    let mut connected = false;
    let reason = match connect(id, addr, chain, start_height, &events, &mut connected).await {
        Ok(()) => "closed".to_string(),
        Err(err) => format!("{err:#}"),
    };
    let _ = events.send(PeerEvent::Disconnected { id, addr, reason, connected }).await;
}

async fn connect(
    id: PeerId,
    addr: SocketAddr,
    chain: Chain,
    start_height: i32,
    events: &mpsc::Sender<PeerEvent>,
    connected: &mut bool,
) -> Result<()> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await.context("connect timed out")??;
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
    let (commands_tx, mut commands) = mpsc::unbounded_channel::<NetworkMessage>();
    events.send(PeerEvent::Connected { id, info, commands: commands_tx }).await?;
    *connected = true;

    // Messages are written by a task of their own, so that a slow reader
    // on the other end can't stall reading from it.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    let result = async {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                frame = tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut read, chain)) => {
                    let frame = frame.context("idle too long")??;
                    if frame.command() == b"block" {
                        events.send(PeerEvent::Block { id, bytes: frame.payload }).await?;
                        continue;
                    }
                    match frame.decode() {
                        Ok(NetworkMessage::Ping(nonce)) => {
                            out_tx.send(encode(chain, NetworkMessage::Pong(nonce)))?;
                        }
                        Ok(NetworkMessage::Pong(_)) => {}
                        Ok(message) => events.send(PeerEvent::Message { id, message }).await?,
                        // Messages rust-bitcoin can't read are skipped.
                        Err(err) => tracing::trace!("peer {id}: {err:#}"),
                    }
                }
                command = commands.recv() => {
                    let Some(message) = command else { return Ok(()) };
                    out_tx.send(encode(chain, message))?;
                }
                _ = ping.tick() => {
                    out_tx.send(encode(chain, NetworkMessage::Ping(rand::random())))?;
                }
            }
        }
    }
    .await;
    writer.abort();
    result
}
