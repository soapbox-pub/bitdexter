//! Settings, from a TOML file and the command line, which wins.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::network::Chain;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// mainnet, testnet4, signet or regtest.
    pub network: Chain,
    /// Where the index is kept, in a directory per network.
    pub data_dir: Option<PathBuf>,
    /// Where the HTTP API listens.
    pub http: SocketAddr,
    /// Index in bulk, merging once caught up, when more than this many
    /// blocks behind.
    pub bulk_threshold: u32,
    /// Skip verifying scripts up to the network's assumevalid block, as
    /// Bitcoin Core does; false verifies every block's.
    pub assume_valid: bool,
    pub p2p: P2p,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct P2p {
    /// Peers always kept connected, as `host:port`.
    pub peers: Vec<String>,
    /// Connect only to `peers`.
    pub connect_only: bool,
    /// How many peers to keep connected.
    pub max_peers: usize,
    /// Stop indexing at this height, for testing.
    pub stop_height: Option<u32>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            network: Chain::Mainnet,
            data_dir: None,
            http: ([127, 0, 0, 1], 3000).into(),
            bulk_threshold: 1000,
            assume_valid: true,
            p2p: P2p::default(),
        }
    }
}

impl Default for P2p {
    fn default() -> P2p {
        P2p { peers: Vec::new(), connect_only: false, max_peers: 12, stop_height: None }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let path = match path {
            Some(path) => Some(path.to_path_buf()),
            None => default_config_path().filter(|p| p.exists()),
        };
        let Some(path) = path else { return Ok(Config::default()) };
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// The directory this network's index is in.
    pub fn network_dir(&self) -> PathBuf {
        let base = self.data_dir.clone().unwrap_or_else(default_data_dir);
        base.join(self.network.name())
    }

    /// The peers to keep connected, resolved, with the network's port
    /// where none is given.
    pub fn resolve_peers(&self) -> Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        let mut addrs = Vec::new();
        for peer in &self.p2p.peers {
            let with_port =
                if peer.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok()) && !peer.ends_with(']') {
                    peer.clone()
                } else {
                    format!("{peer}:{}", self.network.default_port())
                };
            let addr = with_port
                .to_socket_addrs()
                .with_context(|| format!("resolving peer {peer}"))?
                .next()
                .with_context(|| format!("peer {peer} has no address"))?;
            addrs.push(addr);
        }
        Ok(addrs)
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn default_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config"));
    Some(base.join("bitdexter").join("bitdexter.toml"))
}

fn default_data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".local/share"));
    base.join("bitdexter")
}
