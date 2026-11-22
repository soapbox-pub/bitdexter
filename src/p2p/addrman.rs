//! The addresses of peers that might be connected to, from DNS seeds and
//! from what peers say, and how trying them went.
//!
//! Addresses that have worked are saved, one per line, so the next start
//! needn't ask the seeds.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;

/// How long after failing an address isn't tried again, doubling with each
/// failure in a row.
const RETRY_BASE: Duration = Duration::from_secs(60);
/// The most addresses kept.
const MAX_ADDRS: usize = 20_000;

#[derive(Default)]
struct Info {
    failures: u32,
    last_try: Option<Instant>,
    worked: bool,
}

pub struct AddrMan {
    addrs: HashMap<SocketAddr, Info>,
    path: PathBuf,
}

impl AddrMan {
    pub fn load(path: PathBuf) -> AddrMan {
        let mut addrs = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Ok(addr) = line.trim().parse() {
                    addrs.insert(addr, Info { worked: true, ..Info::default() });
                }
            }
        }
        AddrMan { addrs, path }
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn add(&mut self, addr: SocketAddr) {
        if self.addrs.len() < MAX_ADDRS && !addr.ip().is_unspecified() && addr.port() != 0 {
            self.addrs.entry(addr).or_default();
        }
    }

    /// An address to try that isn't in `busy`, those that have worked
    /// before first.
    pub fn pick(&mut self, busy: &HashSet<SocketAddr>) -> Option<SocketAddr> {
        let now = Instant::now();
        let ready = |(addr, info): &(&SocketAddr, &Info)| {
            !busy.contains(addr)
                && info.last_try.is_none_or(|at| now.duration_since(at) >= RETRY_BASE * 2u32.pow(info.failures.min(8)))
        };
        let mut rng = rand::rng();
        let pick = self
            .addrs
            .iter()
            .filter(ready)
            .filter(|(_, info)| info.worked)
            .map(|(addr, _)| *addr)
            .choose(&mut rng)
            .or_else(|| self.addrs.iter().filter(ready).map(|(addr, _)| *addr).choose(&mut rng))?;
        self.addrs.get_mut(&pick).unwrap().last_try = Some(now);
        Some(pick)
    }

    pub fn succeeded(&mut self, addr: SocketAddr) {
        let info = self.addrs.entry(addr).or_default();
        info.failures = 0;
        info.worked = true;
    }

    pub fn failed(&mut self, addr: SocketAddr) {
        if let Some(info) = self.addrs.get_mut(&addr) {
            info.failures += 1;
            if info.failures > 10 && !info.worked {
                self.addrs.remove(&addr);
            }
        }
    }

    pub fn save(&self) {
        let lines: Vec<String> =
            self.addrs.iter().filter(|(_, info)| info.worked).map(|(addr, _)| addr.to_string()).collect();
        if let Err(err) = std::fs::write(&self.path, lines.join("\n")) {
            tracing::warn!("saving peers to {} failed: {err}", self.path.display());
        }
    }
}
