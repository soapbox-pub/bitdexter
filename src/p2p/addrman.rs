//! The addresses of peers that might be connected to, from DNS seeds and
//! from what peers say, and how trying them went.
//!
//! Addresses that have worked are saved, one per line, so the next start
//! needn't ask the seeds.
//!
//! What peers say can't be trusted, so no one can fill the table: only
//! routable addresses are taken, at most so many in each network group (a
//! /16 of IPv4, a /32 of IPv6) and from each group of peers telling of
//! them, and when it's full a random address that's never worked makes
//! room. Peers are picked from groups not connected to already, and those
//! that misbehaved are banned for a day.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;

/// How long after failing an address isn't tried again, doubling with each
/// failure in a row.
const RETRY_BASE: Duration = Duration::from_secs(60);
/// The most addresses kept.
const MAX_ADDRS: usize = 20_000;
/// The most addresses kept of one network group.
const MAX_PER_GROUP: usize = 64;
/// The most addresses kept that peers of one network group told of.
const MAX_PER_SOURCE: usize = 1000;
/// How long a peer that misbehaved isn't connected to again.
pub const BAN: Duration = Duration::from_secs(24 * 3600);

/// The network group an address is in: peers in one are likely run by
/// one party, or reached through one.
pub fn group(ip: IpAddr) -> [u8; 5] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [4, o[0], o[1], 0, 0]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [6, o[0], o[1], o[2], o[3]]
        }
    }
}

/// Whether an address is on the public internet.
pub fn is_routable(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || matches!(o[..3], [192, 0, 2] | [198, 51, 100] | [203, 0, 113])
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

#[derive(Default)]
struct Info {
    failures: u32,
    last_try: Option<Instant>,
    worked: bool,
    /// The group of the peer that told of it, if one did.
    source: Option<[u8; 5]>,
}

pub struct AddrMan {
    addrs: HashMap<SocketAddr, Info>,
    per_group: HashMap<[u8; 5], usize>,
    per_source: HashMap<[u8; 5], usize>,
    banned: HashMap<IpAddr, Instant>,
    /// Whether addresses that aren't routable are taken, as on regtest.
    local: bool,
    path: PathBuf,
}

impl AddrMan {
    pub fn load(path: PathBuf, local: bool) -> AddrMan {
        let mut addrman = AddrMan {
            addrs: HashMap::new(),
            per_group: HashMap::new(),
            per_source: HashMap::new(),
            banned: HashMap::new(),
            local,
            path,
        };
        if let Ok(text) = std::fs::read_to_string(&addrman.path) {
            for line in text.lines() {
                if let Ok(addr) = line.trim().parse() {
                    addrman.insert(addr, Info { worked: true, ..Info::default() });
                }
            }
        }
        addrman
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    fn insert(&mut self, addr: SocketAddr, info: Info) -> bool {
        if self.addrs.contains_key(&addr) || (!self.local && !is_routable(&addr)) {
            return false;
        }
        let group = group(addr.ip());
        if self.per_group.get(&group).copied().unwrap_or(0) >= MAX_PER_GROUP {
            return false;
        }
        if let Some(source) = info.source
            && self.per_source.get(&source).copied().unwrap_or(0) >= MAX_PER_SOURCE
        {
            return false;
        }
        if self.addrs.len() >= MAX_ADDRS {
            // Room is made by a random address that's never worked.
            let mut rng = rand::rng();
            let Some(evict) = self.addrs.iter().filter(|(_, info)| !info.worked).map(|(a, _)| *a).choose(&mut rng)
            else {
                return false;
            };
            self.remove(&evict);
        }
        *self.per_group.entry(group).or_default() += 1;
        if let Some(source) = info.source {
            *self.per_source.entry(source).or_default() += 1;
        }
        self.addrs.insert(addr, info);
        true
    }

    fn remove(&mut self, addr: &SocketAddr) {
        let Some(info) = self.addrs.remove(addr) else { return };
        if let Some(n) = self.per_group.get_mut(&group(addr.ip())) {
            *n -= 1;
        }
        if let Some(source) = info.source
            && let Some(n) = self.per_source.get_mut(&source)
        {
            *n -= 1;
        }
    }

    /// Adds an address a peer at `source` told of, or a DNS seed if none.
    pub fn add(&mut self, addr: SocketAddr, source: Option<IpAddr>) {
        if self.is_banned(&addr.ip()) {
            return;
        }
        self.insert(addr, Info { source: source.map(group), ..Info::default() });
    }

    fn is_banned(&self, ip: &IpAddr) -> bool {
        self.banned.get(ip).is_some_and(|until| *until > Instant::now())
    }

    /// Won't connect to `addr` again for a while, nor say it worked.
    pub fn ban(&mut self, addr: SocketAddr) {
        self.banned.retain(|_, until| *until > Instant::now());
        self.banned.insert(addr.ip(), Instant::now() + BAN);
        self.remove(&addr);
    }

    /// An address to try that isn't in `busy`, nor in the network group of
    /// one that is, those that have worked before first.
    pub fn pick(&mut self, busy: &HashSet<SocketAddr>) -> Option<SocketAddr> {
        let now = Instant::now();
        let busy_groups: HashSet<[u8; 5]> = busy.iter().map(|a| group(a.ip())).collect();
        let local = self.local;
        let ready = |(addr, info): &(&SocketAddr, &Info)| {
            !busy.contains(addr)
                && (local || !busy_groups.contains(&group(addr.ip())))
                && !self.banned.get(&addr.ip()).is_some_and(|until| *until > now)
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
        if !self.addrs.contains_key(&addr) {
            self.insert(addr, Info::default());
        }
        if let Some(info) = self.addrs.get_mut(&addr) {
            info.failures = 0;
            info.worked = true;
        }
    }

    pub fn failed(&mut self, addr: SocketAddr) {
        if let Some(info) = self.addrs.get_mut(&addr) {
            info.failures += 1;
            if info.failures > 10 && !info.worked {
                self.remove(&addr);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_routable_and_so_many_a_group() {
        let mut addrman = AddrMan::load(PathBuf::from("/nonexistent/peers.txt"), false);
        for bad in
            ["127.0.0.1:8333", "10.1.2.3:8333", "192.168.0.1:8333", "[fe80::1]:8333", "[fd00::1]:8333", "1.2.3.4:0"]
        {
            addrman.add(addr(bad), None);
        }
        assert!(addrman.is_empty());
        let source = Some("8.8.8.8".parse().unwrap());
        for i in 0..=255u8 {
            addrman.add(SocketAddr::from(([1, 2, i, 1], 8333)), source);
        }
        assert_eq!(addrman.len(), MAX_PER_GROUP);
        // Each from another /16, all told of by one peer.
        for a in 0..20u8 {
            for b in 0..=255u8 {
                addrman.add(SocketAddr::from(([30 + a, b, 0, 1], 8333)), source);
            }
        }
        assert_eq!(addrman.len(), MAX_PER_SOURCE);
        // Picks avoid the groups of those connected to.
        let busy: HashSet<SocketAddr> = [addr("1.2.0.1:8333")].into();
        for _ in 0..50 {
            let picked = addrman.pick(&busy).unwrap();
            assert_ne!(group(picked.ip()), group(addr("1.2.0.1:8333").ip()));
        }
        let banned = addr("30.0.0.1:8333");
        addrman.ban(banned);
        addrman.add(banned, None);
        assert!(!addrman.addrs.contains_key(&banned));
    }
}
