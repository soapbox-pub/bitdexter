//! What differs between the networks bitdexter can follow.

use bitcoin::Network;
use bitcoin::consensus::Params;
use bitcoin::p2p::Magic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    pub fn network(self) -> Network {
        match self {
            Chain::Mainnet => Network::Bitcoin,
            Chain::Testnet4 => Network::Testnet4,
            Chain::Signet => Network::Signet,
            Chain::Regtest => Network::Regtest,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Testnet4 => "testnet4",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }

    pub fn params(self) -> &'static Params {
        match self {
            Chain::Mainnet => &Params::MAINNET,
            Chain::Testnet4 => &Params::TESTNET4,
            Chain::Signet => &Params::SIGNET,
            Chain::Regtest => &Params::REGTEST,
        }
    }

    pub fn magic(self) -> Magic {
        Magic::from(self.network())
    }

    pub fn default_port(self) -> u16 {
        match self {
            Chain::Mainnet => 8333,
            Chain::Testnet4 => 48333,
            Chain::Signet => 38333,
            Chain::Regtest => 18444,
        }
    }

    /// DNS seeds, as Bitcoin Core lists them.
    pub fn dns_seeds(self) -> &'static [&'static str] {
        match self {
            Chain::Mainnet => &[
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
                "seed.btc.petertodd.net",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
                "seed.mainnet.achownodes.xyz",
            ],
            Chain::Testnet4 => &["seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"],
            Chain::Signet => &["seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz"],
            Chain::Regtest => &[],
        }
    }

    /// Blocks between halvings of the block subsidy.
    pub fn halving_interval(self) -> u32 {
        match self {
            Chain::Regtest => 150,
            _ => 210_000,
        }
    }

    /// The new coins a block at `height` may create, in satoshis.
    pub fn subsidy(self, height: u32) -> u64 {
        let halvings = height / self.halving_interval();
        if halvings >= 64 { 0 } else { (50 * 100_000_000u64) >> halvings }
    }

    /// The first block in which witness data is allowed.
    pub fn segwit_height(self) -> u32 {
        match self {
            Chain::Mainnet => 481_824,
            Chain::Testnet4 | Chain::Signet => 1,
            Chain::Regtest => 0,
        }
    }

    /// The first block in which relative lock times (BIP68, BIP112, BIP113)
    /// are enforced.
    pub fn csv_height(self) -> u32 {
        match self {
            Chain::Mainnet => 419_328,
            Chain::Testnet4 | Chain::Signet | Chain::Regtest => 1,
        }
    }

    /// The block whose scripts needn't be verified, nor those of the blocks
    /// before it, if it's in the best chain: as Bitcoin Core's assumevalid,
    /// a block buried deep enough that it, and the chain to it, are known
    /// good. Checked against bitdexter's own headers and mempool.space.
    pub fn assume_valid(self) -> Option<(u32, &'static str)> {
        match self {
            Chain::Mainnet => Some((950_000, "000000000000000000010b93c9ea1c29fea277383f0f7d1f26de8b5802e885ff")),
            Chain::Testnet4 => Some((150_000, "0000000000d9877342754dea8ec1eb24631517d38e3443c370465ee53a8b7434")),
            Chain::Signet => Some((320_000, "0000000740ae66b284da84387dcfa14d7b1385b0bad482005ba4e770ea6c4b95")),
            Chain::Regtest => None,
        }
    }

    /// The rules block `hash` is held to instead of today's, if it's one of
    /// the two that broke them (as Bitcoin Core's `script_flag_exceptions`).
    pub fn script_flag_exception(self, hash: &[u8; 32]) -> Option<crate::consensus::ScriptException> {
        use crate::consensus::ScriptException;
        if self != Chain::Mainnet {
            return None;
        }
        match crate::hash::to_hex_rev(hash).as_str() {
            // BIP16's exception.
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22" => Some(ScriptException::None),
            // Taproot's.
            "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad" => Some(ScriptException::P2shWitness),
            _ => None,
        }
    }

    /// Whether difficulty is retargeted from the first block of each period,
    /// rather than the last, and the timewarp attack is ruled out (BIP94).
    pub fn enforces_bip94(self) -> bool {
        matches!(self, Chain::Testnet4)
    }

    /// The two blocks whose coinbases repeat an earlier one's txid, which
    /// Bitcoin Core lets through (BIP30): each overwrites the earlier one,
    /// whose outputs can never be spent.
    pub fn bip30_exceptions(self) -> &'static [u32] {
        match self {
            Chain::Mainnet => &[91_842, 91_880],
            _ => &[],
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Chain, String> {
        match s {
            "mainnet" | "bitcoin" | "main" => Ok(Chain::Mainnet),
            "testnet4" => Ok(Chain::Testnet4),
            "signet" => Ok(Chain::Signet),
            "regtest" => Ok(Chain::Regtest),
            _ => Err(format!("unknown network {s:?}: expected mainnet, testnet4, signet or regtest")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsidy_halves() {
        assert_eq!(Chain::Mainnet.subsidy(0), 5_000_000_000);
        assert_eq!(Chain::Mainnet.subsidy(209_999), 5_000_000_000);
        assert_eq!(Chain::Mainnet.subsidy(210_000), 2_500_000_000);
        assert_eq!(Chain::Mainnet.subsidy(840_000), 312_500_000);
        assert_eq!(Chain::Mainnet.subsidy(64 * 210_000), 0);
        assert_eq!(Chain::Regtest.subsidy(150), 2_500_000_000);
    }
}
