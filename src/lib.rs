//! bitdexter: a Bitcoin indexer that downloads the chain itself, over the
//! peer-to-peer network, keeps it in a compact format of its own, and
//! serves an Esplora-compatible API.

pub mod api;
pub mod block;
pub mod chain;
pub mod compact;
pub mod config;
pub mod hash;
pub mod indexer;
pub mod network;
pub mod node;
pub mod p2p;
pub mod script;
pub mod store;
pub mod validate;
