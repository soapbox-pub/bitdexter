//! bitdexter: a Bitcoin indexer that downloads the chain itself, over the
//! peer-to-peer network, keeps it in a compact format of its own, and
//! serves an Esplora-compatible API.

// Fixed-size chunks read as plainly with `chunks_exact`, and lengths are
// counts here, not containers that can be empty.
#![allow(clippy::chunks_exact_to_as_chunks, clippy::len_without_is_empty)]

pub mod api;
pub mod block;
pub mod chain;
pub mod compact;
pub mod config;
pub mod consensus;
pub mod electrum;
pub mod hash;
pub mod indexer;
pub mod mempool;
pub mod network;
pub mod node;
pub mod p2p;
pub mod prices;
pub mod script;
pub mod silent;
pub mod store;
pub mod validate;
pub mod verify;
