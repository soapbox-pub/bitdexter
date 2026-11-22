# bitdexter

A Bitcoin indexer in Rust that downloads the blockchain itself, over Bitcoin's
peer-to-peer network, keeps it in a compact format of its own, and serves an
[Esplora](https://github.com/Blockstream/esplora/blob/master/API.md)-compatible
API. No Bitcoin Core node is needed: it's one program and one data directory.

**Status: early.** It syncs mainnet, testnet4, signet and regtest from peers, follows
reorgs, survives crashes, and serves Esplora's read API for blocks, transactions
and addresses, matching Bitcoin Core and mempool.space byte for byte where tested.
It doesn't verify scripts yet, and has no mempool, so no broadcasting or fee
estimates: see [Roadmap](#roadmap).

## Running

```sh
cargo build --release
./target/release/bitdexter --network signet
```

The API listens on `127.0.0.1:3000`, at the root and under `/api`. Data goes in
`~/.local/share/bitdexter/<network>`. Settings can be given in
`~/.config/bitdexter/bitdexter.toml`, and on the command line, which wins:

```toml
network = "mainnet"            # mainnet, testnet4, signet or regtest
# data_dir = "/var/lib/bitdexter"
http = "127.0.0.1:3000"
bulk_threshold = 1000          # index in bulk when this many blocks behind

[p2p]
peers = []                     # always kept connected, as host:port
connect_only = false           # connect only to `peers`
max_peers = 12
```

`bitdexter --help` lists the flags. `GET /status` says how far it's synced, how
many peers it has, and how much disk each part of the index takes.

## API

The Esplora endpoints served so far:

| | |
|---|---|
| Blocks | `/blocks/tip/height`, `/blocks/tip/hash`, `/blocks[/:start_height]`, `/block-height/:height`, `/block/:hash`, `/block/:hash/header`, `/block/:hash/status`, `/block/:hash/txids`, `/block/:hash/txs[/:start_index]`, `/block/:hash/txid/:index`, `/block/:hash/raw` |
| Transactions | `/tx/:txid`, `/tx/:txid/hex`, `/tx/:txid/raw`, `/tx/:txid/status`, `/tx/:txid/outspend/:vout`, `/tx/:txid/outspends`, `/tx/:txid/merkle-proof`, `/tx/:txid/merkleblock-proof` |
| Addresses | `/address/:address`, `/address/:address/txs`, `/address/:address/txs/chain[/:last_seen_txid]`, `/address/:address/txs/mempool`, `/address/:address/utxo`, and the same under `/scripthash/:hash` |

Still to come: `POST /tx`, `/fee-estimates`, `/mempool*` and mempool stats,
which need a mempool, and mempool.space's `/v1/prices`.

## How it's stored

Every transaction and output has a number, in chain order, and most of the
index is flat files of fixed-width records indexed by them, read through
memory maps:

| File | Per | Holds |
|---|---|---|
| `blocks` | block | header, first transaction and output numbers, size, weight, fees (112 B) |
| `txids` | transaction | txid (32 B) |
| `txidx` | transaction | where it starts in `txdata`, its first output's number (11 B) |
| `outs` | output | value, and the number of the transaction that spent it (12 B) |
| `txdata` | — | transactions in compact form |
| `txid.table` | — | txid → transaction number, a hash table of 8-byte slots |
| `history` | — | script → the outputs paying it, built in bulk |
| `index/` | — | LMDB: the same for the newest 100 blocks, and the store's state |

Transactions are kept in a [compact form](src/compact.rs) from which their raw
bytes are rebuilt exactly: an input names the output it spends by number rather
than by a 36-byte outpoint, amounts are compressed as Bitcoin Core compresses
them, and standard scripts are a template byte plus their hash or key. An
address's history is the outputs paying it, from the history index, and
whatever spent them, from `outs`, so inputs aren't indexed at all.

When it's far behind (more than `bulk_threshold` blocks, 1000 by default), it
indexes in bulk: the columns and two logs, of spends and of history entries,
are only appended to, and inputs are found in a map in memory of the
transactions with outputs left to spend. Once caught up, it merges the logs
in with sequential sorts: spends are marked in `outs` a range at a time, the
txid table is written in one pass from txids sorted by key, and the history
log is merged into the history file, a few bytes an entry. Near the tip it
indexes each block in place. The API serves only what's merged, so it's empty
until the first sync is done. [`src/store/mod.rs`](src/store/mod.rs) and
[`src/store/bulk.rs`](src/store/bulk.rs) describe the format, and how
commits and crash recovery work.

### Measured

Synced from mainnet peers to block 300,000 (April 2014), whose blocks take
18.6 GB:

| | Size | Of raw blocks |
|---|---:|---:|
| `txdata` | 14.1 GB | 76% |
| `txids`, `txidx`, `outs`, `blocks` | 2.8 GB | 15% |
| `history` | 0.52 GB | 2.8% (5.3 bytes an output) |
| `txid.table` | 0.38 GB | 2.1% (10 bytes a transaction) |
| **Total** | **17.9 GB** | **96%** |

That took 13 minutes, limited by downloading from peers, not by indexing,
and wrote 29 GB to disk. Merging 38 million transactions and 99 million
outputs at the end took 11 seconds. (Indexing in place throughout, as the
first version did, took 157% of the raw size and wrote 128 GB.)

## Validation

Headers are checked fully: proof of work, difficulty retargeting (with
testnet's minimum-difficulty rule and testnet4's BIP94), median time past,
future time, and the versions BIP34, BIP65 and BIP66 require. The chain with
the most work is followed.

Blocks are checked for everything but scripts: merkle root (and mutation),
witness commitment, weight, coinbase rules (BIP34 height, amount), that every
input spends an output that exists and is unspent and, if a coinbase's, mature,
that no transaction makes coins, duplicate inputs, and BIP30.

Not yet: script verification (planned with libbitcoinkernel, above an
assumevalid block), sigop limits, BIP68/BIP113 lock times, signet's block
signatures, and a minimum chain work for header sync.

## Roadmap

1. ~~Initial sync in bulk.~~ Done.
2. **Script verification** with libbitcoinkernel above an assumevalid block,
   and the remaining consensus checks.
3. **Mempool**: transaction relay, `POST /tx`, `/fee-estimates`, `/mempool*`,
   unconfirmed history and balances.
4. **Blockbook's API**, optionally: REST and WebSocket, xpub and descriptor
   scans (`getAccountInfo`, `getAccountUtxo`, `estimateFee`,
   `sendTransaction`, …).
5. **Silent payments**: BIP352 tweaks, served as BlindBit Oracle serves them.
6. Prices for `/v1/prices`, the Electrum protocol, and packages.

## Testing

```sh
cargo test
nix shell nixpkgs#bitcoind --command tests/regtest.py   # against Bitcoin Core
tests/compare.py http://127.0.0.1:3000 https://mempool.space/api /tx/<txid> …
```

`tests/regtest.py` makes a regtest chain with every common kind of output and
spend, syncs bitdexter from Bitcoin Core over P2P, and checks every block,
transaction, prevout, outspend and wallet UTXO it serves against Core's; then
again after a reorg, a restart, and being killed mid-sync.

## License

[AGPL-3.0](LICENSE).
