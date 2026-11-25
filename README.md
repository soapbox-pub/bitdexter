# bitdexter

A Bitcoin indexer in Rust that downloads the blockchain itself, over Bitcoin's
peer-to-peer network, keeps it in a compact format of its own, and serves an
[Esplora](https://github.com/Blockstream/esplora/blob/master/API.md)-compatible
API. No Bitcoin Core node is needed: it's one program and one data directory.

**Status: early.** It syncs mainnet, testnet4, signet and regtest from peers,
validates as Bitcoin Core does, follows reorgs, survives crashes, keeps a
mempool, and serves Esplora's API for blocks, transactions, addresses,
broadcasting and fee estimates, matching Bitcoin Core and mempool.space where
tested. See [Roadmap](#roadmap) for what's next.

## Running

Building needs Rust, a C and C++ compiler, cmake and boost (for
libbitcoinkernel); `nix develop` gives them all.

```sh
nix develop --command cargo build --release
./target/release/bitdexter --network signet
```

The API listens on `127.0.0.1:3000`, at the root and under `/api`; `/` itself
is a page saying how far it's synced and listing the APIs. Data goes in
`~/.local/share/bitdexter/<network>`. Settings can be given in
`~/.config/bitdexter/bitdexter.toml`, and on the command line, which wins:

```toml
network = "mainnet"            # mainnet, testnet4, signet or regtest
# data_dir = "/var/lib/bitdexter"
http = "127.0.0.1:3000"
bulk_threshold = 1000          # index in bulk when this many blocks behind
assume_valid = true            # skip scripts up to the assumevalid block
blockbook = false              # serve Blockbook's API too
blindbit = false               # serve silent payment tweaks too
prices = false                 # fetch prices from exchanges for /v1/prices
# electrum = "127.0.0.1:50001"  # serve the Electrum protocol
# mempool_bootstrap = "https://mempool.space/api"  # fill the mempool from its txids

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
| Mempool | `POST /tx`, `/mempool`, `/mempool/txids`, `/mempool/recent`, `/fee-estimates`, and mempool.space's `/v1/fees/recommended` |

Unconfirmed transactions are served by `/tx/:txid` and the rest, and counted
in addresses' `mempool_stats`, transactions and UTXOs, as Esplora does.

With `prices = true` (or `--prices`), it fetches the price of bitcoin from
Coinbase's and Kraken's public tickers every minute and serves the median as
mempool.space's `/v1/prices` does (and Blockbook's `getCurrentFiatRates`).
Otherwise `/v1/prices` answers 404, which wallets take as a reason to ask
another server.

### Blockbook

With `blockbook = true` (or `--blockbook`), it serves
[Blockbook's API](https://github.com/trezor/blockbook/blob/master/docs/api.md)
too: over WebSocket at `/websocket`, `getInfo`, `getAccountInfo`,
`getAccountUtxo`, `getTransaction`, `getBlock`, `getBlockHash`, `estimateFee`,
`sendTransaction` and `ping`; and over REST, `/api/v2/xpub/:descriptor`,
`/api/v2/address/:address`, `/api/v2/utxo/:descriptor`, `/api/v2/tx/:txid`,
`/api/v2/block/:id`, `/api/v2/estimatefee/:blocks` and `/api/v2/sendtx`.

An account is an extended public key (xpub, ypub or zpub, or their testnet
forms) or an output descriptor of one: `pkh()`, `sh(wpkh())`, `wpkh()` or
`tr()`, with or without its key origin, `/<0;1>/*` and checksum. Its receive
and change addresses are derived in turn until 20 in a row are unused, and
their history, balances and UTXOs, unconfirmed too, given at once. Historical fiat
rates and subscriptions aren't served yet.

### Silent payments

With `blindbit = true` (or `--blindbit`), it serves BIP352 tweaks as
[BlindBit Oracle](https://github.com/setavenger/blindbit-oracle) does, under
`/blindbit`: `/info`, `/tweaks/:height` (each eligible transaction's
`input_hash·A`, 33 bytes) and `/utxos/:height` (their taproot outputs, and
whether each is spent). A block's tweaks are computed the first time they're
asked for, from mainnet's taproot activation on, and kept, by block hash, in
LMDB. They match BIP352's test vectors.

### Electrum

With `electrum = "127.0.0.1:50001"` (or `--electrum`), it serves the
[Electrum protocol](https://electrum-protocol.readthedocs.io), version 1.4,
over plain TCP, for Electrum, Sparrow and other wallets: headers, script
hashes' balances, histories, unspent outputs and mempool transactions,
transactions and their merkle proofs, fee estimates and histograms,
broadcasting, and notifications of new blocks and of scripts' status. Put TLS
in front of it to reach it from elsewhere.

## Mempool

Transactions peers announce are fetched once the first sync is done, and kept
if they'd be valid in the next block: their inputs exist and are unspent (in
the chain or the mempool), coinbases mature, lock times passed, sigops few
enough, scripts verified, paying at least 0.1 sat/vB. A transaction spending
what one in the mempool spends replaces it, and what spends it, if it pays
more in all, by 0.1 sat/vB of its size, and at a higher rate (full RBF, as
Bitcoin Core's default). One whose inputs aren't known yet (an orphan) is kept
for up to 20 minutes, its missing parents asked for from the peer that sent
it, and tried again when they arrive. `POST /tx` checks a transaction the same way and sends it to
every peer, again every ten minutes until it's confirmed; a refusal comes as
electrs gives bitcoind's, `sendrawtransaction RPC error: {"code":…,"message":…}`.

Fee estimates come from the mempool: its transactions, highest rate first,
fill blocks in turn, and the estimate for a target of n blocks is the lowest
rate in the n-th, or 1 sat/vB if they don't fill that many.

Peers announce only transactions new to them, so a mempool started empty
misses what was already waiting, at low fees for days or weeks. So:

- It's saved to `mempool.dat` every ten minutes and when bitdexter stops, and
  loaded, each transaction checked again, when it starts.
- Peers that serve bloom filters are asked for their whole mempool (BIP35).
  Most don't: Bitcoin Core's default is not to.
- With `mempool_bootstrap = "https://mempool.space/api"` (or any Esplora
  server; `--mempool-bootstrap`), the txids in that server's mempool are
  fetched once the first sync is done, and again ten minutes later, and the
  transactions themselves asked of peers, which send any they had when they
  last announced one. The server's trusted for nothing but the list: every
  transaction is checked as any is.

`/status` counts what was accepted, refused (by reason) and kept as orphans.

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

Synced all of mainnet from peers, to block 977,181 (November 2026), on a
Proxmox container with 16 cores, 32 then 64 GB of memory and SATA SSDs in
RAID 10:

| | Size |
|---|---:|
| `txdata` | 612 GB |
| `txids`, `txidx`, `outs`, `blocks` | 112 GB |
| `history` | 22.6 GB (6 bytes an output, 3.7 billion of them) |
| `txid.table` | 14.2 GB (10 bytes a transaction, 1.48 billion of them) |
| **Total** | **710 GB** |

The first 500,000 blocks took 52 minutes, the next 300,000 three hours, and
blocks 800,000 to 950,000 eleven hours, slowing to two to five blocks a
second as reads of `outs`, `txidx` and `txdata` at random each read a
hundred kilobytes or more around them. Above the assumevalid block, where
each input's script is read too, that came to a gigabyte read from disk a
block, and one block a second. Advising the maps as read at random fixed it:
2–3 blocks a second with every script verified, reading 11 MB/s. (Below the
assumevalid block it hasn't been measured since.) Merging the bulk index,
1.42 billion transactions and 3.6 billion outputs, took 22 minutes; a second
merge, of 14,000 blocks more, 9.5 minutes. Restarting in bulk rebuilds its map
of the 115 million transactions with outputs left to spend in 3.5 minutes; at
the tip, the API is up in 12 seconds. About 1.1 TB was written in all.

At the tip, blocks, transactions, outspends, merkle proofs and addresses
compared with mempool.space all match, busy ones too. An address's history
takes about a second for one with tens of thousands of transactions, 13 for
the genesis block's.

Before the mempool was saved, bootstrapped and kept orphans, it held 1,800
transactions minutes after a restart against mempool.space's 70,000, and
19,000 a day later against its 65,000. Bootstrapped from mempool.space, it
held 63,977 of mempool.space's 64,213 transactions 15 minutes later, and 17
it didn't have; the rest were the newest links of chains of 0.1 sat/vB
transactions, still arriving. Most of the mempool is such chains, fetched in
no particular order, so tens of thousands of transactions are orphans for a
while. Its 39,000 transactions, saved (85 MB), loaded again in 13 seconds.

Synced from testnet4's peers to its tip, 162,719 blocks and 15 million
transactions, in 13 minutes, merging the bulk index in 5 seconds, then
following it in place, reorgs too. Blocks, transactions, outspends, merkle
proofs, addresses and unconfirmed transactions compared with mempool.space's
testnet4 API all match, but for the order of UTXOs (which Esplora leaves
open), and one address so busy mempool.space gives a different set of its
UTXOs each time it's asked, some spent in its own chain.

## Validation

As Bitcoin Core validates, with Core's own script interpreter,
[libbitcoinkernel](https://github.com/sedited/rust-bitcoinkernel).

Headers are checked fully: proof of work, difficulty retargeting (with
testnet's minimum-difficulty rule and testnet4's BIP94), median time past,
future time, and the versions BIP34, BIP65 and BIP66 require. The chain with
the most work is followed.

Every block is checked for its merkle root (and mutation), witness
commitment, weight, coinbase (BIP34 height, amount), that every input spends
an output that exists and is unspent and, if a coinbase's, mature, that no
transaction makes coins, duplicate inputs, BIP30, sigop cost (BIP141), lock
times (BIP113) and relative lock times (BIP68).

Scripts are verified on several threads, with the flags Core applies at each
height, for every block after the network's assumevalid block, a block a few
months old that Core's would also skip, checked against bitdexter's own
headers and mempool.space. `--verify-all` verifies every block's.

Not yet: signet's block signatures, and a minimum chain work for header sync.

## Roadmap

1. ~~Initial sync in bulk.~~ Done.
2. ~~Script verification~~ Done.
3. ~~Mempool~~ Done.
4. ~~Blockbook's API~~ Done, but for fiat rates and subscriptions.
5. ~~Silent payments~~ Done.
6. ~~Prices~~ Done.
7. ~~A full mainnet sync measured end to end~~ Done. Faster downloads from
   peers.
8. ~~The Electrum protocol~~ Done. Packages.

## Testing

```sh
nix develop
cargo test
tests/regtest.py                                         # against Bitcoin Core
tests/compare.py http://127.0.0.1:3000 https://mempool.space/api /tx/<txid> …
```

`tests/regtest.py` makes a regtest chain with every common kind of output and
spend, syncs bitdexter from Bitcoin Core over P2P, and checks every block,
transaction, prevout, outspend and wallet UTXO it serves against Core's; then
again after a reorg, a restart, and being killed mid-sync.

## License

[AGPL-3.0](LICENSE).
