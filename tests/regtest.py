#!/usr/bin/env python3
"""End-to-end test against Bitcoin Core on regtest.

Starts bitcoind, makes a chain with every common kind of output and spend,
syncs bitdexter from it over P2P, and checks every block, transaction and
wallet UTXO bitdexter serves against what bitcoind says. Then reorganizes
the chain and checks again, and restarts bitdexter and checks again. It
does it all twice: indexing in place, and indexing in bulk, with a low
enough threshold that both the first sync and a catch-up go in bulk.

    tests/regtest.py [path/to/bitdexter]

bitcoind and bitcoin-cli must be on PATH.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BITDEXTER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target/debug/bitdexter")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Core:
    def __init__(self, tmp):
        self.dir = os.path.join(tmp, "core")
        os.makedirs(self.dir)
        self.p2p = free_port()
        self.rpc = free_port()
        self.proc = subprocess.Popen(
            [
                "bitcoind", "-regtest", f"-datadir={self.dir}", f"-port={self.p2p}", f"-rpcport={self.rpc}",
                "-txindex", "-fallbackfee=0.0002", "-listen=1", "-bind=127.0.0.1", "-whitelist=127.0.0.1",
                "-printtoconsole=0", "-acceptnonstdtxn=1",
            ],
            stdout=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                self.cli("getblockchaininfo")
                return
            except subprocess.CalledProcessError:
                time.sleep(0.2)
        raise RuntimeError("bitcoind didn't start")

    def cli(self, *args, wallet=None):
        cmd = ["bitcoin-cli", "-regtest", f"-datadir={self.dir}", f"-rpcport={self.rpc}"]
        if wallet:
            cmd.append(f"-rpcwallet={wallet}")
        args = [json.dumps(a) if isinstance(a, bool) else str(a) for a in args]
        out = subprocess.run(cmd + args, check=True, capture_output=True, text=True).stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


class Dexter:
    def __init__(self, tmp, core, bulk_threshold):
        self.bulk_threshold = bulk_threshold
        self.dir = os.path.join(tmp, "dexter")
        self.http = free_port()
        self.core = core
        self.log = open(os.path.join(tmp, "dexter.log"), "a")
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            [
                BITDEXTER, "--network", "regtest", "--data-dir", self.dir, "--http", f"127.0.0.1:{self.http}",
                "--peer", f"127.0.0.1:{self.core.p2p}", "--connect-only",
                "--bulk-threshold", str(self.bulk_threshold),
            ],
            stdout=self.log,
            stderr=self.log,
            env={**os.environ, "RUST_LOG": "info,bitdexter=debug"},
        )

    def stop(self, sig=signal.SIGINT):
        self.proc.send_signal(sig)
        self.proc.wait(timeout=60)

    def post(self, path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{self.http}{path}", data=body.encode(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode()

    def get(self, path, raw=False):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.http}{path}", timeout=30) as r:
            body = r.read()
            if raw:
                return body
            return json.loads(body) if r.headers.get("content-type", "").startswith("application/json") else body.decode()

    def wait_for(self, height, hash_):
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                if self.get("/blocks/tip/hash") == hash_:
                    return
            except (urllib.error.URLError, ConnectionError):
                pass
            time.sleep(0.3)
        raise RuntimeError(f"bitdexter didn't reach block {height} {hash_}")


def make_chain(core, blocks):
    """Mines blocks full of transactions of every kind."""
    w = "w"
    if w not in core.cli("listwallets"):
        try:
            core.cli("createwallet", w)
        except subprocess.CalledProcessError:
            core.cli("loadwallet", w)
    types = ["legacy", "p2sh-segwit", "bech32", "bech32m"]
    miner = core.cli("getnewaddress", "", "bech32", wallet=w)
    if core.cli("getblockcount") < 110:
        core.cli("generatetoaddress", 110, miner)
    for i in range(blocks):
        for j in range(6):
            to = core.cli("getnewaddress", "", types[(i + j) % 4], wallet=w)
            core.cli("sendtoaddress", to, f"{0.1 + 0.01 * j:.8f}", wallet=w)
        # A transaction with many outputs, some to the same address.
        many = {core.cli("getnewaddress", "", types[k % 4], wallet=w): 0.001 for k in range(8)}
        core.cli("sendmany", "", json.dumps(many), wallet=w)
        if i % 5 == 0:
            # OP_RETURN data.
            raw = core.cli("createrawtransaction", "[]", json.dumps([{"data": "626974646578746572"}]))
            funded = core.cli("fundrawtransaction", raw, wallet=w)["hex"]
            signed = core.cli("signrawtransactionwithwallet", funded, wallet=w)["hex"]
            core.cli("sendrawtransaction", signed)
        core.cli("generatetoaddress", 1, miner)


def check(core, dexter):
    """Checks everything bitdexter serves against bitcoind."""
    tip = core.cli("getblockcount")
    tip_hash = core.cli("getbestblockhash")
    dexter.wait_for(tip, tip_hash)
    assert int(dexter.get("/blocks/tip/height")) == tip
    txs = 0
    for height in range(tip + 1):
        hash_ = core.cli("getblockhash", height)
        assert dexter.get(f"/block-height/{height}") == hash_
        block = core.cli("getblock", hash_, 3)
        ours = dexter.get(f"/block/{hash_}")
        for key, theirs in [("height", "height"), ("tx_count", "nTx"), ("size", "size"), ("weight", "weight"),
                            ("merkle_root", "merkleroot"), ("mediantime", "mediantime"), ("nonce", "nonce")]:
            assert ours[key] == block[theirs], (height, key, ours[key], block[theirs])
        assert dexter.get(f"/block/{hash_}/txids") == [tx["txid"] for tx in block["tx"]]
        assert dexter.get(f"/block/{hash_}/raw", raw=True).hex() == core.cli("getblock", hash_, 0)
        for tx in block["tx"]:
            txs += 1
            mine = dexter.get(f"/tx/{tx['txid']}")
            assert mine["txid"] == tx["txid"]
            assert mine["size"] == tx["size"] and mine["weight"] == tx["weight"], tx["txid"]
            assert mine["status"]["block_height"] == height
            assert dexter.get(f"/tx/{tx['txid']}/hex") == tx["hex"]
            if "fee" in tx:
                assert mine["fee"] == round(tx["fee"] * 1e8), (mine["fee"], tx["fee"])
            for vin, theirs in zip(mine["vin"], tx["vin"]):
                if "coinbase" in theirs:
                    assert vin["is_coinbase"]
                    continue
                assert vin["txid"] == theirs["txid"] and vin["vout"] == theirs["vout"]
                assert vin["prevout"]["value"] == round(theirs["prevout"]["value"] * 1e8)
                assert vin["prevout"]["scriptpubkey"] == theirs["prevout"]["scriptPubKey"]["hex"]
                assert vin.get("witness", []) == theirs.get("txinwitness", [])
            for vout, theirs in zip(mine["vout"], tx["vout"]):
                assert vout["value"] == round(theirs["value"] * 1e8)
                assert vout["scriptpubkey"] == theirs["scriptPubKey"]["hex"]
                assert vout.get("scriptpubkey_address") == theirs["scriptPubKey"].get("address"), (vout, theirs)
            # Outspends agree with gettxout: unspent outputs are in the UTXO set.
            for n, spend in enumerate(dexter.get(f"/tx/{tx['txid']}/outspends")):
                utxo = core.cli("gettxout", tx["txid"], n)
                if spend["spent"]:
                    assert utxo == "", (tx["txid"], n)
                elif tx["vout"][n]["scriptPubKey"]["type"] != "nulldata" and height > 0:
                    assert utxo != "", (tx["txid"], n)
    # Every wallet address's UTXOs and balance, immature coinbases too, as
    # the UTXO set has them (listunspent leaves those out).
    addresses = {u["address"] for u in core.cli("listunspent", 0, 9999999, wallet="w")}
    addresses |= {a["address"] for a in core.cli("listreceivedbyaddress", 0, True, wallet="w")}
    by_address = {}
    for address in addresses:
        scan = core.cli("scantxoutset", "start", json.dumps([f"addr({address})"]))
        by_address[address] = {(u["txid"], u["vout"], round(u["amount"] * 1e8)) for u in scan["unspents"]}
    for address, utxos in by_address.items():
        ours = {(u["txid"], u["vout"], u["value"]) for u in dexter.get(f"/address/{address}/utxo")}
        assert ours == utxos, (address, ours, utxos)
        stats = dexter.get(f"/address/{address}")["chain_stats"]
        assert stats["funded_txo_sum"] - stats["spent_txo_sum"] == sum(v for _, _, v in utxos)
        history = dexter.get(f"/address/{address}/txs")
        assert len(history) == min(stats["tx_count"], 25)
    print(f"  checked {tip + 1} blocks, {txs} transactions, {len(by_address)} addresses")


def until(what, f, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if f():
            return
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {what}")


def check_mempool(core, dexter):
    """Checks unconfirmed transactions: relayed from Core, broadcast to it,
    replaced, refused, and confirmed."""
    w = "w"
    sent = []
    for kind in ["bech32", "bech32m", "p2sh-segwit", "legacy"]:
        to = core.cli("getnewaddress", "", kind, wallet=w)
        sent.append((core.cli("sendtoaddress", to, "0.5", wallet=w), to))
    theirs = set(core.cli("getrawmempool"))
    until("relayed transactions", lambda: theirs <= set(dexter.get("/mempool/txids")))
    for txid, to in sent:
        tx = dexter.get(f"/tx/{txid}")
        assert tx["status"] == {"confirmed": False}, tx["status"]
        assert tx["fee"] == round(core.cli("getmempoolentry", txid)["fees"]["base"] * 1e8)
        assert dexter.get(f"/tx/{txid}/hex") == core.cli("getrawtransaction", txid)
        stats = dexter.get(f"/address/{to}")["mempool_stats"]
        assert stats["funded_txo_sum"] == 50_000_000 and stats["tx_count"] == 1, stats
        utxos = dexter.get(f"/address/{to}/utxo")
        assert {"txid": txid, "vout": utxos[0]["vout"], "status": {"confirmed": False}, "value": 50_000_000} in utxos
        assert dexter.get(f"/address/{to}/txs/mempool")[0]["txid"] == txid
    info = dexter.get("/mempool")
    assert info["count"] == len(theirs), info
    estimates = dexter.get("/fee-estimates")
    assert set(estimates) >= {"1", "6", "144", "1008"} and all(v >= 1 for v in estimates.values()), estimates

    # Broadcast through bitdexter: Core gets it.
    to = core.cli("getnewaddress", "", "bech32", wallet=w)
    raw = core.cli("createrawtransaction", "[]", json.dumps({to: 0.25}))
    funded = core.cli("fundrawtransaction", raw, wallet=w)["hex"]
    signed = core.cli("signrawtransactionwithwallet", funded, wallet=w)["hex"]
    status, txid = dexter.post("/tx", signed)
    assert status == 200, (status, txid)
    until("Core to have the broadcast transaction", lambda: txid in core.cli("getrawmempool"))
    # Sending it again is refused, as is spending what it spends.
    status, error = dexter.post("/tx", signed)
    assert status == 400 and "sendrawtransaction RPC error" in error, (status, error)
    status, error = dexter.post("/tx", "00")
    assert status == 400, (status, error)

    # Replaced by a fee bump: the replacement takes its place.
    old = sent[0][0]
    new = core.cli("bumpfee", old, wallet=w)["txid"]
    until("the replacement", lambda: new in dexter.get("/mempool/txids"))
    assert old not in dexter.get("/mempool/txids")

    # Mined: they leave.
    miner = core.cli("getnewaddress", "", "bech32", wallet=w)
    core.cli("generatetoaddress", 1, miner)
    until("an empty mempool", lambda: dexter.get("/mempool")["count"] == len(core.cli("getrawmempool")))
    assert dexter.get(f"/tx/{txid}/status")["confirmed"]
    print(f"  checked the mempool: {len(theirs)} relayed, one broadcast, one replaced")


def scenario(bulk_threshold):
    tmp = tempfile.mkdtemp(prefix="bitdexter-regtest-")
    core = Core(tmp)
    dexter = Dexter(tmp, core, bulk_threshold)
    try:
        print("making a chain")
        make_chain(core, 40)
        dexter.start()
        print("syncing")
        check(core, dexter)

        print("unconfirmed transactions")
        check_mempool(core, dexter)
        check(core, dexter)

        print("reorganizing")
        tip = core.cli("getblockcount")
        core.cli("invalidateblock", core.cli("getblockhash", tip - 3))
        make_chain(core, 6)
        check(core, dexter)

        print("restarting")
        dexter.stop()
        make_chain(core, 5)
        dexter.start()
        check(core, dexter)

        print("killing mid-sync and recovering")
        dexter.stop(signal.SIGKILL)
        make_chain(core, 25)
        dexter.start()
        time.sleep(0.5)
        dexter.stop(signal.SIGKILL)
        dexter.start()
        check(core, dexter)
    finally:
        if dexter.proc and dexter.proc.poll() is None:
            dexter.stop()
        core.stop()
        if os.environ.get("KEEP") is None:
            shutil.rmtree(tmp)
        else:
            print(f"kept {tmp}")


def main():
    print("== indexing in place")
    scenario(1_000_000)
    print("== indexing in bulk")
    scenario(10)
    print("ok")


if __name__ == "__main__":
    main()
