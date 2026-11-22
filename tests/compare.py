#!/usr/bin/env python3
"""Compares bitdexter's Esplora API with a public Esplora's, path by path.

    tests/compare.py http://127.0.0.1:3000 https://mempool.space/api PATH...

Each path is fetched from both, and the JSON compared field by field.
Fields only one side has are reported, not failed, as Esplora's flavors
differ (mempool.space adds `sigops`, for one).
"""

import json
import sys
import time
import urllib.error
import urllib.request


def fetch(base, path):
    req = urllib.request.Request(base + path, headers={"User-Agent": "bitdexter-compare"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as err:
        return {"http_status": err.code}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def diff(a, b, at=""):
    """Differences between a and b, as (path, ours, theirs)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            if key not in a:
                out.append((f"{at}.{key}", "<missing>", b[key]))
            elif key not in b:
                out.append((f"{at}.{key}", a[key], "<missing>"))
            else:
                out += diff(a[key], b[key], f"{at}.{key}")
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [(f"{at}[len]", len(a), len(b))]
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in diff(x, y, f"{at}[{i}]")]
    if isinstance(a, float) or isinstance(b, float):
        return [] if abs(float(a) - float(b)) <= 1e-9 * max(1, abs(float(b))) else [(at, a, b)]
    return [] if a == b else [(at, a, b)]


def main():
    ours, theirs, paths = sys.argv[1], sys.argv[2], sys.argv[3:]
    failed = False
    for path in paths:
        a, b = fetch(ours, path), fetch(theirs, path)
        differences = diff(a, b)
        real = [d for d in differences if "<missing>" not in (d[1], d[2])]
        extra = [d for d in differences if "<missing>" in (d[1], d[2])]
        status = "ok" if not real else "DIFFERS"
        print(f"{status:8} {path}")
        for d in real[:20]:
            print(f"           {d[0]}: ours {json.dumps(d[1])[:100]}, theirs {json.dumps(d[2])[:100]}")
        keys = sorted({d[0].split("]")[-1] for d in extra})
        if keys:
            print(f"           only one side has: {', '.join(keys)[:200]}")
        failed |= bool(real)
        time.sleep(0.5)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
