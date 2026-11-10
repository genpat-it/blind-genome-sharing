# SPDX-License-Identifier: EUPL-1.2
"""Append-only, hash-chained log (tamper-evident).

Each entry stores h_i = SHA-256(h_{i-1} || canonical JSON of the entry). Anyone holding a copy of the
latest head (index, hash) -- e.g. every member of the consortium -- detects a rewritten or deleted
entry, because the chain no longer reaches the head they hold. This is deployment model B in its
simplest form; RFC 9162 Merkle trees (Trillian, Rekor) add compact inclusion proofs.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class TransparencyLog:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS log (idx INTEGER PRIMARY KEY, ts REAL, kind TEXT,"
                        " body TEXT, prev TEXT, hash TEXT)")
        self.db.commit()

    def head(self) -> dict:
        row = self.db.execute("SELECT idx, hash FROM log ORDER BY idx DESC LIMIT 1").fetchone()
        return {"index": row[0], "hash": row[1]} if row else {"index": -1, "hash": GENESIS}

    def append(self, kind: str, body: dict) -> dict:
        head = self.head()
        idx, ts = head["index"] + 1, round(time.time(), 3)
        entry = {"index": idx, "ts": ts, "kind": kind, "body": body}
        h = hashlib.sha256(bytes.fromhex(head["hash"]) + canonical(entry)).hexdigest()
        self.db.execute("INSERT INTO log VALUES (?,?,?,?,?,?)",
                        (idx, ts, kind, json.dumps(body, sort_keys=True), head["hash"], h))
        self.db.commit()
        return {"index": idx, "hash": h}

    def entries(self, since: int = 0) -> list[dict]:
        rows = self.db.execute("SELECT idx, ts, kind, body, prev, hash FROM log WHERE idx >= ? ORDER BY idx",
                               (since,)).fetchall()
        return [{"index": i, "ts": ts, "kind": k, "body": json.loads(b), "prev": p, "hash": h}
                for i, ts, k, b, p, h in rows]


def verify_chain(entries: list[dict], head: dict) -> bool:
    """Recompute the chain from genesis and check that it ends at `head`."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e["index"] != i or e["prev"] != prev:
            return False
        entry = {"index": e["index"], "ts": e["ts"], "kind": e["kind"], "body": e["body"]}
        prev = hashlib.sha256(bytes.fromhex(prev) + canonical(entry)).hexdigest()
        if prev != e["hash"]:
            return False
    return head["index"] == len(entries) - 1 and head["hash"] == prev
