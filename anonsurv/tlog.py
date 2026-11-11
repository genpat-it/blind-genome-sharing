# SPDX-License-Identifier: EUPL-1.2
"""Append-only Merkle-tree log (RFC 9162 hashing and proofs) with witness cosigning.

Every record and alert is a leaf. The operator publishes a signed tree head (STH: size, root,
time). Each consortium member runs a *witness*: before cosigning a new head it checks a
consistency proof from the last head it cosigned, so the log can only grow. A client accepts a
head only with enough cosignatures, and checks an inclusion proof for what it cares about (its own
record, the issuer key). A rewritten or deleted entry changes the root, and no honest witness
will cosign a head that is not an extension of the old one.

This replaces a Trillian/Rekor/Tessera deployment in the proof of concept; the proofs are the
same, checked against the transparency-dev test probes.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

EMPTY_ROOT = hashlib.sha256(b"").digest()
STH_CONTEXT = b"anonsurv-sth-v1\n"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


# ---------------------------------------------------------------- tree over a list of leaf hashes

class MerkleTree:
    def __init__(self, leaves: list[bytes] | None = None):
        self.leaves: list[bytes] = list(leaves or [])
        self._mth = lru_cache(maxsize=None)(self._mth_uncached)   # ranges never change: append-only

    def append(self, lh: bytes) -> int:
        self.leaves.append(lh)
        return len(self.leaves) - 1

    def _mth_uncached(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.leaves[lo]
        k = _split(n)
        return node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))

    def root(self, size: int | None = None) -> bytes:
        return self._mth(0, len(self.leaves) if size is None else size)

    def inclusion_proof(self, index: int, size: int) -> list[bytes]:
        """RFC 9162 2.1.3.1 PATH(m, D[n])."""
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("index outside tree")

        def path(m, lo, hi):
            n = hi - lo
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, lo, lo + k) + [self._mth(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]
        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int) -> list[bytes]:
        """RFC 9162 2.1.4.1 PROOF(m, D[n]) = SUBPROOF(m, D[n], true)."""
        if not 0 < first <= second <= len(self.leaves):
            raise ValueError("sizes outside tree")

        def sub(m, lo, hi, b):
            n = hi - lo
            if m == n:
                return [] if b else [self._mth(lo, hi)]
            k = _split(n)
            if m <= k:
                return sub(m, lo, lo + k, b) + [self._mth(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]
        return sub(first, 0, second, True)


# ---------------------------------------------------------------- verification (RFC 9162 2.1.3.2, 2.1.4.2)

def verify_inclusion(index: int, size: int, lh: bytes, proof: list[bytes], root: bytes) -> bool:
    if index >= size or len(root) != 32 or len(lh) != 32:
        return False
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, root1: bytes, root2: bytes, proof: list[bytes]) -> bool:
    if first == 0 or first > second:   # a proof from the empty tree is meaningless
        return False
    if first == second:
        return not proof and root1 == root2
    if not proof:
        return False
    if first & (first - 1) == 0:  # exact power of two: the old root is a node of the new tree
        proof = [root1] + list(proof)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == root1 and sr == root2 and sn == 0


# ---------------------------------------------------------------- signed tree heads

def ed25519_pub_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sth_message(sth: dict) -> bytes:
    return STH_CONTEXT + canonical({"size": sth["size"], "root": sth["root"], "ts": sth["ts"]})


def sign_sth(sk: Ed25519PrivateKey, sth: dict) -> str:
    return sk.sign(sth_message(sth)).hex()


def check_sig(pub_hex: str, sth: dict, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), sth_message(sth))
        return True
    except (InvalidSignature, ValueError):
        return False


def accept_sth(sth: dict, log_pub: str, witness_pubs: dict[str, str], quorum: int) -> bool:
    """A client's rule: operator signature plus at least `quorum` valid witness cosignatures."""
    if not check_sig(log_pub, sth, sth.get("sig", "")):
        return False
    good = {w for w, s in sth.get("cosigs", {}).items() if w in witness_pubs and check_sig(witness_pubs[w], sth, s)}
    return len(good) >= quorum


class Witness:
    """A consortium member. Remembers the last head it cosigned and never cosigns a fork."""

    def __init__(self, name: str, log_pub: str, sk: Ed25519PrivateKey | None = None):
        self.name, self.log_pub = name, log_pub
        self.sk = sk or Ed25519PrivateKey.generate()
        self.pub = ed25519_pub_hex(self.sk)
        self.last = {"size": 0, "root": EMPTY_ROOT.hex()}

    def cosign(self, sth: dict, proof: list[str]) -> str:
        if not check_sig(self.log_pub, sth, sth.get("sig", "")):
            raise ValueError("tree head not signed by the log operator")
        if self.last["size"] and not verify_consistency(self.last["size"], sth["size"], bytes.fromhex(self.last["root"]),
                                  bytes.fromhex(sth["root"]), [bytes.fromhex(p) for p in proof]):
            raise ValueError(f"{self.name}: new head is not an extension of the one cosigned at size "
                             f"{self.last['size']}: log rewritten")
        self.last = {"size": sth["size"], "root": sth["root"]}
        return sign_sth(self.sk, sth)


# ---------------------------------------------------------------- the log

class TransparencyLog:
    def __init__(self, path: str = ":memory:", sk: Ed25519PrivateKey | None = None):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS log (idx INTEGER PRIMARY KEY, ts REAL, kind TEXT, body TEXT)")
        self.db.commit()
        self.sk = sk or Ed25519PrivateKey.generate()
        self.pub = ed25519_pub_hex(self.sk)
        self.tree = MerkleTree([leaf_hash(entry_bytes(e)) for e in self.entries()])

    def append(self, kind: str, body: dict) -> dict:
        idx, ts = len(self.tree.leaves), round(time.time(), 3)
        self.db.execute("INSERT INTO log VALUES (?,?,?,?)", (idx, ts, kind, json.dumps(body, sort_keys=True)))
        self.db.commit()
        self.tree.append(leaf_hash(entry_bytes({"index": idx, "ts": ts, "kind": kind, "body": body})))
        return {"index": idx}

    @property
    def size(self) -> int:
        return len(self.tree.leaves)

    def sth(self) -> dict:
        sth = {"size": self.size, "root": self.tree.root().hex(), "ts": round(time.time(), 3)}
        return {**sth, "sig": sign_sth(self.sk, sth)}

    def entries(self, since: int = 0, until: int | None = None) -> list[dict]:
        rows = self.db.execute("SELECT idx, ts, kind, body FROM log WHERE idx >= ? AND idx < ? ORDER BY idx",
                               (since, 2**62 if until is None else until)).fetchall()
        return [{"index": i, "ts": ts, "kind": k, "body": json.loads(b)} for i, ts, k, b in rows]

    def inclusion(self, index: int, size: int) -> list[str]:
        return [h.hex() for h in self.tree.inclusion_proof(index, size)]

    def consistency(self, first: int, second: int) -> list[str]:
        if first == 0 or first == second:   # first cosignature: trust on first use
            return []
        return [h.hex() for h in self.tree.consistency_proof(first, second)]


def entry_bytes(e: dict) -> bytes:
    return canonical({"index": e["index"], "ts": e["ts"], "kind": e["kind"], "body": e["body"]})


def entry_included(entry: dict, sth: dict, proof: list[str]) -> bool:
    return verify_inclusion(entry["index"], sth["size"], leaf_hash(entry_bytes(entry)),
                            [bytes.fromhex(p) for p in proof], bytes.fromhex(sth["root"]))
