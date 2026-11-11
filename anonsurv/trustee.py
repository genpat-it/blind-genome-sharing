# SPDX-License-Identifier: EUPL-1.2
"""Trustee: one consortium member holding one share of every escrow.

A trustee releases its share for a record only if
  1. a disclosure request for that record is in the log, under a tree head cosigned by enough
     witnesses (so the request is public and cannot be withdrawn afterwards), and
  2. the escrow blob it is given is the one the log recorded for that record, and
  3. its own people agree with the stated reason (`approve`, a human decision).
The competent authority needs t shares; it combines them with escrow.reveal.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from . import escrow
from .client import Anchors, ClientError, accepted_sth, prove_entry


@dataclass
class Trustee:
    name: str
    x: int                  # share index, 1..n
    sk: bytes               # HPKE X25519 secret key
    anchors: Anchors
    approve: Callable[[dict], bool] = lambda request: True

    def release(self, platform: httpx.Client, record_id: str) -> tuple[int, int]:
        sth = accepted_sth(platform, self.anchors)
        entries = platform.get("/log/entries", params={"since": 0, "until": sth["size"]}).json()
        reqs = [e for e in entries if e["kind"] == "disclosure_request" and e["body"]["record_id"] == record_id]
        if not reqs:
            raise ClientError(f"{self.name}: no disclosure request for {record_id} in the cosigned log")
        req = reqs[-1]
        prove_entry(platform, sth, req)
        blob = bytes.fromhex(platform.get(f"/escrow/{record_id}").json()["escrow"])
        if hashlib.sha256(blob).hexdigest() != req["body"]["escrow_sha256"]:
            raise ClientError(f"{self.name}: escrow blob differs from the one in the log")
        if not self.approve(req["body"]):
            raise ClientError(f"{self.name}: refuses, reason not accepted")
        return escrow.open_share(blob, self.x, self.sk)
