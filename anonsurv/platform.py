# SPDX-License-Identifier: EUPL-1.2
"""Submission platform: accepts a record only with a valid, unused token; stores no identity.

It holds the issuer's public key only. Every accepted record and every alert is appended to the
hash-chained log, whose head the consortium members keep (deployment model B).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import policy
from . import rsabssa as bs
from .tlog import TransparencyLog


class Submission(BaseModel):
    token: str          # hex, the prepared message signed blind by the issuer
    signature: str      # hex
    scheme: str         # typing scheme, e.g. cgMLST name
    alleles: list[int]  # allele profile, 0 = missing
    meta: dict          # species, month, region, category
    pk_alert: str       # hex, one-time HPKE public key


class Alert(BaseModel):
    enc: str
    ct: str


class PlatformState:
    def __init__(self, issuer_pk: bs.PublicKey, stats: dict[str, int], k: int, lab_key: str,
                 db: str = ":memory:"):
        self.issuer_pk, self.stats, self.k, self.lab_key = issuer_pk, stats, k, lab_key
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS spent (h TEXT PRIMARY KEY);"
            "CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, id TEXT, body TEXT);"
            "CREATE TABLE IF NOT EXISTS bulletin (seq INTEGER PRIMARY KEY, enc TEXT, ct TEXT);")
        self.log = TransparencyLog(db)
        if self.log.head()["index"] < 0:
            self.log.append("issuer_key", {"fingerprint": issuer_pk.fingerprint()})


def create_app(st: PlatformState) -> FastAPI:
    app = FastAPI(title="Submission platform")

    def lab_only(key: str | None):
        if key is None or not hmac.compare_digest(key, st.lab_key):
            raise HTTPException(403, "public-health laboratories only")

    @app.post("/submit")
    def submit(s: Submission):
        try:
            token, sig = bytes.fromhex(s.token), bytes.fromhex(s.signature)
            if len(bytes.fromhex(s.pk_alert)) != 32:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "malformed hex field")
        if not bs.verify(st.issuer_pk, token, sig):
            raise HTTPException(403, "signature not valid: not an authorised company")
        err = policy.check(s.meta, st.stats, st.k)
        if err:
            raise HTTPException(422, err)
        h = hashlib.sha256(token).hexdigest()
        try:
            st.db.execute("INSERT INTO spent VALUES (?)", (h,))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "token already used")
        rid = secrets.token_hex(8)
        body = {"id": rid, "scheme": s.scheme, "alleles": s.alleles, "meta": s.meta, "pk_alert": s.pk_alert}
        st.db.execute("INSERT INTO records (id, body) VALUES (?,?)", (rid, json.dumps(body)))
        st.db.commit()
        entry = st.log.append("record", {"id": rid, "sha256": hashlib.sha256(policy_bytes(body)).hexdigest(),
                                         "meta": s.meta})
        return {"record_id": rid, "log": entry}

    @app.get("/records")
    def records(since: int = 0, x_lab_key: str | None = Header(None)):
        lab_only(x_lab_key)
        rows = st.db.execute("SELECT seq, body FROM records WHERE seq > ? ORDER BY seq", (since,)).fetchall()
        return [{"seq": q, **json.loads(b)} for q, b in rows]

    @app.post("/alerts")
    def post_alert(a: Alert, x_lab_key: str | None = Header(None)):
        lab_only(x_lab_key)
        st.db.execute("INSERT INTO bulletin (enc, ct) VALUES (?,?)", (a.enc, a.ct))
        st.db.commit()
        return st.log.append("alert", {"sha256": hashlib.sha256(bytes.fromhex(a.ct)).hexdigest()})

    @app.get("/bulletin")
    def bulletin():
        return [{"enc": e, "ct": c} for e, c in st.db.execute("SELECT enc, ct FROM bulletin ORDER BY seq")]

    @app.get("/log")
    def log(since: int = 0):
        return st.log.entries(since)

    @app.get("/log/head")
    def head():
        return st.log.head()

    return app


def policy_bytes(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
