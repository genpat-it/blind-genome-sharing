# SPDX-License-Identifier: EUPL-1.2
"""Submission platform: accepts a record only with a valid, unused token; stores no identity.

It holds the issuer's public key only. Every accepted record, alert and disclosure request is a
leaf of the Merkle log; at each checkpoint the consortium members' witnesses cosign the new tree
head after checking it extends the previous one (deployment model B).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import alerts, escrow, policy
from . import rsabssa as bs
from .tlog import TransparencyLog, canonical


class Submission(BaseModel):
    token: str          # hex, the prepared message signed blind by the issuer
    signature: str      # hex
    scheme: str         # typing scheme, e.g. cgMLST name
    alleles: list[int]  # allele profile, 0 = missing
    meta: dict          # species, month, region, category
    pk_alert: str       # hex, one-time HPKE public key
    escrow: str | None = None   # hex, escrow blob bound to the token (when escrow is on)


class Alert(BaseModel):
    enc: str
    ct: str


class DisclosureRequest(BaseModel):
    record_id: str
    reason: str


class PlatformState:
    def __init__(self, issuer_pk: bs.PublicKey, stats: dict[str, int], k: int, lab_key: str,
                 db: str = ":memory:", escrow_cfg: escrow.Config | None = None, log_sk=None,
                 witnesses: dict[str, httpx.Client] | None = None, ohttp_keys: bytes | None = None):
        self.issuer_pk, self.stats, self.k, self.lab_key = issuer_pk, stats, k, lab_key
        self.escrow_cfg, self.witnesses = escrow_cfg, witnesses or {}
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS spent (h TEXT PRIMARY KEY);"
            "CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, id TEXT UNIQUE, body TEXT, escrow TEXT);"
            "CREATE TABLE IF NOT EXISTS bulletin (seq INTEGER PRIMARY KEY, enc TEXT, ct TEXT);")
        self.log = TransparencyLog(db, sk=log_sk)
        if self.log.size == 0:
            # Genesis entry: what every client must check before trusting anything else.
            self.log.append("config", {
                "issuer_key": issuer_pk.fingerprint(), "k_anonymity": k,
                "escrow": escrow_cfg.to_json() if escrow_cfg else None,
                "ohttp_keys": hashlib.sha256(ohttp_keys).hexdigest() if ohttp_keys else None,
                "register_stats": hashlib.sha256(canonical(stats)).hexdigest()})
        self.checkpoint_sth: dict | None = None

    def checkpoint(self) -> dict:
        """Sign a new tree head and collect a cosignature from every witness that accepts it."""
        sth = self.log.sth()
        cosigs, refusals = {}, {}
        for name, w in self.witnesses.items():
            last = w.get("/state").json()["size"]
            r = w.post("/cosign", json={"sth": sth, "proof": self.log.consistency(last, sth["size"])})
            if r.status_code == 200:
                cosigs[name] = r.json()["sig"]
            else:
                refusals[name] = r.json().get("detail")
        self.checkpoint_sth = {**sth, "cosigs": cosigs}
        return {"sth": self.checkpoint_sth, "refusals": refusals}


def create_app(st: PlatformState) -> FastAPI:
    app = FastAPI(title="Submission platform")
    cfg = st.escrow_cfg

    def lab_only(key: str | None):
        if key is None or not hmac.compare_digest(key, st.lab_key):
            raise HTTPException(403, "public-health laboratories only")

    @app.post("/submit")
    def submit(s: Submission):
        try:
            token, sig = bytes.fromhex(s.token), bytes.fromhex(s.signature)
            blob = bytes.fromhex(s.escrow) if s.escrow is not None else None
            pk_alert = bytes.fromhex(s.pk_alert)
        except ValueError:
            raise HTTPException(400, "malformed hex field")
        if not alerts.valid_public_key(pk_alert):
            raise HTTPException(400, "pk_alert is not a valid X25519 public key")
        if not bs.verify(st.issuer_pk, token, sig):
            raise HTTPException(403, "signature not valid: not an authorised company")
        if cfg is not None and (blob is None or not escrow.token_matches(token, blob) or not escrow.well_formed(blob, cfg)):
            raise HTTPException(403, "escrow blob missing or not the one bound to this token")
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
        st.db.execute("INSERT INTO records (id, body, escrow) VALUES (?,?,?)",
                      (rid, json.dumps(body), s.escrow))
        st.db.commit()
        entry = st.log.append("record", {"id": rid, "sha256": hashlib.sha256(canonical(body)).hexdigest(),
                                         "escrow_sha256": hashlib.sha256(blob).hexdigest() if blob else None,
                                         "meta": s.meta})
        return {"record_id": rid, "log_index": entry["index"]}

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

    @app.post("/disclosure")
    def disclosure(d: DisclosureRequest, x_lab_key: str | None = Header(None)):
        """A competent authority asks the trustees to reveal who submitted one record. The request
        is public in the log before any trustee acts on it."""
        lab_only(x_lab_key)
        row = st.db.execute("SELECT escrow FROM records WHERE id = ?", (d.record_id,)).fetchone()
        if row is None or row[0] is None:
            raise HTTPException(404, "no such record, or no escrow for it")
        return st.log.append("disclosure_request", {"record_id": d.record_id, "reason": d.reason,
                                                    "escrow_sha256": hashlib.sha256(bytes.fromhex(row[0])).hexdigest()})

    @app.get("/escrow/{record_id}")
    def escrow_blob(record_id: str):
        """Encrypted to the trustees: opening it takes t of them."""
        row = st.db.execute("SELECT escrow FROM records WHERE id = ?", (record_id,)).fetchone()
        if row is None or row[0] is None:
            raise HTTPException(404, "no escrow for this record")
        return {"record_id": record_id, "escrow": row[0]}

    @app.get("/log/entries")
    def entries(since: int = 0, until: int | None = None):
        return st.log.entries(since, until)

    @app.post("/log/checkpoint")
    def checkpoint(x_lab_key: str | None = Header(None)):
        lab_only(x_lab_key)     # operator action; in a deployment a timer
        return st.checkpoint()

    @app.get("/log/sth")
    def sth():
        if st.checkpoint_sth is None:
            raise HTTPException(404, "no checkpoint yet")
        return st.checkpoint_sth

    @app.get("/log/proof/inclusion")
    def inclusion(index: int, size: int):
        if not 0 <= index < size <= st.log.size:
            raise HTTPException(400, "index or size outside the log")
        return {"index": index, "size": size, "proof": st.log.inclusion(index, size)}

    @app.get("/log/proof/consistency")
    def consistency(first: int, second: int):
        if not 0 <= first <= second <= st.log.size:
            raise HTTPException(400, "sizes outside the log")
        return {"first": first, "second": second, "proof": st.log.consistency(first, second)}

    return app
