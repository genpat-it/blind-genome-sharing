# SPDX-License-Identifier: EUPL-1.2
"""Issuer: checks that a company is in the register and blind-signs its tokens.

It knows who the companies are and how many tokens each received -- nothing else. It never sees a
token or a final signature, so it cannot recognise a token when it is spent.

Login is OpenID Connect (SPID/CIE in a deployment): the ID token's VAT number is looked up in the
register. When identity escrow is configured, issuance is cut-and-choose (see escrow.py): the
company commits to k blinded candidates per token, the issuer picks one to sign and checks the
openings of all the others.
"""
from __future__ import annotations

import secrets
import time
from collections import Counter
from dataclasses import dataclass, field

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import escrow
from . import rsabssa as bs
from .oidc import AuthError, OidcVerifier, bearer


@dataclass
class Company:
    company_id: str
    name: str
    region: str      # NUTS-2, e.g. ITF1
    category: str    # food sector, e.g. dairy
    vat: str         # partita IVA, 11 digits


@dataclass
class IssuerState:
    sk: bs.SecretKey
    register: dict[str, Company]
    auth: OidcVerifier
    escrow_cfg: escrow.Config | None = None
    quota: int = 50
    issued: Counter = field(default_factory=Counter)      # the only thing the issuer records
    flagged: set = field(default_factory=set)              # companies caught cheating at cut-and-choose
    sessions: dict = field(default_factory=dict)

    def __post_init__(self):
        self.by_vat = {c.vat: c for c in self.register.values()}


class IssueRequest(BaseModel):
    blinded: list[str]                 # hex, one per token


class CommitRequest(BaseModel):
    candidates: list[list[str]]        # per token, k blinded candidates (hex)


class OpenRequest(BaseModel):
    session: str
    openings: list[dict[str, dict]]    # per token, {candidate index: opening} for every index but the kept one


def register_stats(register: dict[str, Company]) -> dict[str, int]:
    """Number of enrolled companies per region|category: public, used for k-anonymity."""
    return dict(Counter(f"{c.region}|{c.category}" for c in register.values()))


def create_app(state: IssuerState) -> FastAPI:
    app = FastAPI(title="Issuer")
    pk = state.sk.public_key
    cfg = state.escrow_cfg

    def company(authorization: str | None) -> Company:
        try:
            claims = state.auth.verify(bearer(authorization))
            c = state.by_vat.get(state.auth.vat(claims))
        except AuthError as e:
            raise HTTPException(401, str(e))
        if c is None:
            raise HTTPException(403, "not an enrolled food business operator")
        if c.company_id in state.flagged:
            raise HTTPException(403, "issuance suspended: a previous escrow opening did not match")
        return c

    def reserve(c: Company, n: int):
        if state.issued[c.company_id] + n > state.quota:
            raise HTTPException(429, f"quota exceeded ({state.quota} tokens per period)")

    @app.get("/key")
    def key():
        return {"pem": pk.to_pem().decode(), "fingerprint": pk.fingerprint(),
                "scheme": "RSABSSA-SHA384-PSS-Randomized", "escrow": cfg.to_json() if cfg else None}

    @app.get("/register/stats")
    def stats():
        return register_stats(state.register)

    @app.post("/issue")
    def issue(req: IssueRequest, authorization: str | None = Header(None)):
        c = company(authorization)
        if cfg is not None:
            raise HTTPException(409, "identity escrow is on: use /issue/commit and /issue/open")
        reserve(c, len(req.blinded))
        try:
            sigs = [bs.blind_sign(state.sk, bytes.fromhex(b)).hex() for b in req.blinded]
        except (ValueError, bs.BlindSignatureError) as e:
            raise HTTPException(400, str(e))
        state.issued[c.company_id] += len(sigs)
        return {"blind_sigs": sigs}

    @app.post("/issue/commit")
    def commit(req: CommitRequest, authorization: str | None = Header(None)):
        c = company(authorization)
        if cfg is None:
            raise HTTPException(409, "identity escrow is off: use /issue")
        if any(len(cands) != cfg.k for cands in req.candidates):
            raise HTTPException(400, f"exactly k={cfg.k} candidates per token")
        reserve(c, len(req.candidates))
        sid = secrets.token_hex(16)
        keep = [secrets.randbelow(cfg.k) for _ in req.candidates]      # chosen after the commitment
        state.sessions = {s: v for s, v in state.sessions.items() if v["t"] > time.time() - 600}
        state.sessions[sid] = {"company": c.company_id, "candidates": req.candidates, "keep": keep, "t": time.time()}
        return {"session": sid, "keep": keep}

    @app.post("/issue/open")
    def open_(req: OpenRequest, authorization: str | None = Header(None)):
        c = company(authorization)
        s = state.sessions.pop(req.session, None)
        if s is None or s["company"] != c.company_id:
            raise HTTPException(404, "unknown or expired session")
        if len(req.openings) != len(s["candidates"]):
            raise HTTPException(400, "one set of openings per token")
        reserve(c, len(s["candidates"]))
        for cands, keep, opened in zip(s["candidates"], s["keep"], req.openings):
            if set(opened) != {str(j) for j in range(cfg.k) if j != keep}:
                raise HTTPException(400, "every candidate except the kept one must be opened")
            for j, o in opened.items():
                if not escrow.check_opening(pk, c.company_id, cfg, bytes.fromhex(cands[int(j)]), o):
                    state.flagged.add(c.company_id)
                    raise HTTPException(400, "an opened candidate does not carry this company's escrow: "
                                             "issuance suspended")
        try:
            sigs = [bs.blind_sign(state.sk, bytes.fromhex(cands[keep])).hex()
                    for cands, keep in zip(s["candidates"], s["keep"])]
        except (ValueError, bs.BlindSignatureError) as e:
            raise HTTPException(400, str(e))
        state.issued[c.company_id] += len(sigs)
        return {"blind_sigs": sigs}

    return app
