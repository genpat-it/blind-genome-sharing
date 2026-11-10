# SPDX-License-Identifier: EUPL-1.2
"""Issuer: checks that a company is in the register and blind-signs its tokens.

It knows who the companies are and how many tokens each received -- nothing else. It never sees a
token or a final signature, so it cannot recognise a token when it is spent.
Authentication is an API key here; in a deployment it would be the national digital identity.
"""
from __future__ import annotations

import hmac
from collections import Counter
from dataclasses import dataclass, field

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import rsabssa as bs


@dataclass
class Company:
    company_id: str
    name: str
    region: str      # NUTS-2, e.g. ITF1
    category: str    # food sector, e.g. dairy
    api_key: str


@dataclass
class IssuerState:
    sk: bs.SecretKey
    register: dict[str, Company]
    quota: int = 50
    issued: Counter = field(default_factory=Counter)   # the only thing the issuer records


class IssueRequest(BaseModel):
    company_id: str
    api_key: str
    blinded: list[str]   # hex


def register_stats(register: dict[str, Company]) -> dict[str, int]:
    """Number of enrolled companies per region|category: public, used for k-anonymity."""
    return dict(Counter(f"{c.region}|{c.category}" for c in register.values()))


def create_app(state: IssuerState) -> FastAPI:
    app = FastAPI(title="Issuer")
    pk = state.sk.public_key

    @app.get("/key")
    def key():
        return {"pem": pk.to_pem().decode(), "fingerprint": pk.fingerprint(), "scheme": "RSABSSA-SHA384-PSS-Randomized"}

    @app.get("/register/stats")
    def stats():
        return register_stats(state.register)

    @app.post("/issue")
    def issue(req: IssueRequest):
        c = state.register.get(req.company_id)
        if c is None or not hmac.compare_digest(c.api_key, req.api_key):
            raise HTTPException(403, "not an enrolled food business operator")
        if state.issued[c.company_id] + len(req.blinded) > state.quota:
            raise HTTPException(429, f"quota exceeded ({state.quota} tokens per period)")
        try:
            sigs = [bs.blind_sign(state.sk, bytes.fromhex(b)).hex() for b in req.blinded]
        except (ValueError, bs.BlindSignatureError) as e:
            raise HTTPException(400, str(e))
        state.issued[c.company_id] += len(sigs)
        return {"blind_sigs": sigs}

    return app
