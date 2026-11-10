# SPDX-License-Identifier: EUPL-1.2
"""Company client: everything secret is generated here, on the company's machine.

  enrol  : authenticated with the issuer; draws tokens and blinding factors locally, sends only
           the blinded values, unblinds the signatures and keeps (token, signature).
  submit : anonymous; sends profile + generalised metadata + one-time alert key + a token.
  check  : downloads the whole bulletin and tries every alert with its own one-time keys.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import alerts, policy
from . import rsabssa as bs


class ClientError(Exception):
    pass


@dataclass
class Wallet:
    tokens: list[dict] = field(default_factory=list)       # {"token", "signature"} hex
    alert_keys: list[dict] = field(default_factory=list)   # {"record_id", "sk"} hex

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.__dict__, indent=1))

    @classmethod
    def load(cls, path: str | Path) -> "Wallet":
        p = Path(path)
        return cls(**json.loads(p.read_text())) if p.exists() else cls()


def issuer_key(issuer: httpx.Client, platform: httpx.Client) -> bs.PublicKey:
    """Fetch the issuer key and check it is the one recorded in the public log (no per-company key)."""
    k = issuer.get("/key").json()
    pk = bs.PublicKey.from_pem(k["pem"].encode())
    genesis = platform.get("/log", params={"since": 0}).json()[0]
    if genesis["kind"] != "issuer_key" or genesis["body"]["fingerprint"] != pk.fingerprint():
        raise ClientError("issuer key differs from the published one: possible key tagging")
    return pk


def enrol(wallet: Wallet, issuer: httpx.Client, platform: httpx.Client, company_id: str, api_key: str,
          n: int) -> int:
    pk = issuer_key(issuer, platform)
    pending = []
    for _ in range(n):
        token = bs.prepare(secrets.token_bytes(32))          # random, known only to the company
        blinded, inv = bs.blind(pk, token)                      # the "envelope"
        pending.append((token, blinded, inv))
    r = issuer.post("/issue", json={"company_id": company_id, "api_key": api_key,
                                    "blinded": [b.hex() for _, b, _ in pending]})
    if r.status_code != 200:
        raise ClientError(f"issuer refused: {r.status_code} {r.json().get('detail')}")
    for (token, _, inv), bsig in zip(pending, r.json()["blind_sigs"]):
        sig = bs.finalize(pk, token, bytes.fromhex(bsig), inv)  # open the envelope; inv is then dropped
        wallet.tokens.append({"token": token.hex(), "signature": sig.hex()})
    return n


def submit(wallet: Wallet, platform: httpx.Client, stats: dict[str, int], k: int, scheme: str,
           alleles: list[int], meta: dict) -> dict:
    if not wallet.tokens:
        raise ClientError("no tokens left")
    gen = policy.generalise(meta, stats, k)
    if gen is None:
        raise ClientError("metadata cannot be generalised to an anonymity set of k")
    sk, pk = alerts.new_keypair()
    tok = wallet.tokens.pop(0)
    r = platform.post("/submit", json={"token": tok["token"], "signature": tok["signature"],
                                       "scheme": scheme, "alleles": alleles, "meta": gen,
                                       "pk_alert": pk.hex()})
    if r.status_code != 200:
        raise ClientError(f"platform refused: {r.status_code} {r.json().get('detail')}")
    out = r.json()
    wallet.alert_keys.append({"record_id": out["record_id"], "sk": sk.hex()})
    return {**out, "meta_sent": gen}


def check(wallet: Wallet, platform: httpx.Client) -> list[dict]:
    found = []
    for item in platform.get("/bulletin").json():
        enc, ct = bytes.fromhex(item["enc"]), bytes.fromhex(item["ct"])
        for key in wallet.alert_keys:
            pt = alerts.try_open(bytes.fromhex(key["sk"]), enc, ct)
            if pt is not None:
                found.append(json.loads(pt))
    return found
