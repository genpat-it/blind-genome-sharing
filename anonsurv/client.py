# SPDX-License-Identifier: EUPL-1.2
"""Company client: everything secret is generated here, on the company's machine.

  login  : OpenID Connect with the identity provider (SPID/CIE); yields an ID token.
  enrol  : authenticated with the issuer; draws tokens and blinding factors locally, sends only
           blinded values (k candidates per token, cut-and-choose, when escrow is on), unblinds
           the signatures and keeps (token, signature, escrow blob).
  submit : anonymous, best sent through the OHTTP relay; profile + generalised metadata + one-time
           alert key + a token. The receipt (log index) is checked later against a cosigned head.
  check  : downloads the whole bulletin and tries every alert with its own one-time keys.

Trust anchors, distributed by the consortium out of band: the log operator's key, the witnesses'
keys and how many cosignatures to require. Everything else (issuer key, escrow trustees, gateway
keys) is checked against the log's genesis entry.
"""
from __future__ import annotations

import hashlib
import json
import random
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import alerts, escrow, policy, tlog
from . import rsabssa as bs


class ClientError(Exception):
    pass


@dataclass
class Anchors:
    log_pub: str
    witnesses: dict[str, str]     # name -> Ed25519 public key (hex)
    quorum: int


@dataclass
class Wallet:
    tokens: list[dict] = field(default_factory=list)       # {"token", "signature", "escrow"} hex
    alert_keys: list[dict] = field(default_factory=list)   # {"record_id", "log_index", "sk"} hex

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.__dict__, indent=1))

    @classmethod
    def load(cls, path: str | Path) -> "Wallet":
        p = Path(path)
        return cls(**json.loads(p.read_text())) if p.exists() else cls()


# ---------------------------------------------------------------- log checks

def accepted_sth(platform: httpx.Client, anchors: Anchors) -> dict:
    r = platform.get("/log/sth")
    if r.status_code != 200:
        raise ClientError("no cosigned tree head yet")
    sth = r.json()
    if not tlog.accept_sth(sth, anchors.log_pub, anchors.witnesses, anchors.quorum):
        raise ClientError("tree head lacks the operator signature or enough witness cosignatures")
    return sth


def prove_entry(platform: httpx.Client, sth: dict, entry: dict):
    proof = platform.get("/log/proof/inclusion", params={"index": entry["index"], "size": sth["size"]}).json()["proof"]
    if not tlog.entry_included(entry, sth, proof):
        raise ClientError(f"log entry {entry['index']} is not in the cosigned tree")


def genesis(platform: httpx.Client, anchors: Anchors) -> dict:
    """The log's first entry, proven to be in a head cosigned by the consortium."""
    sth = accepted_sth(platform, anchors)
    g = platform.get("/log/entries", params={"since": 0, "until": 1}).json()[0]
    prove_entry(platform, sth, g)
    if g["kind"] != "config":
        raise ClientError("log does not start with the configuration entry")
    return g["body"]


def issuer_key(issuer: httpx.Client, platform: httpx.Client, anchors: Anchors) -> tuple[bs.PublicKey, escrow.Config | None]:
    """Fetch the issuer key and check it is the one in the cosigned log (no per-company key)."""
    conf = genesis(platform, anchors)
    k = issuer.get("/key").json()
    pk = bs.PublicKey.from_pem(k["pem"].encode())
    if conf["issuer_key"] != pk.fingerprint():
        raise ClientError("issuer key differs from the published one: possible key tagging")
    cfg = escrow.Config.from_json(conf["escrow"]) if conf["escrow"] else None
    if (k["escrow"] and escrow.Config.from_json(k["escrow"])) != cfg:
        raise ClientError("issuer and log disagree on the escrow trustees")
    return pk, cfg


def ohttp_keys(gateway_keys: bytes, platform: httpx.Client, anchors: Anchors) -> bytes:
    """Gateway key configuration, accepted only if it is the one in the log (no per-client keys)."""
    if genesis(platform, anchors)["ohttp_keys"] != hashlib.sha256(gateway_keys).hexdigest():
        raise ClientError("gateway keys differ from the published ones")
    return gateway_keys


# ---------------------------------------------------------------- identity

def login(idp: httpx.Client, client_id: str, username: str, password: str, token_path: str = "/token") -> str:
    """Password grant, for the demo and Keycloak. SPID/CIE use the browser authorisation-code flow."""
    r = idp.post(token_path, data={"grant_type": "password", "client_id": client_id, "username": username,
                                   "password": password, "scope": "openid"})
    if r.status_code != 200:
        raise ClientError(f"login failed: {r.status_code}")
    return r.json()["id_token"]


# ---------------------------------------------------------------- enrolment

def enrol(wallet: Wallet, issuer: httpx.Client, platform: httpx.Client, anchors: Anchors, id_token: str,
          n: int, company_id: str | None = None) -> int:
    """`company_id` is needed only with escrow: the company encrypts its own identifier."""
    pk, cfg = issuer_key(issuer, platform, anchors)
    auth = {"authorization": f"Bearer {id_token}"}
    if cfg is None:
        pending = []
        for _ in range(n):
            token = bs.prepare(secrets.token_bytes(32))          # random, known only to the company
            blinded, inv = bs.blind(pk, token)                   # the "envelope"
            pending.append((token, blinded, inv, None))
        r = issuer.post("/issue", json={"blinded": [b.hex() for _, b, _, _ in pending]}, headers=auth)
    else:
        if company_id is None:
            raise ClientError("escrow is on: the company identifier is needed to build the escrow")
        cands = [[escrow.make_candidate(pk, company_id, cfg) for _ in range(cfg.k)] for _ in range(n)]
        r = issuer.post("/issue/commit", json={"candidates": [[c.blinded.hex() for c in cs] for cs in cands]},
                        headers=auth)
        if r.status_code != 200:
            raise ClientError(f"issuer refused: {r.status_code} {r.json().get('detail')}")
        sid, keep = r.json()["session"], r.json()["keep"]
        openings = [{str(j): c.opening() for j, c in enumerate(cs) if j != kp} for cs, kp in zip(cands, keep)]
        r = issuer.post("/issue/open", json={"session": sid, "openings": openings}, headers=auth)
        pending = [(cs[kp].token, cs[kp].blinded, cs[kp].inv, cs[kp].blob) for cs, kp in zip(cands, keep)]
    if r.status_code != 200:
        raise ClientError(f"issuer refused: {r.status_code} {r.json().get('detail')}")
    for (token, _, inv, blob), bsig in zip(pending, r.json()["blind_sigs"]):
        sig = bs.finalize(pk, token, bytes.fromhex(bsig), inv)  # open the envelope; inv is then dropped
        wallet.tokens.append({"token": token.hex(), "signature": sig.hex(), "escrow": blob.hex() if blob else None})
    return n


def submission_delays(n: int, mean_hours: float = 12.0, rng: random.Random | None = None) -> list[float]:
    """Random waits (seconds) between enrolment and each submission, so that the issuer and the
    platform cannot match a token's issuance time to its use. Exponential, memoryless."""
    rng = rng or random.SystemRandom()
    return [rng.expovariate(1 / (mean_hours * 3600)) for _ in range(n)]


# ---------------------------------------------------------------- submission and alerts

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
                                       "pk_alert": pk.hex(), "escrow": tok.get("escrow")})
    if r.status_code != 200:
        raise ClientError(f"platform refused: {r.status_code} {r.json().get('detail')}")
    out = r.json()
    wallet.alert_keys.append({"record_id": out["record_id"], "log_index": out["log_index"], "sk": sk.hex()})
    return {**out, "meta_sent": gen}


def verify_receipts(wallet: Wallet, platform: httpx.Client, anchors: Anchors) -> int:
    """Check that each of our records is in the cosigned log, unchanged. Returns how many were checked."""
    sth = accepted_sth(platform, anchors)
    n = 0
    for key in wallet.alert_keys:
        if key["log_index"] >= sth["size"]:
            continue                                     # not yet covered by a checkpoint
        e = platform.get("/log/entries", params={"since": key["log_index"], "until": key["log_index"] + 1}).json()[0]
        if e["kind"] != "record" or e["body"]["id"] != key["record_id"]:
            raise ClientError(f"log entry {key['log_index']} is not our record {key['record_id']}")
        prove_entry(platform, sth, e)
        n += 1
    return n


def check(wallet: Wallet, platform: httpx.Client) -> list[dict]:
    found = []
    for item in platform.get("/bulletin").json():
        enc, ct = bytes.fromhex(item["enc"]), bytes.fromhex(item["ct"])
        for key in wallet.alert_keys:
            pt = alerts.try_open(bytes.fromhex(key["sk"]), enc, ct)
            if pt is not None:
                found.append(json.loads(pt))
    return found
