# SPDX-License-Identifier: EUPL-1.2
"""The whole deployment in one process, for the demo, the tests and the benchmarks.

Every service is a FastAPI app reached through httpx (FastAPI TestClient: real HTTP requests,
no open ports). The same apps run as separate processes with `python -m anonsurv.serve` and in
docker compose.

    identity provider  <- company logs in (stands in for SPID/CIE)
    issuer             <- company enrols (OIDC ID token; blind, cut-and-choose)
    relay -> gateway -> platform   <- company submits (Oblivious HTTP)
    witnesses (consortium members) <- platform asks them to cosign each checkpoint
    trustees  (consortium members) <- release escrow shares for a logged disclosure request
    laboratory                     <- reads records, posts alerts
"""
from __future__ import annotations

import contextlib
import random
import time
from dataclasses import dataclass, field

import httpx
from fastapi.testclient import TestClient

from . import alerts, client, escrow, idp, ohttp, synth, tlog
from . import rsabssa as bs
from .issuer import Company, IssuerState, create_app as issuer_app, register_stats
from .network import create_gateway, create_relay, create_witness
from .oidc import OidcVerifier
from .platform import PlatformState, create_app as platform_app
from .trustee import Trustee

CLIENT_ID = "anonsurv-issuer"
LAB_KEY = "lab-secret"


class Tracer:
    """Records every HTTP exchange between the parties: who called whom, what, how big, the answer.

    Used by simulate.py to replay the real flows in the office animation (docs/office.html).
    Clients that belong to one service record that service as the caller; the clients shared by
    companies, laboratory and trustees record whoever `acting(...)` says is acting.
    """

    def __init__(self):
        self.events: list[dict] = []
        self.actor = "?"
        self.t0 = time.perf_counter()
        self.enabled = True

    @contextlib.contextmanager
    def acting(self, actor: str):
        prev, self.actor = self.actor, actor
        try:
            yield
        finally:
            self.actor = prev

    def note(self, kind: str, **kw):
        if self.enabled:
            self.events.append({"t": round(time.perf_counter() - self.t0, 4), "kind": kind, "actor": self.actor, **kw})

    def hook(self, client: httpx.Client, to: str, caller: str | None = None):
        def on_request(req: httpx.Request):        # recorded when sent, so nested calls come in order
            if self.enabled:
                ev = {"t": round(time.perf_counter() - self.t0, 4), "kind": "http",
                      "from": caller or self.actor, "to": to, "method": req.method,
                      "path": req.url.raw_path.decode().split("?")[0], "status": None,
                      "req_bytes": len(req.read() or b""), "res_bytes": 0,
                      "req_type": req.headers.get("content-type", ""), "auth": "authorization" in req.headers}
                self.events.append(ev)
                req.extensions["trace"] = ev

        def on_response(r: httpx.Response):
            ev = r.request.extensions.get("trace")
            if ev is not None:
                r.read()
                ev.update(status=r.status_code, res_bytes=len(r.content))
        client.event_hooks["request"].append(on_request)
        client.event_hooks["response"].append(on_response)
        return client


def password(cid: str) -> str:
    return f"pw-{cid}"


@dataclass
class World:
    register: dict[str, Company]
    stats: dict[str, int]
    k: int
    issuer_state: IssuerState
    platform_state: PlatformState
    idp: httpx.Client
    issuer: httpx.Client
    platform: httpx.Client          # direct: operator, laboratory, trustees
    relay: httpx.Client
    gateway: httpx.Client
    anchors: client.Anchors
    witnesses: dict[str, tlog.Witness]
    trustees: list[Trustee] = field(default_factory=list)
    tracer: Tracer | None = None
    relay_upstream: httpx.Client | None = None     # the relay's own connection to the gateway

    def oblivious_platform(self) -> httpx.Client:
        """The company's view of the platform: every request goes through the relay."""
        keys = client.ohttp_keys(self.gateway.get("/ohttp-keys").content, self.platform, self.anchors)
        c = httpx.Client(transport=ohttp.OhttpTransport(self.relay, keys), base_url="https://platform.invalid")
        return c

    def login(self, cid: str) -> str:
        return client.login(self.idp, CLIENT_ID, cid.lower(), password(cid))

    def enrol(self, wallet: client.Wallet, cid: str, n: int) -> int:
        return client.enrol(wallet, self.issuer, self.platform, self.anchors, self.login(cid), n, cid)

    def checkpoint(self) -> dict:
        return self.platform.post("/log/checkpoint", headers={"x-lab-key": LAB_KEY}).json()


def build(seed: int = 7, k: int = 5, use_escrow: bool = True, n_witnesses: int = 3, quorum: int = 2,
          n_trustees: int = 5, t: int = 3, cut_and_choose: int = 8, quota: int = 50, bits: int = 2048,
          register: dict[str, Company] | None = None, tracer: Tracer | None = None) -> World:
    rng = random.Random(seed)
    register = register or synth.register(rng)
    stats = register_stats(register)

    users = {cid.lower(): {"password": password(cid),
                           "claims": {"https://attributes.eid.gov.it/vat_number": f"VATIT-{c.vat}",
                                      "https://attributes.eid.gov.it/company_name": c.name}}
             for cid, c in register.items()}
    # a real company that logs in successfully but is not a registered food business operator
    users["notafbo"] = {"password": "pw-notafbo", "claims": {"https://attributes.eid.gov.it/vat_number": "VATIT-99999999999"}}
    provider = idp.DemoIdP("http://idp.local", CLIENT_ID, users)
    idp_app = idp.create_app(provider)
    idp_c = TestClient(idp_app, base_url="http://idp.local")                 # used by companies
    idp_issuer = TestClient(idp_app, base_url="http://idp.local")            # used by the issuer (JWKS)

    trustee_keys = [alerts.new_keypair() for _ in range(n_trustees)]
    cfg = escrow.Config(tuple(pk.hex() for _, pk in trustee_keys), t, cut_and_choose) if use_escrow else None

    sk = bs.SecretKey.generate(bits)
    log_sk = tlog.Ed25519PrivateKey.generate()
    log_pub = tlog.ed25519_pub_hex(log_sk)
    witnesses = {f"member-{i + 1}": tlog.Witness(f"member-{i + 1}", log_pub) for i in range(n_witnesses)}
    wclients = {n: TestClient(create_witness(w), base_url=f"http://{n}.local") for n, w in witnesses.items()}
    tr = tracer
    if tr:
        for n, c in wclients.items():
            tr.hook(c, n, caller="platform")

    gw = ohttp.Gateway()
    pst = PlatformState(sk.public_key, stats, k, LAB_KEY, escrow_cfg=cfg, log_sk=log_sk, witnesses=wclients,
                        ohttp_keys=gw.keys())
    papp = platform_app(pst)
    platform = TestClient(papp, base_url="http://platform.local")                  # operator, lab, trustees
    gw_to_platform = TestClient(papp, base_url="http://platform.local")
    gwapp = create_gateway(gw, gw_to_platform)
    gateway = TestClient(gwapp, base_url="http://gateway.local")                   # key fetches
    relay_to_gw = TestClient(gwapp, base_url="http://gateway.local")
    relay = TestClient(create_relay(relay_to_gw), base_url="http://relay.local")

    ist = IssuerState(sk, register, OidcVerifier(idp_issuer, provider.issuer, CLIENT_ID), escrow_cfg=cfg, quota=quota)
    issuer = TestClient(issuer_app(ist), base_url="http://issuer.local")
    if tr:
        tr.hook(idp_c, "idp"), tr.hook(idp_issuer, "idp", caller="issuer"), tr.hook(platform, "platform")
        tr.hook(gw_to_platform, "platform", caller="gateway"), tr.hook(gateway, "gateway")
        tr.hook(relay_to_gw, "gateway", caller="relay"), tr.hook(relay, "relay"), tr.hook(issuer, "issuer")

    anchors = client.Anchors(log_pub, {n: w.pub for n, w in witnesses.items()}, quorum)
    w = World(register, stats, k, ist, pst, idp_c, issuer, platform, relay, gateway, anchors, witnesses, tracer=tr,
              relay_upstream=relay_to_gw)
    w.trustees = [Trustee(f"member-{i + 1}", i + 1, sk_t, anchors) for i, (sk_t, _) in enumerate(trustee_keys)]
    if tr:
        tr.actor = "operator"
    w.checkpoint()          # the consortium cosigns the genesis entry
    return w
