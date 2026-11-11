# SPDX-License-Identifier: EUPL-1.2
"""Run one service as its own process (used by docker compose).

    python -m anonsurv.serve issuer|platform|gateway|relay|witness [--port 8000]

Configuration comes from the directory in $ANONSURV_CONFIG (written by deploy/setup.py) and these
environment variables, all URLs inside the deployment's network:
  OIDC_ISSUER, OIDC_CLIENT_ID          issuer: the identity provider (Keycloak, SPID/CIE)
  WITNESSES  name=url,...              platform: the consortium members' witnesses
  CHECKPOINT_SECONDS                   platform: how often to ask for cosignatures (default 10)
  PLATFORM_URL                         gateway
  GATEWAY_URL                          relay
  WITNESS_NAME                         witness
  DATA_DIR                             platform, witness: where SQLite and state live
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import escrow, ohttp, tlog
from . import rsabssa as bs
from .issuer import Company, IssuerState, create_app as issuer_app, register_stats
from .network import create_gateway, create_relay, create_witness
from .oidc import OidcVerifier
from .platform import PlatformState, create_app as platform_app


def cfg_dir() -> Path:
    return Path(os.environ.get("ANONSURV_CONFIG", "deploy/config"))


def load_json(name: str):
    return json.loads((cfg_dir() / name).read_text())


def load_register() -> dict[str, Company]:
    return {c["company_id"]: Company(**c) for c in load_json("register.json")}


def ed25519(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex((cfg_dir() / name).read_text().strip()))


def escrow_cfg() -> escrow.Config | None:
    p = cfg_dir() / "escrow.json"
    return escrow.Config.from_json(json.loads(p.read_text())) if p.exists() else None


def build(role: str):
    data = Path(os.environ.get("DATA_DIR", "."))
    if role == "issuer":
        sk = bs.SecretKey.from_pem((cfg_dir() / "issuer_sk.pem").read_bytes())
        iss = os.environ["OIDC_ISSUER"]
        u = httpx.URL(iss)
        http = httpx.Client(base_url=f"{u.scheme}://{u.netloc.decode()}", timeout=10)
        auth = OidcVerifier(http, iss, os.environ.get("OIDC_CLIENT_ID", "anonsurv-issuer"))
        return issuer_app(IssuerState(sk, load_register(), auth, escrow_cfg(),
                                      quota=int(os.environ.get("QUOTA", "50"))))
    if role == "platform":
        pk = bs.PublicKey.from_pem((cfg_dir() / "issuer_pk.pem").read_bytes())
        witnesses = {n: httpx.Client(base_url=url, timeout=10)
                     for n, url in (w.split("=", 1) for w in os.environ.get("WITNESSES", "").split(",") if w)}
        st = PlatformState(pk, register_stats(load_register()), int(os.environ.get("K_ANONYMITY", "5")),
                           (cfg_dir() / "lab_key").read_text().strip(), db=str(data / "platform.db"),
                           escrow_cfg=escrow_cfg(), log_sk=ed25519("log_sk"), witnesses=witnesses,
                           ohttp_keys=(cfg_dir() / "ohttp_keys.bin").read_bytes())
        period = float(os.environ.get("CHECKPOINT_SECONDS", "10"))

        @asynccontextmanager
        async def lifespan(app):
            async def loop():
                while True:
                    try:
                        await asyncio.to_thread(st.checkpoint)
                    except httpx.HTTPError:
                        pass                     # a witness is down: try again at the next period
                    await asyncio.sleep(period)
            task = asyncio.create_task(loop())
            yield
            task.cancel()
        app = platform_app(st)
        app.router.lifespan_context = lifespan
        return app
    if role == "gateway":
        gw = ohttp.Gateway(bytes.fromhex((cfg_dir() / "gateway_sk").read_text().strip()))
        return create_gateway(gw, httpx.Client(base_url=os.environ["PLATFORM_URL"], timeout=30))
    if role == "relay":
        return create_relay(httpx.Client(base_url=os.environ["GATEWAY_URL"], timeout=30))
    if role == "witness":
        name = os.environ["WITNESS_NAME"]
        log_pub = load_json("anchors.json")["log_pub"]
        w = tlog.Witness(name, log_pub, ed25519(f"witness_{name}_sk"))
        state = data / f"witness_{name}.json"
        if state.exists():
            w.last = json.loads(state.read_text())
        orig = w.cosign

        def cosign(sth, proof):                  # persist the last cosigned head: a witness must not forget it
            sig = orig(sth, proof)
            state.write_text(json.dumps(w.last))
            return sig
        w.cosign = cosign
        return create_witness(w)
    raise SystemExit(f"unknown role {role}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("role")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    uvicorn.run(build(a.role), host="0.0.0.0", port=a.port, log_level="warning")
