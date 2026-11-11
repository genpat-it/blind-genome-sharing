# SPDX-License-Identifier: EUPL-1.2
"""Services around the platform: the OHTTP relay and gateway, and a consortium member's witness.

  relay   : run by a party independent of the platform. Forwards opaque encapsulated requests to
            the gateway and drops everything that identifies the sender (address, headers).
  gateway : run with the platform. Decrypts, forwards to the platform only, encrypts the answer.
  witness : run by each consortium member. Cosigns a tree head only if it extends the last one.
"""
from __future__ import annotations

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from . import ohttp, tlog


def create_relay(gateway: httpx.Client, gateway_path: str = "/gateway") -> FastAPI:
    app = FastAPI(title="OHTTP relay")

    @app.post("/relay")
    async def relay(request: Request):
        if request.headers.get("content-type") != ohttp.REQ_TYPE:
            raise HTTPException(415, f"expected {ohttp.REQ_TYPE}")
        body = await request.body()
        # Only the ciphertext goes on: no client address, no forwarded-for, no cookies, no user agent.
        r = gateway.post(gateway_path, content=body, headers={"content-type": ohttp.REQ_TYPE})
        return Response(r.content, status_code=r.status_code, media_type=r.headers.get("content-type"))

    return app


def create_gateway(gw: ohttp.Gateway, platform: httpx.Client,
                   allowed_paths: tuple[str, ...] = ("/submit", "/bulletin", "/log/")) -> FastAPI:
    app = FastAPI(title="OHTTP gateway")

    @app.get("/ohttp-keys")
    def keys():
        return Response(gw.keys(), media_type=ohttp.KEYS_TYPE)

    @app.post("/gateway")
    async def gateway(request: Request):
        try:
            breq, pending = gw.decapsulate_request(await request.body())
            req = ohttp.decode_request(breq)
        except ohttp.OhttpError as e:
            raise HTTPException(400, str(e))
        path = req["path"].split("?")[0]
        if not any(path == p or (p.endswith("/") and path.startswith(p)) for p in allowed_paths):
            bres = ohttp.encode_response(403, [("content-type", "application/json")],
                                         b'{"detail":"target not allowed through this gateway"}')
        else:
            r = platform.request(req["method"], req["path"], content=req["body"],
                                 headers=[(k, v) for k, v in req["headers"] if k == "content-type"])
            bres = ohttp.encode_response(r.status_code, [("content-type", r.headers.get("content-type", ""))], r.content)
        return Response(gw.encapsulate_response(pending, bres), media_type=ohttp.RES_TYPE)

    return app


class CosignRequest(BaseModel):
    sth: dict
    proof: list[str]


def create_witness(w: tlog.Witness) -> FastAPI:
    app = FastAPI(title=f"Witness {w.name}")

    @app.get("/state")
    def state():
        return {"name": w.name, "pub": w.pub, **w.last}

    @app.post("/cosign")
    def cosign(req: CosignRequest):
        try:
            return {"sig": w.cosign(req.sth, req.proof)}
        except (ValueError, KeyError) as e:
            raise HTTPException(409, str(e))

    return app
