# SPDX-License-Identifier: EUPL-1.2
"""End-to-end check against running services (docker compose, or `python -m anonsurv.serve`).

    docker compose run --rm e2e

Every party talks to the others over the network only: companies log in to Keycloak, enrol with
the issuer, submit through the relay; the laboratory reads records and posts alerts; trustees
release escrow shares for a logged disclosure request.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from anonsurv import client, escrow, lab, ohttp, synth  # noqa: E402
from anonsurv.trustee import Trustee  # noqa: E402

CFG = Path(os.environ.get("ANONSURV_CONFIG", "deploy/config"))
URL = {k: os.environ.get(f"{k.upper()}_URL", f"http://{k}:8000") for k in ("issuer", "platform", "relay", "gateway")}
KC = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
TOKEN_PATH = "/realms/anonsurv/protocol/openid-connect/token"
SP = "Listeria monocytogenes"


def wait(c: httpx.Client, path: str, tries: int = 120):
    for _ in range(tries):
        try:
            if c.get(path).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise SystemExit(f"{c.base_url}{path} not reachable")


def main():
    a = json.loads((CFG / "anchors.json").read_text())
    anchors = client.Anchors(a["log_pub"], a["witnesses"], a["quorum"])
    lab_key = (CFG / "lab_key").read_text().strip()
    register = {c["company_id"]: c for c in json.loads((CFG / "register.json").read_text())}
    stats = {}
    for c in register.values():
        stats[f"{c['region']}|{c['category']}"] = stats.get(f"{c['region']}|{c['category']}", 0) + 1

    idp = httpx.Client(base_url=KC, timeout=30)
    issuer = httpx.Client(base_url=URL["issuer"], timeout=30)
    platform = httpx.Client(base_url=URL["platform"], timeout=30)      # laboratory and trustees
    relay = httpx.Client(base_url=URL["relay"], timeout=30)
    gateway = httpx.Client(base_url=URL["gateway"], timeout=30)
    wait(idp, "/realms/anonsurv/.well-known/openid-configuration")
    for c in (issuer, platform, gateway):
        wait(c, "/docs")
    while platform.get("/log/sth").status_code != 200:
        time.sleep(1)

    keys = client.ohttp_keys(gateway.get("/ohttp-keys").content, platform, anchors)
    oblivious = httpx.Client(transport=ohttp.OhttpTransport(relay, keys), base_url="https://platform.invalid")
    rng = random.Random(3)
    base = synth.clone(rng)
    ids = sorted(register)[:6]
    wallets = {}
    for i, cid in enumerate(ids):
        tok = client.login(idp, "anonsurv-issuer", cid.lower(), f"pw-{cid}", TOKEN_PATH)
        wallets[cid] = client.Wallet()
        client.enrol(wallets[cid], issuer, platform, anchors, tok, 3, cid)
        c = register[cid]
        prof = synth.variant(rng, base, 2) if i < 2 else synth.clone(rng)
        out = client.submit(wallets[cid], oblivious, stats, 5, "Lm_cgMLST_1748", prof,
                            {"species": SP, "month": "2026-10", "region": c["region"], "category": c["category"]})
        print(f"{cid}: enrolled 3 tokens via Keycloak, submitted via relay -> record {out['record_id']} "
              f"({out['meta_sent']['region']}, {out['meta_sent']['category']})")
    try:
        client.enrol(client.Wallet(), issuer, platform, anchors,
                     client.login(idp, "anonsurv-issuer", "notafbo", "pw-notafbo", TOKEN_PATH), 1, "X")
        raise SystemExit("FAIL: a non-registered company obtained tokens")
    except client.ClientError as e:
        print("Keycloak user not in the register:", e)

    sent, _ = lab.run(platform, lab_key, [{"id": "h1", "species": SP, "alleles": base}])
    alerted = [cid for cid in ids if client.check(wallets[cid], oblivious)]
    print(f"Laboratory sent {len(sent)} alerts; companies that found one: {alerted}")
    assert alerted == ids[:2], alerted

    rid = wallets[ids[0]].alert_keys[0]["record_id"]
    platform.post("/disclosure", json={"record_id": rid, "reason": "e2e test"}, headers={"x-lab-key": lab_key})
    size = platform.get("/log/sth").json()["size"]
    while platform.get("/log/sth").json()["size"] <= size:     # wait for the periodic checkpoint
        time.sleep(1)
    n = sum(client.verify_receipts(w, oblivious, anchors) for w in wallets.values())
    print(f"Receipts verified against the cosigned head: {n}")
    cfg = json.loads((CFG / "escrow.json").read_text())
    trustees = [Trustee(f"trustee-{i}", i, bytes.fromhex((CFG / f"trustee_{i}_sk").read_text().strip()), anchors)
                for i in range(1, cfg["t"] + 1)]
    shares = [t.release(platform, rid) for t in trustees]
    who = escrow.reveal(bytes.fromhex(platform.get(f"/escrow/{rid}").json()["escrow"]), shares)
    print(f"Disclosure by {cfg['t']} trustees: record {rid} -> {who}")
    assert who == ids[0]
    print("E2E OK")


if __name__ == "__main__":
    main()
