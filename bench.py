# SPDX-License-Identifier: EUPL-1.2
"""Micro-benchmarks of the cryptographic operations and of the end-to-end flow.

    .venv/bin/python bench.py            # writes results/bench.json
"""
from __future__ import annotations

import json
import os
import platform as pyplatform
import random
import secrets
import statistics
import time
from pathlib import Path

from fastapi.testclient import TestClient

from anonsurv import alerts, client, lab, synth
from anonsurv import rsabssa as bs
from anonsurv.issuer import IssuerState, create_app as issuer_app, register_stats
from anonsurv.platform import PlatformState, create_app as platform_app

REPS = 200


def timeit(fn, reps=REPS):
    ts = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t)
    return statistics.median(ts) * 1000  # ms


def crypto_costs(bits: int) -> dict:
    sk = bs.SecretKey.generate(bits)
    pk = sk.public_key
    msg = bs.prepare(secrets.token_bytes(32))
    blinded, inv = bs.blind(pk, msg)
    bsig = bs.blind_sign(sk, blinded)
    sig = bs.finalize(pk, msg, bsig, inv)
    return {
        "bits": bits,
        "blind_ms": timeit(lambda: bs.blind(pk, msg)),
        "blind_sign_ms": timeit(lambda: bs.blind_sign(sk, blinded), reps=50 if bits > 2048 else REPS),
        "finalize_ms": timeit(lambda: bs.finalize(pk, msg, bsig, inv)),
        "verify_ms": timeit(lambda: bs.verify(pk, msg, sig)),
        "token_bytes": len(msg) + len(sig),
    }


def hpke_costs() -> dict:
    sk, pk = alerts.new_keypair()
    other, _ = alerts.new_keypair()
    payload = json.dumps({"record_id": "0" * 16, "text": "x" * 120}).encode()
    enc, ct = alerts.seal(pk, payload)
    return {"seal_ms": timeit(lambda: alerts.seal(pk, payload)),
            "open_ms": timeit(lambda: alerts.try_open(sk, enc, ct)),
            "trial_fail_ms": timeit(lambda: alerts.try_open(other, enc, ct)),
            "alert_bytes": len(enc) + len(ct)}


def end_to_end() -> dict:
    rng = random.Random(7)
    reg = synth.register(rng)
    stats = register_stats(reg)
    sk = bs.SecretKey.generate(2048)
    ist = IssuerState(sk, reg, quota=10_000)
    pst = PlatformState(sk.public_key, stats, 5, "lab")
    issuer, platform = TestClient(issuer_app(ist)), TestClient(platform_app(pst))
    c = reg["FBO0001"]
    w = client.Wallet()
    t = time.perf_counter()
    client.enrol(w, issuer, platform, c.company_id, c.api_key, 100)
    enrol_per_token = (time.perf_counter() - t) / 100 * 1000
    base = synth.clone(rng)
    meta = {"species": "Listeria monocytogenes", "month": "2026-10", "region": c.region, "category": c.category}
    ts = []
    for _ in range(100):
        prof = synth.variant(rng, base, 3)
        t = time.perf_counter()
        client.submit(w, platform, stats, 5, "Lm_cgMLST_1748", prof, meta)
        ts.append(time.perf_counter() - t)
    clinical = [{"id": f"h{i}", "species": "Listeria monocytogenes", "alleles": synth.clone(rng)} for i in range(1000)]
    t = time.perf_counter()
    lab.run(platform, "lab", clinical)
    lab_s = time.perf_counter() - t
    # bulletin scan: a wallet with 50 keys over a bulletin of 1000 alerts (worst case: none is ours)
    keys = [alerts.new_keypair() for _ in range(1000)]
    bulletin = [alerts.seal(pk, b"x" * 150) for _, pk in keys]
    wallet_keys = [alerts.new_keypair()[0] for _ in range(50)]
    t = time.perf_counter()
    for enc, ct in bulletin:
        for skw in wallet_keys:
            alerts.try_open(skw, enc, ct)
    scan_s = time.perf_counter() - t
    return {"enrol_per_token_ms": enrol_per_token,
            "submit_ms": statistics.median(ts) * 1000,
            "lab_100rec_x_1000clin_s": lab_s,
            "scan_1000alerts_50keys_s": scan_s,
            "record_json_bytes": len(json.dumps({"alleles": prof, "meta": meta}))}


if __name__ == "__main__":
    out = {"machine": f"{pyplatform.processor() or pyplatform.machine()}, {os.cpu_count()} CPUs, "
                      f"Python {pyplatform.python_version()}",
           "rsa": [crypto_costs(b) for b in (2048, 3072, 4096)], "hpke": hpke_costs(), "e2e": end_to_end()}
    Path("results").mkdir(exist_ok=True)
    Path("results/bench.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
