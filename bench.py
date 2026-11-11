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
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message=".*httpx2.*")

from anonsurv import alerts, client, escrow, lab, synth, tlog, world  # noqa: E402
from anonsurv import rsabssa as bs  # noqa: E402

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


def escrow_costs() -> dict:
    tr = [alerts.new_keypair() for _ in range(5)]
    cfg = escrow.Config(tuple(pk.hex() for _, pk in tr), 3, 8)
    sk = bs.SecretKey.generate(2048)
    pk = sk.public_key
    c = escrow.make_candidate(pk, "FBO0001", cfg)
    shares = [escrow.open_share(c.blob, x, tr[x - 1][0]) for x in (1, 2, 3)]
    return {"candidate_ms": timeit(lambda: escrow.make_candidate(pk, "FBO0001", cfg)),
            "check_opening_ms": timeit(lambda: escrow.check_opening(pk, "FBO0001", cfg, c.blinded, c.opening())),
            "open_share_ms": timeit(lambda: escrow.open_share(c.blob, 1, tr[0][0])),
            "reveal_ms": timeit(lambda: escrow.reveal(c.blob, shares)),
            "blob_bytes": len(c.blob), "trustees": 5, "t": 3, "k": 8}


def merkle_costs() -> dict:
    out = {}
    for n in (1_000, 100_000):
        t = tlog.MerkleTree([tlog.leaf_hash(i.to_bytes(8, "big")) for i in range(n)])
        t0 = time.perf_counter()
        root = t.root()
        build = time.perf_counter() - t0
        proof = t.inclusion_proof(n // 3, n)
        cons = t.consistency_proof(n // 2, n)
        out[str(n)] = {"root_s": build, "inclusion_hashes": len(proof), "consistency_hashes": len(cons),
                       "verify_inclusion_ms": timeit(lambda: tlog.verify_inclusion(n // 3, n, t.leaves[n // 3], proof, root)),
                       "verify_consistency_ms": timeit(lambda: tlog.verify_consistency(n // 2, n, t.root(n // 2), root, cons))}
    return out


def end_to_end() -> dict:
    rng = random.Random(7)
    W = world.build(seed=7, quota=10_000)
    W_plain = world.build(seed=8, quota=10_000, use_escrow=False)
    res = {}
    for label, w_ in (("escrow", W), ("plain", W_plain)):
        w = client.Wallet()
        t = time.perf_counter()
        w_.enrol(w, "FBO0001", 100)
        res[f"enrol_per_token_{label}_ms"] = (time.perf_counter() - t) / 100 * 1000
    c = W.register["FBO0001"]
    w = client.Wallet()
    W.enrol(w, "FBO0001", 200)
    base = synth.clone(rng)
    meta = {"species": "Listeria monocytogenes", "month": "2026-10", "region": c.region, "category": c.category}
    for label, P in (("direct", W.platform), ("ohttp", W.oblivious_platform())):
        ts = []
        for _ in range(100):
            prof = synth.variant(rng, base, 3)
            t = time.perf_counter()
            client.submit(w, P, W.stats, 5, "Lm_cgMLST_1748", prof, meta)
            ts.append(time.perf_counter() - t)
        res[f"submit_{label}_ms"] = statistics.median(ts) * 1000
    t = time.perf_counter()
    cp = W.checkpoint()
    res["checkpoint_3_witnesses_ms"] = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    client.verify_receipts(w, W.oblivious_platform(), W.anchors)
    res["verify_receipts_per_record_ms"] = (time.perf_counter() - t) / len(w.alert_keys) * 1000
    clinical = [{"id": f"h{i}", "species": "Listeria monocytogenes", "alleles": synth.clone(rng)} for i in range(1000)]
    t = time.perf_counter()
    lab.run(W.platform, world.LAB_KEY, clinical)
    res["lab_200rec_x_1000clin_s"] = time.perf_counter() - t
    keys = [alerts.new_keypair() for _ in range(1000)]
    bulletin = [alerts.seal(pk, b"x" * 150) for _, pk in keys]
    wallet_keys = [alerts.new_keypair()[0] for _ in range(50)]
    t = time.perf_counter()
    for enc, ct in bulletin:
        for skw in wallet_keys:
            alerts.try_open(skw, enc, ct)
    res["scan_1000alerts_50keys_s"] = time.perf_counter() - t
    res["record_json_bytes"] = len(json.dumps({"alleles": prof, "meta": meta}))
    res["log_entries"] = cp["sth"]["size"]
    return res


if __name__ == "__main__":
    out = {"machine": f"{pyplatform.processor() or pyplatform.machine()}, {os.cpu_count()} CPUs, "
                      f"Python {pyplatform.python_version()}",
           "rsa": [crypto_costs(b) for b in (2048, 3072, 4096)], "hpke": hpke_costs(),
           "escrow": escrow_costs(), "merkle": merkle_costs(), "e2e": end_to_end()}
    Path("results").mkdir(exist_ok=True)
    Path("results/bench.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
