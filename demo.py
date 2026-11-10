# SPDX-License-Identifier: EUPL-1.2
"""End-to-end demo of the anonymous submission protocol, on synthetic data.

    .venv/bin/python demo.py

Runs issuer and platform in-process (FastAPI TestClient: real HTTP requests, no open ports).
"""
from __future__ import annotations

import random
import secrets
import statistics
import time

from fastapi.testclient import TestClient

from anonsurv import client, lab, synth
from anonsurv import rsabssa as bs
from anonsurv.issuer import IssuerState, create_app as issuer_app, register_stats
from anonsurv.platform import PlatformState, create_app as platform_app
from anonsurv.tlog import verify_chain

SPECIES, SCHEME, K = "Listeria monocytogenes", "Lm_cgMLST_Pasteur_1748", 5
rng = random.Random(42)


def title(t):
    print(f"\n== {t} " + "=" * (70 - len(t)))


# ---------------------------------------------------------------- set-up
register = synth.register(rng)
stats = register_stats(register)
t0 = time.perf_counter()
sk = bs.SecretKey.generate(2048)
print(f"Issuer RSA-2048 key generated in {time.perf_counter() - t0:.2f} s; "
      f"{len(register)} companies enrolled in {len(stats)} region x category cells")

istate = IssuerState(sk, register, quota=50)
pstate = PlatformState(sk.public_key, stats, K, lab_key="lab-secret")
issuer, platform = TestClient(issuer_app(istate)), TestClient(platform_app(pstate))

clones = [synth.clone(rng) for _ in range(20)]
outbreak = {0, 1, 2}                                   # clones with human cases
clinical = [{"id": f"HUM{c}-{j}", "species": SPECIES, "alleles": synth.variant(rng, clones[c], rng.randint(0, 3))}
            for c in outbreak for j in range(5)]

# ---------------------------------------------------------------- 1. enrolment
title("1. Enrolment: companies identify themselves and get blind-signed tokens")
companies = rng.sample(sorted(register), 40)
wallets = {cid: client.Wallet() for cid in companies}
times = []
for cid in companies:
    t = time.perf_counter()
    client.enrol(wallets[cid], issuer, platform, cid, register[cid].api_key, n=10)
    times.append((time.perf_counter() - t) / 10)
print(f"40 companies x 10 tokens; client+issuer time per token: median {statistics.median(times)*1000:.1f} ms")
print("What the issuer knows:", dict(list(istate.issued.items())[:3]), "... (counts only)")

# ---------------------------------------------------------------- 2. submissions
title("2. Anonymous submissions")
truth, times = {}, []
for cid in companies:
    c = rng.randrange(len(clones))
    alleles = synth.variant(rng, clones[c], rng.randint(0, 4))
    meta = {"species": SPECIES, "month": "2026-10", "region": register[cid].region,
            "category": register[cid].category}
    t = time.perf_counter()
    out = client.submit(wallets[cid], platform, stats, K, SCHEME, alleles, meta)
    times.append(time.perf_counter() - t)
    truth[cid] = c in outbreak
print(f"{len(companies)} records accepted; time per submission: median {statistics.median(times)*1000:.1f} ms")
rec = platform.get("/records", headers={"x-lab-key": "lab-secret"}).json()[0]
print("A record as public health sees it:", {k: (v if k != "alleles" else f"[{len(v)} alleles]")
                                             for k, v in rec.items() if k != "pk_alert"})

# small cell: generalisation
small = next(c for c in register.values() if (c.region, c.category) == ("ITF2", "fish"))
w = client.Wallet()
client.enrol(w, issuer, platform, small.company_id, small.api_key, n=1)
out = client.submit(w, platform, stats, K, SCHEME, synth.variant(rng, clones[5], 2),
                    {"species": SPECIES, "month": "2026-10", "region": "ITF2", "category": "fish"})
print(f"Company in a cell with 2 companies (ITF2, fish) -> sent as {out['meta_sent']['region']}, "
      f"{out['meta_sent']['category']} (k={K})")

# ---------------------------------------------------------------- 3. attacks
title("3. What the platform refuses")
cid = companies[0]
tok = wallets[cid].tokens[0]
body = {"token": tok["token"], "signature": tok["signature"], "scheme": SCHEME, "alleles": [1] * synth.N_LOCI,
        "meta": {"species": SPECIES, "month": "2026-10", "region": "IT", "category": "*"},
        "pk_alert": "00" * 32}
print("token used once           :", platform.post("/submit", json=body).status_code)
print("same token again          :", platform.post("/submit", json=body).status_code,
      platform.post("/submit", json=body).json()["detail"])
forged = {**body, "token": secrets.token_bytes(64).hex()}
print("forged token              :", platform.post("/submit", json=forged).status_code,
      platform.post("/submit", json=forged).json()["detail"])
other_key = bs.SecretKey.generate(2048)
m = bs.prepare(b"x")
bl, inv = bs.blind(other_key.public_key, m)
fake = {**body, "token": m.hex(), "signature": bs.finalize(other_key.public_key, m, bs.blind_sign(other_key, bl), inv).hex()}
print("token signed by another key:", platform.post("/submit", json=fake).status_code)
exact = {**body, "token": wallets[cid].tokens[1]["token"], "signature": wallets[cid].tokens[1]["signature"],
         "meta": {"species": SPECIES, "month": "2026-10-14", "region": "ITF1", "category": "dairy"}}
print("exact date in metadata    :", platform.post("/submit", json=exact).status_code,
      platform.post("/submit", json=exact).json()["detail"])
try:
    client.enrol(client.Wallet(), issuer, platform, "FBO9999", "guess", n=1)
except client.ClientError as e:
    print("unregistered company      :", e)
try:
    client.enrol(wallets[cid], issuer, platform, cid, register[cid].api_key, n=45)
except client.ClientError as e:
    print("over quota                :", e)

# ---------------------------------------------------------------- 4. surveillance
title("4. Public health clusters records with human cases and sends private alerts")
sent, _ = lab.run(platform, "lab-secret", clinical)
print(f"{len(sent)} alerts posted on a bulletin of {len(platform.get('/bulletin').json())} entries")
got = {cid: bool(client.check(wallets[cid], platform)) for cid in companies}
tp = sum(got[c] and truth[c] for c in companies)
fp = sum(got[c] and not truth[c] for c in companies)
fn = sum(truth[c] and not got[c] for c in companies)
print(f"Companies whose isolate is in an outbreak clone: {sum(truth.values())}; "
      f"alerted: {tp} correct, {fp} wrong, {fn} missed")
example = next(c for c in companies if got[c])
print(f"What {example} reads:", client.check(wallets[example], platform)[0]["text"])

# ---------------------------------------------------------------- 5. log
title("5. Tamper-evident log")
head = platform.get("/log/head").json()
entries = platform.get("/log").json()
print(f"{len(entries)} entries, head {head['hash'][:16]}...; chain valid: {verify_chain(entries, head)}")
pstate.log.db.execute("UPDATE log SET body = replace(body, '2026-10', '2026-09') WHERE idx = 1")
print("after an operator silently rewrites a record, chain valid against the members' head:",
      verify_chain(platform.get("/log").json(), head))
