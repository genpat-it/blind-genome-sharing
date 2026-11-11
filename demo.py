# SPDX-License-Identifier: EUPL-1.2
"""End-to-end demo of the anonymous submission protocol, on synthetic data.

    .venv/bin/python demo.py

All services run in-process (FastAPI TestClient: real HTTP requests, no open ports); see
anonsurv/world.py. `docker compose up` runs the same services as separate containers.
"""
from __future__ import annotations

import json
import random
import secrets
import statistics
import time
import warnings

warnings.filterwarnings("ignore", message=".*httpx2.*")

from anonsurv import alerts, client, escrow, lab, ohttp, synth, tlog, world  # noqa: E402
from anonsurv import rsabssa as bs  # noqa: E402

SPECIES, SCHEME, K = "Listeria monocytogenes", "Lm_cgMLST_Pasteur_1748", 5
rng = random.Random(42)


def title(t):
    print(f"\n== {t} " + "=" * (72 - len(t)))


def detail(r):
    return f"{r.status_code} {r.json().get('detail')}"


# ---------------------------------------------------------------- set-up
title("0. Set-up: issuer, platform, relay, gateway, 3 witnesses, 5 escrow trustees")
t0 = time.perf_counter()
W = world.build(seed=42, k=K)
print(f"Built in {time.perf_counter() - t0:.2f} s. {len(W.register)} companies enrolled in {len(W.stats)} "
      f"region x category cells. Escrow: {W.issuer_state.escrow_cfg.t} of {len(W.trustees)} trustees, "
      f"{W.issuer_state.escrow_cfg.k} cut-and-choose candidates per token.")
genesis = client.genesis(W.platform, W.anchors)
print("Log entry 0, cosigned by", ", ".join(W.platform.get("/log/sth").json()["cosigs"]), "->",
      {k: (v[:16] + "..." if isinstance(v, str) else "{...}" if isinstance(v, dict) else v) for k, v in genesis.items()})
platform = W.oblivious_platform()          # what companies use: every request goes through the relay

clones = [synth.clone(rng) for _ in range(20)]
outbreak = {0, 1, 2}                                   # clones with human cases
clinical = [{"id": f"HUM{c}-{j}", "species": SPECIES, "alleles": synth.variant(rng, clones[c], rng.randint(0, 3))}
            for c in outbreak for j in range(5)]

# ---------------------------------------------------------------- 1. enrolment
title("1. Enrolment: login with the identity provider, blind cut-and-choose issuance")
companies = rng.sample(sorted(W.register), 40)
wallets = {cid: client.Wallet() for cid in companies}
times = []
for cid in companies:
    t = time.perf_counter()
    W.enrol(wallets[cid], cid, n=10)
    times.append((time.perf_counter() - t) / 10)
print(f"40 companies x 10 tokens; login + client + issuer time per token: median {statistics.median(times)*1000:.1f} ms")
print("What the issuer knows:", dict(list(W.issuer_state.issued.items())[:3]), "... (counts only)")

# a company that tries to put somebody else's identifier in its escrow
cheat, victim = companies[0], companies[1]
caught, trials = 0, 200
pk = bs.PublicKey.from_pem(W.issuer.get("/key").json()["pem"].encode())
cfg = W.issuer_state.escrow_cfg
for _ in range(trials):
    W.issuer_state.flagged.clear()
    W.issuer_state.issued[cheat] = 0
    bad = rng.randrange(cfg.k)
    cands = [escrow.make_candidate(pk, victim if j == bad else cheat, cfg) for j in range(cfg.k)]
    auth = {"authorization": f"Bearer {W.login(cheat)}"}
    r = W.issuer.post("/issue/commit", json={"candidates": [[c.blinded.hex() for c in cands]]}, headers=auth).json()
    opened = {str(j): c.opening() for j, c in enumerate(cands) if j != r["keep"][0]}
    caught += W.issuer.post("/issue/open", json={"session": r["session"], "openings": [opened]},
                            headers=auth).status_code == 400
W.issuer_state.flagged.clear()
print(f"Cheating on one candidate in {trials} attempts: caught {caught} times ({caught / trials:.0%}; "
      f"expected {(cfg.k - 1) / cfg.k:.0%}). A caught company loses issuance.")

# ---------------------------------------------------------------- 2. submissions
title("2. Anonymous submissions through the Oblivious HTTP relay")
forwarded = []                             # what the relay passes on to the gateway
_post = W.relay_upstream.post
W.relay_upstream.post = lambda path, **kw: (forwarded.append(kw), _post(path, **kw))[1]
truth, times = {}, []
for cid in companies:
    c = rng.randrange(len(clones))
    alleles = synth.variant(rng, clones[c], rng.randint(0, 4))
    meta = {"species": SPECIES, "month": "2026-10", "region": W.register[cid].region,
            "category": W.register[cid].category}
    t = time.perf_counter()
    client.submit(wallets[cid], platform, W.stats, K, SCHEME, alleles, meta)
    times.append(time.perf_counter() - t)
    truth[cid] = c in outbreak
print(f"{len(companies)} records accepted; time per submission (relay + gateway + platform): "
      f"median {statistics.median(times)*1000:.1f} ms")
W.relay_upstream.post = _post
f = forwarded[0]
print(f"The relay forwarded {len(forwarded)} requests of ~{len(f['content']) // 1000} kB with headers {f['headers']};"
      f" plaintext visible to it: {b'alleles' in f['content'] or b'token' in f['content']}.")
print("The gateway decrypts them but sees only the relay as sender.")
rec = W.platform.get("/records", headers={"x-lab-key": world.LAB_KEY}).json()[0]
print("A record as public health sees it:", {k: (v if k != "alleles" else f"[{len(v)} alleles]")
                                             for k, v in rec.items() if k != "pk_alert"})
small = next(c for c in W.register.values() if (c.region, c.category) == ("ITF2", "fish"))
w = client.Wallet()
W.enrol(w, small.company_id, n=1)
out = client.submit(w, platform, W.stats, K, SCHEME, synth.variant(rng, clones[5], 2),
                    {"species": SPECIES, "month": "2026-10", "region": "ITF2", "category": "fish"})
print(f"Company in a cell with 2 companies (ITF2, fish) -> sent as {out['meta_sent']['region']}, "
      f"{out['meta_sent']['category']} (k={K})")
print("Waits between enrolment and use, drawn by the client (hours):",
      [round(d / 3600, 1) for d in client.submission_delays(5, 12, rng)])

# ---------------------------------------------------------------- 3. refusals
title("3. What is refused")
cid = companies[2]
tok = wallets[cid].tokens[0]
body = {"token": tok["token"], "signature": tok["signature"], "escrow": tok["escrow"], "scheme": SCHEME,
        "alleles": [1] * synth.N_LOCI, "meta": {"species": SPECIES, "month": "2026-10", "region": "IT", "category": "*"},
        "pk_alert": alerts.new_keypair()[1].hex()}
print("token used once            :", platform.post("/submit", json=body).status_code)
print("same token again           :", detail(platform.post("/submit", json=body)))
print("forged token               :", detail(platform.post("/submit", json={**body, "token": secrets.token_bytes(64).hex()})))
other = bs.SecretKey.generate(2048)
m = bs.prepare(b"x" * 32)
bl, inv = bs.blind(other.public_key, m)
print("token signed by another key:", detail(platform.post("/submit", json={
    **body, "token": m.hex(), "signature": bs.finalize(other.public_key, m, bs.blind_sign(other, bl), inv).hex()})))
t1, t2 = wallets[cid].tokens[1], wallets[cid].tokens[2]
print("escrow of another token    :", detail(platform.post("/submit", json={
    **body, "token": t1["token"], "signature": t1["signature"], "escrow": t2["escrow"]})))
print("exact date in metadata     :", detail(platform.post("/submit", json={
    **body, "token": t1["token"], "signature": t1["signature"], "escrow": t1["escrow"],
    "meta": {"species": SPECIES, "month": "2026-10-14", "region": "ITF1", "category": "dairy"}})))
for label, fn in [
        ("not a food business      ", lambda: client.enrol(client.Wallet(), W.issuer, W.platform, W.anchors,
                                                           client.login(W.idp, world.CLIENT_ID, "notafbo", "pw-notafbo"), 1, "X")),
        ("forged ID token          ", lambda: client.enrol(client.Wallet(), W.issuer, W.platform, W.anchors,
                                                           W.login(cid)[:-6] + "AAAAAA", 1, cid)),
        ("over quota               ", lambda: W.enrol(wallets[cid], cid, n=45))]:
    try:
        fn()
    except client.ClientError as e:
        print(label, ":", e)
print("lab endpoint via the relay :", detail(platform.get("/records")))

# ---------------------------------------------------------------- 4. surveillance
title("4. Public health clusters records with human cases and sends private alerts")
sent, _ = lab.run(W.platform, world.LAB_KEY, clinical)
print(f"{len(sent)} alerts posted on a bulletin of {len(W.platform.get('/bulletin').json())} entries")
got = {cid: bool(client.check(wallets[cid], platform)) for cid in companies}
tp = sum(got[c] and truth[c] for c in companies)
fp = sum(got[c] and not truth[c] for c in companies)
fn = sum(truth[c] and not got[c] for c in companies)
print(f"Companies whose isolate is in an outbreak clone: {sum(truth.values())}; "
      f"alerted: {tp} correct, {fp} wrong, {fn} missed")
example = next(c for c in companies if got[c])
print(f"What {example} reads:", client.check(wallets[example], platform)[0]["text"])

# ---------------------------------------------------------------- 5. log
title("5. Merkle log, cosigned by the consortium")
cp = W.checkpoint()
print(f"Checkpoint: {cp['sth']['size']} entries, root {cp['sth']['root'][:16]}..., cosigned by "
      f"{sorted(cp['sth']['cosigs'])}; refusals {cp['refusals']}")
n = sum(client.verify_receipts(wallets[c], platform, W.anchors) for c in companies)
print(f"Companies check their {n} receipts: each record is in the cosigned tree (inclusion proofs)")
proof = W.platform.get("/log/proof/inclusion", params={"index": 5, "size": cp["sth"]["size"]}).json()["proof"]
print(f"An inclusion proof is {len(proof)} hashes ({len(proof) * 32} bytes) for a log of {cp['sth']['size']} entries")
st = W.platform_state
st.log.db.execute("UPDATE log SET body = replace(body, '2026-10', '2026-09') WHERE idx = 5")
st.log.tree = tlog.MerkleTree([tlog.leaf_hash(tlog.entry_bytes(e)) for e in st.log.entries()])
st.log.append("record", {"id": "after-the-rewrite"})
cp = W.checkpoint()
print("The operator silently rewrites entry 5 and asks for a new checkpoint:")
for name, why in cp["refusals"].items():
    print(f"  {name} refuses: {why}")
try:
    client.accepted_sth(W.platform, W.anchors)
except client.ClientError as e:
    print("  and every client rejects the new head:", e)

# ---------------------------------------------------------------- 6. disclosure
title("6. Accountable disclosure: 3 of 5 trustees, only for a request in the log")
W2 = world.build(seed=43, k=K)               # a fresh deployment (the log above is now forked)
p2 = W2.oblivious_platform()
w = client.Wallet()
W2.enrol(w, "FBO0100", n=1)
c = W2.register["FBO0100"]
rid = client.submit(w, p2, W2.stats, K, SCHEME, synth.clone(rng),
                    {"species": SPECIES, "month": "2026-10", "region": c.region, "category": c.category})["record_id"]
W2.checkpoint()
try:
    W2.trustees[0].release(W2.platform, rid)
except client.ClientError as e:
    print("Before any request:", e)
req = W2.platform.post("/disclosure", json={"record_id": rid, "reason": "ST-1247 outbreak, 9 cases; alert unanswered for 14 days"},
                       headers={"x-lab-key": world.LAB_KEY}).json()
W2.checkpoint()
print(f"Authority's request written at log index {req['index']} and cosigned")
W2.trustees[3].approve = lambda r: False
blob = bytes.fromhex(W2.platform.get(f"/escrow/{rid}").json()["escrow"])
shares = []
for tr in W2.trustees:
    try:
        shares.append(tr.release(W2.platform, rid))
        print(f"  {tr.name} releases its share")
    except client.ClientError as e:
        print(f"  {e}")
try:
    escrow.reveal(blob, shares[:2])
except ValueError as e:
    print("With 2 shares:", e)
print(f"With {len(shares)} shares the authority reads: {escrow.reveal(blob, shares)} "
      f"(true submitter: FBO0100)")
