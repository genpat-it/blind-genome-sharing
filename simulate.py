# SPDX-License-Identifier: EUPL-1.2
"""Run a small, narrated scenario on the real services and record every message for the office
animation (docs/office.html).

    .venv/bin/python simulate.py              # writes docs/sim/trace.json
    .venv/bin/python simulate.py --serve      # ... and opens the office at http://localhost:8765/office.html

Nothing in the trace is scripted by hand except the chapter titles and what the characters say:
every envelope in the animation is an HTTP request that really happened, with its real size and
answer.
"""
from __future__ import annotations

import argparse
import json
import random
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message=".*httpx2.*")

from anonsurv import alerts, client, escrow, lab, synth, tlog, world  # noqa: E402
from anonsurv import rsabssa as bs  # noqa: E402

SP, SCHEME, K = "Listeria monocytogenes", "Lm_cgMLST_Pasteur_1748", 5
OUT = Path(__file__).parent / "docs" / "sim" / "trace.json"


def main(seed: int = 11) -> Path:
    rng = random.Random(seed)
    tr = world.Tracer()
    say = lambda who, text: tr.note("say", who=who, text=text)                     # noqa: E731
    chapter = lambda title, text: tr.note("chapter", title=title, text=text)       # noqa: E731
    chapter("The consortium opens the log",
            "The platform writes its configuration as entry 0 of the log: issuer key, escrow trustees, gateway keys. "
            "The three consortium members cosign it. From now on nobody can change it unnoticed.")

    W = world.build(seed=seed, k=K, n_witnesses=3, quorum=2, n_trustees=3, t=2, tracer=tr)
    say("platform", "Entry 0 written and cosigned by all three members")

    # the cast: six companies, two of which handle the outbreak strain
    picks = {"dairy": "ITF1", "meat": "ITF1", "fish": "ITF3", "ready-to-eat": "ITI4", "produce": "ITC4"}
    cast = [next(c for c in W.register.values() if c.category == cat and c.region == reg) for cat, reg in picks.items()]
    cast.append(next(c for c in W.register.values() if c.category == "dairy" and c.region == "ITH3"))
    ids = [c.company_id for c in cast]
    outbreak = synth.clone(rng)
    positive = {ids[0], ids[3]}

    chapter("Companies log in and get tokens",
            "Each company logs in with its digital identity, then asks the issuer for tokens. It sends 8 sealed "
            "candidates per token; the issuer opens 7 to check that the escrow inside names this company, and "
            "signs the 8th without seeing it.")
    wallets = {}
    for cid in ids:
        with tr.acting(cid):
            say(cid, "Logging in, then asking for 2 tokens")
            wallets[cid] = client.Wallet()
            W.enrol(wallets[cid], cid, 2)
    say("issuer", f"I know: {', '.join(f'{c} got 2' for c in ids[:2])}, ... nothing else")

    chapter("A company tries to cheat",
            "One company hides another company's identifier inside its candidates. When the issuer opens them, "
            "the identifiers do not match: issuance is refused and the company is suspended.")
    cheat = next(c for c in W.register if c not in ids)
    with tr.acting(cheat):
        say(cheat, f"I'll put {ids[1]}'s name in my escrow...")
        pk = bs.PublicKey.from_pem(W.issuer.get("/key").json()["pem"].encode())
        cfg = W.issuer_state.escrow_cfg
        cands = [escrow.make_candidate(pk, ids[1], cfg) for _ in range(cfg.k)]
        auth = {"authorization": f"Bearer {W.login(cheat)}"}
        r = W.issuer.post("/issue/commit", json={"candidates": [[c.blinded.hex() for c in cands]]}, headers=auth).json()
        W.issuer.post("/issue/open", json={"session": r["session"], "openings": [
            {str(j): c.opening() for j, c in enumerate(cands) if j != r["keep"][0]}]}, headers=auth)
    say("issuer", f"The opened candidates name someone else: {cheat} suspended")

    chapter("Anonymous submissions",
            "Each company sends its isolate's cgMLST profile with coarse metadata and a token. It goes through "
            "the relay: the relay sees who is sending but only ciphertext; the gateway decrypts but sees only the "
            "relay. The platform checks the token signature and that it was never used before.")
    P = None
    for cid in ids:
        with tr.acting(cid):
            P = P or W.oblivious_platform()
            c = W.register[cid]
            prof = synth.variant(rng, outbreak, rng.randint(1, 4)) if cid in positive else synth.clone(rng)
            out = client.submit(wallets[cid], P, W.stats, K, SCHEME, prof,
                                {"species": SP, "month": "2026-10", "region": c.region, "category": c.category})
            m = out["meta_sent"]
            say(cid, f"Sent as '{m['region']}, {m['category']}'" + (" (generalised)" if m["region"] != c.region else ""))
    with tr.acting(ids[1]):
        tok = wallets[ids[1]].tokens[0]
        body = {"token": tok["token"], "signature": tok["signature"], "escrow": tok["escrow"], "scheme": SCHEME,
                "alleles": [1], "pk_alert": alerts.new_keypair()[1].hex(),
                "meta": {"species": SP, "month": "2026-10", "region": "IT", "category": "*"}}
        P.post("/submit", json=body)
        say(ids[1], "Let me use this token twice...")
        P.post("/submit", json=body)
    say("platform", "Token already used: refused")

    chapter("The laboratory finds a cluster",
            "The national reference laboratory compares every new profile with human cases. Two records are "
            "within 7 alleles of the outbreak strain: it posts an alert for each, encrypted to the one-time key "
            "that came with the record, on the public bulletin.")
    clinical = [{"id": f"HUM-{j}", "species": SP, "alleles": synth.variant(rng, outbreak, rng.randint(0, 3))} for j in range(4)]
    with tr.acting("lab"):
        sent, _ = lab.run(W.platform, world.LAB_KEY, clinical)
    say("lab", f"{len(sent)} records cluster with 4 human cases: {len(sent)} sealed alerts posted")

    chapter("Every company reads the whole bulletin",
            "All companies download all alerts and try to open them with their own keys. Only the right company "
            "succeeds; downloading everything reveals nothing about who was waiting for what.")
    for cid in ids:
        with tr.acting(cid):
            got = client.check(wallets[cid], P)
            say(cid, "An alert for me! Calling the authority, checking my plant" if got else "Nothing for me")

    chapter("The consortium cosigns the log",
            "The platform signs the new tree head. Each member checks it extends the head it signed last time, and "
            "cosigns. Companies check that their records are in the cosigned tree.")
    with tr.acting("operator"):
        W.checkpoint()
    for cid in ids[:3]:
        with tr.acting(cid):
            n = client.verify_receipts(wallets[cid], P, W.anchors)
            say(cid, f"My record is in the cosigned log ({n} inclusion proof checked)")

    chapter("Disclosure, only in the open",
            f"{ids[3]} does not react to its alert. The authority asks to know who submitted that record. The "
            "request goes in the log first; each member checks it there, and decides. Two of three are enough.")
    rid = wallets[ids[3]].alert_keys[0]["record_id"]
    with tr.acting("lab"):
        say("lab", "Alert unanswered for 14 days, 4 human cases: requesting disclosure")
        W.platform.post("/disclosure", json={"record_id": rid, "reason": "alert unanswered, 4 cases"},
                        headers={"x-lab-key": world.LAB_KEY})
    with tr.acting("operator"):
        W.checkpoint()
    W.trustees[1].approve = lambda req: False
    shares = []
    for t in W.trustees:
        with tr.acting(t.name):
            try:
                shares.append(t.release(W.platform, rid))
                say(t.name, "Request is in the cosigned log, reason accepted: here is my share")
            except client.ClientError:
                say(t.name, "I am not convinced: no share from me")
    with tr.acting("lab"):
        blob = bytes.fromhex(W.platform.get(f"/escrow/{rid}").json()["escrow"])
    say("lab", f"2 shares: record {rid[:6]}... was sent by {escrow.reveal(blob, shares)}")

    chapter("The operator tries to rewrite history",
            "The platform operator edits an old record in its database and asks for a new cosignature. The tree "
            "no longer extends the one the members signed: all three refuse, and clients reject the new head.")
    st = W.platform_state
    st.log.db.execute("UPDATE log SET body = replace(body, '2026-10', '2026-09') WHERE idx = 3")
    st.log.tree = tlog.MerkleTree([tlog.leaf_hash(tlog.entry_bytes(e)) for e in st.log.entries()])
    say("platform", "Nobody will notice if I change entry 3...")
    with tr.acting("operator"):
        cp = W.checkpoint()
    for name in cp["refusals"]:
        say(name, "This head does not extend the one I signed: refused")

    cast_info = {cid: {"region": W.register[cid].region, "category": W.register[cid].category,
                       "positive": cid in positive} for cid in ids}
    cast_info[cheat] = {"region": W.register[cheat].region, "category": W.register[cheat].category, "cheater": True}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"companies": cast_info, "members": [t.name for t in W.trustees],
                               "events": tr.events}, indent=0))
    n_http = sum(e["kind"] == "http" for e in tr.events)
    print(f"{n_http} HTTP exchanges, {sum(e['kind'] == 'say' for e in tr.events)} lines of dialogue -> {OUT}")
    return OUT


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    main(a.seed)
    if a.serve:
        import functools
        import http.server
        import webbrowser
        h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(OUT.parents[1]))
        print("Office at http://localhost:8765/office.html (Ctrl-C to stop)")
        webbrowser.open("http://localhost:8765/office.html")
        http.server.ThreadingHTTPServer(("127.0.0.1", 8765), h).serve_forever()
