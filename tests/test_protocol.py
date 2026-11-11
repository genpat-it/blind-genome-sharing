# SPDX-License-Identifier: EUPL-1.2
import random

import pytest

from anonsurv import alerts, client, escrow, lab, policy, synth, tlog, world

SP = "Listeria monocytogenes"


@pytest.fixture(scope="module")
def W():
    return world.build(seed=1, quota=12)


def meta(c):
    return {"species": SP, "month": "2026-10", "region": c.region, "category": c.category}


def test_full_flow_through_relay(W):
    rng = random.Random(1)
    P = W.oblivious_platform()
    base = synth.clone(rng)
    a, b = W.register["FBO0001"], W.register["FBO0002"]
    wa, wb = client.Wallet(), client.Wallet()
    W.enrol(wa, a.company_id, 2)
    W.enrol(wb, b.company_id, 2)
    client.submit(wa, P, W.stats, 5, "s", synth.variant(rng, base, 2), meta(a))
    client.submit(wb, P, W.stats, 5, "s", synth.clone(rng), meta(b))
    sent, _ = lab.run(W.platform, world.LAB_KEY, [{"id": "h1", "species": SP, "alleles": synth.variant(rng, base, 1)}])
    assert len(sent) == 1
    assert len(client.check(wa, P)) == 1 and client.check(wb, P) == []
    # records and log carry no company identifier, name or VAT number
    blob = str(W.platform.get("/records", headers={"x-lab-key": world.LAB_KEY}).json()) + \
        str(W.platform.get("/log/entries").json())
    for s in (a.company_id, a.name, a.vat):
        assert s not in blob
    W.checkpoint()
    assert client.verify_receipts(wa, P, W.anchors) == 1


def test_refusals(W):
    c = W.register["FBO0003"]
    w = client.Wallet()
    W.enrol(w, c.company_id, 12)
    with pytest.raises(client.ClientError, match="429"):
        W.enrol(w, c.company_id, 1)
    with pytest.raises(client.ClientError, match="401"):
        client.enrol(w, W.issuer, W.platform, W.anchors, "not-a-jwt", 1, c.company_id)
    with pytest.raises(client.ClientError, match="403"):
        client.enrol(w, W.issuer, W.platform, W.anchors,
                     client.login(W.idp, world.CLIENT_ID, "notafbo", "pw-notafbo"), 1, "X")
    tok = w.tokens[0]
    body = {"token": tok["token"], "signature": tok["signature"], "escrow": tok["escrow"], "scheme": "s",
            "alleles": [1], "meta": meta(c) | {"region": "IT", "category": "*"}, "pk_alert": alerts.new_keypair()[1].hex()}
    assert W.platform.post("/submit", json=body).status_code == 200
    assert W.platform.post("/submit", json=body).status_code == 409
    assert W.platform.post("/submit", json=body | {"token": "ab" * 64}).status_code == 403
    t1, t2 = w.tokens[1], w.tokens[2]
    body |= {"token": t1["token"], "signature": t1["signature"]}
    assert W.platform.post("/submit", json=body | {"escrow": t2["escrow"]}).status_code == 403
    assert W.platform.post("/submit", json=body | {"escrow": None}).status_code == 403
    assert W.platform.post("/submit", json=body | {"escrow": t1["escrow"],
                                                   "meta": meta(c) | {"month": "2026-10-14"}}).status_code == 422


def test_cut_and_choose_catches_wrong_identifier(W):
    from anonsurv import rsabssa as bs
    cid = "FBO0010"
    pk = bs.PublicKey.from_pem(W.issuer.get("/key").json()["pem"].encode())
    cfg = W.issuer_state.escrow_cfg
    cands = [escrow.make_candidate(pk, "FBO0011", cfg) for _ in range(cfg.k)]   # every candidate is wrong
    auth = {"authorization": f"Bearer {W.login(cid)}"}
    r = W.issuer.post("/issue/commit", json={"candidates": [[c.blinded.hex() for c in cands]]}, headers=auth).json()
    opened = {str(j): c.opening() for j, c in enumerate(cands) if j != r["keep"][0]}
    assert W.issuer.post("/issue/open", json={"session": r["session"], "openings": [opened]}, headers=auth).status_code == 400
    with pytest.raises(client.ClientError, match="suspended"):
        W.enrol(client.Wallet(), cid, 1)
    # not opening every other candidate is refused too
    cid = "FBO0012"
    auth = {"authorization": f"Bearer {W.login(cid)}"}
    cands = [escrow.make_candidate(pk, cid, cfg) for _ in range(cfg.k)]
    r = W.issuer.post("/issue/commit", json={"candidates": [[c.blinded.hex() for c in cands]]}, headers=auth).json()
    assert W.issuer.post("/issue/open", json={"session": r["session"], "openings": [{}]}, headers=auth).status_code == 400


def test_disclosure_needs_log_entry_and_t_trustees(W):
    c = W.register["FBO0020"]
    w = client.Wallet()
    W.enrol(w, c.company_id, 1)
    rid = client.submit(w, W.platform, W.stats, 5, "s", [1, 2, 3], meta(c))["record_id"]
    W.checkpoint()
    with pytest.raises(client.ClientError, match="no disclosure request"):
        W.trustees[0].release(W.platform, rid)
    W.platform.post("/disclosure", json={"record_id": rid, "reason": "test"}, headers={"x-lab-key": world.LAB_KEY})
    W.checkpoint()
    shares = [tr.release(W.platform, rid) for tr in W.trustees[1:4]]
    blob = bytes.fromhex(W.platform.get(f"/escrow/{rid}").json()["escrow"])
    assert escrow.reveal(blob, shares) == c.company_id
    with pytest.raises(ValueError):
        escrow.reveal(blob, shares[:2])


def test_client_rejects_head_without_quorum(W):
    sth = W.platform.get("/log/sth").json()
    assert tlog.accept_sth(sth, W.anchors.log_pub, W.anchors.witnesses, 2)
    one = {**sth, "cosigs": dict(list(sth["cosigs"].items())[:1])}
    assert not tlog.accept_sth(one, W.anchors.log_pub, W.anchors.witnesses, 2)
    forged = {**sth, "root": "00" * 32}
    assert not tlog.accept_sth(forged, W.anchors.log_pub, W.anchors.witnesses, 2)


def test_gateway_keys_must_match_log(W):
    with pytest.raises(client.ClientError, match="gateway keys"):
        client.ohttp_keys(W.gateway.get("/ohttp-keys").content + b"x", W.platform, W.anchors)


def test_without_escrow():
    W = world.build(seed=2, use_escrow=False)
    c = W.register["FBO0001"]
    w = client.Wallet()
    W.enrol(w, c.company_id, 3)
    assert w.tokens[0]["escrow"] is None
    assert client.submit(w, W.oblivious_platform(), W.stats, 5, "s", [1], meta(c))["record_id"]


def test_generalisation():
    stats = {"ITF1|dairy": 3, "ITF2|dairy": 3, "ITF2|fish": 1, "ITC4|meat": 40}
    m = {"species": SP, "month": "2026-10", "region": "ITF1", "category": "dairy"}
    assert policy.generalise(m, stats, 3)["region"] == "ITF1"
    assert policy.generalise(m, stats, 5)["region"] == "ITF"
    g = policy.generalise(m | {"category": "fish", "region": "ITF2"}, stats, 7)
    assert (g["region"], g["category"]) == ("ITF", "*")
    assert policy.generalise(m, stats, 1000) is None


def test_alert_only_opens_with_own_key():
    sk1, pk1 = alerts.new_keypair()
    sk2, _ = alerts.new_keypair()
    enc, ct = alerts.seal(pk1, b"hi")
    assert alerts.try_open(sk1, enc, ct) == b"hi" and alerts.try_open(sk2, enc, ct) is None


def test_shamir_any_t_shares():
    import itertools
    shares = escrow.split(123456789, 3, 5, [11, 22])
    for sub in itertools.combinations(shares, 3):
        assert escrow.combine(list(sub)) == 123456789
    assert escrow.combine(shares[:2]) != 123456789


def test_low_order_alert_key_refused(W):
    c = W.register["FBO0030"]
    w = client.Wallet()
    W.enrol(w, c.company_id, 1)
    tok = w.tokens[0]
    r = W.platform.post("/submit", json={"token": tok["token"], "signature": tok["signature"], "escrow": tok["escrow"],
                                         "scheme": "s", "alleles": [1], "pk_alert": "00" * 32, "meta": meta(c)})
    assert r.status_code == 400
