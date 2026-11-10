# SPDX-License-Identifier: EUPL-1.2
import random

import pytest
from fastapi.testclient import TestClient

from anonsurv import alerts, client, lab, policy, synth
from anonsurv import rsabssa as bs
from anonsurv.issuer import IssuerState, create_app as issuer_app, register_stats
from anonsurv.platform import PlatformState, create_app as platform_app
from anonsurv.tlog import verify_chain

SP = "Listeria monocytogenes"


@pytest.fixture(scope="module")
def net():
    rng = random.Random(1)
    reg = synth.register(rng)
    stats = register_stats(reg)
    sk = bs.SecretKey.generate(2048)
    ist, pst = IssuerState(sk, reg, quota=5), PlatformState(sk.public_key, stats, 5, "lab")
    return rng, reg, stats, ist, pst, TestClient(issuer_app(ist)), TestClient(platform_app(pst))


def meta(c):
    return {"species": SP, "month": "2026-10", "region": c.region, "category": c.category}


def test_full_flow(net):
    rng, reg, stats, ist, pst, issuer, platform = net
    base = synth.clone(rng)
    a, b = reg["FBO0001"], reg["FBO0002"]
    wa, wb = client.Wallet(), client.Wallet()
    client.enrol(wa, issuer, platform, a.company_id, a.api_key, 2)
    client.enrol(wb, issuer, platform, b.company_id, b.api_key, 2)
    client.submit(wa, platform, stats, 5, "s", synth.variant(rng, base, 2), meta(a))
    client.submit(wb, platform, stats, 5, "s", synth.clone(rng), meta(b))
    sent, _ = lab.run(platform, "lab", [{"id": "h1", "species": SP, "alleles": synth.variant(rng, base, 1)}])
    assert len(sent) == 1
    assert len(client.check(wa, platform)) == 1 and client.check(wb, platform) == []
    # records and log carry no company identifier
    blob = str(platform.get("/records", headers={"x-lab-key": "lab"}).json()) + str(platform.get("/log").json())
    assert a.company_id not in blob and a.name not in blob
    assert verify_chain(platform.get("/log").json(), platform.get("/log/head").json())


def test_refusals(net):
    rng, reg, stats, ist, pst, issuer, platform = net
    c = reg["FBO0003"]
    w = client.Wallet()
    client.enrol(w, issuer, platform, c.company_id, c.api_key, 5)
    with pytest.raises(client.ClientError, match="429"):
        client.enrol(w, issuer, platform, c.company_id, c.api_key, 1)
    with pytest.raises(client.ClientError, match="403"):
        client.enrol(w, issuer, platform, c.company_id, "wrong", 1)
    tok = w.tokens[0]
    body = {"token": tok["token"], "signature": tok["signature"], "scheme": "s", "alleles": [1],
            "meta": meta(c) | {"region": "IT", "category": "*"}, "pk_alert": "00" * 32}
    assert platform.post("/submit", json=body).status_code == 200
    assert platform.post("/submit", json=body).status_code == 409
    assert platform.post("/submit", json=body | {"token": "ab" * 64}).status_code == 403
    tok = w.tokens[1]
    body |= {"token": tok["token"], "signature": tok["signature"]}
    assert platform.post("/submit", json=body | {"meta": meta(c) | {"month": "2026-10-14"}}).status_code == 422


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
