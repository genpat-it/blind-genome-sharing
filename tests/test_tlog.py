# SPDX-License-Identifier: EUPL-1.2
"""Merkle log: RFC 9162 proofs against the transparency-dev probes, and witness behaviour."""
import json
import sqlite3
from pathlib import Path

import pytest

from anonsurv import tlog

PROBES = json.loads((Path(__file__).parent / "merkle_probes.json").read_text())
LEAVES = [bytes.fromhex(x) for x in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                                     "606162636465666768696a6b6c6d6e6f"]]
ROOT8 = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
h = lambda x: bytes.fromhex(x) if x is not None else b""


def test_root_matches_reference():
    t = tlog.MerkleTree([tlog.leaf_hash(x) for x in LEAVES])
    assert t.root().hex() == ROOT8
    assert t.root(0) == tlog.EMPTY_ROOT


@pytest.mark.parametrize("p", PROBES["inclusion"])
def test_inclusion_probe(p):
    ok = tlog.verify_inclusion(p["index"], p["size"], h(p["leaf"]), [h(x) for x in p["proof"]], h(p["root"]))
    assert ok != p["err"]


@pytest.mark.parametrize("p", PROBES["consistency"])
def test_consistency_probe(p):
    ok = tlog.verify_consistency(p["size1"], p["size2"], h(p["root1"]), h(p["root2"]), [h(x) for x in p["proof"]])
    assert ok != p["err"]


def test_generated_proofs_verify_for_all_sizes():
    t = tlog.MerkleTree([tlog.leaf_hash(bytes([i])) for i in range(40)])
    for n in range(1, 41):
        for m in range(n):
            assert tlog.verify_inclusion(m, n, t.leaves[m], t.inclusion_proof(m, n), t.root(n))
        for m in range(1, n + 1):
            assert tlog.verify_consistency(m, n, t.root(m), t.root(n), t.consistency_proof(m, n))


def test_witness_refuses_rewritten_log(tmp_path):
    db = str(tmp_path / "log.db")
    log = tlog.TransparencyLog(db)
    w = tlog.Witness("member-1", log.pub)
    for i in range(5):
        log.append("record", {"i": i})
    sth = log.sth()
    w.cosign(sth, log.consistency(0, sth["size"]))
    copy = str(tmp_path / "copy.db")
    log.db.backup(sqlite3.connect(copy))
    con = sqlite3.connect(copy)
    con.execute("UPDATE log SET body = ? WHERE idx = 2", (json.dumps({"i": 99}),))
    con.commit()
    forged = tlog.TransparencyLog(copy, sk=log.sk)     # operator rebuilds the tree from the edited table
    forged.append("record", {"i": 5})
    new = forged.sth()
    with pytest.raises(ValueError, match="rewritten"):
        w.cosign(new, forged.consistency(sth["size"], new["size"]))
    # the honest continuation is accepted
    log.append("record", {"i": 5})
    good = log.sth()
    sig = w.cosign(good, log.consistency(sth["size"], good["size"]))
    assert tlog.accept_sth({**good, "cosigs": {"member-1": sig}}, log.pub, {"member-1": w.pub}, 1)
