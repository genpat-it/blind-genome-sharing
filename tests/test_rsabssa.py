# SPDX-License-Identifier: EUPL-1.2
import json
from pathlib import Path

import pytest

from anonsurv import rsabssa as bs

VECTORS = json.loads((Path(__file__).parent / "rfc9474_vectors.json").read_text())


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_rfc9474_vector(v):
    h = bytes.fromhex
    n, e, d = int(v["n"], 16), int(v["e"], 16), int(v["d"], 16)
    pk, sk = bs.PublicKey(n, e), bs.SecretKey(n, e, d)
    randomized = "Randomized" in v["name"]
    salt = h(v["salt"]) if "salt" in v else b""

    prepared = bs.prepare(h(v["msg"]), randomized, prefix=h(v["msg_prefix"]) if randomized else None)
    assert prepared.hex() == v["prepared_msg"]
    assert bs.emsa_pss_encode(prepared, n.bit_length() - 1, salt).hex() == v["encoded_msg"]

    inv = int(v["inv"], 16)
    blinded, inv2 = bs.blind(pk, prepared, len(salt), salt=salt, r=pow(inv, -1, n))
    assert inv2 == inv
    assert blinded.hex() == v["blinded_msg"]

    blind_sig = bs.blind_sign(sk, blinded)
    assert blind_sig.hex() == v["blind_sig"]

    sig = bs.finalize(pk, prepared, blind_sig, inv, len(salt))
    assert sig.hex() == v["sig"]
    assert bs.verify(pk, prepared, sig, len(salt))


def test_roundtrip_and_rejections():
    sk = bs.SecretKey.generate(2048)
    pk = sk.public_key
    msg = bs.prepare(b"token nonce")
    blinded, inv = bs.blind(pk, msg)
    sig = bs.finalize(pk, msg, bs.blind_sign(sk, blinded), inv)
    assert bs.verify(pk, msg, sig)
    assert not bs.verify(pk, msg + b"x", sig)                      # other message
    other = bs.SecretKey.generate(2048).public_key
    assert not bs.verify(other, msg, sig)                          # other issuer key
    assert blinded != msg and sig not in blinded                   # issuer never sees msg or sig
    assert bs.PublicKey.from_pem(pk.to_pem()) == pk
    assert bs.SecretKey.from_pem(sk.to_pem()) == sk
