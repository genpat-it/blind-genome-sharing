# SPDX-License-Identifier: EUPL-1.2
"""Oblivious HTTP: the complete example of RFC 9458 Appendix A, and Binary HTTP round trips."""
from pyhpke import AEADId, KDFId

from anonsurv import ohttp

X = bytes.fromhex
GW_SK = X("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")
KEY_CONFIG = X("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003")
BHTTP_REQ = X("00034745540568747470730b6578616d706c652e636f6d012f")
EPH_SK = X("bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73")
ENC_REQ = X("010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e"
            "1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525")
BHTTP_RES = X("0140c8")
RES_NONCE = X("c789e7151fcba46158ca84b04464910d")
ENC_RES = X("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")


def test_rfc9458_appendix_a():
    gw = ohttp.Gateway(GW_SK, key_id=1, suites=((KDFId.HKDF_SHA256, AEADId.AES128_GCM),
                                                 (KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)))
    assert gw.config.encode() == KEY_CONFIG
    assert ohttp.encode_request("GET", "https", "example.com", "/") == BHTTP_REQ
    cfg = ohttp.KeyConfig.decode(KEY_CONFIG)
    eks = ohttp._suite(KDFId.HKDF_SHA256, AEADId.AES128_GCM).kem.deserialize_private_key(EPH_SK)
    from pyhpke import KEMKeyPair
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub = X25519PrivateKey.from_private_bytes(EPH_SK).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kem = ohttp._suite(KDFId.HKDF_SHA256, AEADId.AES128_GCM).kem
    enc_req, pending = ohttp.encapsulate_request(cfg, BHTTP_REQ, eks=KEMKeyPair(eks, kem.deserialize_public_key(pub)))
    assert enc_req == ENC_REQ
    req, gw_pending = gw.decapsulate_request(ENC_REQ)
    assert req == BHTTP_REQ
    assert gw.encapsulate_response(gw_pending, BHTTP_RES, nonce=RES_NONCE) == ENC_RES
    assert ohttp.decapsulate_response(pending, ENC_RES) == BHTTP_RES
    assert ohttp.decode_response(BHTTP_RES) == {"status": 200, "headers": [], "body": b""}


def test_bhttp_round_trip_and_chacha():
    body = b'{"x": 1}' * 100
    b = ohttp.encode_request("POST", "https", "platform.example", "/submit?x=1",
                             [("Content-Type", "application/json")], body)
    d = ohttp.decode_request(b)
    assert (d["method"], d["path"], d["headers"], d["body"]) == ("POST", "/submit?x=1",
                                                                [("content-type", "application/json")], body)
    gw = ohttp.Gateway(suites=((KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305),))
    cfg = ohttp.decode_key_list(gw.keys())[0]
    enc, p = ohttp.encapsulate_request(cfg, b)
    got, gp = gw.decapsulate_request(enc)
    assert got == b
    res = ohttp.encode_response(409, [("content-type", "application/json")], b'{"detail":"used"}')
    assert ohttp.decode_response(ohttp.decapsulate_response(p, gw.encapsulate_response(gp, res)))["status"] == 409
