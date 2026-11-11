# SPDX-License-Identifier: EUPL-1.2
"""Oblivious HTTP (RFC 9458) with Binary HTTP messages (RFC 9292, known-length form).

Submissions travel  company -> relay -> gateway -> platform.  The relay (run by someone other
than the platform: a consortium member, a trade association, a research network) sees the
company's IP address but only ciphertext; the gateway, run with the platform, decrypts the request
but sees only the relay's address. Neither alone can link a submission to a network origin.

`OhttpTransport` plugs into httpx, so the company client code does not change: it is built with
`httpx.Client(transport=OhttpTransport(...), base_url=...)`. Checked against the example in
RFC 9458 Appendix A.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

REQ_LABEL, RES_LABEL = b"message/bhttp request", b"message/bhttp response"
REQ_TYPE, RES_TYPE, KEYS_TYPE = "message/ohttp-req", "message/ohttp-res", "application/ohttp-keys"
KEM = KEMId.DHKEM_X25519_HKDF_SHA256.value
HKDF_SHA256 = KDFId.HKDF_SHA256.value
AEADS = {AEADId.AES128_GCM.value: (16, 12, AESGCM), AEADId.CHACHA20_POLY1305.value: (32, 12, ChaCha20Poly1305)}
N_ENC = 32


class OhttpError(Exception):
    pass


# ---------------------------------------------------------------- QUIC variable-length integers

def put_varint(v: int) -> bytes:
    if v < 1 << 6:
        return bytes([v])
    if v < 1 << 14:
        return struct.pack(">H", v | 0x4000)
    if v < 1 << 30:
        return struct.pack(">I", v | 0x80000000)
    return struct.pack(">Q", v | 0xC000000000000000)


class Reader:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def done(self) -> bool:
        return self.i >= len(self.b)

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise OhttpError("truncated message")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def varint(self) -> int:
        first = self.take(1)[0]
        n = 1 << (first >> 6)
        v = first & 0x3F
        for c in self.take(n - 1):
            v = (v << 8) | c
        return v

    def vbytes(self) -> bytes:
        return self.take(self.varint())


# ---------------------------------------------------------------- Binary HTTP, known-length

def _fields(headers: list[tuple[str, str]]) -> bytes:
    body = b"".join(put_varint(len(k)) + k + put_varint(len(v)) + v
                    for k, v in ((k.lower().encode(), v.encode()) for k, v in headers))
    return put_varint(len(body)) + body


def _read_fields(r: Reader) -> list[tuple[str, str]]:
    if r.done():                       # truncated: empty section (RFC 9292 section 3.8)
        return []
    sub, out = Reader(r.vbytes()), []
    while not sub.done():
        out.append((sub.vbytes().decode(), sub.vbytes().decode()))
    return out


def encode_request(method: str, scheme: str, authority: str, path: str,
                   headers: list[tuple[str, str]] = (), body: bytes = b"") -> bytes:
    out = put_varint(0) + b"".join(put_varint(len(x)) + x for x in
                                   (method.encode(), scheme.encode(), authority.encode(), path.encode()))
    if headers or body:               # trailing empty sections may be truncated (RFC 9292 section 3.8)
        out += _fields(list(headers))
    if body:
        out += put_varint(len(body)) + body + put_varint(0)
    return out


def decode_request(b: bytes) -> dict:
    r = Reader(b)
    if r.varint() != 0:
        raise OhttpError("not a known-length request")
    method, scheme, authority, path = (r.vbytes().decode() for _ in range(4))
    headers = _read_fields(r)
    body = b"" if r.done() else r.vbytes()
    return {"method": method, "scheme": scheme, "authority": authority, "path": path,
            "headers": headers, "body": body}


def encode_response(status: int, headers: list[tuple[str, str]] = (), body: bytes = b"") -> bytes:
    out = put_varint(1) + put_varint(status)
    if headers or body:
        out += _fields(list(headers))
    if body:
        out += put_varint(len(body)) + body + put_varint(0)
    return out


def decode_response(b: bytes) -> dict:
    r = Reader(b)
    if r.varint() != 1:
        raise OhttpError("not a known-length response")
    while True:
        status = r.varint()
        headers = _read_fields(r)
        if status >= 200:
            break                       # 1xx informational responses are skipped
    body = b"" if r.done() else r.vbytes()
    return {"status": status, "headers": headers, "body": body}


# ---------------------------------------------------------------- key configuration (RFC 9458 section 3)

@dataclass
class KeyConfig:
    key_id: int
    public_key: bytes
    suites: list[tuple[int, int]]      # (kdf_id, aead_id)

    def encode(self) -> bytes:
        algs = b"".join(struct.pack(">HH", k, a) for k, a in self.suites)
        return struct.pack(">BH", self.key_id, KEM) + self.public_key + struct.pack(">H", len(algs)) + algs

    @classmethod
    def decode(cls, b: bytes) -> "KeyConfig":
        key_id, kem = struct.unpack(">BH", b[:3])
        if kem != KEM:
            raise OhttpError("unsupported KEM")
        pk = b[3:3 + N_ENC]
        (n,) = struct.unpack(">H", b[3 + N_ENC:5 + N_ENC])
        algs = b[5 + N_ENC:5 + N_ENC + n]
        return cls(key_id, pk, [struct.unpack(">HH", algs[i:i + 4]) for i in range(0, n, 4)])


def encode_key_list(configs: list[bytes]) -> bytes:
    """application/ohttp-keys: each configuration prefixed by its 2-byte length."""
    return b"".join(struct.pack(">H", len(c)) + c for c in configs)


def decode_key_list(b: bytes) -> list[KeyConfig]:
    out, i = [], 0
    while i < len(b):
        (n,) = struct.unpack(">H", b[i:i + 2])
        out.append(KeyConfig.decode(b[i + 2:i + 2 + n]))
        i += 2 + n
    return out


def _suite(kdf: int, aead: int) -> CipherSuite:
    return CipherSuite.new(KEMId(KEM), KDFId(kdf), AEADId(aead))


def _header(key_id: int, kdf: int, aead: int) -> bytes:
    return struct.pack(">BHHH", key_id, KEM, kdf, aead)


@dataclass
class _Pending:
    ctx: object
    enc: bytes
    aead: int


def _response_keys(ctx, enc: bytes, nonce: bytes, aead: int) -> tuple[bytes, bytes]:
    nk, nn, _ = AEADS[aead]
    secret = ctx.export(RES_LABEL, max(nn, nk))
    prk = hmac.new(enc + nonce, secret, hashlib.sha256).digest()          # HKDF-Extract(salt, IKM)
    key = HKDFExpand(hashes.SHA256(), nk, b"key").derive(prk)
    aead_nonce = HKDFExpand(hashes.SHA256(), nn, b"nonce").derive(prk)
    return key, aead_nonce


# ---------------------------------------------------------------- client side

def encapsulate_request(cfg: KeyConfig, request: bytes, eks=None) -> tuple[bytes, _Pending]:
    kdf, aead = next(((k, a) for k, a in cfg.suites if a in AEADS and k == HKDF_SHA256), (None, None))
    if kdf is None:
        raise OhttpError("no supported symmetric suite in key configuration")
    suite = _suite(kdf, aead)
    hdr = _header(cfg.key_id, kdf, aead)
    enc, ctx = suite.create_sender_context(suite.kem.deserialize_public_key(cfg.public_key),
                                           REQ_LABEL + b"\x00" + hdr, eks=eks)
    return hdr + enc + ctx.seal(request), _Pending(ctx, enc, aead)


def decapsulate_response(p: _Pending, enc_response: bytes) -> bytes:
    nk, nn, cls = AEADS[p.aead]
    nonce, ct = enc_response[:max(nk, nn)], enc_response[max(nk, nn):]
    key, aead_nonce = _response_keys(p.ctx, p.enc, nonce, p.aead)
    try:
        return cls(key).decrypt(aead_nonce, ct, None)
    except Exception:
        raise OhttpError("response does not decrypt")


# ---------------------------------------------------------------- gateway side

class Gateway:
    def __init__(self, sk_bytes: bytes | None = None, key_id: int = 1,
                 suites=((KDFId.HKDF_SHA256, AEADId.AES128_GCM), (KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305))):
        sk_bytes = sk_bytes or secrets.token_bytes(32)
        self.sk = _suite(KDFId.HKDF_SHA256, AEADId.AES128_GCM).kem.deserialize_private_key(sk_bytes)
        pkb = X25519PrivateKey.from_private_bytes(sk_bytes).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.config = KeyConfig(key_id, pkb, [(getattr(k, 'value', k), getattr(a, 'value', a)) for k, a in suites])

    def keys(self) -> bytes:
        return encode_key_list([self.config.encode()])

    def decapsulate_request(self, enc_request: bytes) -> tuple[bytes, _Pending]:
        if len(enc_request) < 7 + N_ENC:
            raise OhttpError("encapsulated request too short")
        key_id, kem, kdf, aead = struct.unpack(">BHHH", enc_request[:7])
        if key_id != self.config.key_id or kem != KEM or (kdf, aead) not in self.config.suites:
            raise OhttpError("unknown key or suite")
        enc, ct = enc_request[7:7 + N_ENC], enc_request[7 + N_ENC:]
        suite = _suite(kdf, aead)
        try:
            ctx = suite.create_recipient_context(enc, self.sk, REQ_LABEL + b"\x00" + enc_request[:7])
            return ctx.open(ct), _Pending(ctx, enc, aead)
        except Exception:
            raise OhttpError("request does not decrypt")

    def encapsulate_response(self, p: _Pending, response: bytes, nonce: bytes | None = None) -> bytes:
        nk, nn, cls = AEADS[p.aead]
        nonce = nonce if nonce is not None else secrets.token_bytes(max(nk, nn))
        key, aead_nonce = _response_keys(p.ctx, p.enc, nonce, p.aead)
        return nonce + cls(key).encrypt(aead_nonce, response, None)


# ---------------------------------------------------------------- httpx transport for the company client

class OhttpTransport(httpx.BaseTransport):
    """Sends every request of an httpx.Client through an OHTTP relay.

    `relay` is a plain httpx.Client pointing at the relay; `keys` the gateway's published key
    configuration, obtained once out of band (here: fetched through the relay and pinned).
    Only these request headers are carried inside the encryption: no cookies, no user agent.
    """

    CARRIED = ("content-type", "x-lab-key")

    def __init__(self, relay: httpx.Client, keys: bytes, relay_path: str = "/relay"):
        self.relay, self.relay_path = relay, relay_path
        self.cfg = decode_key_list(keys)[0]

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        headers = [(k, v) for k, v in request.headers.items() if k.lower() in self.CARRIED]
        breq = encode_request(request.method, request.url.scheme, request.url.netloc.decode(), path,
                              headers, request.read())
        enc_req, pending = encapsulate_request(self.cfg, breq)
        r = self.relay.post(self.relay_path, content=enc_req, headers={"content-type": REQ_TYPE})
        if r.status_code != 200 or r.headers.get("content-type") != RES_TYPE:
            return httpx.Response(502, json={"detail": f"relay or gateway error {r.status_code}"}, request=request)
        res = decode_response(decapsulate_response(pending, r.content))
        return httpx.Response(res["status"], headers=res["headers"], content=res["body"], request=request)
