# SPDX-License-Identifier: EUPL-1.2
"""Threshold identity escrow, made verifiable by cut-and-choose.

Each token carries an *escrow blob*: the company identifier encrypted under a fresh key K, and K
split with Shamir's scheme (t of n) into shares, each encrypted with HPKE to one trustee (a
consortium member). No trustee alone, and not the platform, can read the identifier; t trustees
together can, for one record, after a disclosure request has been written in the public log.

The difficulty is that the issuer signs blind: it cannot see that the blob really holds the
company's identifier. Cut-and-choose (Chaum, Fiat and Naor, 1988) fixes this with plain RSA blind
signatures. For every token the company prepares `k` candidates; the issuer picks one at random to
sign, and the company must open the other k-1 (seed and blinding values). The issuer rebuilds
each opened candidate from its seed and the identifier it knows, and refuses everything if one
does not match. A company that cheats on a token is caught with probability (k-1)/k, and loses
its tokens; the kept candidate stays blind, so the issuer still cannot link it to a submission.

All randomness of a candidate comes from its 32-byte seed, which is what makes the opened
candidates checkable byte for byte.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import alerts
from . import rsabssa as bs

P = 2**521 - 1          # Mersenne prime, field for Shamir shares (K is 256 bits)
SHARE_LEN = 66
INFO = b"anonsurv escrow v1"
ZERO_NONCE = b"\x00" * 12   # every AEAD key below is used exactly once


def _kdf(seed: bytes, label: str, n: int = 32) -> bytes:
    return HKDF(hashes.SHA256(), n, salt=None, info=INFO + b"|" + label.encode()).derive(seed)


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Config:
    """Published in the log's first entry: who the trustees are and how many must agree."""
    trustees: tuple[str, ...]   # HPKE X25519 public keys, hex
    t: int
    k: int = 8                  # cut-and-choose candidates per token

    def to_json(self) -> dict:
        return {"trustees": list(self.trustees), "t": self.t, "k": self.k}

    @classmethod
    def from_json(cls, d: dict) -> "Config":
        return cls(tuple(d["trustees"]), d["t"], d["k"])


# ---------------------------------------------------------------- Shamir over GF(P)

def split(secret: int, t: int, n: int, coeffs: list[int]) -> list[tuple[int, int]]:
    poly = [secret] + coeffs[: t - 1]
    return [(x, sum(a * pow(x, j, P) for j, a in enumerate(poly)) % P) for x in range(1, n + 1)]


def combine(shares: list[tuple[int, int]]) -> int:
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * -xj % P
                den = den * (xi - xj) % P
        secret = (secret + yi * num * pow(den, -1, P)) % P
    return secret


# ---------------------------------------------------------------- the blob

def build_blob(seed: bytes, company_id: str, cfg: Config) -> bytes:
    """Deterministic in (seed, company_id, cfg): the issuer can rebuild an opened candidate."""
    key = _kdf(seed, "key")
    id_ct = ChaCha20Poly1305(key).encrypt(ZERO_NONCE, company_id.encode(), b"id")
    coeffs = [int.from_bytes(_kdf(seed, f"coef{j}", 80), "big") % P for j in range(1, cfg.t)]
    shares = []
    for (x, y), pk_hex in zip(split(int.from_bytes(key, "big"), cfg.t, len(cfg.trustees), coeffs), cfg.trustees):
        eks = alerts.SUITE.kem.derive_key_pair(_kdf(seed, f"eph{x}"))
        pkr = alerts.SUITE.kem.deserialize_public_key(bytes.fromhex(pk_hex))
        aad = hashlib.sha256(id_ct).digest() + bytes([x])
        enc, ctx = alerts.SUITE.create_sender_context(pkr, INFO, eks=eks)
        shares.append({"x": x, "enc": enc.hex(), "ct": ctx.seal(y.to_bytes(SHARE_LEN, "big"), aad).hex()})
    return _canonical({"v": 1, "t": cfg.t, "id": id_ct.hex(), "shares": shares})


def token_for(blob: bytes) -> bytes:
    """The message signed blind: a random 32-byte prefix (RFC 9474 randomized) and the blob hash."""
    return bs.prepare(hashlib.sha256(blob).digest())


def token_matches(token: bytes, blob: bytes) -> bool:
    return len(token) == 64 and token[32:] == hashlib.sha256(blob).digest()


def well_formed(blob: bytes, cfg: Config) -> bool:
    try:
        b = json.loads(blob)
        return (b["v"] == 1 and b["t"] == cfg.t and len(b["shares"]) == len(cfg.trustees)
                and [s["x"] for s in b["shares"]] == list(range(1, len(cfg.trustees) + 1)))
    except (ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------- trustees

def open_share(blob: bytes, x: int, trustee_sk: bytes) -> tuple[int, int]:
    """Trustee x decrypts its share. Done only for a disclosure request recorded in the log."""
    b = json.loads(blob)
    s = b["shares"][x - 1]
    aad = hashlib.sha256(bytes.fromhex(b["id"])).digest() + bytes([x])
    ctx = alerts.SUITE.create_recipient_context(bytes.fromhex(s["enc"]),
                                                alerts.SUITE.kem.deserialize_private_key(trustee_sk), INFO)
    return x, int.from_bytes(ctx.open(bytes.fromhex(s["ct"]), aad), "big")


def reveal(blob: bytes, shares: list[tuple[int, int]]) -> str:
    """Combine t shares, recover K, decrypt the company identifier."""
    b = json.loads(blob)
    if len(shares) < b["t"]:
        raise ValueError(f"{b['t']} shares needed, {len(shares)} given")
    key = combine(shares[: b["t"]]).to_bytes(32, "big")
    return ChaCha20Poly1305(key).decrypt(ZERO_NONCE, bytes.fromhex(b["id"]), b"id").decode()


# ---------------------------------------------------------------- cut-and-choose issuance

@dataclass
class Candidate:
    seed: bytes
    blob: bytes
    token: bytes
    salt: bytes
    r: int
    blinded: bytes
    inv: int

    def opening(self) -> dict:
        return {"seed": self.seed.hex(), "token": self.token.hex(), "salt": self.salt.hex(), "r": hex(self.r)}


def make_candidate(pk: bs.PublicKey, company_id: str, cfg: Config) -> Candidate:
    seed = secrets.token_bytes(32)
    blob = build_blob(seed, company_id, cfg)
    token = token_for(blob)
    salt = secrets.token_bytes(bs.H_LEN)
    r = secrets.randbelow(pk.n - 2) + 2
    blinded, inv = bs.blind(pk, token, salt=salt, r=r)
    return Candidate(seed, blob, token, salt, r, blinded, inv)


def check_opening(pk: bs.PublicKey, company_id: str, cfg: Config, blinded: bytes, o: dict) -> bool:
    """Issuer side: rebuild the candidate from its opening and the identifier the issuer knows."""
    try:
        seed, token, salt, r = bytes.fromhex(o["seed"]), bytes.fromhex(o["token"]), bytes.fromhex(o["salt"]), int(o["r"], 16)
        blob = build_blob(seed, company_id, cfg)
        if not token_matches(token, blob):
            return False
        return bs.blind(pk, token, salt=salt, r=r)[0] == blinded
    except (ValueError, KeyError, TypeError, bs.BlindSignatureError):
        return False
