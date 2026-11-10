# SPDX-License-Identifier: EUPL-1.2
"""RSA blind signatures, RFC 9474 (RSABSSA-SHA384-PSS / PSSZERO, Randomized / Deterministic).

Written on top of `cryptography` because no maintained Python package implements RFC 9474.
Checked against the four test vectors of RFC 9474 Appendix A (tests/test_rsabssa.py).
Final signatures are verified with `cryptography`'s own RSASSA-PSS, independently of this code.

Roles:
  client  (company)  : prepare -> blind -> [send blinded_msg] -> finalize
  issuer             : blind_sign  (sees only blinded_msg)
  verifier (platform): verify      (public key only)
"""
from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from functools import cached_property

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

H_LEN = 48  # SHA-384
PREFIX_LEN = 32  # randomized preparation (RFC 9474 Section 4.1)


class BlindSignatureError(Exception):
    pass


# ---------------------------------------------------------------- keys
@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def modulus_len(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_pem(self) -> bytes:
        return rsa.RSAPublicNumbers(self.e, self.n).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def from_pem(cls, pem: bytes) -> "PublicKey":
        nums = serialization.load_pem_public_key(pem).public_numbers()
        return cls(nums.n, nums.e)

    def fingerprint(self) -> str:
        """SHA-256 of the DER encoding; published in the transparency log (key-tagging defence)."""
        der = rsa.RSAPublicNumbers(self.e, self.n).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class SecretKey:
    n: int
    e: int
    d: int

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    @classmethod
    def generate(cls, bits: int = 2048) -> "SecretKey":
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = k.private_numbers()
        return cls(nums.public_numbers.n, nums.public_numbers.e, nums.d)

    def to_pem(self) -> bytes:
        return self._crypto_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    @classmethod
    def from_pem(cls, pem: bytes) -> "SecretKey":
        nums = serialization.load_pem_private_key(pem, password=None).private_numbers()
        return cls(nums.public_numbers.n, nums.public_numbers.e, nums.d)

    @cached_property
    def _crt(self) -> tuple[int, int, int, int, int]:
        p, q = rsa.rsa_recover_prime_factors(self.n, self.e, self.d)
        return p, q, self.d % (p - 1), self.d % (q - 1), pow(q, -1, p)

    def raw_sign(self, m: int) -> int:
        """m^d mod n with the Chinese remainder theorem (about 3-4x faster)."""
        p, q, dp, dq, qinv = self._crt
        mp, mq = pow(m, dp, p), pow(m, dq, q)
        return mq + ((qinv * (mp - mq)) % p) * q

    def _crypto_key(self):
        p, q = rsa.rsa_recover_prime_factors(self.n, self.e, self.d)
        return rsa.RSAPrivateNumbers(
            p, q, self.d, rsa.rsa_crt_dmp1(self.d, p), rsa.rsa_crt_dmq1(self.d, q),
            rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(self.e, self.n)).private_key()


# ---------------------------------------------------------------- encoding helpers
def i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    for counter in range(math.ceil(length / H_LEN)):
        out += hashlib.sha384(seed + i2osp(counter, 4)).digest()
    return out[:length]


def emsa_pss_encode(msg: bytes, em_bits: int, salt: bytes) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 Section 9.1.1), SHA-384 and MGF1-SHA-384."""
    em_len = math.ceil(em_bits / 8)
    m_hash = hashlib.sha384(msg).digest()
    if em_len < H_LEN + len(salt) + 2:
        raise BlindSignatureError("encoding error")
    h = hashlib.sha384(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - H_LEN - 2) + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(db, mgf1(h, em_len - H_LEN - 1)))
    unused = 8 * em_len - em_bits
    masked = bytes([masked[0] & (0xFF >> unused)]) + masked[1:]
    return masked + h + b"\xbc"


# ---------------------------------------------------------------- protocol (RFC 9474 Section 4)
def prepare(msg: bytes, randomized: bool = True, prefix: bytes | None = None) -> bytes:
    if not randomized:
        return msg
    return (prefix if prefix is not None else secrets.token_bytes(PREFIX_LEN)) + msg


def blind(pk: PublicKey, msg: bytes, salt_len: int = H_LEN, *,
          salt: bytes | None = None, r: int | None = None) -> tuple[bytes, int]:
    """Client: returns (blinded_msg, inv). `salt` and `r` are only for test vectors."""
    if salt is None:
        salt = secrets.token_bytes(salt_len)
    encoded = emsa_pss_encode(msg, pk.n.bit_length() - 1, salt)
    m = os2ip(encoded)
    if math.gcd(m, pk.n) != 1:
        raise BlindSignatureError("invalid input")
    if r is None:
        while True:
            r = secrets.randbelow(pk.n - 1) + 1
            if math.gcd(r, pk.n) == 1:
                break
    inv = pow(r, -1, pk.n)
    z = (m * pow(r, pk.e, pk.n)) % pk.n
    return i2osp(z, pk.modulus_len), inv


def blind_sign(sk: SecretKey, blinded_msg: bytes) -> bytes:
    """Issuer: signs a value it cannot read."""
    k = (sk.n.bit_length() + 7) // 8
    if len(blinded_msg) != k:
        raise BlindSignatureError("unexpected input size")
    m = os2ip(blinded_msg)
    if m >= sk.n:
        raise BlindSignatureError("message representative out of range")
    s = sk.raw_sign(m)
    if pow(s, sk.e, sk.n) != m:
        raise BlindSignatureError("signing failure")
    return i2osp(s, k)


def finalize(pk: PublicKey, msg: bytes, blind_sig: bytes, inv: int, salt_len: int = H_LEN) -> bytes:
    """Client: removes the blinding and checks the result."""
    if len(blind_sig) != pk.modulus_len:
        raise BlindSignatureError("unexpected input size")
    sig = i2osp((os2ip(blind_sig) * inv) % pk.n, pk.modulus_len)
    if not verify(pk, msg, sig, salt_len):
        raise BlindSignatureError("invalid signature")
    return sig


def verify(pk: PublicKey, msg: bytes, sig: bytes, salt_len: int = H_LEN) -> bool:
    """Verifier: standard RSASSA-PSS verification, done by `cryptography`."""
    try:
        rsa.RSAPublicNumbers(pk.e, pk.n).public_key().verify(
            sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=salt_len),
            hashes.SHA384())
        return True
    except InvalidSignature:
        return False
