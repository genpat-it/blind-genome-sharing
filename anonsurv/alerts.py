# SPDX-License-Identifier: EUPL-1.2
"""Private alerts with one-time keys: HPKE (RFC 9180), DHKEM-X25519 / HKDF-SHA256 / ChaCha20-Poly1305.

The company attaches a fresh public key to each submission; public health encrypts the alert to it
and posts it on a bulletin that everybody downloads in full. Only the holder of the secret key can
open it, and downloading the whole bulletin reveals nothing about which alert one was waiting for.
"""
from __future__ import annotations

import secrets

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
INFO = b"anonsurv alert v1"


def new_keypair() -> tuple[bytes, bytes]:
    """Returns (secret_key, public_key), 32 bytes each."""
    kp = SUITE.kem.derive_key_pair(secrets.token_bytes(32))
    return kp.private_key.to_private_bytes(), kp.public_key.to_public_bytes()


def seal(public_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Returns (enc, ciphertext)."""
    enc, ctx = SUITE.create_sender_context(SUITE.kem.deserialize_public_key(public_key), INFO)
    return enc, ctx.seal(plaintext)


def try_open(secret_key: bytes, enc: bytes, ciphertext: bytes) -> bytes | None:
    try:
        ctx = SUITE.create_recipient_context(enc, SUITE.kem.deserialize_private_key(secret_key), INFO)
        return ctx.open(ciphertext)
    except Exception:  # wrong key: authentication tag does not verify
        return None
