# SPDX-License-Identifier: EUPL-1.2
"""A minimal OpenID Connect provider for the demo and the tests (stands in for SPID/CIE).

It publishes discovery metadata and a JWKS, and issues RS256 ID tokens through the resource-owner
password grant. Real SPID/CIE use the authorisation-code flow in a browser; for the issuer only the
resulting ID token matters, and that is verified exactly as a real one would be. Docker compose
uses Keycloak instead of this module.
"""
from __future__ import annotations

import hmac
import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException


class DemoIdP:
    def __init__(self, issuer: str, audience: str, users: dict[str, dict]):
        """users: username -> {"password", "claims"}"""
        self.issuer, self.audience, self.users = issuer.rstrip("/"), audience, users
        self.sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = secrets.token_hex(8)

    def id_token(self, username: str, lifetime: int = 300) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": self.audience, "sub": username, "iat": now, "exp": now + lifetime,
                  **self.users[username]["claims"]}
        return jwt.encode(claims, self.sk, algorithm="RS256", headers={"kid": self.kid})

    def jwks(self) -> dict:
        k = jwt.algorithms.RSAAlgorithm.to_jwk(self.sk.public_key(), as_dict=True)
        return {"keys": [{**k, "kid": self.kid, "use": "sig", "alg": "RS256"}]}


def create_app(idp: DemoIdP) -> FastAPI:
    app = FastAPI(title="Demo identity provider")

    @app.get("/.well-known/openid-configuration")
    def discovery():
        return {"issuer": idp.issuer, "jwks_uri": f"{idp.issuer}/jwks", "token_endpoint": f"{idp.issuer}/token",
                "id_token_signing_alg_values_supported": ["RS256"],
                "grant_types_supported": ["password"], "subject_types_supported": ["public"]}

    @app.get("/jwks")
    def jwks():
        return idp.jwks()

    @app.post("/token")
    def token(grant_type: str = Form(...), username: str = Form(...), password: str = Form(...),
              client_id: str = Form(...), scope: str = Form("openid")):
        u = idp.users.get(username)
        if grant_type != "password" or client_id != idp.audience or u is None \
                or not hmac.compare_digest(u["password"], password):
            raise HTTPException(401, "invalid_grant")
        return {"token_type": "Bearer", "id_token": idp.id_token(username), "access_token": secrets.token_hex(16),
                "expires_in": 300}

    return app
