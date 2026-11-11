# SPDX-License-Identifier: EUPL-1.2
"""OpenID Connect ID-token verification for the issuer.

The issuer trusts an identity provider (in Italy SPID or CIE, both offered over OpenID Connect; in
the demo a local provider, in docker compose Keycloak) and reads from the ID token who is logging
in for which company. SPID/CIE OpenID Connect carries the company's VAT number in the claim
https://attributes.eid.gov.it/vat_number ("VATIT-01234567890"; `ivaCode` is the SAML name of the
same attribute, used here by Keycloak); the issuer maps it to the register of food business operators.
"""
from __future__ import annotations

import time

import httpx
import jwt

ALGORITHMS = ["RS256", "ES256", "PS256"]
VAT_CLAIMS = ("https://attributes.eid.gov.it/vat_number", "ivaCode")


class AuthError(Exception):
    pass


class OidcVerifier:
    def __init__(self, http: httpx.Client, issuer: str, audience: str, discovery_path: str | None = None,
                 vat_claims: tuple[str, ...] = VAT_CLAIMS, jwks_ttl: float = 300):
        self.http, self.issuer, self.audience, self.vat_claims, self.ttl = http, issuer.rstrip("/"), audience, vat_claims, jwks_ttl
        self.discovery_path = discovery_path or httpx.URL(self.issuer).path.rstrip("/") + "/.well-known/openid-configuration"
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched = 0.0

    def _refresh(self):
        conf = self.http.get(self.discovery_path).json()
        if conf["issuer"].rstrip("/") != self.issuer:
            raise AuthError("identity provider metadata names another issuer")
        jwks_uri = httpx.URL(conf["jwks_uri"])
        jwks = self.http.get(jwks_uri.raw_path.decode()).json()
        self._keys = {k["kid"]: jwt.PyJWK(k) for k in jwks["keys"] if k.get("use", "sig") == "sig"}
        self._fetched = time.time()

    def verify(self, token: str) -> dict:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as e:
            raise AuthError(f"malformed ID token: {e}")
        if kid not in self._keys or time.time() - self._fetched > self.ttl:
            self._refresh()
        if kid not in self._keys:
            raise AuthError("ID token signed with an unknown key")
        try:
            return jwt.decode(token, self._keys[kid], algorithms=ALGORITHMS, audience=self.audience,
                              issuer=self.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWTError as e:
            raise AuthError(f"ID token rejected: {e}")

    def vat(self, claims: dict) -> str:
        v = next((claims[c] for c in self.vat_claims if claims.get(c)), None)
        if not v:
            raise AuthError("ID token has no VAT number claim: not a company identity")
        return v.removeprefix("VATIT-").removeprefix("IT")


def bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    return authorization[7:].strip()
