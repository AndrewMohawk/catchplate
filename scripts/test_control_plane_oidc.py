#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_uint(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class FakeUrl:
    def __init__(self, path: str, scheme: str = "https"):
        self.path = path
        self.scheme = scheme


class FakeRequest:
    def __init__(self, token: str, *, method: str = "GET", path: str = "/api/bootstrap", cookies: dict[str, str] | None = None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.cookies = cookies or {}
        self.method = method
        self.url = FakeUrl(path)


def sign_jwt(private_key: Any, *, kid: str, issuer: str, audience: str, roles: list[str], subject: str = "andrew") -> str:
    now = int(time.time())
    header = {"typ": "JWT", "alg": "RS256", "kid": kid}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 5,
        "serverware_roles": roles,
    }
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':'), sort_keys=True).encode())}.{b64u(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())}".encode(
        "ascii"
    )
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{b64u(signature)}"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        issuer = "https://idp.example"
        audience = "serverware-control-plane"
        kid = "serverware-oidc-test"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "alg": "RS256",
                    "use": "sig",
                    "n": b64u_uint(numbers.n),
                    "e": b64u_uint(numbers.e),
                }
            ]
        }

        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_OIDC_ENABLED"] = "1"
        os.environ["SERVERWARE_OIDC_ISSUER"] = issuer
        os.environ["SERVERWARE_OIDC_AUDIENCE"] = audience
        os.environ["SERVERWARE_OIDC_JWKS_JSON"] = json.dumps(jwks, separators=(",", ":"), sort_keys=True)
        os.environ["SERVERWARE_OIDC_ROLE_CLAIM"] = "serverware_roles"
        os.environ["SERVERWARE_ADMIN_TOKEN"] = "local-admin-token-for-csrf-test"

        from fastapi import HTTPException

        from serverware import auth

        token = sign_jwt(private_key, kid=kid, issuer=issuer, audience=audience, roles=["auditor", "policy_author"])
        identity = auth.require_admin(FakeRequest(token), x_serverware_admin_token=None)
        if identity.user_id != "oidc:andrew" or identity.auth_method != "oidc-bearer":
            raise AssertionError(f"OIDC identity was not accepted: {identity}")
        if identity.roles != frozenset({"auditor", "policy_author"}):
            raise AssertionError(f"OIDC roles were not mapped from the role claim: {identity}")
        auth.require_role("auditor")(identity)

        csrf_request = FakeRequest(
            token,
            method="POST",
            path="/api/credentials",
            cookies={"serverware_admin": auth.admin_token()},
        )
        auth.validate_csrf_request(csrf_request)

        bad_audience = sign_jwt(private_key, kid=kid, issuer=issuer, audience="wrong-audience", roles=["auditor"])
        try:
            auth.require_admin(FakeRequest(bad_audience), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "audience mismatch" not in str(exc.detail):
                raise AssertionError(f"bad audience failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token with bad audience was accepted")

        missing_roles = sign_jwt(private_key, kid=kid, issuer=issuer, audience=audience, roles=[])
        try:
            auth.require_admin(FakeRequest(missing_roles), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "RBAC roles" not in str(exc.detail):
                raise AssertionError(f"missing roles failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token without Serverware roles was accepted")

        tampered = token.rsplit(".", 1)[0] + "." + b64u(b"bad-signature")
        try:
            auth.require_admin(FakeRequest(tampered), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "signature" not in str(exc.detail):
                raise AssertionError(f"tampered token failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token with bad signature was accepted")

    print(json.dumps({"control_plane_oidc": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
