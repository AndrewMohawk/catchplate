from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request, Response, status
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives import hashes

from serverware.config import (
    ADMIN_ROLES,
    ADMIN_TOKEN_PATH,
    ADMIN_USER_ID,
    OIDC_ALLOWED_ALGORITHMS,
    OIDC_AUDIENCE,
    OIDC_ENABLED,
    OIDC_ISSUER,
    OIDC_JWKS_JSON,
    OIDC_JWKS_PATH,
    OIDC_LEEWAY_SECONDS,
    OIDC_ROLE_CLAIM,
    OIDC_SUBJECT_CLAIM,
    ensure_data_dirs,
)


CSRF_COOKIE_NAME = "serverware_csrf"
CSRF_HEADER_NAME = "X-Serverware-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class OIDCAuthError(ValueError):
    pass


@dataclass(frozen=True)
class AdminIdentity:
    user_id: str
    roles: frozenset[str]
    auth_method: str

    def has_any_role(self, required: set[str]) -> bool:
        return bool(self.roles.intersection(required)) or "admin" in self.roles


@lru_cache(maxsize=1)
def admin_token() -> str:
    env_token = os.getenv("SERVERWARE_ADMIN_TOKEN")
    if env_token:
        return env_token
    ensure_data_dirs()
    if ADMIN_TOKEN_PATH.exists():
        return ADMIN_TOKEN_PATH.read_text().strip()
    token = secrets.token_urlsafe(32)
    ADMIN_TOKEN_PATH.write_text(token + "\n")
    os.chmod(ADMIN_TOKEN_PATH, 0o600)
    return token


def check_admin_token(candidate: str | None) -> bool:
    if not candidate:
        return False
    return hmac.compare_digest(candidate, admin_token())


def rotate_generated_admin_token() -> dict[str, str]:
    if os.getenv("SERVERWARE_ADMIN_TOKEN"):
        raise RuntimeError("environment-provided admin token cannot be rotated at runtime")
    old_token = admin_token()
    token = secrets.token_urlsafe(32)
    ensure_data_dirs()
    ADMIN_TOKEN_PATH.write_text(token + "\n")
    os.chmod(ADMIN_TOKEN_PATH, 0o600)
    admin_token.cache_clear()
    return {
        "token": token,
        "token_sha256": "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "previous_token_sha256": "sha256:" + hashlib.sha256(old_token.encode("utf-8")).hexdigest(),
        "token_path": str(ADMIN_TOKEN_PATH),
    }


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise OIDCAuthError("invalid base64url encoding") from exc


def _b64url_uint(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


@lru_cache(maxsize=1)
def _oidc_jwks() -> dict[str, object]:
    if OIDC_JWKS_JSON:
        raw = OIDC_JWKS_JSON
    elif OIDC_JWKS_PATH.exists():
        raw = OIDC_JWKS_PATH.read_text()
    else:
        raise OIDCAuthError("OIDC JWKS is not configured")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OIDCAuthError("OIDC JWKS is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise OIDCAuthError("OIDC JWKS must contain a keys array")
    return data


def _oidc_key_for_header(header: dict[str, object]) -> dict[str, object]:
    jwks = _oidc_jwks()
    keys = [key for key in jwks.get("keys", []) if isinstance(key, dict)]
    kid = header.get("kid")
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return key
        raise OIDCAuthError("OIDC token kid is not trusted")
    if len(keys) == 1:
        return keys[0]
    raise OIDCAuthError("OIDC token kid is required when JWKS has multiple keys")


def _verify_oidc_signature(algorithm: str, jwk: dict[str, object], signing_input: bytes, signature: bytes) -> None:
    key_type = jwk.get("kty")
    try:
        if algorithm == "RS256" and key_type == "RSA":
            public_key = rsa.RSAPublicNumbers(
                _b64url_uint(str(jwk["e"])),
                _b64url_uint(str(jwk["n"])),
            ).public_key()
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        if algorithm == "ES256" and key_type == "EC" and jwk.get("crv") == "P-256":
            public_key = ec.EllipticCurvePublicNumbers(
                _b64url_uint(str(jwk["x"])),
                _b64url_uint(str(jwk["y"])),
                ec.SECP256R1(),
            ).public_key()
            if len(signature) != 64:
                raise OIDCAuthError("ES256 signature must be raw r||s")
            der_signature = utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
            return
        if algorithm == "EdDSA" and key_type == "OKP" and jwk.get("crv") == "Ed25519":
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(str(jwk["x"])))
            public_key.verify(signature, signing_input)
            return
    except KeyError as exc:
        raise OIDCAuthError("OIDC JWK is missing required key material") from exc
    except InvalidSignature as exc:
        raise OIDCAuthError("OIDC token signature is invalid") from exc
    raise OIDCAuthError(f"OIDC token algorithm/key type is unsupported: {algorithm}/{key_type}")


def _validate_oidc_claims(payload: dict[str, object]) -> None:
    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < now - OIDC_LEEWAY_SECONDS:
        raise OIDCAuthError("OIDC token is expired or missing exp")
    nbf = payload.get("nbf")
    if isinstance(nbf, int) and nbf > now + OIDC_LEEWAY_SECONDS:
        raise OIDCAuthError("OIDC token is not yet valid")
    iat = payload.get("iat")
    if isinstance(iat, int) and iat > now + OIDC_LEEWAY_SECONDS:
        raise OIDCAuthError("OIDC token was issued in the future")
    if OIDC_ISSUER and payload.get("iss") != OIDC_ISSUER:
        raise OIDCAuthError("OIDC issuer mismatch")
    if OIDC_AUDIENCE:
        audience = payload.get("aud")
        audiences = {audience} if isinstance(audience, str) else set(audience or []) if isinstance(audience, list) else set()
        if OIDC_AUDIENCE not in audiences:
            raise OIDCAuthError("OIDC audience mismatch")


def _roles_from_claim(value: object) -> frozenset[str]:
    if isinstance(value, str):
        raw = value.replace(",", " ").split()
    elif isinstance(value, list):
        raw = [str(item) for item in value]
    else:
        raw = []
    return frozenset(role.strip() for role in raw if role.strip())


def oidc_identity_from_token(token: str | None) -> AdminIdentity | None:
    if not OIDC_ENABLED or not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCAuthError("OIDC bearer token must be a JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except json.JSONDecodeError as exc:
        raise OIDCAuthError("OIDC token header or payload is not JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise OIDCAuthError("OIDC token header and payload must be objects")
    algorithm = str(header.get("alg") or "")
    if algorithm not in set(OIDC_ALLOWED_ALGORITHMS):
        raise OIDCAuthError("OIDC token algorithm is not allowed")
    jwk = _oidc_key_for_header(header)
    _verify_oidc_signature(algorithm, jwk, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2]))
    _validate_oidc_claims(payload)
    subject = payload.get(OIDC_SUBJECT_CLAIM) or payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise OIDCAuthError("OIDC token subject is missing")
    roles = _roles_from_claim(payload.get(OIDC_ROLE_CLAIM))
    if not roles:
        raise OIDCAuthError("OIDC token is missing Serverware RBAC roles")
    return AdminIdentity(f"oidc:{subject}", roles, "oidc-bearer")


def require_admin(
    request: Request,
    x_serverware_admin_token: str | None = Header(default=None, alias="X-Serverware-Admin-Token"),
) -> AdminIdentity:
    bearer = request.headers.get("Authorization", "")
    bearer_token = bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else None
    cookie_token = request.cookies.get("serverware_admin")
    if check_admin_token(x_serverware_admin_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "admin-token-header")
    if check_admin_token(bearer_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "bearer-token")
    try:
        oidc_identity = oidc_identity_from_token(bearer_token)
    except OIDCAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    if oidc_identity:
        return oidc_identity
    if check_admin_token(cookie_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "admin-cookie")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="admin authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _bearer_token(request: Request) -> str | None:
    bearer = request.headers.get("Authorization", "")
    return bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else None


def _request_has_valid_non_cookie_admin_auth(request: Request) -> bool:
    if check_admin_token(request.headers.get("X-Serverware-Admin-Token")) or check_admin_token(_bearer_token(request)):
        return True
    try:
        return oidc_identity_from_token(_bearer_token(request)) is not None
    except OIDCAuthError:
        return False


def _csrf_cookie_secure(request: Request) -> bool:
    raw = os.getenv("SERVERWARE_CSRF_COOKIE_SECURE")
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return request.url.scheme == "https"


def issue_csrf_cookie(response: Response, request: Request, token: str | None = None) -> str:
    csrf_token = token or secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        secure=_csrf_cookie_secure(request),
        samesite="strict",
        path="/",
    )
    return csrf_token


def validate_csrf_request(request: Request) -> None:
    if request.method.upper() not in UNSAFE_METHODS:
        return
    path = request.url.path
    if not path.startswith("/api/") or path.startswith("/api/data-plane/"):
        return
    cookie_admin_token = request.cookies.get("serverware_admin")
    if not check_admin_token(cookie_admin_token):
        return
    if _request_has_valid_non_cookie_admin_auth(request):
        return
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    csrf_header = request.headers.get(CSRF_HEADER_NAME)
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token required for cookie-authenticated control-plane mutation",
        )


def require_role(*roles: str) -> Callable[..., AdminIdentity]:
    required = set(roles)

    def dependency(identity: AdminIdentity = Depends(require_admin)) -> AdminIdentity:
        if identity.has_any_role(required):
            return identity
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"required role: {' or '.join(sorted(required))}",
        )

    return dependency


def admin_status() -> dict[str, object]:
    return {
        "admin_auth_required": True,
        "token_source": "env" if os.getenv("SERVERWARE_ADMIN_TOKEN") else "generated-file",
        "generated_token_path": None if os.getenv("SERVERWARE_ADMIN_TOKEN") else str(ADMIN_TOKEN_PATH),
        "admin_user_id": ADMIN_USER_ID,
        "admin_roles": list(ADMIN_ROLES),
        "oidc": {
            "enabled": OIDC_ENABLED,
            "issuer": OIDC_ISSUER or None,
            "audience": OIDC_AUDIENCE or None,
            "role_claim": OIDC_ROLE_CLAIM,
            "subject_claim": OIDC_SUBJECT_CLAIM,
            "allowed_algorithms": list(OIDC_ALLOWED_ALGORITHMS),
        },
        "csrf": {
            "cookie_protection": "double-submit",
            "cookie_name": CSRF_COOKIE_NAME,
            "header_name": CSRF_HEADER_NAME,
            "unsafe_methods": sorted(UNSAFE_METHODS),
        },
    }
