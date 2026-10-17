from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request, Response, status
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives import hashes

from catchplate import db
from catchplate.rbac import RBACRoleValidationError, normalize_rbac_roles
from catchplate.config import (
    ADMIN_ROLES,
    ADMIN_TOKEN,
    ADMIN_TOKEN_PATH,
    ADMIN_TOKEN_SOURCE,
    ADMIN_USER_ID,
    OIDC_ALLOWED_ALGORITHMS,
    OIDC_AUDIENCE,
    OIDC_AUTHORIZATION_ENDPOINT,
    OIDC_BROWSER_LOGIN_ENABLED,
    OIDC_CLIENT_ID,
    OIDC_ENABLED,
    OIDC_ISSUER,
    OIDC_JWKS_JSON,
    OIDC_JWKS_PATH,
    OIDC_LEEWAY_SECONDS,
    OIDC_ROLE_CLAIM,
    OIDC_SUBJECT_CLAIM,
    OIDC_SESSION_WEBAUTHN_REQUIRED,
    CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES,
    CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION,
    OIDC_TOKEN_ENDPOINT,
    RELEASE_CHANNEL,
    ensure_data_dirs,
)


CSRF_COOKIE_NAME = "catchplate_csrf"
CSRF_HEADER_NAME = "X-Catchplate-CSRF-Token"
OIDC_SESSION_COOKIE_NAME = "catchplate_oidc_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_OIDC_BEARER_TOKEN_BYTES = 64 * 1024
MAX_OIDC_SESSION_TOKEN_BYTES = 512
_OIDC_SESSION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{64}")


class OIDCAuthError(ValueError):
    pass


class OIDCAccessDenied(PermissionError):
    pass


class OIDCAuthoritativeStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdminIdentity:
    user_id: str
    roles: frozenset[str]
    auth_method: str

    def has_any_role(self, required: set[str]) -> bool:
        return bool(self.roles.intersection(required)) or "admin" in self.roles


def admin_token() -> str:
    if ADMIN_TOKEN:
        return ADMIN_TOKEN
    from catchplate.control_plane_admin_token_publication import _read_generated_token

    # A different worker may have completed an authorized atomic rotation.
    # A process-local token cache must not preserve the previous credential.
    return _read_generated_token()


def _clear_admin_token_cache() -> None:
    """Compatibility hook: generated administrator tokens are no longer cached."""


admin_token.cache_clear = _clear_admin_token_cache


def check_admin_token(candidate: str | None) -> bool:
    if not candidate:
        return False
    from catchplate.control_plane_admin_token_publication import PublicationError
    from catchplate.policy_bundle import PolicyBundleError

    try:
        return hmac.compare_digest(candidate, admin_token())
    except (PublicationError, PolicyBundleError, OSError):
        # Fail this credential closed without blocking independently configured
        # OIDC authentication (including read-only interrupted-outcome inspection).
        return False


def rotate_generated_admin_token() -> dict[str, str]:
    raise RuntimeError("admin token rotation requires the retained HTTP publication owner")


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


def _oidc_key_for_header(header: dict[str, object], algorithm: str) -> dict[str, object]:
    jwks = _oidc_jwks()
    keys = [key for key in jwks.get("keys", []) if isinstance(key, dict)]
    kid = header.get("kid")
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                selected = key
                break
        else:
            raise OIDCAuthError("OIDC token kid is not trusted")
    elif len(keys) == 1:
        selected = keys[0]
    else:
        raise OIDCAuthError("OIDC token kid is required when JWKS has multiple keys")
    key_use = selected.get("use")
    if key_use is not None and key_use != "sig":
        raise OIDCAuthError("OIDC JWK is not authorized for signatures")
    key_ops = selected.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise OIDCAuthError("OIDC JWK is not authorized for verification")
    key_algorithm = selected.get("alg")
    if key_algorithm is not None and key_algorithm != algorithm:
        raise OIDCAuthError("OIDC JWK algorithm does not match the token")
    return selected


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


def _validate_oidc_claims(payload: dict[str, object], *, expected_nonce: str | None = None) -> None:
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
        if isinstance(audience, str):
            audiences = {audience}
        elif isinstance(audience, list) and audience and all(isinstance(item, str) for item in audience):
            audiences = set(audience)
        else:
            raise OIDCAuthError("OIDC audience claim is invalid")
        if OIDC_AUDIENCE not in audiences:
            raise OIDCAuthError("OIDC audience mismatch")
        authorized_party = payload.get("azp")
        if len(audiences) > 1 and not isinstance(authorized_party, str):
            raise OIDCAuthError("OIDC authorized party is required for multiple audiences")
        if authorized_party is not None and authorized_party != OIDC_AUDIENCE:
            raise OIDCAuthError("OIDC authorized party mismatch")
    if expected_nonce is not None:
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
            raise OIDCAuthError("OIDC nonce mismatch")


def _roles_from_claim(value: object) -> frozenset[str]:
    if isinstance(value, str):
        raw = value.replace(",", " ").split()
    elif isinstance(value, list):
        raw = [str(item) for item in value]
    else:
        raw = []
    try:
        return frozenset(normalize_rbac_roles(raw))
    except RBACRoleValidationError as exc:
        raise OIDCAuthError("OIDC token contains invalid Catchplate RBAC roles") from exc


def _production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in {"dev", "development", "local", "test"}


def _authoritative_oidc_roles(user_id: str, claimed_roles: frozenset[str]) -> frozenset[str]:
    try:
        binding = db.get_rbac_role_binding(user_id)
    except db.RBACBindingStoreError as exc:
        raise OIDCAuthoritativeStateError("authoritative RBAC binding state is unavailable") from exc
    if binding is None:
        if _production_release():
            raise OIDCAccessDenied("OIDC subject is not provisioned")
        return claimed_roles
    if binding["status"] != "active":
        raise OIDCAccessDenied("OIDC subject is deprovisioned")
    return frozenset(binding["roles"])


def _refresh_oidc_authorization(identity: AdminIdentity) -> AdminIdentity:
    if not identity.auth_method.startswith("oidc-"):
        return identity
    try:
        roles = _authoritative_oidc_roles(identity.user_id, identity.roles)
    except OIDCAuthoritativeStateError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except OIDCAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return AdminIdentity(identity.user_id, roles, identity.auth_method)


def oidc_identity_from_token(
    token: str | None,
    *,
    expected_nonce: str | None = None,
    auth_method: str = "oidc-bearer",
) -> AdminIdentity | None:
    if not OIDC_ENABLED or not token:
        return None
    if not OIDC_ISSUER or not OIDC_AUDIENCE:
        raise OIDCAuthError("OIDC issuer and audience must be configured")
    if len(token.encode("utf-8")) > MAX_OIDC_BEARER_TOKEN_BYTES:
        raise OIDCAuthError("OIDC bearer token is too large")
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
    jwk = _oidc_key_for_header(header, algorithm)
    _verify_oidc_signature(algorithm, jwk, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2]))
    _validate_oidc_claims(payload, expected_nonce=expected_nonce)
    subject = payload.get(OIDC_SUBJECT_CLAIM)
    if not isinstance(subject, str) or not subject:
        raise OIDCAuthError("OIDC token subject is missing")
    roles = _roles_from_claim(payload.get(OIDC_ROLE_CLAIM))
    if not roles:
        raise OIDCAuthError("OIDC token is missing Catchplate RBAC roles")
    user_id = f"oidc:{subject}"
    return AdminIdentity(user_id, _authoritative_oidc_roles(user_id, roles), auth_method)


def oidc_session_token_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def oidc_session_token_is_well_formed(token: str | None) -> bool:
    return bool(
        isinstance(token, str)
        and _OIDC_SESSION_TOKEN_PATTERN.fullmatch(token) is not None
    )


def oidc_browser_session_from_token(token: str | None) -> dict[str, object] | None:
    if not OIDC_ENABLED or not OIDC_BROWSER_LOGIN_ENABLED or not token:
        return None
    if not oidc_session_token_is_well_formed(token):
        raise OIDCAuthError("OIDC browser session token is malformed")
    try:
        return db.get_oidc_browser_session(oidc_session_token_digest(token))
    except db.MetadataStoreError as exc:
        raise OIDCAuthoritativeStateError(
            "OIDC browser session state is unavailable"
        ) from exc


def oidc_browser_session_for_request(request: Request) -> dict[str, object] | None:
    cache = getattr(request, "_catchplate_auth_cache", None)
    if cache is None:
        cache = {}
        setattr(request, "_catchplate_auth_cache", cache)
    if "oidc_browser_session" not in cache:
        cache["oidc_browser_session"] = oidc_browser_session_from_token(
            request.cookies.get(OIDC_SESSION_COOKIE_NAME)
        )
    return cache["oidc_browser_session"]


def oidc_identity_from_session_token(token: str | None) -> AdminIdentity | None:
    if not OIDC_ENABLED or not OIDC_BROWSER_LOGIN_ENABLED or not token:
        return None
    if not oidc_session_token_is_well_formed(token):
        raise OIDCAuthError("OIDC browser session token is malformed")
    try:
        session = db.get_active_oidc_browser_session(oidc_session_token_digest(token))
    except db.MetadataStoreError as exc:
        raise OIDCAuthoritativeStateError(
            "OIDC browser session state is unavailable"
        ) from exc
    if session is None:
        raise OIDCAuthError("OIDC browser session is invalid, expired, or revoked")
    return oidc_identity_from_browser_session(session)


def oidc_identity_from_browser_session(
    session: dict[str, object],
) -> AdminIdentity | None:
    if session.get("status") != "active":
        return None
    credential_record_id = session.get("bound_webauthn_credential_id")
    if OIDC_SESSION_WEBAUTHN_REQUIRED and not credential_record_id:
        raise OIDCAuthError("OIDC browser session is not bound to WebAuthn")
    if credential_record_id:
        credential = session.get("_bound_credential")
        if "_bound_credential" not in session:
            credential = db.get_webauthn_credential_by_record_id(
                str(credential_record_id)
            )
        if credential is None or credential.get("user_id") != session.get("user_id"):
            raise OIDCAuthError("OIDC browser session WebAuthn binding is invalid")
        try:
            from catchplate.webauthn import credential_trust_status
            from catchplate.webauthn_trust import WebAuthnTrustError

            trust = credential_trust_status(credential)
        except WebAuthnTrustError as exc:
            raise OIDCAuthoritativeStateError(
                "WebAuthn attestation trust state is unavailable"
            ) from exc
        if (
            CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION
            and not trust.get("currently_trusted")
        ):
            raise OIDCAuthError("OIDC browser session WebAuthn trust is no longer valid")
        current_digest = trust.get("current_trust_bundle_digest")
        current_sequence = trust.get("current_trust_bundle_sequence")
        if (
            session.get("activation_trust_bundle_digest") != current_digest
            or session.get("activation_trust_bundle_sequence") != current_sequence
        ):
            raise OIDCAuthError(
                "OIDC browser session WebAuthn trust generation changed; sign in again"
            )
        effective_class = str(trust.get("effective_authenticator_class") or "unknown")
        activation_class = str(
            session.get("activation_authenticator_class") or "unknown"
        )
        if activation_class != effective_class:
            raise OIDCAuthError("OIDC browser session authenticator class changed")
        allowed_classes = set(CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES)
        credential_classes = {effective_class}
        if effective_class != "platform":
            credential_classes.add("hardware")
        if allowed_classes and not allowed_classes.intersection(credential_classes):
            raise OIDCAuthError("OIDC browser session authenticator is no longer allowed")
    user_id = str(session["user_id"])
    try:
        roles = frozenset(normalize_rbac_roles(session.get("roles", [])))
    except RBACRoleValidationError as exc:
        raise OIDCAuthError("OIDC browser session has invalid RBAC roles") from exc
    return AdminIdentity(
        user_id,
        _authoritative_oidc_roles(user_id, roles),
        "oidc-session",
    )


def oidc_pending_session_identity(session: dict[str, object]) -> AdminIdentity:
    if session.get("status") != "pending_webauthn":
        raise OIDCAuthError("OIDC browser session is not awaiting WebAuthn")
    user_id = str(session.get("user_id") or "")
    try:
        stored_roles = frozenset(normalize_rbac_roles(session.get("roles", [])))
    except RBACRoleValidationError as exc:
        raise OIDCAuthError("OIDC browser session has invalid RBAC roles") from exc
    if not user_id:
        raise OIDCAuthError("OIDC browser session identity is invalid")
    current_roles = _authoritative_oidc_roles(user_id, stored_roles)
    if current_roles != stored_roles:
        raise OIDCAuthError(
            "OIDC browser session roles changed; sign in again before WebAuthn"
        )
    return AdminIdentity(user_id, current_roles, "oidc-pending-session")


def require_admin(
    request: Request,
    x_catchplate_admin_token: str | None = Header(default=None, alias="X-Catchplate-Admin-Token"),
) -> AdminIdentity:
    bearer = request.headers.get("Authorization", "")
    bearer_token = bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else None
    cookie_token = request.cookies.get("catchplate_admin")
    oidc_cookie_token = request.cookies.get(OIDC_SESSION_COOKIE_NAME)
    if check_admin_token(x_catchplate_admin_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "admin-token-header")
    if check_admin_token(bearer_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "bearer-token")
    try:
        oidc_identity = oidc_identity_from_token(bearer_token)
    except OIDCAuthoritativeStateError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except OIDCAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OIDCAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    if oidc_identity:
        return oidc_identity
    if check_admin_token(cookie_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "admin-cookie")
    try:
        oidc_session = oidc_browser_session_for_request(request)
        if oidc_cookie_token and oidc_session is None:
            raise OIDCAuthError("OIDC browser session is invalid, expired, or revoked")
        oidc_cookie_identity = (
            oidc_identity_from_browser_session(oidc_session)
            if oidc_session is not None
            else None
        )
    except OIDCAuthoritativeStateError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except OIDCAccessDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OIDCAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    if oidc_cookie_identity:
        return oidc_cookie_identity
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="admin authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _bearer_token(request: Request) -> str | None:
    bearer = request.headers.get("Authorization", "")
    return bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else None


def _request_has_valid_non_cookie_admin_auth(request: Request) -> bool:
    if check_admin_token(request.headers.get("X-Catchplate-Admin-Token")) or check_admin_token(_bearer_token(request)):
        return True
    try:
        return oidc_identity_from_token(_bearer_token(request)) is not None
    except (OIDCAuthError, OIDCAccessDenied, OIDCAuthoritativeStateError):
        return False


def _csrf_cookie_secure(request: Request) -> bool:
    raw = os.getenv("CATCHPLATE_CSRF_COOKIE_SECURE")
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
    cookie_admin_token = request.cookies.get("catchplate_admin")
    oidc_cookie_token = request.cookies.get(OIDC_SESSION_COOKIE_NAME)
    oidc_cookie_valid = oidc_session_token_is_well_formed(oidc_cookie_token)
    try:
        if oidc_cookie_valid:
            oidc_browser_session_for_request(request)
    except (OIDCAuthError, OIDCAccessDenied, OIDCAuthoritativeStateError):
        oidc_cookie_valid = False
    if not check_admin_token(cookie_admin_token) and not oidc_cookie_valid:
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
    try:
        required = set(normalize_rbac_roles(roles))
    except RBACRoleValidationError as exc:
        raise RuntimeError("control-plane endpoint declares invalid RBAC roles") from exc

    def dependency(identity: AdminIdentity = Depends(require_admin)) -> AdminIdentity:
        identity = _refresh_oidc_authorization(identity)
        if identity.has_any_role(required):
            return identity
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"required role: {' or '.join(sorted(required))}",
        )

    return dependency


def admin_status() -> dict[str, object]:
    token_source = ADMIN_TOKEN_SOURCE if ADMIN_TOKEN else "generated-file"
    return {
        "admin_auth_required": True,
        "token_source": token_source,
        "generated_token_path": None if ADMIN_TOKEN else str(ADMIN_TOKEN_PATH),
        "admin_user_id": ADMIN_USER_ID,
        "admin_roles": list(ADMIN_ROLES),
        "oidc": {
            "enabled": OIDC_ENABLED,
            "issuer": OIDC_ISSUER or None,
            "audience": OIDC_AUDIENCE or None,
            "role_claim": OIDC_ROLE_CLAIM,
            "subject_claim": OIDC_SUBJECT_CLAIM,
            "allowed_algorithms": list(OIDC_ALLOWED_ALGORITHMS),
            "browser_login_enabled": OIDC_BROWSER_LOGIN_ENABLED,
            "browser_session_webauthn_required": OIDC_SESSION_WEBAUTHN_REQUIRED,
            "browser_login_configured": bool(
                OIDC_ENABLED
                and OIDC_BROWSER_LOGIN_ENABLED
                and OIDC_AUTHORIZATION_ENDPOINT
                and OIDC_TOKEN_ENDPOINT
                and OIDC_CLIENT_ID
            ),
        },
        "csrf": {
            "cookie_protection": "double-submit",
            "cookie_name": CSRF_COOKIE_NAME,
            "header_name": CSRF_HEADER_NAME,
            "unsafe_methods": sorted(UNSAFE_METHODS),
        },
    }
