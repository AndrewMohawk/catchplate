from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request, status

from serverware.config import ADMIN_ROLES, ADMIN_TOKEN_PATH, ADMIN_USER_ID, ensure_data_dirs


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
    if check_admin_token(cookie_token):
        return AdminIdentity(ADMIN_USER_ID, frozenset(ADMIN_ROLES), "admin-cookie")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="admin authentication required",
        headers={"WWW-Authenticate": "Bearer"},
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
    }
