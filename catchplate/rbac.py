from __future__ import annotations

from collections.abc import Iterable


VALID_RBAC_ROLES = frozenset(
    {
        "admin",
        "approver",
        "attestation_operator",
        "attestation_reviewer",
        "auditor",
        "credential_owner",
        "policy_author",
        "policy_publisher",
    }
)


class RBACRoleValidationError(ValueError):
    def __init__(self, message: str, *, invalid_roles: Iterable[str] = ()):
        super().__init__(message)
        self.invalid_roles = tuple(sorted(set(invalid_roles)))


def normalize_rbac_roles(
    roles: object,
    *,
    require_nonempty: bool = True,
) -> list[str]:
    if not isinstance(roles, (list, tuple, set, frozenset)):
        raise RBACRoleValidationError("RBAC roles must be a collection of strings")
    normalized: list[str] = []
    for role in roles:
        if not isinstance(role, str) or not role or role != role.strip():
            raise RBACRoleValidationError(
                "RBAC roles must be non-empty, trimmed strings"
            )
        normalized.append(role)
    if len(normalized) != len(set(normalized)):
        raise RBACRoleValidationError("RBAC roles must not contain duplicates")
    invalid = set(normalized) - VALID_RBAC_ROLES
    if invalid:
        raise RBACRoleValidationError(
            "RBAC roles contain values outside the closed vocabulary",
            invalid_roles=invalid,
        )
    normalized.sort()
    if require_nonempty and not normalized:
        raise RBACRoleValidationError("at least one RBAC role is required")
    return normalized
