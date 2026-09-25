"""Source-fixed completion-reader privileges; no installation or DB access.

The genuine generic read-role catalog query checks effective privileges, role
membership, grant options and PUBLIC paths. Only its required table inventory
changes: marker and complete primary/count heads, never business rows. The
role must be independently provisioned; bootstrap seals these exact grants.
An empty violation result is ACL evidence, not commit/currentness authority.
"""
from __future__ import annotations

from typing import Final

from serverware import authority_contract
from serverware.authority_store.verifier_read_sql import (
    VERIFIER_READ_PRIVILEGE_SQL_DIGEST,
    verifier_read_privilege_check,
)


COMPLETION_READER_ROLE: Final[str] = authority_contract.COMPLETION_READER_ROLE
COMPLETION_READ_TABLES: Final[frozenset[str]] = authority_contract.COMPLETION_READ_TABLES
COMPLETION_READ_PRIVILEGE_SQL_DIGEST: Final[str] = VERIFIER_READ_PRIVILEGE_SQL_DIGEST


def completion_read_privilege_check(
    *, role: str, namespace: str
) -> tuple[str, tuple[str, str, list[str]]]:
    """Return the actual generic checker with only the exact three-table scope."""
    if type(role) is not str or role != COMPLETION_READER_ROLE:
        raise ValueError("completion read role differs from its fixed source identity")
    sql, _parameters = verifier_read_privilege_check(role=role, namespace=namespace)
    return sql, (role, namespace, sorted(COMPLETION_READ_TABLES))
