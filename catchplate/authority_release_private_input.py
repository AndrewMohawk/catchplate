"""Temporary refusal of private JIT documents on legacy release inputs.

This is not a new private profile or a custody/approval validator. New release
submissions and retention must not store the raw nested JIT request while its
compound private producer is unavailable. Missing/null nested requests keep
their existing meaning, including existing-grant lookup. Nothing is rewritten.

Historical request validation, retained reads and committed replay deliberately
do not use these new-submission guards.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


OPERATIONS = frozenset({"release.reserve", "release.v1.reserve"})
ERROR = "Private JIT release input requires its explicit private profile"


class PrivateReleaseInputError(ValueError):
    def __init__(self) -> None:
        super().__init__(ERROR)


def require_public_arguments(operation: Any, arguments: Any) -> None:
    """Refuse the private field only; leave all other validation to its owner."""
    if (isinstance(operation, str) and operation in OPERATIONS
            and isinstance(arguments, Mapping)
            and arguments.get("jit_approval_request") is not None):
        raise PrivateReleaseInputError()


def require_public_request(request: Any, *, operation: Any = None) -> None:
    """Check both the request operation and an optional enclosing operation.

    The enclosing plan/envelope cannot hide a private request by contradicting
    its operation tag. Existing owners still reject all malformed bindings.
    """
    if isinstance(request, Mapping):
        arguments = request.get("arguments")
        require_public_arguments(request.get("operation"), arguments)
        require_public_arguments(operation, arguments)
