"""Fixed per-role sealed bootstrap handoff into genuine registration admission.

Only the public bootstrap pathname is replaced by an inherited sealed original.
The existing root/key/TLS/journal paths, signature admission, activated listener,
descriptor roster and privilege drop remain owned by each real entrypoint.
"""
from __future__ import annotations

import importlib
import os

BOOTSTRAP_INPUT_FD = 50
_MODULES = frozenset({
    "registration_execution_authorizer_entrypoint",
    "registration_execution_reserver_entrypoint",
    "registration_execution_sql_entrypoint",
    "registration_execution_completion_entrypoint",
    "registration_finalization_authorizer_entrypoint",
    "registration_finalization_reserver_entrypoint",
    "registration_finalization_sql_entrypoint",
    "registration_finalization_completion_entrypoint",
})


def _fixed(module_name):
    if type(module_name) is not str or module_name not in _MODULES:
        raise ValueError("registration delivery module is not source fixed")
    return importlib.import_module("catchplate." + module_name)


def _incoming(module_name, selected):
    if type(selected) is not bool:
        raise ValueError("registration original delivery mode is not a boolean")
    fixed = _fixed(module_name)
    if not selected:
        return None
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("registration original delivery must begin as root")
    return fixed._sealed_identity(BOOTSTRAP_INPUT_FD, fixed.MAX_BOOTSTRAP_BYTES)


def _source(module_name, identity):
    fixed = _fixed(module_name)
    if identity is None or fixed._sealed_identity(BOOTSTRAP_INPUT_FD, fixed.MAX_BOOTSTRAP_BYTES) != identity:
        raise RuntimeError("registration sealed bootstrap original changed")
    return BOOTSTRAP_INPUT_FD
