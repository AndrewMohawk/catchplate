"""Fixed raw-FD delivery into the eight genuine execution cold owners.

This changes public-original transport only. Each selected source entrypoint
still authenticates the actual signed bootstrap and custody before opening
private keys, TLS or journals and performing its unchanged permanent drop.
No supplied admission result, pathname override or renewed interval is used.
"""
from __future__ import annotations

import importlib
import os


_MODULES = {
    "activation-authorizer": "oidc_session_activation_execution_authorizer_entrypoint",
    "activation-reserver": "oidc_session_activation_execution_reserver_entrypoint",
    "activation-sql": "oidc_session_activation_execution_sql_entrypoint",
    "activation-completion": "oidc_session_activation_completion_entrypoint",
    "consume-authorizer": "oidc_session_activation_delivery_execution_authorizer_entrypoint",
    "consume-reserver": "oidc_session_activation_delivery_execution_reserver_entrypoint",
    "consume-sql": "oidc_session_activation_delivery_execution_sql_entrypoint",
    "consume-completion": "oidc_session_activation_delivery_completion_entrypoint",
}
FIRST_ORIGINAL_FD = 50


def _incoming(module_name, selected):
    if type(selected) is not bool or module_name not in _MODULES.values():
        raise RuntimeError("execution original delivery profile is not source fixed")
    if not selected:
        return {}
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("execution raw originals require the real root delivery process")
    fixed = importlib.import_module("serverware." + module_name)
    incoming = {}
    for index, (path, _target, maximum) in enumerate(fixed._TRUST_FILES):
        descriptor = FIRST_ORIGINAL_FD + index
        identity = fixed._sealed_identity(descriptor, maximum)
        incoming[path] = (descriptor, maximum, identity, fixed)
    return incoming


def _source(path, maximum, incoming, *, work=None, maximum_capture_bytes=None):
    # Only the literal source roster above supplies these private records.
    descriptor, bound, identity, fixed = incoming.pop(path)
    if bound != maximum or fixed._sealed_identity(descriptor, maximum) != identity:
        raise RuntimeError("execution raw original changed before genuine cold admission")
    size = identity[0][6]
    if maximum_capture_bytes is not None and (type(maximum_capture_bytes) is not int
            or maximum_capture_bytes <= 0 or 16 * size > maximum_capture_bytes):
        raise RuntimeError("execution raw original exceeds original cold capture capacity")
    if work is not None:
        # Preserve the existing file-read reservation even though the already
        # sealed original does not require another read-and-seal copy here.
        work.charge(input_bytes=2 * size)
    return descriptor


def main(role):
    if type(role) is not str or role not in _MODULES:
        raise RuntimeError("execution dynamic role is not source fixed")
    fixed = importlib.import_module("serverware." + _MODULES[role])
    return fixed.main(_sealed_originals=True)
