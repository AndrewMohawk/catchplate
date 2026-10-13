"""Read-only compound originals from the actual release facade's arguments.

This producer applies the installed facade's real defaults and marshaling but
never calls it. The resulting original strings are authenticated only by the
control plane's existing HTTP response signer. They are not native admission,
sealing, writer authority, a pending approval, or permission to release.
The endpoint requires preprovisioned shared PostgreSQL metadata/grant sources;
read-only here describes business state, not a new database bootstrap lifecycle.
"""
from __future__ import annotations

import inspect

from serverware import authority_release_private_request as private
from serverware import authority_transition_core as core
from serverware import db
from serverware.authority_store import authority_dispatch


PATH = "/api/data-plane/release-authorizations/native-jit-prepare"
SCHEMA = "serverware.nativeReleaseJitPreparation/v1"
MAX_RESPONSE_BYTES = 512 * 1024


class PreparationError(ValueError):
    pass


def prepare(reserve_arguments: dict) -> dict[str, str]:
    """Derive exact originals without invoking a facade, writer or broker."""
    try:
        if (type(reserve_arguments) is not dict
                or any(type(name) is not str or name.startswith("_")
                    or name in authority_dispatch._AUTHORITY_INTERNAL_ARGUMENTS
                    for name in reserve_arguments)):
            raise ValueError("release arguments are not public facade inputs")
        # @wraps preserves the installed controlled writer's original signature.
        # Never duplicate the facade's defaults or call its underlying handler.
        signature = inspect.signature(db.reserve_release_authorization_v2)
        bound = signature.bind(**reserve_arguments)
        bound.apply_defaults()
        if set(bound.arguments) != private.FIELDS:
            raise ValueError("release facade fields changed")
        marshaled = authority_dispatch._authority_marshal_value(dict(bound.arguments))
        runtime_input = private.prepare(marshaled)
        requests = private.derive_native_requests(runtime_input)
        return {
            "runtimeInput": core.canonical_bytes(runtime_input).decode("ascii"),
            "parentRequest": core.canonical_bytes(requests.parent_request).decode("ascii"),
            "childRequest": core.canonical_bytes(requests.child_request).decode("ascii"),
        }
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError,
            core.TransitionKernelError, db.MetadataStoreError):
        raise PreparationError("native JIT release preparation is unavailable") from None
