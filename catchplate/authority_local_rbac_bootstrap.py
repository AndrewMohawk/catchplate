"""Explicit initial local RBAC timestamp selection, not an observed DB head.

The offline pilot coordinator selects this value once inside its original
window so the signed witness can name the expected initial authenticated row.
Normal bootstrap still obtains its timestamp from PostgreSQL. This helper
grants no database privilege, initializes nothing and cannot refresh a window.
"""
from datetime import datetime, timezone
import os
import time

from catchplate import config
from catchplate.authority_local_limits import LOCAL_SETUP_MAX_NS

FIELDS = frozenset({"initialRbacTimestamp", "issuedAtUnixNanos", "expiresAtUnixNanos"})
WINDOW_NS = LOCAL_SETUP_MAX_NS


def selected_timestamp(selection: dict) -> str:
    development = {"dev", "development", "local", "test"}
    if (config.PRODUCTION_IMAGE or config._production_release()
            or os.environ.get("CATCHPLATE_PRODUCTION_IMAGE", "0") == "1"
            or os.environ.get("CATCHPLATE_RELEASE_CHANNEL", "dev").strip().lower() not in development
            or os.environ.get("CATCHPLATE_PROCESS_MODE", "").strip() != "metadata-bootstrap"
            or type(selection) is not dict or set(selection) != FIELDS
            or any(type(value) is not int for value in selection.values())):
        raise ValueError("explicit initial local RBAC timestamp refused")
    issued, selected, expiry = (selection[name] for name in
        ("issuedAtUnixNanos", "initialRbacTimestamp", "expiresAtUnixNanos"))
    now = time.time_ns()
    if (type(now) is not int or not 0 < issued <= selected <= now < expiry < 2**63
            or expiry - issued > WINDOW_NS or selected % 1000):
        raise ValueError("initial RBAC timestamp is outside its original local window")
    seconds, nanos = divmod(selected, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos // 1000).isoformat()
