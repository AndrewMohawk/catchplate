"""Public retained X configuration for the separately running ordinary gate.

The existing publication owner exports this projection with the signed policy.
It contains no client secret or token, performs no initialization, and does not
authorize consent or posting. A configured profile can precede destination
approval; the readiness observer separately requires the approved API origin.
"""
from __future__ import annotations

import sqlite3

SCHEMA = "serverware.operatorXGateConfiguration/v1"
FILENAME = "operator-x-configuration.json"
MAX_BYTES = 32768
_ERROR = "operator X gate configuration unavailable"


class GateConfigurationUnavailable(RuntimeError):
    """Fixed public refusal without retained paths or material."""


def _require(condition):
    if not condition:
        raise GateConfigurationUnavailable(_ERROR)


def _admit(conn, *, query_only):
    from serverware import operator_publication as publication, operator_x_admission as admission
    publication.assert_held()
    directory = admission.require_runtime()
    admission.check_connection(conn, directory)
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction
        and conn.total_changes == 0
        and conn.execute("PRAGMA query_only").fetchone()[0] == int(query_only)
        and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)


def _project(conn, *, query_only=True):
    from serverware import operator_google_gate_configuration as google_public
    from serverware import operator_google_setup as setup, operator_x_configuration as configuration
    from serverware import operator_x_admission as admission, operator_x_provider_custody as custody
    _admit(conn, query_only=query_only)
    # Deliberately the same retained decoder and canonical digest as Google.
    # Selecting X never appends an upstream or changes fixture CIDRs.
    settings = google_public._settings(conn)
    selected = configuration.retained_public_binding(conn)
    result = {"schema": SCHEMA, "operation": None, "profile_binding": None,
        "profile_binding_digest": None, "effective_settings": settings,
        "effective_settings_digest": setup._digest(settings)}
    if selected is not None:
        owner = admission.admit_owner(selected["owner_id"])
        _require(custody.inspect_public_roster(conn, owner) == ({"schema": custody.SCHEMA,
            "owner_id": selected["owner_id"], "config_version": 1,
            "public_profile": selected["public_profile"], "secret_present": True},))
        result.update(operation={key: selected[key] for key in (
            "operation_id", "owner_id", "config_version")},
            profile_binding=selected["public_profile"],
            profile_binding_digest=selected["profile_binding_digest"])
    _require(len(setup._canonical(result).encode("ascii")) <= MAX_BYTES)
    _admit(conn, query_only=query_only)
    return result


def record(conn):
    """Project a fresh query-only transaction under the original EX owner."""
    try:
        return _project(conn)
    except Exception:
        raise GateConfigurationUnavailable(_ERROR) from None


def expected_identity(conn):
    value = record(conn)
    return {key: value[key] for key in (
        "operation", "profile_binding_digest", "effective_settings_digest")}
