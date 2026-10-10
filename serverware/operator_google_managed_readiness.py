"""Observe the exact committed managed app/gate pair, never grant authority.

Two brief publication-owned read snapshots surround one bounded gate request.
No publication or SQLite ownership crosses HTTP. The result is a point-in-time
observation, not provider health, hardware readiness or a credential lease.
The matching unconfigured pair may be ready for its static policy; consent also
requires a configured, non-null operation and the existing profile/CAS guards.
"""
from __future__ import annotations

import re
import uuid

_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _require(value):
    if not value:
        raise RuntimeError("operator Google managed observation unavailable")


def _digest(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _identity(value):
    """Close the public shape before equality (bool is not config version 1)."""
    from serverware.operator_provider_custody import MAX_VERSIONS
    _require(type(value) is dict and set(value) == {
        "operation", "profile_binding_digest", "effective_settings_digest"})
    _require(_digest(value["effective_settings_digest"]))
    operation = value["operation"]
    if operation is None:
        _require(value["profile_binding_digest"] is None)
    else:
        _require(type(operation) is dict and set(operation) == {"operation_id", "owner_id", "config_version"}
            and type(operation["config_version"]) is int and 1 <= operation["config_version"] <= MAX_VERSIONS
            and _digest(value["profile_binding_digest"]))
        for name in ("operation_id", "owner_id"):
            item = operation[name]
            _require(type(item) is str and len(item) == 36 and str(uuid.UUID(item)) == item)
    return value


def _snapshot():
    """Fresh existing read-only database; no db.connect or initialization."""
    from serverware import config, operator_demo, operator_google_gate_configuration as public
    from serverware import operator_google_managed_config as managed, operator_google_setup as setup
    from serverware import operator_publication as publication
    from serverware.development_sandbox import _open_directory

    publication.assert_not_held()
    with publication.exclusive():
        with publication.closing_fd(_open_directory(publication._directory())) as descriptor:
            with publication._read_database(descriptor) as conn:
                _require(conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
                identity = _identity(public.expected_identity(conn))
                process = managed.committed_identity()
                operation = identity["operation"]
                _require(process == (None if operation is None else {
                    **operation, "profile_binding_digest": identity["profile_binding_digest"]}))
                settings = operator_demo.settings()
                _require(identity["effective_settings_digest"] == setup._digest({
                    key: settings[key] for key in ("allowed_upstreams", "fixture_cidrs")}))
                row = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
                _require(row is not None and _digest(row[0])
                    and _digest(config.EXPECTED_DATA_PLANE_BINARY_DIGEST))
                return {"policy_hash": row[0], "managed_google": identity,
                    "expected_binary_digest": config.EXPECTED_DATA_PLANE_BINARY_DIGEST}


def observe() -> dict:
    """Fixed public outcome; unavailable observation never implies rollback.

    Must be called outside ALL caller-owned publication/SQLite transactions.
    The publication guard also refuses an outer EX rather than polling from a
    nested scope. No state, key or public artifact is created or repaired.
    """
    result = {"ready": False, "policy_hash": None, "loaded_policy_hash": None, "managed_google": None}
    try:
        from serverware import operator_google_managed_config as managed
        from serverware import operator_publication as publication

        publication.assert_not_held()
        if not managed.enabled():
            return result
        from serverware import operator_demo_store as store
        before = _snapshot()
        result.update(policy_hash=before["policy_hash"], managed_google=before["managed_google"])
        publication.assert_not_held()
        observed = store.loaded_gate_status()
        if observed is None:
            return result
        result["loaded_policy_hash"] = observed["policy_hash"]
        shadow = observed.get("policy_shadow")
        _require(type(shadow) is dict)
        identity = _identity(shadow.get("managed_google"))
        after = _snapshot()
        result.update(policy_hash=after["policy_hash"], managed_google=after["managed_google"])
        result["ready"] = (before == after and observed.get("ok") is True
            and _digest(observed.get("policy_hash"))
            and observed["policy_hash"] == after["policy_hash"]
            and type(observed.get("data_plane_binary_digest")) is str
            and observed["data_plane_binary_digest"] == after["expected_binary_digest"]
            and identity == after["managed_google"])
    except Exception:
        # Never serialize configured paths, ciphertext, secret material or a
        # transport/SQLite error. A failed observer cannot undo a prior commit.
        result["ready"] = False
    return result
