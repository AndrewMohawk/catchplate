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
_START_ERROR = "operator Google managed consent unavailable"


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


def _observe(*, require_x: bool = False, require_alchemy: bool = False) -> dict:
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
        if require_x:
            from serverware.operator_catalog_x import gate_descriptor_matches
            _require(gate_descriptor_matches(observed.get("operator_x_app_read")))
        if require_alchemy:
            from serverware.operator_catalog_alchemy import gate_descriptor_matches
            _require(gate_descriptor_matches(observed.get("operator_alchemy_rpc_read")))
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


def observe() -> dict:
    """Observe the existing exact managed pair without a provider-adapter check."""
    return _observe()


def observe_x() -> dict:
    """Join X compatibility to that same fresh, exactly bound gate response."""
    return _observe(require_x=True)


def observe_alchemy() -> dict:
    """Join Alchemy compatibility to the same fresh, exactly bound gate response."""
    return _observe(require_alchemy=True)


def _start_observation(value):
    """Validate and detach the closed, non-capability consent observation."""
    _require(type(value) is dict and set(value) == {
        "ready", "policy_hash", "loaded_policy_hash", "managed_google"}
        and value["ready"] is True and _digest(value["policy_hash"])
        and _digest(value["loaded_policy_hash"])
        and value["policy_hash"] == value["loaded_policy_hash"])
    identity = _identity(value["managed_google"])
    _require(identity["operation"] is not None)
    return {"ready": True, "policy_hash": value["policy_hash"],
        "loaded_policy_hash": value["loaded_policy_hash"], "managed_google": {
            "operation": dict(identity["operation"]),
            "profile_binding_digest": identity["profile_binding_digest"],
            "effective_settings_digest": identity["effective_settings_digest"]}}


def capture_start():
    """Observe before consent owns a publication lock or SQLite transaction.

    Disabled managed configuration preserves the legacy path without any gate
    request. This point-in-time observation is not a lease or provider health.
    The caller must recheck it with require_start before its first local write.
    """
    try:
        from serverware import operator_google_managed_config as managed
        if not managed.enabled():
            return None
        from serverware import operator_publication as publication
        publication.assert_not_held()
        return _start_observation(observe())
    except Exception:
        from serverware.operator_catalog_schema import CatalogConflict
        raise CatalogConflict(_START_ERROR) from None


def _start_writer(conn):
    """Admit the caller's fresh BEGIN IMMEDIATE connection, never acquire it.

    Consent callers establish BEGIN IMMEDIATE. Python's connection attributes
    prove an active writable transaction, not SQLite's reserved-lock state; no
    lock probe, no-op write or second connection is used to manufacture proof.
    """
    import sqlite3
    from serverware import config, operator_publication as publication

    publication.assert_held()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction
        and conn.total_changes == 0
        and conn.execute("PRAGMA query_only").fetchone()[0] == 0
        and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
    databases = conn.execute("PRAGMA database_list").fetchall()
    _require(len(databases) == 1 and tuple(databases[0]) == (0, "main", str(config.DB_PATH)))


def require_start(conn, observation):
    """Recheck only local state in the consent writer before any writes.

    This does not call the gate or the public projection's fresh query-only
    entrypoint. It reuses that projection's retained settings decoder without
    weakening its separate read-only admission contract. Callback, refresh,
    disconnect and existing-intent recovery do not use this new-start guard.
    """
    try:
        from serverware import operator_google_managed_config as managed
        if not managed.enabled():
            return
        captured = _start_observation(observation)
        _start_writer(conn)
        from serverware import operator_catalog_oauth_profile as profiles, operator_demo
        from serverware import operator_google_gate_configuration as public, operator_google_setup as setup

        selected = managed.validate_selection(conn)
        _require(type(selected) is dict and selected["schema"] == setup.MANAGED_PUBLIC_V2
            and selected["setup_contract"] == setup.MANAGED_BINDING_V2
            and selected["status"] == "activated" and selected["activation_receipt"] is not None)
        profile = profiles.require_profile()
        _require(selected["profile_binding"] == profiles._record(profile.client_id, profile.redirect_uri)
            and selected["profile_binding_digest"] == profile.binding_digest)
        settings = public._settings(conn)
        process_settings = operator_demo.settings()
        _require(settings == {key: process_settings[key] for key in ("allowed_upstreams", "fixture_cidrs")}
            and set(profiles.API_ORIGINS) <= set(settings["allowed_upstreams"]))
        reference = selected["custody_ref"]
        identity = _identity({"operation": {"operation_id": selected["operation_id"],
            "owner_id": reference["owner_id"], "config_version": reference["config_version"]},
            "profile_binding_digest": selected["profile_binding_digest"],
            "effective_settings_digest": setup._digest(settings)})

        committed = managed.committed_identity()
        _require(type(committed) is dict and set(committed) == {
            "operation_id", "owner_id", "config_version", "profile_binding_digest"})
        process_identity = _identity({"operation": {key: committed[key] for key in (
            "operation_id", "owner_id", "config_version")},
            "profile_binding_digest": committed["profile_binding_digest"],
            "effective_settings_digest": setup._digest({
                key: process_settings[key] for key in ("allowed_upstreams", "fixture_cidrs")})})
        _require(identity == process_identity == captured["managed_google"])
        rows = conn.execute("SELECT singleton,policy_hash FROM operator_demo_policy LIMIT 2").fetchall()
        _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1
            and _digest(rows[0][1]) and rows[0][1] == captured["policy_hash"])
        _start_writer(conn)
    except Exception:
        from serverware.operator_catalog_schema import CatalogConflict
        raise CatalogConflict(_START_ERROR) from None
