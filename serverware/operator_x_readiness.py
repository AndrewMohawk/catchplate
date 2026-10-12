"""Point-in-time ordinary X app/gate joins, not provider or release authority.

Standalone observations bracket exactly one existing local health request with
read-only snapshots. Catalog observations reuse its already received health
document without another request. No observer publishes files or repairs state.
New consent/grant writers must recheck the captured join before their first write.
"""
from __future__ import annotations

import re
import uuid

_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ERROR = "operator X readiness unavailable"
_DESCRIPTOR = {"schema": "serverware.operatorXPostGate/v1",
    "adapter": "x.post.v1", "operation": "tweets.write"}
_FETCH = object()


def _require(condition):
    if not condition:
        raise RuntimeError(_ERROR)


def _digest(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _identity(value):
    _require(type(value) is dict and set(value) == {
        "operation", "profile_binding_digest", "effective_settings_digest"}
        and _digest(value["effective_settings_digest"]))
    operation = value["operation"]
    if operation is None:
        _require(value["profile_binding_digest"] is None)
    else:
        _require(type(operation) is dict and set(operation) == {
            "operation_id", "owner_id", "config_version"}
            and type(operation["config_version"]) is int and operation["config_version"] == 1
            and _digest(value["profile_binding_digest"]))
        for key in ("operation_id", "owner_id"):
            item = operation[key]
            _require(type(item) is str and len(item) == 36 and str(uuid.UUID(item)) == item)
    return value


def _local(conn, *, query_only):
    from serverware import config, operator_demo, operator_x_gate_configuration as public
    from serverware.operator_x_oauth_profile import API_ORIGINS
    document = public._project(conn, query_only=query_only)
    settings = operator_demo.settings()
    _require(document["effective_settings"] == {
        key: settings[key] for key in ("allowed_upstreams", "fixture_cidrs")})
    rows = conn.execute("SELECT singleton,policy_hash FROM operator_demo_policy LIMIT 2").fetchall()
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1
        and _digest(rows[0][1]) and _digest(config.EXPECTED_DATA_PLANE_BINARY_DIGEST))
    identity = _identity({key: document[key] for key in (
        "operation", "profile_binding_digest", "effective_settings_digest")})
    return {"policy_hash": rows[0][1], "managed_x": identity,
        "expected_binary_digest": config.EXPECTED_DATA_PLANE_BINARY_DIGEST,
        "destination_allowed": set(API_ORIGINS) <= set(document["effective_settings"]["allowed_upstreams"])}


def _snapshot():
    from serverware import operator_publication as publication
    from serverware.development_sandbox import _open_directory
    publication.assert_not_held()
    with publication.exclusive():
        with publication.closing_fd(_open_directory(publication._directory())) as directory:
            with publication._read_database(directory) as conn:
                return _local(conn, query_only=True)


def _observe(document=_FETCH):
    result = {"ready": False, "policy_hash": None, "loaded_policy_hash": None, "managed_x": None}
    try:
        from serverware import operator_publication as publication, operator_x_admission as admission
        publication.assert_not_held()
        if not admission.enabled() or document is None:
            return result
        before = _snapshot()
        result.update(policy_hash=before["policy_hash"], managed_x=before["managed_x"])
        if document is _FETCH:
            from serverware import operator_demo_store as store
            publication.assert_not_held()
            document = store.loaded_gate_status()
        _require(type(document) is dict and _digest(document.get("policy_hash")))
        result["loaded_policy_hash"] = document["policy_hash"]
        shadow = document.get("policy_shadow")
        _require(type(shadow) is dict)
        identity = _identity(shadow.get("managed_x"))
        after = _snapshot()
        result.update(policy_hash=after["policy_hash"], managed_x=after["managed_x"])
        result["ready"] = (before == after and document.get("ok") is True
            and identity["operation"] is not None and after["destination_allowed"] is True
            and document["policy_hash"] == after["policy_hash"]
            and document.get("data_plane_binary_digest") == after["expected_binary_digest"]
            and identity == after["managed_x"]
            and type(document.get("operator_x_post")) is dict
            and document["operator_x_post"] == _DESCRIPTOR)
    except Exception:
        result["ready"] = False
    return result


def observe():
    """Exactly one bounded local gate request, never under publication EX."""
    return _observe()


def observe_health(document):
    """Display-only reuse of actual catalog health; None never triggers HTTP."""
    return _observe(document)


def _captured(value):
    _require(type(value) is dict and set(value) == {
        "ready", "policy_hash", "loaded_policy_hash", "managed_x"}
        and value["ready"] is True and _digest(value["policy_hash"])
        and value["loaded_policy_hash"] == value["policy_hash"])
    identity = _identity(value["managed_x"])
    _require(identity["operation"] is not None)
    return {"ready": True, "policy_hash": value["policy_hash"],
        "loaded_policy_hash": value["loaded_policy_hash"], "managed_x": {
            **identity, "operation": dict(identity["operation"])}}


def capture_start():
    """Capture outside the writer; callbacks and existing work do not use this."""
    try:
        return _captured(observe())
    except Exception:
        from serverware.operator_catalog_schema import CatalogConflict
        raise CatalogConflict(_ERROR) from None


def require_start(conn, observation):
    """Local recheck under a fresh caller-owned BEGIN IMMEDIATE; no HTTP."""
    try:
        captured = _captured(observation)
        current = _local(conn, query_only=False)
        _require(current["destination_allowed"] is True
            and current["managed_x"] == captured["managed_x"]
            and current["policy_hash"] == captured["policy_hash"])
    except Exception:
        from serverware.operator_catalog_schema import CatalogConflict
        raise CatalogConflict(_ERROR) from None
