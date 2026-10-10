"""Read-only discovery of the exact retained managed Google configuration.

Discovery does not prepare, activate, choose history, open ciphertext or grant
serving authority. Existing catalog/profile/policy owners validate one fresh
read-only snapshot. Gate observation runs outside every local lock/transaction,
then a second snapshot suppresses readiness if discovery changed meanwhile.
"""
from __future__ import annotations

import os

SCHEMA = "serverware.operatorGoogleConfiguration/v2"
_FLAG = "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED"
_ERROR = "operator Google configuration unavailable"


class ConfigurationUnavailable(LookupError):
    """This source feature is disabled; no storage access was attempted."""


def _require(value):
    if not value:
        raise RuntimeError(_ERROR)


def _review(value, rows, *, pending_destinations):
    """Render the existing eligible v2 CAS review, never call a write owner."""
    from serverware import operator_google_setup as setup, operator_provider_custody as custody
    from serverware import operator_catalog_oauth_profile as profiles
    if value["state"] == "pending":
        return "pending_configuration", None
    if value["state"] == "activated":
        return "already_configured", None
    _require(all(row["status"] == "cancelled" and setup._managed_configuration(row) for row in rows))
    if pending_destinations:
        return "pending_destinations", None
    old = value["effective_settings"]
    if (len(rows) >= min(setup.MAX_OPERATIONS, custody.MAX_VERSIONS)
            or len(set(old["allowed_upstreams"]) | set(profiles.API_ORIGINS)) > 16):
        return "capacity", None
    return None, {"schema": "serverware.operatorGoogleManagedSetupReview/v2",
        "expected_revision": value["revision"], "expected_policy_hash": value["policy_hash"],
        "expected_settings_digest": value["effective_settings_digest"],
        "old_settings": old, "target_settings": setup._target(old),
        "public_url": value["public_url"], "redirect_uri": value["redirect_uri"],
        "provider_id": "google", "permission_preset": value["permission_preset"],
        "scopes": list(value["scopes"]), "eligible": True}


def _snapshot(actor_id):
    from serverware import config, operator_demo, operator_publication as publication
    from serverware import operator_catalog_oauth_profile as profiles, operator_catalog_schema as catalog
    from serverware import operator_catalog_policy as policy, operator_google_gate_configuration as public
    from serverware import operator_google_setup as setup, operator_google_managed_selection as selection
    from serverware import operator_upstream_setup as upstream
    from serverware.development_sandbox import _open_directory

    setup._actor(actor_id)
    publication.assert_not_held()
    with publication.exclusive():
        with publication.closing_fd(_open_directory(publication._directory())) as descriptor:
            with publication._read_database(descriptor) as conn:
                projected = public.record(conn)  # Strict managed/dev/committed-read admission.
                rows = setup._rows(conn)
                selected = selection._validate_items(conn, rows)
                state = "unconfigured" if selected is None else selected["status"]
                _require(state in {"unconfigured", "pending", "activated"})
                current = None if selected is None else setup._public(selected)
                metadata_profile = None
                if state == "activated":
                    _require(projected["operation"] is not None)
                    # This is the existing explicit public-metadata validation
                    # path, not require_profile() or provisional serving access.
                    metadata_profile = profiles.validate_imported_configuration(config)
                    _require(profiles._record(metadata_profile.client_id, metadata_profile.redirect_uri)
                        == projected["profile_binding"]
                        and metadata_profile.binding_digest == projected["profile_binding_digest"])
                else:
                    _require(projected["operation"] is None)
                settings = projected["effective_settings"]
                runtime = operator_demo.settings()
                _require(settings == {key: runtime[key] for key in ("allowed_upstreams", "fixture_cidrs")}
                    and catalog.active(conn))
                resources = catalog.read_catalog(conn)
                catalog.validate_bindings(conn, resources, metadata_profile=metadata_profile)
                policy.verify_retained_policy(conn, resources, metadata_profile=metadata_profile)
                retained, signed = policy._retained(conn)
                protected, _ = upstream._protected({"old": settings, "signed": signed,
                    "catalog": resources, "profile_binding_digest": projected["profile_binding_digest"]})
                _require(all(item["origin"] in settings["allowed_upstreams"] for item in protected))
                pending_destinations = upstream.pending(conn)
                _require(not (state == "pending" and pending_destinations))
                origin, redirect = setup._public_origin()
                value = {"schema": SCHEMA, "state": state, "revision": resources["revision"],
                    "policy_hash": retained["policy_hash"], "effective_settings": settings,
                    "effective_settings_digest": projected["effective_settings_digest"],
                    "public_url": origin, "redirect_uri": redirect,
                    "permission_preset": profiles.PERMISSION_PRESET, "scopes": list(profiles.SCOPES),
                    "operation": current if selected is not None and selected["actor_id"] == actor_id else None}
                value["blocked_reason"], value["review"] = _review(value, rows,
                    pending_destinations=pending_destinations)
                identity = {key: projected[key] for key in (
                    "operation", "profile_binding_digest", "effective_settings_digest")}
                public._admit(conn)
                return value, identity


def _readiness(before, after, observed):
    """Closed observation only; never disclose another actor's operation IDs."""
    from serverware import operator_google_managed_readiness as readiness
    result = {"pair_ready": False, "consent_ready": False, "loaded_policy_hash": None}
    try:
        _require(type(observed) is dict and set(observed) == {
            "ready", "policy_hash", "loaded_policy_hash", "managed_google"}
            and type(observed["ready"]) is bool)
        if readiness._digest(observed["loaded_policy_hash"]):
            result["loaded_policy_hash"] = observed["loaded_policy_hash"]
        _require(observed["ready"] is True and before == after)
        value, identity = after
        _require(readiness._identity(observed["managed_google"]) == identity
            and observed["policy_hash"] == value["policy_hash"] == result["loaded_policy_hash"])
        result["pair_ready"] = True
        result["consent_ready"] = value["state"] == "activated" and identity["operation"] is not None
    except Exception:
        pass  # Missing, stale or malformed observation is never readiness.
    return result


def configuration(actor_id):
    """Discover only: flag-off/external profiles refuse before configured imports."""
    if os.getenv(_FLAG, "0") != "1":
        raise ConfigurationUnavailable(_ERROR)
    try:
        from serverware import operator_google_managed_readiness as readiness
        from serverware import operator_publication as publication
        before = _snapshot(actor_id)
        publication.assert_not_held()
        observed = readiness.observe()
        publication.assert_not_held()
        after = _snapshot(actor_id)
        value, _ = after
        return {**value, "readiness": _readiness(before, after, observed)}
    except Exception:
        from serverware.operator_google_setup import SetupUnavailable
        raise SetupUnavailable(_ERROR) from None
