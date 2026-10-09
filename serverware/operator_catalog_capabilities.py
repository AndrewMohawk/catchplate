"""Public operator capabilities, joined to the cold and retained profile.

Discovery is not OAuth authority or a provider-health check. Account creation
still requires the existing administrator/same-origin consent endpoint and its
catalog CAS, browser binding, PKCE and callback checks. No fallback is selected.
"""
from __future__ import annotations


def google_oauth(conn) -> dict | None:
    """Return only public fixed-flow configuration from a validated read tx.

An absent profile is disabled. Invalid cold configuration or a retained binding
mismatch propagates to the catalog's fixed unavailable error, never `False`.
"""
    from serverware import operator_catalog_google
    from serverware.operator_catalog_schema import CatalogIntegrityError

    if getattr(conn, "in_transaction", False) is not True:
        raise CatalogIntegrityError("operator capability requires a catalog read snapshot")
    profile = operator_catalog_google.validate_profile_binding(conn)
    if profile is None:
        return None
    return {
        "schema": "serverware.operatorGoogleCapability/v1",
        "profile": profile.profile,
        "provider_id": profile.provider_id,
        "permission_preset": profile.permission_preset,
        "scopes": list(profile.scopes),
        "api_origins": list(profile.api_origins),
        "authorization_origin": "https://accounts.google.com",
        "authorization_path": "/o/oauth2/v2/auth",
        "redirect_uri": profile.redirect_uri,
        "start_path": "/api/operator-demo/oauth/google/start",
        "intents_path": "/api/operator-demo/oauth/google/intents",
    }


def google_disconnect(conn) -> dict | None:
    """Advertise the backend lifecycle only where its retained schema exists."""
    from serverware import operator_catalog_google, operator_google_disconnect
    from serverware.operator_catalog_schema import CatalogIntegrityError

    if getattr(conn, "in_transaction", False) is not True:
        raise CatalogIntegrityError("operator capability requires a catalog read snapshot")
    if operator_catalog_google.validate_profile_binding(conn) is None:
        return None
    if not operator_google_disconnect.capability_available(conn):
        return None
    return {
        "schema": "serverware.operatorGoogleDisconnectCapability/v1",
        "path": "/api/operator-demo/oauth/google/disconnect",
        "status_path_prefix": "/api/operator-demo/oauth/google/disconnect/",
        "requires_affected_rule_confirmation": True,
        "requires_project_wide_revocation_acknowledgement": True,
        "reconnect_supported": False,
    }
