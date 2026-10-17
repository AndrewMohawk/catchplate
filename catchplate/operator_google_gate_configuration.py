"""Public, committed managed-Google configuration for the separate Rust gate.

This projection owns no selection, custody, activation or readiness authority.
The caller holds the existing publication EX and supplies a fresh query-only
SQLite transaction. Export and readiness use the same retained-state decoder;
readiness must release that local lock before contacting the gate.
No database/key/schema initialization, secret access or filesystem write occurs.
"""
from __future__ import annotations

import os
import sqlite3

SCHEMA = "catchplate.operatorGoogleGateConfiguration/v1"
FILENAME = "operator-google-configuration.json"
MAX_BYTES = 32768
_ERROR = "operator Google gate configuration unavailable"
_SETTINGS_SQL = ("CREATE TABLE operator_demo_settings ( singleton INTEGER PRIMARY KEY "
                 "CHECK(singleton=1), settings_json TEXT NOT NULL)")


class GateConfigurationUnavailable(RuntimeError):
    """Fixed refusal; absence is valid only inside a fully decoded record."""


def _require(value):
    if not value:
        raise GateConfigurationUnavailable(_ERROR)


def _admit(conn):
    from catchplate import config, operator_demo, operator_publication
    _require(os.getenv("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED") == "1"
        and operator_demo.active() and config.RELEASE_CHANNEL == "dev" and not config.PRODUCTION_IMAGE
        and config.METADATA_STORE_BACKEND == config.AUDIT_STORE_BACKEND == config.GRANT_STORE_BACKEND == "sqlite"
        and not config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED and not config.KEY_RELEASE_REQUIRED)
    operator_publication.assert_held()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction and conn.total_changes == 0
        and conn.execute("PRAGMA query_only").fetchone()[0] == 1
        and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
    databases = conn.execute("PRAGMA database_list").fetchall()
    _require(len(databases) == 1 and tuple(databases[0]) == (0, "main", str(config.DB_PATH)))


def _settings(conn):
    from catchplate import operator_demo, operator_google_setup as setup
    objects = conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE lower(name)='operator_demo_settings' OR lower(tbl_name)='operator_demo_settings' LIMIT 3").fetchall()
    _require(len(objects) == 1 and tuple(objects[0][:3]) == ("operator_demo_settings", "table", "operator_demo_settings")
        and type(objects[0][3]) is str and len(objects[0][3]) <= 4096
        and " ".join(objects[0][3].split()) == " ".join(_SETTINGS_SQL.split()))
    rows = conn.execute("SELECT singleton,settings_json FROM operator_demo_settings LIMIT 2").fetchall()
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1)
    value = setup._settings(rows[0][1])
    origins, cidrs = operator_demo._destinations(value["allowed_upstreams"], value["fixture_cidrs"])
    _require(list(origins) == value["allowed_upstreams"] and list(cidrs) == value["fixture_cidrs"])
    return value


def _project(conn):
    from catchplate import config, operator_catalog_oauth_profile as profiles
    from catchplate import operator_google_managed_selection as selection, operator_google_setup as setup
    _admit(conn)
    settings = _settings(conn)
    # The existing decoder joins the exact pointer, immutable setup, prepared /
    # terminal audits, retained profile and structural custody envelope. It does
    # not decrypt. Reject legacy foundations rather than silently adopting them.
    selected = selection.read_selection(conn)
    _require(all(setup._managed_configuration(item) for item in setup._rows(conn)))
    result = {"schema": SCHEMA, "operation": None, "profile_binding": None, "profile_binding_digest": None,
        "effective_settings": settings, "effective_settings_digest": setup._digest(settings)}
    if selected is None or selected["status"] == "pending":
        # Same pure retained-state absence check as cold admission: no orphan
        # OAuth profile/intents, cleanup/reauthorization state or credentials.
        from catchplate.operator_google_managed_config import _unconfigured
        _unconfigured(conn)
    else:
        _require(selected["schema"] == setup.MANAGED_PUBLIC_V2 and selected["status"] == "activated"
            and selected["setup_contract"] == setup.MANAGED_BINDING_V2 and selected["activation_receipt"] is not None
            and selected["public_url"] == config.PUBLIC_URL and selected["redirect_uri"] == config.PUBLIC_URL + profiles.CALLBACK_PATH
            and set(profiles.API_ORIGINS) <= set(settings["allowed_upstreams"]))
        reference = selected["custody_ref"]
        result.update(operation={"operation_id": selected["operation_id"], "owner_id": reference["owner_id"],
            "config_version": reference["config_version"]}, profile_binding=selected["profile_binding"],
            profile_binding_digest=selected["profile_binding_digest"])
    _require(len(setup._canonical(result).encode("ascii")) <= MAX_BYTES)
    _admit(conn)
    return result


def record(conn):
    """Project one committed read snapshot under the real publication EX."""
    try:
        return _project(conn)
    except Exception:
        raise GateConfigurationUnavailable(_ERROR) from None


def expected_identity(conn):
    """Same snapshot contract; an unconfigured profile still has an identity."""
    value = record(conn)
    return {key: value[key] for key in ("operation", "profile_binding_digest", "effective_settings_digest")}
