"""Runtime admission for the ordinary operator-owned X application.

The already activated operator process owns environment and data-directory
identity. Each operation independently admits the separate X key directory and
its exact SQLite connection. This module never selects a configuration, reads a
key, creates storage, contacts X, or admits native/enrolled execution.
"""
from __future__ import annotations

import os
import sqlite3

from catchplate import operator_provider_key as keys

_FLAG = "CATCHPLATE_OPERATOR_MANAGED_X_ENABLED"
_DIRECTORY = "CATCHPLATE_OPERATOR_X_CUSTODY_DIR"
_ERROR = "operator X configuration unavailable"


class AdmissionError(RuntimeError):
    """Fixed error without paths, environment values, or secret material."""


def _require(value):
    if not value:
        raise AdmissionError(_ERROR)


def enabled() -> bool:
    value = os.getenv(_FLAG, "0")
    _require(value in {"0", "1"})
    return value == "1"


def public_origin() -> str:
    try:
        from catchplate import config, operator_demo
        value = config.PUBLIC_URL
        _require(type(value) is str and value == os.getenv("CATCHPLATE_PUBLIC_URL")
            and operator_demo.origin(value)[0] == value and value != "https://demo-upstream:8443")
        return value
    except Exception:
        raise AdmissionError(_ERROR) from None


def require_runtime() -> keys.DirectoryAdmission:
    """Require actual process admission; feature selection alone grants nothing."""
    try:
        _require(enabled())
        from catchplate import config, operator_demo, oauth_application_owner
        from catchplate import operator_catalog_oauth_profile as profiles
        _require(operator_demo.active())
        directory = profiles._raw_development_directory(managed=False)
        _require(all(os.getenv(name) == value for name, value in {
            "CATCHPLATE_DEV_AUTHENTICATOR": "0", "CATCHPLATE_DEV_DEMO_SEED": "0",
            "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
        }.items()))
        _require(not any(name.startswith(("CATCHPLATE_X_OAUTH_", "CATCHPLATE_TWITTER_OAUTH_"))
            for name in os.environ))
        _require(os.getenv("CATCHPLATE_TEE_PLATFORM", "none-dev") == "none-dev"
            and os.getenv("CATCHPLATE_TEE_QUOTE_PROVIDER", "dev-signed-quote") == "dev-signed-quote")
        _require(config.DATA_DIR == directory and config.RELEASE_CHANNEL == "dev"
            and config.PRODUCTION_IMAGE is False and config.METADATA_STORE_BACKEND == "sqlite"
            and config.AUDIT_STORE_BACKEND == "sqlite" and config.GRANT_STORE_BACKEND == "sqlite"
            and config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED is False and config.KEY_RELEASE_REQUIRED is False
            and config.TEE_PLATFORM == "none-dev" and config.TEE_QUOTE_PROVIDER == "dev-signed-quote"
            and config.DEV_AUTHENTICATOR_ENABLED is False and config.DEV_DEMO_SEED_ENABLED is False
            and not config.X_OAUTH_CLIENT_ID and not config.X_OAUTH_CLIENT_SECRET
            and config.X_OAUTH_CLIENT_SECRET_FILE is None
            and config.X_OAUTH_REDIRECT_URI == public_origin() + "/api/oauth/callback/x"
            and oauth_application_owner.require_started() is None)
        admitted = keys.admit_directory(os.environ.get(_DIRECTORY, ""), data_directory=directory)
        google_path = os.getenv("CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR", "")
        if google_path:
            google = keys.admit_directory(google_path, data_directory=directory)
            _require(not admitted.path.is_relative_to(google.path)
                and not google.path.is_relative_to(admitted.path)
                and admitted.directory_identity[:2] != google.directory_identity[:2])
        _require(operator_demo.active())
        return admitted
    except Exception:
        raise AdmissionError(_ERROR) from None


def check_connection(conn: sqlite3.Connection, admission: keys.DirectoryAdmission) -> None:
    """Borrow only the existing exact database transaction; never initialize."""
    try:
        _require(type(admission) is keys.DirectoryAdmission and require_runtime() == admission
            and isinstance(conn, sqlite3.Connection) and conn.in_transaction
            and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
        databases = [tuple(row) for row in conn.execute("PRAGMA database_list").fetchall()]
        # SQLite can materialize an empty temp schema while inspecting it. It
        # must contain no objects; attached databases never participate here.
        _require(databases in (
            [(0, "main", str(admission.data_directory / "catchplate.sqlite3"))],
            [(0, "main", str(admission.data_directory / "catchplate.sqlite3")), (1, "temp", "")],
        ))
        if len(databases) == 2:
            _require(conn.execute("SELECT 1 FROM sqlite_temp_master LIMIT 1").fetchone() is None)
    except Exception:
        raise AdmissionError(_ERROR) from None


def admit_owner(owner_id: str):
    require_runtime()
    from catchplate.operator_provider_custody import admit_development_owner
    try:
        return admit_development_owner(owner_id, operator_development=True,
            release_channel="dev", production_image=False, native_or_enrolled=False)
    except Exception:
        raise AdmissionError(_ERROR) from None
