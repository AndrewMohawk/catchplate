"""Existing-lock shared read before generic database initialization.

No schema, journal-mode, settings, policy, resource or audit writes occur here.
SQLite can coordinate WAL sidecars; this does not promise zero filesystem
effects. The exact operation is rechecked by the later publication transaction.
"""
from __future__ import annotations

import json
import os


def validate_before_database_initialization() -> None:
    from serverware import operator_demo
    if not operator_demo.active():
        return
    try:
        _validate()
    except Exception:
        raise RuntimeError("operator upstream setup preflight refused") from None


def _validate():
    from serverware import config, operator_demo, operator_publication as publication
    from serverware.development_sandbox import _open_directory

    directory = publication._directory()
    with publication.closing_fd(_open_directory(directory)) as descriptor:
        try:
            publication._database_identity(descriptor)
        except FileNotFoundError:
            try:
                os.stat(config.POLICY_BUNDLE_PATH.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise RuntimeError("retained operator database unavailable") from None
        # This initial read only distinguishes genuinely fresh core data from
        # retained operator authority; it never authorizes a settings change.
        with publication._read_database(descriptor) as conn:
            names = {row[0].lower() for row in conn.execute("SELECT name FROM sqlite_master")}
            operator_state = any(name.startswith(("operator_demo_", "operator_catalog_", "operator_google_", "operator_upstream_")) for name in names)
            upstream_audit = ("audit_events" in names and conn.execute(
                "SELECT 1 FROM audit_events WHERE event_type LIKE 'operator_catalog.upstream_setup.%' LIMIT 1").fetchone() is not None)
            if not operator_state and not upstream_audit:
                return
            if "operator_demo_settings" not in names:
                raise RuntimeError("retained operator settings unavailable")

    # Unlike the older Google preflight this does not pin EX ownership. It must
    # run first: bootstrap_read refuses already-configured publication owners.
    admission = publication.admit_bootstrap_reader(directory,
        operator_development=operator_demo.active(), release_channel=config.RELEASE_CHANNEL,
        production_image=config.PRODUCTION_IMAGE,
        native_or_enrolled=(config.TEE_PLATFORM != "none-dev" or config.TEE_QUOTE_PROVIDER != "dev-signed-quote"
            or config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED or config.KEY_RELEASE_REQUIRED))
    with publication.bootstrap_read(admission) as conn:
        rows = conn.execute("SELECT singleton,settings_json FROM operator_demo_settings").fetchall()
        if len(rows) != 1 or rows[0]["singleton"] != 1 or not isinstance(rows[0]["settings_json"], str):
            raise RuntimeError("retained operator settings unavailable")
        from serverware import operator_upstream_setup
        settings = operator_demo.settings()
        target = json.dumps({key: settings[key] for key in ("allowed_upstreams", "fixture_cidrs")}, sort_keys=True)
        operator_upstream_setup.validate_startup(conn, rows[0]["settings_json"], target, retained_authority=True)
