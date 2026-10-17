"""Read-only first-Google authorization check before ordinary core DB setup.

The operator runner has already admitted its private directory/configuration;
config admission may have read local key material. This gate does not promise
zero process/filesystem effects: SQLite may coordinate its read through WAL
sidecars, and publication admission pins the preprovisioned lock. It performs no
schema, settings, policy, resource, audit, or provider writes. The exact review
must be checked again by the later activation transaction; this is not a lease
over state between the two checks.
"""
from __future__ import annotations

import json
import os


def validate_before_database_initialization() -> None:
    from catchplate import operator_demo, operator_catalog_oauth_profile
    if not operator_demo.active() or not operator_catalog_oauth_profile.selected():
        return
    from catchplate import config, operator_publication
    from catchplate.development_sandbox import _open_directory

    with operator_publication.closing_fd(_open_directory(operator_publication._directory())) as directory_fd:
        try:
            operator_publication._database_identity(directory_fd)
        except FileNotFoundError:
            # A genuinely fresh operator directory has no retained database.
            # A surviving policy without its DB is not a fresh-state exception.
            try:
                os.stat(config.POLICY_BUNDLE_PATH.name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise RuntimeError("operator Google setup retained database unavailable") from None

        # Retained stores already require this exact preprovisioned inode. The
        # read connection deliberately avoids db.connect() and its journal-mode
        # writes, as well as all generic initializers and schema repair paths.
        with operator_publication.exclusive(startup=True):
            with operator_publication._read_database(directory_fd) as conn:
                objects = {row["name"] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?,?)",
                    ("operator_catalog_state", "operator_catalog_oauth_profile"))}
                if "operator_catalog_oauth_profile" in objects:
                    return  # Existing profile owners retain their normal startup checks.
                if "operator_catalog_state" not in objects:
                    retained = conn.execute("SELECT 1 FROM sqlite_master WHERE "
                        "lower(name) GLOB 'operator_demo_*' OR lower(name) GLOB 'operator_catalog_*' "
                        "OR lower(name) GLOB 'operator_google_*' LIMIT 1").fetchone()
                    if retained is not None:
                        # Legacy/partial operator authority is not fresh core
                        # data. Upgrade its catalog while Google remains off,
                        # then prepare exact first-profile authorization.
                        raise RuntimeError("operator Google setup retained catalog unavailable")
                    return
                from catchplate import operator_catalog_schema, operator_google_setup
                if not operator_catalog_schema.active(conn):
                    raise RuntimeError("operator Google setup retained catalog unavailable")
                rows = conn.execute("SELECT singleton,settings_json FROM operator_demo_settings").fetchall()
                if len(rows) != 1 or rows[0]["singleton"] != 1 or not isinstance(rows[0]["settings_json"], str):
                    raise RuntimeError("operator Google setup retained settings unavailable")
                settings = operator_demo.settings()
                target = json.dumps({key: settings[key] for key in ("allowed_upstreams", "fixture_cidrs")}, sort_keys=True)
                operator_google_setup.validate_startup(conn, rows[0]["settings_json"], target)
