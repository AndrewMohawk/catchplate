#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TEMP_DIR = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = _TEMP_DIR.name
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"

from serverware import control_plane_runner, control_plane_startup  # noqa: E402


_PRODUCTION_CONFIGURATION = {
    "RELEASE_CHANNEL": "production",
    "ATOMIC_RELEASE_AUTHORIZATION_ENABLED": False,
    "WEB_TLS_CERT_FILE": "/run/serverware/tls.crt",
    "WEB_TLS_KEY_FILE": "/run/serverware/tls.key",
    "WEBAUTHN_BOOTSTRAP_TOKEN": "bootstrap-token-with-at-least-32-characters",
    "CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": True,
    "CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": True,
    "CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES": (
        "yubikey",
        "hardware",
    ),
    "CONTROL_PLANE_TWO_PERSON_REQUIRED": True,
    "MASTER_KEY_UNSEAL_COMMAND": "unseal-master-key",
    "NITRO_NSM_UNSEAL_COMMAND_TEMPLATE": "nsm-unseal {ciphertext}",
}


class ControlPlaneStartupTests(unittest.TestCase):
    def test_production_configuration_requires_every_runner_invariant(self) -> None:
        cases = {
            "tls": {"WEB_TLS_CERT_FILE": "", "WEB_TLS_KEY_FILE": ""},
            "bootstrap token": {"WEBAUTHN_BOOTSTRAP_TOKEN": "short"},
            "mutation WebAuthn": {"CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": False},
            "hardware mutation WebAuthn": {
                "CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": False
            },
            "bounded authenticator classes": {
                "CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES": (
                    "yubikey",
                    "platform",
                )
            },
            "two person": {"CONTROL_PLANE_TWO_PERSON_REQUIRED": False},
            "master key custody": {"MASTER_KEY_UNSEAL_COMMAND": ""},
            "NSM custody": {"NITRO_NSM_UNSEAL_COMMAND_TEMPLATE": ""},
        }
        for label, override in cases.items():
            with self.subTest(label=label):
                configuration = {**_PRODUCTION_CONFIGURATION, **override}
                with (
                    patch.multiple(control_plane_startup, **configuration),
                    patch.object(control_plane_startup, "validate_internal_service_auth"),
                    patch.object(control_plane_startup, "setup_receipt_trust_profile"),
                ):
                    with self.assertRaises(RuntimeError):
                        control_plane_startup.validate_control_plane_configuration()

    def test_tls_certificate_and_key_are_an_indivisible_pair_in_development(self) -> None:
        with patch.multiple(
            control_plane_startup,
            RELEASE_CHANNEL="dev",
            WEB_TLS_CERT_FILE="/tmp/tls.crt",
            WEB_TLS_KEY_FILE="",
        ):
            with self.assertRaisesRegex(RuntimeError, "must be set together"):
                control_plane_startup.validate_control_plane_configuration()

    def test_startup_validates_identity_trust_policy_high_water_and_ca(self) -> None:
        snapshot = object()
        with (
            patch.multiple(control_plane_startup, **_PRODUCTION_CONFIGURATION),
            patch.object(control_plane_startup, "validate_internal_service_auth") as identity,
            patch.object(control_plane_startup, "setup_receipt_trust_profile") as setup_trust,
            patch.object(control_plane_startup, "ensure_data_dirs") as data_dirs,
            patch.object(control_plane_startup.db, "init_db") as init_db,
            patch.object(
                control_plane_startup.db,
                "verify_audit_chain",
                return_value={"ok": True, "complete": True},
            ) as verify_audit,
            patch.object(control_plane_startup, "get_policy_snapshot", return_value=snapshot),
            patch.object(control_plane_startup, "enforce_policy_high_water") as high_water,
            patch.object(
                control_plane_startup,
                "policy_uses_atomic_release_authorization",
                return_value=False,
            ),
            patch.object(control_plane_startup, "ensure_mitm_ca_material") as ensure_ca,
        ):
            control_plane_startup.validate_control_plane_startup()

        identity.assert_called_once_with()
        setup_trust.assert_called_once_with()
        data_dirs.assert_called_once_with()
        init_db.assert_called_once_with()
        verify_audit.assert_called_once_with()
        high_water.assert_called_once_with(snapshot)
        ensure_ca.assert_called_once_with()

    def test_production_composed_policy_requires_one_atomic_writer(self) -> None:
        snapshot = object()
        with (
            patch.multiple(control_plane_startup, **_PRODUCTION_CONFIGURATION),
            patch.object(control_plane_startup, "ATOMIC_RELEASE_AUTHORIZATION_ENABLED", False),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
            patch.object(control_plane_startup, "setup_receipt_trust_profile"),
            patch.object(control_plane_startup, "ensure_data_dirs"),
            patch.object(control_plane_startup.db, "init_db"),
            patch.object(
                control_plane_startup.db,
                "verify_audit_chain",
                return_value={"ok": True, "complete": True},
            ),
            patch.object(control_plane_startup, "get_policy_snapshot", return_value=snapshot),
            patch.object(control_plane_startup, "enforce_policy_high_water"),
            patch.object(
                control_plane_startup,
                "policy_uses_atomic_release_authorization",
                return_value=True,
            ),
            patch.object(
                control_plane_startup.db,
                "require_atomic_release_writer",
                side_effect=control_plane_startup.db.ReleaseAuthorizationError(
                    "different writers"
                ),
            ),
            patch.object(control_plane_startup, "ensure_mitm_ca_material") as ensure_ca,
        ):
            with self.assertRaisesRegex(RuntimeError, "same writer DSN and schema"):
                control_plane_startup.validate_control_plane_startup()
        ensure_ca.assert_not_called()

    def test_atomic_startup_runs_bounded_reconciliation_before_workers(self) -> None:
        snapshot = object()
        with (
            patch.multiple(
                control_plane_startup,
                RELEASE_CHANNEL="dev",
                WEB_TLS_CERT_FILE="",
                WEB_TLS_KEY_FILE="",
                ATOMIC_RELEASE_AUTHORIZATION_ENABLED=True,
                RELEASE_AUTHORIZATION_RECONCILE_LIMIT=37,
            ),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
            patch.object(control_plane_startup, "ensure_data_dirs"),
            patch.object(control_plane_startup.db, "init_db"),
            patch.object(control_plane_startup, "get_policy_snapshot", return_value=snapshot),
            patch.object(control_plane_startup, "enforce_policy_high_water"),
            patch.object(
                control_plane_startup,
                "policy_uses_atomic_release_authorization",
                return_value=False,
            ),
            patch.object(control_plane_startup.db, "require_atomic_release_writer") as writer,
            patch.object(control_plane_startup.db, "reconcile_release_authorizations") as reap,
            patch.object(
                control_plane_startup.db,
                "drain_release_authorization_audit_outbox",
            ) as drain,
            patch.object(control_plane_startup, "ensure_mitm_ca_material"),
        ):
            control_plane_startup.validate_control_plane_startup()
        writer.assert_called_once_with()
        reap.assert_called_once_with(limit=37)
        drain.assert_called_once_with(37)

    def test_production_startup_rejects_missing_active_policy_before_ca_creation(self) -> None:
        with (
            patch.multiple(control_plane_startup, **_PRODUCTION_CONFIGURATION),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
            patch.object(control_plane_startup, "setup_receipt_trust_profile"),
            patch.object(control_plane_startup, "ensure_data_dirs"),
            patch.object(control_plane_startup.db, "init_db"),
            patch.object(
                control_plane_startup.db,
                "verify_audit_chain",
                return_value={"ok": True, "complete": True},
            ),
            patch.object(control_plane_startup, "get_policy_snapshot", return_value=None),
            patch.object(control_plane_startup, "ensure_mitm_ca_material") as ensure_ca,
        ):
            with self.assertRaisesRegex(RuntimeError, "active signed policy bundle"):
                control_plane_startup.validate_control_plane_startup()
        ensure_ca.assert_not_called()

    def test_production_startup_rejects_unverified_audit_chain(self) -> None:
        with (
            patch.multiple(control_plane_startup, **_PRODUCTION_CONFIGURATION),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
            patch.object(control_plane_startup, "setup_receipt_trust_profile"),
            patch.object(control_plane_startup, "ensure_data_dirs"),
            patch.object(control_plane_startup.db, "init_db"),
            patch.object(
                control_plane_startup.db,
                "verify_audit_chain",
                return_value={"ok": False, "complete": False},
            ),
            patch.object(control_plane_startup, "ensure_mitm_ca_material") as ensure_ca,
        ):
            with self.assertRaisesRegex(RuntimeError, "complete verified audit chain"):
                control_plane_startup.validate_control_plane_startup()
        ensure_ca.assert_not_called()

    def test_runner_uses_the_shared_startup_gate(self) -> None:
        with (
            patch.object(control_plane_runner, "validate_control_plane_startup") as preflight,
            patch.object(control_plane_runner.uvicorn, "run") as uvicorn_run,
        ):
            control_plane_runner.main()
        preflight.assert_called_once_with()
        uvicorn_run.assert_called_once()

    def test_fastapi_startup_uses_gate_before_workers(self) -> None:
        from serverware import app as app_module

        with (
            patch.object(
                app_module,
                "validate_control_plane_startup",
                side_effect=RuntimeError("preflight denied"),
            ) as preflight,
            patch.object(app_module.runtime, "start_runtime_workers") as workers,
            patch.object(app_module.runtime, "start_audit_anchor_worker") as audit_worker,
            patch.object(app_module.runtime, "start_decision_gate_ca_publisher") as ca_worker,
        ):
            with self.assertRaisesRegex(RuntimeError, "preflight denied"):
                app_module.startup()
        preflight.assert_called_once_with()
        workers.assert_not_called()
        audit_worker.assert_not_called()
        ca_worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
