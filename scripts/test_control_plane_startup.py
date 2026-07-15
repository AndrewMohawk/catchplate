#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    "OIDC_SESSION_WEBAUTHN_REQUIRED": True,
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
    def setUp(self) -> None:
        self.trust_reconcile = patch.object(
            control_plane_startup,
            "reconcile_trust_publications",
            return_value={"ok": True, "reconciled": False},
        )
        self.audit_outbox_drain = patch.object(
            control_plane_startup.db,
            "drain_metadata_audit_outbox_fully",
            return_value={"claimed": 0, "audited": 0, "failed": 0, "pending": 0},
        )
        self.unbound_session_revoke = patch.object(
            control_plane_startup.db,
            "revoke_unbound_oidc_browser_sessions",
            return_value={"revoked_count": 0, "session_ids": []},
        )
        self.recovery_configuration = patch.object(
            control_plane_startup,
            "validate_webauthn_recovery_configuration",
        )
        self.trust_reconcile.start()
        self.audit_outbox_drain.start()
        self.unbound_session_revoke.start()
        self.recovery_configuration.start()
        self.addCleanup(self.trust_reconcile.stop)
        self.addCleanup(self.audit_outbox_drain.stop)
        self.addCleanup(self.unbound_session_revoke.stop)
        self.addCleanup(self.recovery_configuration.stop)

    def test_production_rejects_insecure_webauthn_recovery_configuration(self) -> None:
        control_plane_startup.validate_webauthn_recovery_configuration.side_effect = (
            control_plane_startup.WebAuthnError("offline recovery root mismatch")
        )
        with (
            patch.multiple(control_plane_startup, **_PRODUCTION_CONFIGURATION),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "WebAuthn recovery is not securely configured"
            ):
                control_plane_startup.validate_control_plane_configuration()

    def test_production_recovery_checks_independent_witness(self) -> None:
        configuration = {
            **_PRODUCTION_CONFIGURATION,
            "WEBAUTHN_RECOVERY_ENABLED": True,
        }
        with (
            patch.multiple(control_plane_startup, **configuration),
            patch.object(control_plane_startup, "validate_internal_service_auth"),
            patch.object(control_plane_startup, "setup_receipt_trust_profile"),
            patch.object(
                control_plane_startup,
                "response_public_key_info",
                return_value={"spki_sha256": "response-key"},
            ),
            patch.object(
                control_plane_startup,
                "policy_public_key_hash",
                return_value="policy-key",
            ),
            patch.object(
                control_plane_startup,
                "quote_public_key_info",
                return_value={"spki_sha256": "quote-key"},
            ),
            patch.object(
                control_plane_startup,
                "trust_public_key_hash",
                return_value="trust-key",
            ),
            patch.object(
                control_plane_startup.db,
                "require_independent_recovery_witness",
            ) as witness,
        ):
            control_plane_startup.validate_control_plane_configuration()
        witness.assert_called_once_with(production=True)

    def test_production_configuration_requires_every_runner_invariant(self) -> None:
        cases = {
            "tls": {"WEB_TLS_CERT_FILE": "", "WEB_TLS_KEY_FILE": ""},
            "bootstrap token": {"WEBAUTHN_BOOTSTRAP_TOKEN": "short"},
            "mutation WebAuthn": {"CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": False},
            "OIDC session WebAuthn": {"OIDC_SESSION_WEBAUTHN_REQUIRED": False},
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
        control_plane_startup.db.revoke_unbound_oidc_browser_sessions.assert_called_once_with(
            actor_id="system:startup",
            reason="WebAuthn-bound OIDC browser sessions are required",
        )
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
                app_module, "control_plane_startup_required", return_value=True
            ),
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

    def test_fastapi_startup_does_not_repeat_runner_gate(self) -> None:
        from serverware import app as app_module

        with (
            patch.object(
                app_module, "control_plane_startup_required", return_value=False
            ),
            patch.object(app_module, "validate_control_plane_startup") as preflight,
            patch.object(app_module, "_drain_setup_session_audit_outbox"),
            patch.object(app_module.runtime, "start_runtime_workers"),
            patch.object(app_module.runtime, "start_audit_anchor_worker"),
            patch.object(app_module.runtime, "start_decision_gate_ca_publisher"),
            patch.object(app_module, "_start_oauth_revocation_reconciler"),
        ):
            app_module.startup()
        preflight.assert_not_called()


class RecoveryWitnessIndependenceTests(unittest.TestCase):
    def _patch_production_witness(
        self,
        *,
        metadata_identity: tuple[str, int, int],
        witness_identity: tuple[str, int, int],
        metadata_fault_domain: str = "aws:account-a:use1-az1",
        witness_fault_domain: str = "aws:account-b:use1-az2",
    ):
        stack = ExitStack()
        self.addCleanup(stack.close)
        db = control_plane_startup.db
        stack.enter_context(
            patch.multiple(
                db,
                METADATA_STORE_FAULT_DOMAIN_ID=metadata_fault_domain,
                WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID=witness_fault_domain,
            )
        )
        stack.enter_context(
            patch.object(db, "metadata_uses_postgres", return_value=True)
        )
        stack.enter_context(
            patch.object(db, "recovery_witness_uses_postgres", return_value=True)
        )
        stack.enter_context(
            patch.object(
                db,
                "_metadata_pg_connect_raw",
                return_value=nullcontext(object()),
            )
        )
        stack.enter_context(
            patch.object(
                db,
                "_recovery_witness_pg_connect",
                return_value=nullcontext(object()),
            )
        )
        identity = stack.enter_context(
            patch.object(
                db,
                "_postgres_server_identity",
                side_effect=[metadata_identity, witness_identity],
            )
        )
        initialize = stack.enter_context(
            patch.object(db, "init_recovery_witness_store")
        )
        return initialize, identity

    def test_postgres_identity_includes_cluster_system_identifier(self) -> None:
        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = {
            "address": "10.77.0.12",
            "port": 5432,
            "system_identifier": "7486938123456789012",
        }

        identity = control_plane_startup.db._postgres_server_identity(connection)

        self.assertEqual(identity, ("10.77.0.12", 5432, 7486938123456789012))
        query = connection.execute.call_args.args[0]
        self.assertIn("pg_control_system()", query)
        self.assertIn("system_identifier", query)

    def test_production_rejects_aliases_to_the_same_postgres_cluster(self) -> None:
        initialize, identity = self._patch_production_witness(
            metadata_identity=("10.77.0.12", 5432, 7486938123456789012),
            witness_identity=("10.0.9.24", 6432, 7486938123456789012),
        )

        with self.assertRaisesRegex(
            control_plane_startup.db.RecoveryWitnessError,
            "different PostgreSQL clusters",
        ):
            control_plane_startup.db.require_independent_recovery_witness(
                production=True
            )

        self.assertEqual(identity.call_count, 2)
        initialize.assert_not_called()

    def test_production_still_rejects_the_same_postgres_listener(self) -> None:
        initialize, identity = self._patch_production_witness(
            metadata_identity=("10.77.0.12", 5432, 7486938123456789012),
            witness_identity=("10.77.0.12", 5432, 7486938123456789999),
        )

        with self.assertRaisesRegex(
            control_plane_startup.db.RecoveryWitnessError,
            "non-colocated PostgreSQL server",
        ):
            control_plane_startup.db.require_independent_recovery_witness(
                production=True
            )

        self.assertEqual(identity.call_count, 2)
        initialize.assert_not_called()

    def test_production_rejects_same_declared_fault_domain(self) -> None:
        initialize, identity = self._patch_production_witness(
            metadata_identity=("10.77.0.12", 5432, 7486938123456789012),
            witness_identity=("10.0.9.24", 5432, 7486938123456789999),
            metadata_fault_domain="aws:account-a:use1-az1",
            witness_fault_domain="aws:account-a:use1-az1",
        )

        with self.assertRaisesRegex(
            control_plane_startup.db.RecoveryWitnessError,
            "different declared fault domains",
        ):
            control_plane_startup.db.require_independent_recovery_witness(
                production=True
            )

        identity.assert_not_called()
        initialize.assert_not_called()

    def test_production_requires_both_fault_domain_identities(self) -> None:
        initialize, identity = self._patch_production_witness(
            metadata_identity=("10.77.0.12", 5432, 7486938123456789012),
            witness_identity=("10.0.9.24", 5432, 7486938123456789999),
            witness_fault_domain="",
        )

        with self.assertRaisesRegex(
            control_plane_startup.db.RecoveryWitnessError,
            "recovery witness fault-domain identity is missing or invalid",
        ):
            control_plane_startup.db.require_independent_recovery_witness(
                production=True
            )

        identity.assert_not_called()
        initialize.assert_not_called()

    def test_production_accepts_distinct_clusters_listeners_and_domains(self) -> None:
        initialize, identity = self._patch_production_witness(
            metadata_identity=("10.77.0.12", 5432, 7486938123456789012),
            witness_identity=("10.0.9.24", 5432, 7486938123456789999),
        )

        control_plane_startup.db.require_independent_recovery_witness(production=True)

        self.assertEqual(identity.call_count, 2)
        initialize.assert_called_once_with()

    def test_development_sqlite_keeps_local_witness_behavior(self) -> None:
        db = control_plane_startup.db
        with (
            patch.object(db, "init_recovery_witness_store") as initialize,
            patch.object(db, "metadata_uses_postgres") as metadata_postgres,
            patch.object(db, "recovery_witness_uses_postgres") as witness_postgres,
        ):
            db.require_independent_recovery_witness(production=False)

        initialize.assert_called_once_with()
        metadata_postgres.assert_not_called()
        witness_postgres.assert_not_called()


if __name__ == "__main__":
    unittest.main()
