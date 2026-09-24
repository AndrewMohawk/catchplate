#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
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
from serverware.signed_http import SignedOnlyHttpToolsProtocol  # noqa: E402


_SERVICE_CREDENTIALS = (
    ("SERVERWARE_ADMIN_TOKEN", "ADMIN_TOKEN"),
    ("SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN", "WEBAUTHN_BOOTSTRAP_TOKEN"),
    (
        "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
        "DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
    ),
    ("SERVERWARE_DATA_PLANE_AUDIT_TOKEN", "DATA_PLANE_AUDIT_INGEST_TOKEN"),
    (
        "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN",
        "DATA_PLANE_GRANT_CONSUME_TOKEN",
    ),
    (
        "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
        "DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
    ),
    (
        "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
        "DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
    ),
    ("SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN", "DATA_PLANE_MANAGEMENT_TOKEN"),
    ("SERVERWARE_AUDIT_ANCHOR_TOKEN", "AUDIT_ANCHOR_TOKEN"),
)


_PRODUCTION_CONFIGURATION = {
    "RELEASE_CHANNEL": "production",
    "PRODUCTION_IMAGE": True,
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
    "CONTROL_PLANE_TWO_PERSON_ACTIONS": tuple(
        sorted(control_plane_startup._PRODUCTION_TWO_PERSON_ACTIONS)
    ),
    "DEV_AUTHENTICATOR_ENABLED": False,
    "DIRECT_CA_DOWNLOAD_ENABLED": False,
    "POLICY_PUBLISH_DRY_RUN_REQUIRED": True,
    "POLICY_CANARY_REQUIRED": True,
    "POLICY_CANARY_MIN_OBSERVATION_SECONDS": 60,
    "POLICY_CANARY_MIN_AUDIT_EVENTS": 1,
    "POLICY_CANARY_MAX_DENIALS": 0,
    "MASTER_KEY_UNSEAL_COMMAND": "unseal-master-key",
    "NITRO_NSM_UNSEAL_COMMAND_TEMPLATE": "nsm-unseal {ciphertext}",
}


class ServiceCredentialConfigurationTests(unittest.TestCase):
    def _credential_values(self) -> dict[str, str]:
        return {
            name: f"test-{index:02d}-{name.lower()}-credential"
            for index, (name, _) in enumerate(_SERVICE_CREDENTIALS)
        }

    def _subprocess_env(self, data_dir: str) -> dict[str, str]:
        allowed = {
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PATH",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "TZ",
        }
        env = {name: value for name, value in os.environ.items() if name in allowed}
        env.update(
            {
                "PYTHONPATH": str(ROOT),
                "SERVERWARE_DATA_DIR": data_dir,
                "SERVERWARE_RELEASE_CHANNEL": "production",
                "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
                    "spiffe://prod.serverware.internal/decision-gate/test"
                ),
            }
        )
        return env

    def _run_config(
        self,
        env: dict[str, str],
        source: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=ROOT,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_all_service_credentials_load_from_files(self) -> None:
        values = self._credential_values()
        with tempfile.TemporaryDirectory() as tmp:
            env = self._subprocess_env(tmp)
            for index, (name, _) in enumerate(_SERVICE_CREDENTIALS):
                path = Path(tmp) / f"credential-{index}"
                path.write_text(values[name], encoding="utf-8")
                path.chmod(0o440 if index % 2 else 0o400)
                env[f"{name}_FILE"] = str(path)

            attributes = {name: attribute for name, attribute in _SERVICE_CREDENTIALS}
            source = (
                "import json\n"
                "from serverware import auth, config\n"
                "config.validate_internal_service_auth()\n"
                f"attributes = {attributes!r}\n"
                "values = {name: getattr(config, attribute) "
                "for name, attribute in attributes.items()}\n"
                "values['admin_runtime'] = auth.admin_token()\n"
                "values['admin_external'] = config.ADMIN_TOKEN_EXTERNALLY_CONFIGURED\n"
                "values['admin_source'] = config.ADMIN_TOKEN_SOURCE\n"
                "values['admin_file'] = str(config.ADMIN_TOKEN_FILE_PATH)\n"
                "values['audit_anchor_source'] = config.AUDIT_ANCHOR_TOKEN_SOURCE\n"
                "values['audit_anchor_file'] = str(config.AUDIT_ANCHOR_TOKEN_FILE_PATH)\n"
                "print(json.dumps(values, sort_keys=True))\n"
            )
            result = self._run_config(env, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = json.loads(result.stdout)
        self.assertEqual(
            {name: loaded[name] for name, _ in _SERVICE_CREDENTIALS},
            values,
        )
        self.assertEqual(loaded["admin_runtime"], values["SERVERWARE_ADMIN_TOKEN"])
        self.assertIs(loaded["admin_external"], True)
        self.assertEqual(loaded["admin_source"], "file")
        self.assertEqual(
            loaded["admin_file"],
            str(Path(tmp) / "credential-0"),
        )
        self.assertEqual(loaded["audit_anchor_source"], "file")
        self.assertEqual(
            loaded["audit_anchor_file"],
            str(Path(tmp) / f"credential-{len(_SERVICE_CREDENTIALS) - 1}"),
        )

    def test_env_and_file_presence_are_mutually_exclusive_even_when_blank(
        self,
    ) -> None:
        values = self._credential_values()
        with tempfile.TemporaryDirectory() as tmp:
            for name, _ in _SERVICE_CREDENTIALS:
                with self.subTest(name=name):
                    env = self._subprocess_env(tmp)
                    env.update(values)
                    env[name] = ""
                    env[f"{name}_FILE"] = ""
                    result = self._run_config(env, "import serverware.config\n")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f"must not set both {name} and {name}_FILE", result.stderr)
                    self.assertNotIn(values[name], result.stderr)

    def test_development_defaults_and_direct_value_semantics_are_preserved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._subprocess_env(tmp)
            env["SERVERWARE_RELEASE_CHANNEL"] = "dev"
            env.pop("SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED")
            env.pop("SERVERWARE_DATA_PLANE_INSTANCE_ID")
            env["SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"] = (
                " direct-data-plane-token "
            )
            env["SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN"] = " direct-bootstrap-token "
            source = (
                "import json\n"
                "from serverware import config\n"
                "print(json.dumps({"
                "'admin': config.ADMIN_TOKEN, "
                "'admin_external': config.ADMIN_TOKEN_EXTERNALLY_CONFIGURED, "
                "'admin_source': config.ADMIN_TOKEN_SOURCE, "
                "'audit_anchor': config.AUDIT_ANCHOR_TOKEN, "
                "'audit_anchor_source': config.AUDIT_ANCHOR_TOKEN_SOURCE, "
                "'data_plane': config.DATA_PLANE_CREDENTIAL_LEASE_TOKEN, "
                "'bootstrap': config.WEBAUTHN_BOOTSTRAP_TOKEN"
                "}, sort_keys=True))\n"
            )
            result = self._run_config(env, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = json.loads(result.stdout)
        self.assertEqual(
            loaded,
            {
                "admin": "",
                "admin_external": False,
                "admin_source": "generated-file",
                "audit_anchor": "",
                "audit_anchor_source": "unconfigured",
                "bootstrap": " direct-bootstrap-token ",
                "data_plane": "direct-data-plane-token",
            },
        )

    def test_production_rejects_weak_or_duplicate_service_credentials(self) -> None:
        values = self._credential_values()
        with tempfile.TemporaryDirectory() as tmp:
            weak_env = self._subprocess_env(tmp)
            weak_env.update(values)
            weak_env["SERVERWARE_AUDIT_ANCHOR_TOKEN"] = "too-short"
            weak = self._run_config(
                weak_env,
                "from serverware import config\nconfig.validate_internal_service_auth()\n",
            )
            self.assertNotEqual(weak.returncode, 0)
            self.assertIn("SERVERWARE_AUDIT_ANCHOR_TOKEN", weak.stderr)
            self.assertNotIn("too-short", weak.stderr)

            duplicate_env = self._subprocess_env(tmp)
            duplicate_env.update(values)
            duplicate_env["SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN"] = values[
                "SERVERWARE_ADMIN_TOKEN"
            ]
            duplicate = self._run_config(
                duplicate_env,
                "from serverware import config\nconfig.validate_internal_service_auth()\n",
            )
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("distinct internal service credentials", duplicate.stderr)
            self.assertNotIn(values["SERVERWARE_ADMIN_TOKEN"], duplicate.stderr)

    def test_service_credential_file_modes_and_content_are_strict(self) -> None:
        from serverware import config

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for mode in (0o400, 0o440, 0o600, 0o640):
                with self.subTest(accepted_mode=oct(mode)):
                    path = root / f"accepted-{mode:o}"
                    path.write_text("valid-service-credential", encoding="utf-8")
                    path.chmod(mode)
                    self.assertEqual(
                        config._read_service_credential_file(
                            path, setting_name="TEST_TOKEN_FILE"
                        ),
                        "valid-service-credential",
                    )

            rejected_content = {
                "trailing-newline": b"valid-service-credential\n",
                "leading-space": b" valid-service-credential",
                "embedded-control": b"valid\x00service-credential",
                "invalid-utf8": b"\xff\xfe",
                "oversized": b"x" * (config.MAX_SERVICE_CREDENTIAL_FILE_BYTES + 1),
            }
            for label, payload in rejected_content.items():
                with self.subTest(rejected_content=label):
                    path = root / label
                    path.write_bytes(payload)
                    path.chmod(0o640)
                    with self.assertRaises(RuntimeError):
                        config._read_service_credential_file(
                            path, setting_name="TEST_TOKEN_FILE"
                        )

            for mode in (0o444, 0o660):
                with self.subTest(rejected_mode=oct(mode)):
                    path = root / f"rejected-{mode:o}"
                    path.write_text("valid-service-credential", encoding="utf-8")
                    path.chmod(mode)
                    with self.assertRaisesRegex(RuntimeError, "mode 0400"):
                        config._read_service_credential_file(
                            path, setting_name="TEST_TOKEN_FILE"
                        )

            target = root / "symlink-target"
            target.write_text("valid-service-credential", encoding="utf-8")
            target.chmod(0o400)
            symlink = root / "symlink"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                config._read_service_credential_file(
                    symlink, setting_name="TEST_TOKEN_FILE"
                )

    def test_service_credential_file_rejects_metadata_drift(self) -> None:
        from serverware import config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credential"
            path.write_text("valid-service-credential", encoding="utf-8")
            path.chmod(0o400)
            before = path.stat()
            after = types.SimpleNamespace(
                st_dev=before.st_dev,
                st_ino=before.st_ino,
                st_mode=before.st_mode,
                st_size=before.st_size,
                st_mtime_ns=before.st_mtime_ns + 1,
                st_ctime_ns=before.st_ctime_ns,
            )
            with (
                patch.object(config.os, "fstat", side_effect=[before, after]),
                self.assertRaisesRegex(RuntimeError, "changed while it was being read"),
            ):
                config._read_service_credential_file(
                    path, setting_name="TEST_TOKEN_FILE"
                )


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
            "complete two-person action set": {
                "CONTROL_PLANE_TWO_PERSON_ACTIONS": ("policy.publish",)
            },
            "development authenticator": {"DEV_AUTHENTICATOR_ENABLED": True},
            "direct CA download": {"DIRECT_CA_DOWNLOAD_ENABLED": True},
            "policy dry-run": {"POLICY_PUBLISH_DRY_RUN_REQUIRED": False},
            "policy canary": {"POLICY_CANARY_REQUIRED": False},
            "canary observation": {"POLICY_CANARY_MIN_OBSERVATION_SECONDS": 0},
            "canary audit evidence": {"POLICY_CANARY_MIN_AUDIT_EVENTS": 0},
            "canary denial threshold": {"POLICY_CANARY_MAX_DENIALS": 1},
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

    def test_production_image_rejects_development_release_channel(self) -> None:
        with patch.multiple(
            control_plane_startup,
            RELEASE_CHANNEL="dev",
            PRODUCTION_IMAGE=True,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "production control-plane image requires"
            ):
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
            patch.object(
                control_plane_runner,
                "validate_signed_http_protocol",
            ) as protocol_preflight,
            patch.object(control_plane_runner.uvicorn, "run") as uvicorn_run,
        ):
            control_plane_runner.main()
        preflight.assert_called_once_with()
        protocol_preflight.assert_called_once_with()
        uvicorn_run.assert_called_once()
        runner_kwargs = uvicorn_run.call_args.kwargs
        self.assertIs(runner_kwargs["http"], SignedOnlyHttpToolsProtocol)
        self.assertEqual(runner_kwargs["ws"], "none")
        self.assertFalse(runner_kwargs["server_header"])
        self.assertFalse(runner_kwargs["date_header"])

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


class _RevocationReadCursor:
    """Closed deterministic SQL responses, not PostgreSQL or root authority.

    The populations and stored digests are independent fixture constructions.
    Actual planner SQL, staging, range acquisition and proof engines run without
    successful-result replacements. This suite still imports the real blocked
    startup/registry graph above; this responder does not bypass that gate.
    """

    ROOT_SELECT = ("SELECT root_revision, root_digest, leaf_count FROM serverware_metadata."
                   "policy_authority_authenticated_table_roots WHERE table_name = %s")

    def __init__(self, fixture, *, on_clock=None, change=None):
        import test_authority_complete_acquisition as complete_oracle
        import test_authority_index_frontier as range_oracle
        import test_authority_index_heads as head_oracle
        import test_authority_radix_batch as primary_oracle

        self.fixture, self.on_clock, self.change = fixture, on_clock, change
        root_vectors = fixture.expected_before
        roots = [root for field in ("businessBeforeRoots", "authorizationBeforeRoots")
                 for root in sorted(root_vectors[field], key=lambda item: item["table"])]
        self.root_order = tuple(root["table"] for root in roots)
        self.root_rows = {root["table"]: {"root_revision": root["rootRevision"],
            "root_digest": root["rootDigest"], "leaf_count": root["leafCount"]} for root in roots}
        self.root_calls, self.on_root, self.root_change = [], None, None
        self.return_root_aliases = False
        read = fixture.read_write.read
        stores = {query.role: range_oracle.IndependentStoredIndex(fixture.rows[query.table],
            query=query, expiry_us=fixture.read_write.expiry_before
            if query.table == "webauthn_challenges" else None, revision=29)
            for query in read.queries}
        head_rows = head_oracle.source_rows()
        for row in head_rows:
            revision, root = fixture.read_write.heads[row["index_id"]]
            row.update(index_revision=revision, root_digest=root.digest, leaf_count=root.count)
        raw = types.SimpleNamespace(rows=fixture.rows, queries=read.queries,
                                    stores=stores, head_rows=head_rows)
        self.complete = complete_oracle.Cursor(raw, change=change)
        self.primary = primary_oracle.StoredTreeCursor(*read.trees.values(), reverse=True)
        self.ordinary = []
        for document, members in zip(fixture.resolved_documents, fixture.ordered_rows):
            if document["schema"] == "serverware.policyAuthorityCompleteIndexQuery/v1":
                continue
            if any(item["operator"] != "eq" for item in document["predicates"]):
                raise AssertionError("ordinary fixture escaped its literal equality-only recipe")
            clauses = " AND ".join(f"target.{item['column']} IS NOT DISTINCT FROM %s"
                                   for item in document["predicates"])
            order = ", ".join(f"target.{item['column']} " + ("DESC" if item["descending"] else "ASC")
                              for item in document["orderBy"])
            sql = ("SELECT pg_catalog.to_jsonb(target) AS row_value "
                   f"FROM serverware_metadata.{document['table']} AS target "
                   + ("WHERE " + clauses + " " if clauses else "") + f"ORDER BY {order} LIMIT %s")
            parameters = tuple(item["value"] for item in document["predicates"]) + (document["maximumRows"] + 1,)
            rows = [{"row_value": copy.deepcopy(item["row"])} for item in members if item["present"]]
            self.ordinary.append((sql, parameters, rows))
        self.calls, self.clock_reads, self.ordinary_position = [], 0, 0
        self.target, self.kind, self.rows = None, None, []
        self.write_mode, self.write_cursor = False, None

    def execute(self, sql, parameters=None):
        self.calls.append((sql, copy.deepcopy(parameters)))
        if sql == self.ROOT_SELECT:
            ordinal = len(self.root_calls)
            if ordinal >= len(self.root_order) or parameters != (self.root_order[ordinal],):
                raise AssertionError("root SQL differs from independent source table order")
            self.root_calls.append((sql, parameters))
            self.kind, self.target, self.root_table = "root", None, parameters[0]
            if self.on_root is not None:
                self.on_root(self.root_table)
        elif sql == "SELECT pg_catalog.clock_timestamp() AS database_now":
            if parameters is not None:
                raise AssertionError("clock query unexpectedly acquired parameters")
            self.clock_reads += 1
            if self.clock_reads != 1:
                raise AssertionError("private revocation read sampled a second database cutoff")
            self.kind, self.target = "clock", None
            if self.on_clock is not None:
                self.on_clock()
        elif any(f'FROM "serverware_metadata".{name} ' in sql for name in (
                "policy_authority_authenticated_leaves", "policy_authority_authenticated_tree_nodes")):
            self.kind, self.target = "proof", self.primary
            self.target.execute(sql, parameters)
        elif self.write_mode:
            if self.write_cursor is None:
                raise AssertionError("write acquisition has no independent stored population")
            self.kind, self.target = "write", self.write_cursor
            self.target.execute(sql, parameters)
        elif sql.startswith("SELECT pg_catalog.to_jsonb(target) AS row_value "):
            if self.ordinary_position >= len(self.ordinary):
                raise AssertionError("unexpected extra ordinary query")
            expected_sql, expected_parameters, rows = self.ordinary[self.ordinary_position]
            if sql != expected_sql or parameters != expected_parameters:
                raise AssertionError("ordinary SQL differs from independent resolved source declaration")
            self.ordinary_position += 1
            self.kind, self.target, self.rows = "ordinary", None, copy.deepcopy(rows)
        else:
            self.kind, self.target = "complete", self.complete
            self.target.execute(sql, parameters)
        return self

    def fetchone(self):
        if self.kind == "root":
            row = self.root_rows.get(self.root_table)
            if not self.return_root_aliases:
                row = copy.deepcopy(row)
            return row if self.root_change is None else self.root_change(self.root_table, row)
        if self.kind == "clock":
            return {"database_now": self.fixture.database_now}
        if self.kind != "proof":
            raise AssertionError("unexpected unbounded singleton read")
        return self.target.fetchone()

    def fetchall(self):
        if self.kind != "ordinary":
            raise AssertionError("only already SQL-bounded ordinary queries may use fetchall")
        return copy.deepcopy(self.rows)

    def fetchmany(self, maximum):
        if self.kind not in {"proof", "complete", "write"}:
            raise AssertionError("unexpected bounded fetch")
        return self.target.fetchmany(maximum)


class _RevocationOwnerGetters:
    """One-shot hooks model driver attribute lookup, not successful admission."""

    on_lookup = None

    def __getattribute__(self, name):
        if name in {"transaction", "cursor", "execute", "fetchone", "fetchall", "fetchmany",
                    "rowcount", "info", "pgconn", "closed", "autocommit", "__enter__", "__exit__"}:
            callback = object.__getattribute__(self, "on_lookup")
            if callback is not None:
                callback(name)
        return object.__getattribute__(self, name)


class _RevocationOwnerScope(_RevocationOwnerGetters):
    """Driver lifecycle recorder only, never a transaction/ACL proof."""

    def __init__(self, connection, label, value, *, manager=None, transaction=False):
        self.connection, self.label, self.value = connection, label, value
        self.manager, self.transaction = manager, transaction
        self.previous_status = None

    def __enter__(self):
        if self.manager is not None:
            self.manager.__enter__()
        if self.transaction:
            self.previous_status = self.connection.info.transaction_status
            self.connection.info.transaction_status = 2
        self.connection.event(self.label + ".enter")
        if self.transaction and self.connection.transaction_enter_replacement is not None:
            return self.connection.transaction_enter_replacement
        return self if self.transaction else self.value

    def __exit__(self, kind, error, traceback):
        try:
            if self.manager is not None:
                self.manager.__exit__(kind, error, traceback)
        finally:
            if self.transaction:
                self.connection.info.transaction_status = self.previous_status
            self.connection.event(self.label + ".exit")
        return False


class _RevocationOwnerConnection(_RevocationOwnerGetters):
    def __init__(self, name, cursor, events, *, recorder=None):
        self.name, self.sql_cursor, self.events = name, cursor, events
        self.recorder, self.on_event = recorder, None
        self.info = types.SimpleNamespace(transaction_status=0)
        self.closed, self.autocommit, self.pgconn = False, False, object()
        self.transactions = 0
        self.cursor_lookup = None
        self.enter_result = self
        self.transaction_enter_replacement = None
        self.cursor_enter_replacement = None
        self.execute_replacement = None

    def event(self, name):
        self.events.append(name)
        if self.on_event is not None:
            self.on_event(name)

    def __enter__(self):
        self.event(self.name + ".connection.enter")
        return self.enter_result

    def __exit__(self, kind, error, traceback):
        try:
            self.event(self.name + ".connection.exit")
        finally:
            self.closed = True
        return False

    def close(self):
        self.closed = True
        self.event(self.name + ".close")

    def transaction(self):
        self.transactions += 1
        manager = None if self.recorder is None else self.recorder.transaction()
        return _RevocationOwnerScope(self, f"{self.name}.transaction{self.transactions}", self,
                                    manager=manager, transaction=True)

    def cursor(self):
        scope = _RevocationOwnerCursorScope(self, self.name + ".cursor", self.sql_cursor)
        scope.on_lookup = self.cursor_lookup
        return scope


class _RevocationOwnerCursorScope(_RevocationOwnerScope):
    """Model the same cursor returned by psycopg entry and execute.

    Only driver lifecycle is synthetic. SQL responses and genuine production
    workers remain unchanged; this recorder does not establish DB admission.
    """

    def __enter__(self):
        super().__enter__()
        return self if self.connection.cursor_enter_replacement is None else self.connection.cursor_enter_replacement

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        result = self.value.execute(*arguments)
        if self.connection.execute_replacement is not None:
            return self.connection.execute_replacement
        return self if result is self.value else result

    def fetchone(self):
        return self.value.fetchone()

    def fetchall(self):
        return self.value.fetchall()

    def fetchmany(self, size):
        return self.value.fetchmany(size)

    @property
    def rowcount(self):
        return self.value.rowcount


class _RevocationOwnerReadCursor:
    """Actual identity/manifest SQL responses preceding the real proof cursor."""

    def __init__(self, cursor, identity):
        import test_authority_primary_contract as manifest_oracle

        self.cursor, self.identity = cursor, identity
        operation = cursor.fixture.request["operation"]
        self.business_rows, _ = manifest_oracle.manifest_row_fixture(operation, authorization=False)
        self.authorization_rows, _ = manifest_oracle.manifest_row_fixture(operation, authorization=True)
        self.calls, self.result, self.active = [], None, False
        self.identity_row = {"role": identity.database_role, "ssl": True,
            "client_dn": identity.tls_client_dn, "client_serial": identity.tls_client_serial,
            "issuer_dn": identity.tls_issuer_dn,
            **{name: False for name in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
                "rolbypassrls", "schema_create", "database_create", "database_temporary")}}
        self.mutation_row = None

    def execute(self, sql, parameters=None):
        self.calls.append((sql, copy.deepcopy(parameters)))
        self.active = False
        if sql == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE":
            self.result = None
        elif sql.startswith("SELECT current_user AS role, ssl.ssl, ssl.client_dn, "):
            self.result = self.identity_row
        elif sql.startswith("SELECT 1 FROM pg_catalog.pg_class AS relation "):
            self.result = self.mutation_row
        elif "FROM serverware_metadata.policy_authority_query_dependency_manifests " in sql:
            if parameters != (self.cursor.fixture.request["operation"], len(self.business_rows) + 1):
                raise AssertionError("business manifest SQL lost its source count-plus-one bound")
            self.result = self.business_rows
        elif "FROM serverware_metadata.policy_authority_authorization_dependency_manifests " in sql:
            if parameters != (self.cursor.fixture.request["operation"], len(self.authorization_rows) + 1):
                raise AssertionError("authorization manifest SQL lost its source count-plus-one bound")
            self.result = self.authorization_rows
        else:
            self.active = True
            self.cursor.execute(sql, parameters)
        return self

    def fetchone(self):
        return self.cursor.fetchone() if self.active else copy.deepcopy(self.result)

    def fetchall(self):
        return self.cursor.fetchall() if self.active else copy.deepcopy(self.result)

    def fetchmany(self, maximum):
        if not self.active:
            raise AssertionError("metadata admission unexpectedly used a proof fetch")
        return self.cursor.fetchmany(maximum)


class _RevocationOwnerWriteCursor:
    """Exact synthetic metadata observations followed by the genuine store.

    Identity values are fixture claims, not TLS evidence. The actual fixed ACL
    SQL is matched but not executed here; the separate native catalog fixture
    owns real-query coverage. No helper or verifier is replaced by success.
    """

    def __init__(self, recorder, database_identity):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store.planner_writer_sql import planner_writer_privilege_check

        self.recorder, self.cursor, self.calls = recorder, recorder.cursor(), []
        role, client_dn, client_serial, issuer_dn = database_identity
        self.identity_sql = writer._IDENTITY_SQL
        self.privilege_sql, self.privilege_parameters = planner_writer_privilege_check(
            role=role, namespace="serverware_metadata")
        self.identity_row = {"server_version_num": 160004, "role": role, "session_role": role,
            "transaction_isolation": "serializable", "transaction_read_only": "off",
            "transaction_deferrable": "off", "ssl": True, "client_dn": client_dn,
            "client_serial": client_serial, "issuer_dn": issuer_dn, "rolcanlogin": True,
            **{name: False for name in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
                "rolbypassrls", "schema_create", "database_create", "database_temporary")}}
        self.privilege_row, self.result, self.phase = None, None, 0
        self.on_execute, self.on_fetch, self.return_aliases = None, None, False

    def execute(self, sql, parameters=()):
        self.calls.append((sql, copy.deepcopy(parameters)))
        if self.on_execute is not None:
            self.on_execute(sql, parameters)
        if sql == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE":
            if self.phase != 0 or parameters not in (None, ()):
                raise AssertionError("writer mode is not the first parameter-free statement")
            self.result, self.phase = None, 1
        elif sql == self.identity_sql:
            if self.phase != 1 or parameters not in (None, ()):
                raise AssertionError("writer identity does not immediately follow its mode")
            self.result, self.phase = self.identity_row, 2
        elif sql == self.privilege_sql:
            if self.phase != 2 or parameters != self.privilege_parameters:
                raise AssertionError("writer effective ACL query lost its exact source parameters/order")
            self.result, self.phase = self.privilege_row, 3
        else:
            if self.phase != 3:
                raise AssertionError("custody SQL ran before complete writer admission observations")
            self.result = None
            self.cursor.execute(sql, parameters)
        return self

    def fetchone(self):
        if self.on_fetch is not None:
            self.on_fetch()
        if self.phase < 3 or (self.calls and self.calls[-1][0] == self.privilege_sql):
            return self.result if self.return_aliases else copy.deepcopy(self.result)
        return self.cursor.fetchone()

    @property
    def rowcount(self):
        return self.cursor.rowcount


class TypedRequestPlannerIntegrationTests(unittest.TestCase):
    """Real planner facade/reader checks; registry/startup closure is required.

    These assertions were split from component arithmetic under the reviewed
    authority-request-commitment coverage transition. Imports must succeed
    genuinely: there is no registry patch, skip or expected-failure fallback.
    Private counted-marker checks do not enable a v3 evidence producer or
    establish a maintained population, authenticated clock or current roots.
    """

    def setUp(self) -> None:
        from serverware import authority_planner
        from serverware import authority_request_commitment
        import test_authority_typed_request_work

        self.planner = authority_planner
        self.commitment = authority_request_commitment
        self.oracle = test_authority_typed_request_work

    def test_registered_public_commitments_preserve_independent_request_and_operation_ids(self) -> None:
        for operation in ("webauthn.counter.cas", "webauthn.challenge.create"):
            request = self.oracle.request_fixture(operation=operation)
            expected = self.oracle.expected_digest(request)
            with self.subTest(operation=operation):
                self.assertEqual(self.planner.typed_request_digest(request), expected)
                self.assertEqual(self.planner.operation_id(operation, expected), request["operationId"])
                self.assertEqual(self.commitment.operation_id(operation, expected), request["operationId"])

    def test_public_mapping_compatibility_remains_a_real_planner_call(self) -> None:
        request = self.oracle.request_fixture(operation="webauthn.counter.cas")
        self.assertEqual(self.planner.typed_request_digest(types.MappingProxyType(request)),
                         self.oracle.expected_digest(request))

    def test_intentionally_disabled_public_operation_denies_before_shared_computation(self) -> None:
        request = self.oracle.request_fixture(operation="jit.consume")
        with patch.object(self.planner, "_typed_request_digest",
                          wraps=self.planner._typed_request_digest) as actual_worker:
            with self.assertRaisesRegex(self.planner.AuthorityPlannerError,
                                        "typed planner request is not closed"):
                self.planner.typed_request_digest(request)
        self.assertEqual(actual_worker.call_count, 0)

    def test_planner_reexports_actual_shared_bodies_and_exception_identity(self) -> None:
        for name in ("AuthorityPlannerError", "canonical_bytes", "framed_digest", "operation_id",
                     "_typed_request_digest", "_business_intent", "_authorization_arguments",
                     "_request_different"):
            with self.subTest(name=name):
                self.assertIs(getattr(self.planner, name), getattr(self.commitment, name))
        for encoder in (self.planner.canonical_bytes, self.commitment.canonical_bytes):
            with self.assertRaises(TypeError):
                encoder({"unencodable": object()})
        malformed = self.oracle.request_fixture(operation="webauthn.counter.cas")
        malformed["schema"] = "not-the-request-schema"
        with self.assertRaises(self.commitment.AuthorityPlannerError):
            self.planner.typed_request_digest(malformed)
        with self.assertRaises(self.planner.AuthorityPlannerError):
            self.commitment._typed_request_digest(malformed, work=None)

    def query_reader_fixture(self, work):
        from serverware import authority_contract, authority_query_staging, authority_transition_core
        import test_authority_root_transition as roots

        operation = "webauthn.counter.cas"
        inputs, _ = roots.input_fixture(operation, {})
        query = authority_transition_core.BoundedQuery(
            query_id=f"serverware.policyAuthorityQuery/{operation}/empty-reader/webauthn_credentials/v1",
            table="webauthn_credentials", predicates=(),
            order_by=(authority_transition_core.QueryOrder("id"),), maximum_rows=1)
        request = {}
        for paths in authority_contract.operation_spec(operation)["selectors"].values():
            for path in paths:
                current = request
                for part in path[:-1]:
                    current = current.setdefault(part, {})
                current[path[-1]] = "fixture-selector"
        cursor = MagicMock()
        cursor.execute.return_value.fetchall.return_value = []
        collector = authority_query_staging.StagedQueryProofs(
            operation=operation, business_before_roots=inputs["business_before_roots"],
            authorization_before_roots=inputs["authorization_before_roots"], query_work=work)
        return cursor, {
            "operation": operation, "request": request, "queries": (query,),
            "manifest": ({"table": "webauthn_credentials", "keyColumns": ["id"]},),
            "trace": self.planner.PlannerTrace(operation=operation),
            "query_sources": collector, "query_work": work,
        }

    def test_real_query_reader_empty_observation_preserves_legacy_bytes_with_one_meter(self) -> None:
        # A real planner worker with a deterministic empty SQL responder, not
        # native PostgreSQL or a complete signed-plan invocation. The genuine
        # registry import in setUp must succeed; no bypass or skip is allowed.
        from serverware import authority_query_reads as reads
        from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits

        work = _ValidationWork(QueryReadValidationLimits())
        cursor, arguments = self.query_reader_fixture(work)
        selected, queries, observed = self.planner._read_bounded_transition_rows(cursor, **arguments)
        self.assertEqual(selected, ())
        self.assertEqual(queries, arguments["queries"])
        query, = queries
        resolved = reads.resolve_query(arguments["operation"], query, prior_reads=(), selected_rows=())
        expected = reads.capture_query_read(arguments["operation"], query, resolved_query=resolved,
            ordered_selected_rows=(), returned_row_count=0)
        self.assertEqual(observed, (expected,))
        cursor.execute.assert_called_once()
        self.assertGreater(work.input_bytes, 0)
        self.assertGreater(work.json_nodes, 0)
        self.assertIs(arguments["query_sources"]._query_work, work)

    def test_real_query_reader_exhausted_meter_denies_before_any_business_or_proof_sql(self) -> None:
        from serverware.authority_query_reads import QueryReadError
        from serverware.authority_query_read_work import (
            _ValidationWork, QueryReadValidationLimits, QueryReadWorkError,
        )

        work = _ValidationWork(QueryReadValidationLimits())
        work.charge(json_nodes=work.limits.max_json_nodes)
        cursor, arguments = self.query_reader_fixture(work)
        with self.assertRaises(QueryReadError) as denied:
            self.planner._read_bounded_transition_rows(cursor, **arguments)
        self.assertIsInstance(denied.exception.__cause__, QueryReadWorkError)
        cursor.execute.assert_not_called()
        self.assertEqual(work.json_nodes, work.limits.max_json_nodes)

    def test_default_v3_trace_rejects_counted_head_range_and_complete_primary_markers(self) -> None:
        import test_authority_index_trace as markers

        cases = ((markers.HEAD_TABLE, markers.head_marker()),
                 (markers.LEAF_TABLE, markers.leaf_marker()),
                 (markers.NODE_TABLE, markers.node_marker()),
                 (markers.ROLES[2][1], markers.primary_marker()))
        for table, key in cases:
            with self.subTest(table=table):
                trace = self.planner.PlannerTrace(operation=markers.OPERATION)
                with self.assertRaises(self.planner.AuthorityPlannerError):
                    trace.read(table, key)
                self.assertEqual(trace._entries, [])
                self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (0, 0))
        # Ordinary exact business-key reads retain their existing admission;
        # their table being readable does not admit the complete-read marker.
        trace = self.planner.PlannerTrace(operation=markers.OPERATION)
        trace.read(markers.ROLES[2][1], {"id": "ordinary-member"})
        self.assertEqual(trace._entries, [{"ordinal": 0, "access": "read",
            "table": markers.ROLES[2][1], "key": {"id": "ordinary-member"}}])

    def test_private_revoke_trace_accepts_exact_source_markers_without_write_expansion(self) -> None:
        from serverware import authority_audit_trace, authority_transition_registry
        import test_authority_index_trace as markers

        self.assertIs(self.planner.authority_transition_registry, authority_transition_registry)
        trace = self.planner.PlannerTrace(operation=markers.OPERATION, _complete_queries=True)
        ordinary = self.planner.PlannerTrace(operation=markers.OPERATION)
        self.assertIs(type(trace._budget), authority_audit_trace.AuditTraceBudget)
        self.assertEqual(trace.allowed_reads - ordinary.allowed_reads,
                         {markers.HEAD_TABLE, markers.LEAF_TABLE, markers.NODE_TABLE})
        self.assertEqual(trace.allowed_writes, ordinary.allowed_writes)
        entries = [(markers.HEAD_TABLE, markers.head_marker())]
        for role in markers.ROLES:
            entries.extend(((markers.LEAF_TABLE, markers.leaf_marker(role)),
                            (markers.NODE_TABLE, markers.node_marker(role)),
                            (role[1], markers.primary_marker(role))))
        for table, key in entries:
            trace.read(table, key)
        expected = [{"ordinal": ordinal, "access": "read", "table": table,
                     "key": copy.deepcopy(key)} for ordinal, (table, key) in enumerate(entries)]
        self.assertEqual(trace._entries, expected)
        self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (19, 0))
        for table in (markers.HEAD_TABLE, markers.LEAF_TABLE, markers.NODE_TABLE):
            with self.subTest(write_table=table), self.assertRaises(self.planner.AuthorityPlannerError):
                trace.write(table, {"indexId": markers.HEAD_IDS[0]})
        self.assertEqual(trace._entries, expected)

    def test_private_complete_trace_rejects_other_operations_flags_and_nonclosed_markers(self) -> None:
        import test_authority_index_trace as markers

        for operation in ("webauthn.counter.cas", "webauthn.challenge.create", "jit.consume", "unknown"):
            with self.subTest(operation=operation), self.assertRaises(self.planner.AuthorityPlannerError):
                self.planner.PlannerTrace(operation=operation, _complete_queries=True)
        for flag in (1, 0, "true", None, {}):
            with self.subTest(flag=flag), self.assertRaises(self.planner.AuthorityPlannerError):
                self.planner.PlannerTrace(operation=markers.OPERATION, _complete_queries=flag)
        cases = (
            (markers.HEAD_TABLE, {**markers.head_marker(), "indexIds": list(markers.HEAD_IDS[:-1])}),
            (markers.LEAF_TABLE, {**markers.leaf_marker(), "extra": True}),
            (markers.LEAF_TABLE, {**markers.leaf_marker(), "indexId": "webauthn_publication_status"}),
            (markers.NODE_TABLE, {**markers.node_marker(), "limit": 2}),
            (markers.NODE_TABLE, {**markers.node_marker(), "prefixes": [{"depth": 1, "pathPrefix": "ff"}]}),
            (markers.ROLES[2][1], {**markers.primary_marker(), "limit": 3}),
            (markers.ROLES[0][1], markers.primary_marker()),
            (markers.HEAD_TABLE, types.MappingProxyType(markers.head_marker())),
        )
        for table, key in cases:
            with self.subTest(table=table, key=key):
                trace = self.planner.PlannerTrace(operation=markers.OPERATION, _complete_queries=True)
                with self.assertRaisesRegex(self.planner.AuthorityPlannerError, "not source closed"):
                    trace.read(table, key)
                self.assertEqual(trace._entries, [])
                self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (0, 0))

    def test_complete_markers_use_unchanged_business_trace_budget_not_framework_bonus(self) -> None:
        from serverware import authority_audit_capacity, authority_audit_trace
        import test_authority_index_trace as markers

        self.assertEqual((authority_audit_trace.MAX_TRACE_ENTRIES,
                          authority_audit_trace.MAX_AUDIT_CAPACITY_TRACE_ENTRIES,
                          authority_audit_trace.MAX_PLAN_TRACE_ENTRIES), (4096, 69, 4165))
        trace = self.planner.PlannerTrace(operation=markers.OPERATION, _complete_queries=True)
        original_budget = trace._budget
        direct_budget = authority_audit_trace.AuditTraceBudget(markers.OPERATION)
        cases = ((markers.HEAD_TABLE, markers.head_marker()),
                 (markers.LEAF_TABLE, markers.leaf_marker()),
                 (markers.NODE_TABLE, markers.node_marker()),
                 (markers.ROLES[2][1], markers.primary_marker()))
        for ordinal in range(4096):
            table, key = cases[ordinal % len(cases)]
            trace.read(table, key)
            direct_budget.append({"ordinal": ordinal, "access": "read", "table": table, "key": key})
        self.assertIs(trace._budget, original_budget)
        self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (4096, 0))
        self.assertEqual((direct_budget.business_entries, direct_budget.framework_entries), (4096, 0))
        # The genuine framework scan remains separately classified. No trace
        # close/currentness assertion is made without its full primary proof.
        scan = authority_audit_trace.audit_capacity_scan_key()
        trace.read(authority_audit_capacity.AGGREGATE_TABLE, scan)
        self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (4096, 1))
        self.assertEqual(len(trace._entries), 4097)
        with self.assertRaisesRegex(self.planner.AuthorityPlannerError, "trace bound"):
            trace.read(markers.HEAD_TABLE, markers.head_marker())
        with self.assertRaises(authority_audit_trace.AuditTraceError):
            direct_budget.append({"ordinal": 4096, "access": "read",
                "table": markers.HEAD_TABLE, "key": markers.head_marker()})
        self.assertEqual(len(trace._entries), 4097)

    def test_real_cascade_complete_inventory_denies_before_sql_without_private_acquisition(self) -> None:
        from serverware import authority_complete_query, authority_primary_contract
        from serverware import authority_query_staging, authority_transition_core, authority_transition_webauthn
        from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
        import test_authority_complete_query as declarations
        import test_authority_root_transition as roots

        operation = "webauthn.credential.revoke"
        arguments = authority_transition_webauthn.prepare_revocation_input(declarations.arguments())
        queries = authority_transition_webauthn.cascade_queries_at_cutoff(
            operation=operation, values=arguments, cutoff_us=1_000_007,
            request_digest="sha256:" + "a" * 64)
        self.assertIs(type(queries[0]), authority_transition_core.BoundedQuery)
        self.assertEqual(sum(type(query) is authority_complete_query.CompleteIndexQuery for query in queries), 5)
        inputs, _ = roots.input_fixture(operation, {})
        manifest = tuple({"table": contract.table, "keyColumns": list(contract.key_columns)}
                         for contract in authority_primary_contract.primary_table_contracts(operation))
        for trace_opt_in in (False, True):
            with self.subTest(trace_opt_in=trace_opt_in):
                work = _ValidationWork(QueryReadValidationLimits())
                sources = authority_query_staging.StagedQueryProofs(operation=operation,
                    business_before_roots=inputs["business_before_roots"],
                    authorization_before_roots=inputs["authorization_before_roots"], query_work=work)
                trace = self.planner.PlannerTrace(operation=operation, _complete_queries=trace_opt_in)
                cursor = MagicMock()
                cursor.execute.side_effect = AssertionError("default complete-query gate reached SQL")
                with self.assertRaisesRegex(self.planner.AuthorityPlannerError,
                                            "complete index query acquisition is not available"):
                    self.planner._read_bounded_transition_rows(cursor, operation=operation,
                        request={"arguments": arguments}, queries=queries, manifest=manifest,
                        trace=trace, query_sources=sources, query_work=work)
                cursor.execute.assert_not_called()
                self.assertEqual(trace._entries, [])
                self.assertIs(sources._query_work, work)
                self.assertGreater(work.hash_work, 0)
                self.assertGreater(work.input_bytes, 0)

    def test_raw_complete_evidence_is_denied_before_real_kernel_context_or_transition(self) -> None:
        from datetime import datetime, timezone
        from serverware import authority_complete_acquisition, authority_transition_core
        from serverware import authority_transition_registry, authority_transition_webauthn

        kernels = (authority_transition_registry.KERNELS["webauthn.counter.cas"],
                   authority_transition_webauthn.WebAuthnCredentialRevokeKernel())
        # This freely constructible raw DTO is deliberately not claimed to
        # contain verified observations. Neither it nor a real candidate
        # object may bypass the missing retained-evidence protocol gate.
        raw = authority_complete_acquisition.CompleteAcquisitionEvidence(
            cutoff_us=1_000_007, heads=(), frontiers=(), business_before_roots=(),
            authorization_before_roots=(), before_proofs=())
        for kernel in kernels:
            with self.subTest(operation=kernel.operation):
                program = self.planner.TypedTransitionPlanningProgram(
                    operation=kernel.operation, handler=kernel.handler, kernel=kernel)
                state = self.planner.PlanningState(
                    database_now=datetime(1970, 1, 1, 0, 0, 1, 7, tzinfo=timezone.utc),
                    complete_query_evidence=raw)
                request = self.oracle.request_fixture(operation=kernel.operation)
                with patch.object(authority_transition_core, "KernelContext",
                                  wraps=authority_transition_core.KernelContext) as context, \
                        patch.object(type(kernel), "transition", wraps=kernel.transition) as transition:
                    with self.assertRaisesRegex(self.planner.AuthorityPlannerError,
                            "^complete planning requires the successor retained-evidence protocol$"):
                        program(operation=kernel.operation, handler=kernel.handler, request=request,
                                manifest=(), selected_rows=(), state=state)
                self.assertEqual((context.call_count, transition.call_count), (0, 0))

    def revocation_reader_fixture(self, *, work=None, separate_signer=False, include_audit=True):
        from serverware import authority_transition_webauthn as candidate
        from serverware import authority_webauthn_assertion as assertion
        from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
        from authority_revocation_semantics_fixture import SemanticFixture

        fixture = SemanticFixture(separate_signer=separate_signer, include_audit=include_audit)
        # The private read method consumes an already-verified projection; this
        # fixture obtains it from the actual deterministic Ed25519 receipt.
        # The signer pins and observed roots are synthetic, not current authority.
        inputs = fixture.inputs()
        verified = assertion.verify_revoke_assertion_evidence(inputs["evidence"],
            operation_id=fixture.operation_id, request_digest=fixture.request_digest,
            **{name: inputs[name] for name in ("capability_id", "verifier_identity",
                "verifier_public_key", "now_epoch_ns", "deadline_epoch_ns", "maximum_age_ns")})
        kernel = candidate.WebAuthnCredentialRevokeKernel()
        program = self.planner.TypedTransitionPlanningProgram(
            operation=kernel.operation, handler=kernel.handler, kernel=kernel)
        work = _ValidationWork(QueryReadValidationLimits()) if work is None else work
        arguments = {"request": copy.deepcopy(fixture.request),
            "manifest": tuple({"table": item.table, "keyColumns": list(item.key_columns)}
                              for item in fixture.read_write.read.contracts),
            "trace": self.planner.PlannerTrace(operation=kernel.operation, _complete_queries=True),
            "query_work": work, "verified_webauthn_evidence": verified,
            "business_before_roots": copy.deepcopy(fixture.expected_before["businessBeforeRoots"]),
            "authorization_before_roots": copy.deepcopy(fixture.expected_before["authorizationBeforeRoots"])}
        return fixture, _RevocationReadCursor(fixture), program, arguments

    def assert_revocation_read(self, fixture, selected, state):
        self.assertEqual(selected, fixture.selected_rows)
        self.assertEqual(state.database_now, fixture.database_now)
        self.assertEqual(tuple(query.contract_value() for query in state.query_program), fixture.documents)
        self.assertEqual(state.query_reads, fixture.query_reads)
        self.assertEqual(state.query_work_units, sum(item["workUnits"] for item in fixture.documents))
        self.assertEqual(dict(state.verified_webauthn_evidence), fixture.receipt.evidence)
        raw = state.complete_query_evidence
        self.assertEqual(raw.cutoff_us, fixture.cutoff_us)
        self.assertEqual(raw.business_before_roots, tuple(fixture.expected_before["businessBeforeRoots"]))
        self.assertEqual(raw.authorization_before_roots, tuple(fixture.expected_before["authorizationBeforeRoots"]))
        self.assertEqual(raw.before_proofs, fixture.before_proofs)
        self.assertEqual(tuple((head.index_id, head.index_revision, head.index_root.digest, head.index_root.count)
                              for head in raw.heads),
            tuple((name, revision, root.digest, root.count)
                  for name, (revision, root) in fixture.read_write.heads.items()))
        expected = fixture.read_write.read.arguments()["query_frontiers"]
        self.assertEqual(raw.frontiers, expected)

    def test_private_revocation_reader_uses_one_clock_one_generation_and_real_shared_workers(self):
        from serverware import authority_complete_acquisition as acquisition
        from serverware import authority_complete_query_batch as batch
        from serverware import authority_query_staging as staging
        from serverware import authority_transition_webauthn as candidate
        from serverware import authority_transition_core as core

        fixture, cursor, program, arguments = self.revocation_reader_fixture()
        calls = []
        collector_init = acquisition._CompleteQueryAcquisition.__init__
        staging_init = staging.StagedQueryProofs.__init__

        def collector(instance, *args, **kwargs):
            calls.append(("collector", args, kwargs, instance))
            return collector_init(instance, *args, **kwargs)

        def stage(instance, *args, **kwargs):
            calls.append(("staging", args, kwargs, instance))
            return staging_init(instance, *args, **kwargs)

        with patch.object(self.planner, "_read_database_now", wraps=self.planner._read_database_now) as clock, \
                patch.object(candidate, "_revocation_query_program", wraps=candidate._revocation_query_program) as generation, \
                patch.object(acquisition._CompleteQueryAcquisition, "__init__", new=collector), \
                patch.object(staging.StagedQueryProofs, "__init__", new=stage), \
                patch.object(batch, "_verify_complete_query_batch", wraps=batch._verify_complete_query_batch) as proof, \
                patch.object(self.planner, "_read_bounded_transition_rows", wraps=self.planner._read_bounded_transition_rows) as read:
            selected, state = program._read_revocation_inputs(cursor, **arguments)
        self.assert_revocation_read(fixture, selected, state)
        self.assertEqual((clock.call_count, cursor.clock_reads, generation.call_count, read.call_count, proof.call_count),
                         (1, 1, 1, 1, 1))
        self.assertEqual([name for name, *_ in calls], ["collector", "staging"])
        actual_collector, actual_staging = calls[0][3], calls[1][3]
        self.assertIs(calls[0][1][0], cursor)
        self.assertIs(calls[0][2]["trace"], arguments["trace"])
        for actual in (generation.call_args.kwargs["work"], calls[0][2]["work"],
                       calls[1][2]["query_work"], read.call_args.kwargs["query_work"],
                       proof.call_args.kwargs["work"]):
            self.assertIs(actual, arguments["query_work"])
        self.assertIs(read.call_args.kwargs["complete_acquisition"], actual_collector)
        self.assertIs(read.call_args.kwargs["query_sources"], actual_staging)
        self.assertIs(read.call_args.args[0], cursor)
        self.assertIs(read.call_args.kwargs["trace"], arguments["trace"])
        for name in ("business_before_roots", "authorization_before_roots"):
            self.assertIs(calls[0][2][name], calls[1][2][name])
            self.assertEqual(calls[0][2][name], arguments[name])
        self.assertEqual(generation.call_args.kwargs["cutoff_us"], fixture.cutoff_us)
        self.assertEqual(cursor.ordinary_position, len(cursor.ordinary))
        self.assertGreater(arguments["query_work"].hash_work, 0)
        # Even genuinely acquired raw evidence does not open the v3 kernel path.
        with patch.object(core, "KernelContext", wraps=core.KernelContext) as context, \
                patch.object(type(program.kernel), "transition", wraps=program.kernel.transition) as transition:
            with self.assertRaisesRegex(self.planner.AuthorityPlannerError, "successor retained-evidence protocol"):
                program(operation=program.operation, handler=program.handler, request=arguments["request"],
                        manifest=arguments["manifest"], selected_rows=selected, state=state)
        self.assertEqual((context.call_count, transition.call_count), (0, 0))

    def test_private_revocation_reader_retains_merged_proofs_without_reacquiring_staged_rows(self):
        import test_authority_radix_proof as proof_oracle
        from serverware import authority_complete_query_batch as batch

        for separate, audit in ((False, True), (True, False)):
            with self.subTest(separate_signer=separate, include_audit=audit):
                fixture, cursor, program, arguments = self.revocation_reader_fixture(
                    separate_signer=separate, include_audit=audit)
                selected, state = program._read_revocation_inputs(cursor, **arguments)
                self.assert_revocation_read(fixture, selected, state)
                expected = {(item["table"], proof_oracle.sql_digest(
                    "serverware.policyAuthorityAuthenticatedKey/v1", item["table"].encode("utf-8"),
                    proof_oracle.sql_json(item["key"]))) for item in fixture.selected_rows}
                leaf_reads = [parameters for sql, parameters in cursor.primary.calls
                              if "policy_authority_authenticated_leaves " in sql]
                self.assertEqual(set(leaf_reads), expected)
                self.assertEqual(len(leaf_reads), len(expected))
                high_water = [value for value in leaf_reads if value[0] == "webauthn_trust_publication_high_water"]
                self.assertEqual(len(high_water), 1)
                self.assertEqual(len(state.complete_query_evidence.frontiers), 6)
                self.assertEqual(len(state.complete_query_evidence.heads), 9)
                before_calls = len(cursor.calls)
                # Raw retained fields replay in the genuine engine without SQL
                # or any successful-result token. This is component proof only.
                raw = state.complete_query_evidence
                query_inputs = fixture.read_write.read.arguments()
                batch.verify_complete_query_batch(**{**query_inputs, "selected_rows": selected,
                    "before_proofs": raw.before_proofs, "business_before_roots": raw.business_before_roots,
                    "authorization_before_roots": raw.authorization_before_roots,
                    "query_frontiers": raw.frontiers})
                self.assertEqual(len(cursor.calls), before_calls)

    def test_private_revocation_reader_owns_raw_inputs_before_the_clock_callback(self):
        fixture, cursor, program, arguments = self.revocation_reader_fixture()
        arguments["verified_webauthn_evidence"] = dict(arguments["verified_webauthn_evidence"])
        original = copy.deepcopy({name: value for name, value in arguments.items()
                                  if name not in {"trace", "query_work"}})

        def mutate_caller():
            arguments["request"]["arguments"]["record_id"] = "caller-changed"
            arguments["manifest"][0]["keyColumns"][:] = ["wrong"]
            arguments["verified_webauthn_evidence"]["challengeId"] = "wrong"
            arguments["business_before_roots"][0]["rootDigest"] = "sha256:" + "0" * 64
            arguments["authorization_before_roots"][0]["rootRevision"] += 1

        cursor.on_clock = mutate_caller
        selected, state = program._read_revocation_inputs(cursor, **arguments)
        self.assert_revocation_read(fixture, selected, state)
        self.assertNotEqual(arguments["request"], original["request"])
        self.assertEqual(state.complete_query_evidence.business_before_roots,
                         tuple(original["business_before_roots"]))
        expected_digest = fixture.before_proofs[0]["rootDigest"]
        self.assertIsNot(state.complete_query_evidence.before_proofs[0], fixture.before_proofs[0])
        state.complete_query_evidence.before_proofs[0]["rootDigest"] = "sha256:" + "f" * 64
        self.assertEqual(fixture.before_proofs[0]["rootDigest"], expected_digest)

    def test_private_revocation_reader_rejects_wrong_identity_trace_and_work_before_clock(self):
        from dataclasses import replace
        from serverware import authority_transition_registry as registry
        from serverware import authority_transition_webauthn as candidate
        from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits

        class DerivedKernel(candidate.WebAuthnCredentialRevokeKernel):
            pass

        class DerivedWork(_ValidationWork):
            pass

        fixture, _, program, arguments = self.revocation_reader_fixture()
        cases = [(replace(program, operation="webauthn.counter.cas"), {}),
            (replace(program, handler="wrong"), {}),
            (replace(program, kernel=registry.KERNELS["webauthn.counter.cas"]), {}),
            (replace(program, kernel=DerivedKernel()), {}),
            (program, {"trace": self.planner.PlannerTrace(operation=program.operation)}),
            (program, {"trace": self.planner.PlannerTrace(operation="webauthn.counter.cas")}),
            (program, {"query_work": None}),
            (program, {"query_work": DerivedWork(QueryReadValidationLimits())})]
        for tested, changes in cases:
            with self.subTest(changes=changes, operation=tested.operation):
                cursor = _RevocationReadCursor(fixture)
                with self.assertRaisesRegex(self.planner.AuthorityPlannerError, "private revocation read identity changed"):
                    tested._read_revocation_inputs(cursor, **{**arguments, **changes})
                self.assertEqual(cursor.calls, [])

    def test_private_revocation_reader_rechecks_trace_identity_after_clock_before_generation(self):
        from serverware import authority_transition_webauthn as candidate

        fixture, cursor, program, arguments = self.revocation_reader_fixture()
        cursor.on_clock = lambda: setattr(arguments["trace"], "_complete_queries", False)
        with patch.object(candidate, "_revocation_query_program", wraps=candidate._revocation_query_program) as generation:
            with self.assertRaisesRegex(self.planner.AuthorityPlannerError, "private revocation read identity changed"):
                program._read_revocation_inputs(cursor, **arguments)
        self.assertEqual((cursor.clock_reads, generation.call_count), (1, 0))
        self.assertEqual(len(cursor.calls), 1)

    def test_private_revocation_reader_denies_nonclosed_inputs_and_unverified_raw_dto_shortcuts(self):
        from collections import UserDict
        from serverware import authority_complete_acquisition as acquisition

        fixture, _, program, arguments = self.revocation_reader_fixture()
        raw = acquisition.CompleteAcquisitionEvidence(cutoff_us=fixture.cutoff_us, heads=(),
            frontiers=(), business_before_roots=(), authorization_before_roots=(), before_proofs=())
        evidence = dict(arguments["verified_webauthn_evidence"])
        cases = ({"request": types.MappingProxyType(arguments["request"])},
            {"manifest": list(arguments["manifest"])}, {"verified_webauthn_evidence": raw},
            {"verified_webauthn_evidence": UserDict(evidence)},
            {"verified_webauthn_evidence": {**evidence, "extra": None}},
            {"verified_webauthn_evidence": {name: value for name, value in evidence.items()
                                           if name != "credentialRecordId"}})
        for changes in cases:
            with self.subTest(changes=tuple(changes)):
                cursor = _RevocationReadCursor(fixture)
                with self.assertRaises(self.planner.AuthorityPlannerError):
                    program._read_revocation_inputs(cursor, **{**arguments, **changes})
                self.assertEqual(cursor.calls, [])
        for shortcut in ("complete_acquisition", "query_sources", "queries"):
            with self.subTest(shortcut=shortcut):
                cursor = _RevocationReadCursor(fixture)
                with self.assertRaises(TypeError):
                    program._read_revocation_inputs(cursor, **{**arguments, shortcut: raw})
                self.assertEqual(cursor.calls, [])

    def test_private_revocation_reader_uses_remaining_work_and_denies_before_clock_when_exhausted(self):
        from serverware import authority_transition_webauthn as candidate
        from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits, QueryReadWorkError

        work = _ValidationWork(QueryReadValidationLimits())
        work.charge(hashes=7, input_bytes=11, json_nodes=13)  # Explicit previously charged component work.
        fixture, cursor, program, arguments = self.revocation_reader_fixture(work=work)
        observed = []
        actual = candidate._revocation_query_program

        def generate(**kwargs):
            observed.append(kwargs["work"].metrics)
            return actual(**kwargs)

        with patch.object(candidate, "_revocation_query_program", new=generate):
            selected, state = program._read_revocation_inputs(cursor, **arguments)
        self.assert_revocation_read(fixture, selected, state)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].hash_work, 7)  # Ownership and the clock do not hash.
        self.assertGreater(observed[0].input_bytes, 11)
        self.assertGreater(observed[0].json_nodes, 13)
        self.assertGreater(work.hash_work, observed[0].hash_work)
        for field in ("max_input_bytes", "max_json_nodes"):
            with self.subTest(field=field):
                limited = _ValidationWork(QueryReadValidationLimits(**{field: 1}))
                limited.charge(**{"input_bytes" if field == "max_input_bytes" else "json_nodes": 1})
                cursor = _RevocationReadCursor(fixture)
                with patch.object(candidate, "_revocation_query_program", wraps=actual) as generation:
                    with self.assertRaises(self.planner.AuthorityPlannerError) as raised:
                        program._read_revocation_inputs(cursor, **{**arguments, "query_work": limited})
                self.assertIsInstance(raised.exception.__cause__, QueryReadWorkError)
                self.assertEqual((cursor.calls, generation.call_count), ([], 0))

    def test_private_revocation_reader_wrong_roots_or_staged_proof_deny_before_reference_sql(self):
        from serverware import authority_query_staging as staging
        from serverware import authority_radix_mutation as primary
        from serverware import authority_radix_proof as radix

        for change_root in (True, False):
            with self.subTest(change_root=change_root):
                fixture, cursor, program, arguments = self.revocation_reader_fixture()
                if change_root:
                    root = next(item for item in arguments["authorization_before_roots"]
                                if item["table"] == "webauthn_trust_publication_high_water")
                    root["rootDigest"] = "sha256:" + "0" * 64
                else:
                    def corrupt(kind, rows, parameters):
                        if kind == "batch" and rows:
                            rows[0]["node_digest"] = "sha256:" + "0" * 64
                        return rows
                    cursor.primary.change = corrupt
                with patch.object(staging, "evaluate_primary_radix_memberships",
                                  wraps=staging.evaluate_primary_radix_memberships) as membership:
                    with self.assertRaises(self.planner.AuthorityPlannerError) as raised:
                        program._read_revocation_inputs(cursor, **arguments)
                self.assertIsInstance(raised.exception.__cause__, staging.QueryStagingError)
                self.assertEqual(membership.call_count, 1)
                self.assertIsInstance(raised.exception.__cause__.__cause__, primary.PrimaryRadixMutationError)
                self.assertIsInstance(raised.exception.__cause__.__cause__.__cause__, radix.RadixProofError)
                self.assertEqual(cursor.clock_reads, 1)
                self.assertFalse(any("FROM serverware_metadata.webauthn_trust_publications AS target WHERE" in sql
                                     for sql, _ in cursor.calls))

    def test_actual_public_revocation_read_still_denies_complete_queries_before_proof_or_business_sql(self):
        from serverware import authority_query_staging as staging

        fixture, cursor, program, arguments = self.revocation_reader_fixture()
        sources = staging.StagedQueryProofs(operation=program.operation,
            business_before_roots=arguments["business_before_roots"],
            authorization_before_roots=arguments["authorization_before_roots"],
            query_work=arguments["query_work"])
        with self.assertRaisesRegex(self.planner.AuthorityPlannerError,
                                    "complete index query acquisition is not available"):
            program.read_inputs(cursor, **{name: value for name, value in arguments.items()
                if name not in {"business_before_roots", "authorization_before_roots"}}, query_sources=sources)
        self.assertEqual(cursor.calls, [("SELECT pg_catalog.clock_timestamp() AS database_now", None)])
        self.assertEqual((cursor.primary.calls, cursor.complete.calls), ([], []))

    def revocation_producer_fixture(self, **options):
        from serverware import authority_index_mutation_reader as writer
        import test_authority_index_mutation_reader as write_oracle

        fixture, cursor, program, read_arguments = self.revocation_reader_fixture(**options)
        cursor.write_cursor = write_oracle.Cursor(write_oracle.StoredRows(types.SimpleNamespace(
            indexes=fixture.read_write.indexes, tables=fixture.rows,
            expiry_before=fixture.read_write.expiry_before)))
        inputs = fixture.inputs()
        arguments = {name: read_arguments[name] for name in (
            "request", "manifest", "business_before_roots", "authorization_before_roots", "query_work")}
        arguments.update({name: inputs[name] for name in (
            "evidence", "verifier_identity", "verifier_public_key", "capability_id",
            "now_epoch_ns", "deadline_epoch_ns", "maximum_age_ns")})
        actual = writer._acquire_indexed_primary_batch

        def acquire(*args, **kwargs):
            # Observe the genuine phase boundary to route identical metadata
            # table names into independently rebuilt write-population stores.
            # This wrapper always calls the actual writer, never a success stub.
            cursor.write_mode = True
            return actual(*args, **kwargs)

        return fixture, cursor, program, arguments, patch.object(
            writer, "_acquire_indexed_primary_batch", side_effect=acquire)

    def revocation_plan_fixture(self, *, work=None, separate_signer=False, include_audit=True):
        import test_authority_revocation_plan as plan_oracle

        expectation = plan_oracle.PlanFixture(separate_signer=separate_signer, include_audit=include_audit)
        fixture, cursor, program, acquisition_arguments, writer_scope = self.revocation_producer_fixture(
            work=work, separate_signer=separate_signer, include_audit=include_audit)
        # Both independent fixture populations are built before the observed
        # production call. Pins/time/roots are never copied from its output.
        self.assertEqual(fixture.request, expectation.semantic.request)
        self.assertEqual(fixture.expected_before, expectation.semantic.expected_before)
        self.assertEqual(fixture.receipt.evidence, expectation.semantic.receipt.evidence)
        context = {
            "expectedPlannerIdentity": copy.deepcopy(expectation.identity),
            "expectedVerifierIdentity": copy.deepcopy(fixture.receipt.identity),
            "expectedCapabilityId": fixture.receipt.capability_id,
            "expectedPlannerTransactionId": expectation.planner_transaction_id,
            "expectedFence": expectation.fence,
            "reservedAtEpochNs": expectation.reserved_at_epoch_ns,
            "deadlineEpochNs": expectation.deadline_epoch_ns,
            "deadlineMonotonicNs": expectation.deadline_monotonic_ns,
            "nowEpochNs": expectation.now_epoch_ns,
            "nowMonotonicNs": expectation.now_monotonic_ns,
            "maximumAssertionAgeNs": expectation.maximum_assertion_age_ns,
            "maximumPlanAgeNs": expectation.maximum_plan_age_ns,
            "maximumClockSkewNs": expectation.maximum_clock_skew_ns,
            "expectedBefore": copy.deepcopy(fixture.expected_before),
            "expectedApproverPolicyDigest": expectation.approver_policy_digest,
        }
        arguments = {name: acquisition_arguments[name] for name in (
            "request", "manifest", "evidence", "verifier_public_key", "query_work")}
        arguments.update(context=context, planner_private_key=expectation.key,
                         planner_public_key=expectation.key.public_key())
        return expectation, fixture, cursor, program, arguments, writer_scope

    def original_revocation_context(self, expectation, fixture):
        from serverware import authority_contract

        # Literal transport recipe, built from independent fixture pins and
        # the original database instant, never from a producer observation.
        return {
            "schema": "serverware.policyAuthorityRevocationEvaluationContext/v1",
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "databaseCutoffUs": fixture.cutoff_us,
            "expectedPlannerIdentity": copy.deepcopy(expectation.identity),
            "expectedVerifierIdentity": copy.deepcopy(fixture.receipt.identity),
            "expectedCapabilityId": fixture.receipt.capability_id,
            "expectedPlannerTransactionId": expectation.planner_transaction_id,
            "expectedFence": expectation.fence,
            "reservedAtEpochNs": expectation.reserved_at_epoch_ns,
            "deadlineEpochNs": expectation.deadline_epoch_ns,
            "deadlineMonotonicNs": expectation.deadline_monotonic_ns,
            "nowEpochNs": expectation.now_epoch_ns,
            "nowMonotonicNs": expectation.now_monotonic_ns,
            "maximumAssertionAgeNs": expectation.maximum_assertion_age_ns,
            "maximumPlanAgeNs": expectation.maximum_plan_age_ns,
            "maximumClockSkewNs": expectation.maximum_clock_skew_ns,
            "expectedBefore": copy.deepcopy(fixture.expected_before),
            "expectedApproverPolicyDigest": expectation.approver_policy_digest,
        }

    def revocation_owner_fixture(self, *, work=None):
        from serverware import authority_revocation_coordinator as coordinator
        from serverware import authority_revocation_persistence as persistence
        from serverware import db
        import test_authority_revocation_persistence as store_oracle

        expected, fixture, cursor, _, supplied, writer_scope = self.revocation_plan_fixture(
            work=work, include_audit=False)
        # This owner uses the real database's thirty-second write policy, not
        # the component fixtures' synthetic three-hundred-second allowance.
        # Re-sign both independently built receipts before any observed work;
        # the primary populations, roots and business effects are unchanged.
        for source_fixture in (expected.semantic, fixture):
            receipt = source_fixture.receipt
            receipt.evidence = receipt.sign({**receipt.evidence,
                "expiresAtEpochNs": receipt.now + 10_000_000_000})
            source_fixture._context()
            self.assertLessEqual(receipt.evidence["expiresAtEpochNs"]
                - receipt.evidence["verifiedAtEpochNs"], db._POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS)
        self.assertEqual(expected.semantic.receipt.evidence, fixture.receipt.evidence)
        expected.deadline_epoch_ns = expected.now_epoch_ns + 20_000_000_000
        expected.deadline_monotonic_ns = expected.now_monotonic_ns + 20_000_000_000
        expected.rebuild_payload()
        self.assertLessEqual(expected.deadline_epoch_ns - expected.reserved_at_epoch_ns,
                             db._POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS)
        supplied["evidence"] = copy.deepcopy(fixture.receipt.evidence)
        supplied["context"]["deadlineEpochNs"] = expected.deadline_epoch_ns
        supplied["context"]["deadlineMonotonicNs"] = expected.deadline_monotonic_ns
        identity = self.planner.PlannerIdentity(
            database_role="synthetic-read-planner", tls_client_dn="CN=synthetic-planner",
            tls_client_serial="17", tls_issuer_dn="CN=synthetic-issuer",
            session_identity_digest=expected.identity["sessionIdentityDigest"],
            measurement_digest=expected.identity["measurementDigest"],
            attestation_receipt_digest=expected.identity["attestationReceiptDigest"])
        writer_identity = ("serverware_policy_authority_planner_writer",
            "CN=synthetic-writer", "23", "CN=synthetic-writer-issuer")
        self.assertEqual(writer_identity[0], db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE)
        persisted = persistence.RevocationPlannerPersistence(
            persistence_dsn="postgresql://synthetic-writer.invalid/metadata", connect_timeout_seconds=5,
            planner_public_key=supplied["planner_public_key"],
            verifier_public_key=supplied["verifier_public_key"],
            expected_planner_identity=expected.identity,
            expected_verifier_identity=fixture.receipt.identity,
            writer_database_identity=writer_identity)
        owner = coordinator.RevocationPlanningCoordinator(
            read_dsn="postgresql://synthetic-reader.invalid/metadata", database_identity=identity,
            connect_timeout_seconds=7, planner_private_key=expected.key, persistence=persisted)
        arguments = {"request": supplied["request"], "evidence": supplied["evidence"],
            "context": {name: value for name, value in supplied["context"].items()
                if name not in {"expectedPlannerIdentity", "expectedVerifierIdentity"}},
            "planned_at_epoch_ns": expected.now_epoch_ns, "work": supplied["query_work"]}
        events = []
        read_cursor = _RevocationOwnerReadCursor(cursor, identity)
        read = _RevocationOwnerConnection("read", read_cursor, events)
        recorder = store_oracle.Recorder()
        recorder.role = db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE
        write_cursor = _RevocationOwnerWriteCursor(recorder, writer_identity)
        write = _RevocationOwnerConnection("write", write_cursor, events, recorder=recorder)
        connected = []

        def connect(dsn, **options):
            if dsn == "postgresql://synthetic-reader.invalid/metadata":
                connection, timeout = read, 7
            elif dsn == "postgresql://synthetic-writer.invalid/metadata":
                connection, timeout = write, 5
                self.assertIn("read.connection.exit", events)
                self.assertEqual(read.info.transaction_status, 0)
                self.assertIs(read.closed, True)
            else:
                raise AssertionError("connection escaped the original independently configured DSNs")
            self.assertEqual(set(options), {"row_factory", "connect_timeout", "options", "autocommit"}
                             if connection is write else {"row_factory", "connect_timeout", "options"})
            if connection is write:
                self.assertIs(options["autocommit"], False)
            self.assertEqual((options["connect_timeout"], options["options"]),
                             (timeout, "-c search_path=pg_catalog"))
            connected.append(dsn)
            events.append("connect." + connection.name)
            return connection

        return types.SimpleNamespace(expected=expected, fixture=fixture, cursor=cursor,
            owner=owner, persistence=persisted, arguments=arguments, read=read, write=write,
            read_cursor=read_cursor, write_cursor=write_cursor, recorder=recorder,
            events=events, connected=connected, connect=connect, writer_scope=writer_scope,
            writer_identity=writer_identity)

    def revocation_owner_scope(self, fixture):
        import psycopg
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from serverware.authority_store import planner_connection as admission
        import test_authority_revocation_plan as oracle

        scope = ExitStack()
        scope.enter_context(fixture.writer_scope)
        scope.enter_context(patch.object(psycopg, "connect", side_effect=fixture.connect))
        key = fixture.fixture.receipt.key.public_key()
        scope.enter_context(patch.dict(os.environ, {
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_ED25519_PUBLIC_KEY_BASE64URL":
                oracle.encoded(key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SPKI_SHA256":
                oracle.sha(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
        }))
        scope.enter_context(patch.object(admission.time, "time_ns", return_value=fixture.expected.now_epoch_ns))
        scope.enter_context(patch.object(admission.time, "monotonic_ns", return_value=fixture.expected.now_monotonic_ns))
        return scope

    def revocation_writer_admission_fixture(self):
        """Synthetic metadata/driver denial controls, not an admitted store.

        The real private connection owner and fixed catalog query are used.
        Its actual store operation must remain unreachable in these negative
        cases; genuine producer/replay positives remain in the owner fixture.
        """
        from serverware import authority_query_read_work as accounting
        import test_authority_revocation_persistence as store_oracle

        identity = ("serverware_policy_authority_planner_writer",
            "CN=synthetic-writer", "23", "CN=synthetic-writer-issuer")
        recorder, events = store_oracle.Recorder(), []
        recorder.role = identity[0]
        cursor = _RevocationOwnerWriteCursor(recorder, identity)
        connection = _RevocationOwnerConnection("write", cursor, events, recorder=recorder)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        work.charge(hashes=3, input_bytes=5, json_nodes=7)
        return types.SimpleNamespace(identity=identity, recorder=recorder, cursor=cursor,
            connection=connection, work=work, events=events)

    def revocation_atomic_fixture(self, *, work=None, recorder=None):
        """Original independent proof bytes plus the real configured writer.

        Reuse the policy-correct independent fixture, not a producer's output
        or observed meter. Only driver/catalog observations and five-set SQL
        storage are modeled. The actual db import/registry gate, facade,
        writer admission and both cryptographic store workers stay real.
        """
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_retention as record_oracle
        import test_authority_revocation_wire as wire_oracle

        fixture = self.revocation_owner_fixture(work=work)
        fixture.recorder = reservation_oracle.Recorder() if recorder is None else recorder
        fixture.recorder.role = fixture.writer_identity[0]
        fixture.write_cursor = _RevocationOwnerWriteCursor(fixture.recorder, fixture.writer_identity)
        fixture.write = _RevocationOwnerConnection("write", fixture.write_cursor,
            fixture.events, recorder=fixture.recorder)
        pins = wire_oracle.expectations(fixture.expected)
        for name in ("planner_public_key", "verifier_public_key",
                     "expected_planner_identity", "expected_verifier_identity"):
            pins.pop(name)
        fixture.arguments = {"envelope_bytes": oracle.wire(fixture.expected.envelope),
            "evaluation_context_bytes": oracle.wire(record_oracle.record_context(fixture.expected)),
            "planned_at_epoch_ns": fixture.expected.now_epoch_ns,
            "envelope_id": oracle.sha(b"configured atomic revocation execution"),
            "planner_transaction_id": fixture.expected.planner_transaction_id,
            "work": fixture.arguments["work"], **pins}

        def connect(dsn, **options):
            self.assertEqual(dsn, fixture.persistence.persistence_dsn)
            self.assertEqual(set(options), {"row_factory", "connect_timeout", "options", "autocommit"})
            self.assertEqual((options["connect_timeout"], options["options"]),
                             (5, "-c search_path=pg_catalog"))
            self.assertIs(options["autocommit"], False)
            fixture.connected.append(dsn)
            fixture.events.append("connect.write")
            return fixture.write

        fixture.connect = connect
        return fixture

    def revocation_atomic_work(self, fixture, *, retry=False):
        """Literal sequential composition, including both shifted proof peaks."""
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_persistence as persistence_oracle
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_wire as wire_oracle

        expected = fixture.expected
        external = {name: value for name, value in wire_oracle.expectations(expected).items()
            if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        joined = oracle.canonical_comparison(expected.planner_transaction_id, expected.planner_transaction_id)
        self.assertEqual(joined, (0, 438, 4))
        prefix = oracle.add(joined, oracle.graph_cost(external, 1, 1))
        persisted = persistence_oracle.independent_store_metrics(expected, expected.now_epoch_ns,
            mode="retry" if retry else "new")
        reserved = reservation_oracle.independent_reservation_work(expected, fixture.arguments["envelope_id"])
        total = oracle.add(prefix, persisted["total"], reserved["total"])
        peaks = (total, oracle.add(prefix, persisted["admission"]),
                 oracle.add(prefix, persisted["total"], reserved["admission"]))
        return {"total": total, "admission": tuple(max(values) for values in zip(*peaks)),
            "prefix": prefix, "persisted": persisted, "reserved": reserved}

    def assert_revocation_atomic_rows(self, fixture, *, request_rows=None, acknowledgment_rows=None):
        import test_authority_revocation_persistence as persistence_oracle
        import test_authority_revocation_reservation as reservation_oracle

        parent, sidecar = persistence_oracle.expected_rows(fixture.expected, fixture.expected.now_epoch_ns)
        assertion, projection = persistence_oracle.expected_authorization_rows(fixture.expected)
        row = reservation_oracle.expected_envelope(fixture.expected, fixture.arguments["envelope_id"])
        expected = (parent, sidecar,
            {assertion["assertion_evidence_digest"]: assertion},
            {projection["authorization_projection_digest"]: projection},
            {fixture.arguments["envelope_id"]: row})
        if request_rows is not None:
            expected = (*expected, request_rows)
        if acknowledgment_rows is not None:
            expected = (*expected, acknowledgment_rows)
        self.assertEqual(fixture.recorder.snapshot(), expected)
        return row

    def revocation_action_fixture(self, *, work=None, recorder=None):
        """Real inert action/factory plus gated store, not measured service admission."""
        from serverware import authority_query_read_work as accounting
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_writer_action as action_oracle

        source = action_oracle.WriterActionFixture()
        writer_identity = source.configuration.expected_database_identity()
        stored = reservation_oracle.Recorder() if recorder is None else recorder
        stored.role = writer_identity[0]
        events, connected = [], []
        cursor = _RevocationOwnerWriteCursor(stored, writer_identity)
        connection = _RevocationOwnerConnection("write", cursor, events, recorder=stored)
        dsn, timeout = source.configuration.persistence_dsn, 2
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits()) if work is None else work

        def connect(actual_dsn, **options):
            self.assertEqual(actual_dsn, dsn)
            self.assertEqual(set(options), {"row_factory", "connect_timeout", "options", "autocommit"})
            self.assertEqual((options["connect_timeout"], options["options"]),
                             (timeout, "-c search_path=pg_catalog"))
            self.assertIs(options["autocommit"], False)
            connected.append(actual_dsn)
            events.append("connect.write")
            return connection

        return types.SimpleNamespace(source=source, expected=source.plan, fixture=source.plan.semantic,
            arguments={**source.supplied(), "work": work}, writer_scope=nullcontext(),
            recorder=stored, writer_identity=writer_identity, write_cursor=cursor, write=connection,
            events=events, connected=connected, connect=connect)

    def run_revocation_action_components(self, fixture, *, after_capture=None):
        import test_authority_revocation_writer_action as action_oracle

        work = fixture.arguments["work"]
        args, expectations, owner = action_oracle.compose_components(fixture.source, work,
            after_capture=after_capture)
        fixture.persistence = owner
        return owner.persist_and_reserve_execution(**args, work=work, **expectations)

    def revocation_action_work(self, fixture, *, retry=False):
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_action as action_oracle

        prefix = action_oracle.independent_prefix_work(fixture.source)["total"]
        atomic = self.revocation_atomic_work(fixture, retry=retry)
        return {"prefix": prefix, "atomic": atomic,
            "total": oracle.add(prefix, atomic["total"]),
            "admission": oracle.add(prefix, atomic["admission"])}

    def revocation_composition_fixture(self, *, work=None, recorder=None):
        """Actual gated writer driver with genuine detached originals.

        This extends the existing db/registry lane, not a forged measured
        service process. Driver/catalog/clock observations remain synthetic;
        the real composition, admission query and both proof workers run.
        """
        import test_authority_revocation_writer_composition as composition_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        fixture = self.revocation_action_fixture(work=work,
            recorder=ack_oracle.Recorder() if recorder is None else recorder)
        fixture.detached = composition_oracle.CompositionFixture()
        fixture.source = fixture.detached.action
        fixture.expected, fixture.fixture = fixture.source.plan, fixture.source.plan.semantic
        fixture.arguments = {**fixture.source.supplied(), "work": fixture.arguments["work"]}
        return fixture

    def run_revocation_composition_components(self, fixture, *, after_preparation=None):
        from serverware import authority_revocation_writer_composition as composition
        import test_authority_revocation_writer_composition as composition_oracle

        work = fixture.arguments["work"]
        owner, fixed, arguments = composition_oracle.prepare_components(fixture.detached, work)
        fixture.persistence = owner
        if after_preparation is not None:
            # Test-only observation between genuine components, never a
            # callback authority accepted by the production worker.
            composition.configuration_capture.production._callback(work, lambda: after_preparation(owner, arguments))
        return composition._persist_commitments_on_configuration(fixed, work=work, **arguments)

    def revocation_composition_work(self, fixture, *, retry=False, request_existing=None, ack_existing=None):
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_composition as composition_oracle
        import test_authority_revocation_writer_request as request_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        observed = composition_oracle.independent_prefix_work(fixture.detached)
        # The actual public atomic factor already contains its ID comparison;
        # do not add the sentinel fixture's counted preflight a second time.
        prefix = oracle.add(observed["preparation"], observed["before_atomic"])
        atomic = self.revocation_atomic_work(fixture, retry=retry)
        custody = request_oracle.independent_request_work(fixture.detached,
            existing=retry if request_existing is None else request_existing)
        acknowledgment = ack_oracle.independent_ack_storage_work(fixture.detached,
            existing=retry if ack_existing is None else ack_existing)
        before_proof = oracle.add(prefix, atomic["prefix"], custody["prefix"])
        total = oracle.add(prefix, atomic["total"], custody["total"], acknowledgment["total"])
        peaks = (total, oracle.add(before_proof, atomic["persisted"]["admission"]),
                 oracle.add(before_proof, atomic["persisted"]["total"], atomic["reserved"]["admission"]))
        return {"prefix": prefix, "atomic": atomic, "custody": custody, "acknowledgment": acknowledgment, "total": total,
            "admission": tuple(max(values) for values in zip(*peaks))}

    def assert_revocation_composition_rows(self, fixture):
        import test_authority_revocation_writer_request as request_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        expected = request_oracle.expected_row(fixture.detached)
        acknowledgment = ack_oracle.expected_row(fixture.detached)
        return self.assert_revocation_atomic_rows(fixture,
            request_rows={expected["intent_envelope_id"]: expected},
            acknowledgment_rows={expected["intent_envelope_id"]: acknowledgment})

    def assert_revocation_writer_empty(self, recorder):
        self.assertEqual((recorder.parent, recorder.sidecar), (None, None))
        self.assertEqual((recorder.assertions, recorder.projections), ({}, {}))

    def assert_produced_revocation_plan(self, expectation, fixture, produced):
        import test_authority_revocation_plan as plan_oracle

        signed = produced.signed
        self.assertEqual(produced.database_now, fixture.database_now)
        context = self.original_revocation_context(expectation, fixture)
        self.assertEqual(len(context), 18)
        self.assertIs(type(produced.evaluation_context_bytes), bytes)
        self.assertEqual(produced.evaluation_context_bytes, plan_oracle.wire(context))
        # The actual acquired read/proof transcript is longer than the compact
        # synthetic transcript in PlanFixture; every other expected payload
        # field comes from independently constructed request/effect/tree data.
        for field, expected in expectation.payload.items():
            if field not in {"plannerTrace", "plannerTraceDigest"}:
                self.assertEqual(signed.payload[field], expected, field)
        trace = signed.payload["plannerTrace"]
        self.assertEqual((trace["schema"], trace["operation"]), (
            "serverware.policyAuthorityPlannerTrace/v1", "webauthn.credential.revoke"))
        writer_entries = [entry for entry in trace["entries"] if type(entry["key"]) is dict
            and entry["key"].get("profile") == "serverware.policyAuthorityCountedIndexMutationRead/v1"]
        identity = lambda entry: {name: entry[name] for name in ("access", "table", "key")}
        self.assertEqual([identity(entry) for entry in writer_entries],
            [identity(entry) for entry in plan_oracle.independent_write_trace(fixture)])
        self.assertEqual(signed.payload["plannerTraceDigest"], plan_oracle.framed(
            "serverware.policyAuthorityPlannerTrace/v1", plan_oracle.wire(trace)))
        self.assertEqual(signed.payload_bytes, plan_oracle.wire(signed.payload))
        self.assertEqual(signed.envelope, {"schema": "serverware.signedPolicyAuthorityMeasuredPlan/v4",
            "payload": signed.payload, "signatureBase64Url": plan_oracle.encoded(expectation.key.sign(
                plan_oracle.framed("serverware.signedPolicyAuthorityMeasuredPlan/v4",
                    signed.payload_bytes).encode("ascii")))})
        self.assertEqual(signed.envelope_bytes, plan_oracle.wire(signed.envelope))
        self.assertEqual((signed.signing_attempts, signed.signature_verifications), (1, 1))

    def test_configured_revocation_owner_closes_real_read_before_actual_retained_replay(self):
        from serverware import authority_revocation_retention as retention
        from serverware.authority_store import revocation_retention as store
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_persistence as store_oracle
        import test_authority_revocation_retention as record_oracle

        fixture = self.revocation_owner_fixture()
        work, observed, writer_states = fixture.arguments["work"], [], []
        original = self.planner.TypedTransitionPlanningProgram._produce_revocation_plan
        fixture.write.on_event = lambda event: writer_states.append((event, fixture.write.info.transaction_status))

        def produce(program, *args, **kwargs):
            self.assertIs(kwargs["query_work"], work)
            result = original(program, *args, **kwargs)
            observed.append(result)
            fixture.events.append("produced")
            return result

        with self.revocation_owner_scope(fixture), \
                patch.object(self.planner.TypedTransitionPlanningProgram, "_produce_revocation_plan",
                             autospec=True, side_effect=produce) as producer, \
                patch.object(store, "persist_revocation_planner_record",
                             wraps=store.persist_revocation_planner_record) as persist, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            result = fixture.owner.produce_and_persist(**fixture.arguments)
        self.assertEqual((producer.call_count, persist.call_count, replay.call_count), (1, 1, 1))
        produced, = observed
        self.assert_produced_revocation_plan(fixture.expected, fixture.fixture, produced)
        self.assertIs(persist.call_args.kwargs["work"], work)
        self.assertIs(replay.call_args.kwargs["work"], work)
        self.assertIs(persist.call_args.kwargs["envelope_bytes"], produced.signed.envelope_bytes)
        self.assertIs(persist.call_args.kwargs["evaluation_context_bytes"], produced.evaluation_context_bytes)
        self.assertEqual(replay.call_args.kwargs["expected_request"], fixture.fixture.request)
        self.assertEqual(replay.call_args.kwargs["expected_before"], fixture.fixture.expected_before)
        self.assertEqual(replay.call_args.kwargs["database_now"], fixture.fixture.database_now)
        for before, after in zip(("produced", "read.cursor.exit", "read.transaction1.exit",
                                 "read.connection.exit", "connect.write"),
                                ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit",
                                 "connect.write", "write.connection.enter")):
            self.assertLess(fixture.events.index(before), fixture.events.index(after))
        self.assertEqual((fixture.read.info.transaction_status, fixture.write.info.transaction_status), (0, 0))
        self.assertIs(fixture.read.closed, True)
        self.assertIs(fixture.write.closed, True)
        self.assertEqual(fixture.write_cursor.calls[:3], [
            ("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE", ()),
            (fixture.write_cursor.identity_sql, ()),
            (fixture.write_cursor.privilege_sql, fixture.write_cursor.privilege_parameters)])
        self.assertEqual(fixture.write_cursor.phase, 3)
        self.assertEqual([item for item in writer_states if ".cursor." not in item[0]], [
            ("write.connection.enter", 0), ("write.transaction1.enter", 2),
            ("write.transaction2.enter", 2), ("write.transaction2.exit", 2),
            ("write.transaction1.exit", 0), ("write.connection.exit", 0)])
        self.assertEqual((fixture.cursor.clock_reads, len(fixture.cursor.root_calls)),
                         (1, len(fixture.cursor.root_order)))
        prefix = produced.signed.payload["plannerTrace"]["entries"][:2]
        self.assertEqual([(item["access"], item["table"], item["key"]) for item in prefix], [
            ("read", "policy_authority_query_dependency_manifests", {"operation": "webauthn.credential.revoke"}),
            ("read", "policy_authority_authorization_dependency_manifests", {"operation": "webauthn.credential.revoke"})])
        self.assertEqual(result["exactEnvelopeBytes"], produced.signed.envelope_bytes)
        self.assertEqual(result["evaluationContextBytes"], produced.evaluation_context_bytes)
        self.assertEqual(result["plannedAtEpochNs"], fixture.expected.now_epoch_ns)
        header = record_oracle.record_header(fixture.expected,
            produced.signed.envelope_bytes, produced.evaluation_context_bytes)
        self.assertEqual(result["retainedRecordDigest"], oracle.framed(
            "serverware.policyAuthorityRevocationRetainedPlan/v1", oracle.wire(header)))
        parent, _ = store_oracle.expected_rows(fixture.expected, fixture.expected.now_epoch_ns)
        for name, expected in parent.items():
            if name not in {"exact_plan_base64url", "exact_plan_bytes_digest", "exact_plan_byte_count",
                            "retained_record_digest"}:
                self.assertEqual(fixture.recorder.parent[name], expected, name)
        self.assertEqual(fixture.recorder.parent["exact_plan_base64url"], oracle.encoded(produced.signed.payload_bytes))
        self.assertEqual(fixture.recorder.sidecar["exact_envelope_base64url"], oracle.encoded(produced.signed.envelope_bytes))
        assertion, projection = store_oracle.expected_authorization_rows(fixture.expected)
        self.assertEqual(fixture.recorder.assertions, {assertion["assertion_evidence_digest"]: assertion})
        self.assertEqual(fixture.recorder.projections, {projection["authorization_projection_digest"]: projection})
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (0, 2))
        self.assertGreater(work.hash_work, produced.metrics.hash_work)
        self.assertGreater(work.input_bytes, produced.metrics.input_bytes)
        self.assertGreater(work.json_nodes, produced.metrics.json_nodes)

    def observed_planner_owner_fixture(self):
        """Real gated planner workers over independent synthetic populations."""
        from serverware import authority_revocation_planning as planning
        import test_authority_revocation_handoff as handoff_oracle
        import test_authority_revocation_plan as plan_oracle
        import test_authority_revocation_roots as root_oracle

        fixture = self.revocation_owner_fixture()
        expected = fixture.expected
        expected.maximum_plan_age_ns = 30_000_000_000
        expected.maximum_clock_skew_ns = 5_000_000_000
        expected.rebuild_payload()
        primary, heads = handoff_oracle.full_root_rows(expected)
        inventory = root_oracle.acquire(root_oracle.inventory_fixture(
            primary_values=primary, head_values=heads))
        context = plan_oracle.production_context(expected)
        owner = planning.RevocationObservedPlanner(
            read_dsn="postgresql://synthetic-reader.invalid/metadata", connect_timeout_seconds=7,
            database_identity=fixture.owner._database_identity,
            planner_private_key=expected.key, planner_public_key=expected.key.public_key(),
            verifier_public_key=fixture.fixture.receipt.key.public_key(),
            expected_verifier_identity=fixture.fixture.receipt.identity,
            maximum_assertion_age_ns=expected.maximum_assertion_age_ns,
            maximum_plan_age_ns=30_000_000_000, maximum_clock_skew_ns=5_000_000_000)
        caller = {name: copy.deepcopy(value) for name, value in context.items() if name not in {
            "expectedPlannerIdentity", "expectedVerifierIdentity", "expectedBefore",
            "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs"}}
        arguments = {"request": fixture.arguments["request"], "evidence": fixture.arguments["evidence"],
            "context": caller, "root_inventory": inventory, "work": fixture.arguments["work"]}
        return fixture, owner, arguments, context

    def test_observed_planner_only_owner_returns_originals_then_genuine_independent_handoff(self):
        from serverware import authority_revocation_handoff as handoff
        import test_authority_revocation_plan as plan_oracle

        fixture, owner, arguments, independent = self.observed_planner_owner_fixture()
        original = self.planner.TypedTransitionPlanningProgram._produce_observed_revocation_plan
        productions = []

        def produce(program, *args, **kwargs):
            self.assertIs(kwargs["query_work"], arguments["work"])
            result = original(program, *args, **kwargs)
            productions.append(result)
            fixture.events.append("produced.observed")
            return result

        with self.revocation_owner_scope(fixture), patch.object(
                self.planner.TypedTransitionPlanningProgram, "_produce_observed_revocation_plan",
                autospec=True, side_effect=produce):
            result = owner.produce_observed(**arguments)
        produced, = productions
        self.assert_produced_revocation_plan(fixture.expected, fixture.fixture, produced)
        self.assertIs(result.envelope_bytes, produced.signed.envelope_bytes)
        self.assertIs(result.evaluation_context_bytes, produced.evaluation_context_bytes)
        self.assertEqual(result.expected_context, independent)
        self.assertIsNot(result.expected_context, produced.expected_context)
        self.assertEqual(result.database_now, fixture.fixture.database_now)
        self.assertEqual(fixture.connected, ["postgresql://synthetic-reader.invalid/metadata"])
        self.assertIs(fixture.read.closed, True)
        self.assertEqual(fixture.read.info.transaction_status, 0)
        self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar, fixture.write.transactions), (None, None, 0))
        self.assertLess(fixture.events.index("produced.observed"), fixture.events.index("read.cursor.exit"))
        self.assertLess(fixture.events.index("read.transaction1.exit"), fixture.events.index("read.connection.exit"))
        # Replay the actual originals against independently constructed pins,
        # never expectations recovered from the returned producer object.
        replayed = handoff._verify_observed_plan_handoff_on_work(
            envelope_bytes=result.envelope_bytes, evaluation_context_bytes=result.evaluation_context_bytes,
            expected_request=fixture.expected.semantic.request,
            context={name: value for name, value in independent.items() if name != "expectedBefore"},
            root_inventory=arguments["root_inventory"], planner_public_key=fixture.expected.key.public_key(),
            verifier_public_key=fixture.fixture.receipt.key.public_key(), work=arguments["work"])
        self.assertEqual(replayed.expected_context, independent)
        self.assertEqual(replayed.retained_record.envelope_bytes, result.envelope_bytes)
        self.assertEqual(replayed.retained_record.context_bytes, result.evaluation_context_bytes)
        self.assertEqual(result.evaluation_context_bytes,
            plan_oracle.wire(self.original_revocation_context(fixture.expected, fixture.fixture)))

    def test_observed_planner_only_owner_cannot_return_after_any_read_exit_failure(self):
        for failed in ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit"):
            fixture, owner, arguments, _ = self.observed_planner_owner_fixture()

            def fail(event):
                if event == failed:
                    raise RuntimeError("synthetic observed planner exit denied")

            fixture.read.on_event = fail
            with self.subTest(failed=failed), self.revocation_owner_scope(fixture):
                with self.assertRaisesRegex(RuntimeError, "synthetic observed planner exit denied"):
                    owner.produce_observed(**arguments)
            self.assertEqual(fixture.connected, ["postgresql://synthetic-reader.invalid/metadata"])
            self.assertIs(fixture.read.closed, True)
            self.assertEqual(fixture.read.info.transaction_status, 0)
            for cleanup in ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit"):
                self.assertEqual(fixture.events.count(cleanup), 1)
            self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar, fixture.write.transactions), (None, None, 0))

    def test_configured_revocation_owner_cleanup_failure_never_opens_writer(self):
        for failed in ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit"):
            fixture = self.revocation_owner_fixture()

            def fail(event):
                if event == failed:
                    raise RuntimeError("synthetic read cleanup denied")

            fixture.read.on_event = fail
            with self.subTest(failed=failed), self.revocation_owner_scope(fixture):
                with self.assertRaisesRegex(RuntimeError, "synthetic read cleanup denied"):
                    fixture.owner.produce_and_persist(**fixture.arguments)
            self.assertEqual(fixture.connected, ["postgresql://synthetic-reader.invalid/metadata"])
            self.assertNotIn("connect.write", fixture.events)
            for cleanup in ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit"):
                self.assertEqual(fixture.events.count(cleanup), 1)
            self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar), (None, None))
            self.assertEqual(fixture.read.info.transaction_status, 0)
            self.assertGreater(fixture.arguments["work"].hash_work, 0)

    def test_configured_revocation_owner_captures_inputs_and_all_writer_pins_before_callbacks(self):
        from serverware.authority_store import revocation_retention as store

        fixture = self.revocation_owner_fixture()
        original_request = copy.deepcopy(fixture.arguments["request"])
        original_roots = copy.deepcopy(fixture.arguments["context"]["expectedBefore"])
        planner_key, verifier_key = fixture.persistence.planner_public_key, fixture.persistence.verifier_public_key

        def mutate(event):
            if event == "read.connection.enter":
                fixture.arguments["request"]["arguments"].clear()
                fixture.arguments["evidence"].clear()
                fixture.arguments["context"]["expectedBefore"].clear()
                fixture.arguments["context"]["expectedFence"] += 1
                for name, value in (("persistence_dsn", "postgresql://changed.invalid/metadata"),
                        ("connect_timeout_seconds", 300), ("planner_public_key", fixture.expected.other_key.public_key()),
                        ("verifier_public_key", fixture.expected.other_key.public_key()),
                        ("_planner_identity", ("sha256:" + "0" * 64,) * 3),
                        ("_verifier_identity", ("sha256:" + "0" * 64,) * 3),
                        ("_database_identity", (fixture.writer_identity[0],
                            "CN=changed-writer", "29", "CN=changed-issuer"))):
                    object.__setattr__(fixture.persistence, name, value)
                for name, value in (("read_dsn", "postgresql://changed-reader.invalid/metadata"),
                        ("connect_timeout_seconds", 300),
                        ("_database_identity", ("changed",) * 4 + ("sha256:" + "0" * 64,) * 3),
                        ("planner_private_key", fixture.expected.other_key), ("persistence", object())):
                    object.__setattr__(fixture.owner, name, value)

        fixture.read.on_event = mutate
        with self.revocation_owner_scope(fixture), \
                patch.object(store, "persist_revocation_planner_record",
                             wraps=store.persist_revocation_planner_record) as persist:
            result = fixture.owner.produce_and_persist(**fixture.arguments)
        self.assertEqual(persist.call_count, 1)
        supplied = persist.call_args.kwargs
        self.assertEqual(supplied["expected_request"], original_request)
        self.assertEqual(supplied["expected_before"], original_roots)
        self.assertEqual(supplied["expected_planner_identity"], fixture.expected.identity)
        self.assertEqual(supplied["expected_verifier_identity"], fixture.fixture.receipt.identity)
        self.assertIs(supplied["planner_public_key"], planner_key)
        self.assertIs(supplied["verifier_public_key"], verifier_key)
        self.assertEqual(result["plannerTransactionId"], fixture.expected.planner_transaction_id)
        self.assertEqual(len(fixture.connected), 2)
        self.assertEqual((fixture.write_cursor.identity_row["role"], fixture.write_cursor.identity_row["client_dn"],
            fixture.write_cursor.identity_row["client_serial"], fixture.write_cursor.identity_row["issuer_dn"]),
            fixture.writer_identity)

    def test_configured_revocation_owner_rejects_metadata_and_closed_input_drift_before_production(self):
        for changed in ("identity", "mutation_authority", "business_manifest", "authorization_manifest",
                        "missing_context", "foreign_identity", "foreign_key", "work_none", "work_foreign",
                        "planned_before", "planned_deadline"):
            fixture = self.revocation_owner_fixture()
            if changed == "identity":
                fixture.read_cursor.identity_row["role"] = "foreign-planner"
            elif changed == "mutation_authority":
                fixture.read_cursor.mutation_row = {"?column?": 1}
            elif changed in {"business_manifest", "authorization_manifest"}:
                rows = (fixture.read_cursor.business_rows if changed == "business_manifest"
                        else fixture.read_cursor.authorization_rows)
                rows[0]["entry_digest"] = "sha256:" + "0" * 64
            elif changed == "missing_context":
                fixture.arguments["context"].pop("expectedBefore")
            elif changed == "foreign_identity":
                fixture.arguments["context"]["expectedPlannerIdentity"] = fixture.expected.identity
            elif changed == "foreign_key":
                class ForeignKey(str):
                    pass

                value = fixture.arguments["context"].pop("expectedFence")
                fixture.arguments["context"][ForeignKey("expectedFence")] = value
            elif changed in {"work_none", "work_foreign"}:
                fixture.arguments["work"] = None if changed == "work_none" else object()
            elif changed == "planned_before":
                fixture.arguments["planned_at_epoch_ns"] = fixture.expected.reserved_at_epoch_ns - 1
            else:
                fixture.arguments["planned_at_epoch_ns"] = fixture.expected.deadline_epoch_ns
            metadata = changed in {"identity", "mutation_authority", "business_manifest", "authorization_manifest"}
            expected_error = self.planner.AuthorityPlannerError if metadata else ValueError
            copy_guard = (patch.object(self.planner.authority_query_reads, "_CopyBudget",
                side_effect=AssertionError("invalid key/work reached ownership copy"))
                if changed in {"foreign_key", "work_none", "work_foreign"} else nullcontext())
            with self.subTest(changed=changed), self.revocation_owner_scope(fixture), \
                    copy_guard, \
                    patch.object(self.planner.TypedTransitionPlanningProgram, "_produce_revocation_plan",
                                 side_effect=AssertionError("failed admission reached producer")) as producer:
                with self.assertRaises(expected_error):
                    fixture.owner.produce_and_persist(**fixture.arguments)
            self.assertEqual(producer.call_count, 0)
            self.assertEqual(len(fixture.connected), int(metadata))
            self.assertEqual((fixture.cursor.root_calls, fixture.cursor.clock_reads), ([], 0))
            self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar), (None, None))
            if metadata:
                self.assertIn("read.connection.exit", fixture.events)

    def test_configured_revocation_owner_keeps_original_bytes_across_read_cleanup_callbacks(self):
        from datetime import timedelta
        from serverware.authority_store import revocation_retention as store

        fixture, observed = self.revocation_owner_fixture(), []
        original = self.planner.TypedTransitionPlanningProgram._produce_revocation_plan

        def produce(program, *args, **kwargs):
            result = original(program, *args, **kwargs)
            observed.append((result, result.signed.envelope_bytes, result.evaluation_context_bytes))
            return result

        def mutate(event):
            if event == "read.cursor.exit":
                produced, _, _ = observed[0]
                produced.signed.payload["typedRequest"]["arguments"].clear()
                produced.signed.envelope["signatureBase64Url"] = "A" * 86
                object.__setattr__(produced.signed, "envelope_bytes", b"{}")
                object.__setattr__(produced, "evaluation_context_bytes", b"{}")
                object.__setattr__(produced, "database_now", fixture.fixture.database_now + timedelta(microseconds=1))

        fixture.read.on_event = mutate
        with self.revocation_owner_scope(fixture), \
                patch.object(self.planner.TypedTransitionPlanningProgram, "_produce_revocation_plan",
                             autospec=True, side_effect=produce), \
                patch.object(store, "persist_revocation_planner_record",
                             wraps=store.persist_revocation_planner_record) as persist:
            result = fixture.owner.produce_and_persist(**fixture.arguments)
        _, original_envelope, original_context = observed[0]
        self.assertIs(persist.call_args.kwargs["envelope_bytes"], original_envelope)
        self.assertIs(persist.call_args.kwargs["evaluation_context_bytes"], original_context)
        self.assertEqual(persist.call_args.kwargs["database_now"], fixture.fixture.database_now)
        self.assertEqual((result["exactEnvelopeBytes"], result["evaluationContextBytes"]),
                         (original_envelope, original_context))

    def test_configured_revocation_owner_returns_original_cutoff_only_after_persistence(self):
        from datetime import timedelta
        from serverware.authority_store import revocation_retention as store

        fixture, observed = self.revocation_owner_fixture(), []
        original = self.planner.TypedTransitionPlanningProgram._produce_revocation_plan
        actual_cutoff = fixture.fixture.database_now

        def produce(program, *args, **kwargs):
            result = original(program, *args, **kwargs)
            observed.append(result)
            self.assertIs(result.database_now, actual_cutoff)
            return result

        def mutate(event):
            if event in {"read.cursor.exit", "write.connection.exit"}:
                object.__setattr__(observed[0], "database_now", actual_cutoff + timedelta(microseconds=1))

        fixture.read.on_event = mutate
        fixture.write.on_event = mutate
        with self.revocation_owner_scope(fixture), \
                patch.object(self.planner.TypedTransitionPlanningProgram, "_produce_revocation_plan",
                             autospec=True, side_effect=produce), \
                patch.object(store, "persist_revocation_planner_record",
                             wraps=store.persist_revocation_planner_record) as persist:
            retained, database_now = fixture.owner.produce_and_persist_with_cutoff(**fixture.arguments)
            self.assertIn("write.connection.exit", fixture.events)
        self.assertEqual(len(observed), 1)
        self.assertIs(database_now, actual_cutoff)
        self.assertIs(persist.call_args.kwargs["database_now"], actual_cutoff)
        self.assertIsNot(observed[0].database_now, actual_cutoff)
        self.assertEqual(fixture.cursor.clock_reads, 1)
        self.assertEqual(retained["exactEnvelopeBytes"], observed[0].signed.envelope_bytes)
        self.assertEqual(retained["evaluationContextBytes"], observed[0].evaluation_context_bytes)
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (0, 2))

    def test_configured_revocation_owner_spends_one_cumulative_allowance_and_keeps_prior_work(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan as replay
        from serverware.authority_store import revocation_retention as store
        import test_authority_revocation_plan as oracle

        results = []
        for prior in ((0, 0, 0), (7, 101, 13)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            fixture = self.revocation_owner_fixture(work=work)
            entering, checkpoints = work.limits, []
            actual = store.persist_revocation_planner_record

            def persist(**arguments):
                self.assertIs(arguments["work"], work)
                checkpoints.append(oracle.units(work.metrics))
                return actual(**arguments)

            with self.subTest(prior=prior), self.revocation_owner_scope(fixture), \
                    patch.object(store, "persist_revocation_planner_record", side_effect=persist), \
                    patch.object(replay, "verify_signed_revocation_plan",
                                 side_effect=AssertionError("fresh public replay allowance")):
                result = fixture.owner.produce_and_persist(**fixture.arguments)
            self.assertEqual(len(checkpoints), 1)
            self.assertTrue(all(start < before < final for start, before, final
                in zip(prior, checkpoints[0], oracle.units(work.metrics))))
            self.assertIs(work.limits, entering)
            results.append((result, oracle.units(work.metrics)))
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(tuple(right - left for left, right in zip(results[0][1], results[1][1])), (7, 101, 13))
        # This pins initial remaining-work denial, not an independently derived
        # whole-producer exact peak; separate component oracles cover the holds.
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        work.charge(input_bytes=work.limits.max_input_bytes)
        fixture = self.revocation_owner_fixture(work=work)
        with self.revocation_owner_scope(fixture), self.assertRaises(ValueError):
            fixture.owner.produce_and_persist(**fixture.arguments)
        self.assertEqual(fixture.connected, [])
        self.assertEqual(work.input_bytes, work.limits.max_input_bytes)

    def test_configured_revocation_owner_closes_connection_returned_before_meter_guard_failure(self):
        from serverware import db

        for stage in ("read", "write"):
            fixture = self.revocation_owner_fixture()
            original, work, after_callback = fixture.connect, fixture.arguments["work"], []

            def changed_connect(*args, **kwargs):
                connection = original(*args, **kwargs)
                if connection.name == stage:
                    work.charge(json_nodes=1)
                    after_callback.append(work.metrics)
                return connection

            fixture.connect = changed_connect
            with self.subTest(stage=stage), self.revocation_owner_scope(fixture), self.assertRaises(db.MetadataStoreError):
                fixture.owner.produce_and_persist(**fixture.arguments)
            if stage == "read":
                self.assertEqual(fixture.events, ["connect.read", "read.close"])
                self.assertEqual((fixture.read_cursor.calls, fixture.cursor.calls), ([], []))
            else:
                self.assertEqual(fixture.events[-2:], ["connect.write", "write.close"])
                self.assertIn("read.connection.exit", fixture.events)
                self.assertEqual((fixture.write.transactions, fixture.write_cursor.calls), (0, []))
                self.assertIs(fixture.write.closed, True)
            self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar), (None, None))
            self.assertEqual(work.metrics, after_callback[0])

    def test_configured_revocation_owner_writer_failure_rolls_back_both_actual_transaction_scopes(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from serverware import db
        from serverware.authority_store import planner_connection as admission
        import test_authority_revocation_plan as oracle

        for failure in ("cas", "expired", "wrong_key", "wrong_spki"):
            fixture, produced, receipts = self.revocation_owner_fixture(), [], []
            original = self.planner.TypedTransitionPlanningProgram._produce_revocation_plan

            def produce(program, *args, **kwargs):
                result = original(program, *args, **kwargs)
                produced.append(result)
                fixture.events.append("produced")
                return result

            fixture.recorder.fail_completion = failure == "cas"
            deadline = (patch.object(admission.time, "time_ns",
                return_value=fixture.expected.deadline_epoch_ns + 1) if failure == "expired" else nullcontext())
            current_configuration = {}
            if failure == "wrong_key":
                key = fixture.expected.other_key.public_key()
                current_configuration = {
                    "SERVERWARE_POLICY_AUTHORITY_VERIFIER_ED25519_PUBLIC_KEY_BASE64URL":
                        oracle.encoded(key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
                    "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SPKI_SHA256":
                        oracle.sha(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
                }
            elif failure == "wrong_spki":
                current_configuration = {"SERVERWARE_POLICY_AUTHORITY_VERIFIER_SPKI_SHA256":
                    oracle.sha(b"different current verifier SPKI")}
            error, message = {
                "cas": (db.MetadataStoreError, "completion CAS failed"),
                "expired": (ValueError, "stale or inconsistent"),
                "wrong_key": (ValueError, "measured verifier envelope signature is invalid"),
                "wrong_spki": (db.MetadataStoreError, "does not match its SPKI pin"),
            }[failure]
            # Historical pins and the actual signed bytes remain unchanged.
            # A different genuinely constructed current key has its matching
            # SPKI pin; the SPKI-only case retains the real original key.
            with self.subTest(failure=failure), self.revocation_owner_scope(fixture), deadline, \
                    patch.dict(os.environ, current_configuration), \
                    patch.object(db, "_policy_authority_verifier_public_key",
                                 wraps=db._policy_authority_verifier_public_key) as current_key, \
                    patch.object(self.planner.TypedTransitionPlanningProgram, "_produce_revocation_plan",
                                 autospec=True, side_effect=produce):
                with self.assertRaisesRegex(error, message):
                    receipts.append(fixture.owner.produce_and_persist(**fixture.arguments))
            self.assertEqual(current_key.call_count, int(failure != "expired"))
            self.assertEqual((len(produced), receipts), (1, []))
            self.assert_produced_revocation_plan(fixture.expected, fixture.fixture, produced[0])
            for closed in ("read.cursor.exit", "read.transaction1.exit", "read.connection.exit"):
                self.assertLess(fixture.events.index("produced"), fixture.events.index(closed))
                self.assertLess(fixture.events.index(closed), fixture.events.index("connect.write"))
            self.assertEqual(len(fixture.connected), 2)
            self.assertEqual((fixture.write.transactions, fixture.recorder.rollbacks,
                              fixture.recorder.releases), (2, 2, 0))
            updates = [sql for sql, _ in fixture.recorder.statements
                       if sql.startswith("UPDATE serverware_metadata.policy_authority_planner_transactions")]
            self.assertEqual(len(updates), int(failure == "cas"))
            for table in ("policy_authority_webauthn_assertion_evidence",
                          "policy_authority_authorization_projections"):
                self.assertEqual(any(sql.startswith("INSERT INTO serverware_metadata." + table)
                    for sql, _ in fixture.recorder.statements), failure == "cas")
            self.assertEqual((fixture.recorder.parent, fixture.recorder.sidecar), (None, None))
            self.assertEqual((fixture.recorder.assertions, fixture.recorder.projections), ({}, {}))
            self.assertEqual((fixture.read.info.transaction_status, fixture.write.info.transaction_status), (0, 0))
            self.assertEqual(fixture.events.count("write.connection.exit"), 1)
            self.assertGreater(fixture.arguments["work"].hash_work, produced[0].metrics.hash_work)

    def test_configured_revocation_writer_requires_closed_actual_metadata_before_store(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        baseline = self.revocation_writer_admission_fixture().cursor.identity_row
        self.assertEqual(len(baseline), 19)
        variants = [None, {}, tuple(baseline.items()), {**baseline, "extra": False},
                    {name: value for name, value in baseline.items() if name != "ssl"}]
        for value in (True, "160004", 159999, 170000):
            variants.append({**baseline, "server_version_num": value})
        for field in ("role", "session_role", "client_dn", "client_serial", "issuer_dn",
                      "transaction_isolation", "transaction_read_only", "transaction_deferrable"):
            variants.extend({**baseline, field: value} for value in (None, True, "different"))
        for field in ("ssl", "rolcanlogin"):
            variants.extend({**baseline, field: value} for value in (False, 1, None))
        for field in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
                      "rolbypassrls", "schema_create", "database_create", "database_temporary"):
            variants.extend({**baseline, field: value} for value in (True, 0, None))
        for number, row in enumerate(variants):
            fixture = self.revocation_writer_admission_fixture()
            fixture.cursor.identity_row = row
            entering = fixture.work.metrics
            with self.subTest(variant=number), patch.object(store, "read_revocation_planner_record",
                    wraps=store.read_revocation_planner_record) as operation:
                with self.assertRaises(writer.RevocationWriterConnectionError):
                    writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                        work=fixture.work, operation=operation, arguments={}, expectations={})
            self.assertEqual(operation.call_count, 0)
            self.assertEqual([sql for sql, _ in fixture.cursor.calls],
                             [writer._SET_TRANSACTION, fixture.cursor.identity_sql])
            self.assertEqual(fixture.recorder.statements, [])
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (1, 0))
            self.assertEqual(fixture.connection.info.transaction_status, 0)
            self.assertIs(fixture.connection.closed, True)
            self.assertEqual(fixture.work.metrics, entering)
            self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_denies_every_returned_catalog_violation(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        # These are returned observations, not SQL execution or actual ACL
        # evidence. Any row must deny; the native fixture owns real catalog DDL.
        labels = ("role-or-namespace", "schema-or-database-privilege", "role-membership",
            "required-table", "table-privilege", "column-privilege", "sequence-privilege",
            "required-function", "function-privilege", "function-metadata",
            "public-schema-privilege", "public-relation-privilege", "public-function-privilege")
        for row in ({}, False, *({"violation": label} for label in labels)):
            fixture = self.revocation_writer_admission_fixture()
            fixture.cursor.privilege_row = row
            entering = fixture.work.metrics
            with self.subTest(row=row), patch.object(store, "read_revocation_planner_record",
                    wraps=store.read_revocation_planner_record) as operation:
                with self.assertRaisesRegex(writer.RevocationWriterConnectionError, "effective privileges"):
                    writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                        work=fixture.work, operation=operation, arguments={}, expectations={})
            self.assertEqual(operation.call_count, 0)
            self.assertEqual(fixture.cursor.calls, [(writer._SET_TRANSACTION, ()),
                (fixture.cursor.identity_sql, ()),
                (fixture.cursor.privilege_sql, (fixture.identity[0], "serverware_metadata"))])
            self.assertEqual((fixture.recorder.statements, fixture.recorder.rollbacks,
                              fixture.recorder.releases), ([], 1, 0))
            self.assertEqual(fixture.work.metrics, entering)
            self.assertIs(fixture.connection.closed, True)
            self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_denies_inactive_or_replaced_driver_scopes(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        variants = (("closed", True), ("autocommit", True), ("pgconn", None),
            ("status", True), ("status", 0.0), ("status", 2), ("status", 3),
            ("enter_result", object()), ("transaction_enter_replacement", object()),
            ("cursor_enter_replacement", object()), ("execute_replacement", object()))
        for field, value in variants:
            fixture = self.revocation_writer_admission_fixture()
            if field == "status":
                fixture.connection.info.transaction_status = value
            else:
                setattr(fixture.connection, field, value)
            with self.subTest(field=field, value=value), patch.object(store, "read_revocation_planner_record",
                    wraps=store.read_revocation_planner_record) as operation:
                with self.assertRaises(writer.RevocationWriterConnectionError):
                    writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                        work=fixture.work, operation=operation, arguments={}, expectations={})
            self.assertEqual((operation.call_count, fixture.recorder.statements), (0, []))
            self.assertEqual(fixture.cursor.calls,
                [(writer._SET_TRANSACTION, ())] if field == "execute_replacement" else [])
            self.assertIs(fixture.connection.closed, True)
            entered_transaction = field in {"transaction_enter_replacement", "cursor_enter_replacement", "execute_replacement"}
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases),
                             (int(entered_transaction), 0))
            self.assertEqual(fixture.events.count("write.transaction1.exit"), int(entered_transaction))
            self.assert_revocation_writer_empty(fixture.recorder)

        # Observe the actual proxy allocation, then poison only its working
        # binding. Cleanup must use its separately held original entry scope.
        fixture, cursors = self.revocation_writer_admission_fixture(), []
        actual_cursor = writer._Connection.cursor

        def cursor(connection):
            result = actual_cursor(connection)
            cursors.append((result, result._binding, result._scope))
            return result

        def replace_binding(sql, _parameters):
            if sql == writer._SET_TRANSACTION:
                cursors[0][0]._binding = (None, None, None)

        fixture.cursor.on_execute = replace_binding
        with self.subTest(field="working_scope_binding"), \
                patch.object(writer._Connection, "cursor", autospec=True, side_effect=cursor), \
                patch.object(store, "read_revocation_planner_record",
                             wraps=store.read_revocation_planner_record) as operation:
            with self.assertRaisesRegex(writer.RevocationWriterConnectionError, "scope binding changed"):
                writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                    work=fixture.work, operation=operation, arguments={}, expectations={})
        self.assertEqual((len(cursors), operation.call_count), (1, 0))
        proxy, entry_binding, original_scope = cursors[0]
        self.assertIs(proxy._entry_binding, entry_binding)
        self.assertIs(proxy._scope, original_scope)
        self.assertIsNot(proxy._binding, entry_binding)
        self.assertEqual(fixture.cursor.calls, [(writer._SET_TRANSACTION, ())])
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (1, 0))
        for event in ("write.cursor.exit", "write.transaction1.exit", "write.connection.exit"):
            self.assertEqual(fixture.events.count(event), 1)
        self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_guards_driver_getters_without_refunding_work(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        for target in ("info", "pgconn", "closed", "autocommit", "transaction", "cursor",
                       "__enter__", "execute", "fetchone"):
            fixture, observed = self.revocation_writer_admission_fixture(), []
            work, limits = fixture.work, fixture.work.limits

            def lookup(name):
                if name == target and not observed:
                    fixture.connection.on_lookup = None
                    fixture.connection.cursor_lookup = None
                    work.charge(json_nodes=1)
                    observed.append(work.metrics)

            if target in {"execute", "fetchone"}:
                fixture.connection.cursor_lookup = lookup
            else:
                fixture.connection.on_lookup = lookup
            with self.subTest(target=target), patch.object(store, "read_revocation_planner_record",
                    wraps=store.read_revocation_planner_record) as operation:
                with self.assertRaises(writer.RevocationWriterConnectionError):
                    writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                        work=work, operation=operation, arguments={}, expectations={})
            self.assertEqual((len(observed), operation.call_count), (1, 0))
            self.assertEqual(work.metrics, observed[0])
            self.assertIs(work.limits, limits)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))
            self.assertEqual(fixture.recorder.releases, 0)
            self.assertIs(fixture.connection.closed, True)
            self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_late_state_and_rowcount_getters_roll_back_custody(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        for failure in ("raw", "status", "autocommit", "closed", "rowcount_work", "rowcount_bool"):
            fixture, observed = self.revocation_owner_fixture(), []
            work = fixture.arguments["work"]
            completion = "UPDATE serverware_metadata.policy_authority_planner_transactions"

            def after_sql(sql, _parameters):
                if sql.startswith(completion):
                    observed.append("completion")
                    if failure == "raw":
                        fixture.write.pgconn = object()
                    elif failure == "status":
                        fixture.write.info.transaction_status = 0
                    elif failure == "autocommit":
                        fixture.write.autocommit = True
                    elif failure == "closed":
                        fixture.write.closed = True

            def lookup(name):
                if name == "rowcount" and observed == ["completion"]:
                    if failure == "rowcount_work":
                        work.charge(json_nodes=1)
                        observed.append(work.metrics)
                    elif failure == "rowcount_bool":
                        fixture.recorder_cursor.rowcount = True
                        observed.append("bool")

            fixture.recorder_cursor = fixture.write_cursor.cursor
            fixture.recorder.callback = after_sql
            fixture.write.cursor_lookup = lookup
            with self.subTest(failure=failure), self.revocation_owner_scope(fixture), \
                    patch.object(store.retention, "_verify_record_on_work",
                                 wraps=store.retention._verify_record_on_work) as replay:
                with self.assertRaises(writer.RevocationWriterConnectionError):
                    fixture.owner.produce_and_persist(**fixture.arguments)
            self.assertEqual((replay.call_count, observed[0]), (1, "completion"))
            if failure == "rowcount_work":
                self.assertEqual(work.metrics, observed[1])
            if failure == "rowcount_bool":
                self.assertEqual(observed, ["completion", "bool"])
            self.assertEqual((fixture.write.transactions, fixture.recorder.rollbacks,
                              fixture.recorder.releases), (2, 2, 0))
            self.assertEqual(fixture.write.info.transaction_status, 0)
            self.assertEqual(fixture.events.count("write.connection.exit"), 1)
            self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_preserves_first_driver_error_during_cleanup(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store

        fixture = self.revocation_writer_admission_fixture()
        failure = RuntimeError("synthetic metadata driver failure")

        def execute(sql, _parameters):
            if sql == fixture.cursor.identity_sql:
                raise failure

        def cleanup(event):
            if event in {"write.cursor.exit", "write.transaction1.exit", "write.connection.exit"}:
                raise RuntimeError("secondary synthetic cleanup failure")

        fixture.cursor.on_execute = execute
        fixture.connection.on_event = cleanup
        with patch.object(store, "read_revocation_planner_record",
                wraps=store.read_revocation_planner_record) as operation:
            with self.assertRaises(RuntimeError) as raised:
                writer._run_on_connection(fixture.connection, database_identity=fixture.identity,
                    work=fixture.work, operation=operation, arguments={}, expectations={})
        self.assertIs(raised.exception, failure)
        self.assertEqual(operation.call_count, 0)
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (1, 0))
        self.assertEqual(fixture.connection.info.transaction_status, 0)
        self.assertIs(fixture.connection.closed, True)
        for event in ("write.cursor.exit", "write.transaction1.exit", "write.connection.exit"):
            self.assertEqual(fixture.events.count(event), 1)
        self.assert_revocation_writer_empty(fixture.recorder)

    def test_configured_revocation_writer_post_exit_rejection_does_not_claim_commit_rollback(self):
        from serverware import authority_revocation_writer_connection as writer
        from serverware.authority_store import revocation_retention as store
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_persistence as store_oracle

        for event in ("write.transaction1.exit", "write.connection.exit"):
            for mutation in (False, True):
                fixture, persisted, returned, changed = self.revocation_owner_fixture(), [], [], []
                work, actual = fixture.arguments["work"], store.persist_revocation_planner_record
                failure = RuntimeError("synthetic post-completion driver failure")

                def persist(**arguments):
                    result = actual(**arguments)
                    persisted.append(result)
                    return result

                def exit_callback(observed):
                    if observed == event:
                        if mutation:
                            work.charge(json_nodes=1)
                            changed.append(work.metrics)
                        else:
                            raise failure

                fixture.write.on_event = exit_callback
                with self.subTest(event=event, mutation=mutation), self.revocation_owner_scope(fixture), \
                        patch.object(store, "persist_revocation_planner_record", side_effect=persist), \
                        patch.object(store.retention, "_verify_record_on_work",
                                     wraps=store.retention._verify_record_on_work) as replay:
                    with self.assertRaises(writer.RevocationWriterConnectionError if mutation else RuntimeError) as raised:
                        returned.append(fixture.owner.produce_and_persist(**fixture.arguments))
                self.assertEqual((len(persisted), returned, replay.call_count), (1, [], 1))
                if mutation:
                    self.assertEqual(len(changed), 1)
                    self.assertEqual(work.metrics, changed[0])
                else:
                    self.assertIs(raised.exception, failure)
                # The recorder completed both genuine managers before this
                # callback. Real exit errors can be indeterminate; no assertion
                # here treats a post-exit guard as undoing an actual commit.
                self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (0, 2))
                self.assertEqual(fixture.recorder.parent["status"], "planned")
                self.assertEqual(fixture.recorder.parent["planned_at_epoch_ns"], fixture.expected.now_epoch_ns)
                self.assertEqual(fixture.recorder.sidecar["exact_envelope_base64url"],
                                 oracle.encoded(persisted[0]["exactEnvelopeBytes"]))
                assertion, projection = store_oracle.expected_authorization_rows(fixture.expected)
                self.assertEqual(fixture.recorder.assertions, {assertion["assertion_evidence_digest"]: assertion})
                self.assertEqual(fixture.recorder.projections, {projection["authorization_projection_digest"]: projection})
                self.assertEqual(fixture.write.info.transaction_status, 0)
                self.assertIs(fixture.write.closed, True)
                for name in ("write.transaction2.exit", "write.transaction1.exit", "write.connection.exit"):
                    self.assertEqual(fixture.events.count(name), 1)
                self.assertNotIn("write.close", fixture.events)

    def test_atomic_revocation_custody_replays_twice_in_one_four_manager_writer(self):
        from serverware import authority_revocation_retention as retention
        from serverware.authority_store import revocation_execution as reservation
        from serverware.authority_store import revocation_retention as store
        import test_authority_revocation_plan as oracle

        fixture = self.revocation_atomic_fixture()
        expected, work = self.revocation_atomic_work(fixture), fixture.arguments["work"]
        with self.revocation_owner_scope(fixture), \
                patch.object(store, "persist_revocation_planner_record",
                             wraps=store.persist_revocation_planner_record) as persist, \
                patch.object(reservation, "reserve_revocation_execution_envelope",
                             wraps=reservation.reserve_revocation_execution_envelope) as reserve, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            result = fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
        self.assertIs(type(result), tuple)
        self.assertEqual(len(result), 2)
        receipt, row = result
        self.assertEqual((persist.call_count, reserve.call_count, replay.call_count, proof.call_count), (1, 1, 2, 2))
        self.assertIs(persist.call_args.kwargs["connection"], reserve.call_args.kwargs["connection"])
        self.assertIs(persist.call_args.kwargs["work"], work)
        self.assertIs(reserve.call_args.kwargs["work"], work)
        for call in replay.call_args_list:
            self.assertIs(call.kwargs["work"], work)
            self.assertEqual(call.kwargs["envelope_bytes"], fixture.arguments["envelope_bytes"])
            self.assertEqual(call.kwargs["evaluation_context_bytes"], fixture.arguments["evaluation_context_bytes"])
        self.assertIs(replay.call_args_list[0].kwargs["envelope_bytes"], fixture.arguments["envelope_bytes"])
        self.assertEqual(receipt["exactEnvelopeBytes"], fixture.arguments["envelope_bytes"])
        self.assertEqual(receipt["evaluationContextBytes"], fixture.arguments["evaluation_context_bytes"])
        self.assertEqual(receipt["plannedAtEpochNs"], fixture.expected.now_epoch_ns)
        self.assertEqual(row, self.assert_revocation_atomic_rows(fixture))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases, fixture.write.transactions), (0, 4, 4))
        self.assertEqual(fixture.connected, [fixture.persistence.persistence_dsn])
        self.assertEqual(fixture.write_cursor.phase, 3)
        self.assertEqual([sql for sql, _ in fixture.write_cursor.calls[:3]], [
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE",
            fixture.write_cursor.identity_sql, fixture.write_cursor.privilege_sql])
        for name in ("transaction1", "transaction2", "transaction3", "transaction4"):
            self.assertEqual(fixture.events.count("write." + name + ".exit"), 1)
        self.assertLess(fixture.events.index("write.transaction3.exit"), fixture.events.index("write.transaction4.enter"))
        self.assertEqual(fixture.write.info.transaction_status, 0)
        self.assertIs(fixture.write.closed, True)
        self.assertNotIn("connect.read", fixture.events)

    def test_atomic_revocation_second_stage_failures_restore_all_five_sets(self):
        from serverware import authority_revocation_retention as retention
        from serverware import db
        from serverware.authority_store import planner_connection as admission
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle

        for target in ("missing", "terminal", "expiry", "signature"):
            fixture, changed, returned = self.revocation_atomic_fixture(), [], []
            before = fixture.recorder.snapshot()
            current = [fixture.expected.now_epoch_ns]
            if target == "missing":
                fixture.recorder.missing_envelope_read = True

            def sql_callback(sql, parameters):
                if " FROM " + reservation_oracle.TABLE in sql:
                    changed.append(target)
                    if target == "terminal":
                        fixture.recorder.envelopes[fixture.arguments["envelope_id"]]["terminal_at_epoch_ns"] = 1
                    elif target == "expiry":
                        current[0] = fixture.expected.deadline_epoch_ns + 1

            def exit_callback(event):
                if target == "signature" and event == "write.transaction3.exit":
                    false_envelope = copy.deepcopy(fixture.expected.envelope)
                    false_envelope["signatureBase64Url"] = "A" * 86
                    raw = oracle.wire(false_envelope)
                    self.assertEqual(len(raw), len(fixture.arguments["envelope_bytes"]))
                    fixture.recorder.sidecar["exact_envelope_base64url"] = oracle.encoded(raw)
                    changed.append(target)

            fixture.recorder.callback, fixture.write.on_event = sql_callback, exit_callback
            with self.subTest(target=target), self.revocation_owner_scope(fixture), \
                    patch.object(admission.time, "time_ns", side_effect=lambda: current[0]), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                with self.assertRaises(retention.RevocationRetentionError if target == "signature"
                                       else db.MetadataStoreError):
                    returned.append(fixture.persistence.persist_and_reserve_execution(**fixture.arguments))
            self.assertEqual((returned, replay.call_count), ([], 2))
            self.assertEqual(proof.call_count, 1 if target == "signature" else 2)
            self.assertEqual(changed, [target])
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (3, 1))
            self.assertEqual(fixture.write.transactions, 4)
            self.assertIs(fixture.write.closed, True)
            self.assertEqual(fixture.write.info.transaction_status, 0)

    def test_atomic_revocation_common_savepoint_survives_a_caught_second_stage_error(self):
        from serverware import authority_revocation_persistence as persistence
        from serverware import authority_revocation_retention as retention
        from serverware import db

        fixture, caught = self.revocation_atomic_fixture(), []
        fixture.recorder.missing_envelope_read = True
        before = fixture.recorder.snapshot()
        names = ("envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns", "envelope_id", "planner_transaction_id")
        arguments = {name: fixture.arguments[name] for name in names}
        expectations = {name: value for name, value in fixture.arguments.items() if name not in (*names, "work")}

        def catch_inside_outer(**supplied):
            try:
                persistence._persist_and_reserve_on_connection(**supplied)
            except db.MetadataStoreError as error:
                caught.append(error)
            else:
                self.fail("missing reserved row unexpectedly succeeded")
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual(fixture.write.info.transaction_status, 2)
            self.assertIs(supplied["connection"].in_transaction, True)
            # No fabricated success/receipt leaves this negative-only driver
            # composition. Its enclosing real owner can complete normally.

        with self.revocation_owner_scope(fixture), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            result = persistence._run_on_configuration(fixture.persistence._snapshot_configuration(),
                catch_inside_outer, arguments, expectations, fixture.arguments["work"])
        self.assertIsNone(result)
        self.assertEqual((len(caught), replay.call_count), (1, 2))
        self.assertEqual(fixture.recorder.snapshot(), before)
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (2, 2))
        self.assertEqual(fixture.write.info.transaction_status, 0)
        self.assertIs(fixture.write.closed, True)

    def test_atomic_revocation_retry_preserves_original_custody_and_still_requires_freshness(self):
        from serverware import authority_revocation_retention as retention
        from serverware import db
        from serverware.authority_store import planner_connection as admission
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle

        for target in ("identical", "expired", "consumed", "terminal"):
            fixture = self.revocation_atomic_fixture()
            fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
            identity = fixture.arguments["envelope_id"]
            fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
            if target == "consumed":
                fixture.recorder.parent["status"] = "consumed"
            elif target == "terminal":
                response = oracle.wire({"status": "committed"})
                receipt_bytes = oracle.wire({"status": "committed", "envelopeId": identity})
                fixture.recorder.envelopes[identity].update(status="committed",
                    exact_response_base64url=oracle.encoded(response),
                    exact_response_bytes_digest=oracle.sha(response), exact_response_byte_count=len(response),
                    terminal_at_epoch_ns=fixture.expected.now_epoch_ns,
                    result_digest=fixture.expected.payload["expectedResultDigest"],
                    terminal_receipt_json=receipt_bytes.decode("ascii"),
                    terminal_receipt_digest=oracle.sha(receipt_bytes))
                # Existing table lifecycle/nullability shape, not a claim
                # that synthetic terminal data passed an executor/verifier.
            before = fixture.recorder.snapshot()
            fixture.arguments["planned_at_epoch_ns"] += 1
            expected = self.revocation_atomic_work(fixture, retry=True)
            now = fixture.expected.deadline_epoch_ns + 1 if target == "expired" else fixture.expected.now_epoch_ns
            with self.subTest(target=target), self.revocation_owner_scope(fixture), \
                    patch.object(admission.time, "time_ns", return_value=now), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                if target == "identical":
                    receipt, row = fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
                    self.assertEqual(receipt["plannedAtEpochNs"], fixture.expected.now_epoch_ns)
                    self.assertEqual(receipt["exactEnvelopeBytes"], fixture.arguments["envelope_bytes"])
                    self.assertEqual(receipt["evaluationContextBytes"], fixture.arguments["evaluation_context_bytes"])
                    self.assertEqual(row, before[4][identity])
                    self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])
                else:
                    with self.assertRaises(db.MetadataStoreError):
                        fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual(replay.call_count, 1 if target == "expired" else 2)
            self.assertFalse(any(sql.startswith("UPDATE ") for sql, _ in fixture.recorder.statements))
            self.assertIs(fixture.write.closed, True)

    def test_atomic_revocation_captures_original_inputs_and_configuration_before_callbacks(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for stage in ("connect", "between"):
            fixture, changed = self.revocation_atomic_fixture(), []
            original_dsn = fixture.persistence.persistence_dsn
            original_request = copy.deepcopy(fixture.arguments["expected_request"])
            original_before = copy.deepcopy(fixture.arguments["expected_before"])
            expected = self.revocation_atomic_work(fixture)
            connect = fixture.connect

            def mutate():
                fixture.arguments["expected_request"].clear()
                fixture.arguments["expected_before"].clear()
                object.__setattr__(fixture.persistence, "persistence_dsn", "postgresql://changed.invalid/metadata")
                object.__setattr__(fixture.persistence, "planner_public_key", fixture.expected.other_key.public_key())
                object.__setattr__(fixture.persistence, "_database_identity",
                    ("serverware_policy_authority_planner_writer", "changed", "29", "changed issuer"))
                changed.append(stage)

            def open_connection(*args, **kwargs):
                connection = connect(*args, **kwargs)
                if stage == "connect":
                    mutate()
                return connection

            def exit_callback(event):
                if stage == "between" and event == "write.transaction3.exit":
                    mutate()

            fixture.connect, fixture.write.on_event = open_connection, exit_callback
            with self.subTest(stage=stage), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
            self.assertEqual(changed, [stage])
            self.assertEqual(fixture.connected, [original_dsn])
            self.assertEqual(replay.call_count, 2)
            for call in replay.call_args_list:
                self.assertEqual(call.kwargs["expected_request"], original_request)
                self.assertEqual(call.kwargs["expected_before"], original_before)
                self.assertEqual(call.kwargs["planner_public_key"].public_bytes(Encoding.Raw, PublicFormat.Raw),
                                 fixture.expected.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            self.assert_revocation_atomic_rows(fixture)
            self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])

    def test_atomic_revocation_between_store_driver_changes_restore_original_outer_snapshot(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_connection as writer

        for target in ("meter", "raw"):
            fixture, changed = self.revocation_atomic_fixture(), []
            before, work = fixture.recorder.snapshot(), fixture.arguments["work"]

            def exit_callback(event):
                if event == "write.transaction3.exit":
                    if target == "meter":
                        work.charge(json_nodes=1)
                    else:
                        fixture.write.pgconn = object()
                    changed.append(work.metrics)

            fixture.write.on_event = exit_callback
            with self.subTest(target=target), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(writer.RevocationWriterConnectionError):
                    fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
            self.assertEqual((len(changed), replay.call_count), (1, 1))
            self.assertEqual(work.metrics, changed[0])
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (2, 1))
            self.assertEqual(fixture.write.transactions, 3)
            self.assertEqual(fixture.write.info.transaction_status, 0)
            self.assertIs(fixture.write.closed, True)

    def test_atomic_revocation_exact_prior_and_each_short_composed_budget_use_real_proof_children(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle

        for retry in (False, True):
            for prior, dimension in (((0, 0, 0), None), ((2, 23, 7), None),
                                     ((2, 23, 7), 0), ((2, 23, 7), 1), ((2, 23, 7), 2)):
                fixture = self.revocation_atomic_fixture()
                if retry:
                    fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
                    identity = fixture.arguments["envelope_id"]
                    fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
                before = fixture.recorder.snapshot()
                expected = self.revocation_atomic_work(fixture, retry=retry)
                limits = list(oracle.add(prior, expected["admission"]))
                if dimension is not None:
                    limits[dimension] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                fixture.arguments["work"] = work
                entering = work.limits
                # A genuine mixed proof allocates its remaining-clamped child.
                # Only replacement OUTER packaging ledgers are forbidden.
                with self.subTest(retry=retry, prior=prior, dimension=dimension), \
                        self.revocation_owner_scope(fixture), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                                     side_effect=AssertionError("replacement outer allowance")), \
                        patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                    if dimension is None:
                        fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
                        self.assert_revocation_atomic_rows(fixture)
                        self.assertEqual(proof.call_count, 2)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                    else:
                        with self.assertRaises(ValueError):
                            fixture.persistence.persist_and_reserve_execution(**fixture.arguments)
                        self.assertEqual(fixture.recorder.snapshot(), before)
                        self.assertTrue(all(start <= used <= maximum for start, used, maximum
                            in zip(prior, oracle.units(work.metrics), limits)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_atomic_revocation_repeated_call_spends_new_then_retry_work_without_cached_authority(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for dimension in (None, 0, 1, 2):
            first = self.revocation_atomic_fixture()
            second = self.revocation_atomic_fixture(recorder=first.recorder)
            new, retry, prior = self.revocation_atomic_work(first), self.revocation_atomic_work(second, retry=True), (2, 23, 7)
            first_peak = oracle.add(prior, new["admission"])
            limits = list(oracle.add(prior, new["total"], retry["admission"]))
            self.assertTrue(all(later > earlier for earlier, later in zip(first_peak, limits)))
            if dimension is not None:
                limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering, results = work.limits, []
            first.arguments["work"] = second.arguments["work"] = work
            second.arguments["planned_at_epoch_ns"] += 1
            with self.subTest(dimension=dimension), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                with self.revocation_owner_scope(first):
                    results.append(first.persistence.persist_and_reserve_execution(**first.arguments))
                self.assert_revocation_atomic_rows(first)
                before_second = first.recorder.snapshot()
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"]))
                with self.revocation_owner_scope(second):
                    if dimension is None:
                        results.append(second.persistence.persist_and_reserve_execution(**second.arguments))
                    else:
                        with self.assertRaises(ValueError):
                            second.persistence.persist_and_reserve_execution(**second.arguments)
            self.assertEqual(first.recorder.snapshot(), before_second)
            if dimension is None:
                self.assertEqual(results[0], results[1])
                self.assertEqual((replay.call_count, proof.call_count), (4, 4))
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"], retry["total"]))
                self.assertEqual((first.recorder.rollbacks, first.recorder.releases), (0, 8))
            else:
                self.assertEqual(len(results), 1)
                self.assertTrue(all(start <= used <= maximum for start, used, maximum in zip(
                    oracle.add(prior, new["total"]), oracle.units(work.metrics), limits)))
            self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_atomic_revocation_post_exit_errors_do_not_claim_completed_commit_rollback(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_connection as writer

        for event in ("write.transaction1.exit", "write.connection.exit"):
            for mutation in (False, True):
                fixture, returned, changed = self.revocation_atomic_fixture(), [], []
                work = fixture.arguments["work"]
                failure = RuntimeError("synthetic atomic post-completion driver failure")

                def exit_callback(observed):
                    if observed == event:
                        if mutation:
                            work.charge(json_nodes=1)
                            changed.append(work.metrics)
                        else:
                            raise failure

                fixture.write.on_event = exit_callback
                with self.subTest(event=event, mutation=mutation), self.revocation_owner_scope(fixture), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(writer.RevocationWriterConnectionError if mutation else RuntimeError) as raised:
                        returned.append(fixture.persistence.persist_and_reserve_execution(**fixture.arguments))
                self.assertEqual((returned, replay.call_count), ([], 2))
                if mutation:
                    self.assertEqual(changed, [work.metrics])
                else:
                    self.assertIs(raised.exception, failure)
                self.assert_revocation_atomic_rows(fixture)
                self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (0, 4))
                self.assertEqual(fixture.write.info.transaction_status, 0)
                self.assertIs(fixture.write.closed, True)
                for scope in ("transaction1", "transaction2", "transaction3", "transaction4", "connection"):
                    self.assertEqual(fixture.events.count("write." + scope + ".exit"), 1)
                self.assertNotIn("write.close", fixture.events)

    def test_writer_action_components_feed_real_configured_atomic_custody_on_one_work(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        fixture = self.revocation_action_fixture()
        expected, work = self.revocation_action_work(fixture), fixture.arguments["work"]
        original = fixture.source.arguments.copy()
        instant = fixture.source.expectations["database_now"]
        with self.revocation_owner_scope(fixture), \
                patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            receipt, row = self.run_revocation_action_components(fixture)
        self.assertEqual((replay.call_count, proof.call_count), (2, 2))
        # Two mapper keys plus the current-key loader's SPKI check and the
        # actual current receipt verifier construction. Neither current path
        # is replaced by a successful admission/signature stub.
        self.assertEqual(keys.call_count, 4)
        for call in replay.call_args_list:
            self.assertIs(call.kwargs["work"], work)
            self.assertIs(call.kwargs["database_now"], instant)
            self.assertEqual(call.kwargs["envelope_bytes"], original["envelope_bytes"])
            self.assertEqual(call.kwargs["evaluation_context_bytes"], original["evaluation_context_bytes"])
        self.assertEqual(receipt["exactEnvelopeBytes"], original["envelope_bytes"])
        self.assertEqual(row, self.assert_revocation_atomic_rows(fixture))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        self.assertEqual(expected["prefix"][0], 4)
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (0, 4))
        self.assertEqual(fixture.connected, [fixture.source.configuration.persistence_dsn])
        self.assertIs(fixture.write.closed, True)

    def test_writer_action_owned_inputs_survive_boundary_and_opener_alias_changes(self):
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for stage in ("boundary", "connect"):
            fixture, changed = self.revocation_action_fixture(), []
            expected = self.revocation_action_work(fixture)
            original = copy.deepcopy(fixture.source.expectations)
            connect = fixture.connect
            dsn = fixture.source.configuration.persistence_dsn

            def mutate():
                fixture.source.expectations["expected_request"].clear()
                fixture.source.expectations["expected_before"].clear()
                fixture.source.configuration.payload.clear()
                fixture.source.configuration.persistence_dsn = "postgresql://late-alias.invalid/metadata"
                changed.append(stage)

            def open_connection(*args, **kwargs):
                result = connect(*args, **kwargs)
                if stage == "connect": mutate()
                return result

            fixture.connect = open_connection
            with self.subTest(stage=stage), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                self.run_revocation_action_components(fixture, after_capture=mutate if stage == "boundary" else None)
            self.assertEqual(changed, [stage])
            self.assertEqual(fixture.connected, [dsn])
            self.assertEqual(replay.call_count, 2)
            for call in replay.call_args_list:
                for name in ("expected_request", "expected_before", "maximum_assertion_age_ns",
                             "maximum_plan_age_ns", "maximum_clock_skew_ns", "database_now"):
                    self.assertEqual(call.kwargs[name], original[name])
            self.assert_revocation_atomic_rows(fixture)
            self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])

    def test_writer_action_policy_denies_before_connect_and_second_replay_failure_rolls_back(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_action as action
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_action as action_oracle

        for field in action_oracle.POLICY_FIELDS:
            fixture = self.revocation_action_fixture()
            fixture.source.expectations[field] += 1
            with self.subTest(field=field), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(action.RevocationWriterActionError):
                    self.run_revocation_action_components(fixture)
            self.assertEqual((fixture.connected, replay.call_count, fixture.recorder.statements), ([], 0, []))
            self.assertEqual(fixture.recorder.snapshot(), (None, None, {}, {}, {}))

        fixture, changed, returned = self.revocation_action_fixture(), [], []
        before = fixture.recorder.snapshot()

        def corrupt_original(event):
            if event == "write.transaction3.exit":
                false_envelope = copy.deepcopy(fixture.expected.envelope)
                false_envelope["signatureBase64Url"] = "A" * 86
                fixture.recorder.sidecar["exact_envelope_base64url"] = oracle.encoded(oracle.wire(false_envelope))
                changed.append(event)

        fixture.write.on_event = corrupt_original
        with self.revocation_owner_scope(fixture), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            with self.assertRaises(retention.RevocationRetentionError):
                returned.append(self.run_revocation_action_components(fixture))
        self.assertEqual((len(changed), returned, replay.call_count, proof.call_count), (1, [], 2, 1))
        self.assertEqual(fixture.recorder.snapshot(), before)
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (3, 1))
        self.assertIs(fixture.write.closed, True)

    def test_writer_action_full_composition_exact_prior_and_each_short_budget(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle

        for retry in (False, True):
            for prior, dimension in (((0, 0, 0), None), ((2, 23, 7), None),
                                     ((2, 23, 7), 0), ((2, 23, 7), 1), ((2, 23, 7), 2)):
                fixture = self.revocation_action_fixture()
                if retry:
                    fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
                    identity = fixture.arguments["envelope_id"]
                    fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
                before = fixture.recorder.snapshot()
                expected = self.revocation_action_work(fixture, retry=retry)
                limits = list(oracle.add(prior, expected["admission"]))
                if dimension is not None: limits[dimension] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                fixture.arguments["work"] = work
                entering = work.limits
                with self.subTest(retry=retry, prior=prior, dimension=dimension), self.revocation_owner_scope(fixture), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                                     side_effect=AssertionError("replacement outer proof allowance")), \
                        patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                    if dimension is None:
                        self.run_revocation_action_components(fixture)
                        self.assert_revocation_atomic_rows(fixture)
                        self.assertEqual(proof.call_count, 2)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                    else:
                        with self.assertRaises(ValueError):
                            self.run_revocation_action_components(fixture)
                        self.assertEqual(fixture.recorder.snapshot(), before)
                        self.assertTrue(all(start <= used <= maximum for start, used, maximum in zip(
                            prior, oracle.units(work.metrics), limits)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_writer_action_repeat_rebuilds_factory_and_replays_without_new_allowance(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for dimension in (None, 0, 1, 2):
            first = self.revocation_action_fixture()
            second = self.revocation_action_fixture(recorder=first.recorder)
            new, retry, prior = self.revocation_action_work(first), self.revocation_action_work(second, retry=True), (2, 23, 7)
            limits = list(oracle.add(prior, new["total"], retry["admission"]))
            self.assertTrue(all(later > earlier for earlier, later in zip(oracle.add(prior, new["admission"]), limits)))
            if dimension is not None: limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            first.arguments["work"] = second.arguments["work"] = work
            second.source.arguments["planned_at_epoch_ns"] += 1
            entering = work.limits
            with self.subTest(dimension=dimension), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.revocation_owner_scope(first):
                    original = self.run_revocation_action_components(first)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"]))
                stored = first.recorder.snapshot()
                with self.revocation_owner_scope(second):
                    if dimension is None:
                        self.assertEqual(self.run_revocation_action_components(second), original)
                    else:
                        with self.assertRaises(ValueError):
                            self.run_revocation_action_components(second)
            self.assertEqual(first.recorder.snapshot(), stored)
            if dimension is None:
                self.assertEqual(replay.call_count, 4)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"], retry["total"]))
                self.assertEqual((first.recorder.rollbacks, first.recorder.releases), (0, 8))
            else:
                self.assertTrue(all(start <= used <= maximum for start, used, maximum in zip(
                    oracle.add(prior, new["total"]), oracle.units(work.metrics), limits)))
            self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_detached_writer_composition_authenticates_then_replays_on_actual_gated_writer(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_composition as composition
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_writer_request as request_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        for retry in (False, True):
            fixture = self.revocation_composition_fixture()
            if retry:
                fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
                identity = fixture.arguments["envelope_id"]
                fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
                request = request_oracle.expected_row(fixture.detached)
                fixture.recorder.requests[request["intent_envelope_id"]] = request
                fixture.recorder.acknowledgments[request["intent_envelope_id"]] = ack_oracle.expected_row(fixture.detached)
            expected, meter = self.revocation_composition_work(fixture, retry=retry), fixture.arguments["work"]
            clocks, seen = [], []
            verify = composition.commitment._verify_commitments_on_work

            def authenticate(**arguments):
                self.assertEqual(clocks, ["monotonic", "epoch"])
                self.assertEqual(fixture.connected, [])
                self.assertIs(arguments["work"], meter)
                result = verify(**arguments)
                seen.append(result)
                return result

            with self.subTest(retry=retry), self.revocation_owner_scope(fixture), \
                    patch.object(composition.time, "monotonic_ns", side_effect=lambda: clocks.append("monotonic") or fixture.expected.now_monotonic_ns), \
                    patch.object(composition.time, "time_ns", side_effect=lambda: clocks.append("epoch") or fixture.expected.now_epoch_ns), \
                    patch.object(composition.commitment, "_verify_commitments_on_work", side_effect=authenticate) as authentication, \
                    patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                receipt, row, ack_bytes = self.run_revocation_composition_components(fixture)
            self.assertEqual((authentication.call_count, replay.call_count, proof.call_count), (1, 2, 2))
            self.assertEqual(seen[0].metrics.signature_verifications, 2)
            # Reuse the mapper's keys: new custody additionally invokes the
            # real db SPKI-loader and current receipt constructor; retry does
            # neither. No configured/live-key success result is substituted.
            self.assertEqual(keys.call_count, 2 if retry else 4)
            self.assertEqual(row, self.assert_revocation_composition_rows(fixture))
            self.assertEqual(ack_bytes, ack_oracle.expected_bytes(fixture.detached))
            self.assertEqual(receipt["exactEnvelopeBytes"], fixture.source.arguments["envelope_bytes"])
            self.assertEqual(receipt["evaluationContextBytes"], fixture.source.arguments["evaluation_context_bytes"])
            self.assertEqual((fixture.recorder.releases, fixture.recorder.rollbacks), (4, 0))
            self.assertEqual(fixture.connected, [fixture.source.configuration.persistence_dsn])
            self.assertEqual(expected["prefix"][0], 14)
            self.assertEqual(oracle.units(meter.metrics), expected["total"])
            for call in replay.call_args_list:
                self.assertIs(call.kwargs["work"], meter)
                self.assertEqual(call.kwargs["database_now"], fixture.source.expectations["database_now"])
            self.assertIs(fixture.write.closed, True)

    def test_detached_writer_rejections_precede_connect_and_late_replay_restores_all_five_sets(self):
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for mode in ("signature", "body", "policy", "writer_age"):
            fixture = self.revocation_composition_fixture()
            if mode == "signature":
                fixture.detached.relay["signature"] = "A" * 86
                fixture.detached.relay_bytes = oracle.wire(fixture.detached.relay)
            elif mode == "body": fixture.source.arguments["envelope_bytes"] += b" "
            elif mode == "policy":
                fixture.source.expectations["maximum_assertion_age_ns"] += 1
                fixture.detached.rebuild()
            else:
                fixture.source.configuration.payload["roles"]["planner-writer"]["maximumInternalAgeNs"] = 1
                fixture.detached.refresh_configuration()
            with self.subTest(mode=mode), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError): self.run_revocation_composition_components(fixture)
            self.assertEqual((fixture.connected, replay.call_count, fixture.recorder.statements), ([], 0, []))
            self.assertEqual(fixture.recorder.snapshot(), (None, None, {}, {}, {}, {}, {}))

        fixture, changed = self.revocation_composition_fixture(), []
        before = fixture.recorder.snapshot()

        def corrupt_original(event):
            if event == "write.transaction3.exit":
                false = copy.deepcopy(fixture.expected.envelope)
                false["signatureBase64Url"] = "A" * 86
                fixture.recorder.sidecar["exact_envelope_base64url"] = oracle.encoded(oracle.wire(false))
                changed.append(event)

        fixture.write.on_event = corrupt_original
        with self.revocation_owner_scope(fixture), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            with self.assertRaises(retention.RevocationRetentionError): self.run_revocation_composition_components(fixture)
        self.assertEqual((len(changed), replay.call_count, proof.call_count), (1, 2, 1))
        recorder_state = fixture.recorder.snapshot()
        self.assertEqual(recorder_state, before)
        self.assertEqual(recorder_state, (None, None, {}, {}, {}, {}, {}))
        self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases), (3, 1))
        self.assertIs(fixture.write.closed, True)

    def test_detached_writer_fixed_snapshot_survives_owner_and_config_alias_changes(self):
        from serverware import authority_revocation_writer_composition as composition
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle

        for stage in ("clock", "connect"):
            fixture, changed = self.revocation_composition_fixture(), []
            expected, held = self.revocation_composition_work(fixture), {}
            original_claims = copy.deepcopy(fixture.source.expectations)
            dsn, connect = fixture.source.configuration.persistence_dsn, fixture.connect

            def hold(owner, arguments):
                held.update(owner=owner, arguments=arguments)

            def mutate():
                fixture.source.configuration.payload.clear()
                fixture.source.expectations["expected_request"].clear()
                fixture.source.expectations["expected_before"].clear()
                held["arguments"]["owned_payload"].clear()
                object.__setattr__(held["owner"], "persistence_dsn", "postgresql://retarget.invalid/db")
                object.__setattr__(held["owner"], "planner_public_key", fixture.expected.other_key.public_key())
                object.__setattr__(held["owner"], "_database_identity", ("wrong", "x", "y", "z"))
                changed.append(stage)

            def monotonic():
                if stage == "clock" and not changed: mutate()
                return fixture.expected.now_monotonic_ns

            def open_connection(*args, **kwargs):
                result = connect(*args, **kwargs)
                if stage == "connect": mutate()
                return result

            fixture.connect = open_connection
            with self.subTest(stage=stage), self.revocation_owner_scope(fixture), \
                    patch.object(composition.time, "monotonic_ns", side_effect=monotonic), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                self.run_revocation_composition_components(fixture, after_preparation=hold)
            self.assertEqual(changed, [stage])
            self.assertEqual(fixture.connected, [dsn])
            self.assertEqual(replay.call_count, 2)
            for call in replay.call_args_list:
                for name in original_claims: self.assertEqual(call.kwargs[name], original_claims[name])
            self.assert_revocation_composition_rows(fixture)
            self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])

    def test_detached_writer_full_exact_prior_and_each_short_budget_keep_genuine_proof_children(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_writer_request as request_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        for retry in (False, True):
            for prior, axis in (((0, 0, 0), None), ((3, 17, 11), None),
                                ((3, 17, 11), 0), ((3, 17, 11), 1), ((3, 17, 11), 2)):
                fixture = self.revocation_composition_fixture()
                if retry:
                    fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
                    identity = fixture.arguments["envelope_id"]
                    fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
                    request = request_oracle.expected_row(fixture.detached)
                    fixture.recorder.requests[request["intent_envelope_id"]] = request
                    fixture.recorder.acknowledgments[request["intent_envelope_id"]] = ack_oracle.expected_row(fixture.detached)
                before, expected = fixture.recorder.snapshot(), self.revocation_composition_work(fixture, retry=retry)
                limits = list(oracle.add(prior, expected["admission"]))
                if axis is not None: limits[axis] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                fixture.arguments["work"] = work
                entering = work.limits
                with self.subTest(retry=retry, prior=prior, axis=axis), self.revocation_owner_scope(fixture), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                            side_effect=AssertionError("replacement outer proof allowance")), \
                        patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                    if axis is None:
                        self.run_revocation_composition_components(fixture)
                        self.assert_revocation_composition_rows(fixture)
                        self.assertEqual(proof.call_count, 2)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                    else:
                        with self.assertRaises(ValueError): self.run_revocation_composition_components(fixture)
                        self.assertEqual(fixture.recorder.snapshot(), before)
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_detached_writer_retry_reauthenticates_originals_and_preserves_first_custody(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_composition as composition
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_plan as oracle

        for axis in (None, 0, 1, 2):
            first = self.revocation_composition_fixture()
            second = self.revocation_composition_fixture(recorder=first.recorder)
            # Repeat all five exact originals and the original planned time.
            # The ACK is unchanged custody evidence, never terminal execution.
            originals = first.detached.originals()
            self.assertEqual(second.detached.originals(), originals)
            self.assertEqual(second.source.arguments["planned_at_epoch_ns"],
                             first.source.arguments["planned_at_epoch_ns"])
            new, retry, prior = self.revocation_composition_work(first), self.revocation_composition_work(second, retry=True), (3, 17, 11)
            limits = list(oracle.add(prior, new["total"], retry["admission"]))
            self.assertTrue(all(later > earlier for earlier, later in zip(oracle.add(prior, new["admission"]), limits)))
            if axis is not None: limits[axis] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            first.arguments["work"] = second.arguments["work"] = work
            with self.subTest(axis=axis), \
                    patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign, \
                    patch.object(composition.commitment, "_verify_commitments_on_work",
                        wraps=composition.commitment._verify_commitments_on_work) as authenticate, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.revocation_owner_scope(first): original = self.run_revocation_composition_components(first)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"]))
                stored = first.recorder.snapshot()
                with self.revocation_owner_scope(second):
                    if axis is None: self.assertEqual(self.run_revocation_composition_components(second), original)
                    else:
                        with self.assertRaises(ValueError): self.run_revocation_composition_components(second)
            self.assertEqual(first.recorder.snapshot(), stored)
            self.assertEqual(sign.call_count, 1)
            for call in authenticate.call_args_list:
                for name, value in originals.items(): self.assertEqual(call.kwargs[name], value)
            if axis is None:
                self.assertEqual((authenticate.call_count, replay.call_count), (2, 4))
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, new["total"], retry["total"]))
                self.assertEqual((first.recorder.rollbacks, first.recorder.releases), (0, 8))
            self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def transfer_revocation_composition_components(self, fixture, connection):
        """Actual framing plus gated custody, not a fabricated service launch.

        The recorder supplies only stream/clock/driver observations. No
        AuthorityProcess is constructed, admitted or monkeypatched here. The
        separate source controls bind this same ordering to the real server.
        """
        from serverware import authority_revocation_writer_transport as transfer
        import test_authority_revocation_writer_transport as transport_oracle

        deadline = fixture.expected.now_monotonic_ns + 1_000_000_000
        prefix = transfer._recv_prefix(connection, deadline_ns=deadline)
        received = transfer._recv_request(connection, deadline_ns=deadline, prefix=prefix)

        def use_received(_owner, arguments):
            for name, value in zip(transport_oracle.NAMES, received):
                arguments[name] = value

        result = self.run_revocation_composition_components(fixture, after_preparation=use_received)
        transfer._send_ack(connection, result[2], deadline_ns=deadline)
        return result

    def test_writer_transfer_originals_replay_twice_and_release_stored_ack_only_after_owner_exit(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_writer_transport as transport_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle
        import test_authority_revocation_plan as oracle

        first = self.revocation_composition_fixture()
        retry = self.revocation_composition_fixture(recorder=first.recorder)
        replies = []
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign:
            for index, fixture in enumerate((first, retry)):
                originals = fixture.detached.originals()
                segments = transport_oracle.request_segments(tuple(originals[name] for name in transport_oracle.NAMES))

                def observe(_socket, event, *_arguments):
                    if event == "sendall":
                        self.assertIs(fixture.write.closed, True)
                        self.assertEqual(fixture.write.info.transaction_status, 0)
                        self.assertTrue(fixture.recorder.acknowledgments)

                connection = transport_oracle.SocketRecorder(segments, fragment_size=97, hook=observe)
                expected = self.revocation_composition_work(fixture, retry=bool(index))
                with self.revocation_owner_scope(fixture):
                    result = self.transfer_revocation_composition_components(fixture, connection)
                replies.append(result[2])
                self.assertEqual(connection.received_bytes, sum(map(len, segments)))
                self.assertEqual(connection.sent, list(transport_oracle.ack_segments(result[2])))
                self.assertEqual(result[2], ack_oracle.expected_bytes(fixture.detached))
                self.assertEqual(result[1], self.assert_revocation_composition_rows(fixture))
                self.assertEqual(fixture.write.transactions, 4)
                self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])
                self.assertEqual(connection.close_count, 0)  # Actual server owns close, not component helpers.
        self.assertEqual((replay.call_count, sign.call_count), (4, 1))
        self.assertEqual(replies[0], replies[1])

    def test_writer_transfer_truncation_and_trailing_bytes_never_reach_actual_custody(self):
        from serverware import authority_revocation_writer_transport as transfer
        import test_authority_revocation_writer_transport as transport_oracle

        for changed in ("short_header", "short_body", "trailing"):
            fixture = self.revocation_composition_fixture()
            originals = fixture.detached.originals()
            segments = transport_oracle.request_segments(tuple(originals[name] for name in transport_oracle.NAMES))
            if changed == "short_header":
                segments = (segments[0][:-1],)
            elif changed == "short_body":
                segments = (*segments[:-1], segments[-1][:-1])
            else:
                segments = (*segments, b"x")
            connection = transport_oracle.SocketRecorder(segments, fragment_size=113)
            before = fixture.recorder.snapshot()
            with self.subTest(changed=changed), self.revocation_owner_scope(fixture):
                with self.assertRaises(transfer.AuthorityTransportError):
                    self.transfer_revocation_composition_components(fixture, connection)
            self.assertEqual(fixture.connected, [])
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual(connection.sent, [])
            self.assertEqual((fixture.arguments["work"].hash_work,
                fixture.arguments["work"].input_bytes, fixture.arguments["work"].json_nodes), (0, 0, 0))

    def test_writer_transfer_failure_before_ack_and_after_custody_have_distinct_storage_outcomes(self):
        from serverware import authority_revocation_retention as retention
        from serverware import db
        import test_authority_revocation_writer_transport as transport_oracle

        for changed in ("ack_readback", "outer_exit", "send"):
            fixture = self.revocation_composition_fixture()
            originals = fixture.detached.originals()
            segments = transport_oracle.request_segments(tuple(originals[name] for name in transport_oracle.NAMES))
            failure = OSError("recorded transfer or owner exit failure")
            connection = transport_oracle.SocketRecorder(segments,
                fail_at="sendall" if changed == "send" else None, failure=failure)
            before = fixture.recorder.snapshot()
            if changed == "ack_readback":
                fixture.recorder.missing_ack_readback = True
            elif changed == "outer_exit":
                def exit_failure(event):
                    if event == "write.transaction1.exit":
                        raise failure
                fixture.write.on_event = exit_failure
            expected_error = db.MetadataStoreError if changed == "ack_readback" else OSError
            with self.subTest(changed=changed), self.revocation_owner_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(expected_error) as raised:
                    self.transfer_revocation_composition_components(fixture, connection)
            self.assertEqual(replay.call_count, 2)
            self.assertEqual(fixture.write.transactions, 4)
            if changed == "ack_readback":
                self.assertEqual(str(raised.exception), "revocation writer ACK row is not a closed object")
            else:
                self.assertIs(raised.exception, failure)
            self.assertEqual((fixture.recorder.releases, fixture.recorder.rollbacks),
                (2, 2) if changed == "ack_readback" else (4, 0))
            self.assertEqual(connection.sent, [])
            self.assertEqual(connection.counts.get("sendall", 0), int(changed == "send"))
            self.assertIs(fixture.write.closed, True)
            if changed == "ack_readback":
                self.assertEqual(fixture.recorder.snapshot(), before)
            else:
                # Late outer-exit or response failure cannot imply rollback.
                self.assert_revocation_composition_rows(fixture)
                self.assertTrue(fixture.recorder.acknowledgments)

    def test_writer_ack_legacy_request_attachment_still_authenticates_and_replays_both_originals(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_reservation as reservation_oracle
        import test_authority_revocation_writer_request as request_oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        fixture = self.revocation_composition_fixture()
        # Explicit synthetic historical six-row observation, not a migration
        # result or accepted-receipt token. The fixed action still authenticates
        # the originals and both stores actually replay before attaching.
        fixture.recorder.seed(fixture.expected, fixture.expected.now_epoch_ns)
        identity = fixture.arguments["envelope_id"]
        fixture.recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.expected, identity)
        request = request_oracle.expected_row(fixture.detached)
        fixture.recorder.requests[request["intent_envelope_id"]] = request
        before = fixture.recorder.snapshot()
        expected = self.revocation_composition_work(fixture, retry=True, ack_existing=False)
        with self.revocation_owner_scope(fixture), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign:
            _, _, raw = self.run_revocation_composition_components(fixture)
        self.assertEqual((replay.call_count, sign.call_count), (2, 1))
        self.assertEqual(fixture.recorder.snapshot()[:6], before[:6])
        self.assertEqual(raw, ack_oracle.expected_bytes(fixture.detached))
        self.assert_revocation_composition_rows(fixture)
        self.assertEqual(oracle.units(fixture.arguments["work"].metrics), expected["total"])

    def test_writer_ack_missing_readback_restores_seven_sets_even_when_caught_inside_outer(self):
        from serverware import authority_revocation_persistence as persistence
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        from serverware import db
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        for caught_inside in (False, True):
            fixture, caught, returned = self.revocation_composition_fixture(), [], []
            fixture.recorder.missing_ack_readback = True
            before, runner = fixture.recorder.snapshot(), persistence._run_on_configuration

            def run(configuration, operation, arguments, expectations, work):
                self.assertIs(operation, persistence._persist_and_reserve_request_on_connection)

                def catch(**supplied):
                    try: operation(**supplied)
                    except db.MetadataStoreError as error: caught.append(error)
                    else: self.fail("missing ACK readback unexpectedly succeeded")
                    self.assertEqual(fixture.recorder.snapshot(), before)
                    self.assertEqual(fixture.write.info.transaction_status, 2)
                    self.assertIs(supplied["connection"].in_transaction, True)

                return runner(configuration, catch if caught_inside else operation, arguments, expectations, work)

            with self.subTest(caught_inside=caught_inside), self.revocation_owner_scope(fixture), \
                    patch.object(persistence, "_run_on_configuration", side_effect=run), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign:
                if caught_inside:
                    self.assertIsNone(self.run_revocation_composition_components(fixture))
                else:
                    with self.assertRaises(db.MetadataStoreError):
                        returned.append(self.run_revocation_composition_components(fixture))
            self.assertEqual((replay.call_count, sign.call_count), (2, 1))
            self.assertEqual((len(caught), returned), (int(caught_inside), []))
            self.assertTrue(any(sql == ack_oracle.INSERT for sql, _ in fixture.recorder.statements))
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases),
                (1, 3) if caught_inside else (2, 2))
            self.assertIs(fixture.write.closed, True)

    def test_writer_ack_is_not_released_on_common_outer_or_connection_exit_uncertainty(self):
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        for failed_event in (None, "write.transaction2.exit", "write.transaction1.exit", "write.connection.exit"):
            fixture, returned, observed = self.revocation_composition_fixture(), [], []
            before, failure = fixture.recorder.snapshot(), RuntimeError("actual owner exit failed")

            def observe(event):
                if event in {"write.transaction2.exit", "write.transaction1.exit", "write.connection.exit"}:
                    self.assertEqual(returned, [])
                    if failed_event != "write.transaction2.exit" or event == "write.transaction2.exit":
                        self.assertTrue(fixture.recorder.acknowledgments)
                    observed.append(event)
                if event == failed_event: raise failure

            fixture.write.on_event = observe
            with self.subTest(event=failed_event), self.revocation_owner_scope(fixture), \
                    patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign:
                if failed_event is None:
                    returned.append(self.run_revocation_composition_components(fixture))
                else:
                    with self.assertRaises(RuntimeError) as raised:
                        returned.append(self.run_revocation_composition_components(fixture))
                    self.assertIs(raised.exception, failure)
            self.assertEqual(sign.call_count, 1)
            self.assertIs(fixture.write.closed, True)
            if failed_event == "write.transaction2.exit":
                self.assertEqual(fixture.recorder.snapshot(), before)
            else:
                # The synthetic manager released outer custody before these
                # late hooks. No rollback/delivery certainty is invented.
                self.assert_revocation_composition_rows(fixture)
            if failed_event is None:
                self.assertEqual(observed, ["write.transaction2.exit", "write.transaction1.exit", "write.connection.exit"])
                self.assertEqual(returned[0][2], ack_oracle.expected_bytes(fixture.detached))
            else:
                self.assertEqual(returned, [])

    def test_writer_ack_existing_corrupted_signature_denies_after_both_replays_without_resigning(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_acknowledgment_storage as ack_oracle

        original = self.revocation_composition_fixture()
        with self.revocation_owner_scope(original): self.run_revocation_composition_components(original)
        envelope = json.loads(ack_oracle.expected_bytes(original.detached))
        envelope["signatureBase64Url"] = "A" * 86
        corrupt = oracle.wire(envelope)
        row = next(iter(original.recorder.acknowledgments.values()))
        row.update(exact_ack_base64url=oracle.encoded(corrupt), exact_ack_bytes_digest=oracle.sha(corrupt),
            exact_ack_byte_count=len(corrupt))
        before = original.recorder.snapshot()
        retry = self.revocation_composition_fixture(recorder=original.recorder)
        with self.revocation_owner_scope(retry), \
                patch.object(acknowledgment, "_sign_on_work", side_effect=AssertionError("existing ACK re-signed")), \
                patch.object(acknowledgment, "_verify_on_work", wraps=acknowledgment._verify_on_work) as verify, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                self.assertRaises(ValueError):
            self.run_revocation_composition_components(retry)
        self.assertEqual((verify.call_count, replay.call_count), (1, 2))
        self.assertEqual(original.recorder.snapshot(), before)

    def test_writer_request_authentic_same_id_changes_conflict_before_either_replay(self):
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_writer_composition as composition
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_request as request_oracle

        for mode in ("intent_header", "relay_header", "history", "configuration", "planned_time"):
            original = self.revocation_composition_fixture()
            with self.revocation_owner_scope(original): self.run_revocation_composition_components(original)
            before = original.recorder.snapshot()
            candidate = self.revocation_composition_fixture(recorder=original.recorder)
            changed = candidate.detached
            if mode == "intent_header":
                changed.intent["issuedAtEpochNs"] += 1
                changed.resign_intent()
            elif mode == "relay_header":
                changed.relay["issuedAtEpochNs"] += 1
                changed.resign_relay()
            elif mode == "history":
                changed.history["now_monotonic_ns"] += 1
                changed.history_bytes = oracle.wire(changed.history)
                changed.rebuild_intent()
            elif mode == "configuration":
                changed.action.configuration.payload["roles"]["planner-writer"]["maximumInternalAgeNs"] += 1
                changed.refresh_configuration()
                candidate.expected, candidate.fixture = changed.plan, changed.plan.semantic
            else:
                changed.action.arguments["planned_at_epoch_ns"] += 1
                changed.rebuild()
            old, new = request_oracle.expected_row(original.detached), request_oracle.expected_row(changed)
            self.assertEqual((old["intent_envelope_id"], old["relay_envelope_id"]),
                             (new["intent_envelope_id"], new["relay_envelope_id"]))
            self.assertNotEqual(changed.originals(), original.detached.originals())
            authenticated = []
            verify = composition.commitment._verify_commitments_on_work

            def observe(**arguments):
                received = verify(**arguments)
                authenticated.append(received.metrics.signature_verifications)
                return received

            previous_statements = len(original.recorder.statements)
            with self.subTest(mode=mode), self.revocation_owner_scope(candidate), \
                    patch.object(composition.commitment, "_verify_commitments_on_work", side_effect=observe), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError): self.run_revocation_composition_components(candidate)
            self.assertEqual(authenticated, [2])
            self.assertEqual(replay.call_count, 0)
            self.assertEqual(candidate.connected, [candidate.source.configuration.persistence_dsn])
            self.assertTrue(any(sql == request_oracle.SELECT
                for sql, _ in original.recorder.statements[previous_statements:]))
            self.assertFalse(any(sql.startswith(("INSERT ", "UPDATE ", "DELETE "))
                for sql, _ in original.recorder.statements[previous_statements:]))
            self.assertEqual(original.recorder.snapshot(), before)

    def test_writer_request_first_attachment_requires_the_actual_original_stored_planned_time(self):
        from serverware import authority_revocation_retention as retention
        import test_authority_revocation_plan as oracle
        import test_authority_revocation_writer_request as request_oracle

        for retimed in (False, True):
            legacy = self.revocation_composition_fixture()
            # Obtain the five legacy rows through the real existing public
            # atomic owner, not by treating an independently seeded row as
            # admitted custody. The opt-in sixth/seventh sets stay absent.
            with self.revocation_owner_scope(legacy): self.run_revocation_action_components(legacy)
            self.assertEqual(legacy.recorder.requests, {})
            self.assertEqual(legacy.recorder.acknowledgments, {})
            before = legacy.recorder.snapshot()
            attached = self.revocation_composition_fixture(recorder=legacy.recorder)
            if retimed:
                attached.detached.action.arguments["planned_at_epoch_ns"] += 1
                attached.detached.rebuild()
            expected = self.revocation_composition_work(attached, retry=True, request_existing=False, ack_existing=False)
            with self.subTest(retimed=retimed), self.revocation_owner_scope(attached), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                if retimed:
                    with self.assertRaises(ValueError): self.run_revocation_composition_components(attached)
                else:
                    receipt, _, _ = self.run_revocation_composition_components(attached)
                    self.assertEqual(receipt["plannedAtEpochNs"], legacy.source.arguments["planned_at_epoch_ns"])
            self.assertEqual((replay.call_count, proof.call_count), (2, 2))
            self.assertEqual(attached.recorder.snapshot()[:5], before[:5])
            if retimed:
                self.assertEqual(attached.recorder.snapshot(), before)
                self.assertEqual((attached.recorder.rollbacks, attached.recorder.releases), (2, 6))
            else:
                self.assert_revocation_composition_rows(attached)
                self.assertEqual(oracle.units(attached.arguments["work"].metrics), expected["total"])
                self.assertEqual((attached.recorder.rollbacks, attached.recorder.releases), (0, 8))
            request_inserts = [sql for sql, _ in attached.recorder.statements if sql == request_oracle.INSERT]
            self.assertEqual(len(request_inserts), 0 if retimed else 1)

    def test_writer_request_late_readback_failure_restores_six_sets_even_if_caught_inside_outer_scope(self):
        from serverware import authority_revocation_persistence as persistence
        from serverware import authority_revocation_retention as retention
        from serverware import db
        import test_authority_revocation_writer_request as request_oracle

        for caught_inside in (False, True):
            fixture, caught, returned = self.revocation_composition_fixture(), [], []
            fixture.recorder.missing_request_readback = True
            before = fixture.recorder.snapshot()
            runner = persistence._run_on_configuration

            def run(configuration, operation, arguments, expectations, work):
                self.assertIs(operation, persistence._persist_and_reserve_request_on_connection)

                def catch(**supplied):
                    try: operation(**supplied)
                    except db.MetadataStoreError as error: caught.append(error)
                    else: self.fail("missing request readback unexpectedly succeeded")
                    self.assertEqual(fixture.recorder.snapshot(), before)
                    self.assertEqual(fixture.write.info.transaction_status, 2)
                    self.assertIs(supplied["connection"].in_transaction, True)
                    # No receipt/ACK escapes this negative-only catch. The
                    # actual runner still owns admission and outer cleanup.

                return runner(configuration, catch if caught_inside else operation,
                    arguments, expectations, work)

            with self.subTest(caught_inside=caught_inside), self.revocation_owner_scope(fixture), \
                    patch.object(persistence, "_run_on_configuration", side_effect=run), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                if caught_inside:
                    self.assertIsNone(self.run_revocation_composition_components(fixture))
                else:
                    with self.assertRaises(db.MetadataStoreError):
                        returned.append(self.run_revocation_composition_components(fixture))
            self.assertEqual((replay.call_count, proof.call_count), (2, 2))
            self.assertEqual(len(caught), int(caught_inside))
            self.assertEqual(returned, [])
            self.assertTrue(any(sql == request_oracle.INSERT for sql, _ in fixture.recorder.statements))
            self.assertEqual(fixture.recorder.snapshot(), before)
            self.assertEqual((fixture.recorder.rollbacks, fixture.recorder.releases),
                             (1, 3) if caught_inside else (2, 2))
            self.assertEqual(fixture.write.transactions, 4)
            self.assertEqual(fixture.write.info.transaction_status, 0)
            self.assertIs(fixture.write.closed, True)

    def test_private_original_wire_replays_actual_production_with_external_expectations(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan as replay
        from serverware import authority_revocation_read_write as mixed
        from serverware import authority_revocation_wire as wire

        for separate, audit in ((False, True), (True, False)):
            with self.subTest(separate_signer=separate, include_audit=audit):
                expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture(
                    separate_signer=separate, include_audit=audit)
                with writer_scope:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                self.assert_produced_revocation_plan(expected, fixture, produced)
                supplied = expected.arguments()
                supplied.pop("envelope")
                # This consumer invocation owns its own work, including any
                # earlier admission. It never adopts a producer result meter.
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=3, input_bytes=11, json_nodes=7)
                entering_limits = work.limits
                calls_before = copy.deepcopy(cursor.calls)
                with patch.object(wire, "_decode_envelope", wraps=wire._decode_envelope) as decode, \
                        patch.object(replay, "_verify_signed_revocation_plan_on_work",
                                     wraps=replay._verify_signed_revocation_plan_on_work) as verify, \
                        patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                        patch.object(replay, "verify_signed_revocation_plan",
                                     side_effect=AssertionError("fresh verification allowance")):
                    observed = wire._verify_signed_envelope_on_work(
                        produced.signed.envelope_bytes, work=work, **supplied)
                self.assertEqual((decode.call_count, verify.call_count, proof.call_count), (1, 1, 1))
                self.assertIs(decode.call_args.kwargs["work"], work)
                self.assertIs(verify.call_args.kwargs["work"], work)
                self.assertIs(verify.call_args.kwargs["original_envelope_bytes"], produced.signed.envelope_bytes)
                self.assertIs(work.limits, entering_limits)
                self.assertEqual(observed.envelope_bytes, produced.signed.envelope_bytes)
                self.assertEqual(observed.payload_bytes, produced.signed.payload_bytes)
                self.assertEqual(observed.semantics.mutations, fixture.final_mutations)
                self.assertEqual(observed.semantics.kernel.result, fixture.kernel_expected["result"])
                self.assertEqual((observed.metrics.total_hashes, observed.metrics.total_input_bytes,
                                  observed.metrics.total_json_nodes),
                                 (work.hash_work, work.input_bytes, work.json_nodes))
                self.assertEqual((observed.metrics.planner_signature_attempts,
                                  observed.metrics.assertion_signature_attempts), (1, 1))
                self.assertEqual(cursor.calls, calls_before)

    def test_private_original_wire_does_not_adopt_mutated_producer_graphs_or_currentness(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_wire as wire

        expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
        with writer_scope:
            produced = program._produce_revocation_plan(cursor, **arguments)
        original = produced.signed.envelope_bytes
        # Returned graphs are ordinary mutable observations. The consumer
        # accepts only original bytes and independently supplied expectations.
        produced.signed.payload["typedRequest"]["arguments"]["reason"] = "changed after production"
        produced.signed.envelope["signatureBase64Url"] = "A" * 86
        supplied = expected.arguments()
        supplied.pop("envelope")
        observed = wire._verify_signed_envelope_on_work(original,
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)
        self.assertEqual(observed.envelope_bytes, original)
        self.assertEqual(observed.semantics.mutations, fixture.final_mutations)
        stale = dict(supplied)
        stale["now_epoch_ns"] = expected.deadline_epoch_ns
        with self.assertRaises(ValueError):
            wire._verify_signed_envelope_on_work(original,
                work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **stale)
        with self.assertRaises(ValueError):
            wire._verify_signed_envelope_on_work(produced,
                work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)

    def test_private_produced_original_context_replays_raw_retention_with_independent_expectations(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan as replay
        from serverware import authority_revocation_read_write as mixed
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_semantics as semantics
        import test_authority_revocation_plan as plan_oracle

        for separate, audit in ((False, True), (True, False)):
            with self.subTest(separate_signer=separate, include_audit=audit):
                expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture(
                    separate_signer=separate, include_audit=audit)
                supplied = expected.arguments()
                supplied.pop("envelope")
                self.assertEqual(set(supplied), {
                    "expected_request", "expected_planner_identity", "planner_public_key",
                    "expected_verifier_identity", "verifier_public_key", "expected_capability_id",
                    "expected_planner_transaction_id", "expected_fence", "reserved_at_epoch_ns",
                    "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
                    "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns",
                    "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest"})
                original_context = self.original_revocation_context(expected, fixture)
                with writer_scope:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                self.assert_produced_revocation_plan(expected, fixture, produced)
                raw, context_raw = produced.signed.envelope_bytes, produced.evaluation_context_bytes
                # Caller-facing graph observations cannot alter the original
                # immutable handoff. All nineteen expectations predate it.
                produced.signed.payload["typedRequest"]["arguments"]["reason"] = "mutated observation"
                produced.signed.envelope["signatureBase64Url"] = "A" * 86
                calls_before = copy.deepcopy(cursor.calls)
                clock_reads = cursor.clock_reads
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=3, input_bytes=11, json_nodes=7)
                limits = work.limits
                with patch.object(replay, "_verify_signed_revocation_plan_on_work",
                        wraps=replay._verify_signed_revocation_plan_on_work) as verify, \
                        patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                        patch.object(semantics, "_derive_revocation_effects",
                                     wraps=semantics._derive_revocation_effects) as effects, \
                        patch.object(replay, "verify_signed_revocation_plan",
                                     side_effect=AssertionError("fresh verification allowance")):
                    observed = retention._verify_record_on_work(envelope_bytes=raw,
                        evaluation_context_bytes=context_raw, work=work, **supplied)
                self.assertEqual((verify.call_count, proof.call_count, effects.call_count), (1, 1, 1))
                self.assertIs(verify.call_args.kwargs["work"], work)
                self.assertIs(verify.call_args.kwargs["original_envelope_bytes"], raw)
                self.assertIs(observed.envelope_bytes, raw)
                self.assertIs(observed.context_bytes, context_raw)
                self.assertEqual(observed.context, original_context)
                self.assertEqual(context_raw, plan_oracle.wire(original_context))
                self.assertEqual(observed.payload_bytes, produced.signed.payload_bytes)
                self.assertEqual(observed.verification.semantics.mutations, fixture.final_mutations)
                self.assertEqual(observed.verification.semantics.kernel.result, fixture.kernel_expected["result"])
                self.assertEqual(observed.metrics, work.metrics)
                self.assertIs(work.limits, limits)
                self.assertEqual((cursor.calls, cursor.clock_reads), (calls_before, clock_reads))
                wrong = dict(supplied)
                wrong["expected_fence"] += 1
                with patch.object(replay, "_verify_signed_revocation_plan_on_work",
                        wraps=replay._verify_signed_revocation_plan_on_work) as verify:
                    with self.assertRaises(retention.RevocationRetentionError):
                        retention._verify_record_on_work(envelope_bytes=raw,
                            evaluation_context_bytes=context_raw,
                            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **wrong)
                self.assertEqual(verify.call_count, 0)
                with self.assertRaises(retention.RevocationRetentionError):
                    retention._verify_record_on_work(envelope_bytes=produced,
                        evaluation_context_bytes=context_raw,
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)

    def test_private_plan_production_replays_real_acquisition_packaging_and_signed_verification(self):
        from serverware import authority_revocation_plan as replay
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_revocation_proof_bundle as retained
        from serverware import authority_revocation_read_write as mixed
        from serverware import authority_revocation_retention as retention
        from serverware import authority_revocation_semantics as semantics
        from serverware import authority_transition_webauthn as candidate
        from serverware import authority_webauthn_assertion as assertion

        for separate, audit in ((False, True), (True, False)):
            with self.subTest(separate_signer=separate, include_audit=audit):
                expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture(
                    separate_signer=separate, include_audit=audit)
                work = arguments["query_work"]
                entering_limits = work.limits
                with writer_scope as writer, \
                        patch.object(program, "_acquire_revocation_transition",
                                     wraps=program._acquire_revocation_transition) as acquisition, \
                        patch.object(candidate, "_revocation_query_program",
                                     wraps=candidate._revocation_query_program) as generation, \
                        patch.object(assertion, "_verify_revoke_assertion_evidence",
                                     wraps=assertion._verify_revoke_assertion_evidence) as receipt, \
                        patch.object(semantics, "_derive_revocation_effects",
                                     wraps=semantics._derive_revocation_effects) as effects, \
                        patch.object(retained, "_derive_on_work", wraps=retained._derive_on_work) as packaging, \
                        patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                        patch.object(retention, "_encode_context_on_work",
                                     wraps=retention._encode_context_on_work) as context_encoding, \
                        patch.object(production, "_build_and_sign", wraps=production._build_and_sign) as build, \
                        patch.object(replay, "verify_signed_revocation_plan",
                                     wraps=replay.verify_signed_revocation_plan) as public_replay:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                self.assertEqual((cursor.clock_reads, acquisition.call_count, generation.call_count,
                    receipt.call_count, effects.call_count, writer.call_count, packaging.call_count,
                    proof.call_count, context_encoding.call_count, build.call_count, public_replay.call_count),
                    (1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 0))
                # Acquisition generates once at the original cutoff; genuine
                # raw packaging replays that source recipe once more.
                self.assertIs(acquisition.call_args.kwargs["query_work"], work)
                self.assertIs(receipt.call_args.kwargs["work"].shared, work)
                for actual in (effects, packaging, context_encoding, build):
                    self.assertIs(actual.call_args.kwargs["work"], work)
                self.assertIs(context_encoding.call_args.args[0], build.call_args.kwargs["context"])
                self.assertEqual(context_encoding.call_args.kwargs["database_now"], fixture.database_now)
                self.assertIs(writer.call_args.kwargs["acquisition_budget"].engine.work, work)
                self.assertEqual(produced.metrics, work.metrics)
                self.assertIs(work.limits, entering_limits)
                self.assertGreater(produced.metrics.hash_work, produced.signed.metrics.hash_work)
                self.assertGreater(produced.metrics.input_bytes, produced.signed.metrics.input_bytes)
                self.assertGreater(produced.metrics.json_nodes, produced.signed.metrics.json_nodes)
                self.assert_produced_revocation_plan(expected, fixture, produced)

                # A separate real consumer invocation uses the original pins,
                # roots and cutoff, never values adopted from the signed plan.
                supplied = expected.arguments()
                supplied["envelope"] = produced.signed.envelope
                calls_before = copy.deepcopy(cursor.calls)
                with patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                        patch.object(semantics, "_derive_revocation_effects",
                                     wraps=semantics._derive_revocation_effects) as effects:
                    observed = replay.verify_signed_revocation_plan(**supplied)
                self.assertEqual((proof.call_count, effects.call_count), (1, 1))
                self.assertEqual(observed.payload_bytes, produced.signed.payload_bytes)
                self.assertEqual(observed.envelope_bytes, produced.signed.envelope_bytes)
                self.assertEqual(observed.semantics.mutations, fixture.final_mutations)
                self.assertEqual(observed.semantics.kernel.result, fixture.kernel_expected["result"])
                self.assertEqual((observed.metrics.planner_signature_attempts,
                                  observed.metrics.assertion_signature_attempts), (1, 1))
                self.assertEqual(cursor.calls, calls_before)

    def test_private_plan_independent_root_mismatch_denies_before_packaging_or_signing(self):
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_revocation_proof_bundle as retained

        for vector in ("businessBeforeRoots", "authorizationBeforeRoots", "indexBeforeHeads"):
            with self.subTest(vector=vector):
                _, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
                arguments["context"]["expectedBefore"][vector][0]["rootDigest"] = "sha256:" + "0" * 64
                with writer_scope, \
                        patch.object(retained, "_derive_on_work", wraps=retained._derive_on_work) as packaging, \
                        patch.object(production, "_build_and_sign", wraps=production._build_and_sign) as build:
                    with self.assertRaises(self.planner.AuthorityPlannerError):
                        program._produce_revocation_plan(cursor, **arguments)
                self.assertEqual((packaging.call_count, build.call_count), (0, 0))
                self.assertEqual(cursor.clock_reads, int(vector == "indexBeforeHeads"))
                if vector == "indexBeforeHeads":
                    # Counted roots are independently compared only after the
                    # genuine acquisition, including its actual write proofs.
                    self.assertGreater(len(cursor.write_cursor.calls), 0)

    def test_private_plan_bad_context_request_and_receipt_never_reach_sql_or_builder(self):
        from serverware import authority_revocation_plan_production as production

        for changed in ("extra", "fence", "deadline", "reservation", "transaction", "request", "signature"):
            with self.subTest(changed=changed):
                _, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
                context = arguments["context"]
                if changed == "extra":
                    context["authorityToken"] = True
                elif changed == "fence":
                    context["expectedFence"] = True
                elif changed == "deadline":
                    context["deadlineMonotonicNs"] = context["nowMonotonicNs"]
                elif changed == "reservation":
                    context["reservedAtEpochNs"] = context["nowEpochNs"] + context["maximumClockSkewNs"] + 1
                elif changed == "transaction":
                    context["expectedPlannerTransactionId"] = "sha256:" + "0" * 64
                elif changed == "request":
                    arguments["request"]["arguments"]["record_id"] = "different-request"
                else:
                    arguments["evidence"]["verifierSignatureBase64url"] = "A" * 86
                    arguments["evidence"]["verifierSignatureDigest"] = "sha256:" + hashlib.sha256(bytes(64)).hexdigest()
                with writer_scope as writer, \
                        patch.object(production, "_build_and_sign", wraps=production._build_and_sign) as build:
                    with self.assertRaises(self.planner.AuthorityPlannerError):
                        program._produce_revocation_plan(cursor, **arguments)
                self.assertEqual((cursor.calls, cursor.clock_reads, writer.call_count, build.call_count),
                                 ([], 0, 0, 0))

    def test_private_plan_joint_capture_keeps_original_context_through_clock_callback(self):
        from serverware import authority_revocation_plan as replay

        expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()

        def change_caller():
            arguments["request"]["arguments"]["record_id"] = "changed-after-capture"
            arguments["manifest"][0]["table"] = "foreign_table"
            arguments["evidence"].clear()
            context = arguments["context"]
            context["expectedPlannerIdentity"].clear()
            context["expectedVerifierIdentity"].clear()
            context["expectedBefore"]["indexBeforeHeads"].clear()
            context["expectedFence"] += 1
            context["deadlineEpochNs"] = 1

        cursor.on_clock = change_caller
        with writer_scope:
            produced = program._produce_revocation_plan(cursor, **arguments)
        self.assertEqual(cursor.clock_reads, 1)
        self.assert_produced_revocation_plan(expected, fixture, produced)
        supplied = expected.arguments()
        supplied["envelope"] = produced.signed.envelope
        observed = replay.verify_signed_revocation_plan(**supplied)
        self.assertEqual(observed.semantics.mutations, fixture.final_mutations)

    def test_private_plan_output_does_not_replace_consumer_pins_roots_or_original_cutoff(self):
        from datetime import timedelta
        from serverware import authority_revocation_plan as replay

        expected, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
        with writer_scope:
            produced = program._produce_revocation_plan(cursor, **arguments)
        for changed in ("planner_key", "planner_identity", "verifier_identity", "fence", "roots", "cutoff"):
            with self.subTest(changed=changed):
                supplied = expected.arguments()
                supplied["envelope"] = produced.signed.envelope
                if changed == "planner_key":
                    supplied["planner_public_key"] = expected.other_key.public_key()
                elif changed in {"planner_identity", "verifier_identity"}:
                    supplied["expected_" + changed]["measurementDigest"] = "sha256:" + "0" * 64
                elif changed == "fence":
                    supplied["expected_fence"] += 1
                elif changed == "roots":
                    supplied["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = "sha256:" + "0" * 64
                else:
                    supplied["database_now"] += timedelta(microseconds=1)
                with self.assertRaises(replay.RevocationPlanError):
                    replay.verify_signed_revocation_plan(**supplied)

    def test_private_plan_prior_work_remains_spent_across_acquisition_packaging_and_signing(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_revocation_proof_bundle as retained

        observations = []
        # Explicit synthetic prior accounting supplements the actual chained
        # phases; it is not represented as proof of some earlier operation.
        for prior in ((0, 0, 0), (7, 101, 13)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture(work=work)
            before = work.metrics
            seen = []
            real_acquire, real_package, real_build = (program._acquire_revocation_transition,
                retained._derive_on_work, production._build_and_sign)

            def acquire(*args, **kwargs):
                self.assertIs(kwargs["query_work"], work)
                seen.append(work.metrics)
                return real_acquire(*args, **kwargs)

            def package(**kwargs):
                self.assertIs(kwargs["work"], work)
                seen.append(work.metrics)
                return real_package(**kwargs)

            def build(**kwargs):
                self.assertIs(kwargs["work"], work)
                seen.append(work.metrics)
                return real_build(**kwargs)

            with self.subTest(prior=prior), writer_scope, \
                    patch.object(program, "_acquire_revocation_transition", side_effect=acquire), \
                    patch.object(retained, "_derive_on_work", side_effect=package), \
                    patch.object(production, "_build_and_sign", side_effect=build):
                produced = program._produce_revocation_plan(cursor, **arguments)
            self.assertEqual(len(seen), 3)
            for first, second in zip((before, *seen), (*seen, produced.metrics)):
                self.assertGreater(second.hash_work, first.hash_work)
                self.assertGreater(second.input_bytes, first.input_bytes)
                self.assertGreater(second.json_nodes, first.json_nodes)
            self.assert_produced_revocation_plan(expected, fixture, produced)
            self.assertEqual(produced.metrics, work.metrics)
            observations.append(produced)
        plain, prior = observations
        self.assertEqual(prior.signed.envelope_bytes, plain.signed.envelope_bytes)
        self.assertEqual(prior.evaluation_context_bytes, plain.evaluation_context_bytes)
        self.assertEqual(prior.signed.metrics, plain.signed.metrics)
        self.assertEqual((prior.metrics.hash_work - plain.metrics.hash_work,
                          prior.metrics.input_bytes - plain.metrics.input_bytes,
                          prior.metrics.json_nodes - plain.metrics.json_nodes), (7, 101, 13))

    def test_private_plan_original_context_cost_and_short_budget_deny_before_signing(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_revocation_retention as retention
        from serverware import authority_transition_core as core
        import test_authority_revocation_plan as plan_oracle
        import test_webauthn_revocation_work as kernel_oracle

        for deficient in (None, "input_bytes", "json_nodes"):
            expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
            expected_context = self.original_revocation_context(expected, fixture)
            length, nodes = len(plan_oracle.wire(expected_context)), kernel_oracle.nodes(expected_context)
            work = arguments["query_work"]
            limits = work.limits
            original_context, original_encode = retention._encode_context_on_work, core.canonical_bytes
            phases, encodings = [], []

            def encode_context(context, **kwargs):
                self.assertIs(kwargs["work"], work)
                self.assertEqual(kwargs["database_now"], fixture.database_now)
                self.assertEqual(cursor.clock_reads, 1)
                # An explicit prior synthetic debit leaves one unit less
                # than the real context's two passes. It never changes the
                # ceiling or substitutes for acquisition/proof work.
                if deficient is not None:
                    remaining = (work.limits.max_input_bytes - work.input_bytes,
                                 work.limits.max_json_nodes - work.json_nodes)
                    self.assertGreaterEqual(remaining[0], 2 * length)
                    self.assertGreaterEqual(remaining[1], 2 * nodes)
                    work.charge(input_bytes=(remaining[0] - (2 * length - 1)
                                             if deficient == "input_bytes" else 0),
                                json_nodes=(remaining[1] - (2 * nodes - 1)
                                            if deficient == "json_nodes" else 0))
                before = work.metrics
                try:
                    return original_context(context, **kwargs)
                finally:
                    phases.append((work.hash_work - before.hash_work,
                                   work.input_bytes - before.input_bytes,
                                   work.json_nodes - before.json_nodes))

            def encode(value):
                if type(value) is dict and value.get("schema") == expected_context["schema"]:
                    encodings.append(copy.deepcopy(value))
                return original_encode(value)

            with self.subTest(deficient=deficient), writer_scope, \
                    patch.object(retention, "_encode_context_on_work", side_effect=encode_context), \
                    patch.object(core, "canonical_bytes", side_effect=encode), \
                    patch.object(production, "_build_and_sign", wraps=production._build_and_sign) as build, \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                if deficient is None:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                else:
                    with self.assertRaises(self.planner.AuthorityPlannerError) as raised:
                        program._produce_revocation_plan(cursor, **arguments)
                    self.assertIsInstance(raised.exception.__cause__, retention.RevocationRetentionError)
                    self.assertIsInstance(raised.exception.__cause__.__cause__, accounting.QueryReadWorkError)
            self.assertIs(work.limits, limits)
            self.assertEqual(cursor.clock_reads, 1)
            if deficient is None:
                self.assertEqual(phases, [(0, 2 * length, 2 * nodes)])
                self.assertEqual(encodings, [expected_context])
                self.assertEqual((build.call_count, sign.call_count), (1, 1))
                self.assert_produced_revocation_plan(expected, fixture, produced)
            else:
                # Genuine measurement remains spent; the subsequent full
                # encoder reservation fails atomically before any buffer/sign.
                self.assertEqual(phases, [(0, length, nodes)])
                self.assertEqual((encodings, build.call_count, sign.call_count), ([], 0, 0))

    def test_private_plan_exact_final_wire_reservation_and_one_less_deny_before_signing(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_transition_core as core
        import test_authority_revocation_plan as plan_oracle
        import test_webauthn_revocation_work as kernel_oracle

        domain = "serverware.signedPolicyAuthorityMeasuredPlan/v4"
        fields = ("hash_work", "input_bytes", "json_nodes")
        for deficient in (None, *fields):
            expected, fixture, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
            work = arguments["query_work"]
            entering_limits = work.limits
            original_measure, original_encode = work.measure, core.canonical_bytes
            reserved, encodings = [], []

            def measure(value, **kwargs):
                measured = original_measure(value, **kwargs)
                if type(value) is dict and value.get("schema") == domain:
                    self.assertEqual(reserved, [])
                    payload_size = len(plan_oracle.wire(value["payload"]))
                    envelope_size = len(plan_oracle.wire(value))
                    payload_nodes = kernel_oracle.nodes(value["payload"])
                    envelope_nodes = kernel_oracle.nodes(value)
                    # Both measurement walks have genuinely completed. Pin
                    # the remaining three real encodes, post-sign payload
                    # measure/comparison, signature64/base64 transport and
                    # actual domain frame/message preparation.
                    # Spend excess allowance synthetically; no counter reset,
                    # output metric or successful helper substitutes for work.
                    pending = (1, 5 * payload_size + envelope_size + 2 * 64 + 4 * 88 + 86
                        + 2 * len(domain) + 9 + payload_size + 2 * 71,
                        3 * payload_nodes + envelope_nodes + 4)
                    remaining = (work.limits.max_hashes - work.hash_work,
                        work.limits.max_input_bytes - work.input_bytes,
                        work.limits.max_json_nodes - work.json_nodes)
                    allowed = tuple(amount - int(name == deficient) for name, amount in zip(fields, pending))
                    self.assertTrue(all(available >= required for available, required in zip(remaining, pending)))
                    work.charge(hashes=remaining[0] - allowed[0],
                        input_bytes=remaining[1] - allowed[1], json_nodes=remaining[2] - allowed[2])
                    reserved.append((pending, work.metrics))
                return measured

            def encode(value):
                if type(value) is dict and value.get("schema") in {
                        domain, "serverware.policyAuthorityPlannerResponse/v4"}:
                    encodings.append(value["schema"])
                return original_encode(value)

            with self.subTest(deficient=deficient), writer_scope, \
                    patch.object(work, "measure", side_effect=measure), \
                    patch.object(core, "canonical_bytes", side_effect=encode), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                if deficient is None:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                else:
                    with self.assertRaises(self.planner.AuthorityPlannerError) as raised:
                        program._produce_revocation_plan(cursor, **arguments)
                    self.assertIsInstance(raised.exception.__cause__, accounting.QueryReadWorkError)
            self.assertEqual(len(reserved), 1)
            self.assertEqual(cursor.clock_reads, 1)
            self.assertIs(work.limits, entering_limits)
            if deficient is None:
                self.assertEqual((sign.call_count, encodings), (1,
                    ["serverware.policyAuthorityPlannerResponse/v4",
                     "serverware.policyAuthorityPlannerResponse/v4", domain]))
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                    (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes))
                self.assert_produced_revocation_plan(expected, fixture, produced)
            else:
                self.assertEqual((sign.call_count, encodings), (0, []))
                spent = reserved[0][1]
                self.assertGreaterEqual(work.hash_work, spent.hash_work)
                self.assertGreaterEqual(work.input_bytes, spent.input_bytes)
                self.assertGreaterEqual(work.json_nodes, spent.json_nodes)

    def test_private_plan_actual_paired_key_denial_and_no_result_token_entrypoint(self):
        from cryptography.exceptions import InvalidSignature
        from serverware import authority_revocation_plan as replay
        from serverware import authority_revocation_plan_production as production

        expected, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
        arguments["planner_public_key"] = expected.other_key.public_key()
        with writer_scope, \
                patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
            with self.assertRaises(self.planner.AuthorityPlannerError) as raised:
                program._produce_revocation_plan(cursor, **arguments)
        self.assertEqual((cursor.clock_reads, sign.call_count), (1, 1))
        self.assertIsInstance(raised.exception.__cause__, replay.RevocationPlanError)
        self.assertIsInstance(raised.exception.__cause__.__cause__, InvalidSignature)
        self.assertGreater(arguments["query_work"].hash_work, 0)
        for name in ("planner_private_key", "planner_public_key", "verifier_public_key", "context", "query_work"):
            with self.subTest(name=name):
                _, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
                arguments[name] = types.SimpleNamespace(verified=True)
                with writer_scope, patch.object(production, "_sign_and_verify",
                        wraps=production._sign_and_verify) as sign:
                    with self.assertRaises(self.planner.AuthorityPlannerError):
                        program._produce_revocation_plan(cursor, **arguments)
                self.assertEqual((cursor.calls, sign.call_count), ([], 0))
        _, _, cursor, program, arguments, writer_scope = self.revocation_plan_fixture()
        with writer_scope:
            with self.assertRaises(TypeError):
                program._produce_revocation_plan(cursor, **arguments, successful_result={})
        self.assertEqual(cursor.calls, [])

    def test_private_revocation_producer_runs_real_receipt_reads_effects_and_write_proofs_on_one_ledger(self):
        from serverware import authority_webauthn_assertion as assertion
        from serverware import authority_revocation_semantics as semantics
        from serverware import authority_index_trace as markers
        from serverware import authority_index_reader as reader

        for separate, audit in ((False, True), (True, False)):
            with self.subTest(separate_signer=separate, include_audit=audit):
                fixture, cursor, program, arguments, writer_scope = self.revocation_producer_fixture(
                    separate_signer=separate, include_audit=audit)
                contexts = []
                original = reader._ReadAcquisitionBudget.__init__

                def initialize(instance, *args, **kwargs):
                    contexts.append(instance)
                    return original(instance, *args, **kwargs)

                with writer_scope as write, \
                        patch.object(reader._ReadAcquisitionBudget, "__init__", new=initialize), \
                        patch.object(assertion, "_verify_revoke_assertion_evidence",
                                     wraps=assertion._verify_revoke_assertion_evidence) as receipt, \
                        patch.object(self.planner, "_read_root_set", wraps=self.planner._read_root_set) as roots, \
                        patch.object(semantics, "_derive_revocation_effects",
                                     wraps=semantics._derive_revocation_effects) as effects:
                    result = program._acquire_revocation_transition(cursor, **arguments)
                self.assertEqual((len(contexts), cursor.clock_reads, receipt.call_count,
                                  effects.call_count, write.call_count), (1, 1, 1, 1, 1))
                self.assert_revocation_read(fixture, result.selected_rows, result.state)
                self.assertEqual(result.request, fixture.request)
                self.assertEqual(result.mutations, fixture.final_mutations)
                self.assertEqual(result.work_units, fixture.work_units)
                self.assertEqual(result.kernel.result, fixture.kernel_expected["result"])
                physical = contexts[0]
                self.assertEqual(roots.call_count, 1)
                self.assertIs(roots.call_args.args[0], cursor)
                self.assertIs(roots.call_args.kwargs["trace"], physical.trace)
                self.assertIs(roots.call_args.kwargs["work"], arguments["query_work"])
                expected_root_sql = [(cursor.ROOT_SELECT, (name,)) for name in cursor.root_order]
                self.assertEqual(cursor.root_calls, expected_root_sql)
                self.assertEqual(cursor.calls[:len(expected_root_sql)], expected_root_sql)
                self.assertEqual(cursor.calls[len(expected_root_sql)],
                    ("SELECT pg_catalog.clock_timestamp() AS database_now", None))
                self.assertEqual([(entry["access"], entry["table"], entry["key"])
                                  for entry in result.trace[:len(expected_root_sql)]],
                    [("read", "policy_authority_authenticated_table_roots", {"tableName": name})
                     for name in cursor.root_order])
                aggregate = "policy_authority_bounded_aggregate_states"
                self.assertEqual(sum(entry["table"] == "policy_authority_authenticated_table_roots"
                    and entry["key"] == {"tableName": aggregate} for entry in result.trace), 1)
                self.assertIs(physical.work, arguments["query_work"])
                self.assertIs(effects.call_args.kwargs["work"], physical.work)
                self.assertIs(write.call_args.kwargs["trace"], physical.trace)
                self.assertIs(write.call_args.kwargs["acquisition_budget"].shared_acquisition, physical)
                self.assertEqual(physical.sql_reads, len(cursor.complete.calls) + len(cursor.write_cursor.calls))
                self.assertEqual(result.write_evidence.metrics.cumulative_sql_reads, physical.sql_reads)
                self.assertFalse(physical.failed or physical.active)
                before = tuple((name, info["revision_before"], info["before"].root)
                    for name, info in sorted(fixture.read_write.indexes.items()))
                after = tuple((name, info["revision_before"] + info["revision_delta"], info["after"].root)
                    for name, info in sorted(fixture.read_write.indexes.items()))
                self.assertEqual(tuple((head.index_id, head.index_revision, head.index_root)
                    for head in result.write_evidence.result.before_heads), before)
                self.assertEqual(tuple((head.index_id, head.index_revision, head.index_root)
                    for head in result.write_evidence.result.after_heads), after)
                self.assertEqual(result.write_evidence.result.primary.business_after_roots,
                    tuple(fixture.read_write.after_trees[item.table].root
                          for item in fixture.read_write.read.contracts if item.root_class == "business"))
                writer_markers = [entry for entry in result.trace if type(entry["key"]) is dict
                    and entry["key"].get("profile") == markers.MUTATION_READ_PROFILE]
                self.assertEqual(len(writer_markers), len(cursor.write_cursor.calls))
                suffix = result.trace[-len(result.mutations):]
                self.assertTrue(all(entry["access"] == "write" for entry in suffix))
                self.assertEqual([(entry["table"], entry["key"]) for entry in suffix],
                                 [(item["table"], item["key"]) for item in result.mutations])

    def test_private_revocation_root_rows_deny_missing_malformed_and_drift_before_clock(self):
        from serverware import authority_index_reader as reader
        from serverware import authority_revocation_plan_contract as plan_shape
        from serverware import authority_revocation_semantics as semantics

        for vector in ("businessBeforeRoots", "authorizationBeforeRoots"):
            for changed in ("missing", "extra", "missing_field", "boolean", "float", "string",
                            "digest_shape", "overflow", "digest", "revision", "count"):
                with self.subTest(vector=vector, changed=changed):
                    fixture, cursor, program, arguments, writer_scope = self.revocation_producer_fixture()
                    target = min(root["table"] for root in fixture.expected_before[vector])
                    row = cursor.root_rows[target]
                    if changed == "missing":
                        del cursor.root_rows[target]
                    elif changed == "extra":
                        row["admitted"] = True
                    elif changed == "missing_field":
                        del row["leaf_count"]
                    elif changed == "boolean":
                        row["root_revision"] = True
                    elif changed == "float":
                        row["leaf_count"] = float(row["leaf_count"])
                    elif changed == "string":
                        row["root_revision"] = str(row["root_revision"])
                    elif changed == "digest_shape":
                        row["root_digest"] = "sha256:" + "G" * 64
                    elif changed == "overflow":
                        row["root_revision"] = 2**63
                    elif changed == "digest":
                        row["root_digest"] = "sha256:" + "0" * 64
                    elif changed == "revision":
                        row["root_revision"] += 1
                    else:
                        row["leaf_count"] += 1
                    physical = []
                    original = reader._ReadAcquisitionBudget.__init__

                    def initialize(instance, *args, **kwargs):
                        physical.append(instance)
                        return original(instance, *args, **kwargs)

                    with writer_scope as write, \
                            patch.object(reader._ReadAcquisitionBudget, "__init__", new=initialize), \
                            patch.object(semantics, "_derive_revocation_effects",
                                         wraps=semantics._derive_revocation_effects) as effects:
                        expected_error = (self.planner.AuthorityPlannerError
                            if changed in {"missing", "extra", "missing_field"}
                            else semantics.RevocationSemanticsError
                            if changed in {"digest", "revision", "count"}
                            else plan_shape.RevocationPlanContractError)
                        with self.assertRaises(expected_error):
                            program._acquire_revocation_transition(cursor, **arguments)
                    self.assertEqual((cursor.clock_reads, effects.call_count, write.call_count), (0, 0, 0))
                    self.assertEqual((cursor.complete.calls, cursor.primary.calls, cursor.write_cursor.calls),
                                     ([], [], []))
                    self.assertGreater(len(cursor.root_calls), 0)
                    self.assertEqual(len(physical), 1)
                    self.assertTrue(physical[0].failed)

    def test_private_revocation_root_capture_survives_later_row_and_caller_mutation(self):
        fixture, cursor, program, arguments, writer_scope = self.revocation_producer_fixture()
        cursor.return_root_aliases = True
        first, second = cursor.root_order[:2]
        mutations = []

        def change_later(table):
            if table == second:
                # The first exact SQL row has already been admitted and
                # copied. Later callbacks cannot rewrite that observation or
                # the independently captured caller expectations.
                cursor.root_rows[first]["root_digest"] = "sha256:" + "0" * 64
                arguments["business_before_roots"].clear()
                arguments["authorization_before_roots"].clear()
                arguments["request"]["arguments"]["record_id"] = "changed-after-root-read"
                arguments["manifest"][0]["table"] = "foreign_table"
                mutations.append(table)

        cursor.on_root = change_later
        with writer_scope:
            result = program._acquire_revocation_transition(cursor, **arguments)
        self.assertEqual(mutations, [second])
        self.assertEqual(cursor.clock_reads, 1)
        self.assertEqual(result.request, fixture.request)
        self.assertEqual(result.mutations, fixture.final_mutations)
        self.assert_revocation_read(fixture, result.selected_rows, result.state)

    def test_actual_root_reader_public_parity_and_exact_remaining_work(self):
        from serverware import authority_query_read_work as accounting
        import test_authority_revocation_plan as plan_oracle
        import test_webauthn_revocation_work as kernel_oracle

        fixture, _, _, arguments = self.revocation_reader_fixture()
        business, authorization = (tuple(sorted(copy.deepcopy(fixture.expected_before[field]),
            key=lambda root: root["table"])) for field in ("businessBeforeRoots", "authorizationBeforeRoots"))
        domain = "serverware.policyAuthorityRootSet/v1"
        expected_result = business, authorization, plan_oracle.framed(domain, plan_oracle.wire(business))
        # QueryRead copy has its own real profile: one separator byte per
        # nonempty container and two extra encodes of each numeric scalar.
        copied = (0, sum(len(plan_oracle.wire(root)) + 1
            + 2 * len(plan_oracle.wire(root["rootRevision"]))
            + 2 * len(plan_oracle.wire(root["leafCount"])) for root in (*business, *authorization)),
            sum(kernel_oracle.nodes(root) + 4 for root in (*business, *authorization)))
        expected_work = plan_oracle.add(copied, plan_oracle.json_digest_cost(domain, business))
        legacy_cursor = _RevocationReadCursor(fixture)
        legacy = self.planner._read_root_set(legacy_cursor, operation=fixture.request["operation"],
            manifest=arguments["manifest"], trace=self.planner.PlannerTrace(operation=fixture.request["operation"]))
        self.assertEqual(legacy, expected_result)
        for prior, deficient in (((0, 0, 0), None), ((7, 101, 13), None),
                                  ((7, 101, 13), 0), ((7, 101, 13), 1), ((7, 101, 13), 2)):
            maximum = list(plan_oracle.add(prior, expected_work))
            if deficient is not None:
                maximum[deficient] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*maximum))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            cursor = _RevocationReadCursor(fixture)
            trace = self.planner.PlannerTrace(operation=fixture.request["operation"], _complete_queries=True)
            with self.subTest(prior=prior, deficient=deficient), \
                    patch.object(accounting._ValidationWork, "__init__",
                                 side_effect=AssertionError("fresh root allowance")):
                if deficient is None:
                    actual = self.planner._read_root_set(cursor, operation=fixture.request["operation"],
                        manifest=arguments["manifest"], trace=trace, work=work)
                    self.assertEqual(actual, expected_result)
                    self.assertEqual(plan_oracle.units(work.metrics), plan_oracle.add(prior, expected_work))
                else:
                    with self.assertRaises(accounting.QueryReadWorkError):
                        self.planner._read_root_set(cursor, operation=fixture.request["operation"],
                            manifest=arguments["manifest"], trace=trace, work=work)
                    self.assertGreaterEqual(work.hash_work, prior[0])
                    self.assertGreaterEqual(work.input_bytes, prior[1])
                    self.assertGreaterEqual(work.json_nodes, prior[2])
            self.assertIs(work.limits, entering)
            self.assertEqual(cursor.root_calls, legacy_cursor.root_calls)
            self.assertEqual(cursor.clock_reads, 0)
            self.assertLessEqual(work.hash_work, maximum[0])
            self.assertLessEqual(work.input_bytes, maximum[1])
            self.assertLessEqual(work.json_nodes, maximum[2])

    def test_private_root_callbacks_cannot_spend_refund_or_retype_the_shared_meter(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_semantics as semantics

        for phase in ("trace", "execute", "fetch"):
            for changed in ("spend", "refund", "counter_float", "widen", "limit_float"):
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(
                    max_input_bytes=32 * 1024 * 1024))
                _, cursor, program, arguments, writer_scope = self.revocation_producer_fixture(work=work)
                corrupted = []
                original_read = self.planner.PlannerTrace.read

                def corrupt():
                    self.assertEqual(corrupted, [])
                    if changed == "spend":
                        work.charge(input_bytes=1)
                    elif changed == "refund":
                        self.assertGreater(work.input_bytes, 0)
                        work.input_bytes -= 1
                    elif changed == "counter_float":
                        work.json_nodes = float(work.json_nodes)
                    elif changed == "widen":
                        object.__setattr__(work.limits, "max_input_bytes", work.limits.max_input_bytes + 1)
                    else:
                        object.__setattr__(work.limits, "max_hashes", float(work.limits.max_hashes))
                    corrupted.append(work.metrics)

                def traced(owner, table, key):
                    result = original_read(owner, table, key)
                    if phase == "trace" and table == "policy_authority_authenticated_table_roots":
                        corrupt()
                    return result

                def fetched(table, row):
                    corrupt()
                    return row

                if phase == "execute":
                    cursor.on_root = lambda table: corrupt()
                elif phase == "fetch":
                    cursor.root_change = fetched
                with self.subTest(phase=phase, changed=changed), writer_scope as write, \
                        patch.object(self.planner.PlannerTrace, "read", new=traced), \
                        patch.object(semantics, "_derive_revocation_effects",
                                     wraps=semantics._derive_revocation_effects) as effects:
                    expected_error = (accounting.QueryReadWorkError
                        if changed == "limit_float" else ValueError
                        if changed == "counter_float" else self.planner.AuthorityPlannerError)
                    with self.assertRaises(expected_error):
                        program._acquire_revocation_transition(cursor, **arguments)
                self.assertEqual(len(corrupted), 1)
                self.assertEqual((len(cursor.root_calls), cursor.clock_reads, effects.call_count, write.call_count),
                                 (int(phase != "trace"), 0, 0, 0))
                self.assertEqual(work.metrics, corrupted[0])
                # Failure aborts; it does not repair externally corrupted
                # counters or claim that a refunded failed ledger is reusable.
                if changed == "counter_float":
                    self.assertIs(type(work.json_nodes), float)
                if changed == "limit_float":
                    self.assertIs(type(work.limits.max_hashes), float)

    def test_private_revocation_producer_denies_bad_request_or_receipt_before_database_callbacks(self):
        from serverware import authority_webauthn_assertion as assertion
        for changed in ("request", "operation", "signature", "capability"):
            with self.subTest(changed=changed):
                _, cursor, program, arguments, writer_scope = self.revocation_producer_fixture()
                if changed == "request":
                    arguments["request"]["requestDigest"] = "sha256:" + "0" * 64
                elif changed == "operation":
                    arguments["request"]["operationId"] = "sha256:" + "0" * 64
                elif changed == "signature":
                    arguments["evidence"]["verifierSignatureBase64url"] = "A" * 86
                    arguments["evidence"]["verifierSignatureDigest"] = "sha256:" + hashlib.sha256(bytes(64)).hexdigest()
                else:
                    arguments["capability_id"] = "sha256:" + "0" * 64
                with writer_scope as write, \
                        patch.object(assertion, "_verify_revoke_assertion_evidence",
                                     wraps=assertion._verify_revoke_assertion_evidence) as receipt:
                    with self.assertRaises((self.planner.AuthorityPlannerError, ValueError)):
                        program._acquire_revocation_transition(cursor, **arguments)
                self.assertEqual(cursor.calls, [])
                self.assertEqual(write.call_count, 0)
                self.assertEqual(receipt.call_count, int(changed not in {"request", "operation"}))

    def test_private_revocation_producer_keeps_owned_request_through_reads_and_effects(self):
        fixture, cursor, program, arguments, writer_scope = self.revocation_producer_fixture()

        def change_caller():
            arguments["request"]["arguments"]["record_id"] = "changed-after-admission"
            arguments["evidence"]["credentialRecordId"] = "wrong"
            arguments["verifier_identity"].clear()
            arguments["business_before_roots"][0]["rootDigest"] = "sha256:" + "0" * 64

        cursor.on_clock = change_caller
        with writer_scope:
            result = program._acquire_revocation_transition(cursor, **arguments)
        self.assertEqual(result.request, fixture.request)
        self.assertEqual(result.mutations, fixture.final_mutations)
        self.assert_revocation_read(fixture, result.selected_rows, result.state)

    def test_caught_nested_shared_read_during_clock_poisons_outer_before_generation_or_sql(self):
        from serverware import authority_index_reader as reader
        from serverware import authority_transition_webauthn as candidate

        _, cursor, program, arguments = self.revocation_reader_fixture()
        physical = reader._ReadAcquisitionBudget(cursor, arguments["trace"], work=arguments["query_work"])
        caught = []

        def nested():
            try:
                program._read_revocation_inputs_with_acquisition(cursor,
                    **arguments, acquisition=physical)
            except self.planner.AuthorityPlannerError as exc:
                caught.append(exc)
            else:
                self.fail("nested same-ledger read unexpectedly completed")

        cursor.on_clock = nested
        with patch.object(candidate, "_revocation_query_program",
                          wraps=candidate._revocation_query_program) as generation:
            with self.assertRaises(self.planner.AuthorityPlannerError):
                program._read_revocation_inputs_with_acquisition(cursor,
                    **arguments, acquisition=physical)
        self.assertEqual((len(caught), cursor.clock_reads, generation.call_count), (1, 1, 0))
        self.assertEqual(cursor.calls, [("SELECT pg_catalog.clock_timestamp() AS database_now", None)])
        self.assertTrue(physical.failed)
        self.assertFalse(physical.active or physical._read_phase_active)
        spent = arguments["query_work"].metrics
        self.assertGreater(spent.input_bytes, 0)
        with self.assertRaises(self.planner.AuthorityPlannerError):
            program._read_revocation_inputs_with_acquisition(cursor,
                **arguments, acquisition=physical)
        self.assertEqual(arguments["query_work"].metrics, spent)
        self.assertEqual(cursor.clock_reads, 1)

    def test_genuine_write_leaf_failure_poisons_same_read_ledger_without_refund_or_output(self):
        from serverware import authority_index_mutation_reader as writer
        from serverware import authority_index_reader as reader
        from serverware import authority_revocation_semantics as semantics

        _, cursor, program, arguments, writer_scope = self.revocation_producer_fixture()
        contexts, corrupted = [], []
        original = reader._ReadAcquisitionBudget.__init__
        original_limits = arguments["query_work"].limits

        def initialize(instance, *args, **kwargs):
            contexts.append(instance)
            return original(instance, *args, **kwargs)

        def corrupt(kind, index_id, identities, rows):
            if kind == "leaf" and rows and not corrupted:
                rows[0]["primary_row_digest"] = "sha256:" + "0" * 64
                corrupted.append(index_id)
            return rows

        cursor.write_cursor.alter = corrupt
        with writer_scope as write, \
                patch.object(reader._ReadAcquisitionBudget, "__init__", new=initialize), \
                patch.object(semantics, "_derive_revocation_effects",
                             wraps=semantics._derive_revocation_effects) as effects:
            with self.assertRaises(writer.IndexMutationReadError):
                program._acquire_revocation_transition(cursor, **arguments)
        self.assertEqual((len(contexts), len(corrupted), cursor.clock_reads,
                          effects.call_count, write.call_count), (1, 1, 1, 1, 1))
        physical = contexts[0]
        self.assertTrue(physical.failed)
        self.assertFalse(physical.active or physical._read_phase_active)
        self.assertGreater(physical.sql_reads, len(cursor.complete.calls))
        self.assertIs(write.call_args.kwargs["acquisition_budget"].shared_acquisition, physical)
        self.assertTrue(write.call_args.kwargs["acquisition_budget"].failed)
        self.assertEqual(arguments["query_work"].limits, original_limits)
        spent = arguments["query_work"].metrics
        self.assertGreater(spent.hash_work, 0)
        self.assertGreater(spent.input_bytes, 0)
        with self.assertRaises(reader.IndexReadError):
            physical.require_idle(cursor, physical.trace, arguments["query_work"])
        self.assertEqual(arguments["query_work"].metrics, spent)


if __name__ == "__main__":
    unittest.main()
