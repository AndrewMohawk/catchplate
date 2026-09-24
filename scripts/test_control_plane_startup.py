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

    def __init__(self, fixture, *, on_clock=None, change=None):
        import test_authority_complete_acquisition as complete_oracle
        import test_authority_index_frontier as range_oracle
        import test_authority_index_heads as head_oracle
        import test_authority_radix_batch as primary_oracle

        self.fixture, self.on_clock, self.change = fixture, on_clock, change
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
        if sql == "SELECT pg_catalog.clock_timestamp() AS database_now":
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

    def assert_produced_revocation_plan(self, expectation, fixture, produced):
        import test_authority_revocation_plan as plan_oracle

        signed = produced.signed
        self.assertEqual(produced.database_now, fixture.database_now)
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

    def test_private_plan_production_replays_real_acquisition_packaging_and_signed_verification(self):
        from serverware import authority_revocation_plan as replay
        from serverware import authority_revocation_plan_production as production
        from serverware import authority_revocation_proof_bundle as retained
        from serverware import authority_revocation_read_write as mixed
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
                        patch.object(production, "_build_and_sign", wraps=production._build_and_sign) as build, \
                        patch.object(replay, "verify_signed_revocation_plan",
                                     wraps=replay.verify_signed_revocation_plan) as public_replay:
                    produced = program._produce_revocation_plan(cursor, **arguments)
                self.assertEqual((cursor.clock_reads, acquisition.call_count, generation.call_count,
                    receipt.call_count, effects.call_count, writer.call_count, packaging.call_count,
                    proof.call_count, build.call_count, public_replay.call_count),
                    (1, 1, 2, 1, 1, 1, 1, 1, 1, 0))
                # Acquisition generates once at the original cutoff; genuine
                # raw packaging replays that source recipe once more.
                self.assertIs(acquisition.call_args.kwargs["query_work"], work)
                self.assertIs(receipt.call_args.kwargs["work"].shared, work)
                for actual in (effects, packaging, build):
                    self.assertIs(actual.call_args.kwargs["work"], work)
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
                self.assertEqual(cursor.clock_reads, 1)
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
        self.assertEqual(prior.signed.metrics, plain.signed.metrics)
        self.assertEqual((prior.metrics.hash_work - plain.metrics.hash_work,
                          prior.metrics.input_bytes - plain.metrics.input_bytes,
                          prior.metrics.json_nodes - plain.metrics.json_nodes), (7, 101, 13))

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
