#!/usr/bin/env python3
from __future__ import annotations

import copy
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
        self.assertEqual((trace._budget.business_entries, trace._budget.framework_entries), (16, 0))
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
            cutoff_us=1_000_007, heads=(), frontiers=())
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


if __name__ == "__main__":
    unittest.main()
