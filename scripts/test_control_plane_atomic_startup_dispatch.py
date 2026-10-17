#!/usr/bin/env python3
"""Offline atomic-startup configuration and facade-dispatch regressions.

The real configuration guard, installed writer facades and startup ordering run
without SQL or sockets. Earlier startup stages and the final CA effect are inert
observers; the dispatch transport is explicitly synthetic. Its return sentinel
is NOT a typed authority result, admitted startup, PostgreSQL test or readiness
claim. A separate real-kernel control records the remaining reconciliation gap.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_DATA = tempfile.TemporaryDirectory(prefix="atomic-startup-component-")
os.environ["CATCHPLATE_PROCESS_MODE"] = "catchplate-control-plane"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
os.environ["CATCHPLATE_DATA_DIR"] = _DATA.name

from catchplate import authority_contract as contract
from catchplate import authority_service
from catchplate import authority_transition_core as core
from catchplate import authority_transition_release as release
from catchplate import control_plane_startup as startup
from catchplate import db, development_sandbox, grants, operator_demo
from catchplate import operator_google_setup_preflight, operator_upstream_setup_preflight


DSN = "host=/synthetic-unopened-socket dbname=synthetic user=synthetic"
LIMIT = 37
OPERATIONS = ("release.reconcile", "release.audit-drain")
_FORBIDDEN_EVENTS: list[str] | None = None


def _audit(event, _arguments):
    if _FORBIDDEN_EVENTS is not None and (
        event.startswith(("socket.", "sqlite3."))
        or event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}
    ):
        _FORBIDDEN_EVENTS.append(event)
        raise AssertionError("offline component attempted I/O: " + event)


sys.addaudithook(_audit)


@contextmanager
def configured(metadata="postgres", grant="postgres", metadata_dsn=DSN, grant_dsn=DSN):
    # Patch configuration values only, never backend predicates or the guard.
    with patch.multiple(db, METADATA_STORE_BACKEND=metadata,
                        METADATA_STORE_POSTGRES_DSN=metadata_dsn), patch.multiple(
            grants, GRANT_STORE_BACKEND=grant, GRANT_STORE_POSTGRES_DSN=grant_dsn):
        yield


class AtomicStartupDispatchTests(unittest.TestCase):
    def setUp(self):
        global _FORBIDDEN_EVENTS
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        _FORBIDDEN_EVENTS = []
        self.addCleanup(self._finish_audit)
        self.assertIsNone(db._policy_authority_writer_context.get())
        self.stack.enter_context(patch.dict(os.environ, {
            "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
            "CATCHPLATE_RELEASE_CHANNEL": "dev",
        }))
        self.connections = []
        for module, name in (
            (db, "connect"), (db, "_metadata_pg_connect_raw"),
            (db, "_metadata_pg_connect_with_dsn"), (db, "_audit_pg_connect"),
            (grants, "_connect"),
        ):
            self.connections.append(self.stack.enter_context(patch.object(
                module, name, side_effect=AssertionError("SQL connection is forbidden"))))

    def _finish_audit(self):
        global _FORBIDDEN_EVENTS
        observed, _FORBIDDEN_EVENTS = _FORBIDDEN_EVENTS, None
        self.assertEqual(observed, [])
        for connection in self.connections:
            connection.assert_not_called()
        self.assertIsNone(db._policy_authority_writer_context.get())

    def expected_input(self, operation):
        reconcile = operation == OPERATIONS[0]
        return {
            "schema": "catchplate.policyAuthorityControlledWriterInput/v1",
            "handler": "reconcile_release_authorizations" if reconcile else
                "drain_release_authorization_audit_outbox",
            "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
            "arguments": {"limit": LIMIT, "now_epoch_ms": None,
                          "actor_id": "release-authorization-reconciler"}
                if reconcile else {"limit": LIMIT},
        }

    def transport(self, events, *, failure=None, kernel=False):
        def dispatch(operation, input_value, *, deadline_ns=None):
            self.assertIn(operation, OPERATIONS)
            self.assertEqual(input_value, self.expected_input(operation))
            self.assertIsNone(deadline_ns)
            self.assertIsNone(db._policy_authority_writer_context.get())
            self.assertTrue(startup.control_plane_startup_required())
            events.append(operation)
            if operation == failure:
                raise db.MetadataStoreError("synthetic authority transport unavailable")
            if kernel:
                # Actual current kernel: no invented candidate, rows or receipt.
                release.KERNELS[operation].queries(
                    arguments=authority_service._synthesize_business_arguments(
                        operation, input_value["arguments"]),
                    database_now=datetime(2026, 10, 11, tzinfo=timezone.utc),
                    request_digest="sha256:" + "a" * 64,
                )
            return {"synthetic_dispatch_boundary_only": operation}
        return dispatch

    @contextmanager
    def orchestration(self, *, production=False, enabled=True, atomic_policy=True,
                      failure=None, kernel=False):
        events = []
        snapshot = SimpleNamespace(routes=(SimpleNamespace(
            jit={"required": atomic_policy}, constraints=()),))

        def ca_boundary():
            self.assertIsNone(db._policy_authority_writer_context.get())
            self.assertTrue(startup.control_plane_startup_required())
            events.append("ca")

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ))
            os.environ.pop(startup._STARTUP_VALIDATED_PID_ENV, None)
            stack.enter_context(patch.multiple(startup,
                RELEASE_CHANNEL="production" if production else "dev",
                ATOMIC_RELEASE_AUTHORIZATION_ENABLED=enabled,
                RELEASE_AUTHORIZATION_RECONCILE_LIMIT=LIMIT,
                OIDC_SESSION_WEBAUTHN_REQUIRED=False))
            for module, name, result in (
                (startup, "validate_control_plane_configuration", None),
                (operator_upstream_setup_preflight, "validate_before_database_initialization", None),
                (operator_google_setup_preflight, "validate_before_database_initialization", None),
                (startup, "ensure_data_dirs", None), (db, "init_db", None),
                (development_sandbox, "active", False), (operator_demo, "active", False),
                (startup, "reconcile_trust_publications", None),
                (db, "drain_metadata_audit_outbox_fully", {"failed": 0, "pending": 0}),
                (db, "verify_audit_chain", {"ok": True, "complete": True}),
                (startup, "get_policy_snapshot", snapshot),
                (startup, "enforce_policy_high_water", None),
            ):
                stack.enter_context(patch.object(module, name, return_value=result))
            ca = stack.enter_context(patch.object(
                startup, "ensure_mitm_ca_material", side_effect=ca_boundary))
            # Neither facade nor storage guard is replaced by a successful mock.
            stack.enter_context(patch.object(db, "dispatch_policy_authority_operation",
                side_effect=self.transport(events, failure=failure, kernel=kernel)))
            yield events, ca

    def test_real_configuration_guard_is_nonauthority_and_does_not_connect(self):
        with configured(), patch.object(db, "dispatch_policy_authority_operation",
                side_effect=AssertionError("configuration must not dispatch")) as dispatch:
            self.assertEqual(db.require_atomic_release_storage_configuration(), {
                "metadata_backend": "postgres", "grant_backend": "postgres",
                "shared_transaction": True, "writer": None,
                "writer_candidate": "postgres-external-measured",
                "hot_runtime_write_authorized": False,
                "external_measured_writer_required": True,
            })
            dispatch.assert_not_called()
            self.assertIsNone(db._policy_authority_writer_context.get())

    def test_real_configuration_guard_refuses_sqlite_mismatched_and_empty_dsns(self):
        for settings in (
            ("sqlite", "sqlite", "", ""), ("sqlite", "postgres", DSN, DSN),
            ("postgres", "sqlite", DSN, DSN),
            ("postgres", "postgres", DSN, DSN + " application_name=other"),
            ("postgres", "postgres", "", DSN),
            ("postgres", "postgres", DSN, ""),
            ("postgres", "postgres", "", ""),
            ("postgres", "postgres", "   ", "   "),
        ):
            with self.subTest(settings=settings), configured(*settings), self.assertRaises(db.MetadataStoreError):
                db.require_atomic_release_storage_configuration()

    def test_privileged_writer_still_refuses_the_hot_process(self):
        with configured(), self.assertRaisesRegex(db.ReleaseAuthorizationError, "separately measured"):
            db.require_atomic_release_writer()
        token = db._policy_authority_writer_context.set({
            "operation": OPERATIONS[0], "fence": 1,
            "deadlineMonotonicNs": time.monotonic_ns() + 10_000_000_000,
        })
        try:
            with configured(), self.assertRaisesRegex(db.ReleaseAuthorizationError, "invalid or expired"):
                db.require_atomic_release_writer()
        finally:
            db._policy_authority_writer_context.reset(token)

    def test_actual_installed_facades_marshal_fixed_operations_without_writer_context(self):
        with configured(), self.orchestration() as (events, ca):
            for operation, facade, args, kwargs in (
                (OPERATIONS[0], db.reconcile_release_authorizations, (), {"limit": LIMIT}),
                (OPERATIONS[1], db.drain_release_authorization_audit_outbox, (LIMIT,), {}),
            ):
                self.assertTrue(hasattr(facade, "__wrapped__"))
                self.assertEqual(facade(*args, **kwargs), {
                    "synthetic_dispatch_boundary_only": operation})
            self.assertEqual(events, list(OPERATIONS))
            ca.assert_not_called()

    def test_synthetic_startup_dispatch_returns_before_ca_and_pid_marker(self):
        with configured(), self.orchestration(production=True) as (events, ca):
            startup.validate_control_plane_startup()
            self.assertEqual(events, [*OPERATIONS, "ca"])
            ca.assert_called_once_with()
            self.assertEqual(os.environ[startup._STARTUP_VALIDATED_PID_ENV], str(os.getpid()))
            self.assertFalse(startup.control_plane_startup_required())

    def test_enabled_atomic_storage_refusal_blocks_dispatch_ca_and_marker(self):
        with configured(metadata="sqlite"), self.orchestration() as (events, ca):
            with self.assertRaises(db.MetadataStoreError):
                startup.validate_control_plane_startup()
            self.assertEqual(events, [])
            ca.assert_not_called()
            self.assertTrue(startup.control_plane_startup_required())

    def test_composed_policy_requires_storage_even_without_global_atomic_flag(self):
        with configured(grant_dsn=""), self.orchestration(
                production=True, enabled=False) as (events, ca):
            with self.assertRaisesRegex(RuntimeError, "configured with the same DSN") as caught:
                startup.validate_control_plane_startup()
            self.assertIsInstance(caught.exception.__cause__, db.MetadataStoreError)
            self.assertEqual(events, [])
            ca.assert_not_called()
            self.assertTrue(startup.control_plane_startup_required())

    def test_nonatomic_development_sqlite_keeps_its_existing_startup_path(self):
        with configured(metadata="sqlite", grant="sqlite", metadata_dsn="", grant_dsn=""), \
                self.orchestration(enabled=False, atomic_policy=False) as (events, ca):
            startup.validate_control_plane_startup()
            self.assertEqual(events, ["ca"])
            ca.assert_called_once_with()
            self.assertEqual(os.environ[startup._STARTUP_VALIDATED_PID_ENV], str(os.getpid()))
            self.assertFalse(startup.control_plane_startup_required())

    def test_either_transport_failure_blocks_ca_and_marker_without_retry(self):
        for index, operation in enumerate(OPERATIONS):
            with self.subTest(operation=operation), configured(), self.orchestration(
                    failure=operation) as (events, ca):
                with self.assertRaisesRegex(db.MetadataStoreError, "synthetic authority transport unavailable"):
                    startup.validate_control_plane_startup()
                self.assertEqual(events, list(OPERATIONS[:index + 1]))
                ca.assert_not_called()
                self.assertTrue(startup.control_plane_startup_required())

    def test_captured_default_reconcile_arguments_still_refuse_real_typed_kernel(self):
        with configured(), self.orchestration(kernel=True) as (events, ca):
            with self.assertRaisesRegex(core.TransitionKernelError,
                    "release transition attempt_id is absent"):
                startup.validate_control_plane_startup()
            self.assertEqual(events, [OPERATIONS[0]])
            ca.assert_not_called()
            self.assertTrue(startup.control_plane_startup_required())


if __name__ == "__main__":
    unittest.main()
