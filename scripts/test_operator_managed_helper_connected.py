#!/usr/bin/env python3
"""Offline controls for the connected checker's evidence oracle, not network proof."""
from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import check_operator_managed_helper_connected as check


def no_external_work(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("network and child processes forbidden in oracle tests")


sys.addaudithook(no_external_work)

APP = "12345678-1234-4234-8234-123456789abc"
ENROLL = "22345678-1234-4234-8234-123456789abc"
OP = "32345678-1234-4234-8234-123456789abc"
NOW = 1_900_000_000_000
OLD, NEW = "a" * 43, "b" * 43
PRINCIPAL = "agent:operator-demo:" + APP
HASHES = ["sha256:" + char * 64 for char in "123456789abcdef"]


class ManagedHelperOracleTests(unittest.TestCase):
    def setUp(self):
        self.app = {"id": APP, "name": "test", "version": 2, "status": "active", "principal_id": PRINCIPAL,
            "token_generation": 1, "token_expires_at_epoch_ms": NOW + 3_600_000,
            "access_status": "active", "active_rule_count": 1,
            "client_renewal": {"status": "active", "enrollment_id": ENROLL,
                "audience": check.PROXY + "/v1/workload/renew", "public_key_fingerprint": HASHES[0],
                "expires_at_epoch_ms": NOW + 86_400_000, "token_lifetime_seconds": 3600, "overlap_seconds": 300}}
        self.setup = check.setup_from_catalog(self.app)
        issued = NOW + 1000
        self.lease = check.managed.TokenLease(NEW, 2, issued + 3_600_000, issued + 10 + 300_000)
        self.request = {"schema": "catchplate.workloadTokenRenewal/v1", "audience": self.setup["audience"],
            "application_id": APP, "enrollment_id": ENROLL, "expected_token_generation": 1,
            "operation_id": OP, "issued_at_epoch_ms": issued, "expires_at_epoch_ms": issued + 60_000,
            "token_sha256": check.digest(NEW.encode()), "token_expires_at_epoch_ms": self.lease.expires_at_epoch_ms}
        signing = b"catchplate.workload-token-renewal/v1\x00POST /v1/workload/renew\x00" + check.canonical(self.request)
        self.receipt = {"operation_id": OP, "request_sha256": check.digest(signing), "application_id": APP,
            "enrollment_id": ENROLL, "previous_generation": 1, "token_generation": 2,
            "token_sha256": self.request["token_sha256"], "issued_at_epoch_ms": issued, "rotated_at_epoch_ms": issued + 10,
            "expires_at_epoch_ms": self.lease.expires_at_epoch_ms, "previous_accept_until_epoch_ms": self.lease.pool_refresh_by_epoch_ms}
        self.state = {"setup": self.setup, "pending": None, "last_receipt": self.receipt,
            "current": {"token": NEW, "generation": 2, "expires_at_epoch_ms": self.lease.expires_at_epoch_ms,
                "pool_refresh_by_epoch_ms": self.lease.pool_refresh_by_epoch_ms}}
        self.pending = {"candidate_token": NEW,
            "request_original": check.canonical({**self.request, "signature": "1" * 128}).decode()}
        self.before = {"revision": 5, "credentials": [{"id": "credential", "version": 1}],
            "access_rules": [{"id": "permission", "route_id": "operator.permission", "version": 1}],
            "applications": [deepcopy(self.app)], "observed_activity": {},
            "policy": {"policy_hash": HASHES[2], "loaded_policy_hash": HASHES[2], "sequence": 3, "activation": "active"}}
        self.after = deepcopy(self.before)
        self.after["revision"] = 6
        self.after["applications"][0].update(version=3, token_generation=2,
            token_expires_at_epoch_ms=self.lease.expires_at_epoch_ms, token_rotated_at="2030-03-17T00:00:00+00:00")
        self.after["policy"].update(policy_hash=HASHES[3], loaded_policy_hash=HASHES[3], sequence=4)
        self.rule = {"route_id": "operator.permission"}
        self.binary = HASHES[8]

    def test_public_setup_is_closed_and_never_copies_private_fields(self):
        self.app.update(token_sha256=HASHES[4], client_token="do-not-copy", private_key="do-not-copy")
        self.assertEqual(set(check.setup_from_catalog(self.app)), check.managed.SETUP_FIELDS)
        self.assertNotIn("do-not-copy", json.dumps(check.setup_from_catalog(self.app)))

    def test_public_audience_is_not_reconstructed_with_default_port(self):
        self.app["client_renewal"]["audience"] = check.PROXY + ":443/v1/workload/renew"
        with self.assertRaises(check.CheckFailure):
            check.setup_from_catalog(self.app)

    def test_inactive_enrollment_or_changed_limits_refused(self):
        for field, value in (("status", "expired"), ("token_lifetime_seconds", 7200), ("overlap_seconds", 301)):
            with self.subTest(field=field):
                app = deepcopy(self.app); app["client_renewal"][field] = value
                with self.assertRaises(check.CheckFailure):
                    check.setup_from_catalog(app)

    def test_installed_receipt_and_exact_pending_replay_join(self):
        self.assertEqual(check.validate_receipt(self.state, self.lease, self.setup, OLD), self.receipt)
        self.assertEqual(check.validate_receipt(self.state, self.lease, self.setup, OLD, self.pending), self.receipt)

    def test_safe_old_lease_is_not_counted_as_renewal(self):
        self.state.update(pending=self.pending, last_receipt=None)
        with self.assertRaises(check.CheckFailure):
            check.validate_receipt(self.state, check.managed.TokenLease(OLD, 1, NOW + 3_600_000, NOW + 3_600_000), self.setup, OLD)

    def test_receipt_digest_generation_and_expiry_are_independent_guards(self):
        for field, value in (("request_sha256", HASHES[5]), ("token_generation", 3),
                ("expires_at_epoch_ms", self.lease.expires_at_epoch_ms + 1), ("previous_accept_until_epoch_ms", NOW + 999_999)):
            with self.subTest(field=field):
                state = deepcopy(self.state); state["last_receipt"][field] = value
                with self.assertRaises(check.CheckFailure):
                    check.validate_receipt(state, self.lease, self.setup, OLD)

    def test_pending_replay_cannot_replace_uuid_expiry_or_candidate(self):
        for field, value in (("operation_id", ENROLL), ("expires_at_epoch_ms", NOW + 70_000)):
            with self.subTest(field=field):
                pending = deepcopy(self.pending)
                request = json.loads(pending["request_original"]); request[field] = value
                pending["request_original"] = check.canonical(request).decode()
                with self.assertRaises(check.CheckFailure):
                    check.validate_receipt(self.state, self.lease, self.setup, OLD, pending)
        with self.assertRaises(check.CheckFailure):
            check.validate_receipt(self.state, self.lease, self.setup, OLD, {**self.pending, "candidate_token": OLD})

    def test_catalog_accepts_exact_version_increment_and_observation_only_drift(self):
        self.after["observed_activity"] = {"recent": "read"}
        check.validate_catalog_change(self.before, self.after, self.receipt)

    def test_catalog_refuses_unexpected_resource_or_version_change(self):
        for collection in ("credentials", "access_rules", "applications"):
            with self.subTest(collection=collection):
                after = deepcopy(self.after); after[collection][0]["version"] += 1
                with self.assertRaises(check.CheckFailure):
                    check.validate_catalog_change(self.before, after, self.receipt)

    def test_catalog_refuses_global_active_but_wrong_policy_or_generation(self):
        for field, value in (("loaded_policy_hash", HASHES[2]), ("activation", "pending"), ("sequence", 3)):
            with self.subTest(field=field):
                after = deepcopy(self.after); after["policy"][field] = value
                with self.assertRaises(check.CheckFailure):
                    check.validate_catalog_change(self.before, after, self.receipt)
        self.after["applications"][0]["token_generation"] = 1
        with self.assertRaises(check.CheckFailure):
            check.validate_catalog_change(self.before, self.after, self.receipt)

    def audit_fixture(self):
        mutations = [("operator_catalog.credential.created", "credential", HASHES[0]),
            ("operator_catalog.application.created", APP, HASHES[0]),
            ("operator_catalog.access_rule.created", "permission", HASHES[1]),
            ("operator_catalog.application.renewal_enrolled", APP, HASHES[2])]
        rows = [{"id": "mutation-" + str(i), "event_type": kind, "event": {"resource_id": identifier, "policy_hash": policy}}
            for i, (kind, identifier, policy) in enumerate(mutations)]
        observations = []
        for index in (0, 1):
            key = {"policyHash": HASHES[3], "requestDigest": HASHES[4 + index], "operationDigest": HASHES[6 + index]}
            observations.append(key)
            event = {"policy_hash": key["policyHash"], "request_digest": key["requestDigest"], "operation_digest": key["operationDigest"],
                "principal_id": PRINCIPAL, "route_id": self.rule["route_id"], "credential_ref": "credential", "credential_version": 1,
                "method": "POST", "body_sha256": check.digest(check.REQUEST_BODY), "attempt_id": HASHES[9 + index], "flow_id": HASHES[9 + index]}
            rows += [{"id": "start-" + str(index), "event_type": check.START, "event": {**event, "outcome": "release_started"}},
                {"id": "release-" + str(index), "event_type": check.RELEASE, "event": {**event, "outcome": "released", "upstream_status": 200,
                    "response_body_sha256": check.digest(check.REQUEST_BODY), "response_body_bytes": len(check.REQUEST_BODY),
                    "response_validation": {"ok": True, "mode": check.RESPONSE_MODES[check.V2_RESPONSE_MODE], "body_bytes_preserved": True}}},
                {"id": "connect-" + str(index), "event_type": check.CONNECT, "event": {"method": "CONNECT", "target": check.AUTHORITY,
                    "principal_id": PRINCIPAL, "policy_hash": HASHES[3], "outcome": "established"}}]
        rows.append({"id": "renewed", "event_type": check.RENEWED, "actor_type": "agent", "actor_id": PRINCIPAL,
            "event": {"resource_id": APP, "resource_type": "application", "enrollment_id": ENROLL, "operation_id": OP,
                "token_generation": 2, "token_expires_at_epoch_ms": self.receipt["expires_at_epoch_ms"], "revision": 6,
                "policy_hash": HASHES[3], "policy_sequence": 4}})
        rows.append({"id": "lease", "event_type": check.LEASE, "event": {"principal_id": PRINCIPAL,
            "route_id": self.rule["route_id"], "credential_id": "credential", "policy_hash": HASHES[3], "status_code": 200,
            "outcome": "issued", "data_plane_binary_digest": self.binary, "purpose": "dispatchSecret", "expected_credential_version": 1}})
        chain = Counter()
        for index in range(3):
            chain[(HASHES[index], HASHES[index + 1], index + 2, 1)] += 1
            rows.append({"id": "reload-" + str(index), "event_type": check.RELOAD, "event": {
                "previous_policy_hash": HASHES[index], "policy_hash": HASHES[index + 1], "policy_sequence": index + 2, "routes": 1}})
        return rows, observations, mutations, chain

    def project(self, rows, observations, mutations, chain):
        return check.audit_projection(rows, observations, mutations, self.app, self.rule, "credential", self.receipt, self.after, chain, self.binary)

    def test_complete_audit_requires_two_distinct_attempts_and_one_issuance(self):
        result = self.project(*self.audit_fixture())
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["releaseAttemptIds"]), 2)
        self.assertEqual(result["renewalAuditIds"], ["renewed"])

    def test_missing_terminal_is_incomplete_not_success(self):
        rows, *rest = self.audit_fixture()
        self.assertFalse(self.project([row for row in rows if row["id"] != "release-1"], *rest)["complete"])

    def test_unexpected_audit_or_duplicate_issuance_refused(self):
        for kind in ("data_plane.connect.denied", check.RENEWED):
            with self.subTest(kind=kind):
                rows, *rest = self.audit_fixture()
                rows.append({"id": "extra", "event_type": kind, "event": {}})
                with self.assertRaises(check.CheckFailure):
                    self.project(rows, *rest)

    def test_renewal_actor_and_receipt_scope_are_exact(self):
        for field, value in (("operation_id", ENROLL), ("revision", 7), ("token_generation", 3),
                ("token_expires_at_epoch_ms", NOW), ("policy_hash", HASHES[2])):
            with self.subTest(field=field):
                rows, *rest = self.audit_fixture()
                next(row for row in rows if row["id"] == "renewed")["event"][field] = value
                with self.assertRaises(check.CheckFailure):
                    self.project(rows, *rest)
        rows, *rest = self.audit_fixture()
        next(row for row in rows if row["id"] == "renewed")["actor_id"] = "admin"
        with self.assertRaises(check.CheckFailure):
            self.project(rows, *rest)

    def test_provider_release_must_join_wire_body_and_distinct_attempt(self):
        for field, value in (("body_sha256", HASHES[0]), ("attempt_id", HASHES[9]), ("credential_ref", "other")):
            with self.subTest(field=field):
                rows, *rest = self.audit_fixture()
                next(row for row in rows if row["id"] == "release-1")["event"][field] = value
                with self.assertRaises(check.CheckFailure):
                    self.project(rows, *rest)

    def test_duplicate_wire_commitments_do_not_prove_two_operations(self):
        rows, observations, mutations, chain = self.audit_fixture()
        with self.assertRaises(check.CheckFailure):
            self.project(rows, [observations[0], observations[0]], mutations, chain)

    def test_wrong_binary_lease_or_unknown_policy_reload_refused(self):
        for identifier, field, value in (("lease", "data_plane_binary_digest", HASHES[0]),
                ("reload-2", "policy_sequence", 5)):
            with self.subTest(identifier=identifier):
                rows, *rest = self.audit_fixture()
                next(row for row in rows if row["id"] == identifier)["event"][field] = value
                with self.assertRaises(check.CheckFailure):
                    self.project(rows, *rest)

    def test_stable_file_identity_allows_only_access_time_change(self):
        values = dict(st_dev=1, st_ino=2, st_mode=0o100600, st_nlink=1, st_uid=os.geteuid(), st_gid=os.getegid(),
            st_size=32, st_mtime_ns=100, st_ctime_ns=101, st_atime_ns=99)
        before = SimpleNamespace(**values)
        self.assertEqual(check.stable_file_identity(before), check.stable_file_identity(SimpleNamespace(**{**values, "st_atime_ns": 102})))
        for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
            with self.subTest(field=field):
                self.assertNotEqual(check.stable_file_identity(before),
                    check.stable_file_identity(SimpleNamespace(**{**values, field: values[field] + 1})))

    def test_real_private_file_modes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token.private"
            check.private_write(path, b"synthetic-private")
            self.assertEqual(check.private_read(path, 32), b"synthetic-private")
            with self.assertRaises(FileExistsError):
                check.private_write(path, b"replacement")
            path.chmod(0o644)
            with self.assertRaises(check.CheckFailure):
                check.private_read(path, 32)

    def test_connected_source_never_injects_managed_transport_or_clock(self):
        tree = ast.parse(Path(check.__file__).read_text())
        constructions = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "ManagedClient"]
        self.assertEqual(len(constructions), 3)
        self.assertTrue(all(len(node.args) == 1 and not node.keywords for node in constructions))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"_prepare", "_https_exchange"} for node in ast.walk(tree)))


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ManagedHelperOracleTests))
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
