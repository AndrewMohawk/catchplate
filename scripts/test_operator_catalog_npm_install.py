#!/usr/bin/env python3
"""Explicit install catalog components; no npm, HTTP, provider or SDK acceptance.

Connected workers use real SQLite/custody/signing/CAS. Only the bounded gate
reader's HTTP transport is synthetic; successful admission is never stubbed.
"""
from contextlib import closing, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_operator_catalog_npm as shared
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-npm-install-catalog-test"
BUNDLE = "npm_install_v1"
PACKAGES = ["@serverware/fixture", "serverware-fixture"]
GATE = {"schema": "serverware.operatorNpmInstallGate/v1", "adapter": "npm.install.v1",
    "modes": ["metadata", "tarball", "audit"]}
CURRENT = object()


def no_network(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("npm install catalog fixture forbids network")


sys.addaudithook(no_network)


@contextmanager
def observed_gate(f, payload=CURRENT):
    clients = []
    class Client:
        status = 200
        def __init__(self, host, port, *, timeout):
            f.store.operator_publication.assert_not_held()
            assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
            self.closed = False
            clients.append(self)
        def request(self, method, path, *, headers):
            assert (method, path, headers) == ("GET", "/healthz", {"Connection": "close"})
            if isinstance(payload, BaseException):
                raise payload
            value = ({"ok": True, "policy_hash": f.review()["expected_policy_hash"],
                "operator_npm_install": deepcopy(GATE)} if payload is CURRENT else payload)
            self.raw = json.dumps(value).encode()
        def getresponse(self): return self
        def read(self, limit):
            assert limit == 131073
            return self.raw[:limit]
        def close(self): self.closed = True
    with patch.object(f.config, "DECISION_GATE_BASE", "http://127.0.0.1:9091"), \
            patch.object(f.store.http.client, "HTTPConnection", Client):
        try:
            yield clients
        finally:
            assert all(client.closed for client in clients)


class Fixture(shared.Fixture):
    def call(self, function, *args):
        with observed_gate(self):
            return super().call(function, *args)

    def fields(self, application, credential, packages=None):
        return {**super().fields(application, credential, packages), "operation_bundle": BUNDLE,
            "name": "Install explicit packages and dependencies"}

    def rule(self, application, credential, packages=None):
        return self.call(self.mutations.create_npm_install_rule,
            self.inputs.NpmInstallRuleInput(**self.fields(application, credential, packages)), ACTOR)

    def old_rule(self, application, credential, publish=False):
        fields = {**self.review(), "name": "Existing registry permission",
            "application_id": application["id"], "credential_id": credential["id"]}
        if publish:
            payload = self.inputs.NpmPublishRuleInput(**fields, operation_bundle="npm_publish_v1",
                package="serverware-fixture", tag="latest", publishing_window=None)
            return self.call(self.mutations.create_npm_publish_rule, payload, ACTOR)
        payload = self.inputs.NpmMetadataRuleInput(**fields, operation_bundle="npm_metadata_read_v1", packages=PACKAGES)
        return self.call(self.mutations.create_npm_rule, payload, ACTOR)


def signed_lifecycle():
    from serverware import npm_install
    f = Fixture()
    initial_policy = f.signed()
    before = f.snapshot()[1:]
    credential, app = f.credential()["credential"], f.application()
    assert f.snapshot()[1:] == before
    saved = f.rule(app, credential)["access_rule"]
    core = f.db.get_credential(credential["id"], include_secret=True)
    routes = f.signed()["routes"]
    assert len(routes) == 3 and saved["packages"] == PACKAGES
    expected_paths = {"metadata": ["/{package}"],
        "tarball": ["/{package}/-/{filename}", "/{scope}/{package}/-/{filename}"],
        "audit": ["/-/npm/v1/security/advisories/bulk"]}
    for mode in ("metadata", "tarball", "audit"):
        identifier = saved["route_id"] + ("" if mode == "metadata" else "." + mode)
        route = next(row for row in routes if row["id"] == identifier)
        assert route["match"] == {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
            "methods": ["POST" if mode == "audit" else "GET"], "paths": expected_paths[mode]}
        assert route["credentialRef"] == credential["id"] and route["principals"] == [app["principal_id"]]
        assert route["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "Bearer serverware-npm-placeholder-v1"}
        cfg = route["adapter"]["config"]
        assert route["adapter"]["type"] == "npm.install.v1"
        assert set(cfg) == {"credentialBinding", "packages", "mode", "request", "response"}
        assert cfg["mode"] == mode and cfg["packages"] == PACKAGES
        assert cfg["request"] == npm_install.request_profile(mode)
        assert cfg["response"] == npm_install.response_profile(mode)
        assert route["constraints"] == [npm_install.response_envelope(identifier + ".envelope", mode)]
        assert cfg["credentialBinding"] == {"credentialType": "static", "provider": "operator-demo",
            "subjects": [core["metadata"]["provider_subject"]], "secretClass": "bearerToken"}
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["npm_install"]["dependencies_require_explicit_grant"] is True
    assert status["capabilities"]["npm"]["operation_bundles"] == ["npm_metadata_read_v1"]
    f.privacy(status)
    from serverware import operator_notification_events as events
    with closing(f.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        batch, _ = events.read_batch(conn, events.EventCursor(), limit=64, now_epoch_ms=time.time_ns() // 1000000)
        chosen = [event for event in batch if event.event_type == "operator_catalog.access_rule.npm_install_created"]
        assert len(chosen) == 1 and chosen[0].action_payload is None
        assert chosen[0].audit_payload["details"]["resource_id"] == saved["id"]
        assert events.payload_matches_source(conn, chosen[0].audit_payload, now_epoch_ms=time.time_ns() // 1000000)
        f.privacy(chosen[0].audit_payload)
    assert shared.TOKEN not in json.dumps(workspace.rows(f.db, "credentials"))
    before = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == before
    f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(**f.review(),
        id=credential["id"], expected_credential_generation=1, secret=shared.REPLACEMENT), ACTOR)
    assert f.signed()["routes"] == routes
    f.call(f.mutations.revoke_rule, f.target(saved["id"]), ACTOR)
    revoked_policy = f.signed()
    # An unconfigured policy retains the schema-required, permanently expired
    # operator.empty sentinel. Revocation must restore that exact authority.
    for key in ("defaults", "principals", "credentials", "routes"):
        assert revoked_policy[key] == initial_policy[key]
    assert not {row["id"] for row in routes}.intersection(row["id"] for row in revoked_policy["routes"])
    f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR)
    assert f.db.get_credential(credential["id"], include_secret=True) is None
    f.privacy(f.call(f.mutations.catalog_status))
    return {"signed_three_routes_and_revocation": True}


def overlap():
    f = Fixture()
    credential = f.credential()["credential"]
    generic = f.generic_credential()
    for kind in ("metadata", "publish", "generic"):
        for install_first in (False, True):
            app = f.application()
            other = lambda: (f.generic(app, generic, "/-/arbitrary", ["POST"]) if kind == "generic"
                else f.old_rule(app, credential, kind == "publish"))
            first = f.rule(app, credential) if install_first else other()
            before = f.snapshot()
            shared.refused(other if install_first else lambda: f.rule(app, credential), (ValueError, f.schema.CatalogConflict))
            assert f.snapshot() == before
            f.call(f.mutations.revoke_rule, f.target(first["access_rule"]["id"]), ACTOR)
    app = f.application()
    before = f.snapshot()
    shared.refused(lambda: f.rule(app, generic), ValueError)
    assert f.snapshot() == before
    original = f.old_rule(app, credential)["access_rule"]
    assert original["operation_bundle"] == "npm_metadata_read_v1"
    assert len([row for row in f.signed()["routes"] if row["principals"] == [app["principal_id"]]]) == 1
    return {"both_orders_and_no_implicit_upgrade": True}


def freshness():
    f = Fixture()
    credential, app = f.credential()["credential"], f.application()
    payload = f.inputs.NpmInstallRuleInput(**f.fields(app, credential))
    good = {"ok": True, "policy_hash": payload.expected_policy_hash, "operator_npm_install": deepcopy(GATE)}
    before = f.snapshot()
    for bad in ({**good, "operator_npm_install": None}, {**good, "operator_npm_install": {**GATE, "extra": True}},
            {**good, "policy_hash": "sha256:" + "0" * 64}, {**good, "ok": False}, RuntimeError("synthetic refusal")):
        with observed_gate(f, bad), patch.object(f.store, "loaded_policy_hash", return_value=None):
            assert f.mutations.catalog_status()["capabilities"]["npm_install"] is None
            shared.refused(lambda: f.mutations.create_npm_install_rule(payload, ACTOR), f.schema.CatalogConflict)
        assert f.snapshot() == before
    with observed_gate(f) as clients:
        assert f.mutations.catalog_status()["capabilities"]["npm_install"] is not None
        assert len(clients) == 1
    stale = payload
    f.application()
    before = f.snapshot()
    shared.refused(lambda: f.call(f.mutations.create_npm_install_rule, stale, ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    return {"fresh_paired_observation_and_cas": True}


def rollback():
    f = Fixture()
    credential, app = f.credential()["credential"], f.application()
    for target in ("BEFORE INSERT ON audit_events", "BEFORE UPDATE ON operator_demo_policy"):
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER install_abort " + target + " BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END")
        try:
            shared.refused(lambda: f.rule(app, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER install_abort")
    before = f.snapshot()
    with patch.object(f.bundles, "sign_policy_bundle", side_effect=ValueError("synthetic refusal")):
        shared.refused(lambda: f.rule(app, credential), ValueError)
    assert f.snapshot() == before
    return {"rollback_stages": 3}


def destination():
    f = Fixture()
    credential, app = f.credential()["credential"], f.application()
    assert f.call(f.mutations.catalog_status)["capabilities"]["npm_install"] is None
    before = f.snapshot()
    shared.refused(lambda: f.rule(app, credential), f.schema.CatalogConflict)
    assert f.snapshot() == before
    return {"destination_required": True}


OPERATIONS = {"signed": signed_lifecycle, "overlap": overlap, "freshness": freshness,
    "rollback": rollback, "destination": destination}


class PureInstallTests(unittest.TestCase):
    def fields(self):
        return {"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
            "name": "Install explicit closure", "application_id": "12345678-1234-4234-8234-123456789abc",
            "credential_id": "22345678-1234-4234-8234-123456789abc", "operation_bundle": BUNDLE,
            "packages": list(PACKAGES)}

    def test_closed_input_and_explicit_dependency_names(self):
        from serverware.operator_catalog_inputs import NpmInstallRuleInput
        self.assertEqual(NpmInstallRuleInput(**self.fields()).packages, PACKAGES)
        for changes in ({"packages": []}, {"packages": ["*"]}, {"packages": ["pkg", "pkg"]},
                {"packages": ["z", "a"]}, {"packages": sorted("pkg" + str(i) for i in range(65))},
                {"packages": ["pkg@1.0.0"]}, {"packages": ["https://registry.npmjs.org/pkg"]},
                {"operation_bundle": "npm_metadata_read_v1"}, {"expected_revision": True},
                {"upstream_url": "https://other.example/"}, {"methods": ["PUT"]}, {"placeholder": "real-token"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                NpmInstallRuleInput(**{**self.fields(), **changes})

    def test_exact_gate_descriptor(self):
        from serverware.operator_catalog_npm_install import gate_descriptor_matches
        self.assertTrue(gate_descriptor_matches(deepcopy(GATE)))
        for value in (None, {}, {**GATE, "operation": "npm.install"}, {**GATE, "modes": ["audit", "metadata", "tarball"]},
                {**GATE, "modes": ("metadata", "tarball", "audit")}, {**GATE, "modes": ["metadata", "tarball"]}):
            self.assertFalse(gate_descriptor_matches(value))

    def test_derived_shape_and_all_registry_overlap(self):
        from serverware import operator_catalog_npm_install as install
        from serverware.operator_catalog_inputs import NpmInstallRuleInput
        from serverware.operator_catalog_schema import CatalogIntegrityError
        row = {**install.record_fields(NpmInstallRuleInput(**self.fields())), "status": "active"}
        for changes in ({"methods": ["GET"]}, {"query_mode": None}, {"request_body_mode": "preserve_json_v1"},
                {"response_mode": "unfiltered_json"}, {"allowed_headers": ["content-encoding"]}, {"packages": ["*"]}):
            with self.assertRaises(CatalogIntegrityError):
                install.validate_shape({**row, **changes})
        generic = {"status": "active", "application_id": row["application_id"], "upstream_url": "https://registry.npmjs.org/-/anything"}
        for rules in ([row, generic], [generic, row], [row, deepcopy(row)]):
            with self.assertRaises(CatalogIntegrityError):
                install.validate_route_coexistence(rules)
        for changes in ({"status": "revoked"}, {"application_id": "other"}, {"upstream_url": "https://api.example.com/"}):
            install.validate_route_coexistence([row, {**generic, **changes}])


class ConnectedInstallTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com","https://registry.npmjs.org"]'

    def run_worker(self, name):
        environment = dict(self.environment)
        if name == "destination":
            environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com"]'
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail("isolated install catalog worker failed: " + shared.github_tests.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_real_custody_three_signed_routes_reopen_rotation_revoke(self):
        self.assertTrue(self.run_worker("signed")["signed_three_routes_and_revocation"])

    def test_both_overlap_orders_and_no_old_grant_upgrade(self):
        self.assertTrue(self.run_worker("overlap")["both_orders_and_no_implicit_upgrade"])

    def test_actual_bounded_health_reader_and_fresh_cas(self):
        self.assertTrue(self.run_worker("freshness")["fresh_paired_observation_and_cas"])

    def test_real_audit_policy_signing_rollback(self):
        self.assertEqual(self.run_worker("rollback")["rollback_stages"], 3)

    def test_operator_destination_required(self):
        self.assertTrue(self.run_worker("destination")["destination_required"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
        except Exception as error:
            print(json.dumps(shared.github_tests.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)
