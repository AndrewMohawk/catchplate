#!/usr/bin/env python3
"""Committed catalog receipts versus optional subsequent readiness observation.

Run in the pinned backend image, network none, with read-only source and private
temporary storage. SQLite, publication locking, encryption, policy compilation,
signing and materialization are real. Only failing atomic replacement and the
GET health HTTP transport are injected. No gate/provider serving is claimed;
catalog_status is the GET implementation, not an ASGI admission test.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = workspace.common._ACTOR


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("receipt fixture attempted network contact")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        self.tokens = []

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def call(self, function, payload):
        """Observe real opens: materialization under EX is allowed, GET is not."""
        original = self.db.connect
        opened = []

        def connect(*args, **kwargs):
            self.store.operator_publication.assert_held()
            opened.append(True)
            return original(*args, **kwargs)

        with patch.object(self.db, "connect", side_effect=connect), \
                patch.object(self.mutations, "_policy_observation",
                    side_effect=AssertionError("mutation attempted optional policy observation")) as observe, \
                patch.object(self.store, "loaded_gate_status",
                    side_effect=AssertionError("mutation attempted optional health observation")) as health:
            result = function(payload, ACTOR)
        assert opened, "mutation did not use the actual SQLite path"
        observe.assert_not_called()
        health.assert_not_called()
        self.store.operator_publication.assert_not_held()
        assert result["revision"] == payload.expected_revision + 1
        self.receipt(result)
        if "client_token" in result:
            self.tokens.append(result["client_token"])
            self.token(result)
        return result

    def receipt(self, result):
        row, = workspace.rows(self.db, "operator_demo_policy")
        current = workspace.catalog(self.db, self.schema)
        assert result["revision"] == current["revision"]
        assert result["policy"] == {"policy_hash": row["policy_hash"],
            "sequence": row["sequence"], "loaded_policy_hash": None, "activation": "pending"}
        events = workspace.rows(self.db, "audit_events")
        event = json.loads(events[-1]["event_json"])
        assert event["revision"] == result["revision"]
        assert event["policy_hash"] == row["policy_hash"]
        assert event["policy_sequence"] == row["sequence"]

    def token(self, result):
        token = result["client_token"]
        assert isinstance(token, str) and len(token) >= 40
        application = next(row for row in workspace.catalog(self.db, self.schema)["applications"]
            if row["id"] == result["application"]["id"])
        assert application["token_sha256"] == "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()
        assert application["token_version"] == result["application"]["token_generation"]
        with closing(self.db.connect()) as conn:
            retained = "\n".join(conn.iterdump())
        assert all(value not in retained for value in [*self.tokens, workspace.common._PROVIDER_SECRET])

    def credential(self):
        return self.call(self.mutations.create_credential, self.inputs.CredentialInput(
            **self.review(), name="Receipt fixture credential", auth_type="bearer",
            secret=workspace.common._PROVIDER_SECRET))["credential"]

    def application(self):
        return self.call(self.mutations.create_application, self.inputs.ApplicationInput(
            **self.review(), name="Receipt fixture application", token_lifetime_seconds=3600))

    def rule(self, application, credential):
        return self.call(self.mutations.create_rule, self.inputs.RuleInput(**self.review(),
            name="Receipt fixture permission", application_id=application["id"], credential_id=credential["id"],
            upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["status"]))

    def rotation_input(self, application):
        return self.inputs.RotateApplicationInput(**self.review(), id=application["id"], token_lifetime_seconds=3600)

    def signed(self):
        return workspace.verify_signed(self.config, self.db, self.store, self.bundles)

    def status(self, digest, *, during_request=None, unavailable=False):
        """Actual observer/parser with bounded synthetic HTTP response bytes."""
        trace = []
        fixture = self
        body = json.dumps({"ok": True, "policy_hash": digest}, separators=(",", ":")).encode()

        class Connection:
            def __init__(self, host, port, *, timeout):
                assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
                trace.append("open")

            def request(self, method, path, *, headers):
                fixture.store.operator_publication.assert_not_held()
                assert (method, path, headers) == ("GET", "/healthz", {"Connection": "close"})
                trace.append("request")
                if during_request is not None:
                    during_request()
                if unavailable:
                    raise ConnectionError("synthetic gate unavailable")

            def getresponse(self):
                trace.append("response")
                return self

            @property
            def status(self):
                return 200

            def read(self, limit):
                assert limit == 131073
                trace.append("read")
                return body

            def close(self):
                trace.append("close")

        with patch.object(self.store.http.client, "HTTPConnection", Connection):
            result = self.mutations.catalog_status()
        assert trace == (["open", "request", "close"] if unavailable else
            ["open", "request", "response", "read", "close"])
        public = json.dumps(result, sort_keys=True)
        private = [workspace.common._PROVIDER_SECRET, *self.tokens,
            *[row["token_sha256"] for row in workspace.catalog(self.db, self.schema)["applications"]]]
        assert all(value not in public for value in private)
        return result


def store_only():
    f = Fixture()
    initial = f.store.get_policy_high_water()
    raw = f.config.POLICY_BUNDLE_PATH.read_bytes()
    credential = f.credential()
    application = f.application()
    assert credential["credential_generation"] == 1
    assert application["application"]["access_status"] == "unassigned"
    assert application["application"]["token_status"] == "valid"
    assert f.store.get_policy_high_water() == initial
    assert f.config.POLICY_BUNDLE_PATH.read_bytes() == raw
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    f.signed()
    frozen = deepcopy(application)
    public = f.status(initial["policy_hash"])
    assert public["policy"]["activation"] == "active"
    assert application == frozen and application["policy"]["activation"] == "pending"
    return {"stored_only": True, "one_time_token_retained": True}


def policy_mutations():
    f = Fixture()
    credential, app = f.credential(), f.application()
    initial_sequence = app["policy"]["sequence"]
    created = f.rule(app["application"], credential)
    assert created["access_rule"]["enforcement"] == "pending"
    assert created["policy"]["sequence"] == initial_sequence + 1
    signed = f.signed()
    assert signed["routes"][0]["id"] == created["access_rule"]["route_id"]
    rotated = f.call(f.mutations.rotate_application_token, f.rotation_input(app["application"]))
    assert rotated["policy"]["sequence"] == initial_sequence + 2
    assert rotated["policy"]["policy_hash"] != created["policy"]["policy_hash"]
    assert rotated["client_token"] != app["client_token"]
    assert rotated["application"]["token_generation"] == 2
    assert rotated["application"]["access_status"] == "pending"
    signed = f.signed()
    assert signed["principals"][0]["proxyAuthorization"]["tokenSha256"] == \
        "sha256:" + hashlib.sha256(rotated["client_token"].encode("ascii")).hexdigest()
    revoked = f.call(f.mutations.revoke_application,
        f.inputs.TargetInput(**f.review(), id=app["application"]["id"]))
    assert revoked["policy"]["sequence"] == initial_sequence + 3
    assert revoked["application"]["token_status"] == "revoked"
    assert revoked["application"]["access_status"] == "pending"
    assert revoked["affected_rule_ids"] == [created["access_rule"]["id"]]
    assert "client_token" not in revoked
    f.signed()
    return {"policy_mutations": 3, "pending_receipts_without_observation": True}


def failed_materialization():
    f = Fixture()
    credential, app = f.credential(), f.application()
    created = f.rule(app["application"], credential)
    original_bytes = f.config.POLICY_BUNDLE_PATH.read_bytes()
    original_replace, failures = os.replace, []

    def replace(source, destination, *args, **kwargs):
        if Path(destination) == f.config.POLICY_BUNDLE_PATH:
            f.store.operator_publication.assert_held()
            failures.append(True)
            raise OSError("synthetic policy atomic replacement refusal")
        return original_replace(source, destination, *args, **kwargs)

    with patch.object(os, "replace", side_effect=replace):
        rotated = f.call(f.mutations.rotate_application_token, f.rotation_input(app["application"]))
    assert failures == [True]
    assert f.config.POLICY_BUNDLE_PATH.read_bytes() == original_bytes
    assert rotated["policy"]["sequence"] == created["policy"]["sequence"] + 1
    row, = workspace.rows(f.db, "operator_demo_policy")
    compiled = f.bundles.compile_policy_bundle(json.loads(row["signed_bundle_json"]),
        verify_signature=True, validate_schema=True)
    assert compiled.hash == rotated["policy"]["policy_hash"]
    assert f.bundles.verify_policy_high_water(compiled) == f.store.get_policy_high_water()
    assert f.bundles.get_policy_snapshot() is None, "stale published file escaped committed high water"
    pending = f.status(created["policy"]["policy_hash"])
    assert pending["policy"]["activation"] == "pending"
    assert pending["policy"]["policy_hash"] == rotated["policy"]["policy_hash"]
    before = workspace.snapshot(f.db, catalog=True)
    f.store.materialize()
    assert workspace.snapshot(f.db, catalog=True) == before
    f.signed()
    active = f.status(rotated["policy"]["policy_hash"])
    assert active["policy"]["activation"] == "active"
    assert rotated["policy"]["activation"] == "pending"
    f.token(rotated)
    return {"durable_after_materialization_failure": True, "repaired_without_replay": True}


def fresh_observation():
    f = Fixture()
    credential, app = f.credential(), f.application()
    created = f.rule(app["application"], credential)
    original = deepcopy(created)
    unavailable = f.status(created["policy"]["policy_hash"], unavailable=True)
    assert unavailable["policy"]["activation"] == "pending"
    assert unavailable["policy"]["loaded_policy_hash"] is None
    rotation = f.rotation_input(app["application"])
    newer = []

    def committed_during_observation():
        newer.append(f.call(f.mutations.rotate_application_token, rotation))

    raced = f.status(created["policy"]["policy_hash"], during_request=committed_during_observation)
    assert len(newer) == 1
    assert raced["policy"]["policy_hash"] == raced["policy"]["loaded_policy_hash"] == created["policy"]["policy_hash"]
    assert raced["policy"]["activation"] == "pending", "old loaded/captured equality hid newer committed policy"
    assert raced["revision"] == created["revision"]
    current = newer[0]
    active = f.status(current["policy"]["policy_hash"])
    assert active["revision"] == current["revision"]
    assert active["policy"] == {**current["policy"], "loaded_policy_hash": current["policy"]["policy_hash"],
        "activation": "active"}
    assert active["access_rules"][0]["enforcement"] == "active"
    assert active["applications"][0]["access_status"] == "active"
    assert created == original and current["policy"]["activation"] == "pending"
    f.signed()
    return {"fresh_get_observes_readiness": True, "concurrent_current_hash_join": True}


class OperatorCatalogMutationReceiptTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        environment = {**self.environment, "SERVERWARE_DECISION_GATE_BASE": "http://127.0.0.1:9091"}
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_store_only_receipt_keeps_one_time_token_without_observation(self):
        self.assertTrue(self.run_worker("store-only")["one_time_token_retained"])

    def test_signed_policy_mutations_return_exact_committed_pending_receipts(self):
        self.assertEqual(self.run_worker("policy")["policy_mutations"], 3)

    def test_materialization_failure_preserves_commit_and_token_then_repairs(self):
        self.assertTrue(self.run_worker("materialization")["repaired_without_replay"])

    def test_fresh_catalog_observation_requires_current_committed_hash(self):
        self.assertTrue(self.run_worker("observation")["concurrent_current_hash_join"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        operation = {"store-only": store_only, "policy": policy_mutations,
            "materialization": failed_materialization, "observation": fresh_observation}[sys.argv[2]]
        print(json.dumps(operation(), sort_keys=True))
    else:
        unittest.main(verbosity=2)
