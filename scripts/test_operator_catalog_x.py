#!/usr/bin/env python3
"""Retained X catalog components: actual SQLite/custody/signing, no provider.

Fresh bounded subprocesses reuse the existing operator fixture. Gate health
uses the real bounded reader with an in-memory HTTPConnection, not a running
gate. Custody, capability admission and mutation CAS are real local components;
this is not HTTP, SDK or deployed acceptance.
"""
from contextlib import closing, contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_catalog_github as shared
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-x-catalog-test"
TOKEN = "synthetic_x_catalog_token_123456789"
REPLACEMENT = "synthetic_x_replacement_token_987654321"
USERNAME = "fixture_user"
BUNDLE = "x_username_read_v1"
MARKER = "x_app_bearer_v1"
ORIGIN = "https://api.x.com"
GATE_DESCRIPTOR = {"schema": "catchplate.operatorXAppReadGate/v1",
    "adapter": "x.app_read.v1", "operation": "x.username.read"}
CURRENT = object()


def no_network(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("X catalog fixture forbids network")


sys.addaudithook(no_network)


def refused(callback, error=ValueError):
    try:
        callback()
    except error:
        return
    raise AssertionError("invalid X catalog operation admitted")


def gate_payload(store):
    return {"ok": True, "policy_hash": store.get_policy_high_water()["policy_hash"],
        "operator_x_app_read": dict(GATE_DESCRIPTOR)}


@contextmanager
def observed_gate(config, store, payload=CURRENT):
    """Only the HTTP transport is synthetic; never replace a successful guard."""
    clients = []
    class Client:
        status = 200
        def __init__(self, host, port, *, timeout):
            store.operator_publication.assert_not_held()
            assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
            self.closed = False
            clients.append(self)
        def request(self, method, path, *, headers):
            assert (method, path, headers) == ("GET", "/healthz", {"Connection": "close"})
            if isinstance(payload, BaseException): raise payload
            value = gate_payload(store) if payload is CURRENT else payload
            self.raw = json.dumps(value).encode("utf-8")
        def getresponse(self): return self
        def read(self, limit):
            assert limit == 131073
            return self.raw[:limit]
        def close(self): self.closed = True
    with patch.object(config, "DECISION_GATE_BASE", "http://127.0.0.1:9091"), \
            patch.object(store.http.client, "HTTPConnection", Client):
        try: yield clients
        finally: assert all(client.closed for client in clients), "health reader leaked its transport"


class Fixture(shared.Fixture):
    def call(self, function, *args):
        with observed_gate(self.config, self.store):
            return super().call(function, *args)

    def credential(self):
        return self.call(self.mutations.create_x_credential,
            self.inputs.XAppBearerInput(**self.review(), name="Synthetic X app token", secret=TOKEN), ACTOR)

    def fields(self, application, credential):
        return {**self.review(), "name": "Lookup exact username", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": BUNDLE, "username": USERNAME}

    def rule(self, application, credential):
        return self.call(self.mutations.create_x_rule,
            self.inputs.XUsernameRuleInput(**self.fields(application, credential)), ACTOR)

    def privacy(self, value):
        rendered = json.dumps(value, sort_keys=True)
        audit = json.dumps(workspace.rows(self.db, "audit_events"))
        for secret in (TOKEN, REPLACEMENT, *self.tokens,
                *(row["token_sha256"] for row in self.catalog()["applications"])):
            assert secret not in rendered and secret not in audit


def signed():
    from catchplate import x_app_read as x
    f = Fixture()
    before = f.snapshot()[1:]
    credential, application = f.credential()["credential"], f.application()
    assert f.snapshot()[1:] == before, "saving resources must not grant authority"
    assert credential["auth_type"] == "bearer" and credential["header_name"] == "Authorization"
    assert credential["provider_id"] == "x" and credential["connection_type"] == MARKER
    assert credential["credential_generation"] == 1
    core = f.db.get_credential(credential["id"], include_secret=True)
    assert core["kind"] == "bearer" and core["secret"] == TOKEN
    assert core["metadata"]["provider_id"] == "operator-demo"
    assert core["metadata"]["connection_type"] == MARKER
    assert TOKEN not in json.dumps(workspace.rows(f.db, "credentials"))
    result = f.rule(application, credential)
    rule = result["access_rule"]
    route = next(item for item in f.signed()["routes"] if item["id"] == rule["route_id"])
    assert rule["operation_bundle"] == BUNDLE and rule["username"] == USERNAME
    assert rule["upstream_url"] == ORIGIN + "/2/users/by/username/" + USERNAME
    assert rule["methods"] == ["GET"] and rule["request_fields"] == rule["response_fields"] == rule["query_keys"] == []
    assert rule["response_mode"] == "x_app_read_json_v1"
    assert "request_body_mode" not in rule and "query_mode" not in rule
    assert route["match"] == {"scheme": "https", "host": "api.x.com", "port": 443,
        "methods": ["GET"], "paths": ["/2/users/by/username/" + USERNAME]}
    assert route["credentialRef"] == credential["id"] and route["principals"] == [application["principal_id"]]
    assert route["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "Bearer catchplate-x-placeholder-v1"}
    assert route["adapter"]["type"] == "x.app_read.v1"
    config = route["adapter"]["config"]
    assert config["username"] == USERNAME and config["request"] == x.request_profile()
    assert config["response"] == x.response_profile()
    assert config["credentialBinding"]["provider"] == "operator-demo"
    assert config["credentialBinding"]["subjects"] == [core["metadata"]["provider_subject"]]
    assert route["constraints"] == [x.response_envelope(route["id"] + ".envelope")]
    assert result["policy"]["activation"] == "pending" and result["policy"]["loaded_policy_hash"] is None
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["x"]["destination_allowed"] is True
    assert status["capabilities"]["x"]["operation_bundles"] == [BUNDLE]
    f.privacy(status)
    return {"signed_static_username": True}


def inputs_and_cas():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    fields, before = f.fields(application, credential), f.snapshot()
    for username in ("", "Upper", "a" * 16, "@user", "a/b", "a%2fb", "a?x", "a-b", "é", None, True):
        refused(lambda username=username: f.inputs.XUsernameRuleInput(**{**fields, "username": username}))
    for key, value in (("operation_bundle", "x_write_v1"), ("methods", ["POST"]),
            ("upstream_url", ORIGIN + "/2/users/me"), ("placeholder", "Bearer other"),
            ("request_body_mode", "preserve_json_v1"), ("response_fields", ["data"]),
            ("credential_input", "insert"), ("expected_revision", True)):
        refused(lambda key=key, value=value: f.inputs.XUsernameRuleInput(**{**fields, key: value}))
    for secret in ("", "contains space", "line\nbreak", "é", "x" * 8193):
        refused(lambda secret=secret: f.inputs.XAppBearerInput(**f.review(), name="Refused", secret=secret))
    assert TOKEN not in repr(f.inputs.XAppBearerInput(**f.review(), name="Hidden", secret=TOKEN))
    assert f.snapshot() == before
    stale = f.inputs.XUsernameRuleInput(**fields)
    f.rule(application, credential)
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.create_x_rule, stale, ACTOR), f.schema.CatalogConflict)
    # Current gate/policy with an old revision reaches the actual mutation CAS,
    # independently of the early stale-policy capability refusal above.
    current = f.fields(application, credential)
    current["expected_revision"] -= 1
    refused(lambda: f.call(f.mutations.create_x_rule,
        f.inputs.XUsernameRuleInput(**current), ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    return {"strict_inputs_and_stale_replay": True}


def crossed():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    generic = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(),
        name="Unmarked static bearer", auth_type="bearer", secret=TOKEN), ACTOR)["credential"]
    github = f.call(f.mutations.create_github_credential, f.inputs.GithubTokenInput(**f.review(),
        name="Separate GitHub marker", secret=shared.TOKEN), ACTOR)["credential"]
    before = f.snapshot()
    for wrong in (generic, github): refused(lambda wrong=wrong: f.rule(application, wrong))
    refused(lambda: f.call(f.mutations.create_rule, f.inputs.RuleInput(**f.review(), name="No generic fallback",
        application_id=application["id"], credential_id=credential["id"],
        upstream_url=ORIGIN + "/2/users/by/username/" + USERNAME, methods=["GET"], response_fields=["data"]), ACTOR))
    refused(lambda: f.call(f.mutations.create_github_rule, f.inputs.GithubRuleInput(**f.review(),
        name="No crossed GitHub grant", application_id=application["id"], credential_id=credential["id"],
        operation_bundle=shared.READ, repository=shared.REPOSITORY), ACTOR))
    assert f.snapshot() == before
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    for collection, identifier, changes in (
            ("credentials", credential["id"], {"connection_type": "github_token_v1"}),
            ("credentials", credential["id"], {"connection_type": None}),
            ("credentials", credential["id"], {"connection_type": "unknown"}),
            ("access_rules", rule["id"], {"methods": ["GET", "POST"]}),
            ("access_rules", rule["id"], {"username": "other_user"}),
            ("access_rules", rule["id"], {"placeholder": "Bearer other"}),
            ("access_rules", rule["id"], {"request_body_mode": "preserve_json_v1"})):
        changed = deepcopy(f.catalog())
        next(row for row in changed[collection] if row["id"] == identifier).update(changes)
        with closing(f.db.connect()) as conn:
            refused(lambda: f.schema.validate_bindings(conn, changed), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    return {"crossed_markers_refused": True}


def replacement():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    for marker in (None, "unknown", "github_token_v1", "npm_token_v1"):
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                metadata = json.loads(conn.execute("SELECT metadata FROM credentials WHERE id=?", (credential["id"],)).fetchone()[0])
                if marker is None: metadata.pop("connection_type")
                else: metadata["connection_type"] = marker
                conn.execute("UPDATE credentials SET metadata=? WHERE id=?", (json.dumps(metadata), credential["id"]))
                refused(lambda: f.db.replace_operator_static_credential_secret_if_version(conn, credential["id"],
                    expected_version=1, secret=REPLACEMENT), f.db.MetadataStoreError)
            finally: conn.rollback()
        assert f.snapshot() == before
    prior = f.catalog()
    result = f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(**f.review(),
        id=credential["id"], expected_credential_generation=1, secret=REPLACEMENT), ACTOR)
    assert result["credential"]["credential_generation"] == 2
    assert result["credential"]["connection_type"] == MARKER
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == REPLACEMENT
    assert f.snapshot()[1:] == before[1:]
    assert f.catalog()["applications"] == prior["applications"] and f.catalog()["access_rules"] == prior["access_rules"]
    after = f.snapshot()
    refused(lambda: f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(**f.review(),
        id=credential["id"], expected_credential_generation=1, secret=TOKEN), ACTOR), f.schema.CatalogConflict)
    refused(lambda: f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == after
    f.call(f.mutations.revoke_rule, f.target(rule["id"]), ACTOR)
    f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR)
    assert f.db.get_credential(credential["id"], include_secret=True) is None
    after = f.snapshot()
    refused(lambda: f.rule(application, credential), f.schema.CatalogConflict)
    assert f.snapshot() == after
    f.privacy(f.call(f.mutations.catalog_status))
    return {"generation_rotation_and_explicit_revocation": True}


def failures():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    for statement in ("BEFORE INSERT ON audit_events", "BEFORE UPDATE ON operator_demo_policy"):
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER x_abort " + statement + " BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END")
        try:
            refused(lambda: f.rule(application, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before
        finally:
            with closing(f.db.connect()) as conn, conn: conn.execute("DROP TRIGGER x_abort")
    before = f.snapshot()
    with patch.object(f.bundles, "sign_policy_bundle", side_effect=ValueError("synthetic signing refusal")):
        refused(lambda: f.rule(application, credential))
    assert f.snapshot() == before
    real_replace = os.replace
    def fail_export(source, destination, *args, **kwargs):
        if Path(destination) == f.config.POLICY_BUNDLE_PATH: raise OSError("synthetic export failure")
        return real_replace(source, destination, *args, **kwargs)
    with patch.object(os, "replace", fail_export): result = f.rule(application, credential)
    assert result["policy"]["activation"] == "pending" and result["policy"]["loaded_policy_hash"] is None
    assert f.snapshot()[1] == before[1]
    committed = workspace.snapshot(f.db, catalog=True)
    f.store.initialize()
    assert workspace.snapshot(f.db, catalog=True) == committed and f.snapshot()[1] != before[1]
    f.signed()
    return {"rollback_and_durable_pending": True}


def destination():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    assert f.call(f.mutations.catalog_status)["capabilities"]["x"]["destination_allowed"] is False
    before = f.snapshot()
    refused(lambda: f.rule(application, credential))
    assert f.snapshot() == before
    return {"destination_required": True}


def gate_refusals():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    create = f.inputs.XAppBearerInput(**f.review(), name="No unsupported save", secret=TOKEN)
    grant = f.inputs.XUsernameRuleInput(**f.fields(application, credential))
    good = gate_payload(f.store)
    stale = "sha256:" + "0" * 64
    assert stale != good["policy_hash"]
    descriptors = [None, {}, [], {**GATE_DESCRIPTOR, "unknown": True},
        *({**GATE_DESCRIPTOR, field: value} for field, value in (
            ("schema", "catchplate.operatorXAppReadGate/v0"), ("adapter", "x.v2"),
            ("operation", "x.write"), ("schema", True))),
        *({key: value for key, value in GATE_DESCRIPTOR.items() if key != missing}
            for missing in GATE_DESCRIPTOR)]
    cases = [None, {}, {"ok": True, "policy_hash": good["policy_hash"]},
        {**good, "ok": False}, {**good, "ok": 1}, {**good, "policy_hash": "invalid"},
        {**good, "policy_hash": stale}, OSError("synthetic health unavailable"),
        *({**good, "operator_x_app_read": item} for item in descriptors)]
    before = f.snapshot()
    for case in cases:
        with observed_gate(f.config, f.store, case) as clients, \
                patch.object(f.store, "loaded_policy_hash", return_value=None), \
                patch.object(f.mutations, "_mutate", side_effect=AssertionError("entered mutation before compatibility")) as mutate:
            refused(lambda: f.mutations.create_x_credential(create, ACTOR), f.schema.CatalogConflict)
            assert len(clients) == 1
            refused(lambda: f.mutations.create_x_rule(grant, ACTOR), f.schema.CatalogConflict)
            assert len(clients) == 2
            status = f.mutations.catalog_status()
            assert status["capabilities"]["x"] is None
            assert status["capabilities"]["alchemy"] is None
            # Two refused mutations above, then one fresh catalog observation
            # shared by policy and both optional provider capabilities.
            assert len(clients) == 3
            mutate.assert_not_called()
        assert f.snapshot() == before
    # Matching stale request and gate hashes still fail the real local SQL
    # re-read, before mutation; a hash agreement alone is not current authority.
    with observed_gate(f.config, f.store, {**good, "policy_hash": stale}) as clients, \
            patch.object(f.mutations, "_mutate", side_effect=AssertionError("stale local policy entered mutation")) as mutate:
        for function, payload in ((f.mutations.create_x_credential, create), (f.mutations.create_x_rule, grant)):
            refused(lambda function=function, payload=payload: function(
                payload.model_copy(update={"expected_policy_hash": stale}), ACTOR), f.schema.CatalogConflict)
        assert len(clients) == 2
        mutate.assert_not_called()
    with observed_gate(f.config, f.store) as clients, f.store.operator_publication.exclusive():
        refused(lambda: f.mutations.create_x_credential(create, ACTOR), f.schema.CatalogConflict)
        refused(lambda: f.mutations.create_x_rule(grant, ACTOR), f.schema.CatalogConflict)
        assert clients == [], "no health request may run under publication ownership"
    assert f.snapshot() == before
    assert f.call(f.mutations.catalog_status)["capabilities"]["x"]["operation_bundles"] == [BUNDLE]
    assert f.snapshot() == before
    return {"unsupported_pair_refused_before_writes": True}


def coexistence():
    f = Fixture()
    first, second = f.credential()["credential"], f.credential()["credential"]
    application = f.application()
    rule = f.rule(application, first)["access_rule"]
    before = f.snapshot()
    for credential in (first, second):
        refused(lambda credential=credential: f.rule(application, credential), f.schema.CatalogConflict)
        assert f.snapshot() == before
    fields = {**f.fields(application, second), "username": "other_user"}
    other = f.call(f.mutations.create_x_rule, f.inputs.XUsernameRuleInput(**fields), ACTOR)["access_rule"]
    routes = {row["id"]: row for row in f.signed()["routes"]}
    assert routes[rule["route_id"]]["credentialRef"] == first["id"]
    assert routes[other["route_id"]]["credentialRef"] == second["id"]
    assert len(routes) == 2
    before = f.snapshot()
    changed = deepcopy(f.catalog())
    next(row for row in changed["access_rules"] if row["id"] == other["id"]).update(
        username=USERNAME, upstream_url=ORIGIN + "/2/users/by/username/" + USERNAME)
    with closing(f.db.connect()) as conn:
        refused(lambda: f.schema.validate_bindings(conn, changed), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    return {"duplicate_typed_grants_refused": True}


def retained(seed=False):
    f = Fixture()
    if seed:
        credential, application = f.credential()["credential"], f.application()
        f.rule(application, credential)
        f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(**f.review(),
            id=credential["id"], expected_credential_generation=1, secret=REPLACEMENT), ACTOR)
    catalog = f.catalog()
    assert len(catalog["credentials"]) == len(catalog["applications"]) == len(catalog["access_rules"]) == 1
    core = f.db.get_credential(catalog["credentials"][0]["id"], include_secret=True)
    assert core["secret"] == REPLACEMENT and core["metadata"]["connection_type"] == MARKER
    prior = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == prior
    f.signed()
    f.privacy(f.call(f.mutations.catalog_status))
    return {"revision": catalog["revision"], "credential": catalog["credentials"][0]["id"],
        "rule": catalog["access_rules"][0]["id"], "policy_sha256": hashlib.sha256(prior[1]).hexdigest(),
        "audit_count": len(workspace.rows(f.db, "audit_events"))}


def legacy():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    before, signed_bytes = workspace.snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    workspace.migrate(db, schema)
    assert workspace.snapshot(db) == before and config.POLICY_BUNDLE_PATH.read_bytes() == signed_bytes
    old = workspace.catalog(db, schema)
    from catchplate import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    with observed_gate(config, store), patch.object(store, "loaded_policy_hash", return_value=None):
        result = mutations.create_x_credential(inputs.XAppBearerInput(**workspace.review(db, store, schema),
            name="New separate X token", secret=TOKEN), ACTOR)
    current = workspace.catalog(db, schema)
    for collection in ("credentials", "applications", "access_rules"):
        assert current[collection][:len(old[collection])] == old[collection]
    assert result["credential"]["connection_type"] == MARKER
    assert config.POLICY_BUNDLE_PATH.read_bytes() == signed_bytes
    workspace.verify_signed(config, db, store, bundles)
    return {"legacy_authority_unchanged": True}


OPERATIONS = {"signed": signed, "inputs": inputs_and_cas, "crossed": crossed,
    "replacement": replacement, "failures": failures, "destination": destination,
    "seed": lambda: retained(True), "reopen": retained, "legacy": legacy,
    "gate": gate_refusals, "coexistence": coexistence}


class OperatorCatalogXTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(
            ["https://api.example.com", "https://api.github.com", ORIGIN])

    def worker(self, name):
        environment = dict(self.environment)
        if name == "destination": environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com"]'
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail("isolated X catalog worker refused: " + shared.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_signed_static_username_and_private_custody(self): self.assertTrue(self.worker("signed")["signed_static_username"])
    def test_strict_inputs_and_stale_cas_replay(self): self.assertTrue(self.worker("inputs")["strict_inputs_and_stale_replay"])
    def test_crossed_markers_and_generic_fallback_refused(self): self.assertTrue(self.worker("crossed")["crossed_markers_refused"])
    def test_actual_rotation_and_explicit_revocation(self): self.assertTrue(self.worker("replacement")["generation_rotation_and_explicit_revocation"])
    def test_rollback_and_postcommit_pending(self): self.assertTrue(self.worker("failures")["rollback_and_durable_pending"])
    def test_destination_required_even_after_key_saved(self): self.assertTrue(self.worker("destination")["destination_required"])
    def test_retained_restart_in_fresh_process(self): self.assertEqual(self.worker("seed"), self.worker("reopen"))
    def test_legacy_rows_and_authority_unchanged(self): self.assertTrue(self.worker("legacy")["legacy_authority_unchanged"])
    def test_gate_compatibility_is_current_closed_and_prewrite(self): self.assertTrue(self.worker("gate")["unsupported_pair_refused_before_writes"])
    def test_duplicate_typed_grants_and_disjoint_usernames(self): self.assertTrue(self.worker("coexistence")["duplicate_typed_grants_refused"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try: outcome = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(shared.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else: unittest.main(verbosity=2)
