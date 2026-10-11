#!/usr/bin/env python3
"""Retained Alchemy catalog components: actual SQLite/custody/signing, no provider.

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
ACTOR = "operator-alchemy-catalog-test"
TOKEN = "synthetic_alchemy_catalog_key_123456789"
REPLACEMENT = "synthetic_alchemy_replacement_key_987654321"
CHAIN = "eth-mainnet"
OTHER_CHAIN = "eth-sepolia"
BUNDLE = "alchemy_chain_status_read_v1"
MARKER = "alchemy_key_v1"
ORIGIN = "https://eth-mainnet.g.alchemy.com"
OTHER_ORIGIN = "https://eth-sepolia.g.alchemy.com"
GATE_DESCRIPTOR = {"schema": "serverware.operatorAlchemyRpcReadGate/v1",
    "adapter": "alchemy.rpc_read.v1", "operation": "alchemy.rpc.read"}
HEADERS = ["accept", "accept-language", "alchemy-ethers-sdk-method",
    "alchemy-ethers-sdk-version", "sec-fetch-mode", "user-agent"]
CURRENT = object()


def no_network(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("Alchemy catalog fixture forbids network")


sys.addaudithook(no_network)


def refused(callback, error=ValueError):
    try:
        callback()
    except error:
        return
    raise AssertionError("invalid Alchemy catalog operation admitted")


def gate_payload(store):
    return {"ok": True, "policy_hash": store.get_policy_high_water()["policy_hash"],
        "operator_alchemy_rpc_read": dict(GATE_DESCRIPTOR),
        "operator_x_app_read": {"schema": "serverware.operatorXAppReadGate/v1",
            "adapter": "x.app_read.v1", "operation": "x.username.read"}}


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
        return self.call(self.mutations.create_alchemy_credential,
            self.inputs.AlchemyKeyInput(**self.review(), name="Synthetic Alchemy key", secret=TOKEN), ACTOR)

    def fields(self, application, credential):
        return {**self.review(), "name": "Read exact chain status", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": BUNDLE, "chain": CHAIN}

    def rule(self, application, credential):
        return self.call(self.mutations.create_alchemy_rule,
            self.inputs.AlchemyChainStatusRuleInput(**self.fields(application, credential)), ACTOR)

    def application(self):
        result = self.call(self.mutations.create_application, self.inputs.ApplicationInput(
            **self.review(), name="Alchemy read-only client", token_lifetime_seconds=3600,
            proxy_authentication="basic_and_bearer_v1"), ACTOR)
        self.tokens.append(result["client_token"])
        return result["application"]

    def privacy(self, value):
        rendered = json.dumps(value, sort_keys=True)
        audit = json.dumps(workspace.rows(self.db, "audit_events"))
        for secret in (TOKEN, REPLACEMENT, *self.tokens,
                *(row["token_sha256"] for row in self.catalog()["applications"])):
            assert secret not in rendered and secret not in audit


def signed():
    from serverware import alchemy_rpc_read as alchemy
    f = Fixture()
    before = f.snapshot()[1:]
    credential, application = f.credential()["credential"], f.application()
    assert f.snapshot()[1:] == before, "saving resources must not grant authority"
    assert credential["auth_type"] == "bearer" and credential["header_name"] == "Authorization"
    assert credential["provider_id"] == "alchemy" and credential["connection_type"] == MARKER
    assert credential["credential_generation"] == 1
    core = f.db.get_credential(credential["id"], include_secret=True)
    assert core["kind"] == "bearer" and core["secret"] == TOKEN
    assert core["metadata"]["provider_id"] == "operator-demo"
    assert core["metadata"]["connection_type"] == MARKER
    assert TOKEN not in json.dumps(workspace.rows(f.db, "credentials"))
    result = f.rule(application, credential)
    rule = result["access_rule"]
    route = next(item for item in f.signed()["routes"] if item["id"] == rule["route_id"])
    assert rule["operation_bundle"] == BUNDLE and rule["chain"] == CHAIN
    assert rule["upstream_url"] == ORIGIN + "/v2"
    assert rule["methods"] == ["POST"] and rule["request_fields"] == rule["response_fields"] == rule["query_keys"] == []
    assert rule["response_mode"] == "alchemy_rpc_read_json_v1"
    assert "request_body_mode" not in rule and "query_mode" not in rule
    assert route["match"] == {"scheme": "https", "host": "eth-mainnet.g.alchemy.com", "port": 443,
        "methods": ["POST"], "paths": ["/v2"]}
    assert route["credentialRef"] == credential["id"] and route["principals"] == [application["principal_id"]]
    assert route["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "Bearer serverware-alchemy-placeholder-v1"}
    assert route["adapter"]["type"] == "alchemy.rpc_read.v1"
    config = route["adapter"]["config"]
    assert set(config) == {"credentialBinding", "chain", "request", "response"}
    assert config["chain"] == CHAIN
    assert config["request"] == {"allowedHeaders": HEADERS, "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": [], "allowedMediaTypes": ["application/json"],
        "maxBodyBytes": 65536, "valueRules": []}
    assert config["response"] == {"mode": "alchemyRpcReadJsonV1", "maxBodyBytes": 65536,
        "contentTypes": ["application/json"], "allowedHeaders": [],
        "error": {"mode": "alchemyRpcReadJsonV1", "maxBodyBytes": 65536,
            "contentTypes": ["application/json"], "allowedHeaders": [], "onInvalid": "block"}}
    assert config["credentialBinding"] == {"credentialType": "static", "provider": "operator-demo",
        "subjects": [core["metadata"]["provider_subject"]], "secretClass": "bearerToken"}
    assert route["constraints"] == [{"id": route["id"] + ".envelope", "type": "responseEnvelope",
        "phase": "response", "statusCodes": [200, 400, 401, 403, 404, 429, 500, 502, 503, 504],
        "bodyPresence": "required", "contentTypes": ["application/json"],
        "allowedResponseHeaderNames": [], "responseHeaderRules": [],
        "unlistedHeaderPolicy": "discardUnselectedV1", "contentTypePolicy": "alchemyRpcReadJsonUtf8V1"}]
    assert rule["allowed_headers"] == HEADERS
    alchemy.validate_config(config)
    assert result["policy"]["activation"] == "pending" and result["policy"]["loaded_policy_hash"] is None
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["alchemy"] == {
        "schema": "serverware.operatorAlchemyRpcRead/v1", "connection_type": MARKER,
        "create_credential_path": "/api/operator-demo/credentials/alchemy-key",
        "create_rule_path": "/api/operator-demo/access-rules/alchemy-chain-status",
        "chains": [{"chain": CHAIN, "api_origin": ORIGIN, "destination_allowed": True},
            {"chain": OTHER_CHAIN, "api_origin": OTHER_ORIGIN, "destination_allowed": True}],
        "operation_bundles": [BUNDLE], "rpc_methods": ["eth_chainId", "eth_blockNumber"],
        "sdk_auth_token": "serverware-alchemy-placeholder-v1",
        "placeholder": "Bearer serverware-alchemy-placeholder-v1",
        "response_mode": "alchemy_rpc_read_json_v1", "source_pair_required": True}
    with closing(f.db.connect()) as conn:
        kinds = {row[0] for row in conn.execute("SELECT event_type FROM audit_events")}
    assert {"operator_catalog.credential.alchemy_key_created",
        "operator_catalog.access_rule.alchemy_chain_status_created"} <= kinds
    f.privacy(status)
    return {"signed_static_chain_status": True}


def inputs_and_cas():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    fields, before = f.fields(application, credential), f.snapshot()
    for chain in ("", "ETH-MAINNET", "eth-goerli", "polygon-mainnet", "eth-mainnet/", 1, None, True):
        refused(lambda chain=chain: f.inputs.AlchemyChainStatusRuleInput(**{**fields, "chain": chain}))
    for key, value in (("operation_bundle", "alchemy_rpc_write_v1"), ("methods", ["POST"]),
            ("upstream_url", ORIGIN + "/v2"), ("placeholder", "Bearer other"),
            ("rpc_methods", ["eth_chainId"]), ("query_keys", ["apikey"]), ("params", []),
            ("request_body_mode", "preserve_json_v1"), ("response_fields", ["data"]),
            ("credential_input", "insert"), ("expected_revision", True)):
        refused(lambda key=key, value=value: f.inputs.AlchemyChainStatusRuleInput(**{**fields, key: value}))
    for secret in ("", "contains space", "line\nbreak", "é", "x" * 8193):
        refused(lambda secret=secret: f.inputs.AlchemyKeyInput(**f.review(), name="Refused", secret=secret))
    assert TOKEN not in repr(f.inputs.AlchemyKeyInput(**f.review(), name="Hidden", secret=TOKEN))
    canary = "PRIVATE_ALCHEMY_INPUT_CANARY"
    for changes in ({"secret": canary + " invalid"}, {"unexpected": canary}):
        try:
            f.inputs.AlchemyKeyInput(**{**f.review(), "name": "Refused private input",
                "secret": TOKEN, **changes})
        except ValueError as error:
            assert canary not in str(error) and canary not in repr(error)
            assert TOKEN not in str(error) and TOKEN not in repr(error)
        else:
            raise AssertionError("private invalid Alchemy input admitted")
    assert f.snapshot() == before
    stale = f.inputs.AlchemyChainStatusRuleInput(**fields)
    f.rule(application, credential)
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.create_alchemy_rule, stale, ACTOR), f.schema.CatalogConflict)
    # Current gate/policy with an old revision reaches the actual mutation CAS,
    # independently of the early stale-policy capability refusal above.
    current = f.fields(application, credential)
    current["expected_revision"] -= 1
    refused(lambda: f.call(f.mutations.create_alchemy_rule,
        f.inputs.AlchemyChainStatusRuleInput(**current), ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    return {"strict_inputs_and_stale_replay": True}


def crossed():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    generic = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(),
        name="Unmarked static bearer", auth_type="bearer", secret=TOKEN), ACTOR)["credential"]
    github = f.call(f.mutations.create_github_credential, f.inputs.GithubTokenInput(**f.review(),
        name="Separate GitHub marker", secret=shared.TOKEN), ACTOR)["credential"]
    npm = f.call(f.mutations.create_npm_credential, f.inputs.NpmTokenInput(**f.review(),
        name="Separate npm marker", secret=TOKEN), ACTOR)["credential"]
    x = f.call(f.mutations.create_x_credential, f.inputs.XAppBearerInput(**f.review(),
        name="Separate X marker", secret=TOKEN), ACTOR)["credential"]
    before = f.snapshot()
    for wrong in (generic, github, npm, x): refused(lambda wrong=wrong: f.rule(application, wrong))
    refused(lambda: f.call(f.mutations.create_rule, f.inputs.RuleInput(**f.review(), name="No generic fallback",
        application_id=application["id"], credential_id=credential["id"],
        upstream_url=ORIGIN + "/v2", methods=["POST"], response_fields=["data"]), ACTOR))
    refused(lambda: f.call(f.mutations.create_github_rule, f.inputs.GithubRuleInput(**f.review(),
        name="No crossed GitHub grant", application_id=application["id"], credential_id=credential["id"],
        operation_bundle=shared.READ, repository=shared.REPOSITORY), ACTOR))
    refused(lambda: f.call(f.mutations.create_npm_rule, f.inputs.NpmMetadataRuleInput(**f.review(),
        name="No crossed npm grant", application_id=application["id"], credential_id=credential["id"],
        operation_bundle="npm_metadata_read_v1", packages=["serverware-fixture"]), ACTOR))
    refused(lambda: f.call(f.mutations.create_x_rule, f.inputs.XUsernameRuleInput(**f.review(),
        name="No crossed X grant", application_id=application["id"], credential_id=credential["id"],
        operation_bundle="x_username_read_v1", username="fixture_user"), ACTOR))
    assert f.snapshot() == before
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    for collection, identifier, changes in (
            ("credentials", credential["id"], {"connection_type": "github_token_v1"}),
            ("credentials", credential["id"], {"connection_type": "npm_token_v1"}),
            ("credentials", credential["id"], {"connection_type": "x_app_bearer_v1"}),
            ("credentials", credential["id"], {"connection_type": None}),
            ("credentials", credential["id"], {"connection_type": "unknown"}),
            ("access_rules", rule["id"], {"methods": ["GET", "POST"]}),
            ("access_rules", rule["id"], {"chain": OTHER_CHAIN}),
            ("access_rules", rule["id"], {"query_keys": ["apikey"]}),
            ("access_rules", rule["id"], {"rpc_methods": ["eth_sendRawTransaction"]}),
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
    for marker in (None, "unknown", "github_token_v1", "npm_token_v1", "x_app_bearer_v1"):
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
            conn.execute("CREATE TRIGGER alchemy_abort " + statement + " BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END")
        try:
            refused(lambda: f.rule(application, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before
        finally:
            with closing(f.db.connect()) as conn, conn: conn.execute("DROP TRIGGER alchemy_abort")
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
    chains = f.call(f.mutations.catalog_status)["capabilities"]["alchemy"]["chains"]
    assert chains == [{"chain": CHAIN, "api_origin": ORIGIN, "destination_allowed": False},
        {"chain": OTHER_CHAIN, "api_origin": OTHER_ORIGIN, "destination_allowed": True}]
    before = f.snapshot()
    refused(lambda: f.rule(application, credential))
    assert f.snapshot() == before
    # Approving Sepolia does not approve Mainnet. The selected approved chain
    # is independently usable with the very same previously saved key.
    fields = {**f.fields(application, credential), "chain": OTHER_CHAIN}
    result = f.call(f.mutations.create_alchemy_rule, f.inputs.AlchemyChainStatusRuleInput(**fields), ACTOR)
    assert result["access_rule"]["upstream_url"] == OTHER_ORIGIN + "/v2"
    f.signed()
    return {"destination_required": True}


def gate_refusals():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    create = f.inputs.AlchemyKeyInput(**f.review(), name="No unsupported save", secret=TOKEN)
    grant = f.inputs.AlchemyChainStatusRuleInput(**f.fields(application, credential))
    good = gate_payload(f.store)
    stale = "sha256:" + "0" * 64
    assert stale != good["policy_hash"]
    descriptors = [None, {}, [], {**GATE_DESCRIPTOR, "unknown": True},
        *({**GATE_DESCRIPTOR, field: value} for field, value in (
            ("schema", "serverware.operatorAlchemyRpcReadGate/v0"), ("adapter", "alchemy.v2"),
            ("operation", "alchemy.write"), ("schema", True))),
        *({key: value for key, value in GATE_DESCRIPTOR.items() if key != missing}
            for missing in GATE_DESCRIPTOR)]
    cases = [None, {}, {"ok": True, "policy_hash": good["policy_hash"]},
        {**good, "ok": False}, {**good, "ok": 1}, {**good, "policy_hash": "invalid"},
        {**good, "policy_hash": stale}, OSError("synthetic health unavailable"),
        *({**good, "operator_alchemy_rpc_read": item} for item in descriptors)]
    before = f.snapshot()
    for case in cases:
        with observed_gate(f.config, f.store, case) as clients, \
                patch.object(f.store, "loaded_policy_hash", return_value=None), \
                patch.object(f.mutations, "_mutate", side_effect=AssertionError("entered mutation before compatibility")) as mutate:
            refused(lambda: f.mutations.create_alchemy_credential(create, ACTOR), f.schema.CatalogConflict)
            assert len(clients) == 1
            refused(lambda: f.mutations.create_alchemy_rule(grant, ACTOR), f.schema.CatalogConflict)
            assert len(clients) == 2
            status = f.mutations.catalog_status()
            assert status["capabilities"]["alchemy"] is None
            assert len(clients) == 3  # Two mutations and one shared catalog observation.
            mutate.assert_not_called()
        assert f.snapshot() == before
    # Matching stale request and gate hashes still fail the real local SQL
    # re-read, before mutation; a hash agreement alone is not current authority.
    with observed_gate(f.config, f.store, {**good, "policy_hash": stale}) as clients, \
            patch.object(f.mutations, "_mutate", side_effect=AssertionError("stale local policy entered mutation")) as mutate:
        for function, payload in ((f.mutations.create_alchemy_credential, create), (f.mutations.create_alchemy_rule, grant)):
            refused(lambda function=function, payload=payload: function(
                payload.model_copy(update={"expected_policy_hash": stale}), ACTOR), f.schema.CatalogConflict)
        assert len(clients) == 2
        mutate.assert_not_called()
    with observed_gate(f.config, f.store) as clients, f.store.operator_publication.exclusive():
        refused(lambda: f.mutations.create_alchemy_credential(create, ACTOR), f.schema.CatalogConflict)
        refused(lambda: f.mutations.create_alchemy_rule(grant, ACTOR), f.schema.CatalogConflict)
        assert clients == [], "no health request may run under publication ownership"
    assert f.snapshot() == before
    assert f.call(f.mutations.catalog_status)["capabilities"]["alchemy"]["operation_bundles"] == [BUNDLE]
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
    fields = {**f.fields(application, second), "chain": OTHER_CHAIN}
    other = f.call(f.mutations.create_alchemy_rule, f.inputs.AlchemyChainStatusRuleInput(**fields), ACTOR)["access_rule"]
    routes = {row["id"]: row for row in f.signed()["routes"]}
    assert routes[rule["route_id"]]["credentialRef"] == first["id"]
    assert routes[other["route_id"]]["credentialRef"] == second["id"]
    assert len(routes) == 2
    before = f.snapshot()
    changed = deepcopy(f.catalog())
    next(row for row in changed["access_rules"] if row["id"] == other["id"]).update(
        chain=CHAIN, upstream_url=ORIGIN + "/v2")
    with closing(f.db.connect()) as conn:
        refused(lambda: f.schema.validate_bindings(conn, changed), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    # Another application is a distinct principal; it may explicitly receive
    # the same chain. Revoking the original also releases only its own slot.
    other_app = f.application()
    f.rule(other_app, second)
    f.call(f.mutations.revoke_rule, f.target(rule["id"]), ACTOR)
    replacement = f.rule(application, second)["access_rule"]
    assert replacement["id"] != rule["id"]
    # The existing signed-policy compiler, not a new catalog exception, owns
    # equal-specificity generic/typed route collisions. Prove both insertion
    # orders roll back rather than silently choosing a different credential.
    generic = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(),
        name="Separate explicit generic key", auth_type="bearer", secret=TOKEN), ACTOR)["credential"]
    def generic_rule(app):
        return f.call(f.mutations.create_rule, f.inputs.RuleInput(**f.review(),
            name="Explicit generic POST", application_id=app["id"], credential_id=generic["id"],
            upstream_url=ORIGIN + "/v2", methods=["POST"],
            request_body_mode="preserve_json_v1", response_mode="unfiltered_json_or_empty_v2"), ACTOR)
    before = f.snapshot()
    refused(lambda: generic_rule(application), f.bundles.PolicyBundleError)
    assert f.snapshot() == before
    manual_app = f.application()
    manual_rule = generic_rule(manual_app)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.rule(manual_app, first), f.bundles.PolicyBundleError)
    assert f.snapshot() == before
    f.call(f.mutations.revoke_rule, f.target(manual_rule["id"]), ACTOR)
    f.rule(manual_app, first)
    f.signed()
    return {"duplicate_typed_grants_refused": True}


def rpc_boundary():
    """Validate the fixed body grammar used by the actually signed adapter."""
    from serverware import alchemy_rpc_read as alchemy
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    f.rule(application, credential)
    before = f.snapshot()
    headers = {"content-type": "application/json; charset=utf-8", "accept": "*/*"}
    value = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    for method in ("eth_chainId", "eth_blockNumber"):
        for request_id in (0, (1 << 53) - 1, "rpc-1"):
            raw = json.dumps({**value, "method": method, "id": request_id}).encode()
            assert alchemy.validate_request("POST", ORIGIN + "/v2", raw, chain=CHAIN,
                headers=headers) == {"operation": "alchemy.rpc.read", "chain": CHAIN,
                    "method": method, "requestId": request_id}
    raw = json.dumps(value).encode()
    padded = raw + b" " * (65536 - len(raw))
    alchemy.validate_request("POST", ORIGIN + "/v2", padded, chain=CHAIN, headers=headers)
    refused(lambda: alchemy.validate_request("POST", ORIGIN + "/v2", padded + b" ", chain=CHAIN))
    for url in (ORIGIN + "/v2?", ORIGIN + "/v2?apikey=dummy", ORIGIN + "/v2/",
            ORIGIN + "/v2/dummy", OTHER_ORIGIN + "/v2", ORIGIN + "/v2#fragment"):
        refused(lambda url=url: alchemy.validate_request("POST", url, raw, chain=CHAIN))
    for method in ("GET", "PUT", "DELETE"):
        refused(lambda method=method: alchemy.validate_request(method, ORIGIN + "/v2", raw, chain=CHAIN))
    for document in ([value], {key: item for key, item in value.items() if key != "id"},
            {**value, "method": "eth_sendRawTransaction"}, {**value, "method": "eth_getBalance"},
            {**value, "params": ["0x0"]}, {**value, "params": {}}, {**value, "jsonrpc": "1.0"},
            {**value, "id": True}, {**value, "id": None}, {**value, "id": 1.0},
            {**value, "id": (1 << 53)}, {**value, "id": ""}, {**value, "extra": True}):
        encoded = json.dumps(document).encode()
        refused(lambda encoded=encoded: alchemy.validate_request("POST", ORIGIN + "/v2", encoded, chain=CHAIN))
    for encoded in (b'{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_chainId","params":[]}',
            b'\xff', b'{', b''):
        refused(lambda encoded=encoded: alchemy.validate_request("POST", ORIGIN + "/v2", encoded, chain=CHAIN))
    assert f.snapshot() == before
    return {"signed_rpc_body_and_empty_query_boundary": True}


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
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    with observed_gate(config, store), patch.object(store, "loaded_policy_hash", return_value=None):
        result = mutations.create_alchemy_credential(inputs.AlchemyKeyInput(**workspace.review(db, store, schema),
            name="New separate Alchemy key", secret=TOKEN), ACTOR)
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
    "gate": gate_refusals, "coexistence": coexistence, "rpc": rpc_boundary}


class OperatorCatalogAlchemyTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(
            ["https://api.example.com", "https://api.github.com", "https://registry.npmjs.org",
                "https://api.x.com", ORIGIN, OTHER_ORIGIN])

    def worker(self, name):
        environment = dict(self.environment)
        if name == "destination":
            environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(["https://api.example.com", OTHER_ORIGIN])
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail("isolated Alchemy catalog worker refused: " + shared.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_signed_static_chain_status_and_private_custody(self): self.assertTrue(self.worker("signed")["signed_static_chain_status"])
    def test_strict_inputs_and_stale_cas_replay(self): self.assertTrue(self.worker("inputs")["strict_inputs_and_stale_replay"])
    def test_crossed_markers_and_generic_fallback_refused(self): self.assertTrue(self.worker("crossed")["crossed_markers_refused"])
    def test_actual_rotation_and_explicit_revocation(self): self.assertTrue(self.worker("replacement")["generation_rotation_and_explicit_revocation"])
    def test_rollback_and_postcommit_pending(self): self.assertTrue(self.worker("failures")["rollback_and_durable_pending"])
    def test_destination_required_even_after_key_saved(self): self.assertTrue(self.worker("destination")["destination_required"])
    def test_retained_restart_in_fresh_process(self): self.assertEqual(self.worker("seed"), self.worker("reopen"))
    def test_legacy_rows_and_authority_unchanged(self): self.assertTrue(self.worker("legacy")["legacy_authority_unchanged"])
    def test_gate_compatibility_is_current_closed_and_prewrite(self): self.assertTrue(self.worker("gate")["unsupported_pair_refused_before_writes"])
    def test_duplicate_typed_grants_and_disjoint_chains(self): self.assertTrue(self.worker("coexistence")["duplicate_typed_grants_refused"])
    def test_signed_rpc_body_and_empty_query_boundary(self): self.assertTrue(self.worker("rpc")["signed_rpc_body_and_empty_query_boundary"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try: outcome = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(shared.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else: unittest.main(verbosity=2)
