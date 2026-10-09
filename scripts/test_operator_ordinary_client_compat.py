#!/usr/bin/env python3
"""Prepared ordinary-client compatibility checks; not actual-proxy acceptance.

Synthetic lower-level cases call the real compiler, mitmproxy objects, adapters
and engine guards. Two catalog children use real SQLite/encryption/signing;
the third checks input DTOs only. Nothing
here contacts a provider, starts a proxy, consumes an approval, or proves Rust
wire parsing. In particular, exposed 204 bytes/framing can be checked; bytes a
transport parser has already hidden require separate connection-isolation proof.
Run only after source freeze/review in the bounded network-none test container.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import ordinary_client_compat_fixtures as fx
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]


class OrdinaryClientLowerLevelTests(unittest.TestCase):
    def setUp(self):
        self.adapters, self.engine, self.adapter = fx.runtime()
        self.snapshot = fx.compile_snapshot()
        self.route = self.snapshot.routes[0]

    def admit_request(self, flow, route=None):
        route = self.route if route is None else route
        normalized = self.engine._normalized_request_headers(flow)
        for check in (
            lambda: self.adapters.preflight_request_admission(flow, route, normalized),
            lambda: self.adapter.validate_request(flow, route, {}),
            lambda: self.adapter.rewrite_request(flow, route, {}),
        ):
            decision = check()
            if not decision.allowed:
                return decision
        return decision

    def admit_response(self, flow, route=None):
        route = self.route if route is None else route
        for check in (
            lambda: self.engine._validate_response_content_encoding(flow),
            lambda: self.engine._evaluate_response_envelope(flow, route),
            lambda: self.adapter.prepare_response(flow, route, {}),
            lambda: self.adapter.validate_response(flow, route, {}),
        ):
            decision = check()
            if not decision.allowed:
                return decision
        return decision

    def test_request_exact_bytes_and_explicit_empty_get_delete(self):
        bodies = (b'{ "z": [1e+02, 18446744073709551617], "a": "\\u0061\\/b" }\r\n',
            b'[true, null, {"deep": [1, 2]}]', b'"caf\\u00e9"', b'"\\ud83d\\ude00"',
            b"1.2300", b"-0.0", b"1e308", b"true")
        for raw in bodies:
            with self.subTest(case="nonempty", size=len(raw)):
                flow = fx.request_flow(raw)
                self.assertTrue(self.admit_request(flow).allowed)
                self.assertEqual(flow.request.raw_content, raw)
                self.assertEqual(self.adapter.operation_fields(flow, self.route, {})["payloadDigest"],
                    "sha256:" + hashlib.sha256(raw).hexdigest())
        for method in ("GET", "DELETE"):
            for fields in ([], [(b"Content-Type", b"application/json")]):
                with self.subTest(method=method, declared_type=bool(fields)):
                    flow = fx.request_flow(b"", fields=fields)
                    flow.request.method = method
                    self.assertTrue(self.admit_request(flow).allowed)
                    self.assertEqual(flow.request.raw_content, b"")
                    self.assertEqual(self.adapter.operation_fields(flow, self.route, {})["payloadDigest"],
                        "sha256:" + hashlib.sha256(b"").hexdigest())

    def test_request_strict_json_media_utf8_and_size_refuse(self):
        invalid = (b" ", b"\r\n\t", b"{", b"{} trailing", b'{"a":1,"a":2}',
            b'{"nested":{"x":1,"x":2}}', b"NaN", b"Infinity", b"1e309", b"-0", b'{"x":-0}',
            b'"\xff"', b'"\\ud800"', b'{"\\ud800":1}', b'"raw\nnewline"')
        for index, raw in enumerate(invalid):
            with self.subTest(json_case=index):
                decision = self.admit_request(fx.request_flow(raw))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status_code, 400)
        for fields in ([], [(b"Content-Type", b"text/plain")],
                [(b"Content-Type", b"application/json;")],
                [(b"Content-Type", b"application/json; charset=utf-8; charset=utf-8")]):
            with self.subTest(media_case=fields):
                self.assertFalse(self.admit_request(fx.request_flow(b"{}", fields=fields)).allowed)
        flow = fx.request_flow(b'"' + b"a" * 1023 + b'"')
        self.assertEqual(self.admit_request(flow).status_code, 413)
        at_limit = b'"' + b"a" * 1022 + b'"'
        self.assertTrue(self.admit_request(fx.request_flow(at_limit)).allowed)
        self.assertFalse(self.admit_request(fx.request_flow(b"", fields=[(b"Content-Type", b"text/plain")])).allowed)

    def test_request_depth_bound_ignores_quoted_brackets_and_escapes(self):
        at_limit = b"[" * 127 + b"0" + b"]" * 127
        too_deep = b"[" * 128 + b"0" + b"]" * 128
        self.assertTrue(self.admit_request(fx.request_flow(at_limit)).allowed)
        self.assertFalse(self.admit_request(fx.request_flow(too_deep)).allowed)
        quoted = json.dumps({"text": "[" * 128 + '"\\' + "]" * 128}).encode()
        flow = fx.request_flow(quoted)
        self.assertTrue(self.admit_request(flow).allowed)
        self.assertEqual(flow.request.raw_content, quoted)

    def test_request_physical_headers_framing_and_encoding_refuse(self):
        for field in ((b"Content-Length", b"0"), (b"Content-Length", b"03"),
                (b"Content-Length", b"+2"), (b"Transfer-Encoding", b"chunked"),
                (b"Content-Encoding", b"gzip")):
            with self.subTest(field=field):
                decision = self.admit_request(fx.request_flow(b"{}",
                    fields=[(b"Content-Type", b"application/json"), field]))
                self.assertFalse(decision.allowed)
        for name, value in ((b"Content-Type", b"application/json"), (b"Content-Length", b"2")):
            with self.subTest(duplicate=name):
                flow = fx.request_flow(b"{}", fields=[(name, value), (name.lower(), value)])
                with self.assertRaises(ValueError):
                    self.engine._normalized_request_headers(flow)
        self.assertTrue(self.admit_request(fx.request_flow(b"{}", fields=[
            (b"Content-Type", b"application/json"), (b"Content-Length", b"2")])).allowed)

    def test_approval_digest_seam_binds_exact_bytes_not_json_equivalence(self):
        # These are the real canonical/digest/recheck seams, not a claim that an
        # approval was issued/consumed or that a credential was dispatched.
        flow = fx.request_flow(b'{"a":1}')
        self.assertTrue(self.admit_request(flow).allowed)
        credential = self.snapshot.credentials[self.route.credential_ref]
        def canonical():
            return self.engine._canonical_request(flow,
                principal=self.snapshot.principals[self.route.principals[0]], route=self.route,
                credential_version="7", policy_hash=self.snapshot.hash,
                operation_fields=self.adapter.operation_fields(flow, self.route, {}),
                forwarded_headers=self.engine._canonical_forwarded_request_headers(flow, credential),
                discard_headers=())
        before = canonical()
        self.assertEqual(before["request"]["body_sha256"], "sha256:" + hashlib.sha256(b'{"a":1}').hexdigest())
        self.assertTrue(self.engine._provider_request_matches_canonical(flow, before, credential))
        flow.request.raw_content = b'{ "a": 1 }'
        self.assertEqual(json.loads(flow.request.raw_content), {"a": 1})
        self.assertTrue(self.admit_request(flow).allowed)
        after = canonical()
        self.assertNotEqual(self.engine._digest(before), self.engine._digest(after))
        self.assertNotEqual(self.engine._operation_digest(before), self.engine._operation_digest(after))
        self.assertFalse(self.engine._provider_request_matches_canonical(flow, before, credential))
        self.assertTrue(self.engine._provider_request_matches_canonical(flow, after, credential))

    def test_compiler_and_runtime_refuse_contradictory_request_profiles(self):
        from serverware.policy_bundle import PolicyBundleError
        changes = ({"allowedFields": []}, {"allowedFields": ["a"]}, {"maxRecordBytes": 64},
            {"allowedMediaTypes": ["text/plain"]}, {"maxBodyBytes": 0},
            {"maxBodyBytes": True}, {"maxBodyBytes": 16777217},
            {"operation": {"name": "fixture.read", "jsonFields": []}},
            {"operation": {"name": "fixture.read", "formFields": []}})
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                with self.assertRaises(PolicyBundleError):
                    fx.compile_snapshot(fx.with_request_change(change))
                forged = deepcopy(self.route)
                forged.adapter_config["request"].update(change)
                self.assertFalse(self.adapter.validate_request(fx.request_flow(b"{}"), forged, {}).allowed)
                self.assertFalse(self.adapter.rewrite_request(fx.request_flow(b"{}"), forged, {}).allowed)
        for kind in ("jsonBody", "formBody"):
            constraint = {"id": "conflict", "type": kind, "allowedFields": ["a"]}
            value = fx.document()
            value["routes"][0]["constraints"].append(constraint)
            with self.subTest(constraint=kind), self.assertRaises(PolicyBundleError):
                fx.compile_snapshot(value)
            forged = replace(self.route, constraints=(*self.route.constraints, constraint))
            self.assertFalse(self.adapter.validate_request(fx.request_flow(b"{}"), forged, {}).allowed)
        for source in ("jsonBody", "formBody"):
            value = fx.document()
            value["routes"][0]["constraints"].append({"id": "typed-conflict", "type": "requestValue",
                "rules": [{"source": source, "name": "a", "predicate": {"kind": "equals", "value": "x"}}]})
            with self.subTest(source=source), self.assertRaises(PolicyBundleError):
                fx.compile_snapshot(value)

    def test_204_absent_or_json_metadata_preserves_empty_without_framing(self):
        for media in (None, b"application/json", b'Application/JSON; charset="utf-8"'):
            fields = [] if media is None else [(b"Content-Type", media)]
            with self.subTest(media=media):
                flow = fx.response_flow(b"", status=204, fields=fields)
                self.assertTrue(self.admit_response(flow).allowed)
                self.assertEqual(flow.response.raw_content, b"")
                self.assertNotIn("content-length", flow.response.headers)
                self.assertNotIn("transfer-encoding", flow.response.headers)
                self.assertEqual(flow.response.headers.get("content-type"), None if media is None else media.decode())

    def test_204_exposed_body_framing_media_and_trailers_refuse(self):
        from mitmproxy import http
        cases = [(b"x", [], None), (b"{}", [], None), (b"", [(b"Content-Length", b"0")], None),
            (b"", [(b"Content-Length", b"1")], None), (b"", [(b"Transfer-Encoding", b"chunked")], None),
            (b"", [(b"Content-Type", b"text/plain")], None),
            (b"", [(b"Content-Type", b"application/json; charset=utf-8; charset=utf-8")], None),
            (b"", [(b"Content-Type", b"application/json"), (b"content-type", b"application/json")], None),
            (b"", [], http.Headers([(b"X-Extra", b"synthetic")]))]
        for index, (body, fields, trailers) in enumerate(cases):
            with self.subTest(case=index):
                flow = fx.response_flow(body, status=204, fields=fields, trailers=trailers)
                self.assertFalse(self.engine._evaluate_response_envelope(flow, self.route).allowed)
                self.assertFalse(self.adapter.validate_response(flow, self.route, {}).allowed)

    def test_other_statuses_require_strict_bounded_json_and_preserve_exact_bytes(self):
        raw = b' \n{"nested": [1e+02, 18446744073709551617], "s":"\\u0061"}\t'
        for status in (200, 201, 400, 500):
            with self.subTest(status=status):
                flow = fx.response_flow(raw, status=status)
                self.assertTrue(self.admit_response(flow).allowed)
                self.assertEqual(flow.response.raw_content, raw)
                self.assertEqual(flow.response.headers["content-length"], str(len(raw)))
                for invalid in (b"", b" ", b'{"a":1,"a":2}', b'"\xff"', b"NaN", b'"\\ud800"', b"{}junk"):
                    self.assertFalse(self.admit_response(fx.response_flow(invalid, status=status)).allowed)
        for status in (100, 205, 302, 304, 418, 600):
            with self.subTest(status=status):
                self.assertFalse(self.admit_response(fx.response_flow(b"{}", status=status)).allowed)
        for status in (200, 400):
            self.assertFalse(self.admit_response(fx.response_flow(b'"' + b"a" * 1024 + b'"', status=status)).allowed)

    def test_response_contract_is_paired_and_envelopes_do_not_relax_old_modes(self):
        from serverware.policy_bundle import PolicyBundleError, compile_policy_bundle
        for change in ({"bodyPresence": "required"}, {"contentTypes": []}, {"statusCodes": [200]},
                {"statusCodes": [200, 204, 205]}, {"statusCodes": [204, 302]}):
            value = fx.document()
            value["routes"][0]["constraints"][0].update(change)
            with self.subTest(change=change), self.assertRaises(PolicyBundleError):
                fx.compile_snapshot(value)
        for error_mode in ("json", "bufferedPassthrough"):
            value = fx.document()
            fx.response_config(value)["error"]["mode"] = error_mode
            with self.subTest(error_mode=error_mode), self.assertRaises(PolicyBundleError):
                fx.compile_snapshot(value)
        old = fx.compile_snapshot(fx.document(new_request=False, new_response=False)).routes[0]
        self.assertFalse(self.admit_request(fx.request_flow(b"{}"), old).allowed)
        self.assertFalse(self.admit_response(fx.response_flow(b"", status=204, fields=[]), old).allowed)
        self.assertTrue(self.admit_response(fx.response_flow(b'{"unchanged":1}'), old).allowed)
        import test_buffered_passthrough_response as buffered
        projected = buffered.compile_route(buffered.bundle(buffered.projected()))
        flow = fx.response_flow(b'{"keep":1,"extra":2}')
        self.assertTrue(self.admit_response(flow, projected).allowed)
        self.assertEqual(json.loads(flow.response.raw_content), {"keep": 1})
        for mode in ("json", "headersOnly", "bufferedPassthrough"):
            profile = buffered.passthrough() if mode == "bufferedPassthrough" else buffered.projected()
            if mode == "headersOnly":
                profile.update(mode=mode, maxBodyBytes=0, contentTypes=[])
                del profile["allowedFields"]
            control = buffered.bundle(profile)
            envelope = control["routes"][0]["constraints"][0]
            if mode == "headersOnly":
                envelope.update(statusCodes=[204], bodyPresence="forbidden", contentTypes=[])
            invalid = deepcopy(control)
            new_envelope = invalid["routes"][0]["constraints"][0]
            new_envelope.update(bodyPresence=fx.PRESENCE, contentTypes=["application/json"])
            if 204 not in new_envelope["statusCodes"]:
                new_envelope["statusCodes"].append(204)
            for validate_schema in (True, False):
                with self.subTest(reverse_mode=mode, schema=validate_schema):
                    compile_policy_bundle(control, validate_schema=validate_schema)
                    with self.assertRaises(PolicyBundleError):
                        compile_policy_bundle(invalid, validate_schema=validate_schema)

    def test_new_whole_response_rejects_durable_claims_with_valid_old_control(self):
        import test_buffered_passthrough_response as buffered
        from serverware.policy_bundle import PolicyBundleError
        value = buffered.bundle(buffered.projected())
        value["routes"][0]["constraints"].append({"id": "fixture.durable", "type": "slidingWindowLimit",
            "max": 5, "windowSeconds": 3600, "windowSemantics": "sliding", "measure": "operationCount",
            "reservationMode": "atomicReserveCommitRelease", "onOverflow": "deny", "store": "shared",
            "key": {"scope": ["route", "operation"], "operationFields": ["providerAccount"]}})
        fx.compile_snapshot(value)  # Prove the negative fixture is otherwise admissible.
        value["routes"][0]["adapter"]["config"]["response"] = fx.response_config(fx.document())
        value["routes"][0]["constraints"][0].update(bodyPresence=fx.PRESENCE, statusCodes=[200, 204, 400, 500])
        with self.assertRaises(PolicyBundleError):
            fx.compile_snapshot(value)

    def test_legacy_transport_refuses_new_204_but_keeps_old_credentialless_profile(self):
        # The real admission boundary refuses a transport capability it cannot
        # prove. This does not claim observation of parser-hidden 204 bytes.
        for new_response in (False, True):
            value = fx.document(new_request=False, new_response=new_response)
            value["credentials"] = []
            route_value = value["routes"][0]
            del route_value["credentialRef"]
            config = route_value["adapter"]["config"]
            del config["credentialBinding"]
            config.update(credentialMode="none", noCredentialProof={
                "credentialRefAbsent": True, "secretInjectionDisabled": True,
                "sensitiveHeadersForwarded": False, "authorizationForwarded": False})
            route = fx.compile_snapshot(value).routes[0]
            self.assertIsNone(route.credential_ref)
            self.assertIsNone(route.credential_header)
            self.assertIsNone(route.resolved_cidrs)
            flow = fx.request_flow(b"", fields=[])
            self.assertIsNone(self.engine._legacy_mitm_route_admission(flow, route))
            flow.metadata[self.engine.LEGACY_MITM_TRANSPORT_METADATA_KEY] = True
            decision = self.engine._legacy_mitm_route_admission(flow, route)
            if new_response:
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status_code, 503)
                self.assertEqual(decision.payload, {"error": "python_json_or_empty_204_transport_unsupported"})
            else:
                self.assertIsNone(decision)


def catalog_inputs():
    from pydantic import ValidationError
    from serverware.operator_catalog_inputs import RuleInput
    values = fx.input_values()
    accepted = RuleInput(**values)
    assert accepted.request_body_mode == fx.REQUEST_API_MODE
    assert RuleInput(**{**values, "response_mode": "projected_json", "response_fields": ["status"]}).response_mode == "projected_json"
    response_only = {key: item for key, item in values.items() if key != "request_body_mode"}
    assert "request_body_mode" not in RuleInput(**{**response_only, "request_fields": ["message"]}).model_fields_set
    legacy = {key: item for key, item in values.items() if key not in {"request_body_mode", "response_mode"}}
    legacy["response_fields"] = ["status"]
    assert "request_body_mode" not in RuleInput(**legacy).model_fields_set
    for change in ({"request_body_mode": None}, {"request_body_mode": "restricted_json"},
            {"request_body_mode": True}, {"request_fields": ["message"]},
            {"response_fields": ["status"]}, {"response_mode": None}):
        fx.refused(lambda: RuleInput(**{**values, **change}), ValidationError)
    return {"strict_inputs": True}


def catalog_migration():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    before, original = workspace.snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    high_water = store.get_policy_high_water()
    workspace.migrate(db, schema)
    assert workspace.snapshot(db) == before and config.POLICY_BUNDLE_PATH.read_bytes() == original
    assert store.get_policy_high_water() == high_water
    old = workspace.catalog(db, schema)
    assert all("request_body_mode" not in rule for rule in old["access_rules"])
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    values = {**fx.input_values(), **workspace.review(db, store, schema),
        "application_id": old["applications"][0]["id"], "credential_id": old["credentials"][0]["id"]}
    created = mutations.create_rule(inputs.RuleInput(**values), workspace.common._ACTOR)
    assert created["access_rule"]["request_body_mode"] == fx.REQUEST_API_MODE
    assert created["access_rule"]["response_mode"] == fx.RESPONSE_API_MODE
    current = workspace.catalog(db, schema)
    assert current["access_rules"][:2] == old["access_rules"]
    assert current["credentials"] == old["credentials"] and current["applications"] == old["applications"]
    signed = workspace.verify_signed(config, db, store, bundles)
    assert signed["routes"][:2] == json.loads(original)["routes"]
    route = signed["routes"][2]
    request, response = route["adapter"]["config"]["request"], route["adapter"]["config"]["response"]
    assert request["bodyMode"] == fx.REQUEST_MODE and request["maxBodyBytes"] == 65536
    assert request["allowedMediaTypes"] == ["application/json"] and "allowedFields" not in request
    assert not any(item["type"] == "jsonBody" for item in route["constraints"])
    assert response["mode"] == response["error"]["mode"] == fx.RESPONSE_MODE
    assert response["maxBodyBytes"] == 1048576 and response["error"]["maxBodyBytes"] == 65536
    assert all(item["bodyPresence"] == fx.PRESENCE and 204 in item["statusCodes"]
        for item in route["constraints"] if item["type"] == "responseEnvelope")
    from serverware import operator_catalog_policy as policy
    state = workspace.rows(db, "operator_demo_policy")[0]
    for request_only in (False, True):
        independent = deepcopy(current)
        record = independent["access_rules"][2]
        if request_only:
            record.update(response_mode="projected_json", response_fields=["status"])
        else:
            del record["request_body_mode"]
            record["request_fields"] = ["message"]
        rendered = policy.render(independent, state["sequence"], state["initial_hash"])
        compiled = bundles.compile_policy_bundle(rendered, validate_schema=True)
        paired = compiled.routes[2].adapter_config
        assert paired["request"]["bodyMode"] == (fx.REQUEST_MODE if request_only else "json")
        assert paired["response"]["mode"] == ("json" if request_only else fx.RESPONSE_MODE)
    for change in ({"request_body_mode": None}, {"request_fields": ["message"]},
            {"response_mode": "unknown"}, {"response_fields": ["status"]}):
        invalid = deepcopy(current)
        invalid["access_rules"][2].update(change)
        with closing(db.connect()) as conn:
            fx.refused(lambda: schema.validate_bindings(conn, invalid), schema.CatalogIntegrityError)
        fx.refused(lambda: policy.render(invalid, state["sequence"], state["initial_hash"]), schema.CatalogIntegrityError)
    saved, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == saved and config.POLICY_BUNDLE_PATH.read_bytes() == raw
    with patch.object(store, "loaded_policy_hash", return_value=None):
        status = mutations.catalog_status()
    assert all("request_body_mode" not in item for item in status["access_rules"][:2])
    assert status["capabilities"]["request_body_modes"] == [fx.REQUEST_API_MODE]
    assert status["capabilities"]["response_modes"] == ["projected_json", "unfiltered_json", fx.RESPONSE_API_MODE]
    return {"migration_preserved": True, "new_route_compiled": True}


def catalog_invalid_and_rollback():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    legacy = workspace.create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    assert "request_body_mode" not in legacy["access_rule"]
    stored_legacy = workspace.catalog(db, schema)["access_rules"][0]
    assert "request_body_mode" not in stored_legacy
    legacy_request = workspace.verify_signed(config, db, store, bundles)["routes"][0]["adapter"]["config"]["request"]
    assert legacy_request["bodyMode"] == "none" and legacy_request["maxBodyBytes"] == 0
    values = {**fx.input_values(), **workspace.review(db, store, schema),
        "application_id": application["id"], "credential_id": credential["id"]}
    for change in ({"request_body_mode": None}, {"request_body_mode": "unknown"},
            {"request_fields": ["message"]}, {"response_fields": ["status"]}):
        fx.refused(lambda: schema.rule_content_modes({**values, **change}), schema.CatalogIntegrityError)
    fx.refused(lambda: schema.rule_request_body_mode(values, {"auth_type": "google_oauth"}),
        schema.CatalogIntegrityError)
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    with closing(db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER ordinary_client_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.access_rule.created' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic ordinary client audit refusal'); END")
    fx.refused(lambda: mutations.create_rule(inputs.RuleInput(**values), workspace.common._ACTOR), sqlite3.IntegrityError)
    assert workspace.snapshot(db, catalog=True) == before and config.POLICY_BUNDLE_PATH.read_bytes() == raw
    workspace.verify_signed(config, db, store, bundles)
    return {"contradictions_refused": True, "atomic_rollback": True}


class OrdinaryClientCatalogTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_catalog_strict_opt_in_and_absent_default(self):
        self.assertTrue(self.worker("inputs")["strict_inputs"])

    def test_catalog_migration_new_signed_modes_and_reinitialize_preserve_legacy(self):
        self.assertTrue(self.worker("migration")["migration_preserved"])

    def test_catalog_contradictions_google_join_and_atomic_audit_rollback(self):
        self.assertTrue(self.worker("rollback")["atomic_rollback"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        operations = {"inputs": catalog_inputs, "migration": catalog_migration,
            "rollback": catalog_invalid_and_rollback}
        print(json.dumps(operations[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
