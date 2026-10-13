"""Inert protocol/oracle controls, not actual browser/backend/proxy acceptance."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_operator_guided as checker
from scripts import operator_guided_browser as wire
from scripts.check_operator_demo import CheckFailure

IDS = {key: f"00000000-0000-4000-8000-{n:012d}" for n, key in enumerate(("credential", "application", "rule"), 1)}
TOKEN = "s" * 43
SECRET = "synthetic-operator-" + "p" * 43
RUN = "operator-check-" + "1" * 32
DIGESTS = ["sha256:" + str(n) * 64 for n in range(8)]
INITIAL = {"revision": 1, "policy": {"policy_hash": DIGESTS[1], "sequence": 1}}
SCOPE = ("agent:operator-demo:" + IDS["application"], "operator." + IDS["rule"], DIGESTS[2])


def frame(identifier, method="GET", path="/", value=None):
    return {"kind": "request", "id": identifier, "method": method, "path": path,
        "headers": {} if method == "GET" else {"origin": wire.ORIGIN, "content-type": "application/json"},
        "body": base64.b64encode(b"" if value is None else wire.encoded(value)).decode()}


def browser():
    return {"postCount": 6, "getCount": 14, "pageErrors": 0, "consoleErrors": 0, "refusedRequests": 0,
        "downloadCount": 1, "downloadDeleted": True, "tokenCleared": True,
        "steps": ["credential", "application", "permission", "download", "proxy_success", "rule_revoked",
                  "proxy_denied", "application_revoked", "credential_revoked"]}


def configuration():
    # Independent literal matching the actual public download producer.
    return {"application_id": IDS["application"], "access_rule_id": IDS["rule"],
        "proxy_url": "https://serverware-gmail-proxy.example.com", "upstream_url": "https://demo-upstream:8443/echo",
        "methods": ["POST"], "response_mode": "unfiltered_json_or_empty_v2", "credential_input": "replace_exact",
        "request_headers": {"Authorization": "Bearer SERVERWARE_DUMMY"}, "ca_file": "/client-trust/inner-ca.pem",
        "token_expires_at_epoch_ms": 2000000000000,
        "note": "Private development client configuration. Never commit or share. Provider credential not included.",
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": IDS["application"], "proxy_password": TOKEN,
        "request_body_mode": "preserve_json_v1"}


def positive():
    return {"case": "positive", "status": 200, "responseMode": "unfiltered_json_or_empty_v2",
        "responseBodySha256": DIGESTS[4], "responseBodyBytes": 301,
        "requestDigest": DIGESTS[5], "operationDigest": DIGESTS[6]}


def audit_rows():
    common = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": SCOPE[2],
        "credential_ref": IDS["credential"], "credential_version": 1, "method": "POST",
        "body_sha256": checker.sha(wire.BODY), "request_digest": DIGESTS[5], "operation_digest": DIGESTS[6],
        "attempt_id": DIGESTS[7], "flow_id": DIGESTS[7]}
    return [{"id": IDS["credential"], "event_type": checker.START, "event": {**common, "outcome": "release_started"}},
        {"id": IDS["application"], "event_type": checker.RELEASE, "event": {**common, "outcome": "released",
            "upstream_status": 200, "response_body_sha256": DIGESTS[4], "response_body_bytes": 301,
            "response_validation": {"ok": True, "mode": "bufferedJsonOrEmpty204V2", "body_bytes_preserved": True}}}]


def result():
    operations = [(0, False), (1, False), (2, False), (2, True), (1, True), (0, True)]
    mutations = [{"route": wire.PREFIX + wire.ROUTES[index] + ("/revoke" if revoke else ""),
        "status": 200 if revoke else 201, "revision": ordinal + 2,
        "resourceId": IDS[("credential", "application", "rule")[index]],
        "policyHash": DIGESTS[1] if ordinal < 2 else DIGESTS[2] if ordinal == 2 else DIGESTS[3]}
        for ordinal, (index, revoke) in enumerate(operations)]
    counts = {"operator_catalog." + wire.KINDS[index] + (".revoked" if revoke else ".created"): 1
              for index, revoke in operations}
    counts.update({checker.START: 1, checker.RELEASE: 1, checker.CONNECT: 1, checker.CONNECT_DENIED: 1,
                   checker.RELOAD: 2, checker.LEASE: 2})
    return {"schema": checker.SCHEMA, "ok": True, "syntheticOnly": True, "realProviderVerified": False,
        "publicDnsVerified": False, "externalSsoVerified": False, "productionReady": False, "hardwareVerified": False,
        "runId": RUN, "dataPlaneBinaryDigest": DIGESTS[0], "resourceIds": IDS.copy(), "initialRevision": 1,
        "finalRevision": 7, "initialPolicyHash": DIGESTS[1], "policyHash": DIGESTS[3], "providerArrivals": 1,
        "proxyAttempts": 2, "mutations": mutations, "positive": positive(),
        "negative": {"outcome": "denied", "connectStatus": 403, "providerArrivals": 0},
        "audit": {"eventCounts": counts, "eventIds": [f"00000000-0000-4000-8000-{n:012d}"
            for n in range(100, 100 + sum(counts.values()))], "attemptIds": [DIGESTS[7]], "chainVerified": True},
        "browser": browser()}


class GuidedProtocolTests(unittest.TestCase):
    def protocol(self):
        return wire.Protocol(RUN, SECRET)

    def create_key(self, protocol):
        protocol.admit(frame(1), INITIAL)
        value = {"name": protocol.names["credential"], "auth_type": "bearer", "header_name": "Authorization",
                 "secret": SECRET, "expected_revision": 1, "expected_policy_hash": DIGESTS[1]}
        return frame(2, "POST", wire.PREFIX + "/credentials", value)

    def test_ready_exposes_only_private_fixture_inputs_and_literal_rule(self):
        ready = self.protocol().ready(INITIAL)
        self.assertEqual(ready["providerSecret"], SECRET)
        self.assertEqual(ready["timeoutSeconds"], 180)
        self.assertEqual(ready["tokenTtlSeconds"], 3600)
        self.assertEqual(ready["origin"], "https://serverware-guided.example.com")
        self.assertEqual(wire.rule_values("Rule", IDS["application"], IDS["credential"]), {
            "name": "Rule", "application_id": IDS["application"], "credential_id": IDS["credential"],
            "upstream_url": "https://demo-upstream:8443/echo", "methods": ["POST"], "request_fields": [],
            "response_fields": [], "request_body_mode": "preserve_json_v1", "response_mode": "unfiltered_json_or_empty_v2",
            "credential_input": "replace_exact", "placeholder": "Bearer SERVERWARE_DUMMY",
            "query_keys": ["expectedAuthorizationSha256"], "allowed_headers": ["accept", "accept-encoding", "user-agent"]})

    def test_permission_admits_only_the_reviewed_curl_header_roster(self):
        for headers in (["accept", "accept-encoding", "user-agent"], ["accept", "user-agent"],
                        ["accept", "accept-encoding", "user-agent", "cookie"]):
            protocol = self.protocol()
            protocol.documents, protocol.posts = 1, 2
            protocol.identifiers.update(credential=IDS["credential"], application=IDS["application"])
            current = {"revision": 3, "policy": INITIAL["policy"]}
            value = {**wire.rule_values(protocol.names["rule"], IDS["application"], IDS["credential"]),
                "allowed_headers": headers, "expected_revision": 3, "expected_policy_hash": DIGESTS[1]}
            request = frame(1, "POST", wire.PREFIX + "/access-rules", value)
            if headers == ["accept", "accept-encoding", "user-agent"]:
                self.assertEqual(wire.document(protocol.admit(request, current)), value)
            else:
                with self.assertRaises(CheckFailure):
                    protocol.admit(request, current)

    def test_ready_preflight_uses_actual_catalog_validation_not_retired_status(self):
        catalog = {**deepcopy(INITIAL), "schema": "serverware.operatorCatalog/v1",
            "mode": "operator-development", "productionReady": False, "hardwareVerified": False,
            "allowed_upstreams": ["https://demo-upstream:8443"], "proxy_url": wire.PROXY,
            **{key: [] for key in wire.COLLECTIONS}}
        class ReadyReached(Exception):
            pass
        def exercise(value):
            check = object.__new__(checker.GuidedCheck)
            check.args = SimpleNamespace(admin_token_file=Path("/unused-synthetic-token"))
            check.protocol = self.protocol()
            calls = []
            check.health = lambda: calls.append("health")
            def control(path, **kwargs):
                self.assertEqual((path, kwargs), (wire.CATALOG, {"authenticated": True}))
                calls.append("catalog")
                return value
            check.control_json = control  # Actual inherited catalog validator runs.
            check.profile = lambda: self.fail("retired status endpoint must not be called")
            check.count = lambda: 0
            check.wait_catalog_loaded = lambda label: calls.append(label)
            check.settled = lambda: []
            def ready(frame):
                self.assertEqual(frame, check.protocol.ready(value))
                raise ReadyReached()
            with patch.object(checker, "token_file", return_value=TOKEN), patch.object(checker, "emit", side_effect=ready):
                check.run()
            return calls
        with self.assertRaises(ReadyReached):
            exercise(catalog)
        for key, value in (("schema", "serverware.operatorDemo/v1"), ("mode", "native"),
                           ("productionReady", True), ("hardwareVerified", True),
                           ("allowed_upstreams", ["https://outside.example.com"])):
            with self.subTest(key=key), self.assertRaises(CheckFailure):
                exercise({**catalog, key: value})

    def test_reload_joins_exact_hash_chain_and_sequence_with_empty_sentinel(self):
        create = {"routes": 1, "policy_hash": DIGESTS[2], "previous_policy_hash": DIGESTS[1], "policy_sequence": 2}
        revoke = {"routes": 1, "policy_hash": DIGESTS[3], "previous_policy_hash": DIGESTS[2], "policy_sequence": 3}
        for event in (create, revoke):
            checker.validate_reload(event, INITIAL["policy"], DIGESTS[2], DIGESTS[3])
            for key, value in (("routes", 0), ("routes", 2), ("routes", True),
                               ("policy_hash", DIGESTS[4]), ("previous_policy_hash", DIGESTS[4]),
                               ("policy_sequence", 4), ("policy_sequence", True)):
                with self.subTest(event=event["policy_hash"], key=key, value=value), self.assertRaises(CheckFailure):
                    checker.validate_reload({**event, key: value}, INITIAL["policy"], DIGESTS[2], DIGESTS[3])
        for changed in ({**create, "policy_sequence": 3}, {**revoke, "policy_sequence": 2},
                        {**revoke, "previous_policy_hash": DIGESTS[1]}):
            with self.assertRaises(CheckFailure):
                checker.validate_reload(changed, INITIAL["policy"], DIGESTS[2], DIGESTS[3])

    def test_failure_receipt_retains_only_source_location_not_message_or_locals(self):
        canary = "private-message-and-local-canary"
        try:
            exec(compile("raise RuntimeError(secret)", checker.__file__, "exec"), {"secret": canary})
        except RuntimeError as error:
            value = checker.failure_result(error, "preflight")
        self.assertEqual(value, {"schema": checker.SCHEMA, "ok": False, "error": "guided_check_failed",
            "stage": "preflight", "exceptionType": "RuntimeError",
            "failureSite": {"module": "scripts.check_operator_guided", "line": 1}})
        self.assertNotIn(canary.encode(), wire.encoded(value))
        self.assertIsNone(checker.failure_result(ValueError(canary), "preflight")["failureSite"])

    def test_post_consumed_before_transport_cannot_be_replayed_after_lost_reply(self):
        protocol = self.protocol()
        request = self.create_key(protocol)
        self.assertEqual(wire.document(protocol.admit(request, INITIAL))["secret"], SECRET)
        self.assertIn(request["path"], protocol.claimed)
        request["id"] = 3
        with self.assertRaises(CheckFailure):
            protocol.admit(request, INITIAL)

    def test_closed_request_origin_headers_cas_identity_and_types(self):
        edits = [lambda r: r.update(path="/api/credentials"), lambda r: r["headers"].update(origin="https://evil.example.com"),
            lambda r: r["headers"].update(authorization="private-canary"), lambda r: r.update(id=True),
            lambda r: r.update(extra="private-canary"), lambda r: r.update(method="PUT")]
        for edit in edits:
            with self.subTest(edit=edits.index(edit)):
                protocol = self.protocol(); request = self.create_key(protocol); edit(request)
                with self.assertRaises(CheckFailure): protocol.admit(request, INITIAL)
        for key, replacement in (("expected_revision", True), ("expected_revision", 2),
                                 ("expected_policy_hash", DIGESTS[2]), ("secret", "private-canary")):
            protocol = self.protocol(); request = self.create_key(protocol)
            content = wire.document(base64.b64decode(request["body"])); content[key] = replacement
            request["body"] = base64.b64encode(wire.encoded(content)).decode()
            with self.assertRaises(CheckFailure): protocol.admit(request, INITIAL)

    def test_checkpoint_order_and_mutation_phase_cannot_be_skipped(self):
        for phase in ("configured", "rule_revoked", "completed", "other"):
            with self.assertRaises(CheckFailure):
                self.protocol().admit({"kind": "checkpoint", "id": 1, "phase": phase}, INITIAL)
        protocol = self.protocol(); protocol.posts = 3
        checkpoint = {"kind": "checkpoint", "id": 1, "phase": "configured", "configuration": "e30="}
        self.assertIsNone(protocol.admit(checkpoint, INITIAL))
        # Admission alone does not advance; actual saved-state/use checks must do so.
        self.assertEqual(protocol.phase, "create")
        with self.assertRaises(CheckFailure):
            protocol.admit(frame(2, "POST", wire.PREFIX + "/access-rules/revoke", {}), INITIAL)

    def test_get_route_document_and_request_budget(self):
        for path in ("/api/audit", "/api/operator-demo/credentials", "//outside", "/?x=1"):
            with self.assertRaises(CheckFailure): self.protocol().admit(frame(1, path=path), INITIAL)
        protocol = self.protocol()
        protocol.admit(frame(1), INITIAL); protocol.admit(frame(2), INITIAL)
        with self.assertRaises(CheckFailure): protocol.admit(frame(3), INITIAL)

    def test_actual_private_download_requires_all_exact_saved_bindings(self):
        app = {"id": IDS["application"], "token_expires_at_epoch_ms": 2000000000000}
        rule = {"id": IDS["rule"]}
        value = configuration()
        self.assertEqual(wire.private_configuration(wire.encoded(value), app, rule, TOKEN), value)
        changes = {"proxy_password": "wrong", "application_id": IDS["credential"], "access_rule_id": IDS["application"],
            "proxy_url": "https://outside.example.com", "methods": ["GET"], "ca_file": "/etc/ssl/ca.pem",
            "token_expires_at_epoch_ms": True, "request_headers": {}, "request_body_mode": "project_fields_v1"}
        for key, change in changes.items():
            with self.subTest(key=key), self.assertRaises(CheckFailure):
                wire.private_configuration(wire.encoded({**value, key: change}), app, rule, TOKEN)
        with self.assertRaises(CheckFailure):
            wire.private_configuration(wire.encoded({**value, "client_secret": "private-canary"}), app, rule, TOKEN)

    def test_json_duplicates_nonfinite_and_noncanonical_base64_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff'):
            with self.assertRaises(CheckFailure): wire.document(raw)
        for text in ("e30", "e30=\n", "!!!!", "e30=" * 100):
            with self.assertRaises(CheckFailure): wire.decode(text, 16)

    def test_browser_completion_is_positive_closed_and_type_exact(self):
        wire.validate_browser(browser(), get_count=14)
        for key, change in (("postCount", 5), ("pageErrors", False), ("downloadDeleted", 1),
                            ("tokenCleared", False), ("getCount", 15), ("steps", []), ("secret", "private-canary")):
            with self.subTest(key=key), self.assertRaises(CheckFailure):
                wire.validate_browser({**browser(), key: change}, get_count=14)

    def test_real_wire_and_audit_pair_shape_matches_attempt_not_list_order(self):
        rows = audit_rows()
        self.assertEqual(set(checker.audit_pairs(list(reversed(rows)), SCOPE, IDS["credential"], positive())), {DIGESTS[7]})
        self.assertEqual(checker.audit_pairs(rows[:1], SCOPE, IDS["credential"], positive()), {})
        with self.assertRaises(CheckFailure): checker.audit_pairs(rows + [deepcopy(rows[1])], SCOPE, IDS["credential"], positive())

    def test_audit_pair_rejects_wrong_scope_body_version_commitment_and_terminal(self):
        replacements = {"principal_id": "other", "route_id": "other", "policy_hash": DIGESTS[0],
            "credential_ref": IDS["rule"], "credential_version": True, "method": "GET", "body_sha256": DIGESTS[0],
            "request_digest": DIGESTS[0], "operation_digest": DIGESTS[0], "attempt_id": "bad", "flow_id": DIGESTS[0],
            "response_body_sha256": DIGESTS[0], "response_body_bytes": 999, "upstream_status": 201}
        for key, change in replacements.items():
            rows = audit_rows(); rows[1]["event"][key] = change
            with self.subTest(key=key), self.assertRaises(CheckFailure):
                checker.audit_pairs(rows, SCOPE, IDS["credential"], positive())

    def test_terminal_and_joined_receipts_are_closed_without_private_canaries(self):
        value = result(); checker.validate_success_result(value)
        joined = {"schema": wire.JOINED_SCHEMA, "ok": True, "browserClosed": True, "browser": browser(), "checker": value}
        checker.validate_joined_result(joined)
        self.assertNotIn(TOKEN.encode(), wire.encoded(joined)); self.assertNotIn(SECRET.encode(), wire.encoded(joined))
        for section in (None, "positive", "negative", "audit", "browser", "resourceIds"):
            changed = deepcopy(value)
            (changed if section is None else changed[section])["secret"] = "private-canary"
            with self.subTest(section=section), self.assertRaises(CheckFailure): checker.validate_success_result(changed)
        for key, change in (("providerArrivals", True), ("proxyAttempts", 3), ("realProviderVerified", True), ("finalRevision", 8)):
            with self.assertRaises(CheckFailure): checker.validate_success_result({**value, key: change})
        with self.assertRaises(CheckFailure): checker.validate_joined_result({**joined, "browserClosed": False})

    def test_lean_actual_checker_import_and_help_require_no_site_packages_or_network(self):
        root = Path(__file__).resolve().parents[1]
        code = """import sys,runpy
def guard(event,args):
    if event.startswith(('socket.','sqlite3.','subprocess.','os.system','os.exec')):
        raise RuntimeError('runtime effects refused')
sys.addaudithook(guard)
sys.path.insert(0,sys.argv[1])
import scripts.operator_guided_browser
import scripts.check_operator_guided
sys.argv=['check_operator_guided.py','--help']
runpy.run_module('scripts.check_operator_guided',run_name='__main__')
"""
        observed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, str(root)],
            capture_output=True, timeout=8, env={"LANG": "C"})
        self.assertEqual(observed.returncode, 0, "lean checker import/help failed")
        self.assertIn(b"--expected-curl-sha256", observed.stdout)

    def test_owned_process_captures_bounded_output_and_failure_without_shell(self):
        command = [sys.executable, "-I", "-S", "-c", "import sys; assert sys.stdin.read()=='private-input'; print('ok'); sys.exit(2)"]
        code, out, err = checker.run_curl(command, b"private-input", 4)
        self.assertEqual((code, out, err), (2, b"ok\n", b""))
        with self.assertRaises(CheckFailure):
            checker.run_curl([sys.executable, "-I", "-S", "-c", "print('x'*100000)"], b"", 4)


if __name__ == "__main__":
    unittest.main()
