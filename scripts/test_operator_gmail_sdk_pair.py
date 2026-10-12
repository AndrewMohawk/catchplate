"""Closed paired-SDK component oracles, not TLS/Rust/provider acceptance.

Independent literal wire vectors plus the existing real in-memory OAuth
receiver. Synthetic clocks and process seams never authorize a joined run.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl

from scripts import check_operator_gmail_sdk as check
from scripts import operator_gmail_sdk_profiles as profiles
from scripts import prepare_operator_gmail_sdk_fixture as recipe
from scripts import test_operator_gmail_sdk_checker as old
from scripts import test_operator_gmail_sdk_fixture as receiver
from scripts import test_operator_gmail_sdk_recipe as old_recipe

CLIENTS = ("node", "python")
CASES = ("list_page_1", "message_metadata_1", "list_page_2", "message_metadata_2")
QUERIES = {
    "node": ("maxResults=5&labelIds=INBOX",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date",
        "maxResults=5&labelIds=INBOX&pageToken=next%2Bpage%20%2F%3D",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date"),
    "python": ("maxResults=5&labelIds=INBOX&alt=json",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&alt=json",
        "maxResults=5&labelIds=INBOX&pageToken=next%2Bpage+%2F%3D&alt=json",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&alt=json"),
}
HEADERS = {
    "node": {"accept": "application/json", "user-agent": "google-api-nodejs-client/9.2.0 (gzip)",
        "x-goog-api-client": "gdcl/9.2.0 gl-node/25.5.0"},
    "python": {"accept": "application/json", "user-agent": "(gzip)",
        "x-goog-api-client": "gdcl/2.201.0 gl-python/3.12.14"},
}
PHASES = tuple(client + ":" + phase for phase in
    ("first", "refreshed", "wrong_outer_ca", "wrong_inner_ca", "wrong_app", "revoked") for client in CLIENTS)
EXPECTED_CASES = tuple(client + ":" + case for client in CLIENTS for case in CASES)
NODE_PIN = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"


def target(client, index):
    path = receiver.PATH + ("/msg_1" if index == 1 else "/msg-2" if index == 3 else "")
    return path + "?" + QUERIES[client][index]


def request(client, index, token):
    value = receiver.request(target(client, index), token=token)
    for name in receiver.PUBLIC_HEADERS:
        if name != "host": del value.headers[name]
    for name, item in HEADERS[client].items(): value.headers[name] = item
    return value


@contextmanager
def captured():
    provider = check.fixture.GmailSdkFixture(Path("/synthetic-unopened"), sdk_pair=True)
    provider.replies = []
    with patch.object(check.fixture.base.GoogleFixture, "_send_json",
            lambda self, handler, status, payload: self.replies.append((status, deepcopy(payload)))), \
         patch.object(check.fixture.base.GoogleFixture, "_send_redirect",
            lambda self, handler, location: self.replies.append((302, location))):
        yield provider


def documents():
    with captured() as provider, receiver.clock(0):
        result = {"fresh": provider.observations()}
        tokens = receiver.authorize(provider)
        assert receiver.send(provider, receiver.request("/v1/userinfo", host="openidconnect.googleapis.com",
            token=tokens["access_token"]))[0] == 200
        result["connected"] = provider.observations()
        for seconds, stage in ((1, "first"), (91, "refreshed")):
            with receiver.clock(seconds):
                if stage == "refreshed":
                    result["expired"] = provider.observations()
                    status, tokens = receiver.refresh(provider, tokens)
                    assert status == 200
                for client in CLIENTS:
                    for index in range(4):
                        assert receiver.send(provider, request(client, index, tokens["access_token"]))[0] == 200
                    result["node_" + stage if client == "node" else stage] = provider.observations()
    return result


def canonical(client, index, generation):
    value = old.canonical(index, generation)
    path, query = target(client, index).split("?", 1)
    value["request"].update(path=path, query_wire=query,
        query=[list(pair) for pair in parse_qsl(query, keep_blank_values=True)],
        headers={"host": "gmail.googleapis.com", **HEADERS[client],
            **({"content-length": "0"} if client == "python" else {})})
    return value


def commitments(document):
    result = []
    for index, row in enumerate(document["gmailSdk"]["attempts"]):
        client, generation = CLIENTS[(index % 8) // 4], 1 + index // 8
        value = canonical(client, index % 4, generation)
        result.append({"case": client + ":" + CASES[index % 4], "generation": generation,
            "requestDigest": receiver.digest(receiver.encoded(value)),
            "operationDigest": receiver.digest(receiver.encoded({k: v for k, v in value.items() if k not in {"v", "client_ip"}})),
            "responseBodySha256": row["responseBodySha256"], "responseBodyBytes": row["responseBodyBytes"]})
    return result


def success_result(docs, wire):
    # Reuse only the unchanged common receipt fields, then replace every mode
    # dependent inventory with independently sized literal paired expectations.
    value = old.success_result(wire)
    del value["goExampleSha256"]
    value.update(schema="serverware.privateGmailSdkCheck/v2", providerAttempts=16,
        nodeExampleSha256=NODE_PIN, sdkDependenciesSha256="a" * 64,
        exampleSourceSha256={name: "b" * 64 for name in (
            "examples/google-gmail-node/client.mjs", "examples/google-gmail-node/package.json",
            "examples/google-gmail-node/package-lock.json", "examples/google-gmail-python/gmail.py",
            "examples/google-gmail-python/requirements.txt")},
        completed=[{"phase": phase, "exitCode": 0 if i < 4 else 1,
            "summary": {"pages": 2, "messages_read": 2, "more_pages": False} if i < 4 else None}
            for i, phase in enumerate(PHASES)],
        providerObservations=[{"stage": stage, "counts": old.counts(consent, refresh, count),
            "initialAccessExpiresAtEpochMs": receiver.EPOCH_MS + 90000 if consent else None,
            "initialAccessExpired": stage in ("expired", "refreshed"),
            "resourceGenerations": [1 + i // 8 for i in range(count)],
            "cases": [EXPECTED_CASES[i % 8] for i in range(count)],
            "refreshCompletedAtExpiry": False if stage == "expired" else None}
            for stage, consent, refresh, count in (("fresh", 0, 0, 0), ("connected", 1, 0, 0),
                ("first", 1, 0, 8), ("expired", 1, 0, 8), ("refreshed", 1, 1, 16))],
        negativeControls=[{"phase": phase, "providerAttemptsBefore": 16, "providerAttemptsAfter": 16,
            "auditEventType": kind, "auditEventId": old.sha(300 + i) if kind else None}
            for i, (phase, kind) in enumerate(zip(PHASES[4:],
                (None, None, old.CONNECT, old.CONNECT, old.DENIED, old.DENIED, old.DENIED, old.DENIED)))],
        durableAuditEventIds=[old.uid(400 + i) for i in range(4)] + [old.sha(102 + i) for i in range(32)],
        auditAttemptIds=[old.sha(i + 1) for i in range(16)],
        generationAuditEventIds=[old.uid(100), old.uid(101)] + [old.sha(102 + 2 * i) for i in range(16)],
        namedAuditInventory={old.START: 16, old.RELEASE: 16, old.CONNECT: 18, old.DENIED: 4, old.LEASE: 16,
            "data_plane.policy.reloaded": 2, "credential.oauth_connected": 1, "credential.oauth_refreshed": 1})
    return value


class PairedGmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = documents()
        cls.wire = commitments(cls.docs["refreshed"])

    def test_closed_wire_vectors_never_rewrite_query_or_headers(self):
        self.assertEqual(profiles.PHASES, PHASES)
        for client in CLIENTS:
            for index, case in enumerate(CASES):
                self.assertEqual(check.fixture.recognized_case(target(client, index), True), client + ":" + case)
                self.assertIsNone(check.fixture.recognized_case(target(client, index)))
                self.assertEqual(profiles.provider_headers(client + ":" + case), {"host": "gmail.googleapis.com", **HEADERS[client]})
                self.assertEqual(profiles.canonical_headers(client + ":" + case), {"host": "gmail.googleapis.com", **HEADERS[client],
                    **({"content-length": "0"} if client == "python" else {})})
        for invalid in ("node", "python:publish", "go:first", True):
            with self.assertRaises((ValueError, check.CheckFailure)):
                profiles.split_phase(invalid)
        for client in CLIENTS:
            self.assertIsNone(check.fixture.recognized_case(target(client, 0) + "&q=extra", True))
            self.assertIsNone(check.fixture.recognized_case(target(client, 2).replace("%2B", "%2b"), True))

    def test_real_inmemory_exchange_original_expiry_and_exact_sixteen(self):
        for stage, document in self.docs.items():
            safe = check.observations(document, stage, sdk_pair=True)
            if stage != "fresh": self.assertEqual(safe["initialAccessExpiresAtEpochMs"], receiver.EPOCH_MS + 90000)
        final = self.docs["refreshed"]
        self.assertEqual(len(final["gmailSdk"]["attempts"]), 16)
        self.assertEqual(final["counts"]["google"]["refresh_exchanges"], 1)
        self.assertEqual([r["tokenGeneration"] for r in final["gmailSdk"]["attempts"]], [1] * 8 + [2] * 8)
        self.assertEqual([r["case"] for r in final["gmailSdk"]["attempts"]], list(EXPECTED_CASES) * 2)
        for mutate in (lambda v: v["gmailSdk"]["attempts"][4].update(tokenGeneration=2),
                lambda v: v["gmailSdk"]["attempts"][8].update(timestampEpochMs=receiver.EPOCH_MS + 89999),
                lambda v: v["gmailSdk"].update(schema="serverware.privateGmailSdkObservations/v1"),
                lambda v: v["tokenLifetimes"].update(authorizationCodeExchangeSeconds=120),
                lambda v: v["counts"]["google"].update(refresh_exchanges=2)):
            bad = deepcopy(final); mutate(bad)
            with self.assertRaises(check.CheckFailure): check.observations(bad, "refreshed", sdk_pair=True)

    def test_canonical_original_headers_and_distinct_requests(self):
        for index, row in enumerate(self.docs["refreshed"]["gmailSdk"]["attempts"]):
            actual = check.request_commitments(row, scope=old.SCOPE, credential_id=old.CREDENTIAL,
                generation=1 + index // 8, sdk_pair=True)
            expected = self.wire[index]
            self.assertEqual(actual, (expected["requestDigest"], expected["operationDigest"]))
        self.assertEqual(len({r["requestDigest"] for r in self.wire}), 16)
        bad = deepcopy(self.docs["refreshed"]["gmailSdk"]["attempts"][0])
        bad["requestHeaders"]["accept"] = "*/*"
        with self.assertRaises(check.CheckFailure):
            check.request_commitments(bad, scope=old.SCOPE, credential_id=old.CREDENTIAL, generation=1, sdk_pair=True)

    def test_python_provider_omits_length_but_canonical_preserves_ingress_zero(self):
        for index in range(4):
            row = self.docs["first"]["gmailSdk"]["attempts"][4 + index]
            expected_headers = {"host": "gmail.googleapis.com", **HEADERS["python"]}
            self.assertEqual(row["requestHeaders"], expected_headers)
            self.assertNotIn("content-length", row["requestHeaders"])
            path, query = target("python", index).split("?", 1)
            public = {"schema": "serverware.privateGmailSdkRequest/v1", "method": "GET",
                "authority": "gmail.googleapis.com", "path": path, "rawQuery": query,
                "headers": expected_headers, "bodySha256": receiver.digest(b""), "bodyBytes": 0}
            self.assertEqual(row["requestCommitment"], receiver.digest(receiver.encoded(public)))
            expected = canonical("python", index, 1)
            self.assertEqual(expected["request"]["headers"]["content-length"], "0")
            actual = check.request_commitments(row, scope=old.SCOPE, credential_id=old.CREDENTIAL,
                generation=1, sdk_pair=True)
            without_length = deepcopy(expected)
            del without_length["request"]["headers"]["content-length"]
            self.assertNotEqual(actual[0], receiver.digest(receiver.encoded(without_length)))
            self.assertNotEqual(actual[1], receiver.digest(receiver.encoded(
                {k: v for k, v in without_length.items() if k not in {"v", "client_ip"}})))
            # Recompute the public hash: refusal must not rely on a stale hash.
            bad = deepcopy(row)
            bad["requestHeaders"]["content-length"] = "0"
            public["headers"] = bad["requestHeaders"]
            bad["requestCommitment"] = receiver.digest(receiver.encoded(public))
            with self.assertRaises(check.CheckFailure):
                check.request_commitments(bad, scope=old.SCOPE, credential_id=old.CREDENTIAL,
                    generation=1, sdk_pair=True)
        wrong_wire = deepcopy(self.wire)
        missing = canonical("python", 0, 1)
        del missing["request"]["headers"]["content-length"]
        wrong_wire[4].update(requestDigest=receiver.digest(receiver.encoded(missing)),
            operationDigest=receiver.digest(receiver.encoded(
                {k: v for k, v in missing.items() if k not in {"v", "client_ip"}})))
        with self.assertRaises(check.CheckFailure):
            check.generation_evidence(old.audit_rows(wrong_wire), old.SCOPE, old.CREDENTIAL, self.wire,
                expected_binary_sha256=old.sha(901), sdk_pair=True)

    def test_python_provider_empty_get_framing_remains_closed(self):
        variants = ((), (("Content-Length", "0"),), (("Content-Length", "1"),),
            (("Content-Length", "00"),), (("Content-Length", "0"), ("Content-Length", "0")),
            (("Transfer-Encoding", "chunked"),), (("Content-Length", "0"), ("Transfer-Encoding", "chunked")))
        for additions in variants:
            with self.subTest(headers=additions), captured() as provider, receiver.clock(0):
                tokens = receiver.authorize(provider)
                handler = request("python", 0, tokens["access_token"])
                self.assertEqual(handler.headers.get_all("Content-Length", []), [])
                for name, value in additions:
                    handler.headers[name] = value
                accepted = additions in ((), (("Content-Length", "0"),))
                self.assertEqual(receiver.send(provider, handler)[0], 200 if accepted else 400)
                observed = provider.observations()
                row = observed["gmailSdk"]["attempts"][0]
                self.assertEqual(row["authorized"], accepted)
                self.assertEqual(row["framingMatch"], accepted)
                self.assertEqual(observed["counts"]["google"]["resource_attempts"], 1)
                if accepted:
                    self.assertEqual(row["requestHeaders"], {"host": "gmail.googleapis.com", **HEADERS["python"]})
                    self.assertIsNotNone(row["requestCommitment"])
                else:
                    self.assertIsNone(row["requestCommitment"])
                    self.assertEqual(observed["counts"]["google"].get("resource_requests", 0), 0)

    def test_generation_pairs_same_scope_one_refresh_no_retry(self):
        rows = old.audit_rows(self.wire)
        def evidence(events, wire=self.wire):
            return check.generation_evidence(events, old.SCOPE, old.CREDENTIAL, wire,
                expected_binary_sha256=old.sha(901), sdk_pair=True)
        self.assertEqual(len(evidence(rows)["generationAuditEventIds"]), 18)
        self.assertEqual(evidence([*rows, old.reconciliation_row()])["reconciliationRejections"], 1)
        for change in (lambda v: v.pop(4), lambda v: v[1]["event"].update(previous_credential_version=True),
                lambda v: v[2]["event"].update(credential_version=2),
                lambda v: v[3]["event"].update(route_id="other"),
                lambda v: v[3]["event"].update(response_body_bytes=1)):
            bad = deepcopy(rows); change(bad)
            with self.assertRaises(check.CheckFailure): evidence(bad)
        with self.assertRaises(check.CheckFailure): evidence(rows, self.wire[:8])

    def test_exact_entrypoint_process_results_and_clean_environment(self):
        instance = check.GmailSdkCheck.__new__(check.GmailSdkCheck)
        instance.sdk_pair, instance.args = True, SimpleNamespace(browser_permission=False)
        instance.current_files, instance.clean, instance.completed = Mock(), Mock(), []
        instance.deadline = time.monotonic() + 29
        with patch.object(check, "run_example") as launch:
            for i, phase in enumerate(PHASES):
                client, stage = phase.split(":")
                failure = (b"Gmail example failed; check configuration, permissions and service audit logs.\n" if client == "node"
                    else b"Gmail read failed; check application permission, proxy trust and the operator audit log.\n")
                launch.return_value = (0, old.SUCCESS, b"") if i < 4 else (1, b"", failure)
                instance.client(phase, {"id": old.uid(2)}, "a" * 43)
                expected_command = (("/node", "/app/examples/google-gmail-node/client.mjs") if client == "node" else
                    ("/example-python/bin/python", "-I", "-B", "/app/examples/google-gmail-python/gmail.py"))
                self.assertEqual(launch.call_args.kwargs, {"command": expected_command})
                environment = launch.call_args.args[0]
                self.assertEqual(set(environment), {"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID",
                    "SERVERWARE_PROXY_TOKEN", "SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"})
                self.assertEqual(environment, check.client_environment(old.uid(2), "a" * 43, stage))
                with self.assertRaises(check.CheckFailure):
                    check.validate_client_result(phase, 1, b"", b"arbitrary failure", sdk_pair=True)
        self.assertEqual(len(instance.completed), 12)

    def test_child_result_observation_is_closed_bounded_and_output_free(self):
        for phase in PHASES:
            client = phase.split(":")[0]
            for result, success, denial in (((0, old.SUCCESS, b""), True, False),
                    ((1, b"", profiles.FAILURES[client]), False, True),
                    ((-15, b"secret-canary", b"private-provider-value"), False, False)):
                value = check.client_result_observation(phase, *result, sdk_pair=True)
                self.assertEqual(value, {"phase": phase, "exitCode": result[0],
                    "stdoutBytes": len(result[1]), "stderrBytes": len(result[2]),
                    "exactSuccess": success, "exactDenial": denial})
                self.assertNotIn(b"secret-canary", receiver.encoded(value))
                self.assertNotIn(b"private-provider-value", receiver.encoded(value))
        self.assertTrue(check.client_result_observation("first", 0, old.SUCCESS, b"")["exactSuccess"])
        self.assertTrue(check.client_result_observation("revoked", 1, b"", old.DENIAL)["exactDenial"])
        for phase, code, out, err, paired in (("python:first", True, b"", b"", True),
                ("python:first", 256, b"", b"", True), ("python:first", -256, b"", b"", True),
                ("python:first", 1, b"a" * 1025, b"", True), ("python:first", 1, b"", b"a" * 1025, True),
                ("python:first", 1, "secret-canary", b"", True), ("python:first", 1, b"", None, True),
                ("secret-canary", 1, b"", b"", True), ("first", 1, b"", b"", 0)):
            self.assertIsNone(check.client_result_observation(phase, code, out, err, sdk_pair=paired))

    def test_client_failure_keeps_original_order_exception_and_never_replays(self):
        instance = check.GmailSdkCheck.__new__(check.GmailSdkCheck)
        instance.sdk_pair, instance.args = True, SimpleNamespace(browser_permission=False)
        instance.completed, instance.deadline = ["already-completed"], time.monotonic() + 29
        calls, errors = [], []
        instance.current_files = lambda: calls.append("files")
        instance.clean = lambda raw: calls.append("clean")
        original_validator = check.validate_client_result
        def validate(*args, **kwargs):
            calls.append("validate")
            try:
                return original_validator(*args, **kwargs)
            except check.CheckFailure as error:
                errors.append(error)
                raise
        def launch(*args, **kwargs):
            calls.append("run")
            return 1, b"", profiles.FAILURES["python"]
        with patch.object(check, "run_example", side_effect=launch) as process, \
                patch.object(check, "validate_client_result", side_effect=validate), \
                self.assertRaises(check.CheckFailure) as caught:
            instance.client("python:first", {"id": old.uid(2)}, "a" * 43)
        self.assertIs(caught.exception, errors[0])
        process.assert_called_once()
        self.assertEqual(calls, ["files", "run", "files", "clean", "clean", "validate"])
        self.assertEqual(instance.completed, ["already-completed"])
        self.assertTrue(instance.client_result["exactDenial"])
        calls.clear()
        original_failure = RuntimeError("secret-canary")
        with patch.object(check, "run_example", side_effect=original_failure) as process, \
                self.assertRaises(RuntimeError) as caught:
            instance.client("python:refreshed", {"id": old.uid(2)}, "a" * 43)
        self.assertIs(caught.exception, original_failure)
        self.assertEqual(calls, ["files"])
        self.assertIsNone(instance.client_result)
        self.assertEqual(instance.completed, ["already-completed"])
        process.assert_called_once()

    def test_failure_receipt_reports_only_current_returned_child_observation(self):
        args = SimpleNamespace(control_base=check.base.fixture.CONTROL_ORIGIN,
            operator_origin=check.base.fixture.CONTROL_ORIGIN, management_base="http://127.0.0.1:9091",
            proxy_url=check.PROXY, ca_file=check.TRUST_FILES["inner"], proxy_ca_file=check.TRUST_FILES["outer"],
            combined_ca_file=check.TRUST_FILES["combined"], sdk_pair=True, browser_permission=False,
            expected_go_sha256=None, expected_dependencies_sha256="a" * 64,
            expected_binary_sha256=old.sha(901), timeout_seconds=180,
            google_fixture_marker_file=Path("/unused-google"), fixture_marker_file=Path("/unused-fixture"),
            run_claim_file=Path("/unused-claim"))
        observation = check.client_result_observation("python:first", 1, b"secret-canary", b"private-value", sdk_pair=True)
        for phase, saved, expected in (("python:first", observation, observation),
                ("node:refreshed", observation, None), ("revoke", observation, None), ("python:first", None, None)):
            error = check.CheckFailure("secret-canary")
            instance = SimpleNamespace(phase=phase, client_result=saved, run=Mock(side_effect=error))
            with patch.object(check.base.fixture, "assert_isolated_network"), \
                    patch.object(check.base, "read_google_marker"), patch.object(check, "claim_fixture"), \
                    patch.object(check, "GmailSdkCheck", return_value=instance), \
                    patch.object(check, "failure_site", wraps=check.failure_site) as site:
                result = check.run_checks(args)
            self.assertEqual(result["clientResult"], expected)
            self.assertFalse(result["ok"])
            self.assertEqual(result["phase"], phase)
            self.assertEqual(result["error"], "acceptance_check_failed")
            self.assertIs(site.call_args.args[0], error)
            self.assertNotIn(b"secret-canary", receiver.encoded(result))
            self.assertNotIn(b"private-value", receiver.encoded(result))
            instance.run.assert_called_once()

    def test_runtime_batch_order_keeps_only_five_original_checkpoints(self):
        instance = check.GmailSdkCheck.__new__(check.GmailSdkCheck)
        instance.sdk_pair, instance.client, instance.accept = True, Mock(), Mock()
        instance.observe = Mock(side_effect=lambda stage, **kwargs: self.docs[stage])
        for stage in ("first", "refreshed"):
            self.assertEqual(instance.accept_batch(stage, {}, "synthetic"), self.docs[stage])
        self.assertEqual([c.args[0] for c in instance.client.call_args_list], list(PHASES[:4]))
        self.assertEqual([(c.args[0], c.kwargs["retain"]) for c in instance.observe.call_args_list],
            [("node_first", False), ("first", True), ("node_refreshed", False), ("refreshed", True)])

    def test_denied_provider_deltas_abort_without_new_mutation(self):
        document = self.docs["refreshed"]
        self.assertTrue(check.validate_no_arrivals(document, deepcopy(document), sdk_pair=True))
        altered = deepcopy(document); altered["gmailSdk"]["attempts"].append(deepcopy(altered["gmailSdk"]["attempts"][-1]))
        instance = check.GmailSdkCheck.__new__(check.GmailSdkCheck)
        instance.sdk_pair, instance.settled_audit, instance.client = True, lambda: [], Mock()
        instance.observe = lambda *args, **kwargs: altered
        instance.audit = Mock(side_effect=AssertionError("must stop before later audit or mutation"))
        for phase in PHASES[4:]:
            with self.assertRaises(check.CheckFailure): instance.deny(phase, {}, "synthetic", document)
        instance.audit.assert_not_called()

    def test_closed_final_v2_receipt_does_not_accept_partial_or_legacy_counts(self):
        value = success_result(self.docs, self.wire)
        self.assertTrue(check.validate_success_result(value))
        for change in (lambda v: v.update(providerAttempts=8), lambda v: v.update(automaticRefreshes=2),
                lambda v: v["completed"].pop(), lambda v: v.update(nodeExampleSha256="b" * 64),
                lambda v: v.update(goExampleSha256="c" * 64), lambda v: v["negativeControls"][0].update(providerAttemptsAfter=17),
                lambda v: v["requests"][4].update(generation=2), lambda v: v["namedAuditInventory"].update({old.CONNECT: 17}),
                lambda v: v["providerObservations"][2]["cases"].reverse(),
                lambda v: v.update(schema="serverware.privateGmailSdkCheck/v1")):
            bad = deepcopy(value); change(bad)
            with self.assertRaises(check.CheckFailure): check.validate_success_result(bad)

    def test_recipe_explicit_ro_dependencies_and_unchanged_default(self):
        kwargs = {"expected_binary_sha256": "a" * 64, "expected_go_sha256": None, "sdk_pair": True,
            "node": Path("/synthetic/node"), "node_modules": Path("/synthetic/node_modules"),
            "python_runtime": Path("/synthetic/python"), "python_packages": Path("/synthetic/site-packages"),
            "expected_dependencies_sha256": "b" * 64}
        args = (*old_recipe.ARGS[:4], None)
        value = recipe.build(*args, **kwargs)
        self.assertEqual(set(value["services"]), recipe.RUNTIME_SERVICES | {"initialize", "basic-pki"})
        checker = value["services"]["check"]
        self.assertEqual(checker["image"], "sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad")
        self.assertEqual(checker["command"][:3], ["/example-python/bin/python", "-B", "/app/scripts/check_operator_gmail_sdk.py"])
        self.assertIn("--sdk-pair", checker["command"])
        self.assertIn("--sdk-pair", value["services"]["provider"]["command"])
        mounts = {m["target"]: m for m in checker["volumes"]}
        for target in ("/node", "/example-python", "/example-python/lib/python3.12/site-packages",
                "/app/examples/google-gmail-node/node_modules", "/usr/lib/x86_64-linux-gnu/libatomic.so.1"):
            self.assertTrue(mounts[target]["read_only"])
        self.assertNotIn("/example-go/google-gmail", mounts)
        for change in ({"browser_permission": True}, {"expected_go_sha256": "a" * 64}, {"sdk_pair": False}, {"node": Path("relative")}):
            with self.assertRaises(ValueError): recipe.build(*args, **{**kwargs, **change})
        original = recipe.build(*old_recipe.ARGS, **old_recipe.PINS)
        self.assertNotIn("--sdk-pair", original["services"]["check"]["command"])
        self.assertEqual(original["services"]["check"]["image"], recipe.base.APP_IMAGE)


if __name__ == "__main__":
    unittest.main()
