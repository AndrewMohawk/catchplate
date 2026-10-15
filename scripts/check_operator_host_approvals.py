#!/usr/bin/env python3
"""One isolated real Rust -> operator review -> one explicit retry acceptance.

Reuses the guided fixture's network-none runtime and synthetic byte oracle.
Never starts services, builds, contacts a provider, or retries a mutation.
Admin/application/provider tokens stay in memory or private curl stdin.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_guided_fixture_network as network
from scripts import operator_ordinary_client_fixture as oracle
from scripts.check_operator_catalog import COLLECTIONS, OperatorCatalogCheck, claim_fixture
from scripts.check_operator_demo import AUTHORITY, CheckFailure, SHA256, require, token_file
from scripts.check_operator_guided import CURL_SHA256, audit_pairs, run_curl
from scripts.check_operator_ordinary_client import OrdinaryClientCheck, START, RELEASE, BLOCK, check_response, V2_RESPONSE_MODE
from scripts.run_operator_x_examples_fixture import failure_site

PREFIX = "/api/operator-demo/approvals"
SCHEMA = "serverware.privateHostApprovalCheck/v1"


class HostApprovalCheck(OperatorCatalogCheck):
    count = OrdinaryClientCheck.count
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        super().__init__(args)
        self.phase, self.basic_secret = "preflight", None
        network.assert_isolated_network()
        require(args.control_base == "http://127.0.0.1:3000"
            and args.management_base == "http://127.0.0.1:9091"
            and args.operator_origin == "https://" + network.CONTROL_HOST
            and args.proxy_url == "https://" + network.PROXY_HOST
            and self.proxy.address == "127.0.0.1" and self.upstream.address == "127.0.0.2",
            "isolated fixture endpoints differ")
        path = args.curl_binary
        require(path.is_absolute() and path.resolve() == path and path.is_file()
            and path.stat().st_size <= 67108864 and args.expected_curl_sha256 == CURL_SHA256
            and hashlib.sha256(path.read_bytes()).hexdigest() == CURL_SHA256, "cached curl differs")
        self.bodies = []
        for name, body in (("approved", oracle.REQUEST_BODY), ("denied", oracle.REQUEST_BODY + b" ")):
            path = args.run_claim_file.parent / (".host-approval-" + name + ".json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
            self.bodies.append(path)

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        secret = getattr(self, "basic_secret", None)
        require(secret is None or secret.encode() not in content, "proxy secret escaped")

    def dispatch(self, body_index, expected_status, expected_count):
        target = "https://" + AUTHORITY + oracle.build_target(oracle.PROXY_BASIC_CASE,
            hashlib.sha256(("Bearer " + self.credential).encode()).hexdigest())
        argv = [str(self.args.curl_binary), "-q", "--config", "-", "--silent", "--show-error",
            "--proxy-basic", "--proxy", self.args.proxy_url, "--noproxy", "",
            "--proxy-cacert", str(self.args.proxy_ca_file), "--cacert", str(self.args.ca_file),
            "--proto", "=https", "--proto-redir", "=https", "--http1.1", "--connect-timeout", "3",
            "--max-time", "8", "--retry", "0", "--max-filesize", "65536", "--raw", "--include",
            "--suppress-connect-headers", "--request", "POST", "--data-binary", "@" + str(self.bodies[body_index]),
            "--header", "Authorization: " + oracle.DUMMY_AUTHORIZATION, "--header", "Content-Type: application/json",
            "--header", "Accept: application/json", "--header", "Accept-Encoding: identity",
            "--header", "Connection: close", "--header", "User-Agent: serverware-test-run/" + self.run_id,
            "--write-out", "\nserverware-host-approval:%{http_connect}:%{http_code}\n", target]
        private = ('proxy-user = "' + self.application["id"] + ":" + self.client_token + '"\n').encode()
        code, output, error = run_curl(argv, private, min(12, self.timeout()))
        self.clean(output); self.clean(error)
        wire, separator, tail = output.rpartition(b"\nserverware-host-approval:")
        require(separator and tail == ("200:" + str(expected_status) + "\n").encode()
            and code == 0 and not error and self.count() == expected_count, "proxy result or provider count differs")
        head, separator, body = wire.partition(b"\r\n\r\n")
        require(separator and len(head) <= 16384 and head.startswith(("HTTP/1.1 " + str(expected_status) + " ").encode()),
            "origin response framing differs")
        headers = []
        for line in head.split(b"\r\n")[1:]:
            name, colon, value = line.partition(b":")
            require(colon and len(line) <= 4096, "origin header differs")
            headers.append((name.decode("ascii"), value.decode("ascii").strip()))
        if expected_status == 200:
            result = check_response("json", 200, headers, body, wire, self.policy_hash, response_mode=V2_RESPONSE_MODE)
            return {key: value for key, value in result.items() if key != "capturedWireBytes"}
        result = json.loads(body)
        identifier = result.get("approval_id")
        require(result.get("error") == "host_trusted_approval_required"
            and isinstance(identifier, str) and str(uuid.UUID(identifier)) == identifier
            and result.get("approval_status") == ("pending" if expected_status == 428 else "denied"),
            "approval response differs")
        return identifier

    def metadata(self, identifier):
        row = self.control_json(PREFIX + "/" + identifier, authenticated=True)
        require(row.get("id") == identifier and row.get("assurance") == "host-trusted"
            and row.get("principal_id") == self.application["principal_id"]
            and row.get("route_id") == self.rule["route_id"] and row.get("policy_hash") == self.policy_hash
            and all(isinstance(row.get(key), str) and SHA256.fullmatch(row[key])
                for key in ("request_digest", "operation_digest")), "approval metadata binding differs")
        return row

    def decide(self, identifier, decision, expected_body):
        before = self.metadata(identifier)
        require(before["status"] == "pending", "review is not pending")
        review = self.control_json(PREFIX + "/" + identifier + "/review", authenticated=True, method="POST", payload={})
        require(review.get("assurance") == "host-trusted" and review["approval"]["id"] == identifier
            and review["document"]["body_sha256"] == "sha256:" + hashlib.sha256(expected_body).hexdigest()
            and all(review["document"][key] == before[key] for key in ("request_digest", "operation_digest", "policy_hash")),
            "fresh private review differs")
        result = self.control_json(PREFIX + "/" + identifier + "/decision", authenticated=True, method="POST",
            payload={"decision": decision, "review_receipt_id": review["review_receipt_id"],
                "review_digest": review["review_digest"], "note": None})
        require(result["id"] == identifier and result["status"] == ("approved" if decision == "approve" else "denied"),
            "operator decision failed")
        return before

    def run(self):
        self.admin_token = token_file(self.args.admin_token_file)
        self.health()
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] for key in COLLECTIONS) and self.count() == 0,
            "fixture is not unused")
        capabilities = self.control_json("/api/approvals/capabilities", authenticated=True)
        require(capabilities.get("mode") == "host_trusted_v1" and capabilities.get("can_decide") is True,
            "host approval capability is unavailable")
        self.policy_hash = initial["policy"]["policy_hash"]
        self.phase = "create-resources"
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id, "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        self.application, self.client_token, _ = self.mutate("/applications", {"name": self.run_id,
            "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        self.basic_secret = base64.b64encode((self.application["id"] + ":" + self.client_token).encode()).decode()
        self.rule, _, _ = self.mutate("/access-rules", {"name": self.run_id, "application_id": self.application["id"],
            "credential_id": credential["id"], "upstream_url": "https://" + AUTHORITY + oracle.FIXTURE_PATH,
            "methods": ["POST"], "request_body_mode": "preserve_json_v1", "response_mode": V2_RESPONSE_MODE,
            "request_fields": [], "response_fields": [], "credential_input": "replace_exact",
            "placeholder": oracle.DUMMY_AUTHORIZATION, "query_keys": list(oracle.QUERY_KEYS),
            "allowed_headers": ["accept", "user-agent"], "approval_mode": "host_review_v1"},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("approval_rule_loaded")
        self.phase = "first-request"
        approved = self.dispatch(0, 428, 0)
        self.phase = "approve"
        reviewed = self.decide(approved, "approve", oracle.REQUEST_BODY)
        self.phase = "identical-retry"
        success = self.dispatch(0, 200, 1)
        require(success["requestDigest"] == reviewed["request_digest"]
            and success["operationDigest"] == reviewed["operation_digest"], "released request differs from review")
        consumed = self.metadata(approved)
        require(consumed["status"] == "consumed" and consumed["consumed_at"],
            "one-use approval not consumed")
        self.phase = "replay"
        replay = self.dispatch(0, 428, 1)
        replay_row = self.metadata(replay)
        require(replay != approved and replay_row["request_digest"] == reviewed["request_digest"],
            "repeated operation did not require fresh approval")
        self.phase = "deny"
        denied = self.dispatch(1, 428, 1)
        denied_row = self.decide(denied, "deny", oracle.REQUEST_BODY + b" ")
        require(denied not in {approved, replay} and denied_row["request_digest"] != reviewed["request_digest"],
            "changed request did not receive a distinct review")
        require(self.dispatch(1, 403, 1) == denied and self.metadata(denied)["status"] == "denied", "denial differs")
        self.phase = "audit"
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        rows = self.audit()
        approvals = [row for row in rows if row["event_type"].startswith("operator.host_approval.")]
        expected = Counter({"operator.host_approval.requested": 3, "operator.host_approval.reviewed": 2,
            "operator.host_approval.approved": 1, "operator.host_approval.denied": 1, "operator.host_approval.claimed": 1})
        require(Counter(row["event_type"] for row in approvals) == expected, "durable approval audit differs")
        known = {approved: reviewed, replay: replay_row, denied: denied_row}
        for row in approvals:
            event = row["event"]; reference = known[event["approval_request_id"]]
            require(event["assurance"] == "host-trusted" and all(event[key] == reference[key]
                for key in ("principal_id", "route_id", "policy_hash", "request_digest", "operation_digest")),
                "approval audit identity differs")
        attempts = [row for row in rows if row["event_type"] in {START, RELEASE, BLOCK}]
        require(Counter(row["event_type"] for row in attempts) == Counter({START: 1, RELEASE: 1}),
            "upstream release count differs")
        pairs = audit_pairs(rows, (self.application["principal_id"], self.rule["route_id"], self.policy_hash),
            credential["id"], success)
        claimed = next(row["event"] for row in approvals if row["event_type"] == "operator.host_approval.claimed")
        require(len(pairs) == 1 and claimed["approval_request_id"] == approved
            and claimed["attempt_id"] in pairs, "claimed approval does not join the actual release")
        require(self.count() == 1 and self.catalog()["revision"] == 4, "final fixture state differs")
        self.phase = "complete"
        return {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realProviderVerified": False,
            "hardwareVerified": False, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "policyHash": self.policy_hash, "statuses": [428, 200, 428, 428, 403],
            "providerArrivals": 1, "exactRetryMatchesReview": True, "approvalConsumed": True,
            "replayRequiresFreshApproval": True, "deniedWithoutDispatch": True,
            "claimedAttemptJoinsRelease": True,
            "approved": {"id": approved, "requestDigest": reviewed["request_digest"],
                "operationDigest": reviewed["operation_digest"], "attemptId": claimed["attempt_id"]},
            "replayApprovalId": replay, "deniedApprovalId": denied,
            "responseBodyBytes": success["responseBodyBytes"], "responseBodySha256": success["responseBodySha256"],
            "approvalAuditCounts": dict(expected), "catalogRevision": 4}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-curl-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "curl-binary"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    check = None
    def expired(*_):
        raise CheckFailure("host approval acceptance deadline expired")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 180)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256), "fixed bounds differ")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = HostApprovalCheck(args)
        result = check.run()
    except Exception as error:
        result = {"schema": SCHEMA, "ok": False, "stage": check.phase if check else "preflight",
            "error": "host_approval_acceptance_failed", "exceptionType": type(error).__name__,
            "failureSite": failure_site(error, Path(__file__).resolve().parents[1])}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
