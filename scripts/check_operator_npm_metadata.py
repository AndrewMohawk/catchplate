#!/usr/bin/env python3
"""One-shot stock npm view/pacote metadata check in the private fixture only.

No registry discovery, client transport replacement, install, or retry loop.
Repeated package reads intentionally share canonical digests; distinct audit
attempt IDs and the exact fixture arrival sequence account for every dispatch.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, Endpoint, require, token_file
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, OrdinaryClientCheck, digest
from scripts import operator_npm_metadata_fixture as fixture
from scripts import operator_npm_metadata_fixture_network as isolated

PROXY = "https://proxy.operator-basic.example.test:8443"
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
CONNECT_DENIED = "data_plane.connect.denied"
NEGATIVES = ("wrong_app", "wrong_package_denied", "wrong_dummy")
PHASES = frozenset((*NEGATIVES, *(row["case"] for row in fixture.SPECS)))
BLOCK_ERRORS = {"wrong_package": "npm_metadata_response_package_mismatch", "reflection": "response_credential_reflection"}
DENIAL_PATHS = {"npm_metadata_package_denied": "/serverware-fixture-denied",
    "credential_existing_header_mismatch": fixture.path(fixture.PACKAGES[0])}


def validate_denial(event, route_id):
    error = event.get("error")
    require(error in DENIAL_PATHS and event.get("route_id") == route_id and event.get("adapter") == "npm.metadata.v1"
        and event.get("method") == "GET" and event.get("outcome") == "denied" and event.get("status_code") == 403,
        "npm precredential guard denial differs")
    # These early deny_for_route decisions carry no fabricated principal,
    # policy hash or canonical digest; the established CONNECT has that scope.
    path = DENIAL_PATHS[error]
    require(event.get("url") == {"origin_sha256": digest(fixture.ORIGIN.encode()), "origin_bytes": len(fixture.ORIGIN),
        "path_sha256": digest(path.encode()), "path_bytes": len(path), "query_keys": []}, "npm denial destination differs")
    return error


def run_client(phase, application, token, run_id, seconds):
    require(phase in PHASES and 0 < seconds <= 25, "npm client phase or deadline invalid")
    payload = json.dumps({"phase": phase, "applicationId": application, "token": token, "runId": run_id}).encode()
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(["/node", "/app/scripts/operator_npm_metadata_job.mjs"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8", "NODE_EXTRA_CA_CERTS": "/client-trust/requests-ca.pem"}, close_fds=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        process.stdin.write(payload); process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                require(time.monotonic() < deadline, "npm client deadline exceeded")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (16384 if key.data == "out" else 8192), "npm client output bound exceeded")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(code == 0 and not output["err"], "stock npm client failed in " + phase + "; raw output suppressed")
        return bytes(output["out"])
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def canonical_digests(row, scope, credential_id, peer):
    """Independent canonical-v2 recipe using the observed validated headers."""
    spec = next(item for item in fixture.SPECS if item["case"] == row["case"])
    headers = row["requestHeaders"]
    require(set(headers) <= {"host", "accept", "user-agent", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope",
        "pacote-pkg-id", "pacote-req-type", "pacote-version"} and headers.get("host") == "registry.npmjs.org",
        "unexpected canonical npm request header")
    canonical = {"v": 2, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "registry.npmjs.org", "path": spec["target"],
            "query": [], "headers": headers, "body_sha256": digest(b""),
            "discard_headers": ["accept-encoding", "npm-session"]},
        "operation": {"operation": "npm.metadata.read", "package": spec["package"]}}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({key: value for key, value in canonical.items() if key not in {"v", "client_ip"}}))


def terminal_signature(item):
    key = (item["requestDigest"], item["operationDigest"], item["upstreamStatus"])
    if item["case"] in BLOCK_ERRORS:
        return (*key, BLOCK, BLOCK_ERRORS[item["case"]])
    return (*key, RELEASE, item["responseBodySha256"], item["responseBodyBytes"])


def joined_attempts(rows, wire, scope, credential_id):
    """Partial snapshots are admissible; no duplicate/mismatched pair is."""
    expected = Counter(terminal_signature(item) for item in wire)
    keys = {(item["requestDigest"], item["operationDigest"]) for item in wire}
    pairs, observed = {}, Counter()
    for row in rows:
        kind, event = row["event_type"], row["event"]
        if kind not in {START, RELEASE, BLOCK}:
            continue
        key = (event.get("request_digest"), event.get("operation_digest"))
        attempt = event.get("attempt_id")
        require(key in keys and SHA256.fullmatch(attempt or "") and event.get("flow_id") == attempt
            and tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == scope
            and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
            and event["credential_version"] == 1 and event.get("method") == "GET"
            and event.get("body_sha256") == digest(b""), "npm audit authority or canonical request differs")
        pair = pairs.setdefault(attempt, {"key": key})
        slot = "start" if kind == START else "terminal"
        require(pair["key"] == key and slot not in pair, "npm audit attempt was reused or rebound")
        pair[slot] = row["id"]
        if kind == START:
            require(event.get("outcome") == "release_started", "npm release start outcome differs")
            continue
        validation = event.get("response_validation", {})
        signature = (*key, event.get("upstream_status"), kind)
        if kind == BLOCK:
            require(event.get("outcome") == "blocked", "npm response block outcome differs")
            signature += (validation.get("error"),)
        else:
            require(event.get("outcome") == "released" and validation.get("ok") is True
                and validation.get("mode") == "npmMetadataJsonV1" and validation.get("adapter") == "npm.metadata.v1"
                and validation.get("body_bytes_preserved") is True
                and validation.get("allowed_fields_redacted") is False, "whole npm metadata release differs")
            signature += (event.get("response_body_sha256"), event.get("response_body_bytes"))
        observed[signature] += 1
        require(signature in expected and observed[signature] <= expected[signature], "npm terminal response is unaccounted or repeated")
    require(len(pairs) <= len(wire), "extra npm credential release attempt")
    complete = observed == expected and len(pairs) == len(wire) and all({"start", "terminal"} <= pair.keys() for pair in pairs.values())
    return pairs, complete


class NpmMetadataCheck(OrdinaryClientCheck):
    def __init__(self, args):
        isolated.assert_isolated_network()
        require(args.control_base == "http://serverware:3000" and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == PROXY and args.upstream_address is None, "fixed isolated npm endpoints required")
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": isolated.LOOPBACK}))
        self.credential = fixture.TOKEN
        require(Path("/node").is_file() and hashlib.sha256(Path("/node").read_bytes()).hexdigest() == NODE_SHA256,
            "pinned npm Node executable differs")
        require(self.control.address == self.management.address == self.proxy.address == isolated.LOOPBACK,
            "isolated npm control/proxy peer differs")
        self.registry = Endpoint(fixture.ORIGIN, address=isolated.LOOPBACK)
        self.registry.address = isolated.FIXTURE_IP
        self.wire, self.clients, self.negative_cutoffs = [], [], []

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("productionReady") is False and value.get("hardwareVerified") is False
            and value.get("allowed_upstreams") == [fixture.ORIGIN] and type(value.get("revision")) is int
            and all(isinstance(value.get(key), list) for key in COLLECTIONS), "synthetic npm catalog contract differs")
        policy = value.get("policy", {})
        require(SHA256.fullmatch(policy.get("policy_hash", "")) and type(policy.get("sequence")) is int,
            "npm signed policy unavailable")
        self.snapshot = value
        return value

    def observe(self):
        status, value = self.json_request(self.registry, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and value.get("schema") == fixture.SCHEMA and value.get("syntheticOnly") is True
            and type(value.get("total")) is int and isinstance(value.get("attempts"), list)
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS, "bounded npm observations unavailable")
        return value

    def count(self):
        return self.observe()["total"]

    def unchanged(self, pins):
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(pins), "npm catalog authority changed during client job")

    def client(self, phase, app, token):
        raw = run_client(phase, app["id"], token, self.run_id, min(25, self.deadline - time.monotonic()))
        self.clean(raw); value = json.loads(raw)
        require(value.get("schema") == "serverware.privateNpmMetadataClient/v1" and value.get("ok") is True
            and value.get("phase") == phase and value.get("npmVersion") == "11.8.0"
            and value.get("pacoteVersion") == "21.0.4" and value.get("registryFetchVersion") == "19.1.1"
            and value.get("client") == ("pacote" if phase.startswith("pacote_") else "npm")
            and value.get("strictSSL") is True and value.get("extraCaPreservesDefaultRoots") is True
            and value.get("configuredRetries") == 0 and value.get("isolatedCache") is True
            and value.get("requestRewrite") is False, "stock npm client receipt differs")
        self.clients.append(value)
        return value

    def checkpoint(self, baseline, phase, denied_count):
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for prior in [baseline, *self.negative_cutoffs]
                for key, value in prior.items()), "npm negative audit prefix changed")
            rows = [row for row in events if row["id"] not in baseline]
            require(self.count() == 0 and not any(row["event_type"] in {LEASE, START, RELEASE, BLOCK} for row in rows),
                "denied npm request reached provider or credential release")
            counts = Counter(row["event_type"] for row in rows)
            require(counts[CONNECT_DENIED] <= 1 and counts[DENIED] <= denied_count, "extra npm denial or retry detected")
            if counts[CONNECT_DENIED] == 1 and counts[DENIED] == denied_count and self.audit_drained():
                self.negative_cutoffs.append(cutoff)
                self.negative_observations.append({"case": phase, "providerAttempts": 0, "leaseEvents": 0})
                return
            time.sleep(min(0.1, self.timeout()))

    def accept_wire(self, row, spec, scope, credential_id, ordinal):
        require(row.get("ordinal") == ordinal and row.get("accepted") is True and row.get("case") == spec["case"]
            and row.get("allParsedHeadersValidated") is True and row.get("method") == "GET"
            and row.get("rawTarget") == spec["target"] and row.get("requestBodySha256") == digest(b"")
            and row.get("status") == spec["status"] and row.get("responseContentType") == spec["contentType"]
            and row.get("responseBodySha256") == digest(spec["body"]) and row.get("responseBodyBytes") == len(spec["body"]),
            "npm wire oracle found retry, changed target, headers or metadata")
        request_digest, operation_digest = canonical_digests(row, scope, credential_id, self.proxy.address)
        self.wire.append({"case": spec["case"], "target": spec["target"], "requestDigest": request_digest,
            "operationDigest": operation_digest, "bodySha256": digest(b""), "upstreamStatus": spec["status"],
            "responseBodySha256": digest(spec["body"]), "responseBodyBytes": len(spec["body"]),
            "responseContentType": spec["contentType"]})

    def verify_audits(self, baseline, scope, credential_id):
        exact = Counter(kind for kind, _, _ in self.mutations)
        exact.update({START: 7, RELEASE: 5, BLOCK: 2, CONNECT: 9, CONNECT_DENIED: 1, DENIED: 2, RELOAD: 1})
        drained = None
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for prior in [baseline, *self.negative_cutoffs]
                for key, value in prior.items()), "npm audit prefix changed")
            if drained is not None:
                require(all(cutoff.get(key) == value for key, value in drained.items())
                    and all(row["id"] in drained or row["event_type"] == LEASE for row in events), "npm drained audit changed unexpectedly")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row["event_type"] for row in rows)
            require(set(counts) <= set(exact) | {LEASE} and all(counts[key] <= count for key, count in exact.items()),
                "extra npm audit event or retry detected")
            pairs, complete = joined_attempts(rows, self.wire, scope, credential_id)
            dispatched = False
            denial_counts = Counter()
            for row in rows:
                kind, event = row["event_type"], row["event"]
                if kind == CONNECT:
                    require(event.get("target") == "registry.npmjs.org:443" and event.get("method") == "CONNECT"
                        and event.get("principal_id") == scope[0] and event.get("policy_hash") == scope[2]
                        and event.get("outcome") == "established", "npm CONNECT authority differs")
                elif kind == CONNECT_DENIED:
                    require(event.get("target") == "registry.npmjs.org:443" and event.get("method") == "CONNECT"
                        and event.get("outcome") == "denied" and event.get("principal_id") is None
                        and event.get("payload", {}).get("error") == "client_principal_denied", "npm unassigned application denial differs")
                elif kind == DENIED:
                    denial_counts[validate_denial(event, scope[1])] += 1
                    require(all(count == 1 for count in denial_counts.values()), "npm guard denial was repeated")
                elif kind == LEASE:
                    require(tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == scope
                        and event.get("credential_id") == credential_id and event.get("status_code") == 200
                        and event.get("outcome") == "issued" and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                        and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "npm lease authority differs")
                    if event["purpose"] == "dispatchSecret":
                        require(type(event.get("expected_credential_version")) is int and event["expected_credential_version"] == 1,
                            "npm dispatch lease generation differs")
                        dispatched = True
                    else:
                        require(event.get("expected_credential_version") is None, "npm metadata lease unexpectedly pins a version")
                elif kind == RELOAD:
                    require(event.get("previous_policy_hash") == self.initial_policy_hash and event.get("policy_hash") == scope[2]
                        and event.get("policy_sequence") == self.snapshot["policy"]["sequence"] and event.get("routes") == 1,
                        "npm policy reload does not join the sole rule")
            mutations = {(row["event_type"], row["event"].get("resource_id"), row["event"].get("policy_hash")) for row in rows}
            if all(counts[key] == count for key, count in exact.items()) and complete and dispatched and set(self.mutations) <= mutations and self.audit_drained():
                if drained is not None:
                    break
                drained = cutoff
                continue  # Revalidate the entire fresh snapshot, including any late lease.
            time.sleep(min(0.1, self.timeout()))
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True and verified.get("backend") == "sqlite",
            "npm durable audit chain incomplete")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(pairs)}

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.count() == 0, "fresh npm catalog and unused fixture required")
        capability = initial.get("capabilities", {}).get("npm", {})
        require(capability.get("destination_allowed") is True and capability.get("connection_type") == "npm_token_v1"
            and capability.get("metadata_only") is True and capability.get("registry_origin") == fixture.ORIGIN,
            "paired npm metadata catalog unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained(): time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials/npm-token", {"name": self.run_id + "-npm", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.npm_token_created", creates=True)
        apps = []
        for suffix in ("assigned", "unassigned"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + suffix,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
            apps.append((app, token))
        app, token = apps[0]
        rule, _, _ = self.mutate("/access-rules/npm-metadata", {"name": self.run_id + "-metadata", "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "npm_metadata_read_v1", "packages": sorted(fixture.PACKAGES)},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.npm_metadata_created",
            creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins = self.warm_cas_snapshot(); scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        require([len(pins[key]) for key in COLLECTIONS] == [1, 2, 1] and credential.get("credential_generation") == 1,
            "npm saved resource inventory differs")
        for index, phase in enumerate(NEGATIVES):
            self.unchanged(pins)
            result = self.client(phase, *(apps[1] if phase == "wrong_app" else apps[0]))
            require(result.get("refused") is True, "npm negative client did not refuse")
            self.checkpoint(baseline, phase, index)
        for ordinal, spec in enumerate(fixture.SPECS, 1):
            self.client(spec["case"], app, token)
            observed = self.observe()
            require(observed["total"] == ordinal, "npm client retried, followed or fetched an extra resource")
            self.accept_wire(observed["attempts"][-1], spec, scope, credential["id"], ordinal)
        evidence = self.verify_audits(baseline, scope, credential["id"])
        self.unchanged(pins)
        require(self.count() == 7, "late npm provider request detected")
        return {"ok": True, "schema": "serverware.privateNpmMetadataCheck/v1", "syntheticOnly": True,
            "productionReady": False, "realNpmVerified": False, "npmInstallVerified": False,
            "npmVersion": "11.8.0", "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1",
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "providerAttempts": 7,
            "releases": 5, "responseBlocks": 2, "deniedBeforeLease": 3, "canonicalRequestVersion": 2,
            "configuredRetries": 0, "defaultRetryBehaviorVerified": False, "metadataOnly": True,
            "stockClientTransports": True, "fullAndCorgiMetadataVerified": True,
            "allParsedUpstreamHeadersValidated": True, "hiddenWireHeaderProof": False, "publicDnsVerified": False,
            "negativeControls": self.negative_observations, "clients": self.clients, "requests": self.wire, **evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address"); parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_): raise CheckFailure("private npm checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256), "npm checker bounds invalid")
        signal.alarm(args.timeout_seconds); claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = NpmMetadataCheck(args); result = check.run()
        check.clean(json.dumps(result).encode())
    except Exception as error:
        safe = {}
        if check is not None:
            try:
                safe = features.safe_evidence(check)
                safe.update(completedClientRequests=check.wire, completedClientPhases=[item["phase"] for item in check.clients])
            except Exception:
                safe = {"safeEvidenceUnavailable": True}
        result = {"ok": False, "syntheticOnly": True, "productionReady": False,
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__, **safe}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
