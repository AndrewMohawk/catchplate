#!/usr/bin/env python3
"""Synthetic managed readiness GETs, then the unchanged stock-client workload.

The two observation phases perform GETs only and do not claim the client run.
The clients phase is one-shot and retains the actual catalog revision after
Prepare/activation. No OAuth initiation, provider calls or Google credentials.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_proxy_basic as clients
from scripts import prepare_operator_managed_google_gate_fixture as fixture
from scripts.check_operator_demo import OperatorDemoCheck, Endpoint, CheckFailure, SHA256, require, token_file
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, MARKER, claim_fixture, features
from scripts.operator_managed_google_gate_prepare import SYNTHETIC_SECRET


def private_document(path, mode, maximum):
    require(path.is_absolute() and path.resolve() == path, "exact private fixture file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 10001
            and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum, "private fixture file differs")
        raw = os.read(descriptor, maximum + 1)
        require(len(raw) == info.st_size and SYNTHETIC_SECRET.encode() not in raw, "private public receipt differs")
        return json.loads(raw)
    finally:
        os.close(descriptor)


class ManagedMetadata:
    def metadata(self, args):
        receipt = None if args.phase == "unconfigured" else private_document(args.prepare_receipt_file, 0o600, 32768)
        self.managed_manifest = fixture.expected_manifest(args.fixture_cidr, receipt)
        self.managed_identity = fixture.identity(self.managed_manifest)
        self.managed_initial_revision = 1 if receipt is None else receipt["operation"]["staged_revision"] + 1
        self.prepared_policy = None if receipt is None else receipt["operation"]["policy_hash"]

    def __init__(self, args):
        self.metadata(args)
        super().__init__(args)

    def clean(self, content, *, allow_client_token=False):
        require(SYNTHETIC_SECRET.encode("ascii") not in content, "synthetic OAuth secret escaped public evidence")
        return super().clean(content, allow_client_token=allow_client_token)

    def health(self):
        health = super().health()
        require(health.get("policy_shadow", {}).get("managed_google") == self.managed_identity,
            "actual gate managed operation/profile/settings identity differs")
        return health

    def catalog(self):
        snapshot = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(type(snapshot) is dict and snapshot.get("schema") == "serverware.operatorCatalog/v1"
            and snapshot.get("mode") == "operator-development" and snapshot.get("productionReady") is False
            and snapshot.get("hardwareVerified") is False
            and snapshot.get("allowed_upstreams") == self.managed_manifest["effective_settings"]["allowed_upstreams"]
            and type(snapshot.get("revision")) is int and snapshot["revision"] >= self.managed_initial_revision
            and all(type(snapshot.get(key)) is list for key in COLLECTIONS), "managed fixture catalog differs")
        policy = snapshot.get("policy", {})
        require(type(policy) is dict and isinstance(policy.get("policy_hash"), str) and SHA256.fullmatch(policy["policy_hash"])
            and type(policy.get("sequence")) is int and policy["sequence"] > 0, "managed catalog policy metadata differs")
        capability = snapshot.get("capabilities", {}).get("google_oauth")
        if self.managed_identity["operation"] is None:
            require(capability is None, "unconfigured app advertised Google capability")
        else:
            profile = fixture.public_profile()
            require(capability == {"schema": "serverware.operatorGoogleCapability/v1",
                **{key: profile[key] for key in ("profile", "provider_id", "permission_preset", "scopes", "api_origins", "redirect_uri")},
                "authorization_origin": "https://accounts.google.com", "authorization_path": "/o/oauth2/v2/auth",
                "start_path": "/api/operator-demo/oauth/google/start", "intents_path": "/api/operator-demo/oauth/google/intents"},
                "committed app public Google profile differs")
        self.snapshot = snapshot
        return snapshot


class Observation(ManagedMetadata, OperatorDemoCheck):
    def __init__(self, args):
        # These GETs precede creation of the short-lived TLS edge. Do not even
        # resolve that proxy hostname or initialize the mutating client checker.
        self.metadata(args)
        self.args, self.results = args, []
        self.deadline = time.monotonic() + args.timeout_seconds
        self.credential = self.wrong_token = self.admin_token = self.client_token = None
        self.control, self.management = Endpoint(args.control_base), Endpoint(args.management_base)
        self.control_ca = self._optional_ca(args.control_ca_file, self.control)
        self.management_ca = self._optional_ca(args.management_ca_file, self.management)

    def run(self):
        self.admin_token = token_file(self.args.admin_token_file)
        health, catalog = self.health(), self.catalog()
        require(catalog["revision"] == self.managed_initial_revision
            and all(not catalog[key] and catalog["limits"][key]["retained"] == 0 for key in COLLECTIONS),
            "managed phase must precede all credential/application/rule writes")
        policy = catalog["policy"]
        require(policy["activation"] == "active" and policy["loaded_policy_hash"] == policy["policy_hash"]
            == health["policy_hash"] == health["policy_shadow"]["operator_policy_sha256"],
            "actual app readiness did not join the selected real gate")
        require(self.prepared_policy is None or self.prepared_policy == policy["policy_hash"],
            "Prepare/activation unexpectedly changed authority policy")
        return {"ok": True, "schema": "serverware.managedGoogleFixtureObservation/v1", "syntheticOnly": True,
            "phase": self.args.phase, "managedGoogle": self.managed_identity, "catalogRevision": catalog["revision"],
            "policyHash": policy["policy_hash"], "policySequence": policy["sequence"],
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "actualAppGateReady": True,
            "catalogResources": {key: len(catalog[key]) for key in COLLECTIONS}, "readOnly": True,
            "googleConsentStarted": False, "realProviderVerified": False, "productionReady": False}


class ManagedClients(ManagedMetadata, clients.ProxyBasicCheck):
    def run(self):
        # Preserve the stock check's orchestration and actual audit cutoffs. Its
        # initial revision is now exactly 3, not a fabricated revision-1 view.
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.managed_initial_revision == 3
            and initial["policy"]["policy_hash"] == self.prepared_policy
            and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.count() == 0, "fresh activated private catalog and upstream required")
        capability = initial.get("capabilities", {}).get("application_proxy_authentication")
        require(capability == {"schema": "serverware.operatorProxyAuthentication/v1", "modes": ["bearer", clients.BASIC],
            "path": PREFIX + "/applications/proxy-authentication"}
            and clients.V2_RESPONSE_MODE in initial.get("capabilities", {}).get("response_modes", []),
            "paired Basic and ordinary response capabilities unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-key", "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        require(credential.get("credential_generation") == 1, "fresh static generation differs")
        apps = []
        for index, mode in enumerate((clients.BASIC, "bearer", clients.BASIC)):
            payload = {"name": self.run_id + "-app-" + str(index), "token_lifetime_seconds": 3600}
            if mode == clients.BASIC:
                payload["proxy_authentication"] = mode
            app, token, _ = self.mutate("/applications", payload, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            require(app.get("proxy_authentication") == mode, "saved application authentication mode differs")
            self.credentials(app["id"], token)
            apps.append((app, token))
        assigned = []
        for index, (app, token) in enumerate(apps[:2]):
            rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-rule-" + str(index),
                "application_id": app["id"], "credential_id": credential["id"],
                "upstream_url": "https://" + clients.AUTHORITY + clients.FIXTURE_PATH, "methods": ["POST"],
                "request_body_mode": "preserve_json_v1", "response_mode": clients.V2_RESPONSE_MODE,
                "request_fields": [], "response_fields": [], "credential_input": "replace_exact",
                "placeholder": clients.DUMMY_AUTHORIZATION, "query_keys": list(clients.QUERY_KEYS),
                "allowed_headers": ["accept", "accept-encoding", "user-agent"]},
                collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created",
                creates=True, authority_changed=True)
            self.wait_catalog_loaded("assigned_rule_" + str(index))
            assigned.append((app, rule, token))
        pins = self.warm_cas_snapshot()
        require([len(pins[key]) for key in COLLECTIONS] == [1, 3, 2]
            and self.resource(pins, "applications", apps[2][0]["id"])["access_status"] == "unassigned", "resource budget differs")
        opt, opt_token = apps[0]
        for client in ("requests", "curl"):
            call = self.requests_call if client == "requests" else self.curl_call
            for label, username, token in (("wrong_username", apps[1][0]["id"], opt_token),
                ("wrong_token", opt["id"], self.wrong_basic_token), ("default_bearer", apps[1][0]["id"], apps[1][1]),
                ("unassigned", apps[2][0]["id"], apps[2][1])):
                self.current(pins)
                call(username, token, expected="denied")
                self.expected_denials += 1
                self.cold_checkpoint(client + "_" + label, baseline)
            for layer in ("outer", "inner"):
                if client == "requests":
                    call(opt["id"], opt_token, expected="tls", ca=self.args.ca_file if layer == "outer" else self.args.proxy_ca_file)
                else:
                    observed = call(opt["id"], opt_token, expected="tls", outer=self.args.ca_file if layer == "outer" else None,
                        inner=self.args.proxy_ca_file if layer == "inner" else None)
                    require(observed["connectStatus"] == (0 if layer == "outer" else 200), "curl failed at the wrong TLS layer")
                if layer == "inner":
                    self.expected_connects += 1
                self.cold_checkpoint(client + "_missing_" + layer + "_root", baseline)
                self.trust_controls.append({"client": client, "missingRoot": layer, "certificateVerificationRefused": True})
        for client, selected in (("requests", assigned[0]), ("curl", assigned[0]),
                ("bearer_opt_in", assigned[0]), ("bearer_default", assigned[1])):
            self.current(pins)
            self.positive(client, *selected)
        require(self.count() == 4 and self.expected_connects == 6 and self.expected_denials == 8, "fixed actual-client inventory differs")
        evidence = self.verify_client_audit(baseline, assigned, credential["id"])
        self.current(pins)
        return {"ok": True, "schema": "serverware.operatorProxyBasicCheck/v1", "syntheticOnly": True,
            "productionReady": False, "realProviderVerified": False, "publicDnsVerified": False,
            "managedGoogle": self.managed_identity, "managedInitialRevision": self.managed_initial_revision,
            "googleConsentStarted": False, "proxyTransport": "private-verified-https-edge", "proxyHostname": clients.PROXY_HOST,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "curlExecutableSha256": self.curl_digest,
            "requestsVersion": clients.requests.__version__, "urllib3Version": clients.urllib3.__version__,
            "customRequestsAdapter": False, "manufacturedBasicHeaderUsed": False,
            "upstreamDispatches": 4, "authenticationDenials": 8, "tlsControls": self.trust_controls,
            "functionalRetries": 0, "freshApiNaturalExpiryVerified": False,
            "expiryBoundary": "OPEN: minimum API token lifetime is3600s; no TTL/clock/database override",
            "basicHeaderForwarded": False, "providerInjectionVerifiedByPhysicalHeaderDigest": True,
            "upstreamClosedHeaderOracleVerified": True,
            "secretIsolationBoundary": "json_proxy_basic_v1 closes parsed upstream headers and exact query/body; no arbitrary encoding claim",
            **self.ca_evidence, **features.safe_evidence(self), **evidence}


def run_checks(args):
    check = None
    try:
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256)
            and type(args.timeout_seconds) is int and 30 <= args.timeout_seconds <= 120,
            "selected binary and bounded deadline required")
        require(args.operator_origin == fixture.base.ORIGIN and args.proxy_url == clients.PROXY
            and args.response_mode == clients.V2_RESPONSE_MODE, "fixed private fixture endpoints required")
        require(private_document(args.fixture_marker_file, 0o400, 1024) == MARKER, "synthetic marker differs")
        if args.phase == "clients":
            claim_fixture(args.fixture_marker_file, args.run_claim_file)
            check = ManagedClients(args)
        else:
            check = Observation(args)
        result = check.run()
        check.clean(json.dumps(result, sort_keys=True).encode("ascii"))
        return result
    except Exception as error:
        safe = {}
        if isinstance(check, ManagedClients):
            try:
                safe = features.safe_evidence(check)
            except Exception:
                safe = {"safeEvidenceUnavailable": True}
        return {"ok": False, "syntheticOnly": True, "productionReady": False, **safe,
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "fixture-cidr"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "requests-ca-file", "upstream-ca-file", "admin-token-file",
            "fixture-marker-file", "run-claim-file", "curl-binary", "prepare-receipt-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--response-mode", choices=(clients.V2_RESPONSE_MODE,), default=clients.V2_RESPONSE_MODE)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--phase", choices=("unconfigured", "activated", "clients"), required=True)
    args = parser.parse_args()
    def expired(*_):
        raise CheckFailure("managed fixture deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(min(max(args.timeout_seconds, 1), 120))
    try:
        result = run_checks(args)
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
