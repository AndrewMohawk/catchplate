#!/usr/bin/env python3
"""Read-only retained-demo app/gate check, run inside the selected app container.

Reuses existing response validation but permits only catalog and health GETs.
No proxy dispatch, catalog mutation, provider request or pilot operation.
The caller verifies container/source identity and supplies previously recorded
public policy pins. Administrator credentials never leave this process.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import time
from types import SimpleNamespace

from scripts.check_operator_catalog import COLLECTIONS, PREFIX, OperatorCatalogCheck
from scripts.check_operator_demo import SHA256, require, token_file
from scripts.check_operator_ordinary_client import ZERO_COUNTERS, DRAIN_COUNTERS
from serverware.operator_demo import _destinations, origin


class ReadonlyPair(OperatorCatalogCheck):
    def catalog(self):
        upstreams, _ = _destinations(
            json.loads(os.environ.get("SERVERWARE_OPERATOR_DEMO_UPSTREAMS", "null")),
            json.loads(os.environ.get("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", "[]")))
        snapshot = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(isinstance(snapshot, dict) and snapshot.get("schema") == "serverware.operatorCatalog/v1"
                and snapshot.get("mode") == "operator-development"
                and snapshot.get("productionReady") is False and snapshot.get("hardwareVerified") is False
                and snapshot.get("allowed_upstreams") == list(upstreams)
                and type(snapshot.get("revision")) is int and snapshot["revision"] >= 1
                and all(isinstance(snapshot.get(key), list) for key in COLLECTIONS),
                "target is not the configured operator catalog")
        policy = snapshot.get("policy", {})
        require(isinstance(policy, dict) and isinstance(policy.get("policy_hash"), str)
                and SHA256.fullmatch(policy["policy_hash"])
                and type(policy.get("sequence")) is int and policy["sequence"] > 0,
                "catalog signed policy metadata is invalid")
        self.snapshot = snapshot
        return snapshot

    def json_request(self, endpoint, path, **kwargs):
        require((endpoint is self.control and path == "/api/operator-demo/catalog")
                or (endpoint is self.management and path == "/healthz"), "read-only endpoint required")
        require(kwargs.get("method", "GET") == "GET" and kwargs.get("payload") is None
                and not kwargs.get("creation"), "read-only request required")
        return super().json_request(endpoint, path, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--revision", type=int, required=True)
    parser.add_argument("--sequence", type=int, required=True)
    pins = parser.parse_args()
    signal.alarm(45)
    require(os.getuid() == os.getgid() == 10001 and pins.revision > 0 and pins.sequence > 0,
            "retained app identity required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", pins.binary_sha256)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", pins.policy_hash), "exact public pins required")
    require(os.environ.get("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST") == pins.binary_sha256,
            "app expected binary differs")
    args = SimpleNamespace(timeout_seconds=40, control_base="http://172.16.249.19:3000",
        management_base="http://172.16.249.20:9091", proxy_url="http://172.16.249.20:8080",
        operator_origin=origin(os.environ.get("SERVERWARE_PUBLIC_URL", "").strip())[0],
        upstream_address="172.16.249.18",
        expected_binary_sha256=pins.binary_sha256, proxy_ca_file=None, control_ca_file=None,
        management_ca_file=None, ca_file=Path("/data/mitmproxy/mitmproxy-ca-cert.pem"),
        upstream_ca_file=Path("/demo-upstream/ca.pem"))
    check = ReadonlyPair(args)
    check.admin_token = token_file(Path("/run/secrets/serverware/admin.token"))
    check.policy_hash = pins.policy_hash
    catalog, health = check.wait_catalog_loaded("retained_pair_readonly")
    while True:
        health = check.health()
        audit = health.get("audit", {})
        require(all(type(audit.get(key)) is int and audit[key] >= 0 for key in ZERO_COUNTERS + DRAIN_COUNTERS)
                and all(audit[key] == 0 for key in ZERO_COUNTERS), "audit delivery failed")
        if all(audit[key] == 0 for key in DRAIN_COUNTERS):
            break
        time.sleep(min(0.2, check.timeout()))
    require(catalog["revision"] == pins.revision and catalog["policy"]["sequence"] == pins.sequence,
            "retained catalog pins differ")
    require(catalog["capabilities"].get("oauth") is False
            and catalog["capabilities"].get("google_oauth") is None, "Google unexpectedly enabled")
    return {"ok": True, "binary_digest": pins.binary_sha256, "policy_hash": pins.policy_hash,
        "revision": pins.revision, "sequence": pins.sequence,
        "counts": {key: len(catalog[key]) for key in ("credentials", "applications", "access_rules")},
        "audit": {key: audit[key] for key in ZERO_COUNTERS + DRAIN_COUNTERS},
        "mutations_or_proxy_requests": False, "provider_or_production_acceptance": False}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"read-only pair check refused"}')
        raise SystemExit(1) from None
