#!/usr/bin/env python3
"""One-shot private acceptance of the shipped managed client's default HTTPS.

Requires a fresh, separately owned fixture, normal Rust binary, genuine private
DNS and outer CA in the interpreter's default trust store. The helper's child
uses -I and env={}; no transport, clock, resolver or TLS context is injected.
Creates one ordinary API client, enrolls its locally generated public key, and
dispatches twice with locked stock Requests across a close/reopen of its real
private journal. A naturally pending first result permits one exact replay only
after independent catalog/loaded-policy confirmation. No fabricated lost reply,
second issuance, provider retry, expiry/cancellation or public-provider claim.
This checker does not launch services, install dependencies or change trust.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys
import time
from urllib.parse import quote

# The reviewed fixture mounts just this new checker at /checker.py, outside the
# immutable /app snapshot. Ordinary repository invocation retains its own root.
SOURCE = Path(__file__).resolve().parents[1] if Path(__file__).parent.name == "scripts" else Path("/app")
sys.path[:0] = [str(SOURCE), str(SOURCE / "examples/managed-client")]

import requests
import managed_client as managed

from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, require, token_file
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import CONNECT, LEASE, RELEASE, RELOAD, START, OrdinaryClientCheck, RESPONSE_MODES, V2_RESPONSE_MODE, digest
from scripts.check_operator_proxy_basic import BASIC, ProxyBasicCheck, certificate_blocks, parsed_response, require_ca_pair
from scripts.operator_ordinary_client_fixture import DUMMY_AUTHORIZATION, FIXTURE_PATH, QUERY_KEYS, REQUEST_BODY

PROXY = "https://serverware-gmail-proxy.example.com"
RENEWED = "operator_catalog.application.token_renewed"
LOCK_SHA = "465a7fad6e1bc86bcefe947e41a4e478be306bc37893161fe4986da5304c869b"
VERSIONS = {"certifi": "2026.7.22", "cffi": "2.1.0", "charset-normalizer": "3.5.2",
    "cryptography": "50.0.0", "idna": "3.18", "pycparser": "3.0", "requests": "2.34.2", "urllib3": "2.8.0"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def dependency_evidence():
    directory = SOURCE / "examples/managed-client"
    locked = directory / "requirements.lock"
    require(sys.version_info[:2] == (3, 12) and hashlib.sha256(locked.read_bytes()).hexdigest() == LOCK_SHA,
        "reviewed CPython 3.12 and exact managed-client lock required")
    versions = {name: metadata.version(name) for name in VERSIONS}
    require(versions == VERSIONS and requests.__version__ == VERSIONS["requests"]
        and Path(requests.__file__).resolve() == Path(metadata.distribution("requests").locate_file("requests/__init__.py")).resolve()
        and Path(managed.__file__).resolve() == directory / "managed_client.py", "actual locked dependencies/helper differ")
    return {"pythonVersion": ".".join(map(str, sys.version_info[:3])), "dependencyVersions": versions,
        "managedRequirementsSha256": LOCK_SHA, "managedHelperSha256": hashlib.sha256(Path(managed.__file__).read_bytes()).hexdigest()}


def setup_from_catalog(application):
    """Same public DTO as the UI; there is no server-side setup-download route."""
    enrollment = application["client_renewal"]
    require(application["status"] == "active" and enrollment["status"] == "active"
        and enrollment["audience"] == PROXY + managed.PUBLIC_PATH
        and enrollment["token_lifetime_seconds"] == 3600 and enrollment["overlap_seconds"] == 300,
        "public workload enrollment differs")
    return {"schema": "serverware.managedClientSetup/v1", "application_id": application["id"],
        "enrollment_id": enrollment["enrollment_id"], "audience": enrollment["audience"],
        "public_key_fingerprint": enrollment["public_key_fingerprint"], "token_generation": application["token_generation"],
        "token_expires_at_epoch_ms": application["token_expires_at_epoch_ms"],
        "enrollment_expires_at_epoch_ms": enrollment["expires_at_epoch_ms"],
        "token_lifetime_seconds": enrollment["token_lifetime_seconds"], "overlap_seconds": enrollment["overlap_seconds"]}


def private_read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == os.geteuid() and before.st_nlink == 1 and 0 < before.st_size <= maximum,
            "private helper artifact permissions refused")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and stable_file_identity(before) == stable_file_identity(after)
            == stable_file_identity(path.stat(follow_symlinks=False)),
            "private helper artifact changed while reading")
        return raw


def stable_file_identity(info):
    # Our own read can update atime on relatime/tmpfs; it is not file mutation.
    return tuple(getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def private_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def journal(directory):
    require(set(path.name for path in directory.iterdir()) == {"lock", "ed25519.key", "state.json"},
        "unexpected helper journal file")
    return json.loads(private_read(directory / "state.json", managed.MAX_STATE_BYTES))


def validate_receipt(state, lease, setup, previous, pending=None):
    """Independent public receipt/installed-token join; never return a token."""
    receipt = state["last_receipt"]
    require(state["pending"] is None and type(receipt) is dict and set(receipt) == managed.RECEIPT_FIELDS
        and state["setup"] == setup and state["current"] == {
            "token": lease.token, "generation": lease.generation, "expires_at_epoch_ms": lease.expires_at_epoch_ms,
            "pool_refresh_by_epoch_ms": lease.pool_refresh_by_epoch_ms}, "helper did not install a definitive receipt")
    request = {"schema": "serverware.workloadTokenRenewal/v1", "audience": setup["audience"],
        "application_id": setup["application_id"], "enrollment_id": setup["enrollment_id"],
        "expected_token_generation": setup["token_generation"], "operation_id": receipt["operation_id"],
        "issued_at_epoch_ms": receipt["issued_at_epoch_ms"], "expires_at_epoch_ms": receipt["issued_at_epoch_ms"] + 60_000,
        "token_sha256": digest(lease.token.encode("ascii")), "token_expires_at_epoch_ms": lease.expires_at_epoch_ms}
    signing = b"serverware.workload-token-renewal/v1\x00POST /v1/workload/renew\x00" + canonical(request)
    require(receipt["application_id"] == setup["application_id"] and receipt["enrollment_id"] == setup["enrollment_id"]
        and receipt["previous_generation"] == setup["token_generation"] == 1
        and receipt["token_generation"] == lease.generation == 2 and receipt["token_sha256"] == request["token_sha256"]
        and receipt["request_sha256"] == digest(signing) and lease.token != previous
        and receipt["expires_at_epoch_ms"] == lease.expires_at_epoch_ms == min(
            receipt["issued_at_epoch_ms"] + 3_600_000, setup["enrollment_expires_at_epoch_ms"])
        and receipt["previous_accept_until_epoch_ms"] == min(setup["token_expires_at_epoch_ms"], receipt["rotated_at_epoch_ms"] + 300_000)
        and lease.pool_refresh_by_epoch_ms == min(receipt["previous_accept_until_epoch_ms"], lease.expires_at_epoch_ms),
        "installed helper receipt differs from the signed issuance")
    if pending is not None:
        original = json.loads(pending["request_original"])
        require(pending["candidate_token"] == lease.token
            and {key: value for key, value in original.items() if key != "signature"} == request
            and canonical(original).decode("ascii") == pending["request_original"], "recovery changed the retained operation")
    return receipt


def validate_catalog_change(before, after, receipt):
    left, right = authority_projection(before), authority_projection(after)
    require(all(left[key] == right[key] for key in left if key not in {"applications", "revision", "policy"})
        and set(left) == set(right) and len(left["applications"]) == len(right["applications"]) == 1
        and right["revision"] == left["revision"] + 1, "renewal changed unrelated catalog authority")
    old, current = left["applications"][0], right["applications"][0]
    changed = {"token_generation", "token_expires_at_epoch_ms", "token_rotated_at", "version"}
    require({key: value for key, value in old.items() if key not in changed}
        == {key: value for key, value in current.items() if key not in changed}
        and current["id"] == receipt["application_id"] and current["version"] == old["version"] + 1
        and current["token_generation"] == receipt["token_generation"]
        and current["token_expires_at_epoch_ms"] == receipt["expires_at_epoch_ms"]
        and current["access_status"] == "active" and current["active_rule_count"] == 1,
        "current application or permission does not match installed helper lease")
    policy = right["policy"]
    require(policy["sequence"] == left["policy"]["sequence"] + 1
        and policy["policy_hash"] != left["policy"]["policy_hash"] and policy["activation"] == "active"
        and policy["loaded_policy_hash"] == policy["policy_hash"], "renewal's current policy is not independently active")


def audit_projection(rows, observations, mutations, application, rule, credential_id, receipt, catalog, reload_chain, binary):
    """Closed two-request audit oracle, also checked on every incomplete view."""
    expected = Counter(kind for kind, _, _ in mutations)
    expected.update({START: 2, RELEASE: 2, CONNECT: 2, RENEWED: 1})
    counts = Counter(row["event_type"] for row in rows)
    require(len(rows) <= 100 and len({row["id"] for row in rows}) == len(rows)
        and not set(counts) - (set(expected) | {LEASE, RELOAD}) and counts[LEASE] <= 16
        and all(counts[kind] <= count for kind, count in expected.items()), "unexpected helper audit inventory")
    wire = Counter((row["policyHash"], row["requestDigest"], row["operationDigest"]) for row in observations)
    require(len(wire) == 2 and sum(wire.values()) == 2, "two distinct observed request commitments required")
    pairs, reloads, renewed, leased = {}, Counter(), [], False
    for row in rows:
        event, kind = row.get("event", {}), row["event_type"]
        if kind in {START, RELEASE}:
            key = tuple(event.get(name) for name in ("policy_hash", "request_digest", "operation_digest"))
            require(key in wire and event.get("principal_id") == application["principal_id"]
                and event.get("route_id") == rule["route_id"] and event.get("credential_ref") == credential_id
                and event.get("credential_version") == 1 and event.get("method") == "POST"
                and event.get("body_sha256") == digest(REQUEST_BODY), "provider release audit scope differs")
            attempt = event.get("attempt_id")
            require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                "provider release attempt identity differs")
            pair = pairs.setdefault(attempt, {"key": key})
            slot = "start" if kind == START else "terminal"
            require(pair["key"] == key and slot not in pair, "provider release attempt duplicated")
            pair[slot] = row["id"]
            if kind == START:
                require(event.get("outcome") == "release_started", "provider start outcome differs")
            else:
                validation = event.get("response_validation", {})
                require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                    and event.get("response_body_sha256") == digest(REQUEST_BODY)
                    and event.get("response_body_bytes") == len(REQUEST_BODY) and validation.get("ok") is True
                    and validation.get("mode") == RESPONSE_MODES[V2_RESPONSE_MODE]
                    and validation.get("body_bytes_preserved") is True, "provider terminal audit differs")
        elif kind == CONNECT:
            require(event.get("method") == "CONNECT" and event.get("target") == AUTHORITY
                and event.get("principal_id") == application["principal_id"]
                and event.get("policy_hash") == catalog["policy"]["policy_hash"]
                and event.get("outcome") == "established", "stock CONNECT audit differs")
        elif kind == RENEWED:
            require(row.get("actor_type") == "agent" and row.get("actor_id") == application["principal_id"]
                and all(event.get(key) == value for key, value in {
                    "resource_id": application["id"], "resource_type": "application",
                    "enrollment_id": receipt["enrollment_id"], "operation_id": receipt["operation_id"],
                    "token_generation": 2, "token_expires_at_epoch_ms": receipt["expires_at_epoch_ms"],
                    "revision": catalog["revision"], "policy_hash": catalog["policy"]["policy_hash"],
                    "policy_sequence": catalog["policy"]["sequence"]}.items()), "renewal audit receipt/actor differs")
            renewed.append(row["id"])
        elif kind == LEASE:
            require(event.get("principal_id") == application["principal_id"] and event.get("route_id") == rule["route_id"]
                and event.get("credential_id") == credential_id and event.get("policy_hash") == catalog["policy"]["policy_hash"]
                and event.get("status_code") == 200 and event.get("outcome") == "issued"
                and event.get("data_plane_binary_digest") == binary and event.get("purpose") in {"generationMetadata", "dispatchSecret"}
                and event.get("expected_credential_version") == (1 if event.get("purpose") == "dispatchSecret" else None),
                "credential lease audit differs")
            leased |= event["purpose"] == "dispatchSecret"
        elif kind == RELOAD:
            transition = tuple(event.get(key) for key in ("previous_policy_hash", "policy_hash", "policy_sequence", "routes"))
            reloads[transition] += 1
            require(transition in reload_chain and reloads[transition] <= reload_chain[transition], "unobserved policy reload")
    complete = [pair for pair in pairs.values() if {"start", "terminal"} <= pair.keys()]
    require(len(pairs) <= 2, "extra release attempts")
    lifecycle = {(row["event_type"], row.get("event", {}).get("resource_id"), row.get("event", {}).get("policy_hash")) for row in rows}
    return {"complete": all(counts[kind] == count for kind, count in expected.items())
        and len(complete) == 2 and Counter(pair["key"] for pair in complete) == wire
        and reloads == reload_chain and leased and set(mutations) <= lifecycle,
        "releaseAttemptIds": sorted(pairs), "renewalAuditIds": renewed,
        "auditEventIds": sorted(row["id"] for row in rows), "namedAuditInventory": dict(sorted(counts.items()))}


class ManagedHelperCheck(ProxyBasicCheck):
    def __init__(self, args):
        self.sensitive_proxy_forms = []
        OrdinaryClientCheck.__init__(self, args)
        self.ca_evidence = require_ca_pair(args.proxy_ca_file, args.ca_file, args.requests_ca_file)
        self.dependencies = dependency_evidence()
        require(not any(name in os.environ for name in ("SSL_CERT_FILE", "SSL_CERT_DIR")),
            "default-child trust must not depend on inherited environment")
        roots = set(ssl.create_default_context().get_ca_certs(binary_form=True))
        require(set(certificate_blocks(args.proxy_ca_file)) <= roots
            and not set(certificate_blocks(args.ca_file)) & roots, "default interpreter trust does not isolate outer CA")
        self.application = self.rule = self.renewal_receipt = None
        self.manager = None

    def stock(self, manager, lease, phase, accept):
        require(manager.proxy_origin == self.args.proxy_url == PROXY, "helper and stock proxy origin differ")
        addresses = {row[4][0] for row in socket.getaddrinfo(self.proxy.host, self.proxy.port, type=socket.SOCK_STREAM)}
        require(addresses == {self.proxy.address}, "default private proxy DNS differs")
        username, token = self.credentials(manager.application_id, lease.token)
        proxy = "https://" + quote(username, safe="") + ":" + quote(token, safe="") + "@" + PROXY.removeprefix("https://")
        self.sensitive_proxy_forms.append(proxy)
        before = self.count()
        with requests.Session() as session:
            session.trust_env = False
            session.proxies = {"https": proxy}
            session.verify = str(self.args.requests_ca_file)
            require(all(adapter.max_retries.total == 0 for adapter in session.adapters.values()), "stock Requests retries enabled")
            with session.post(self.target(), data=REQUEST_BODY, headers=self.request_headers(accept),
                    timeout=(min(3.0, self.timeout()), min(5.0, self.timeout())), allow_redirects=False, stream=True) as response:
                require(response.request.url == self.target() and response.request.method == "POST"
                    and response.request.body == REQUEST_BODY
                    and not any(name.lower() == "proxy-authorization" for name in response.request.headers),
                    "stock Requests changed the provider request")
                body = response.raw.read(65537, decode_content=False)
                fields = list(response.raw.headers.iteritems())
                self.clean(body); self.clean(str(fields).encode())
                result = parsed_response(response.status_code, fields, body, self.policy_hash)
        require(self.count() == before + 1, "stock request did not dispatch exactly once")
        result.update(phase=phase, policyHash=self.policy_hash, principalId=self.application["principal_id"],
            applicationId=self.application["id"], routeId=self.rule["route_id"], tokenGeneration=lease.generation)
        self.feature_observations.append(result)

    def verify_audit(self, baseline, catalog):
        chain = Counter((left["policyHash"], right["policyHash"], right["sequence"], 1)
            for left, right in zip(self.observations, self.observations[1:]))
        drained = None
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit changed")
            if drained is not None:
                require(all(cutoff.get(key) == value for key, value in drained.items())
                    and all(row["id"] in drained or row["event_type"] == LEASE for row in events), "audit changed after drain")
            result = audit_projection([row for row in events if row["id"] not in baseline], self.feature_observations,
                self.mutations, self.application, self.rule, self.credential_id, self.renewal_receipt, catalog, chain,
                self.args.expected_binary_sha256)
            if result["complete"] and self.audit_drained():
                if drained is not None:
                    verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
                    require(verified.get("ok") is True and verified.get("complete") is True
                        and verified.get("backend") == "sqlite", "durable audit chain failed")
                    return result
                drained = cutoff
            time.sleep(min(0.1, self.timeout()))

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[name] for name in COLLECTIONS) and self.count() == 0,
            "fresh empty private fixture required")
        self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-key", "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        self.credential_id = credential["id"]
        self.application, old_token, _ = self.mutate("/applications", {"name": self.run_id + "-client",
            "token_lifetime_seconds": 3600, "proxy_authentication": BASIC}, collection="applications", result_key="application",
            event="operator_catalog.application.created", creates=True, token=True)
        self.credentials(self.application["id"], old_token)
        self.rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-rule", "application_id": self.application["id"],
            "credential_id": credential["id"], "upstream_url": "https://" + AUTHORITY + FIXTURE_PATH, "methods": ["POST"],
            "request_body_mode": "preserve_json_v1", "response_mode": V2_RESPONSE_MODE, "request_fields": [], "response_fields": [],
            "credential_input": "replace_exact", "placeholder": DUMMY_AUTHORIZATION, "query_keys": list(QUERY_KEYS),
            "allowed_headers": ["accept", "accept-encoding", "user-agent"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("permission")
        directory = self.args.state_directory
        require(directory.is_absolute() and directory.parent == self.args.run_claim_file.parent
            and directory.name == "manager" and not os.path.lexists(directory), "fresh private helper directory required")
        self.manager = managed.ManagedClient(directory)
        public = self.manager.initialize()
        private_key = private_read(directory / "ed25519.key", 32)
        self.sensitive_proxy_forms.extend([private_key.hex(), base64.b64encode(private_key).decode()])
        self.application, _, _ = self.mutate("/applications/renewal/enroll", {"id": self.application["id"], "public_key": public,
            "enrollment_lifetime_seconds": 86400, "token_lifetime_seconds": 3600}, collection="applications", result_key="application",
            event="operator_catalog.application.renewal_enrolled", authority_changed=True)
        before, _ = self.wait_catalog_loaded("enrolled")
        self.application = self.resource(before, "applications", self.application["id"])
        setup = setup_from_catalog(self.application)
        old_file = directory.parent / "initial-token.private"
        private_write(old_file, old_token.encode("ascii"))
        private_write(directory.parent / "public-setup.json", canonical(setup))
        self.manager.configure(setup, old_file)
        lease = self.manager.lease()
        state = journal(directory)
        pending = state["pending"]
        recovered = pending is not None
        if recovered:
            require(lease.generation == 1 and lease.token == old_token and state["last_receipt"] is None,
                "pending renewal did not retain only the old safe lease")
            self.issued_tokens.append(pending["candidate_token"])
            self.manager.close(); self.manager = None
            committed = self.catalog()
            require(self.resource(committed, "applications", self.application["id"])["token_generation"] == 2
                and committed["revision"] == before["revision"] + 1, "pending issuance not independently observed; no replay")
            self.policy_hash = committed["policy"]["policy_hash"]
            self.wait_catalog_loaded("renewed")
            require(journal(directory) == state, "pending journal changed while waiting for current policy")
            self.manager = managed.ManagedClient(directory)
            lease = self.manager.lease()  # Only the retained literal operation can be sent.
            state = journal(directory)
        else:
            self.issued_tokens.append(lease.token)
        self.renewal_receipt = validate_receipt(state, lease, setup, old_token, pending)
        after = self.catalog()
        self.policy_hash = after["policy"]["policy_hash"]
        if not recovered:
            after, _ = self.wait_catalog_loaded("renewed")
        validate_catalog_change(before, after, self.renewal_receipt)
        self.application = after["applications"][0]
        require(self.count() == 0, "renewal incorrectly dispatched to provider")
        self.stock(self.manager, lease, "first_managed_lease", "application/json")
        installed = journal(directory)
        self.manager.close(); self.manager = None
        self.manager = managed.ManagedClient(directory)
        require(self.manager.initialize() == public and journal(directory) == installed, "restart changed key or installed journal")
        reopened = self.manager.lease()
        require(reopened == lease and journal(directory) == installed, "restart minted or changed the installed lease")
        self.stock(self.manager, reopened, "reopened_managed_lease", "application/json;q=0.9")
        require(self.count() == 2 and authority_projection(self.catalog()) == authority_projection(after),
            "dispatch/reopen changed catalog authority or provider count")
        audit = self.verify_audit(baseline, after)
        require(authority_projection(self.catalog()) == authority_projection(after), "audit observation changed authority")
        return {"schema": "serverware.operatorManagedHelperConnected/v1", "ok": True, "syntheticOnly": True,
            "productionReady": False, "realProviderVerified": False, "publicOriginVerified": False,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "defaultHelperHttpsTransport": True,
            "injectedTransport": False, "injectedClock": False, "resolverPatched": False,
            "customRequestsAdapter": False, "freshApiClient": True, "setupSource": "public-catalog-ui-equivalent-projection",
            "setupDownloaded": False, "journalReloadVerified": True, "keyRetained": True,
            "firstLeasePendingObserved": recovered, "exactPendingReplayAfterReload": recovered,
            "explicitPendingReplays": int(recovered), "artificialResponseLoss": False,
            "tokenGeneration": lease.generation, "renewalIssuances": 1, "upstreamDispatches": 2,
            "providerWriteRetries": 0, "expiryOrCancellationVerified": False, "fiveMinuteWallWaitPerformed": False,
            "operation": self.renewal_receipt, "observations": self.feature_observations,
            "catalogAuthorityPreservedAfterRenewal": True, "fixtureResourcesRetainedForOwnerCleanup": True,
            **self.dependencies, **self.ca_evidence, **audit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "requests-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file",
            "run-claim-file", "state-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    args.response_mode = V2_RESPONSE_MODE
    check = None
    def expired(*_):
        raise CheckFailure("managed helper connected check deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 120))
    try:
        require(args.proxy_url == PROXY and SHA256.fullmatch(args.expected_binary_sha256)
            and 30 <= args.timeout_seconds <= 120, "exact private proxy, normal binary and finite bound required")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = ManagedHelperCheck(args)
        result = check.run()
        check.clean(canonical(result))
    except Exception as error:
        result = {"ok": False, "syntheticOnly": True, "productionReady": False, "automaticRetry": False,
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}
    finally:
        if check is not None and check.manager is not None:
            check.manager.close()
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
