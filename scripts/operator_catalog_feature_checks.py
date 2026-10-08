"""Private catalog feature oracles and bounded evidence; no launch capability."""
from __future__ import annotations

from collections import Counter
import hashlib
import http.client
import json
import os
import re
import stat
import time
from urllib.parse import urlencode

try:
    from scripts.check_operator_demo import AUTHORITY, MAX_BODY, SHA256, TunnelTLS, require
except ModuleNotFoundError:
    from check_operator_demo import AUTHORITY, MAX_BODY, SHA256, TunnelTLS, require


FULL_JSON = (b'\n{\n  "fixture_case": "catalog_full_json",\n'
    b'  "extra": {"nested": [1, true, null, {"kept": "all-fields"}], "unicode": "\\u2603"},\n'
    b'  "authorization_present": true, "authorization_matches_expected": true,\n'
    b'  "proxy_authorization_seen": false\n}\n')
PROJECTED_FIELDS = frozenset(("method", "path", "authorization_present", "authorization_scheme",
    "authorization_matches_expected", "proxy_authorization_seen"))
AUDIT_COUNTERS = ("dropped", "required_failed", "send_failed", "queue_depth", "reserved",
    "in_flight_optional", "pending_retry_batches", "pending_retry_events", "enqueued", "sent")
DIAGNOSTIC_STAGES = frozenset(("unclassified", "preflight", "transport", "response_body", "service_lifetime",
    "snapshot_not_current", "snapshot_changed", "response_statement_parse", "response_context_parse",
    "response_context_policy_mismatch", "response_context_other_mismatch", "response_verification_other",
    "http_status", "ack_parse", "ack_instance_mismatch", "ack_count_mismatch", "ack_digest_mismatch", "ack_contract_mismatch"))


def fixture_body(case, authorization, *, matched, proxy_seen):
    """Opt-in fixture responses only; reflection accepts this checker's synthetic key shape."""
    if case == "full":
        return FULL_JSON.replace(b'"authorization_present": true', b'"authorization_present": ' +
            (b"true" if authorization else b"false")).replace(b'"authorization_matches_expected": true',
            b'"authorization_matches_expected": ' + (b"true" if matched else b"false")).replace(
            b'"proxy_authorization_seen": false', b'"proxy_authorization_seen": ' + (b"true" if proxy_seen else b"false"))
    require(case in {"reflect_raw", "reflect_decoded"} and isinstance(authorization, str)
            and re.fullmatch(r"Bearer synthetic-operator-[A-Za-z0-9_-]{32,128}", authorization) is not None,
            "fixture reflection requires a bounded synthetic operator credential")
    reflected = (json.dumps(authorization).encode("ascii") if case == "reflect_raw" else
        ('"' + "".join("\\u%04x" % ord(character) for character in authorization) + '"').encode("ascii"))
    return b'{"credential_reflection":' + reflected + b'}'


def release_attempt_pairs(events, needed, blocked=None):
    """Each expected dispatch needs one start and its exact successful/blocked terminal."""
    blocked = blocked or Counter()
    total = needed + blocked
    pairs, row_ids = {}, set()
    kinds = {"data_plane.credential.release_started", "data_plane.response.released", "data_plane.response.blocked"}
    for row in events:
        event, kind = row.get("event", {}), row.get("event_type")
        scope = (event.get("principal_id"), event.get("route_id"), event.get("policy_hash"))
        if scope not in total or kind not in kinds:
            continue
        attempt = event.get("attempt_id")
        require(isinstance(attempt, str) and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt
                and event.get("method") == "GET", "successful audit request identity differs")
        require(row.get("id") not in row_ids, "duplicate durable audit row identity")
        row_ids.add(row["id"])
        terminal = kind != "data_plane.credential.release_started"
        if terminal:
            outcome = "blocked" if kind.endswith("blocked") else "released"
            require(event.get("upstream_status") == 200 and event.get("outcome") == outcome,
                    "audit response terminal outcome differs")
            if outcome == "blocked":
                require(event.get("response_validation", {}).get("error") == "response_credential_reflection"
                        and event.get("response_validation", {}).get("ok") is False,
                        "audit blocked response reason differs")
        else:
            require(event.get("outcome") == "release_started", "audit credential release outcome differs")
        pair = pairs.setdefault(attempt, {"scope": scope, "events": {}})
        slot = "terminal" if terminal else "start"
        require(pair["scope"] == scope and slot not in pair["events"],
                "request attempt reused across scopes or audit events")
        pair["events"][slot] = row["id"]
        if terminal:
            pair["outcome"] = outcome
    observed = Counter(pair["scope"] for pair in pairs.values())
    require(not observed - total, "more audit request identities than observed dispatches")
    complete = {attempt: pair for attempt, pair in pairs.items() if len(pair["events"]) == 2}
    actual = Counter(pair["scope"] for pair in complete.values() if pair["outcome"] == "released")
    actual_blocked = Counter(pair["scope"] for pair in complete.values() if pair["outcome"] == "blocked")
    require(not actual - needed and not actual_blocked - blocked,
            "more audit terminal outcomes than observed dispatches")
    return actual, complete


def verify_audit(check):
    needed, blocked, mutations = Counter(check.successes), Counter(getattr(check, "blocked_responses", [])), set(check.mutations)
    while True:
        events = check.audit()
        found, retained = set(), set()
        for row in events:
            event = row.get("event", {})
            key = (row.get("event_type"), event.get("resource_id"), event.get("policy_hash"))
            if key in mutations:
                found.add(key)
                retained.add(row["id"])
        actual, pairs = release_attempt_pairs(events, needed, blocked)
        actual_blocked = Counter(pair["scope"] for pair in pairs.values() if pair["outcome"] == "blocked")
        retained.update(identifier for pair in pairs.values() for identifier in pair["events"].values())
        audit = check.health().get("audit", {})
        check.last_audit_counters = {key: audit[key] for key in AUDIT_COUNTERS
            if type(audit.get(key)) is int and 0 <= audit[key] < 2**63}
        require(all(audit.get(key) == 0 for key in ("dropped", "required_failed", "send_failed")),
                "audit delivery reported a failure in the normal fixture")
        drained = all(audit.get(key) == 0 for key in ("queue_depth", "reserved", "in_flight_optional",
            "pending_retry_batches", "pending_retry_events"))
        if mutations <= found and actual == needed and actual_blocked == blocked and drained:
            break
        time.sleep(min(0.25, check.timeout()))
    final_events = check.audit()
    require(retained <= {row["id"] for row in final_events}, "audit rows did not survive fresh read")
    reconcile_negative_phases(check, final_events)
    chain = check.control_json("/api/audit/verify?limit=1000", authenticated=True)
    require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "complete persisted audit chain verification failed")
    check.results.append("distinct_request_attempt_pairs_with_drained_verified_audit_chain")
    return sorted(retained), sorted(pairs)


def safe_evidence(check):
    """Only authored observations/counters, never bodies, server errors or tokens."""
    value = {"policyObservations": getattr(check, "observations", []),
        "warmLeaseInvalidations": getattr(check, "warm_observations", []),
        "featureObservations": getattr(check, "feature_observations", []),
        "negativePhaseObservations": getattr(check, "negative_observations", []),
        "auditCounters": getattr(check, "last_audit_counters", {})}
    encoded = json.dumps(value, sort_keys=True).encode("utf-8")
    require(len(encoded) <= 32768, "safe evidence exceeds checkpoint bound")
    check.clean(encoded)
    return value


def checkpoint(check, stage):
    require(stage in {"lifecycle", "negative-phase", "features"}, "unexpected acceptance checkpoint")
    value = {"schema": "serverware.operatorCatalogObservations/v1", "stage": stage,
        "acceptanceComplete": False, **safe_evidence(check)}
    path = check.args.run_claim_file.parent / (".operator-catalog-" + stage + "-observations.json")
    directory = path.parent.stat()
    require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
            and directory.st_uid == os.geteuid() and path.parent.resolve() == path.parent,
            "observation directory must be private and owned")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(value, target, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def audit_cutoff(events):
    """UUID row IDs are not temporal; retain the complete bounded view and hashes."""
    require(isinstance(events, list) and len(events) < 500, "negative-phase audit view is saturated")
    cutoff = {}
    for row in events:
        identifier, event_hash = row.get("id"), row.get("event_hash")
        require(isinstance(identifier, str) and 1 <= len(identifier) <= 128 and identifier not in cutoff
                and isinstance(event_hash, str) and SHA256.fullmatch(event_hash),
                "negative-phase audit identity or chain hash is invalid")
        cutoff[identifier] = event_hash
    return cutoff


def issued_lease(row, scope):
    return row.get("event_type") == "data_plane.credential_lease.issued" and all(
        row.get("event", {}).get(key) == value for key, value in scope.items())


def record_negative_phase(check, code, scope):
    events = check.audit()
    cutoff = audit_cutoff(events)
    # The receiver persists the first exact-scope issuance before returning a
    # lease. This fresh principal/route has had no positive requests or lease.
    issued = [row["id"] for row in events if issued_lease(row, scope)]
    check.negative_observations.append({"case": code, "scope": dict(scope),
        "auditCutoff": cutoff, "issuedLeaseAuditEventIds": issued})
    require(not issued, "denied placeholder obtained a scoped dispatchSecret credential lease")
    require(not any(row.get("event_type") == "data_plane.credential.release_started"
        and row.get("event", {}).get("principal_id") == scope["principal_id"] for row in events),
        "denied placeholder obtained credential release authority")


def reconcile_negative_phases(check, events):
    observations = getattr(check, "negative_observations", [])
    if not observations:
        return
    current = audit_cutoff(events)
    for observation in observations:
        cutoff, scope = observation["auditCutoff"], observation["scope"]
        require(all(current.get(identifier) == event_hash for identifier, event_hash in cutoff.items()),
                "negative-phase audit cutoff did not survive final read")
        require(not any(issued_lease(row, scope) for row in events if row["id"] in cutoff),
                "negative-phase credential lease appeared in the final audit chain")


def request(check, path, placeholder):
    raw = check.tunnel(check.client_token)
    try:
        with TunnelTLS(raw, check.ca, check.timeout) as tls:
            headers = [f"GET {path} HTTP/1.1", f"Host: {AUTHORITY}", "Connection: close",
                f"User-Agent: serverware-test-run/{check.run_id}", "Accept: application/json"]
            if placeholder is not None:
                require(isinstance(placeholder, str) and len(placeholder) <= 1024
                        and all(32 <= ord(character) < 127 for character in placeholder), "unsafe synthetic header")
                headers.append("Authorization: " + placeholder)
            tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(tls)
            try:
                response.begin()
                body = response.read(MAX_BODY + 1)
                require(len(body) <= MAX_BODY, "feature response exceeds body bound")
                check.clean(str(response.getheaders()).encode("utf-8"))
                check.clean(body)
                document = json.loads(body)
                check.clean(json.dumps(document).encode("utf-8"))
                return response.status, document, body
            finally:
                response.close()
    finally:
        raw.close()


def run_features(check, credential):
    check.feature_observations, check.blocked_responses, check.negative_observations = [], [], []
    application, token, _ = check.mutate("/applications", {"name": check.run_id + "-features",
        "token_lifetime_seconds": 3600}, collection="applications", result_key="application",
        event="operator_catalog.application.created", creates=True, token=True)
    placeholder = "Bearer serverware-placeholder-" + check.run_id
    rule, _, _ = check.mutate("/access-rules", {"name": check.run_id + "-exact-full-json",
        "application_id": application["id"], "credential_id": credential["id"],
        "upstream_url": "https://" + AUTHORITY + "/echo", "methods": ["GET"],
        "request_fields": [], "response_fields": [], "response_mode": "unfiltered_json",
        "credential_input": "replace_exact", "placeholder": placeholder,
        "query_keys": ["expectedAuthorizationSha256", "catalogProof"], "allowed_headers": ["accept", "user-agent"]},
        collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created",
        creates=True, authority_changed=True)
    require(rule.get("response_mode") == "unfiltered_json" and rule.get("response_fields") == []
            and rule.get("credential_input") == "replace_exact" and rule.get("placeholder") == placeholder,
            "saved feature rule differs")
    check.wait_catalog_loaded("unfiltered_exact_replacement")
    check.client_token = token
    scope = (application["principal_id"], rule["route_id"], check.policy_hash)
    lease_scope = {"purpose": "dispatchSecret", "principal_id": application["principal_id"],
        "route_id": rule["route_id"], "credential_id": credential["id"], "policy_hash": check.policy_hash,
        "data_plane_binary_digest": check.args.expected_binary_sha256}
    digest = "sha256:" + hashlib.sha256(("Bearer " + check.credential).encode("ascii")).hexdigest()
    def path(case):
        return "/echo?" + urlencode({"expectedAuthorizationSha256": digest, "catalogProof": case})
    for supplied, code in ((None, "credential_existing_header_missing"),
                           (placeholder + "x", "credential_existing_header_mismatch")):
        before = check.count()
        status, document, _ = request(check, path("full"), supplied)
        require(status == 403 and document.get("allowed") is False and document.get("action") == "deny"
                and document.get("payload", {}).get("error") == code and check.count() == before,
                "placeholder mismatch or absence was not denied before dispatch")
        record_negative_phase(check, code, lease_scope)
        check.feature_observations.append({"case": code, "status": status, "upstreamDispatches": 0})
    checkpoint(check, "negative-phase")
    for case in ("full", "reflect_raw", "reflect_decoded"):
        before = check.count()
        status, document, body = request(check, path(case), placeholder)
        require(check.count() == before + 1, "feature request dispatch count differs")
        if case == "full":
            require(status == 200 and body == FULL_JSON, "unfiltered response bytes or exact credential replacement differs")
            check.successes.append(scope)
        else:
            require(status == 502 and document == {"error": "response_credential_reflection"},
                    "synthetic reflected credential was released")
            check.blocked_responses.append(scope)
        check.feature_observations.append({"case": case, "status": status, "upstreamDispatches": 1,
            "responseBodySha256": "sha256:" + hashlib.sha256(body).hexdigest()})
    snapshot = check.catalog()
    retained = check.resource(snapshot, "credentials", credential["id"])
    require(check.count() == 9 and len(snapshot["credentials"]) == 1 and retained["status"] == "active"
            and retained["version"] == credential["version"] and retained["active_rule_count"] == 2,
            "feature dispatch budget or shared credential preservation differs")
    check.results.append("unfiltered_full_json_exact_replacement_and_two_reflection_blocks")
    checkpoint(check, "features")
    return application["id"], rule["id"]


def parse_diagnostic(line):
    """Host-side collector may pass a single log message, never return raw text."""
    if not isinstance(line, str) or len(line) > 512:
        return None
    pairs = re.findall(r"([a-z_]+)=([^ ]+)", line)
    fields = dict(pairs)
    keys = {"phase", "stage", "outcome", "status", "event_count", "elapsed_ms", "same_snapshot", "same_policy_sequence"}
    if (len(pairs) != 8 or line != "audit_post_failure " + " ".join(key + "=" + value for key, value in pairs)
            or set(fields) != keys
            or fields["phase"] not in {"initial", "retry"} or fields["stage"] not in DIAGNOSTIC_STAGES
            or fields["outcome"] not in {"not_sent", "local_too_large", "authenticated_too_large", "outcome_unknown"}
            or any(fields[key] not in {"true", "false", "unknown"} for key in ("same_snapshot", "same_policy_sequence"))):
        return None
    for key in ("status", "event_count", "elapsed_ms"):
        value = fields[key]
        if value != "unknown" and (not value.isascii() or not value.isdecimal() or len(value) > 20):
            return None
        fields[key] = None if value == "unknown" else int(value)
    return fields
