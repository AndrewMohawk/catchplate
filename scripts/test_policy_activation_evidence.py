#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

verifier = importlib.import_module("verify_policy_activation_evidence")


TIMES = {
    "staged": "2026-07-14T12:00:00+00:00",
    "baseline": "2026-07-14T12:01:00+00:00",
    "activated": "2026-07-14T12:02:00+00:00",
    "published": "2026-07-14T12:02:01+00:00",
    "allow": "2026-07-14T12:03:00+00:00",
    "deny": "2026-07-14T12:04:00+00:00",
    "generated": "2026-07-14T12:05:00+00:00",
}
BASELINE_HASH = "sha256:" + "1" * 64
STAGE_PAYLOAD_DIGEST = "sha256:" + "2" * 64
ACTIVATION_PAYLOAD_DIGEST = "sha256:" + "3" * 64
ROUTE_ID = "payments.read"
POLICY_ID = "serverware-production"
CANARY_ID = "policy-canary-42-candidate"
DATA_PLANE_ACTOR = "spiffe://prod.serverware.internal/decision-gate/instance-01"
BEARER_EXPIRY_EPOCH_MS = 1784077200000


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def signing_key_info(seed: bytes = b"\x19" * 32) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "private_key": private_key,
        "public_key_pem": pem,
        "key_id": verifier.sha256_prefixed_bytes(der),
    }


def candidate_document(
    *,
    key_info: dict[str, Any] | None = None,
    bundle_mutator: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    key_info = key_info or signing_key_info()
    bundle = {
        "apiVersion": "serverware.policy/v1",
        "kind": "PolicyBundle",
        "metadata": {
            "id": POLICY_ID,
            "sequence": 42,
            "rollbackEpoch": 7,
            "signingKeyId": key_info["key_id"],
        },
        "defaults": {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "principals": [
            {
                "id": "agent:payments",
                "sourceCidrs": ["10.20.0.0/16"],
                "requiredHeaders": {"X-Serverware-Agent": "payments-agent-prod-01"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "payments-prod-token-20260714",
                    "tokenSha256": "sha256:889d05b96df56cb1b5f15e51d8a922f4374877880b21cd9840a8404e3f54688e",
                    "sourceCidrs": ["10.20.1.0/24"],
                    "expiresAtEpochMs": BEARER_EXPIRY_EPOCH_MS,
                },
            }
        ],
        "credentials": [],
        "routes": [
            {
                "id": ROUTE_ID,
                "principals": ["agent:payments"],
                "match": {
                    "scheme": "https",
                    "host": "api.payments.internal",
                    "port": 443,
                    "methods": ["GET"],
                    "paths": ["/v1/customers/*"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedQueryKeys": [],
                            "bodyMode": "none",
                            "maxBodyBytes": 0,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": ["customer.id", "customer.name"],
                        },
                    },
                },
            }
        ],
    }
    if bundle_mutator is not None:
        bundle_mutator(bundle)
    signature = key_info["private_key"].sign(
        verifier.canonical_json(verifier.signature_payload(bundle)).encode("utf-8")
    )
    bundle["metadata"]["signature"] = "ed25519:" + b64e(signature)
    dry_run = {
        "required": True,
        "count": 2,
        "passed": True,
        "results": [
            {
                "index": 0,
                "name": "allow bounded read",
                "principalId": "agent:payments",
                "method": "GET",
                "host": "api.payments.internal",
                "path": "/v1/customers/customer-7",
                "expect": "allow",
                "decision": "allow",
                "routeId": ROUTE_ID,
                "reason": "route_matched",
                "passed": True,
            },
            {
                "index": 1,
                "name": "deny mutation",
                "principalId": "agent:payments",
                "method": "DELETE",
                "host": "api.payments.internal",
                "path": "/v1/customers/customer-7",
                "expect": "deny",
                "decision": "deny",
                "routeId": None,
                "reason": "route_not_matched",
                "passed": True,
            },
        ],
    }
    candidate = {
        "policy_hash": verifier.policy_hash(bundle),
        "signing_key_id": key_info["key_id"],
        "signing_public_key_pem": key_info["public_key_pem"],
        "signed_bundle": bundle,
        "dry_run": dry_run,
        "dry_run_sha256": verifier.sha256_prefixed_json(dry_run),
    }
    return candidate, key_info


def policy_diff() -> dict[str, Any]:
    return {
        "routes": {"added": [], "changed": [ROUTE_ID], "removed": []},
        "principals": {"added": [], "changed": [], "removed": []},
        "credentials": {"added": [], "changed": [], "removed": []},
    }


def data_plane_event(
    *,
    action: str,
    outcome: str,
    policy_hash: str,
    request_digest: str,
    operation_digest: str,
) -> dict[str, Any]:
    return {
        "component": "serverware-decision-gate-rs",
        "method": "GET" if action == "allow" else "DELETE",
        "url": {
            "scheme": "https",
            "authority": "api.payments.internal",
            "path": "/v1/customers/customer-7",
            "query_keys": [],
        },
        "outcome": outcome,
        "action": action,
        "status_code": 200 if action == "allow" else 403,
        "reason": "route_matched" if action == "allow" else "method_not_allowed",
        "principal_id": "agent:payments",
        "route_id": ROUTE_ID,
        "policy_hash": policy_hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "operation": "customers.read" if action == "allow" else "customers.delete",
    }


def append_audit_record(
    records: list[dict[str, Any]],
    *,
    event_type: str,
    actor_type: str,
    actor_id: str,
    event: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    record = {
        "id": f"audit-{len(records) + 1}",
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "event": event,
        "prev_event_hash": records[-1]["event_hash"] if records else None,
        "event_hash": "",
        "created_at": created_at,
    }
    record["event_hash"] = verifier.audit_event_hash(record)
    records.append(record)
    return record


def binding(record: dict[str, Any]) -> dict[str, Any]:
    event = record["event"]
    return {
        "audit_event_id": record["id"],
        "audit_event_hash": record["event_hash"],
        "observed_at": record["created_at"],
        "route_id": event["route_id"],
        "policy_hash": event["policy_hash"],
        "request_digest": event["request_digest"],
        "operation_digest": event["operation_digest"],
    }


def signed_audit_checkpoint(
    *,
    head: str,
    count: int,
    backend: str,
    ha: bool,
    key_info: dict[str, Any],
    export_header: dict[str, Any],
) -> dict[str, Any]:
    checkpoint = {
        "apiVersion": verifier.AUDIT_CHECKPOINT_API_VERSION,
        "kind": verifier.AUDIT_CHECKPOINT_KIND,
        "key_id": key_info["key_id"],
        "created_at": TIMES["generated"],
        "backend": backend,
        "ha": ha,
        "chain_head": head,
        "chain_count": count,
        "export_header_sha256": verifier.sha256_prefixed_json(export_header),
    }
    signature = key_info["private_key"].sign(
        verifier.canonical_json(verifier.audit_checkpoint_signature_payload(checkpoint)).encode("utf-8")
    )
    checkpoint["signature"] = "ed25519:" + b64e(signature)
    return checkpoint


def audit_export(
    records: list[dict[str, Any]],
    *,
    audit_key_info: dict[str, Any] | None = None,
    backend: str = "postgres",
    ha: bool = True,
) -> dict[str, Any]:
    audit_key_info = audit_key_info or signing_key_info(b"\x29" * 32)
    newest_first = list(reversed(records))
    count = len(newest_first)
    head = newest_first[0]["event_hash"]
    filters = {field: None for field in verifier.AUDIT_FILTER_FIELDS}
    filters["start"] = TIMES["staged"]
    header = {
        "kind": "serverware.auditExport.v1",
        "generated_at": TIMES["generated"],
        "backend": backend,
        "filters": filters,
        "count": count,
        "matched_in_scan": count,
        "scanned": count,
        "total_candidates": count,
        "complete": True,
        "chain": {
            "ok": True,
            "backend": backend,
            "ha": ha,
            "complete": True,
            "count": count,
            "total": count,
            "head": head,
        },
    }
    return {
        "header": header,
        "events": [
            {"kind": "serverware.auditEvent.v1", "export_index": index, "event": record}
            for index, record in enumerate(newest_first)
        ],
        "footer": {
            "kind": "serverware.auditExportEnd.v1",
            "count": count,
            "complete": True,
            "chain_head": head,
        },
        "checkpoint": signed_audit_checkpoint(
            head=head,
            count=count,
            backend=backend,
            ha=ha,
            key_info=audit_key_info,
            export_header=header,
        ),
    }


def evidence_document(
    *,
    policy_key_info: dict[str, Any] | None = None,
    audit_key_info: dict[str, Any] | None = None,
    actor_id: str = DATA_PLANE_ACTOR,
    bundle_mutator: Callable[[dict[str, Any]], None] | None = None,
    environment: str = "production",
    backend: str = "postgres",
    ha: bool = True,
) -> dict[str, Any]:
    policy_key_info = policy_key_info or signing_key_info()
    audit_key_info = audit_key_info or signing_key_info(b"\x29" * 32)
    candidate, _ = candidate_document(key_info=policy_key_info, bundle_mutator=bundle_mutator)
    candidate_hash = candidate["policy_hash"]
    dry_run = candidate["dry_run"]
    diff = policy_diff()
    records: list[dict[str, Any]] = []
    staged = append_audit_record(
        records,
        event_type="policy.canary.started",
        actor_type="admin",
        actor_id="user:publisher",
        event={
            "canary_id": CANARY_ID,
            "policy_id": POLICY_ID,
            "previous_policy_hash": BASELINE_HASH,
            "candidate_policy_hash": candidate_hash,
            "candidate_sequence": 42,
            "candidate_rollback_epoch": 7,
            "canary_bundle_path": "/var/lib/serverware/policy-canary-bundle.json",
            "diff": diff,
            "dry_run": dry_run,
            "control_plane_mfa": {"verified": True, "method": "webauthn"},
            "control_plane_approval": {"status": "approved", "approvers": 2},
            "payload_digest": STAGE_PAYLOAD_DIGEST,
        },
        created_at=TIMES["staged"],
    )
    baseline = append_audit_record(
        records,
        event_type="data_plane.response.released",
        actor_type="data-plane",
        actor_id=actor_id,
        event=data_plane_event(
            action="allow",
            outcome="released",
            policy_hash=BASELINE_HASH,
            request_digest="sha256:" + "4" * 64,
            operation_digest="sha256:" + "5" * 64,
        ),
        created_at=TIMES["baseline"],
    )
    activation_payload = {
        "activation_mode": "canary",
        "canary_id": CANARY_ID,
        "policy_id": POLICY_ID,
        "previous_policy_hash": BASELINE_HASH,
        "new_policy_hash": candidate_hash,
        "previous_sequence": 41,
        "new_sequence": 42,
        "previous_rollback_epoch": 7,
        "new_rollback_epoch": 7,
        "diff": diff,
        "dry_run": dry_run,
        "canary_monitoring": {
            "routeFilter": [ROUTE_ID],
            "auditEvents": 1,
            "denials": 0,
            "complete": True,
        },
        "canary_thresholds": {
            "requiredObservationSeconds": 60,
            "requiredAuditEvents": 1,
            "maxDenials": 0,
        },
        "control_plane_mfa": {"verified": True, "method": "webauthn"},
        "control_plane_approval": {"status": "approved", "approvers": 2},
        "payload_digest": ACTIVATION_PAYLOAD_DIGEST,
    }
    activated = append_audit_record(
        records,
        event_type="policy.canary.activated",
        actor_type="admin",
        actor_id="user:publisher",
        event=copy.deepcopy(activation_payload),
        created_at=TIMES["activated"],
    )
    published = append_audit_record(
        records,
        event_type="policy.published",
        actor_type="admin",
        actor_id="user:publisher",
        event=copy.deepcopy(activation_payload),
        created_at=TIMES["published"],
    )
    allowed = append_audit_record(
        records,
        event_type="data_plane.response.released",
        actor_type="data-plane",
        actor_id=actor_id,
        event=data_plane_event(
            action="allow",
            outcome="released",
            policy_hash=candidate_hash,
            request_digest="sha256:" + "6" * 64,
            operation_digest="sha256:" + "7" * 64,
        ),
        created_at=TIMES["allow"],
    )
    denied = append_audit_record(
        records,
        event_type="data_plane.request.denied",
        actor_type="data-plane",
        actor_id=actor_id,
        event=data_plane_event(
            action="deny",
            outcome="denied",
            policy_hash=candidate_hash,
            request_digest="sha256:" + "8" * 64,
            operation_digest="sha256:" + "9" * 64,
        ),
        created_at=TIMES["deny"],
    )
    allowed_binding = {"name": "production allow canary", "expected_decision": "allow", **binding(allowed)}
    denied_binding = {"name": "production denial canary", "expected_decision": "deny", **binding(denied)}
    document = {
        "apiVersion": verifier.API_VERSION,
        "kind": verifier.KIND,
        "evidence_sha256": "",
        "generated_at": TIMES["generated"],
        "deployment": {
            "environment": environment,
            "deployment_id": "deploy-20260714-001",
            "canary_id": CANARY_ID,
            "policy_id": POLICY_ID,
            "affected_route_ids": [ROUTE_ID],
            "baseline_policy_hash": BASELINE_HASH,
            "candidate_policy_hash": candidate_hash,
            "staged_at": TIMES["staged"],
            "activated_at": TIMES["activated"],
        },
        "candidate": candidate,
        "staging": {
            "staged_at": TIMES["staged"],
            "audit_event_id": staged["id"],
            "audit_event_hash": staged["event_hash"],
            "active_policy_hash": BASELINE_HASH,
            "candidate_policy_hash": candidate_hash,
        },
        "baseline": {
            "started_at": TIMES["staged"],
            "ended_at": TIMES["activated"],
            "policy_hash": BASELINE_HASH,
            "route_ids": [ROUTE_ID],
            "observations": [binding(baseline)],
        },
        "activation": {
            "activated_at": TIMES["activated"],
            "published_at": TIMES["published"],
            "audit_event_id": activated["id"],
            "audit_event_hash": activated["event_hash"],
            "published_audit_event_id": published["id"],
            "published_audit_event_hash": published["event_hash"],
            "previous_policy_hash": BASELINE_HASH,
            "candidate_policy_hash": candidate_hash,
        },
        "post_activation_canaries": [allowed_binding, denied_binding],
        "audit_export": audit_export(
            records,
            audit_key_info=audit_key_info,
            backend=backend,
            ha=ha,
        ),
    }
    refresh_evidence_digest(document)
    return document


def refresh_evidence_digest(document: dict[str, Any]) -> None:
    document["evidence_sha256"] = verifier.evidence_digest(document)


def chronological_records(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [wrapper["event"] for wrapper in reversed(document["audit_export"]["events"])]


def sync_reference_hashes(document: dict[str, Any]) -> None:
    records = {record["id"]: record for record in chronological_records(document)}
    document["staging"]["audit_event_hash"] = records[document["staging"]["audit_event_id"]]["event_hash"]
    document["activation"]["audit_event_hash"] = records[document["activation"]["audit_event_id"]]["event_hash"]
    document["activation"]["published_audit_event_hash"] = records[document["activation"]["published_audit_event_id"]]["event_hash"]
    for item in document["baseline"]["observations"] + document["post_activation_canaries"]:
        item["audit_event_hash"] = records[item["audit_event_id"]]["event_hash"]


def rebuild_audit_export(document: dict[str, Any], records: list[dict[str, Any]]) -> None:
    previous_hash = None
    for record in records:
        record["prev_event_hash"] = previous_hash
        record["event_hash"] = verifier.audit_event_hash(record)
        previous_hash = record["event_hash"]
    document["audit_export"] = audit_export(records)
    sync_reference_hashes(document)
    refresh_evidence_digest(document)


def mutate(document: dict[str, Any], operation: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    operation(changed)
    refresh_evidence_digest(changed)
    return changed


def verification_inputs(
    *,
    policy_key_info: dict[str, Any] | None = None,
    audit_key_info: dict[str, Any] | None = None,
    expected_actor: str = DATA_PLANE_ACTOR,
) -> dict[str, str]:
    policy_key_info = policy_key_info or signing_key_info()
    audit_key_info = audit_key_info or signing_key_info(b"\x29" * 32)
    return {
        "trusted_policy_public_key_pem": policy_key_info["public_key_pem"],
        "trusted_audit_checkpoint_public_key_pem": audit_key_info["public_key_pem"],
        "expected_data_plane_actor": expected_actor,
    }


def expect_failure(
    document: dict[str, Any],
    expected: str,
    *,
    production: bool = True,
    inputs: dict[str, str] | None = None,
) -> None:
    try:
        verifier.verify_evidence(
            document,
            production=production,
            **(inputs or verification_inputs()),
        )
    except verifier.EvidenceError as exc:
        if expected not in str(exc):
            raise AssertionError(f"expected failure containing {expected!r}, got {exc!r}") from exc
    else:
        raise AssertionError(f"evidence unexpectedly passed; expected {expected!r}")


def main() -> None:
    valid = evidence_document()
    result = verifier.verify_evidence(valid, production=True, **verification_inputs())
    if result.get("ok") is not True:
        raise AssertionError(f"valid production evidence failed: {result}")
    if result.get("candidate_pre_activation_traffic") != 0:
        raise AssertionError(f"valid evidence did not prove zero candidate traffic: {result}")
    if result.get("post_activation_allow_canaries") != 1 or result.get("post_activation_denial_canaries") != 1:
        raise AssertionError(f"valid evidence did not prove both post-activation canaries: {result}")
    if result.get("expected_data_plane_actor") != DATA_PLANE_ACTOR:
        raise AssertionError(f"valid evidence did not bind the configured SPIFFE actor: {result}")
    if result.get("trusted_policy_signing_key_id") == result.get("audit_checkpoint_signing_key_id"):
        raise AssertionError(f"valid evidence reused a trust root across policy and audit roles: {result}")

    expect_failure(
        mutate(valid, lambda document: document["deployment"].__setitem__("deployment_id", "synthetic-deployment")),
        "synthetic/fixture marker",
    )
    test_mode = evidence_document(environment="test", backend="sqlite", ha=False)
    test_mode["deployment"]["deployment_id"] = "synthetic-deployment"
    refresh_evidence_digest(test_mode)
    test_result = verifier.verify_evidence(test_mode, production=False, **verification_inputs())
    if test_result.get("ok") is not True or test_result.get("production_mode") is not False:
        raise AssertionError(f"explicit test mode did not permit fixture evidence: {test_result}")
    expect_failure(
        mutate(valid, lambda document: document["candidate"]["signed_bundle"]["metadata"].__setitem__("signature", "ed25519:" + b64e(b"x" * 64))),
        "candidate policy signature verification failed",
    )

    forged_policy_key = signing_key_info(b"\x39" * 32)
    expect_failure(
        evidence_document(policy_key_info=forged_policy_key),
        "candidate signing key does not match the operator trust root",
    )
    forged_audit_key = signing_key_info(b"\x49" * 32)
    expect_failure(
        evidence_document(audit_key_info=forged_audit_key),
        "audit checkpoint signing key does not match the operator trust root",
    )
    expect_failure(
        mutate(
            valid,
            lambda document: document["audit_export"]["checkpoint"].__setitem__(
                "signature",
                "ed25519:" + b64e(b"x" * 64),
            ),
        ),
        "audit checkpoint signature verification failed",
    )
    expect_failure(
        valid,
        "wrong data-plane audit actor",
        inputs=verification_inputs(
            expected_actor="spiffe://prod.serverware.internal/decision-gate/instance-02"
        ),
    )
    expect_failure(
        evidence_document(
            bundle_mutator=lambda bundle: bundle["routes"][0]["match"].__setitem__("paths", [])
        ),
        "candidate failed canonical policy schema or semantic validation",
    )
    expect_failure(
        evidence_document(
            bundle_mutator=lambda bundle: bundle["principals"][0].pop("proxyAuthorization")
        ),
        "candidate failed canonical production identity validation",
    )
    expect_failure(
        mutate(valid, lambda document: document["post_activation_canaries"].pop()),
        "denial canary is missing",
    )
    expect_failure(
        mutate(valid, lambda document: document["post_activation_canaries"][0].__setitem__("route_id", "other.route")),
        "route is outside",
    )
    expect_failure(
        mutate(valid, lambda document: document["post_activation_canaries"][0].__setitem__("observed_at", TIMES["baseline"])),
        "observation time mismatch",
    )
    expect_failure(
        mutate(valid, lambda document: document["post_activation_canaries"][0].__setitem__("request_digest", "sha256:" + "a" * 64)),
        "request_digest mismatch",
    )
    expect_failure(
        mutate(valid, lambda document: document["activation"].__setitem__("candidate_policy_hash", BASELINE_HASH)),
        "activation candidate policy mismatch",
    )
    expect_failure(
        mutate(valid, lambda document: document["audit_export"]["header"].__setitem__("complete", False)),
        "audit export scan is incomplete",
    )

    tampered_audit = copy.deepcopy(valid)
    tampered_audit["audit_export"]["events"][0]["event"]["event"]["reason"] = "tampered"
    refresh_evidence_digest(tampered_audit)
    expect_failure(tampered_audit, "event hash mismatch")

    bad_evidence_digest = copy.deepcopy(valid)
    bad_evidence_digest["evidence_sha256"] = "sha256:" + "f" * 64
    expect_failure(bad_evidence_digest, "evidence digest mismatch")

    candidate_traffic = copy.deepcopy(valid)
    records = chronological_records(candidate_traffic)
    extra = {
        "id": "audit-candidate-before-activation",
        "event_type": "data_plane.connect.established",
        "actor_type": "data-plane",
        "actor_id": DATA_PLANE_ACTOR,
        "event": {
            "component": "serverware-decision-gate-rs",
            "method": "CONNECT",
            "outcome": "established",
            "action": "allow",
            "route_ids": [ROUTE_ID],
            "policy_hash": candidate_traffic["deployment"]["candidate_policy_hash"],
        },
        "prev_event_hash": None,
        "event_hash": "",
        "created_at": "2026-07-14T12:01:30+00:00",
    }
    records.insert(2, extra)
    rebuild_audit_export(candidate_traffic, records)
    expect_failure(candidate_traffic, "candidate policy received traffic before explicit activation")

    activation_mismatch = copy.deepcopy(valid)
    activation_records = chronological_records(activation_mismatch)
    activated_record = next(record for record in activation_records if record["event_type"] == "policy.canary.activated")
    activated_record["event"]["new_policy_hash"] = BASELINE_HASH
    rebuild_audit_export(activation_mismatch, activation_records)
    expect_failure(activation_mismatch, "activation candidate policy hash mismatch")

    with tempfile.TemporaryDirectory() as tmp:
        evidence_path = Path(tmp) / "policy-activation-evidence.json"
        policy_key_path = Path(tmp) / "policy-public.pem"
        audit_key_path = Path(tmp) / "audit-checkpoint-public.pem"
        evidence_path.write_text(json.dumps(valid, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        policy_key_path.write_text(signing_key_info()["public_key_pem"], encoding="ascii")
        audit_key_path.write_text(signing_key_info(b"\x29" * 32)["public_key_pem"], encoding="ascii")
        cli = [
            sys.executable,
            str(ROOT / "scripts" / "verify_policy_activation_evidence.py"),
            "--trusted-policy-public-key",
            str(policy_key_path),
            "--trusted-audit-checkpoint-public-key",
            str(audit_key_path),
            "--expected-data-plane-actor",
            DATA_PLANE_ACTOR,
        ]
        completed = subprocess.run(
            [*cli, str(evidence_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"verifier CLI rejected valid evidence: {completed.stderr or completed.stdout}")
        cli_result = json.loads(completed.stdout)
        if cli_result.get("ok") is not True or cli_result.get("post_activation_denial_canaries") != 1:
            raise AssertionError(f"verifier CLI returned the wrong result: {cli_result}")

        duplicate_path = Path(tmp) / "duplicate.json"
        duplicate_path.write_text('{"apiVersion":"one","apiVersion":"two"}\n', encoding="utf-8")
        duplicate = subprocess.run(
            [*cli, str(duplicate_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if duplicate.returncode == 0 or "duplicate JSON object key" not in duplicate.stderr:
            raise AssertionError(f"verifier CLI accepted duplicate JSON keys: {duplicate.stderr or duplicate.stdout}")

        nonstandard_path = Path(tmp) / "nonstandard-number.json"
        nonstandard_path.write_text('{"value":NaN}\n', encoding="utf-8")
        nonstandard = subprocess.run(
            [*cli, str(nonstandard_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if nonstandard.returncode == 0 or "non-standard JSON constant" not in nonstandard.stderr:
            raise AssertionError(
                f"verifier CLI accepted a non-standard numeric constant: {nonstandard.stderr or nonstandard.stdout}"
            )

    print(verifier.canonical_json({"ok": True, "policy_activation_evidence": "pass"}))


if __name__ == "__main__":
    main()
