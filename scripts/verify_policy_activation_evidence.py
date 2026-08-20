#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.policy_bundle import PolicyBundleError, compile_policy_bundle  # noqa: E402
from verify_production_policy_identity import verify_production_policy_identity  # noqa: E402


API_VERSION = "serverware.policyActivationEvidence/v1"
KIND = "PolicyActivationEvidence"
VERIFICATION_API_VERSION = "serverware.policyActivationEvidenceVerification/v1"
AUDIT_CHECKPOINT_API_VERSION = "serverware.auditCheckpoint/v1"
AUDIT_CHECKPOINT_KIND = "AuditCheckpoint"
MAX_PUBLIC_KEY_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PRODUCTION_MARKER_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:fixture|synthetic|simulated|mock|test[-_ ]only|development[-_ ]fixture|none[-_ ]dev)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)
AUDIT_FILTER_FIELDS = {
    "event_type",
    "actor_type",
    "actor_id",
    "principal_id",
    "route_id",
    "policy_hash",
    "credential_id",
    "credential_version",
    "approval_id",
    "decision",
    "attestation_measurement",
    "start",
    "end",
    "q",
}
BASELINE_EVENT_TYPES = {
    "data_plane.request.denied",
    "data_plane.request.streamed",
    "data_plane.response.blocked",
    "data_plane.response.released",
}


class EvidenceError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def require_object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} must be a sha256-prefixed digest")
    return value


def require_exact_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    actual = set(value)
    missing = sorted(fields - actual)
    extra = sorted(actual - fields)
    require(not missing, f"{label} is missing fields: {', '.join(missing)}")
    require(not extra, f"{label} has unknown fields: {', '.join(extra)}")


def parse_time(value: Any, label: str) -> datetime:
    raw = require_string(value, label)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} is not an ISO-8601 timestamp") from exc
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    require(parsed.utcoffset() == timezone.utc.utcoffset(parsed), f"{label} must be UTC")
    return parsed


def b64d(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise EvidenceError(f"{label} is invalid base64url") from exc


def parse_trusted_ed25519_public_key(public_key_pem: str, label: str) -> tuple[Ed25519PublicKey, str]:
    require(isinstance(public_key_pem, str) and bool(public_key_pem), f"{label} is required")
    require(len(public_key_pem.encode("utf-8")) <= MAX_PUBLIC_KEY_BYTES, f"{label} exceeds 64 KiB")
    require("PRIVATE KEY" not in public_key_pem, f"{label} must contain public key material only")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise EvidenceError(f"{label} is invalid") from exc
    require(isinstance(public_key, Ed25519PublicKey), f"{label} must be Ed25519")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key, sha256_prefixed_bytes(public_der)


def load_trusted_public_key(path: Path, label: str) -> str:
    require(path.is_file(), f"{label} does not exist")
    require(path.stat().st_size <= MAX_PUBLIC_KEY_BYTES, f"{label} exceeds 64 KiB")
    try:
        value = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise EvidenceError(f"{label} could not be read as ASCII PEM") from exc
    parse_trusted_ed25519_public_key(value, label)
    return value


def verify_ed25519_signature(
    public_key: Ed25519PublicKey,
    signature_value: Any,
    payload: dict[str, Any],
    label: str,
) -> None:
    signature = require_string(signature_value, f"{label} signature")
    require(signature.startswith("ed25519:"), f"{label} signature is not ed25519")
    signature_bytes = b64d(signature.split(":", 1)[1], f"{label} signature")
    require(len(signature_bytes) == 64, f"{label} signature has the wrong length")
    try:
        public_key.verify(signature_bytes, canonical_json(payload).encode("utf-8"))
    except InvalidSignature as exc:
        raise EvidenceError(f"{label} signature verification failed") from exc


def reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise EvidenceError(f"duplicate JSON object key: {key}")
        parsed[key] = value
    return parsed


def reject_json_constant(value: str) -> None:
    raise EvidenceError(f"non-standard JSON constant is forbidden: {value}")


def load_evidence(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"evidence document does not exist: {path}")
    require(path.stat().st_size <= 64 * 1024 * 1024, "evidence document exceeds 64 MiB")
    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_object_keys,
            parse_constant=reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise EvidenceError("evidence document is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"evidence document is invalid JSON: {exc}") from exc
    return require_object(parsed, "evidence document")


def evidence_digest(document: dict[str, Any]) -> str:
    payload = copy.deepcopy(document)
    payload.pop("evidence_sha256", None)
    return sha256_prefixed_json(payload)


def signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(bundle)
    metadata = unsigned.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
    return unsigned


def policy_hash(bundle: dict[str, Any]) -> str:
    return sha256_prefixed_json(signature_payload(bundle))


def verify_candidate(
    candidate: dict[str, Any],
    deployment: dict[str, Any],
    affected_routes: set[str],
    *,
    production: bool,
    trusted_policy_public_key_pem: str,
    policy_validation_time: datetime,
) -> dict[str, Any]:
    require_exact_fields(
        candidate,
        {
            "policy_hash",
            "signing_key_id",
            "signing_public_key_pem",
            "signed_bundle",
            "dry_run",
            "dry_run_sha256",
        },
        "candidate",
    )
    candidate_hash = require_sha256(candidate.get("policy_hash"), "candidate.policy_hash")
    require(candidate_hash == deployment["candidate_policy_hash"], "candidate policy hash does not match deployment")
    bundle = require_object(candidate.get("signed_bundle"), "candidate.signed_bundle")
    metadata = require_object(bundle.get("metadata"), "candidate.signed_bundle.metadata")
    require(metadata.get("id") == deployment["policy_id"], "signed candidate policy id mismatch")
    require(policy_hash(bundle) == candidate_hash, "signed candidate policy hash mismatch")
    bundle_routes = require_list(bundle.get("routes"), "candidate.signed_bundle.routes")
    signed_route_ids = {
        route.get("id")
        for route in bundle_routes
        if isinstance(route, dict) and isinstance(route.get("id"), str) and route.get("id")
    }
    require(affected_routes.issubset(signed_route_ids), "affected route is missing from the signed candidate")

    signing_key_id = require_sha256(candidate.get("signing_key_id"), "candidate.signing_key_id")
    require(metadata.get("signingKeyId") == signing_key_id, "signed candidate signing key id mismatch")
    trusted_public_key, trusted_key_id = parse_trusted_ed25519_public_key(
        trusted_policy_public_key_pem,
        "trusted policy public key",
    )
    require(signing_key_id == trusted_key_id, "candidate signing key does not match the operator trust root")
    embedded_public_key_pem = require_string(
        candidate.get("signing_public_key_pem"),
        "candidate.signing_public_key_pem",
    )
    _, embedded_key_id = parse_trusted_ed25519_public_key(
        embedded_public_key_pem,
        "candidate signing public key",
    )
    require(embedded_key_id == trusted_key_id, "candidate embedded signing key does not match the operator trust root")
    verify_ed25519_signature(
        trusted_public_key,
        metadata.get("signature"),
        signature_payload(bundle),
        "candidate policy",
    )

    try:
        compile_policy_bundle(bundle, validate_schema=True, verify_signature=False)
    except (PolicyBundleError, KeyError, TypeError, ValueError) as exc:
        raise EvidenceError("candidate failed canonical policy schema or semantic validation") from exc
    if production:
        identity_report = verify_production_policy_identity(
            bundle,
            trusted_policy_public_key_pem,
            trusted_public_key_hash=trusted_key_id,
            now_epoch_ms=int(policy_validation_time.timestamp() * 1000),
        )
        if identity_report.get("ok") is not True:
            issue_codes = sorted(
                {
                    str(item.get("code"))
                    for item in identity_report.get("issues", [])
                    if isinstance(item, dict) and item.get("code")
                }
            )
            suffix = f": {', '.join(issue_codes)}" if issue_codes else ""
            raise EvidenceError(f"candidate failed canonical production identity validation{suffix}")

    dry_run = require_object(candidate.get("dry_run"), "candidate.dry_run")
    require_exact_fields(dry_run, {"required", "count", "passed", "results"}, "candidate.dry_run")
    results = require_list(dry_run.get("results"), "candidate.dry_run.results")
    require(isinstance(dry_run.get("count"), int) and not isinstance(dry_run.get("count"), bool), "candidate dry-run count must be an integer")
    require(dry_run["count"] == len(results) and len(results) > 0, "candidate dry-run count mismatch or empty results")
    require(dry_run.get("passed") is True, "candidate dry-runs did not pass")
    if production:
        require(dry_run.get("required") is True, "production candidate did not require dry-runs")
    dry_run_route_ids: set[str] = set()
    for index, item in enumerate(results):
        result = require_object(item, f"candidate.dry_run.results[{index}]")
        require(result.get("passed") is True, f"candidate dry-run result {index} did not pass")
        expected = result.get("expect")
        decision = result.get("decision")
        require(expected in {"allow", "deny"}, f"candidate dry-run result {index} has invalid expectation")
        require(decision == expected, f"candidate dry-run result {index} decision mismatch")
        route_id = result.get("routeId")
        expected_route_id = result.get("expectedRouteId")
        if expected_route_id is not None:
            require(
                isinstance(expected_route_id, str) and expected_route_id,
                f"candidate dry-run result {index} expected route is invalid",
            )
            require(
                expected == "allow" and route_id == expected_route_id,
                f"candidate dry-run result {index} did not select its expected route",
            )
            require(
                expected_route_id in signed_route_ids,
                f"candidate dry-run result {index} expected route is not in the signed candidate",
            )
        if isinstance(route_id, str) and route_id:
            require(route_id in signed_route_ids, f"candidate dry-run result {index} route is not in the signed candidate")
            dry_run_route_ids.add(route_id)
    require(affected_routes.issubset(dry_run_route_ids), "candidate dry-runs do not cover every affected route")
    dry_run_digest = require_sha256(candidate.get("dry_run_sha256"), "candidate.dry_run_sha256")
    require(dry_run_digest == sha256_prefixed_json(dry_run), "candidate dry-run digest mismatch")
    sequence = metadata["sequence"]
    rollback_epoch = metadata["rollbackEpoch"]
    return {
        "hash": candidate_hash,
        "policy_id": metadata.get("id"),
        "sequence": sequence,
        "rollback_epoch": rollback_epoch,
        "dry_run": dry_run,
        "dry_run_sha256": dry_run_digest,
        "signing_key_id": signing_key_id,
    }


def audit_event_hash(record: dict[str, Any]) -> str:
    payload = {
        "id": record["id"],
        "event_type": record["event_type"],
        "actor_type": record["actor_type"],
        "actor_id": record["actor_id"],
        "event_json": canonical_json(record["event"]),
        "prev_event_hash": record["prev_event_hash"],
        "created_at": record["created_at"],
    }
    return sha256_prefixed_json(payload)


def audit_checkpoint_signature_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(checkpoint)
    unsigned.pop("signature", None)
    return unsigned


def verify_audit_checkpoint(
    checkpoint: dict[str, Any],
    *,
    trusted_audit_checkpoint_public_key_pem: str,
    generated_at: str,
    backend: str,
    ha: bool,
    chain_head: str,
    chain_count: int,
    export_header: dict[str, Any],
) -> str:
    require_exact_fields(
        checkpoint,
        {
            "apiVersion",
            "kind",
            "key_id",
            "created_at",
            "backend",
            "ha",
            "chain_head",
            "chain_count",
            "export_header_sha256",
            "signature",
        },
        "audit_export.checkpoint",
    )
    require(checkpoint.get("apiVersion") == AUDIT_CHECKPOINT_API_VERSION, "audit checkpoint apiVersion mismatch")
    require(checkpoint.get("kind") == AUDIT_CHECKPOINT_KIND, "audit checkpoint kind mismatch")
    trusted_public_key, trusted_key_id = parse_trusted_ed25519_public_key(
        trusted_audit_checkpoint_public_key_pem,
        "trusted audit checkpoint public key",
    )
    checkpoint_key_id = require_sha256(checkpoint.get("key_id"), "audit_export.checkpoint.key_id")
    require(checkpoint_key_id == trusted_key_id, "audit checkpoint signing key does not match the operator trust root")
    require(checkpoint.get("created_at") == generated_at, "audit checkpoint timestamp does not bind the export")
    parse_time(checkpoint.get("created_at"), "audit_export.checkpoint.created_at")
    require(checkpoint.get("backend") == backend, "audit checkpoint backend does not bind the export")
    require(checkpoint.get("ha") is ha, "audit checkpoint HA claim does not bind the export")
    require(checkpoint.get("chain_head") == chain_head, "audit checkpoint chain head does not bind the export")
    require(checkpoint.get("chain_count") == chain_count, "audit checkpoint count does not bind the export")
    require(
        checkpoint.get("export_header_sha256") == sha256_prefixed_json(export_header),
        "audit checkpoint header digest does not bind the export",
    )
    verify_ed25519_signature(
        trusted_public_key,
        checkpoint.get("signature"),
        audit_checkpoint_signature_payload(checkpoint),
        "audit checkpoint",
    )
    return trusted_key_id


def verify_audit_record(record: dict[str, Any], index: int) -> None:
    label = f"audit_export.events[{index}].event"
    require_exact_fields(
        record,
        {"id", "event_type", "actor_type", "actor_id", "event", "prev_event_hash", "event_hash", "created_at"},
        label,
    )
    require_string(record.get("id"), f"{label}.id")
    require_string(record.get("event_type"), f"{label}.event_type")
    require_string(record.get("actor_type"), f"{label}.actor_type")
    require(record.get("actor_id") is None or isinstance(record.get("actor_id"), str), f"{label}.actor_id is invalid")
    require_object(record.get("event"), f"{label}.event")
    if record.get("prev_event_hash") is not None:
        require_sha256(record.get("prev_event_hash"), f"{label}.prev_event_hash")
    event_hash = require_sha256(record.get("event_hash"), f"{label}.event_hash")
    parse_time(record.get("created_at"), f"{label}.created_at")
    require(event_hash == audit_event_hash(record), f"{label} event hash mismatch")


def verify_audit_export(
    audit_export: dict[str, Any],
    *,
    production: bool,
    trusted_audit_checkpoint_public_key_pem: str,
    expected_data_plane_actor: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], str]:
    require_exact_fields(audit_export, {"header", "events", "footer", "checkpoint"}, "audit_export")
    header = require_object(audit_export.get("header"), "audit_export.header")
    footer = require_object(audit_export.get("footer"), "audit_export.footer")
    checkpoint = require_object(audit_export.get("checkpoint"), "audit_export.checkpoint")
    wrappers = require_list(audit_export.get("events"), "audit_export.events")
    require_exact_fields(
        header,
        {
            "kind",
            "generated_at",
            "backend",
            "filters",
            "count",
            "matched_in_scan",
            "scanned",
            "total_candidates",
            "complete",
            "chain",
        },
        "audit_export.header",
    )
    require(header.get("kind") == "serverware.auditExport.v1", "audit export header kind mismatch")
    generated_at = parse_time(header.get("generated_at"), "audit_export.header.generated_at")
    require(header.get("complete") is True, "audit export scan is incomplete")
    backend = require_string(header.get("backend"), "audit_export.header.backend")
    filters = require_object(header.get("filters"), "audit_export.header.filters")
    require_exact_fields(filters, AUDIT_FILTER_FIELDS, "audit_export.header.filters")
    for field in AUDIT_FILTER_FIELDS - {"start", "end"}:
        require(filters.get(field) is None or filters.get(field) == "", f"audit export filter {field} can hide policy traffic")
    require(filters.get("end") is None or filters.get("end") == "", "audit export end filter can hide post-activation traffic")
    require(filters.get("start") is not None and filters.get("start") != "", "audit export must start no later than candidate staging")
    filter_start = parse_time(filters["start"], "audit_export.header.filters.start")

    for field in ("count", "matched_in_scan", "scanned", "total_candidates"):
        require(isinstance(header.get(field), int) and not isinstance(header.get(field), bool), f"audit export {field} must be an integer")
    event_count = len(wrappers)
    require(event_count > 0, "audit export has no events")
    require(
        header["count"] == header["matched_in_scan"] == header["scanned"] == header["total_candidates"] == event_count,
        "audit export counts do not prove a complete unfiltered time slice",
    )

    chain = require_object(header.get("chain"), "audit_export.header.chain")
    require_exact_fields(chain, {"ok", "backend", "ha", "complete", "count", "total", "head"}, "audit_export.header.chain")
    require(chain.get("ok") is True and chain.get("complete") is True, "audit export source chain is not complete and valid")
    require(chain.get("backend") == backend, "audit export chain backend mismatch")
    require(
        isinstance(chain.get("count"), int)
        and not isinstance(chain.get("count"), bool)
        and chain.get("count") >= event_count,
        "audit export chain count is invalid",
    )
    require(chain.get("count") == chain.get("total"), "audit export chain verification was bounded")
    chain_head = require_sha256(chain.get("head"), "audit_export.header.chain.head")
    if production:
        require(backend == "postgres", "production evidence must come from the PostgreSQL audit store")
        require(chain.get("ha") is True, "production evidence must come from the HA audit chain")

    records: list[dict[str, Any]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for index, wrapper_value in enumerate(wrappers):
        wrapper = require_object(wrapper_value, f"audit_export.events[{index}]")
        require_exact_fields(wrapper, {"kind", "export_index", "event"}, f"audit_export.events[{index}]")
        require(wrapper.get("kind") == "serverware.auditEvent.v1", f"audit export event {index} kind mismatch")
        require(wrapper.get("export_index") == index, f"audit export event {index} index mismatch")
        record = require_object(wrapper.get("event"), f"audit_export.events[{index}].event")
        verify_audit_record(record, index)
        if record.get("actor_type") == "data-plane" or str(record.get("event_type") or "").startswith("data_plane."):
            require(
                record.get("actor_id") == expected_data_plane_actor,
                f"audit export event {index} has the wrong data-plane audit actor",
            )
        require(record["id"] not in ids, f"duplicate audit event id: {record['id']}")
        require(record["event_hash"] not in hashes, f"duplicate audit event hash: {record['event_hash']}")
        ids.add(record["id"])
        hashes.add(record["event_hash"])
        records.append(record)

    require(records[0]["event_hash"] == chain_head, "audit export does not run through the verified chain head")
    for index, (newer, older) in enumerate(zip(records, records[1:])):
        require(newer["prev_event_hash"] == older["event_hash"], f"audit export chain gap between events {index} and {index + 1}")
        newer_time = parse_time(newer["created_at"], f"audit event {index} time")
        older_time = parse_time(older["created_at"], f"audit event {index + 1} time")
        require(newer_time >= older_time, "audit export events are not newest-first")
    oldest_time = parse_time(records[-1]["created_at"], "oldest audit event time")
    newest_time = parse_time(records[0]["created_at"], "newest audit event time")
    require(filter_start <= oldest_time, "audit export start filter excludes the oldest included event")
    require(generated_at >= newest_time, "audit export was generated before its newest event")

    require_exact_fields(footer, {"kind", "count", "complete", "chain_head"}, "audit_export.footer")
    require(footer.get("kind") == "serverware.auditExportEnd.v1", "audit export footer kind mismatch")
    require(footer.get("count") == event_count, "audit export footer count mismatch")
    require(footer.get("complete") is True, "audit export footer reports incomplete evidence")
    require(footer.get("chain_head") == chain_head, "audit export footer chain head mismatch")
    checkpoint_key_id = verify_audit_checkpoint(
        checkpoint,
        trusted_audit_checkpoint_public_key_pem=trusted_audit_checkpoint_public_key_pem,
        generated_at=header["generated_at"],
        backend=backend,
        ha=chain.get("ha") is True,
        chain_head=chain_head,
        chain_count=chain["count"],
        export_header=header,
    )
    return records, {record["id"]: record for record in records}, checkpoint_key_id


def resolve_record_binding(binding: dict[str, Any], records_by_id: dict[str, dict[str, Any]], label: str) -> dict[str, Any]:
    event_id = require_string(binding.get("audit_event_id"), f"{label}.audit_event_id")
    record = records_by_id.get(event_id)
    require(record is not None, f"{label} references an audit event outside the complete export")
    require(binding.get("audit_event_hash") == record["event_hash"], f"{label} audit event digest mismatch")
    return record


def event_route_ids(event: dict[str, Any]) -> set[str]:
    route_ids: set[str] = set()
    route_id = event.get("route_id")
    if isinstance(route_id, str) and route_id:
        route_ids.add(route_id)
    raw_many = event.get("route_ids")
    if isinstance(raw_many, list):
        route_ids.update(str(item) for item in raw_many if isinstance(item, str) and item)
    return route_ids


def diff_route_ids(event: dict[str, Any]) -> set[str]:
    diff = event.get("diff") if isinstance(event.get("diff"), dict) else {}
    routes = diff.get("routes") if isinstance(diff.get("routes"), dict) else {}
    result: set[str] = set()
    for key in ("added", "changed", "removed"):
        values = routes.get(key)
        if isinstance(values, list):
            result.update(str(item) for item in values if isinstance(item, str) and item)
    return result


def verify_real_data_plane_record(
    record: dict[str, Any],
    label: str,
    expected_data_plane_actor: str,
) -> dict[str, Any]:
    require(record.get("actor_type") == "data-plane", f"{label} is not a data-plane audit record")
    require(record.get("actor_id") == expected_data_plane_actor, f"{label} has the wrong data-plane audit actor")
    event = require_object(record.get("event"), f"{label}.event")
    require(event.get("component") == "serverware-decision-gate-rs", f"{label} is not from the Rust decision gate")
    return event


def verify_traffic_binding(
    binding: dict[str, Any],
    record: dict[str, Any],
    *,
    label: str,
    expected_policy_hash: str,
    affected_routes: set[str],
    expected_data_plane_actor: str,
) -> tuple[dict[str, Any], datetime]:
    event = verify_real_data_plane_record(record, label, expected_data_plane_actor)
    observed_at = require_string(binding.get("observed_at"), f"{label}.observed_at")
    require(observed_at == record["created_at"], f"{label} observation time mismatch")
    event_time = parse_time(observed_at, f"{label}.observed_at")
    route_id = require_string(binding.get("route_id"), f"{label}.route_id")
    require(route_id in affected_routes, f"{label} route is outside the affected route set")
    require(event.get("route_id") == route_id, f"{label} route mismatch")
    policy = require_sha256(binding.get("policy_hash"), f"{label}.policy_hash")
    require(policy == expected_policy_hash, f"{label} policy mismatch")
    require(event.get("policy_hash") == policy, f"{label} audit policy mismatch")
    for field in ("request_digest", "operation_digest"):
        claimed = require_sha256(binding.get(field), f"{label}.{field}")
        require(event.get(field) == claimed, f"{label} {field} mismatch")
    return event, event_time


def verify_staging(
    staging: dict[str, Any],
    records_by_id: dict[str, dict[str, Any]],
    deployment: dict[str, Any],
    candidate: dict[str, Any],
    affected_routes: set[str],
) -> tuple[dict[str, Any], datetime]:
    require_exact_fields(
        staging,
        {"staged_at", "audit_event_id", "audit_event_hash", "active_policy_hash", "candidate_policy_hash"},
        "staging",
    )
    record = resolve_record_binding(staging, records_by_id, "staging")
    require(record.get("event_type") == "policy.canary.started", "staging audit event type mismatch")
    require(record.get("actor_type") == "admin", "staging audit event actor type mismatch")
    require(staging.get("staged_at") == record.get("created_at"), "staging time mismatch")
    staged_at = parse_time(staging.get("staged_at"), "staging.staged_at")
    require(staging.get("active_policy_hash") == deployment["baseline_policy_hash"], "staging active policy mismatch")
    require(staging.get("candidate_policy_hash") == deployment["candidate_policy_hash"], "staging candidate policy mismatch")
    event = require_object(record.get("event"), "staging audit payload")
    require(event.get("canary_id") == deployment["canary_id"], "staging canary id mismatch")
    require(event.get("policy_id") == deployment["policy_id"], "staging policy id mismatch")
    require(event.get("previous_policy_hash") == deployment["baseline_policy_hash"], "staging baseline policy mismatch")
    require(event.get("candidate_policy_hash") == deployment["candidate_policy_hash"], "staging candidate hash mismatch")
    require(event.get("candidate_sequence") == candidate["sequence"], "staging candidate sequence mismatch")
    require(event.get("candidate_rollback_epoch") == candidate["rollback_epoch"], "staging candidate rollback epoch mismatch")
    require(event.get("dry_run") == candidate["dry_run"], "staging candidate dry-run mismatch")
    require_sha256(event.get("payload_digest"), "staging payload digest")
    require(affected_routes.issubset(diff_route_ids(event)), "staging diff does not cover every affected route")
    return record, staged_at


def verify_activation(
    activation: dict[str, Any],
    records_by_id: dict[str, dict[str, Any]],
    deployment: dict[str, Any],
    candidate: dict[str, Any],
    affected_routes: set[str],
) -> tuple[dict[str, Any], dict[str, Any], datetime, datetime]:
    require_exact_fields(
        activation,
        {
            "activated_at",
            "published_at",
            "audit_event_id",
            "audit_event_hash",
            "published_audit_event_id",
            "published_audit_event_hash",
            "previous_policy_hash",
            "candidate_policy_hash",
        },
        "activation",
    )
    activated_record = resolve_record_binding(activation, records_by_id, "activation")
    published_binding = {
        "audit_event_id": activation.get("published_audit_event_id"),
        "audit_event_hash": activation.get("published_audit_event_hash"),
    }
    published_record = resolve_record_binding(published_binding, records_by_id, "activation published event")
    require(activated_record.get("event_type") == "policy.canary.activated", "activation audit event type mismatch")
    require(published_record.get("event_type") == "policy.published", "activation publish audit event type mismatch")
    require(activated_record.get("actor_type") == "admin" and published_record.get("actor_type") == "admin", "activation audit actor type mismatch")
    require(activation.get("activated_at") == activated_record.get("created_at"), "activation time mismatch")
    require(activation.get("published_at") == published_record.get("created_at"), "activation publish time mismatch")
    activated_at = parse_time(activation.get("activated_at"), "activation.activated_at")
    published_at = parse_time(activation.get("published_at"), "activation.published_at")
    require(published_at >= activated_at, "policy publish audit precedes explicit activation")
    require(activation.get("previous_policy_hash") == deployment["baseline_policy_hash"], "activation previous policy mismatch")
    require(activation.get("candidate_policy_hash") == deployment["candidate_policy_hash"], "activation candidate policy mismatch")

    activated_event = require_object(activated_record.get("event"), "activation audit payload")
    published_event = require_object(published_record.get("event"), "published audit payload")
    for label, event in (("activation", activated_event), ("published", published_event)):
        require(event.get("activation_mode") == "canary", f"{label} audit did not record explicit staged activation")
        require(event.get("canary_id") == deployment["canary_id"], f"{label} canary id mismatch")
        require(event.get("policy_id") == deployment["policy_id"], f"{label} policy id mismatch")
        require(event.get("previous_policy_hash") == deployment["baseline_policy_hash"], f"{label} previous policy hash mismatch")
        require(event.get("new_policy_hash") == deployment["candidate_policy_hash"], f"{label} candidate policy hash mismatch")
        require(event.get("new_sequence") == candidate["sequence"], f"{label} candidate sequence mismatch")
        require(event.get("new_rollback_epoch") == candidate["rollback_epoch"], f"{label} rollback epoch mismatch")
        require(event.get("dry_run") == candidate["dry_run"], f"{label} dry-run mismatch")
        require(affected_routes.issubset(diff_route_ids(event)), f"{label} diff does not cover every affected route")
        require_sha256(event.get("payload_digest"), f"{label} payload digest")
    require(activated_event.get("payload_digest") == published_event.get("payload_digest"), "activation and publish payload digests mismatch")
    return activated_record, published_record, activated_at, published_at


def verify_baseline(
    baseline: dict[str, Any],
    records: list[dict[str, Any]],
    records_by_id: dict[str, dict[str, Any]],
    deployment: dict[str, Any],
    affected_routes: set[str],
    *,
    staged_at: datetime,
    activated_at: datetime,
    expected_data_plane_actor: str,
) -> int:
    require_exact_fields(baseline, {"started_at", "ended_at", "policy_hash", "route_ids", "observations"}, "baseline")
    require(baseline.get("started_at") == deployment["staged_at"], "baseline start does not match staging")
    require(baseline.get("ended_at") == deployment["activated_at"], "baseline end does not match activation")
    require(parse_time(baseline.get("started_at"), "baseline.started_at") == staged_at, "baseline start time mismatch")
    require(parse_time(baseline.get("ended_at"), "baseline.ended_at") == activated_at, "baseline end time mismatch")
    require(baseline.get("policy_hash") == deployment["baseline_policy_hash"], "baseline policy hash mismatch")
    route_ids = require_list(baseline.get("route_ids"), "baseline.route_ids")
    require(route_ids == sorted(affected_routes), "baseline route set mismatch")
    observations = require_list(baseline.get("observations"), "baseline.observations")
    require(observations, "active-policy baseline observations are missing")
    observed_routes: set[str] = set()
    referenced_ids: set[str] = set()
    for index, item in enumerate(observations):
        label = f"baseline.observations[{index}]"
        binding = require_object(item, label)
        require_exact_fields(
            binding,
            {"audit_event_id", "audit_event_hash", "observed_at", "route_id", "policy_hash", "request_digest", "operation_digest"},
            label,
        )
        record = resolve_record_binding(binding, records_by_id, label)
        require(record.get("event_type") in BASELINE_EVENT_TYPES, f"{label} is not a baseline traffic event")
        _, observed_at = verify_traffic_binding(
            binding,
            record,
            label=label,
            expected_policy_hash=deployment["baseline_policy_hash"],
            affected_routes=affected_routes,
            expected_data_plane_actor=expected_data_plane_actor,
        )
        require(staged_at <= observed_at < activated_at, f"{label} is outside the staged baseline window")
        require(record["id"] not in referenced_ids, f"duplicate baseline audit reference: {record['id']}")
        referenced_ids.add(record["id"])
        observed_routes.add(binding["route_id"])
    require(observed_routes == affected_routes, "baseline observations do not cover every affected route")

    for record in records:
        event_time = parse_time(record["created_at"], f"audit event {record['id']} time")
        if not (staged_at <= event_time < activated_at):
            continue
        event = require_object(record.get("event"), f"audit event {record['id']} payload")
        policy = event.get("policy_hash")
        routes = event_route_ids(event)
        data_plane_activity = record.get("actor_type") == "data-plane" or str(record.get("event_type") or "").startswith("data_plane.")
        proxy_activity = record.get("event_type") in {"proxy.request_decision", "request.completed"}
        if data_plane_activity or proxy_activity:
            require(policy != deployment["candidate_policy_hash"], "candidate policy received traffic before explicit activation")
        if (data_plane_activity or proxy_activity) and routes & affected_routes:
            require(policy == deployment["baseline_policy_hash"], "affected route used a mismatched policy before activation")
    return len(observations)


def verify_post_activation_canaries(
    canaries_value: Any,
    records_by_id: dict[str, dict[str, Any]],
    deployment: dict[str, Any],
    affected_routes: set[str],
    *,
    published_at: datetime,
    expected_data_plane_actor: str,
) -> tuple[int, int, datetime]:
    canaries = require_list(canaries_value, "post_activation_canaries")
    require(canaries, "post-activation canaries are missing")
    decisions: dict[str, int] = {"allow": 0, "deny": 0}
    referenced_ids: set[str] = set()
    latest = published_at
    for index, item in enumerate(canaries):
        label = f"post_activation_canaries[{index}]"
        binding = require_object(item, label)
        require_exact_fields(
            binding,
            {
                "name",
                "expected_decision",
                "audit_event_id",
                "audit_event_hash",
                "observed_at",
                "route_id",
                "policy_hash",
                "request_digest",
                "operation_digest",
            },
            label,
        )
        require_string(binding.get("name"), f"{label}.name")
        expected = binding.get("expected_decision")
        require(expected in {"allow", "deny"}, f"{label} expected decision is invalid")
        record = resolve_record_binding(binding, records_by_id, label)
        event, observed_at = verify_traffic_binding(
            binding,
            record,
            label=label,
            expected_policy_hash=deployment["candidate_policy_hash"],
            affected_routes=affected_routes,
            expected_data_plane_actor=expected_data_plane_actor,
        )
        require(observed_at > published_at, f"{label} did not run after activation was published")
        if expected == "allow":
            require(record.get("event_type") == "data_plane.response.released", f"{label} is not an allowed released response")
            require(event.get("outcome") == "released" and event.get("action") == "allow", f"{label} did not prove an allow decision")
        else:
            require(record.get("event_type") == "data_plane.request.denied", f"{label} is not a denied request")
            require(event.get("outcome") == "denied" and event.get("action") in {"deny", "block"}, f"{label} did not prove a denial decision")
        require(record["id"] not in referenced_ids, f"duplicate post-activation canary audit reference: {record['id']}")
        referenced_ids.add(record["id"])
        decisions[expected] += 1
        latest = max(latest, observed_at)
    require(decisions["allow"] > 0, "post-activation allow canary is missing")
    require(decisions["deny"] > 0, "post-activation denial canary is missing")
    return decisions["allow"], decisions["deny"], latest


def reject_production_markers(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            inactive_marker = child is None or child is False or child == "" or (isinstance(child, (int, float)) and child == 0)
            if PRODUCTION_MARKER_RE.search(key_text) and not inactive_marker:
                raise EvidenceError(f"production evidence contains synthetic/fixture marker at {path}.{key_text}")
            reject_production_markers(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_production_markers(child, f"{path}[{index}]")
    elif isinstance(value, str) and PRODUCTION_MARKER_RE.search(value):
        raise EvidenceError(f"production evidence contains synthetic/fixture marker at {path}")


def verify_evidence(
    document: dict[str, Any],
    *,
    trusted_policy_public_key_pem: str,
    trusted_audit_checkpoint_public_key_pem: str,
    expected_data_plane_actor: str,
    production: bool = True,
) -> dict[str, Any]:
    _, trusted_policy_key_id = parse_trusted_ed25519_public_key(
        trusted_policy_public_key_pem,
        "trusted policy public key",
    )
    _, trusted_audit_checkpoint_key_id = parse_trusted_ed25519_public_key(
        trusted_audit_checkpoint_public_key_pem,
        "trusted audit checkpoint public key",
    )
    require(
        trusted_policy_key_id != trusted_audit_checkpoint_key_id,
        "policy and audit checkpoint trust roots must use different keys",
    )
    expected_actor = require_string(expected_data_plane_actor, "expected data-plane actor")
    if production:
        require(
            expected_actor.startswith("spiffe://") and len(expected_actor) > len("spiffe://"),
            "production expected data-plane actor must be a non-empty SPIFFE ID",
        )
    require_exact_fields(
        document,
        {
            "apiVersion",
            "kind",
            "evidence_sha256",
            "generated_at",
            "deployment",
            "candidate",
            "staging",
            "baseline",
            "activation",
            "post_activation_canaries",
            "audit_export",
        },
        "evidence document",
    )
    require(document.get("apiVersion") == API_VERSION, "policy activation evidence apiVersion mismatch")
    require(document.get("kind") == KIND, "policy activation evidence kind mismatch")
    claimed_evidence_digest = require_sha256(document.get("evidence_sha256"), "evidence_sha256")
    require(claimed_evidence_digest == evidence_digest(document), "policy activation evidence digest mismatch")
    generated_at = parse_time(document.get("generated_at"), "generated_at")
    if production:
        reject_production_markers(document)

    deployment = require_object(document.get("deployment"), "deployment")
    require_exact_fields(
        deployment,
        {
            "environment",
            "deployment_id",
            "canary_id",
            "policy_id",
            "affected_route_ids",
            "baseline_policy_hash",
            "candidate_policy_hash",
            "staged_at",
            "activated_at",
        },
        "deployment",
    )
    environment = require_string(deployment.get("environment"), "deployment.environment")
    if production:
        require(environment == "production", "production verification requires deployment.environment=production")
    require_string(deployment.get("deployment_id"), "deployment.deployment_id")
    require_string(deployment.get("canary_id"), "deployment.canary_id")
    require_string(deployment.get("policy_id"), "deployment.policy_id")
    baseline_hash = require_sha256(deployment.get("baseline_policy_hash"), "deployment.baseline_policy_hash")
    candidate_hash = require_sha256(deployment.get("candidate_policy_hash"), "deployment.candidate_policy_hash")
    require(baseline_hash != candidate_hash, "candidate policy hash is identical to the active baseline")
    affected_route_values = require_list(deployment.get("affected_route_ids"), "deployment.affected_route_ids")
    require(all(isinstance(item, str) and item for item in affected_route_values), "affected route ids must be non-empty strings")
    require(affected_route_values == sorted(set(affected_route_values)), "affected route ids must be unique and sorted")
    require(affected_route_values, "affected route ids are empty")
    affected_routes = set(affected_route_values)
    parse_time(deployment.get("staged_at"), "deployment.staged_at")
    parse_time(deployment.get("activated_at"), "deployment.activated_at")

    candidate = verify_candidate(
        require_object(document.get("candidate"), "candidate"),
        deployment,
        affected_routes,
        production=production,
        trusted_policy_public_key_pem=trusted_policy_public_key_pem,
        policy_validation_time=generated_at,
    )
    records, records_by_id, audit_checkpoint_key_id = verify_audit_export(
        require_object(document.get("audit_export"), "audit_export"),
        production=production,
        trusted_audit_checkpoint_public_key_pem=trusted_audit_checkpoint_public_key_pem,
        expected_data_plane_actor=expected_actor,
    )
    _, staged_at = verify_staging(
        require_object(document.get("staging"), "staging"),
        records_by_id,
        deployment,
        candidate,
        affected_routes,
    )
    require(deployment.get("staged_at") == document["staging"].get("staged_at"), "deployment staging time mismatch")
    _, _, activated_at, published_at = verify_activation(
        require_object(document.get("activation"), "activation"),
        records_by_id,
        deployment,
        candidate,
        affected_routes,
    )
    require(deployment.get("activated_at") == document["activation"].get("activated_at"), "deployment activation time mismatch")
    require(activated_at > staged_at, "candidate activation did not occur after staging")

    filter_start = parse_time(document["audit_export"]["header"]["filters"]["start"], "audit export start")
    require(filter_start <= staged_at, "audit export starts after candidate staging")
    baseline_count = verify_baseline(
        require_object(document.get("baseline"), "baseline"),
        records,
        records_by_id,
        deployment,
        affected_routes,
        staged_at=staged_at,
        activated_at=activated_at,
        expected_data_plane_actor=expected_actor,
    )
    allow_count, denial_count, latest_canary = verify_post_activation_canaries(
        document.get("post_activation_canaries"),
        records_by_id,
        deployment,
        affected_routes,
        published_at=published_at,
        expected_data_plane_actor=expected_actor,
    )
    export_generated_at = parse_time(document["audit_export"]["header"]["generated_at"], "audit export generated_at")
    require(export_generated_at >= latest_canary, "audit export predates a post-activation canary")
    require(generated_at >= export_generated_at, "evidence document predates its audit export")

    return {
        "apiVersion": VERIFICATION_API_VERSION,
        "kind": "PolicyActivationEvidenceVerification",
        "ok": True,
        "production_mode": production,
        "environment": environment,
        "deployment_id": deployment["deployment_id"],
        "canary_id": deployment["canary_id"],
        "policy_id": deployment["policy_id"],
        "baseline_policy_hash": baseline_hash,
        "candidate_policy_hash": candidate_hash,
        "candidate_signing_key_id": candidate["signing_key_id"],
        "trusted_policy_signing_key_id": trusted_policy_key_id,
        "candidate_dry_run_sha256": candidate["dry_run_sha256"],
        "affected_route_ids": sorted(affected_routes),
        "baseline_observations": baseline_count,
        "candidate_pre_activation_traffic": 0,
        "post_activation_allow_canaries": allow_count,
        "post_activation_denial_canaries": denial_count,
        "audit_events": len(records),
        "audit_chain_head": document["audit_export"]["header"]["chain"]["head"],
        "audit_checkpoint_signing_key_id": audit_checkpoint_key_id,
        "expected_data_plane_actor": expected_actor,
        "evidence_sha256": claimed_evidence_digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify fail-closed Serverware policy activation deployment evidence.")
    parser.add_argument("evidence", nargs="?", help="Policy activation evidence JSON document")
    parser.add_argument("--evidence-file", dest="evidence_file", help="Policy activation evidence JSON document")
    parser.add_argument(
        "--trusted-policy-public-key",
        required=True,
        type=Path,
        help="operator-pinned Ed25519 policy-signing public key PEM",
    )
    parser.add_argument(
        "--trusted-audit-checkpoint-public-key",
        required=True,
        type=Path,
        help="operator-pinned Ed25519 audit-checkpoint public key PEM",
    )
    parser.add_argument(
        "--expected-data-plane-actor",
        required=True,
        help="configured data-plane actor identity (a SPIFFE ID in production)",
    )
    parser.add_argument(
        "--allow-fixtures-for-test",
        action="store_true",
        help="Test-only mode: permits non-production environment/backend and fixture markers.",
    )
    args = parser.parse_args()
    path_value = args.evidence_file or args.evidence
    if not path_value:
        parser.error("an evidence path is required")
    if args.evidence_file and args.evidence:
        parser.error("provide the evidence path once")
    try:
        result = verify_evidence(
            load_evidence(Path(path_value)),
            trusted_policy_public_key_pem=load_trusted_public_key(
                args.trusted_policy_public_key,
                "trusted policy public key",
            ),
            trusted_audit_checkpoint_public_key_pem=load_trusted_public_key(
                args.trusted_audit_checkpoint_public_key,
                "trusted audit checkpoint public key",
            ),
            expected_data_plane_actor=args.expected_data_plane_actor,
            production=not args.allow_fixtures_for_test,
        )
    except Exception as exc:
        print(
            canonical_json(
                {
                    "apiVersion": VERIFICATION_API_VERSION,
                    "kind": "PolicyActivationEvidenceVerification",
                    "ok": False,
                    "error": str(exc),
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    print(canonical_json(result))


if __name__ == "__main__":
    main()
