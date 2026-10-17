"""Bounded HTTP adapter for a native-sealed pending review submission.

The runtime original contains private request material. It is transient input,
not an audit payload, a persisted plan, or proof of native authority. The HTTP
owner rejoins current release policy and its actual facade defaults before the
existing authority runtime independently verifies custody and commits anything.
There is no reservation fallback, provider call, or automatic retry here.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hmac
import json
import re
import time

from fastapi import HTTPException

from catchplate import authority_contract as contract
from catchplate import authority_jit_private_request as jit
from catchplate import authority_native_jit_review_assignment as grammar
from catchplate import authority_native_jit_review_custody as custody
from catchplate import authority_native_jit_submission as submission
from catchplate import authority_release_private_request as private
from catchplate import authority_transition_core as core
from catchplate import authority_transition_native_jit_pending as pending
from catchplate import db
from catchplate import release_authorization_profiles as profiles


PATH = "/api/data-plane/release-authorizations/native-jit-submit"
MAX_REQUEST_BYTES = contract.MAX_REQUEST_BYTES
BODY_TIMEOUT_SECONDS = 5.0
REQUEST_TIMEOUT_NS = 30_000_000_000
ERROR = "native JIT pending submission is unavailable"
DEADLINE_SCOPE_KEY = "catchplate.native_jit_pending_deadline"


def require_live(deadline_ns: int) -> None:
    if type(deadline_ns) is not int or not time.monotonic_ns() < deadline_ns < 2**63:
        raise submission.SubmissionError()


async def read_body(request, *, deadline_ns: int) -> dict[str, str]:
    """Read only after token, nonce, and PostgreSQL topology admission."""
    lengths = [value for name, value in request.scope.get("headers", [])
        if name.lower() == b"content-length"]
    if len(lengths) > 1 or (lengths and re.fullmatch(rb"(?:0|[1-9][0-9]{0,15})", lengths[0]) is None):
        raise HTTPException(status_code=400, detail=ERROR)
    if lengths and int(lengths[0]) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail=ERROR)
    body = bytearray()

    async def consume():
        async for chunk in request.stream():
            require_live(deadline_ns)
            if len(chunk) > MAX_REQUEST_BYTES - len(body):
                raise HTTPException(status_code=413, detail=ERROR)
            body.extend(chunk)

    try:
        require_live(deadline_ns)
        await asyncio.wait_for(consume(), timeout=min(BODY_TIMEOUT_SECONDS,
            (deadline_ns - time.monotonic_ns()) / 1_000_000_000))
        require_live(deadline_ns)
        if lengths and int(lengths[0]) != len(body):
            raise HTTPException(status_code=400, detail=ERROR)

        def pairs(items):
            result = {}
            for name, item in items:
                if name in result:
                    raise submission.SubmissionError()
                result[name] = item
            return result

        def constant(_value):
            raise submission.SubmissionError()

        parsed = json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
        owned = submission.parse_submission(parsed)
        require_live(deadline_ns)
        return owned
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail=ERROR) from None
    except HTTPException:
        raise
    except Exception:
        # Never emit validation inputs, private JSON, URLs, or nested exceptions.
        raise HTTPException(status_code=422, detail=ERROR) from None
    finally:
        body.clear()


@submission._checked
def reserve_request(value: dict[str, str]) -> dict:
    """Reconstruct the existing DTO, not a new self-asserted public parent."""
    owned = submission.parse_submission(value)
    # This also checks literal parent/child derivation and pair/proof bindings.
    # Parsing is deliberately not custody verification or writer admission.
    submission.public_request_from_submission(owned)
    runtime = grammar.document(owned["runtimeOriginal"], custody.MAX_ORIGINAL_BYTES)
    public, documents = private.validate_runtime_input(runtime)
    if (public["native_profile"] is not True or public["policy_aware_profile"] is not False
            or public["now_epoch_ms"] is not None):
        raise submission.SubmissionError()
    aliases = {
        "attemptId": "attempt_id", "flowId": "flow_id", "principalId": "principal_id",
        "routeId": "route_id", "credentialVersion": "credential_version",
        "policyHash": "policy_hash", "requestDigest": "request_digest",
        "operationDigest": "operation_digest", "operationContext": "operation_context",
        "durablePolicy": "durable_policy_binding",
        "approverPolicySha256": "expected_approver_policy_sha256",
    }
    return {"apiVersion": "catchplate.nativeReleaseAuthorizationReserve/v2",
        **{alias: public[name] for alias, name in aliases.items()},
        "credentialRef": public["credential_id"] or None,
        "canonicalRequest": documents["canonical_request"]}


@submission._checked
def require_prepared(value: dict[str, str], prepared: dict[str, str]) -> None:
    for submitted, original in (("runtimeOriginal", "runtimeInput"),
            ("parentOriginal", "parentRequest"), ("childOriginal", "childRequest")):
        if not hmac.compare_digest(value[submitted], prepared[original]):
            raise submission.SubmissionError()


@submission._checked
def clipped_deadline(value: dict[str, str], *, deadline_ns: int) -> int:
    require_live(deadline_ns)
    proof = custody.authority_evidence(value["evidenceOriginal"])
    # Sample monotonic first. Claimed expiry can only narrow this HTTP owner's
    # unchanged window; service and planner must authenticate it independently.
    sampled_monotonic, sampled_epoch = time.monotonic_ns(), time.time_ns()
    remaining = proof["statement"]["expiresAtEpochNs"] - sampled_epoch
    if remaining <= 0:
        raise submission.SubmissionError()
    clipped = min(deadline_ns, sampled_monotonic + remaining)
    require_live(clipped)
    return clipped


@submission._checked
def submit(value: dict[str, str], *, deadline_ns: int) -> dict:
    """One authenticated runtime call, retaining the caller's deadline."""
    require_live(deadline_ns)
    parent = submission.public_request_from_submission(value)
    child = grammar.document(value["childOriginal"], custody.MAX_ORIGINAL_BYTES)
    expected_id = core.deterministic_uuid(operation="jit.request",
        request_digest=child["requestDigest"], purpose="jit-approval-request")
    business = parent["arguments"]
    normalized = jit.public_arguments(child["arguments"], typed=True,
        request_digest=child["requestDigest"])
    expected_binding = pending.pending_binding_digest(business=business, normalized_child=normalized)
    pair = grammar.document(value["pairOriginal"], custody.MAX_PAIR_BYTES)
    # Admission requires database now >= seal issuance, and the authenticated
    # document lifetime is no longer than pending TTL from issuance. Therefore
    # the pending projection's minimum is this original expiry, floored to µs.
    expected_expiry = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=pair["scope"]["documentExpiresAtEpochNs"] // 1_000)).isoformat()
    require_live(deadline_ns)
    result = db.dispatch_policy_authority_operation("release.reserve", value,
        deadline_ns=deadline_ns)
    require_live(deadline_ns)
    if (type(result) is not dict or result.get("authorized") is not False
            or result.get("state") != "denied" or result.get("reason") != "jit_grant_unavailable"
            or result.get("approval_status") != "pending"
            or type(result.get("approval_created")) is not bool
            or result.get("approval_request_id") != expected_id
            or result.get("attempt_id") != business["attempt_id"]
            or result.get("binding_api_version") != profiles.NATIVE_BINDING_V2
            or result.get("binding_digest") != expected_binding
            or result.get("approval_expires_at") != expected_expiry
            or type(result.get("retry_after_seconds")) is not int or result["retry_after_seconds"] != 3
            or type(result.get("idempotent_replay")) is not bool
            or result.get("quotas") != []
            or result.get("release_authorization_store_backend") != "postgres"
            or result.get("release_authorization_store_ha") is not True
            or result.get("grant_id") is not None
            or any(result.get(name) is not None for name in (
                "reservation_expires_at_epoch_ms", "dispatch_started_at_epoch_ms",
                "dispatch_expires_at_epoch_ms", "completion_outcome"))):
        raise submission.SubmissionError()
    durable = result.get("durable_policy")
    if (type(durable) is not dict or durable.get("state") != "denied"
            or durable.get("attempt_id") != business["attempt_id"]
            or durable.get("actor_id") != business["actor_id"]
            or durable.get("claim_digest") != business["durable_policy_binding"]["claimDigest"]
            or any(durable.get(name) is not None for name in (
                "reservation_id", "reservation_deadline_at_epoch_ms", "dispatch_deadline_at_epoch_ms",
                "response_evidence_digest", "response_body_sha256", "failure_reason", "uncertainty"))):
        raise submission.SubmissionError()
    return result
