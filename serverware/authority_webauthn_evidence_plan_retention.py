"""Original-three-record verification for evidence-admission plan custody.

The signed plan, detached original inputs and canonical historical evaluation
context are immutable byte inputs. Every historical expectation and both real
public keys must be independently admitted; stored context cannot enroll any
request, root, configuration, identity, key, purpose or clock expectation.

This worker compares the entire decoded context with its owned independent
expectations, then invokes genuine original plan signature, query, primary
proof, evidence-semantic and write-root replay. Only afterward does it derive
actual byte/key hashes and the closed record commitment. The returned carrier
is local data, never accepted by this or another verifier as proof authority.

No SQL, persistence, schema, privilege, clock sample, signing, reservation,
execution permission or registry activation is supplied. All copies, codecs,
hashes and actual replay use the existing shared allowance. Historical replay
is not a currentness check or a claim that these originals are durable.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_webauthn_evidence_plan as plan
from serverware import authority_webauthn_evidence_plan_context as context_wire
from serverware.authority_query_read_work import QueryReadValidationMetrics


evidence = plan.evidence
RECORD_SCHEMA = "serverware.policyAuthorityWebAuthnEvidenceAdmissionRetainedPlan/v1"
PLAN_PROTOCOL = plan.contract.PROTOCOL


class WebAuthnEvidencePlanRetentionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RetainedEvidencePlan:
    """Actual locally verified originals and observations, not durable custody."""

    envelope_bytes: bytes
    inputs_bytes: bytes
    evaluation_context_bytes: bytes
    header: dict
    record_digest: str
    verification: plan._VerifiedEvidencePlan
    metrics: QueryReadValidationMetrics


def _bytes_digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _key_digest(key, work):
    # These are the same independently held handles used by genuine replay,
    # not keys restored from the context. Prepay the real output; method lookup
    # and invocation are both inside the success/failure continuity guard.
    work.charge(input_bytes=32)
    raw = evidence.production._callback(work,
        lambda: key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if type(raw) is not bytes or len(raw) != 32:
        raise WebAuthnEvidencePlanRetentionError("retained evidence plan key is not exact raw32")
    return _bytes_digest(raw, work)


def _verify_record_on_work(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        expectations, planner_public_key, evidence_public_key, work):
    """Genuinely replay raw3 against independent owned historical expectations.

    No current clock is read. Historical pins and expectations must already
    have the provenance required by the plan verifier. Returned metrics are
    cumulative, including prior invocation work; failure grants no retry or
    replacement allowance. Fixed header/hash-output scaffolding is not a claim
    of whole-process allocation or native-crypto accounting.
    """
    try:
        ledger = evidence.capture._SharedLedger(work)
        for raw, maximum in ((envelope_bytes, plan.contract.MAX_BYTES),
                (inputs_bytes, plan.inputs_wire.MAX_BYTES),
                (evaluation_context_bytes, context_wire.MAX_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise WebAuthnEvidencePlanRetentionError("retained evidence plan requires bounded original bytes")
        if (not isinstance(planner_public_key, plan.Ed25519PublicKey)
                or not isinstance(evidence_public_key, plan.Ed25519PublicKey)):
            raise WebAuthnEvidencePlanRetentionError("retained evidence plan needs independently pinned Ed25519 keys")
        shape = evidence.plan.contract
        shape._object(expectations, plan._EXPECTATION_FIELDS, "independent retained evidence expectations")
        # Hold key handles and own every variable independent expectation before
        # the first decoder/native/key callback. Raw bytes are already immutable.
        planner_key, evidence_key = planner_public_key, evidence_public_key
        owned = evidence.capture._JSONCapture(ledger).visit(expectations)
        request = owned["request"]
        if type(request) is not dict:
            raise WebAuthnEvidencePlanRetentionError("retained evidence request is not an exact object")
        operation = request.get("operation")
        plan._validate_expectations(owned, operation)
        context = context_wire._decode_on_work(evaluation_context_bytes, work=work)
        evidence.plan._same(context, owned, work,
            "retained evidence context differs from independent historical expectations")
        # Use the independent capture, never the decoded stored context, as the
        # genuine verifier input. This repeats real membership and semantic
        # work even when all three original byte strings were retained before.
        verification = plan._verify_on_work(envelope_bytes=envelope_bytes,
            inputs_bytes=inputs_bytes, expectations=owned,
            planner_public_key=planner_key, evidence_public_key=evidence_key, work=work)
        planner_key_digest = _key_digest(planner_key, work)
        evidence_key_digest = _key_digest(evidence_key, work)
        envelope_digest = _bytes_digest(envelope_bytes, work)
        inputs_digest = _bytes_digest(inputs_bytes, work)
        context_digest = _bytes_digest(evaluation_context_bytes, work)
        header = {"schema": RECORD_SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
            "planProtocol": PLAN_PROTOCOL, "operation": operation,
            "operationId": request["operationId"], "requestDigest": request["requestDigest"],
            "configurationDigest": owned["configurationDigest"],
            "plannerKeyDigest": planner_key_digest, "evidenceKeyDigest": evidence_key_digest,
            "planDigest": verification.plan_digest,
            "envelopeBytesDigest": envelope_digest, "envelopeByteCount": len(envelope_bytes),
            "inputsBytesDigest": inputs_digest, "inputsByteCount": len(inputs_bytes),
            "contextBytesDigest": context_digest, "contextByteCount": len(evaluation_context_bytes)}
        record_digest = evidence.plan._json_digest(RECORD_SCHEMA, header, ledger)
        return _RetainedEvidencePlan(envelope_bytes, inputs_bytes, evaluation_context_bytes,
            header, record_digest, verification, work.metrics)
    except evidence.keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidencePlanRetentionError):
            raise
        raise WebAuthnEvidencePlanRetentionError("retained evidence plan verification failed") from exc
