"""Signed evidence-admission observations with genuine semantic/proof replay.

The separately admitted context supplies request, roots, original-input
commitment, configuration/planner/evidence pins and time expectations. A signed
plan cannot enroll those expectations. Neither a current owner nor copied
storage metadata establishes historical authority. This protocol carries no
execution capability, reservation, fence, durable custody or terminal witness.

The producer replays raw memberships, exact queries, actual evidence semantics
and root effects before signing. The verifier authenticates the original plan
then independently performs the same fixed replay. All phases use the existing
work; no v3/v4 extension, SQL, registry activation or new allowance is provided.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_input_wire as inputs_wire
from serverware import authority_webauthn_evidence_plan_contract as contract
from serverware import authority_webauthn_evidence_plan_reads as reads_wire
from serverware import authority_webauthn_evidence_proofs as proofs
from serverware import authority_webauthn_evidence_replay as replay


_EXPECTATION_FIELDS = frozenset({"request", "businessBeforeRoots", "authorizationBeforeRoots",
    "inputsDigest", "configurationDigest", "plannerIdentity", "plannerSpkiDigest",
    "evidenceIdentity", "evidenceSpkiDigest", "databaseCutoffUs", "nowEpochNs", "deadlineEpochNs",
    "maximumPlanAgeNs", "maximumEvidenceAgeNs", "maximumClockSkewNs", "rpId", "origin",
    "installationTargetDigest"})


class WebAuthnEvidencePlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedEvidencePlan:
    """Original bytes and actual local observations, never execution authority."""

    envelope_bytes: bytes
    payload_bytes: bytes
    inputs_bytes: bytes
    plan_digest: str
    semantics: replay._EvidenceReplayObservation
    write_result: proofs.indexed.IndexedMutationResult


def _capture(payload, expectations, inputs_bytes, work):
    ledger = evidence.capture._SharedLedger(work)
    inputs_wire._raw(inputs_bytes, 2, inputs_wire.MAX_BYTES)
    owned = evidence.capture._JSONCapture(ledger).visit({"payload": payload, "expectations": expectations})
    contract.validate_payload_shape(owned["payload"])
    expected = owned["expectations"]
    shape = evidence.plan.contract
    shape._object(expected, _EXPECTATION_FIELDS, "independent evidence plan expectations")
    for name in ("inputsDigest", "configurationDigest", "plannerSpkiDigest", "evidenceSpkiDigest"):
        shape._digest(expected[name])
    for name in ("plannerIdentity", "evidenceIdentity"):
        evidence._identity(expected[name])
    for name in ("nowEpochNs", "deadlineEpochNs", "databaseCutoffUs"):
        shape._integer(expected[name], minimum=1)
    for name in ("maximumPlanAgeNs", "maximumEvidenceAgeNs"):
        shape._integer(expected[name], evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(expected["maximumClockSkewNs"], evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if owned["payload"]["operation"] == replay.registration.OPERATION:
        shape._text(expected["rpId"], 4096)
        shape._text(expected["origin"], 8192)
        if expected["installationTargetDigest"] is not None:
            raise WebAuthnEvidencePlanError("registration expectations cannot use an installation target")
    else:
        shape._digest(expected["installationTargetDigest"])
        if expected["rpId"] is not None or expected["origin"] is not None:
            raise WebAuthnEvidencePlanError("installation expectations cannot use a registration RP")
    if expected["nowEpochNs"] >= expected["deadlineEpochNs"]:
        raise WebAuthnEvidencePlanError("evidence plan invocation has expired")
    return owned["payload"], expected


def _bind(payload, expected, work):
    for name in ("request", "businessBeforeRoots", "authorizationBeforeRoots", "inputsDigest",
            "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "databaseCutoffUs"):
        evidence.plan._same(payload[name], expected[name], work,
            "evidence plan differs from independent " + name)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    now, skew = expected["nowEpochNs"], expected["maximumClockSkewNs"]
    cutoff = inputs_wire._from_epoch_us(payload["databaseCutoffUs"])
    cutoff_ns = replay.registration.registration._now(cutoff)
    if (issued > now + skew or now - issued > expected["maximumPlanAgeNs"]
            or now >= expires or expires - issued > expected["maximumPlanAgeNs"]
            or expires > expected["deadlineEpochNs"] or cutoff_ns >= expires
            or abs(cutoff_ns - issued) > skew):
        raise WebAuthnEvidencePlanError("evidence plan times differ from independent freshness and cutoff")
    return cutoff


def _tuple(value, work):
    work.prepare_copy(value)
    return tuple(value)


def _root_documents(values, work):
    # Engine-produced roots have fixed four-field source-bounded scalars.
    # Reserve a conservative full projection before allocating its graph;
    # genuine canonical comparisons afterward have their own actual charges.
    work.charge(input_bytes=2 + 512 * len(values), json_nodes=1 + 9 * len(values))
    return [root.json_projection() for root in values]


def _replay_owned(payload, expected, inputs_bytes, evidence_public_key, work):
    operation = payload["operation"]
    maximum = evidence.authority.operation_spec(operation)["maximumBusinessQueryRows"]
    records = reads_wire._decode_reads_on_work(payload["queryReads"], maximum_rows=maximum, work=work)
    read = proofs._verify_reads_on_work(operation=operation, arguments=payload["request"]["arguments"],
        business_before_roots=_tuple(payload["businessBeforeRoots"], work),
        authorization_before_roots=_tuple(payload["authorizationBeforeRoots"], work),
        selected_rows=_tuple(payload["selectedRows"], work), before_proofs=_tuple(payload["beforeProofs"], work),
        query_reads=records, work=work)
    common = {"request": payload["request"], "selected_rows": read["selected_rows"],
        "database_now": inputs_wire._from_epoch_us(payload["databaseCutoffUs"]),
        "inputs_bytes": inputs_bytes, "expected_inputs_digest": expected["inputsDigest"],
        "expected_transition": payload["transition"], "public_key": evidence_public_key,
        "expected_identity": expected["evidenceIdentity"], "expected_spki_digest": expected["evidenceSpkiDigest"],
        "maximum_age_ns": expected["maximumEvidenceAgeNs"],
        "maximum_clock_skew_ns": expected["maximumClockSkewNs"], "work": work}
    if operation == replay.registration.OPERATION:
        if expected["installationTargetDigest"] is not None:
            raise WebAuthnEvidencePlanError("registration plan cannot use an installation target")
        semantics = replay._replay_registration_on_work(**common, rp_id=expected["rpId"], origin=expected["origin"])
    else:
        if expected["rpId"] is not None or expected["origin"] is not None:
            raise WebAuthnEvidencePlanError("installation plan cannot use a registration RP")
        semantics = replay._replay_installation_on_work(**common,
            installation_target_digest=expected["installationTargetDigest"])
    written = proofs._derive_writes_on_work(operation=operation,
        business_before_roots=read["business_before_roots"],
        authorization_before_roots=read["authorization_before_roots"], selected_rows=read["selected_rows"],
        before_proofs=read["before_proofs"], mutations=semantics.kernel.mutations, work=work)
    evidence.plan._same(_root_documents(written.primary.business_after_roots, work),
        payload["businessAfterRoots"], work, "evidence plan business after-roots differ from genuine replay")
    evidence.plan._same(_root_documents(written.primary.authorization_after_roots, work),
        payload["authorizationAfterRoots"], work, "evidence plan authorization after-roots differ from genuine replay")
    return semantics, written


def _produce_on_work(*, payload, inputs_bytes, expectations, planner_private_key,
        planner_public_key, evidence_public_key, work):
    """Reverify raw proof/semantic inputs before signing one actual plan.

    A supplied payload or claimed acquisition never substitutes for replay.
    Key/configuration provenance and the independent expectation admission
    remain external; this private primitive opens no serving or persistence path.
    """
    if (not isinstance(planner_private_key, Ed25519PrivateKey)
            or not isinstance(planner_public_key, Ed25519PublicKey)
            or not isinstance(evidence_public_key, Ed25519PublicKey)):
        raise WebAuthnEvidencePlanError("evidence plan production needs actual independently admitted Ed25519 keys")
    payload, expected = _capture(payload, expectations, inputs_bytes, work)
    _bind(payload, expected, work)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
    _replay_owned(payload, expected, inputs_bytes, evidence_public_key, work)
    ledger = evidence.capture._SharedLedger(work)
    payload_bytes = evidence.capability._wire(payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    message = evidence.plan._ascii(evidence.plan._frame(contract.SIGNATURE_DOMAIN, (payload_bytes,), work), work)
    placeholder = {"schema": contract.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    if size > contract.MAX_BYTES or nodes > contract.MAX_NODES:
        raise WebAuthnEvidencePlanError("signed evidence plan exceeds its transport bound")
    # Reserve the post-sign payload encoder/comparison and final envelope
    # encoder plus fixed signature transport before the actual key callback.
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    if (work.limits.max_input_bytes - work.input_bytes < payload_size
            or work.limits.max_json_nodes - work.json_nodes < payload_nodes):
        raise WebAuthnEvidencePlanError("evidence plan cannot reserve its post-sign measurement")
    signature = evidence.production._sign_and_verify(planner_private_key, planner_public_key, message, work)
    if work.measure(payload) != (payload_size, payload_nodes):
        raise WebAuthnEvidencePlanError("evidence plan size changed during signing")
    if evidence.plan.core.canonical_bytes(payload) != payload_bytes:
        raise WebAuthnEvidencePlanError("evidence plan changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    original = evidence.plan.core.canonical_bytes({"schema": contract.ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    if len(original) != size:
        raise WebAuthnEvidencePlanError("signed evidence plan output changed after sizing")
    return original


def _verify_on_work(*, envelope_bytes, inputs_bytes, expectations,
        planner_public_key, evidence_public_key, work):
    """Authenticate original bytes, then independently replay real raw inputs."""
    if (not isinstance(planner_public_key, Ed25519PublicKey)
            or not isinstance(evidence_public_key, Ed25519PublicKey)):
        raise WebAuthnEvidencePlanError("evidence plan verification needs actual independently admitted Ed25519 keys")
    ledger = evidence.capture._SharedLedger(work)
    inputs_wire._raw(inputs_bytes, 2, inputs_wire.MAX_BYTES)
    # Own independent expectations before parsing any received plan bytes.
    expected = evidence.capture._JSONCapture(ledger).visit(expectations)
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES, maximum_depth=contract.MAX_DEPTH)
    contract.validate_envelope_shape(envelope)
    payload, expected = _capture(envelope["payload"], expected, inputs_bytes, work)
    signature = envelope["signatureBase64Url"]
    _bind(payload, expected, work)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    payload_bytes = evidence.capability._wire(payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_public_key, signature, contract.SIGNATURE_DOMAIN, payload_bytes, ledger)
    evidence.capability._canonical(payload_bytes, payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    semantics, written = _replay_owned(payload, expected, inputs_bytes, evidence_public_key, work)
    digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)
    return _VerifiedEvidencePlan(envelope_bytes, payload_bytes, inputs_bytes, digest, semantics, written)
