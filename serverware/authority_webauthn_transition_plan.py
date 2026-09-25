"""Signed successor plans with genuine detached-original proof replay.

The independent context supplies the original request, roots, counted heads,
verification policy, historical times and configured planner pins. Neither a
received context nor a signed plan enrolls those expectations. The producer
replays actual proofs and semantics before signing; the verifier authenticates
all original byte commitments before decoding context and replaying them again.

Production retains its one actual live window. Verification uses independently
admitted historical time without refreshing it. These observations provide no
execution capability, current-root authority, reservation or durable custody.
There is no SQL, registry activation, callback injection or replacement budget.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware import authority_webauthn_transition_plan_contract as contract
from serverware import authority_webauthn_transition_plan_context as context
from serverware import authority_webauthn_transition_proof as proof


class WebAuthnTransitionPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedTransitionPlan:
    """Original bytes and actual local replay, never an input authority token."""

    envelope_bytes: bytes
    proof_bytes: bytes
    inputs_bytes: bytes
    context_bytes: bytes
    plan_digest: str
    replay: proof._ProofObservation


def _originals(proof_bytes, inputs_bytes, context_bytes):
    proof.wire._raw(proof_bytes, 2, proof.contract.MAX_BYTES)
    proof.wire._raw(inputs_bytes, 2, proof.wire.MAX_BYTES)
    proof.wire._raw(context_bytes, 2, context.MAX_BYTES)


def _capture(payload, expectations, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "payload": payload, "expectations": expectations})
    contract.validate_payload_shape(owned["payload"])
    operation = contract._validate_expectations(owned["expectations"])
    evidence.plan._same(owned["payload"]["operation"], operation, work,
        "successor plan differs from the independent operation")
    return owned["payload"], owned["expectations"]


def _fresh(payload, expected, now):
    """Join original policy/cutoff times without reissuing any historical data."""
    policy = expected["proofExpectations"]["policy"]
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    skew, maximum = policy["maximumClockSkewNs"], expected["maximumPlanAgeNs"]
    cutoff_ns = expected["proofExpectations"]["databaseCutoffUs"] * 1000
    if (abs(issued - policy["nowEpochNs"]) > skew
            or issued > now + skew or now - issued > maximum
            or now >= expires or expires - issued > maximum
            or now >= policy["deadlineEpochNs"] or expires > policy["deadlineEpochNs"]
            or cutoff_ns >= expires or abs(cutoff_ns - issued) > skew):
        raise WebAuthnTransitionPlanError("successor plan differs from the original freshness and cutoff")


def _bind(payload, expected, work):
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        evidence.plan._same(payload[name], expected[name], work,
            "successor plan differs from independent " + name)
    evidence.plan._same(payload["inputsDigest"], expected["proofExpectations"]["inputsDigest"], work,
        "successor plan inputs differ from independent history")
    _fresh(payload, expected, expected["proofExpectations"]["policy"]["nowEpochNs"])


def _commitments(payload, proof_bytes, inputs_bytes, context_bytes, work):
    """Authenticate complete original frames, not a caller's claimed digest."""
    actual = (
        ("proofDigest", evidence.plan._frame(proof.contract.IDENTITY_DOMAIN, (proof_bytes,), work)),
        ("proofByteCount", len(proof_bytes)),
        ("inputsDigest", proof.inputs._digest_on_work(inputs_bytes, work)),
        ("inputsByteCount", len(inputs_bytes)),
        ("contextDigest", context._digest_on_work(context_bytes, work)),
        ("contextByteCount", len(context_bytes)),
    )
    for name, value in actual:
        evidence.plan._same(payload[name], value, work,
            "successor plan differs from original " + name)


def _context(context_bytes, expected, work):
    received = context._decode_on_work(context_bytes, work=work)
    evidence.plan._same(received, expected, work,
        "successor plan context differs from independently admitted expectations")


def _produce_on_work(*, payload, proof_bytes, inputs_bytes, context_bytes,
        expectations, planner_private_key, planner_public_key, public_key,
        live_window, work):
    """Replay original proofs and semantics before signing the exact payload.

    The actual configured owner supplies the independent context and one live
    clock window. Its clipped deadline may be earlier than the original policy
    deadline, but cannot replace that original assertion/evidence history.
    """
    if (not isinstance(planner_private_key, Ed25519PrivateKey)
            or not isinstance(planner_public_key, Ed25519PublicKey)
            or not isinstance(public_key, Ed25519PublicKey)):
        raise WebAuthnTransitionPlanError("successor plan production requires actual admitted Ed25519 keys")
    _originals(proof_bytes, inputs_bytes, context_bytes)
    live_window = clock._validate(live_window)
    payload, expected = _capture(payload, expectations, work)
    policy = expected["proofExpectations"]["policy"]
    if (payload["issuedAtEpochNs"] != live_window[0]
            or payload["expiresAtEpochNs"] != live_window[3]
            or live_window[3] > policy["deadlineEpochNs"]
            or live_window[5] != expected["maximumPlanAgeNs"]
            or live_window[6] != policy["maximumClockSkewNs"]):
        raise WebAuthnTransitionPlanError("successor plan differs from its unchanged live window")
    _bind(payload, expected, work)
    _fresh(payload, expected, clock._check_on_work(live_window, work=work))
    _commitments(payload, proof_bytes, inputs_bytes, context_bytes, work)
    _context(context_bytes, expected, work)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
    replayed = proof._replay_on_work(proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        expectations=expected["proofExpectations"], public_key=public_key, work=work)
    evidence.plan._same(replayed.proof_digest, payload["proofDigest"], work,
        "successor plan proof identity differs from genuine replay")
    ledger = evidence.capture._SharedLedger(work)
    payload_bytes = evidence.capability._wire(payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    message = evidence.plan._ascii(evidence.plan._frame(contract.SIGNATURE_DOMAIN, (payload_bytes,), work), work)
    placeholder = {"schema": contract.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    if size > contract.MAX_BYTES or nodes > contract.MAX_NODES:
        raise WebAuthnTransitionPlanError("signed successor plan exceeds its transport bound")
    # Prepay actual post-sign encodings/comparison and signature transport.
    # The immediately post-callback measurement has its own remaining reserve.
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    if (work.limits.max_input_bytes - work.input_bytes < payload_size
            or work.limits.max_json_nodes - work.json_nodes < payload_nodes):
        raise WebAuthnTransitionPlanError("successor plan cannot reserve its post-sign measurement")
    _fresh(payload, expected, clock._check_on_work(live_window, work=work))
    signature = evidence.production._sign_and_verify(planner_private_key, planner_public_key, message, work)
    _fresh(payload, expected, clock._check_on_work(live_window, work=work))
    if work.measure(payload) != (payload_size, payload_nodes):
        raise WebAuthnTransitionPlanError("successor plan size changed during signing")
    if evidence.plan.core.canonical_bytes(payload) != payload_bytes:
        raise WebAuthnTransitionPlanError("successor plan changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    original = evidence.plan.core.canonical_bytes({"schema": contract.ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    if len(original) != size:
        raise WebAuthnTransitionPlanError("signed successor plan output changed after sizing")
    _fresh(payload, expected, clock._check_on_work(live_window, work=work))
    return original


def _verify_on_work(*, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        expectations, planner_public_key, public_key, work):
    """Authenticate originals, then genuinely replay against independent history."""
    if (not isinstance(planner_public_key, Ed25519PublicKey)
            or not isinstance(public_key, Ed25519PublicKey)):
        raise WebAuthnTransitionPlanError("successor plan verification requires actual admitted Ed25519 keys")
    ledger = evidence.capture._SharedLedger(work)
    _originals(proof_bytes, inputs_bytes, context_bytes)
    proof.wire._raw(envelope_bytes, 2, contract.MAX_BYTES)
    # No received context or payload is consulted to establish these pins.
    expected = evidence.capture._JSONCapture(ledger).visit(expectations)
    contract._validate_expectations(expected)
    envelope = evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES, maximum_depth=contract.MAX_DEPTH)
    contract.validate_envelope_shape(envelope)
    payload, expected = _capture(envelope["payload"], expected, work)
    signature = envelope["signatureBase64Url"]
    _bind(payload, expected, work)
    evidence.capability._canonical(envelope_bytes, envelope, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    payload_bytes = evidence.capability._wire(payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_public_key, signature, contract.SIGNATURE_DOMAIN, payload_bytes, ledger)
    evidence.capability._canonical(payload_bytes, payload, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    # Verify every signed detached-byte commitment before parsing the original
    # context or adopting any original proof/input graph into genuine replay.
    _commitments(payload, proof_bytes, inputs_bytes, context_bytes, work)
    _context(context_bytes, expected, work)
    replayed = proof._replay_on_work(proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        expectations=expected["proofExpectations"], public_key=public_key, work=work)
    evidence.plan._same(replayed.proof_digest, payload["proofDigest"], work,
        "successor plan proof identity differs from genuine replay")
    digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)
    return _VerifiedTransitionPlan(envelope_bytes, proof_bytes, inputs_bytes, context_bytes, digest, replayed)
