"""Replay original successor read/write proofs and actual operation semantics.

An independent admission boundary must supply request, original-input identity,
primary/count heads, historical cutoff and operation-specific verification
policy. A decoded proof or its digest cannot enroll any of those expectations.
This is a separate unsigned proof record, not a v3/v4 execution plan, signature,
reservation, current-root assertion, custody receipt or authorization token.
Proof records contain selected rows and belong inside the semantic/storage
boundary, not a public response or an external witness request.

The same work covers canonical transport, genuine primary/count proofs, query
associations, original-input signatures/semantics and actual indexed writes.
No read-success object is accepted as a substitute for original write proofs.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_webauthn_transition_inputs as inputs
from catchplate import authority_webauthn_transition_proof_contract as contract
from catchplate import authority_webauthn_transition_proof_wire as proof_wire
from catchplate import authority_webauthn_complete_proofs as complete_proofs
from catchplate import authority_webauthn_completion_proofs as completion_proofs
from catchplate import authority_webauthn_registration_replay as registration
from catchplate import authority_webauthn_stage_replay as stage
from catchplate import authority_webauthn_completion_replay as completion


evidence, wire = inputs.evidence, inputs.wire
_EXPECTATIONS = frozenset({"request", "inputsDigest", "databaseCutoffUs", "businessBeforeRoots",
    "authorizationBeforeRoots", "countedBeforeHeads", "policy"})
_TIME_FIELDS = frozenset({"nowEpochNs", "deadlineEpochNs", "maximumAgeNs", "maximumClockSkewNs"})
_POLICY_FIELDS = {
    registration.OPERATION: _TIME_FIELDS | {"signerIdentity", "signerSpkiDigest", "rpId", "origin"},
    stage.OPERATION: _TIME_FIELDS | {"verifierIdentity", "capabilityId", "candidateSigningKeyId",
        "developmentEnabled", "requireApproval", "requireApproverWebauthn"},
    completion.OPERATION: _TIME_FIELDS | {"installerIdentity", "installerSpkiDigest",
        "installationTargetDigest", "committedStage"},
}


class WebAuthnTransitionProofError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProofObservation:
    """Original bytes and genuine local outputs, not a reusable proof token."""

    proof_bytes: bytes
    proof_digest: str
    semantics: inputs._ReplayObservation
    written: object


@dataclass(frozen=True, slots=True)
class _RetainedProofAcquisition:
    acquisition: object
    inputs_bytes: bytes
    inputs_digest: str
    semantics: inputs._ReplayObservation
    proof_bytes: bytes
    proof_digest: str


def _validate_expectations(expected):
    shape = evidence.plan.contract
    shape._object(expected, _EXPECTATIONS, "independent transition proof expectations")
    if type(expected["request"]) is not dict:
        raise WebAuthnTransitionProofError("independent proof request is not an exact object")
    operation = expected["request"].get("operation")
    if type(operation) is not str or operation not in contract.OPERATIONS:
        raise WebAuthnTransitionProofError("independent proof operation is not source fixed")
    shape._digest(expected["inputsDigest"])
    wire._from_epoch_us(expected["databaseCutoffUs"])
    for field in ("businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads"):
        if type(expected[field]) is not list:
            raise WebAuthnTransitionProofError("independent proof roots require canonical arrays")
    policy = expected["policy"]
    shape._object(policy, _POLICY_FIELDS[operation], "independent successor proof policy")
    for field in ("nowEpochNs", "deadlineEpochNs"):
        shape._integer(policy[field], minimum=1)
    shape._integer(policy["maximumAgeNs"], inputs.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(policy["maximumClockSkewNs"], inputs.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if policy["nowEpochNs"] >= policy["deadlineEpochNs"]:
        raise WebAuthnTransitionProofError("independent proof history has an expired invocation")
    # Each genuine family replay closes and independently joins the remaining
    # policy fields before its native/key callbacks. No policy is read from the
    # received proof or original-input record.
    return operation


def _root_documents(values, work):
    work.charge(input_bytes=2 + 512 * len(values), json_nodes=1 + 9 * len(values))
    return [root.json_projection() for root in values]


def _head_documents(values, work):
    work.charge(input_bytes=2 + 512 * len(values), json_nodes=1 + 9 * len(values))
    return [{"indexId": head.index_id, "indexRevision": head.index_revision,
        "rootDigest": head.index_root.digest, "leafCount": head.index_root.count} for head in values]


def _semantics(operation, *, document, expected, selected, records, inputs_bytes, public_key, work):
    policy = expected["policy"]
    common = {"request": expected["request"], "selected_rows": selected,
        "database_now": wire._from_epoch_us(expected["databaseCutoffUs"]), "query_reads": records,
        "inputs_bytes": inputs_bytes, "expected_inputs_digest": expected["inputsDigest"],
        "expected_transition": document["transition"], "now_epoch_ns": policy["nowEpochNs"],
        "deadline_epoch_ns": policy["deadlineEpochNs"], "maximum_age_ns": policy["maximumAgeNs"],
        "maximum_clock_skew_ns": policy["maximumClockSkewNs"], "work": work}
    if operation == registration.OPERATION:
        return registration._replay_on_work(**common, evidence_public_key=public_key,
            expected_signer_identity=policy["signerIdentity"], expected_signer_spki_digest=policy["signerSpkiDigest"],
            expected_rp_id=policy["rpId"], expected_origin=policy["origin"])
    if operation == stage.OPERATION:
        return stage._replay_on_work(**common, verifier_public_key=public_key,
            verifier_identity=policy["verifierIdentity"], capability_id=policy["capabilityId"],
            expected_candidate_signing_key_id=policy["candidateSigningKeyId"],
            development_enabled=policy["developmentEnabled"], require_approval=policy["requireApproval"],
            require_approver_webauthn=policy["requireApproverWebauthn"])
    return completion._replay_on_work(**common, installer_public_key=public_key,
        expected_installer_identity=policy["installerIdentity"], expected_installer_spki_digest=policy["installerSpkiDigest"],
        installation_target_digest=policy["installationTargetDigest"], expected_committed_stage=policy["committedStage"])


def _replay_on_work(*, proof_bytes, inputs_bytes, expectations, public_key, work):
    """Recompute from raw proof originals and independently admitted history."""
    ledger = evidence.capture._SharedLedger(work)
    if not isinstance(public_key, evidence.keys.Ed25519PublicKey):
        raise WebAuthnTransitionProofError("transition proof replay needs the actual admitted public key")
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    wire._raw(proof_bytes, 2, contract.MAX_BYTES)
    # Own the entire independent context before any decoder, mathematical
    # constructor or native/key callback, including the completion stage graph.
    expected = evidence.capture._JSONCapture(ledger).visit(expectations)
    operation = _validate_expectations(expected)
    document = evidence.wire._decode_object(proof_bytes, work=work,
        maximum_bytes=contract.MAX_BYTES, maximum_nodes=contract.MAX_NODES, maximum_depth=contract.MAX_DEPTH)
    contract.validate_payload_shape(document)
    evidence.capability._canonical(proof_bytes, document, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    evidence.plan._same(document["operation"], operation, work, "proof operation differs from independent history")
    for field in sorted(_EXPECTATIONS - {"policy"}):
        evidence.plan._same(document[field], expected[field], work,
            "proof differs from independent " + field)
    # The original-input commitment is authenticated independently of the
    # proof before any mathematical replay; families recheck it before decode.
    evidence.plan._same(inputs._digest_on_work(inputs_bytes, work), expected["inputsDigest"], work,
        "proof original inputs differ from independent history")
    records = proof_wire._decode_reads_on_work(document["queryReads"], operation=operation, work=work)
    engine = completion_proofs if operation == completion.OPERATION else complete_proofs
    read = engine._verify_reads_on_work(document=document, work=work)
    semantics = _semantics(operation, document=document, expected=expected,
        selected=read.selected_rows, records=records, inputs_bytes=inputs_bytes, public_key=public_key, work=work)
    written = engine._derive_writes_on_work(document=document, mutations=semantics.mutations, work=work)
    for field, values in (("businessAfterRoots", written.primary.business_after_roots),
            ("authorizationAfterRoots", written.primary.authorization_after_roots)):
        evidence.plan._same(_root_documents(values, work), document[field], work,
            "proof after roots differ from actual indexed replay")
    for field, values in (("countedBeforeHeads", written.before_heads), ("countedAfterHeads", written.after_heads)):
        evidence.plan._same(_head_documents(values, work), document[field], work,
            "proof counted heads differ from actual indexed replay")
    digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (proof_bytes,), work)
    return _ProofObservation(proof_bytes, digest, semantics, written)
