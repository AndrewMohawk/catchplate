"""Configured read-acquire-and-sign owner for evidence-admission plans.

Construction is inert and requires an independently admitted real read owner
and separate planner signing pins. Calls cannot replace the operation, read
DSN, evidence policy, signing key, configuration digest or clock. The original
request/root/ceremony or committed-stage/readback authority still belongs to
the upstream admission boundary, not to copied arguments or this owner.

Each call owns its complete variable inputs before native/key/clock/SQL
callbacks, uses the actual read owner through normal scope exits, then invokes
genuine acquisition-to-plan proof and original-input replay before signing.
One live monotonic/epoch window covers acquisition and production, including
the lower signer's immediate pre/post checks. Expiry is additionally clipped
to the same external evidence original; decoding that bound is not signature
authority. No historical instant is rewritten and no retry is automatic.

Returned originals are not persisted, execution-authorized or a terminal
receipt. Neither this owner nor a signed plan activates a registry handler,
admits current roots or establishes historical configuration/physical custody.
All source-visible work uses the existing invocation allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_query_reads as reads
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware import authority_webauthn_evidence_plan_production as producing
from serverware import authority_webauthn_evidence_planning as planning


evidence, authority = planning.evidence, planning.authority
production = planning.production
_IDENTITY_FIELDS = planning._IDENTITY_FIELDS


class WebAuthnEvidencePlanOwnerError(ValueError):
    pass


def _configuration(values):
    """Validate only held source scalars and key types, without callbacks."""
    if type(values) is not tuple or len(values) != 6:
        raise WebAuthnEvidencePlanOwnerError("evidence plan owner configuration is not exact")
    read_config, private, public, identity, spki, configuration_digest = values
    planning._configuration(read_config)
    if (not isinstance(private, evidence.Ed25519PrivateKey)
            or not isinstance(public, evidence.keys.Ed25519PublicKey)
            or type(identity) is not tuple or len(identity) != 3):
        raise WebAuthnEvidencePlanOwnerError("evidence plan owner signing pins are not exact")
    for value in (*identity, spki, configuration_digest):
        evidence.plan.contract._digest(value)
    return values


def _read_owner(configured):
    """Build a private real owner from the held tuple, never reread its caller."""
    return planning.EvidenceAdmissionPlanner(operation=configured[3],
        read_dsn=configured[0], connect_timeout_seconds=configured[1], database_identity=configured[2],
        evidence_public_key=configured[4],
        expected_evidence_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
        expected_evidence_spki_digest=configured[6], maximum_age_ns=configured[7],
        maximum_clock_skew_ns=configured[8], rp_id=configured[9], origin=configured[10],
        installation_target_digest=configured[11])


def _capture(configured, *, request, business_before_roots, authorization_before_roots,
        deadline_epoch_ns, inputs, work):
    evidence.capture._SharedLedger(work)
    operation = configured[0][3]
    if type(request) is not dict:
        raise WebAuthnEvidencePlanOwnerError("evidence plan request is not an exact object")
    for values, tables in ((business_before_roots, producing.contract._BUSINESS_TABLES[operation]),
            (authorization_before_roots, producing.contract._AUTHORIZATION_TABLES[operation])):
        if type(values) not in (tuple, list) or len(values) != len(tables):
            raise WebAuthnEvidencePlanOwnerError("evidence plan root expectations are not source bounded")
    owned = reads._CopyBudget(work).copy({"request": request,
        "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
        "deadlineEpochNs": deadline_epoch_ns, "inputs": inputs})
    if owned["request"].get("operation") != operation:
        raise WebAuthnEvidencePlanOwnerError("evidence plan request differs from its configured operation")
    evidence.plan.contract._integer(owned["deadlineEpochNs"], minimum=1)
    # Plan expectations use the existing closed JSON form. Every original
    # caller graph is detached before these bounded tuple-to-list copies.
    for name in ("businessBeforeRoots", "authorizationBeforeRoots"):
        work.prepare_copy(owned[name])
        owned[name] = list(owned[name])
    return owned


def _open(configured, owned, envelope_bytes, work):
    # This is a narrowing bound from the exact immutable original, not an
    # authenticated claim. Actual acquisition and replay both verify it.
    envelope = evidence._decode_on_work(envelope_bytes, work)
    purpose = ("registration-attestation" if configured[0][3] == planning.registration.OPERATION
        else "trust-installation")
    if envelope["purpose"] != purpose:
        raise WebAuthnEvidencePlanOwnerError("evidence plan original has the wrong configured purpose")
    deadline = min(owned["deadlineEpochNs"], envelope["expiresAtEpochNs"])
    return clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=configured[0][7], maximum_clock_skew_ns=configured[0][8], work=work)


def _finish(configured, owned, acquisition, live_window, work):
    # The actual read method has returned only after cursor, transaction and
    # connection normal exits. Its original-input commitment and DB cutoff are
    # locally derived observations; request/root expectations remain the held
    # independent inputs, never values enrolled from the database result.
    now = clock._check_on_work(live_window, work=work)
    read_config, private, public, identity, spki, configuration_digest = configured
    expected = {"request": owned["request"],
        "businessBeforeRoots": owned["businessBeforeRoots"],
        "authorizationBeforeRoots": owned["authorizationBeforeRoots"],
        "inputsDigest": acquisition.original_inputs_digest,
        "configurationDigest": configuration_digest,
        "plannerIdentity": dict(zip(_IDENTITY_FIELDS, identity)), "plannerSpkiDigest": spki,
        "evidenceIdentity": dict(zip(_IDENTITY_FIELDS, read_config[5])),
        "evidenceSpkiDigest": read_config[6],
        "databaseCutoffUs": producing.plan.inputs_wire._to_epoch_us(acquisition.state.database_now),
        "nowEpochNs": now, "deadlineEpochNs": clock._deadline_epoch_ns(live_window),
        "maximumPlanAgeNs": read_config[7], "maximumEvidenceAgeNs": read_config[7],
        "maximumClockSkewNs": read_config[8], "rpId": read_config[9], "origin": read_config[10],
        "installationTargetDigest": read_config[11]}
    result = producing._produce_from_acquisition_on_work(acquisition, expectations=expected,
        planner_private_key=private, planner_public_key=public, evidence_public_key=read_config[4],
        live_window=live_window, work=work)
    clock._check_on_work(live_window, work=work)
    return result


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidenceAdmissionPlanOwner:
    """Hold one purpose's read configuration and separately admitted signer."""

    _configured: tuple

    def __init__(self, *, read_planner, planner_private_key, planner_public_key,
            expected_planner_identity, expected_planner_spki_digest, configuration_digest):
        if type(read_planner) is not planning.EvidenceAdmissionPlanner:
            raise WebAuthnEvidencePlanOwnerError("evidence plan owner requires the actual configured reader")
        read_config = planning._configuration(read_planner._configured)
        evidence._identity(expected_planner_identity)
        configured = _configuration((read_config, planner_private_key, planner_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            expected_planner_spki_digest, configuration_digest))
        object.__setattr__(self, "_configured", configured)

    def _snapshot(self, operation):
        if type(self) is not EvidenceAdmissionPlanOwner:
            raise WebAuthnEvidencePlanOwnerError("evidence plan owner type changed")
        configured = _configuration(self._configured)
        if configured[0][3] != operation:
            raise WebAuthnEvidencePlanOwnerError("evidence plan method differs from its configured purpose")
        return configured

    def verify_retained(self, *, envelope_bytes, inputs_bytes, evaluation_context_bytes,
            expectations, work):
        """Replay three originals against separately admitted historical context.

        Matching this owner's configured pins does not establish that it was
        the historical configuration. The caller still admits the request,
        roots, input commitment, database cutoff and historical time window.
        This method neither samples a new clock nor uses the private signer.
        """
        if type(self) is not EvidenceAdmissionPlanOwner:
            raise WebAuthnEvidencePlanOwnerError("evidence plan owner type changed")
        held = _configuration(self._configured)
        configured = self._snapshot(held[0][3])
        ledger = evidence.capture._SharedLedger(work)
        expected = evidence.capture._JSONCapture(ledger).visit(expectations)
        operation = configured[0][3]
        producing.plan._validate_expectations(expected, operation)
        read_config, _private, public, identity, spki, configuration_digest = configured
        evidence.plan._same((expected["configurationDigest"], expected["plannerIdentity"],
                expected["plannerSpkiDigest"], expected["evidenceIdentity"], expected["evidenceSpkiDigest"],
                expected["maximumPlanAgeNs"], expected["maximumEvidenceAgeNs"],
                expected["maximumClockSkewNs"], expected["rpId"], expected["origin"],
                expected["installationTargetDigest"]),
            (configuration_digest, dict(zip(_IDENTITY_FIELDS, identity)), spki,
                dict(zip(_IDENTITY_FIELDS, read_config[5])), read_config[6],
                read_config[7], read_config[7], read_config[8], read_config[9], read_config[10], read_config[11]),
            work, "retained evidence plan context differs from held configuration")
        from serverware import authority_webauthn_evidence_plan_retention as retention

        return retention._verify_record_on_work(envelope_bytes=envelope_bytes,
            inputs_bytes=inputs_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expectations=expected, planner_public_key=public, evidence_public_key=read_config[4], work=work)

    def produce_registration(self, *, request, business_before_roots, authorization_before_roots,
            envelope_bytes, client_data_json, attestation_object, credential_id, transports,
            scope, verification_context, expected_authorization, deadline_epoch_ns, work):
        configured = self._snapshot(planning.registration.OPERATION)
        evidence.capture._SharedLedger(work)
        raw = (planning._raw(envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            planning._raw(client_data_json, 1, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            planning._raw(attestation_object, 1, production.attestation.MAX_ATTESTATION_OBJECT_BYTES))
        if type(transports) is not tuple or len(transports) > 16:
            raise WebAuthnEvidencePlanOwnerError("evidence plan transports are not a bounded exact tuple")
        ceremony = production._hold_context(scope, verification_context, work)
        owned = _capture(configured, request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, deadline_epoch_ns=deadline_epoch_ns,
            inputs={"credentialId": credential_id, "transports": transports,
                "authorization": expected_authorization}, work=work)
        scope_fields, context_fields, root_fields = ceremony
        production.registration._same(context_fields[:2], configured[0][9:11], work,
            "evidence plan RP/origin differs from held configuration")
        read_owner = _read_owner(configured[0])
        live_window = _open(configured, owned, raw[0], work)
        # No caller object is read from here onward. Reconstruction uses only
        # held exact immutable context members on the original work allowance.
        held_scope = production.attestation.CeremonyScope(*scope_fields, _work=work)
        roots = tuple(production.attestation.TrustRootSnapshot(*fields, _work=work) for fields in root_fields)
        held_context = production.attestation.VerificationContext(*context_fields, roots, _work=work)
        now = clock._check_on_work(live_window, work=work)
        result = planning.EvidenceAdmissionPlanner.acquire_registration(read_owner,
            request=owned["request"], business_before_roots=owned["businessBeforeRoots"],
            authorization_before_roots=owned["authorizationBeforeRoots"],
            envelope_bytes=raw[0], client_data_json=raw[1], attestation_object=raw[2],
            credential_id=owned["inputs"]["credentialId"], transports=owned["inputs"]["transports"],
            scope=held_scope, verification_context=held_context,
            expected_authorization=owned["inputs"]["authorization"], now_epoch_ns=now,
            deadline_epoch_ns=clock._deadline_epoch_ns(live_window), work=work)
        return _finish(configured, owned, result, live_window, work)

    def produce_installation(self, *, request, business_before_roots, authorization_before_roots,
            installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, observed_at, deadline_epoch_ns, work):
        configured = self._snapshot(planning.installation.OPERATION)
        evidence.capture._SharedLedger(work)
        raw = (planning._raw(installation_envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            planning._raw(installed_bundle_bytes, 2, planning.installation.completion.bundle_core.MAX_INSTALLATION_BYTES),
            planning._raw(installed_state_bytes, 2, planning.installation.completion.bundle_core.MAX_STATE_BYTES))
        planning.installation.completion._now(observed_at)
        owned = _capture(configured, request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, deadline_epoch_ns=deadline_epoch_ns,
            inputs={"stage": expected_committed_stage}, work=work)
        read_owner = _read_owner(configured[0])
        live_window = _open(configured, owned, raw[0], work)
        now = clock._check_on_work(live_window, work=work)
        result = planning.EvidenceAdmissionPlanner.acquire_installation(read_owner,
            request=owned["request"], business_before_roots=owned["businessBeforeRoots"],
            authorization_before_roots=owned["authorizationBeforeRoots"],
            installation_envelope_bytes=raw[0], installed_bundle_bytes=raw[1], installed_state_bytes=raw[2],
            expected_committed_stage=owned["inputs"]["stage"], observed_at=observed_at,
            now_epoch_ns=now, deadline_epoch_ns=clock._deadline_epoch_ns(live_window), work=work)
        return _finish(configured, owned, result, live_window, work)
