"""Configured read-only owner for the two purpose-specific admission flows.

Construction is inert. The real planner/driver and unchanged registry gate are
entered only after invocation ownership. Each owner pins one operation, one
evidence signer and freshness policy, and either RP/origin or installation
target. Requests cannot replace those pins, supply a cursor/manifest or expand
the read transaction. Actual acquisition uses one original work allowance.

These explicit configuration inputs require independent admission through the
signed purpose-policy mapper and actual service factory. This owner does not
infer that authority from a generic verifier key. Likewise,
caller root/time/enrollment or committed-stage/readback expectations still need
independent provenance. SQL identity/source checks and driver work retain their
existing separate bounds. No signing, persistence, execution or service/registry
activation follows from the returned ordinary acquisition observations. The
private replay methods repeat genuine historical semantics with the held pins;
historical input/context admission and durable plan/proof replay remain external.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_query_reads as reads
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_planning as planning
from serverware import authority_transition_webauthn_registration_admission as registration
from serverware import authority_transition_webauthn_installation_admission as installation


authority, evidence = registration.authority, registration.evidence
production = registration.admission.production
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


class WebAuthnEvidencePlanningError(ValueError):
    pass


def _configuration(values):
    """Bound fixed scalar configuration without a key callback or connection."""
    if type(values) is not tuple or len(values) != 12:
        raise WebAuthnEvidencePlanningError("evidence planner configuration is not exact")
    dsn, timeout, database, operation, key, identity, spki, age, skew, rp_id, origin, target = values
    planning.reader._bounded_text(dsn, 65536)
    if "\n" in dsn or "\r" in dsn or type(timeout) is not int or not 2 <= timeout <= 300:
        raise WebAuthnEvidencePlanningError("evidence planner connection settings are invalid")
    if type(database) is not tuple or len(database) != 7:
        raise WebAuthnEvidencePlanningError("evidence planner database identity is not exact")
    planning.reader._bounded_text(database[0], 63)
    for value in database[1:4]:
        planning.reader._bounded_text(value, 4096)
    for value in database[4:]:
        evidence.plan.contract._digest(value)
    if type(operation) is not str or operation not in (registration.OPERATION, installation.OPERATION):
        raise WebAuthnEvidencePlanningError("evidence planner operation is not source fixed")
    if not isinstance(key, evidence.keys.Ed25519PublicKey) or type(identity) is not tuple or len(identity) != 3:
        raise WebAuthnEvidencePlanningError("evidence planner signer configuration is invalid")
    for value in (*identity, spki):
        evidence.plan.contract._digest(value)
    production.registration._integer(age, "evidence maximum age", 1, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    production.registration._integer(skew, "evidence clock skew", 0, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if operation == registration.OPERATION:
        planning.reader._bounded_text(rp_id, 4096)
        planning.reader._bounded_text(origin, 8192)
        if target is not None:
            raise WebAuthnEvidencePlanningError("registration planner cannot admit an installation target")
    else:
        evidence.plan.contract._digest(target)
        if rp_id is not None or origin is not None:
            raise WebAuthnEvidencePlanningError("installation planner cannot admit a registration RP")
    return values


def _capture(values, *, request, business_before_roots, authorization_before_roots,
             now_epoch_ns, deadline_epoch_ns, inputs, work):
    evidence.capture._SharedLedger(work)
    owned = reads._CopyBudget(work).copy({"request": request,
        "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
        "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns, "inputs": inputs})
    operation = values[3]
    adapter = registration if operation == registration.OPERATION else installation
    actual = owned["request"]
    if (type(actual) is not dict or actual.get("operation") != operation
            or actual.get("handler") != adapter.HANDLER):
        raise WebAuthnEvidencePlanningError("evidence planner request differs from its configured operation")
    adapter._arguments(actual.get("arguments"), work)
    digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(digest, actual.get("requestDigest"), work=work):
        raise WebAuthnEvidencePlanningError("evidence planner request digest changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), actual.get("operationId"), work=work):
        raise WebAuthnEvidencePlanningError("evidence planner operation ID changed")
    for name in ("nowEpochNs", "deadlineEpochNs"):
        production.registration._integer(owned[name], name, 1)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise WebAuthnEvidencePlanningError("evidence planner call has expired")
    return owned


def _raw(value, minimum, maximum):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise WebAuthnEvidencePlanningError("evidence planner requires bounded original bytes")
    return value


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidenceAdmissionPlanner:
    """Own one real read transaction using configuration held before callbacks."""

    _configured: tuple

    def __init__(self, *, operation, read_dsn, connect_timeout_seconds, database_identity,
                 evidence_public_key, expected_evidence_identity, expected_evidence_spki_digest,
                 maximum_age_ns, maximum_clock_skew_ns, rp_id=None, origin=None,
                 installation_target_digest=None):
        evidence._identity(expected_evidence_identity)
        configured = _configuration((read_dsn, connect_timeout_seconds, database_identity, operation,
            evidence_public_key, tuple(expected_evidence_identity[name] for name in _IDENTITY_FIELDS),
            expected_evidence_spki_digest, maximum_age_ns, maximum_clock_skew_ns,
            rp_id, origin, installation_target_digest))
        object.__setattr__(self, "_configured", configured)

    def _snapshot(self, operation):
        if type(self) is not EvidenceAdmissionPlanner:
            raise WebAuthnEvidencePlanningError("evidence planner owner type changed")
        configured = _configuration(self._configured)
        if configured[3] != operation:
            raise WebAuthnEvidencePlanningError("evidence planner method differs from its configured operation")
        return configured

    def replay_registration(self, *, request, selected_rows, database_now,
            inputs_bytes, expected_inputs_digest, expected_transition, work):
        """Recheck actual originals/effects under independently admitted history.

        The historical commitment, selected rows and cutoff must come from an
        admitted original plan, not be copied from untrusted input storage.
        Held configuration must be independently resolved for that history;
        using a currently active owner does not establish historical authority.
        This opens no SQL and does not establish current roots or execution.
        """
        configured = self._snapshot(registration.OPERATION)
        from serverware import authority_webauthn_evidence_replay as replay

        return replay._replay_registration_on_work(request=request, selected_rows=selected_rows,
            database_now=database_now, inputs_bytes=inputs_bytes,
            expected_inputs_digest=expected_inputs_digest, expected_transition=expected_transition,
            public_key=configured[4], expected_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
            expected_spki_digest=configured[6], maximum_age_ns=configured[7],
            maximum_clock_skew_ns=configured[8], rp_id=configured[9], origin=configured[10], work=work)

    def replay_installation(self, *, request, selected_rows, database_now,
            inputs_bytes, expected_inputs_digest, expected_transition, work):
        """Recheck original installation semantics, never attest physical state.

        Historical input commitment, selected rows/cutoff and the configured
        signer/target policy need independent admission for the exact history.
        No current owner or retained stage descriptor establishes that lineage.
        """
        configured = self._snapshot(installation.OPERATION)
        from serverware import authority_webauthn_evidence_replay as replay

        return replay._replay_installation_on_work(request=request, selected_rows=selected_rows,
            database_now=database_now, inputs_bytes=inputs_bytes,
            expected_inputs_digest=expected_inputs_digest, expected_transition=expected_transition,
            public_key=configured[4], expected_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
            expected_spki_digest=configured[6], maximum_age_ns=configured[7],
            maximum_clock_skew_ns=configured[8], installation_target_digest=configured[11], work=work)

    def acquire_registration(self, *, request, business_before_roots, authorization_before_roots,
            envelope_bytes, client_data_json, attestation_object, credential_id, transports,
            scope, verification_context, expected_authorization, now_epoch_ns, deadline_epoch_ns, work):
        configured = self._snapshot(registration.OPERATION)
        evidence.capture._SharedLedger(work)
        raw = (_raw(envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            _raw(client_data_json, 1, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
            _raw(attestation_object, 1, production.attestation.MAX_ATTESTATION_OBJECT_BYTES))
        if type(transports) is not tuple or len(transports) > 16:
            raise WebAuthnEvidencePlanningError("evidence planner transports are not a bounded exact tuple")
        scope_fields, context_fields, root_fields = production._hold_context(scope, verification_context, work)
        owned = _capture(configured, request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={"credentialId": credential_id,
                "transports": transports, "authorization": expected_authorization}, work=work)
        production.registration._same(context_fields[:2], configured[9:11], work,
            "evidence planner RP/origin differs from its configuration")
        # No caller graph is read after this point. The actual core constructors
        # revalidate only held immutable fields, on the same remaining work.
        held_scope = production.attestation.CeremonyScope(*scope_fields, _work=work)
        held_roots = tuple(production.attestation.TrustRootSnapshot(*fields, _work=work)
            for fields in root_fields)
        held_context = production.attestation.VerificationContext(*context_fields, held_roots, _work=work)
        evidence.keys._public_binding(configured[4], configured[6], work)
        # Import the genuine acquisition and registry; no fake import or
        # placeholder kernel can make this boundary succeed.
        from serverware import authority_webauthn_evidence_acquisition as acquisition

        with planning._read_scope(configured[:3], operation=configured[3], work=work) as (cursor, manifest, trace):
            result = acquisition._acquire_registration_evidence_on_work(cursor,
                request=owned["request"], manifest=manifest,
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                envelope_bytes=raw[0], client_data_json=raw[1], attestation_object=raw[2],
                credential_id=owned["inputs"]["credentialId"], transports=owned["inputs"]["transports"],
                scope=held_scope, verification_context=held_context,
                expected_authorization=owned["inputs"]["authorization"],
                public_key=configured[4], expected_signer_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
                expected_signer_spki_digest=configured[6], now_epoch_ns=owned["nowEpochNs"],
                deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=configured[7],
                maximum_clock_skew_ns=configured[8], query_work=work, trace=trace)
        return result

    def acquire_installation(self, *, request, business_before_roots, authorization_before_roots,
            installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, observed_at, now_epoch_ns, deadline_epoch_ns, work):
        configured = self._snapshot(installation.OPERATION)
        evidence.capture._SharedLedger(work)
        raw = (_raw(installation_envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            _raw(installed_bundle_bytes, 2, installation.completion.bundle_core.MAX_INSTALLATION_BYTES),
            _raw(installed_state_bytes, 2, installation.completion.bundle_core.MAX_STATE_BYTES))
        installation.completion._now(observed_at)
        owned = _capture(configured, request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={"stage": expected_committed_stage}, work=work)
        evidence.keys._public_binding(configured[4], configured[6], work)
        from serverware import authority_webauthn_evidence_acquisition as acquisition

        with planning._read_scope(configured[:3], operation=configured[3], work=work) as (cursor, manifest, trace):
            result = acquisition._acquire_installation_evidence_on_work(cursor,
                request=owned["request"], manifest=manifest,
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                installation_envelope_bytes=raw[0], installed_bundle_bytes=raw[1], installed_state_bytes=raw[2],
                installation_target_digest=configured[11], expected_committed_stage=owned["inputs"]["stage"],
                observed_at=observed_at, installer_public_key=configured[4],
                expected_installer_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
                expected_installer_spki_digest=configured[6], now_epoch_ns=owned["nowEpochNs"],
                deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=configured[7],
                maximum_clock_skew_ns=configured[8], query_work=work, trace=trace)
        return result
