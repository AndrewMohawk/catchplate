"""Private exact-PK acquisition for the two v2 evidence admission operations.

The caller owns the genuine read-only transaction and independently admits the
request, complete source manifest, current business/authorization roots, pins,
ceremony or installed originals and time expectations. This module reads and
joins those roots, proves its actual selected rows, invokes the fixed genuine
semantic adapter and derives the real primary after-roots on the same work.
Neither supplied context data nor the returned observations grant admission.
The held originals are encoded and committed before root/row/proof SQL reads;
their returned bytes are retained data, not a substitute for genuine replay.

These operations have no outbox/capacity state or counted-index profiles. The
actual indexed-primary engine receives an empty head inventory and still runs
its genuine primary evaluator; it performs no counted frontier SQL. Ordinary
PK/proof SQL retains the existing separate physical bounds and callback guards.
There is no new allowance, write SQL, transaction owner, signer, registry
activation, configured service or terminal/durable receipt in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_planner as planner
from serverware import authority_transition_webauthn_registration_admission as registration
from serverware import authority_transition_webauthn_installation_admission as installation
from serverware import authority_webauthn_evidence_input_wire as input_wire
from serverware import authority_webauthn_registration_inputs as registration_inputs
from serverware import authority_webauthn_installation_inputs as installation_inputs


authority, core = planner.authority_contract, planner.authority_transition_core
reads, batch = planner.authority_query_reads, planner.authority_complete_query_batch
evidence, production = registration.evidence, registration.admission.production


class WebAuthnEvidenceAcquisitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _EvidenceAdmissionAcquisition:
    """Actual planning observations, not an admitted request or durable row."""

    request: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    state: planner.PlanningState
    kernel: core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    write_evidence: planner.authority_index_mutation_reader.AcquiredIndexedMutation
    trace: tuple[dict[str, Any], ...]
    business_before_roots: tuple[dict[str, Any], ...]
    authorization_before_roots: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    original_inputs_bytes: bytes
    original_inputs_digest: str


def _source(operation):
    if operation == registration.OPERATION:
        adapter, maximum = registration, 5
    elif operation == installation.OPERATION:
        adapter, maximum = installation, 3
    else:
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition operation is not source fixed")
    spec = authority.operation_spec(operation)
    templates = spec["mutationTemplates"]
    if (tuple(spec["businessWrites"]) != (evidence.EVIDENCE_TABLE,)
            or spec["globalAuditCapacity"] is not False or spec["selectors"]
            or spec["maximumQueryRows"] != maximum or spec["maximumBusinessQueryRows"] != maximum
            or spec["maximumMutations"] != 1 or spec["maximumBusinessMutations"] != 1
            or spec["maximumWorkUnits"] != 128 or spec["maximumBusinessWorkUnits"] != 128
            or len(templates) != 1 or templates[0]["table"] != evidence.EVIDENCE_TABLE
            or templates[0]["mutation"] != "INSERT"
            or planner.authority_index_projection.index_ids_for_table(evidence.EVIDENCE_TABLE)):
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition escaped its exact no-index INSERT contract")
    return adapter, spec


def _capture(operation, *, request, manifest, business_before_roots,
        authorization_before_roots, now_epoch_ns, deadline_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, inputs, query_work):
    """Own every variable graph before either entrypoint can invoke callbacks."""
    batch._SharedLedger(query_work)
    adapter, _ = _source(operation)
    if type(request) is not dict or type(manifest) is not tuple:
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition request/manifest is not exact")
    owned = reads._CopyBudget(query_work).copy({"request": request, "manifest": manifest,
        "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
        "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
        "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns, "inputs": inputs})
    request = owned["request"]
    if (request.get("operation") != operation or request.get("handler") != adapter.HANDLER
            or type(request.get("arguments")) is not dict):
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition request identity changed")
    for name in ("nowEpochNs", "deadlineEpochNs"):
        production.registration._integer(owned[name], name, 1)
    production.registration._integer(owned["maximumAgeNs"], "evidence maximum age", 1,
        authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    production.registration._integer(owned["maximumClockSkewNs"], "evidence clock skew", 0,
        authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition deadline has expired")
    evidence._identity(owned["inputs"]["identity"])
    core.require_digest(owned["inputs"]["signerSpkiDigest"], "evidence admission signer SPKI")
    request_digest = planner._typed_request_digest(request, work=query_work)
    if planner._request_different(request_digest, request.get("requestDigest"), work=query_work):
        raise WebAuthnEvidenceAcquisitionError("evidence admission typed request digest changed")
    query_work.prepare_utf8(operation)
    query_work.prepare_utf8(request_digest)
    query_work.charge(hashes=1)
    actual_operation = planner.operation_id(operation, request_digest)
    if planner._request_different(actual_operation, request.get("operationId"), work=query_work):
        raise WebAuthnEvidenceAcquisitionError("evidence admission operation identity changed")
    return owned


def _raw(value, minimum, maximum):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition requires bounded immutable originals")
    return value


def _acquire_owned(cursor, *, operation, owned, raw, ceremony, public_key, query_work, trace):
    """Fixed dispatch over locally owned inputs; never accept a verifier result."""
    adapter, spec = _source(operation)
    if trace is None:
        trace = planner.PlannerTrace(operation=operation)
    if (type(trace) is not planner.PlannerTrace or trace.operation != operation
            or trace._complete_queries is not False or trace._counted_writes is not False):
        raise WebAuthnEvidenceAcquisitionError("evidence acquisition needs the ordinary source trace")
    acquisition = planner.authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
    try:
        request, inputs = owned["request"], owned["inputs"]
        arguments, request_digest = request["arguments"], request["requestDigest"]
        if operation == registration.OPERATION:
            # All request/root/manifest/pin and ceremony graphs have already
            # been held. Reconstruct from immutable members only; constructors
            # genuinely revalidate on the original meter before any SQL.
            scope_fields, context_fields, root_fields = ceremony
            scope = production.attestation.CeremonyScope(*scope_fields, _work=query_work)
            roots = tuple(production.attestation.TrustRootSnapshot(*fields, _work=query_work)
                for fields in root_fields)
            context = production.attestation.VerificationContext(*context_fields, roots, _work=query_work)
            original_inputs_bytes = registration_inputs._encode_on_work(
                envelope_bytes=raw[0], client_data_json=raw[1], attestation_object=raw[2],
                credential_id=inputs["credentialId"], transports=inputs["transports"],
                scope=scope, verification_context=context,
                expected_authorization=inputs["authorization"], work=query_work)
        else:
            original_inputs_bytes = installation_inputs._encode_on_work(
                installation_envelope_bytes=raw[0], installed_bundle_bytes=raw[1],
                installed_state_bytes=raw[2], observed_at=ceremony,
                expected_committed_stage=inputs["stage"], work=query_work)
        # The codecs own the actual held originals, not caller-supplied record
        # bytes. This framed commitment spends the same remaining allowance
        # before any root, clock, business-row or proof SQL callback.
        original_inputs_digest = input_wire._digest_on_work(original_inputs_bytes, query_work)
        queries = adapter._query_recipe_on_work(arguments=arguments, work=query_work)
        if (any(type(query) is not core.BoundedQuery for query in queries)
                or sum(query.maximum_rows for query in queries) > spec["maximumQueryRows"]):
            raise WebAuthnEvidenceAcquisitionError("evidence admission queries are not exact bounded PK declarations")
        with acquisition.read_phase(cursor, trace, query_work):
            business, authorization, _ = planner._read_root_set(cursor, operation=operation,
                manifest=owned["manifest"], trace=trace, work=query_work)
            planner.authority_revocation_semantics._canonical_equal((business, authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work=query_work,
                label="evidence admission roots differ from independent expectations")
            database_now = planner._read_database_now_on_work(cursor, query_work)
            database_now_ns = production.registration._now(database_now)
            if (abs(database_now_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
                    or database_now_ns >= owned["deadlineEpochNs"]):
                raise WebAuthnEvidenceAcquisitionError("evidence admission database cutoff differs from live expectations")
            # The real staging constructor may initialize the primary empty
            # ladder. Reserve its source allowance here, without a cache or
            # child-budget discount; no deferred selectors are introduced.
            query_work.charge(hashes=authority.TREE_DEPTH + 2)
            staging = planner.authority_query_staging.StagedQueryProofs(operation=operation,
                business_before_roots=business, authorization_before_roots=authorization, query_work=query_work)
            selected, queries, records = planner._read_bounded_transition_rows(cursor,
                operation=operation, request=request, queries=queries, manifest=owned["manifest"],
                trace=trace, query_sources=staging, query_work=query_work)
            pending = staging.unproved_rows(selected)
            proofs = planner._completion_read_callback_on_work(query_work,
                lambda: planner._derive_multiproofs(cursor, selected_rows=pending,
                    roots=business + authorization, trace=trace))
            proofs = staging.merge_proofs(selected_rows=selected, remaining_proofs=proofs)
            ledger = batch._SharedLedger(query_work)
            ledger.charge(hashes=authority.TREE_DEPTH + 2)
            primary_business, primary_authorization = batch._roots(business), batch._roots(authorization)
            memberships = batch.primary.evaluate_primary_radix_memberships(
                table_contracts=planner.authority_primary_contract.primary_table_contracts(operation),
                business_before_roots=primary_business, authorization_before_roots=primary_authorization,
                selected_rows=selected, before_proofs=proofs,
                limits=batch._primary_limits(spec, spec["maximumQueryRows"], ledger))
            metrics = memberships.result.metrics
            ledger.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
            if (memberships.result.business_after_roots != primary_business
                    or memberships.result.authorization_after_roots != primary_authorization
                    or metrics.mutations != 0 or metrics.recomputed_ancestors != 0):
                raise WebAuthnEvidenceAcquisitionError("evidence membership verification changed the before roots")
            selected, proofs = memberships.selected_rows, memberships.before_proofs
            # This existing generic inventory check enforces selected-byte and
            # exact row/key bounds. For these source operations it admits no
            # counter/outbox row and creates no capacity query or mutation.
            planner.authority_audit_capacity._validate_capacity_transition(operation=operation,
                selected_rows=selected, mutations=(), work=query_work)
            _, records = reads._validate_query_reads(operation, queries=queries,
                query_reads=records, selected_rows=selected, work=query_work)
            acquisition.require_idle(cursor, trace, query_work)
        kernel_context = core.KernelContext(operation, arguments, selected,
            database_now, request_digest, query_reads=records)
        if operation == registration.OPERATION:
            kernel = registration._kernel_transition_on_work(kernel_context,
                envelope_bytes=raw[0], client_data_json=raw[1], attestation_object=raw[2],
                credential_id=inputs["credentialId"], transports=inputs["transports"],
                scope=scope, verification_context=context, expected_authorization=inputs["authorization"],
                public_key=public_key, expected_signer_identity=inputs["identity"],
                expected_signer_spki_digest=inputs["signerSpkiDigest"],
                maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"],
                work=query_work)
        else:
            kernel = installation._kernel_transition_on_work(kernel_context,
                installation_envelope_bytes=raw[0], installed_bundle_bytes=raw[1], installed_state_bytes=raw[2],
                installation_target_digest=inputs["target"], expected_committed_stage=inputs["stage"],
                observed_at=ceremony, installer_public_key=public_key,
                expected_installer_identity=inputs["identity"], expected_installer_spki_digest=inputs["signerSpkiDigest"],
                maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"],
                work=query_work)
        query_work.prepare_copy(kernel.mutations)
        mutations = tuple(kernel.mutations)
        if (len(mutations) > 1 or any(item["table"] != evidence.EVIDENCE_TABLE
                or item["operation"] != "INSERT" for item in mutations)):
            raise WebAuthnEvidenceAcquisitionError("evidence admission proposed a non-INSERT business effect")
        work_units = planner.authority_audit_capacity.transition_work_units(operation=operation,
            query_work_units=sum(query.work_units for query in queries),
            kernel_work_units=kernel.work_units, mutations=mutations)
        limits = planner.authority_complete_read_write._write_limits(spec, batch._SharedLedger(query_work))
        writer = planner.authority_index_mutation_reader._AcquisitionBudget(
            shared_acquisition=acquisition, work=query_work)
        write_evidence = planner.authority_index_mutation_reader._acquire_indexed_primary_batch(cursor,
            table_contracts=planner.authority_primary_contract.primary_table_contracts(operation),
            business_before_roots=primary_business, authorization_before_roots=primary_authorization,
            selected_rows=selected, before_proofs=proofs, mutations=mutations,
            index_before_heads=(), limits=limits, trace=trace, acquisition_budget=writer)
        acquisition.require_idle(cursor, trace, query_work)
        for mutation in mutations:
            planner._completion_read_callback_on_work(query_work,
                lambda: trace.write(mutation["table"], mutation["key"]))
        closed_trace = planner._completion_read_callback_on_work(query_work,
            lambda: trace.close(selected_rows=selected, mutation_plan=mutations))
        state = planner.PlanningState(database_now=database_now,
            query_work_units=sum(query.work_units for query in queries), query_program=queries, query_reads=records)
        return _EvidenceAdmissionAcquisition(request, selected, state, kernel, mutations,
            work_units, write_evidence, closed_trace, business, authorization, proofs,
            original_inputs_bytes, original_inputs_digest)
    except BaseException:
        acquisition.failed = True
        raise


def _acquire_registration_evidence_on_work(cursor, *, request, manifest,
        business_before_roots, authorization_before_roots, envelope_bytes,
        client_data_json, attestation_object, credential_id, transports, scope,
        verification_context, expected_authorization, public_key,
        expected_signer_identity, expected_signer_spki_digest, now_epoch_ns,
        deadline_epoch_ns, maximum_age_ns, maximum_clock_skew_ns, query_work, trace=None):
    """Acquire the registration operation from actual originals and held pins."""
    batch._SharedLedger(query_work)
    raw = (_raw(envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
        _raw(client_data_json, 1, production.attestation.MAX_CLIENT_DATA_JSON_BYTES),
        _raw(attestation_object, 1, production.attestation.MAX_ATTESTATION_OBJECT_BYTES))
    if not isinstance(public_key, evidence.keys.Ed25519PublicKey) or type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnEvidenceAcquisitionError("registration admission key/transports are not source bounded")
    held_context = production._hold_context(scope, verification_context, query_work)
    owned = _capture(registration.OPERATION, request=request, manifest=manifest,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        inputs={"authorization": expected_authorization, "identity": expected_signer_identity,
            "signerSpkiDigest": expected_signer_spki_digest, "credentialId": credential_id, "transports": transports},
        query_work=query_work)
    return _acquire_owned(cursor, operation=registration.OPERATION, owned=owned, raw=raw,
        ceremony=held_context, public_key=public_key, query_work=query_work, trace=trace)


def _acquire_installation_evidence_on_work(cursor, *, request, manifest,
        business_before_roots, authorization_before_roots, installation_envelope_bytes,
        installed_bundle_bytes, installed_state_bytes, installation_target_digest,
        expected_committed_stage, observed_at, installer_public_key,
        expected_installer_identity, expected_installer_spki_digest, now_epoch_ns,
        deadline_epoch_ns, maximum_age_ns, maximum_clock_skew_ns, query_work, trace=None):
    """Acquire installation evidence; supplied originals do not prove readback."""
    batch._SharedLedger(query_work)
    raw = (_raw(installation_envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
        _raw(installed_bundle_bytes, 2, installation.completion.bundle_core.MAX_INSTALLATION_BYTES),
        _raw(installed_state_bytes, 2, installation.completion.bundle_core.MAX_STATE_BYTES))
    if not isinstance(installer_public_key, evidence.keys.Ed25519PublicKey):
        raise WebAuthnEvidenceAcquisitionError("installation admission requires its pinned Ed25519 key")
    installation.completion._now(observed_at)
    owned = _capture(installation.OPERATION, request=request, manifest=manifest,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        inputs={"target": installation_target_digest, "stage": expected_committed_stage,
            "identity": expected_installer_identity, "signerSpkiDigest": expected_installer_spki_digest},
        query_work=query_work)
    core.require_digest(owned["inputs"]["target"], "installation admission target")
    return _acquire_owned(cursor, operation=installation.OPERATION, owned=owned, raw=raw,
        ceremony=observed_at, public_key=installer_public_key, query_work=query_work, trace=trace)
