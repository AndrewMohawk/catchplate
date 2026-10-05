"""Original-byte maintenance issuance and durable identifier-only execution.

The inert owners below require independently selected actual database/TLS and
complete source-catalog pins. The configured native connection component admits
those pins and owns every actual resource. The issuer performs genuine raw
grant/pending/page replay once while retaining same-call effect bytes, then
seals only that invocation's completed packet in the SAME SQL transaction.
An error rolls back all tentative steps; no public method accepts a packet,
mutation list, signed-success DTO, callback SQL or completed proof observation.

The executor consumes its actual catalog-bound durable attempt BEFORE opening
the database and accepts only pending/packet identifiers. SQL holds the complete
root chain and unique marker until the single outer commit. The unsigned return
is an observed normal transaction exit, not signed completion or off-host
currentness. Uncertain exits do not authorize retry or undo a burned attempt.

Neither constructor provisions roles/keys/journals or enrolls configuration.
Measured original-FD/configuration selection and downstream postcommit evidence
remain mandatory independent callers. This module opens no new clock or work
allowance and never accepts the cold inputs themselves as launch evidence.
"""
from __future__ import annotations

import os
import threading

from serverware import authority_challenge_execution_connection as connection
from serverware import authority_challenge_execution_contract as contract
from serverware import authority_challenge_execution_packet as packet
from serverware import authority_successor_execution_attempts as attempts
from serverware import authority_successor_execution_owner as existing


admission = packet.admission
plan, authorization, grants = admission.plan, admission.authorization, admission.grants


class ChallengeExecutionOwnerError(RuntimeError):
    pass


def _require(condition):
    if not condition:
        raise ChallengeExecutionOwnerError("maintenance execution owner lost its original custody")


def _configuration(*, role, dsn, connect_timeout_seconds, tls_client_dn,
        tls_client_serial, tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest):
    return existing._configuration((dsn, connect_timeout_seconds, role, tls_client_dn,
        tls_client_serial, tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest), role)


def _enter(owner, expected_type, role):
    _require(type(owner) is expected_type and owner._process == (os.getpid(), threading.get_ident())
        and owner._active is False and owner._failed is False)
    configured = existing._configuration(owner._configured, role)
    owner._active = True

    def held(active_work):
        # Neutral owner check: native and child-stage callbacks may not spend
        # the suspended parent's allowance just to recheck these exact pins.
        plan.evidence.capture._SharedLedger(active_work)
        _require(owner._configured is configured and owner._active is True and owner._failed is False
            and owner._process == (os.getpid(), threading.get_ident()))

    return configured, held


class MaintenanceExecutionIssuer:
    """Process/thread-bound original-only producer; a failed owner is retired."""

    __slots__ = ("_configured", "_process", "_active", "_failed")

    def __init__(self, *, dsn, connect_timeout_seconds, tls_client_dn, tls_client_serial,
            tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest):
        self._configured = _configuration(role=contract.ISSUER_ROLE, dsn=dsn,
            connect_timeout_seconds=connect_timeout_seconds, tls_client_dn=tls_client_dn,
            tls_client_serial=tls_client_serial, tls_issuer_dn=tls_issuer_dn,
            query_manifest_digest=query_manifest_digest,
            expected_structure_manifest_digest=expected_structure_manifest_digest)
        self._process = os.getpid(), threading.get_ident()
        self._active = self._failed = False

    def issue(self, *, originals, expectations, planner_public_key,
            enrollment_bytes, root_public_key, reserve_request_bytes, reserve_receipt_bytes,
            snapshot_bytes, grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
            expected_database_id, expected_generation_digest, expected_pending_sequence,
            expected_pending_head_digest, expected_fence, live_window, read_original, check, work):
        configured, held = _enter(self, MaintenanceExecutionIssuer, contract.ISSUER_ROLE)
        try:
            _require(callable(read_original) and callable(check)
                and type(originals) is tuple and len(originals) == 3)
            # Own every mutable graph before any native SQL/clock/key callback.
            # Exact bytes and immutable scalar scope need no mutable DTO alias.
            expected = plan._expectations(expectations, work)
            _require(expected["context"]["operation"] == contract.OPERATION)
            for raw, maximum in zip(originals, grants.FRAME_MAXIMA, strict=True):
                authorization._original(raw, maximum, "maintenance raw3")
            control_values = (enrollment_bytes, grant_enrollment_bytes, grant_bytes,
                reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
            for raw, (_name, maximum) in zip(control_values, packet.CONTROL_MAXIMA, strict=True):
                authorization._original(raw, maximum, "maintenance original control")
            authorization._public(planner_public_key)
            authorization._public(root_public_key)
            authorization.shape._digest(expected_authorization_digest)
            scope = admission.pending._scope(expected_database_id=expected_database_id,
                expected_generation_digest=expected_generation_digest,
                expected_pending_sequence=expected_pending_sequence,
                expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
                live_window=live_window, transport_deadline_ns=expected["context"]["originalDeadlineNs"])
            pending_digest = authorization._receipt_digest_on_work(reserve_receipt_bytes, work)
            held(work)

            def operation(session):
                def current(stage):
                    _require(type(stage) is admission.streams.compound._Stage)
                    session.check(stage.work)
                    _require(plan.evidence.production._callback(stage.work, lambda: check(stage)) is None)
                    session.check(stage.work)

                def raw_page(parent_digest, manifest_digest, phase, kind, index, ordinal, stage):
                    current(stage)
                    original = read_original(parent_digest, manifest_digest, phase, kind, index, ordinal, stage)
                    current(stage)
                    return original

                def retain(ordinal, raw, descriptor, stage):
                    current(stage)
                    session.retain_step(pending_decision_digest=pending_digest, ordinal=ordinal,
                        body_bytes=raw, descriptor=descriptor, work=stage.work)
                    current(stage)

                # This is the only path to sealing. Neither the public issuer
                # nor the private connection method receives supplied effects.
                prepared = packet._prepare_on_work(originals=originals, expectations=expected,
                    planner_public_key=planner_public_key, enrollment_bytes=enrollment_bytes,
                    root_public_key=root_public_key, reserve_request_bytes=reserve_request_bytes,
                    reserve_receipt_bytes=reserve_receipt_bytes, snapshot_bytes=snapshot_bytes,
                    grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
                    expected_authorization_digest=expected_authorization_digest,
                    expected_database_id=scope[0], expected_generation_digest=scope[1],
                    expected_pending_sequence=scope[2], expected_pending_head_digest=scope[3],
                    expected_fence=scope[4], live_window=scope[5], read_original=raw_page,
                    check=current, retain_effect=retain, work=work)
                held(work)
                _require(type(prepared) is packet._PreparedPacket)
                plan._same(prepared.pending_decision_digest, pending_digest, work)
                session.check(work)
                return session.seal(packet_bytes=prepared.packet_bytes, packet_digest=prepared.packet_digest,
                    pending_decision_digest=pending_digest, issued_at_epoch_ns=prepared.issued_at_epoch_ns,
                    expires_at_epoch_ns=prepared.expires_at_epoch_ns, work=work)

            result = connection._run_on_configuration(configured, purpose="issue", live_window=scope[5],
                original_deadline_ns=scope[6], work=work, operation=operation, check=held)
            held(work)
            _require(type(result) is existing.SuccessorCustodyObservation)
            return result
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = False


class MaintenanceExecutionExecutor:
    """No packet/effect input; durable exact attempt precedes every connection."""

    __slots__ = ("_configured", "_process", "_active", "_failed", "_attempts")

    def __init__(self, *, dsn, connect_timeout_seconds, tls_client_dn, tls_client_serial,
            tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest, attempt_owner):
        self._configured = _configuration(role=contract.EXECUTOR_ROLE, dsn=dsn,
            connect_timeout_seconds=connect_timeout_seconds, tls_client_dn=tls_client_dn,
            tls_client_serial=tls_client_serial, tls_issuer_dn=tls_issuer_dn,
            query_manifest_digest=query_manifest_digest,
            expected_structure_manifest_digest=expected_structure_manifest_digest)
        _require(type(attempt_owner) is attempts.SuccessorExecutionAttempts
            and attempt_owner.structure_manifest_digest == self._configured[7])
        self._attempts = attempt_owner
        self._process = os.getpid(), threading.get_ident()
        self._active = self._failed = False

    def execute(self, *, pending_decision_digest, packet_digest, live_window,
            original_deadline_ns, work):
        configured, held = _enter(self, MaintenanceExecutionExecutor, contract.EXECUTOR_ROLE)
        try:
            owner = self._attempts
            _require(type(owner) is attempts.SuccessorExecutionAttempts
                and owner.structure_manifest_digest == configured[7])
            authorization.shape._digest(pending_decision_digest)
            authorization.shape._digest(packet_digest)
            window, bound = existing._window(live_window, original_deadline_ns)
            for identity in (pending_decision_digest, packet_digest):
                work.prepare_utf8(identity)
            attempts.SuccessorExecutionAttempts._claim_on_work(owner,
                pending_decision_digest=pending_decision_digest, packet_digest=packet_digest,
                live_window=window, work=work, transport_deadline_ns=bound)

            def current(active_work):
                held(active_work)
                _require(self._attempts is owner and owner.structure_manifest_digest == configured[7])

            def operation(session):
                return session.execute(pending_decision_digest=pending_decision_digest,
                    packet_digest=packet_digest, work=work)

            current(work)
            result = connection._run_on_configuration(configured, purpose="execute", live_window=window,
                original_deadline_ns=bound, work=work, operation=operation, check=current)
            current(work)
            _require(type(result) is existing.SuccessorExecutionObservation)
            return result
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = False
