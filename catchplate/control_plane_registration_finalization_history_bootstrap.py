"""Optional finalization originals against the parent's existing history archive.

Parent v18 authenticates this finite inventory. It introduces neither another
configuration catalog nor a record-supplied root, and confers no live execution
permission. Historical intervals remain original evidence, not renewed clocks.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_historical_archive as archive
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_enrollment_policy as enrollment_policy
from catchplate import control_plane_registration_finalization_bootstrap as finalization
from catchplate import control_plane_registration_history_bootstrap as registration


SCHEMA = "catchplate.controlPlaneRegistrationFinalizationHistory/v1"
MAX_BYTES = registration.MAX_BYTES
_FIELDS = frozenset({"schema", "finalizations"})
_SCOPE_FIELDS = frozenset({"configurationDigest", "plannerAttestationReceiptDigest",
    "registrationFinalization"})
shape, capture, plan = finalization.shape, finalization.capture, finalization.plan


class RegistrationFinalizationHistoryBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FinalizationHistoryScope:
    configuration_digest: str
    generation_digest: str
    planner_attestation_receipt_digest: str
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    root_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    current_pending: tuple
    completion_packet_digest: str
    completion_authorization_digest: str
    original_bytes: bytes
    caller_public_key: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FinalizationHistoryMaterial:
    archive: archive.HistoryArchive
    registration_history: registration._RegistrationHistoryMaterial
    scopes: tuple
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    original_bytes: bytes


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "registration finalization history")
    shape._literal(value["schema"], SCHEMA)
    scopes = value["finalizations"]
    if type(scopes) is not list or not 1 <= len(scopes) <= archive.MAX_ENTRIES + 1:
        raise RegistrationFinalizationHistoryBootstrapError("finalization history inventory exceeds its fixed bound")
    previous = None
    for selected in scopes:
        shape._object(selected, _SCOPE_FIELDS, "finalization historical operation scope")
        shape._digest(selected["configurationDigest"])
        shape._digest(selected["plannerAttestationReceiptDigest"])
        selector = selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]
        if previous is not None and selector <= previous:
            raise RegistrationFinalizationHistoryBootstrapError("finalization history selectors must be sorted and unique")
        previous = selector
        configured = selected["registrationFinalization"]
        finalization._shape(configured)
        if configured is None or configured["schema"] != finalization.V4_SCHEMA:
            raise RegistrationFinalizationHistoryBootstrapError("finalization history requires exact v4 completion pins")


def _admit_on_work(*, finalization_history, registration_history, work):
    """Admit originals only after the parent authenticates the shared archive."""
    try:
        _shape(finalization_history)
        if finalization_history is None:
            return None
        history = registration_history
        if (type(history) is not registration._RegistrationHistoryMaterial
                or type(history.archive) is not archive.HistoryArchive):
            raise RegistrationFinalizationHistoryBootstrapError("finalization history requires actual registration history")
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work),
            maximum_bytes=MAX_BYTES).visit(finalization_history)
        _shape(owned)
        original = configuration._configuration_wire(owned, capture._SharedLedger(work))
        # Both inventories are already inside the same 4 MiB signed parent.
        # Charge this inventory's retained/decode copies on that same work;
        # no archive is decoded again and no replacement allowance is created.
        work.charge(input_bytes=4 * len(original))
        captured = archive._capture_on_work(history.archive, work=work)
        scopes = []
        for selected in owned["finalizations"]:
            chosen = None
            for record in captured.records:
                work.charge(input_bytes=2 * 71, json_nodes=1)
                if (selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]) == (
                        record.configuration_digest, record.planner_receipt_digest):
                    if chosen is not None:
                        raise RegistrationFinalizationHistoryBootstrapError("finalization history selector is ambiguous")
                    chosen = record
            if chosen is None:
                raise RegistrationFinalizationHistoryBootstrapError("finalization history is absent from the shared archive")
            snapshot = archive._lookup_on_work(captured,
                configuration_digest=chosen.configuration_digest,
                planner_attestation_receipt_digest=chosen.planner_receipt_digest,
                evaluation_epoch_ns=chosen.valid_from_epoch_ns, work=work)
            prior = registration._scope_on_work(history, snapshot=snapshot, work=work)
            issuer = enrollment_policy._capture_on_work(payload=snapshot.payload,
                configuration_digest=snapshot.configuration_digest, generation=snapshot.generation,
                runtime_role_identities=snapshot.runtime_role_identities, work=work)
            # The same archived root and genuine registration caller key are
            # supplied by cold admission, not selected from finalization data.
            # Existing v4 admission verifies original purpose/enrollments,
            # configured transition and key separation, predecessor/pending
            # succession, capacity, packet and authorization digest shapes.
            held = finalization._admit_on_work(
                registration_finalization=selected["registrationFinalization"],
                configuration_payload=snapshot.payload, configuration_digest=snapshot.configuration_digest,
                generation=snapshot.generation, runtime_role_identities=snapshot.runtime_role_identities,
                runtime_root_public_key=prior.root_public_key, issuer_public_key=issuer.issuer_public_key,
                execution_caller_public_key=prior.caller_public_key, work=work)
            scope_raw = configuration._configuration_wire(selected, capture._SharedLedger(work))
            scopes.append(_FinalizationHistoryScope(chosen.configuration_digest, chosen.generation_digest,
                chosen.planner_receipt_digest, chosen.valid_from_epoch_ns, chosen.valid_until_epoch_ns,
                prior.root_public_key, held.current_root_enrollment_bytes, held.grant_enrollment_bytes,
                held.authorization_enrollment_bytes, held.current_pending, held.completion_packet_digest,
                held.completion_authorization_digest, scope_raw, held.caller_public_key))
        plan._same(configuration._configuration_wire(owned, capture._SharedLedger(work)), original, work,
            "finalization history changed during cold admission")
        return _FinalizationHistoryMaterial(history.archive, history, tuple(scopes),
            history.valid_from_epoch_ns, history.valid_until_epoch_ns, original)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationFinalizationHistoryBootstrapError):
            raise
        raise RegistrationFinalizationHistoryBootstrapError("finalization historical cold admission failed") from exc


def _scope_on_work(material, *, snapshot, work):
    """Select independently pinned finalization data, not a replay-success DTO."""
    if (type(material) is not _FinalizationHistoryMaterial
            or type(material.registration_history) is not registration._RegistrationHistoryMaterial
            or material.archive is not material.registration_history.archive
            or type(snapshot) is not archive._HistoricalSnapshot
            or material.valid_from_epoch_ns != material.registration_history.valid_from_epoch_ns
            or material.valid_until_epoch_ns != material.registration_history.valid_until_epoch_ns):
        raise RegistrationFinalizationHistoryBootstrapError("finalization history differs from actual shared registration history")
    prior = registration._scope_on_work(material.registration_history, snapshot=snapshot, work=work)
    if type(material.scopes) is not tuple or not 1 <= len(material.scopes) <= archive.MAX_ENTRIES + 1:
        raise RegistrationFinalizationHistoryBootstrapError("finalization historical scope inventory changed")
    selected = None
    for scope in material.scopes:
        if type(scope) is not _FinalizationHistoryScope:
            raise RegistrationFinalizationHistoryBootstrapError("finalization historical scope type changed")
        work.charge(input_bytes=3 * 71 + 32, json_nodes=1)
        if (scope.configuration_digest, scope.generation_digest, scope.planner_attestation_receipt_digest,
                scope.valid_from_epoch_ns, scope.valid_until_epoch_ns) == (
                prior.configuration_digest, prior.generation_digest, prior.planner_attestation_receipt_digest,
                prior.valid_from_epoch_ns, prior.valid_until_epoch_ns):
            if selected is not None or scope.root_public_key is not prior.root_public_key:
                raise RegistrationFinalizationHistoryBootstrapError("finalization historical selector or shared root differs")
            selected = scope
    if selected is None:
        raise RegistrationFinalizationHistoryBootstrapError("finalization historical operation is not independently configured")
    return selected
