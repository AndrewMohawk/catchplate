"""Optional registration-only cold history, authenticated by parent v17.

The existing signed historical archive remains the sole configuration catalog.
Operation enrollments and completion pins are independently configured alongside
that archive, never taken from the retained operation being inspected.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_historical_archive as archive
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import control_plane_registration_execution_bootstrap as execution


SCHEMA = "serverware.controlPlaneRegistrationHistory/v1"
MAX_BYTES = archive.MAX_BYTES
_FIELDS = frozenset({"schema", "currentEntry", "archive", "registrations"})
_SCOPE_FIELDS = frozenset({"configurationDigest", "plannerAttestationReceiptDigest",
    "registrationExecution"})
shape, capture, plan = execution.shape, execution.capture, execution.plan


class RegistrationHistoryBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RegistrationHistoryScope:
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
    original_bytes: bytes


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RegistrationHistoryMaterial:
    archive: archive.HistoryArchive
    scopes: tuple
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    original_bytes: bytes


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "registration history")
    shape._literal(value["schema"], SCHEMA)
    shape._object(value["currentEntry"], frozenset(archive._ENTRY_FIELDS),
        "registration history current provenance")
    original = value["archive"]
    shape._object(original, execution._ORIGINAL_FIELDS, "registration historical archive original")
    execution.caller.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], MAX_BYTES)
    scopes = value["registrations"]
    if type(scopes) is not list or not 1 <= len(scopes) <= archive.MAX_ENTRIES + 1:
        raise RegistrationHistoryBootstrapError("registration history inventory is outside its fixed bound")
    previous = None
    for selected in scopes:
        shape._object(selected, _SCOPE_FIELDS, "registration historical operation scope")
        shape._digest(selected["configurationDigest"])
        shape._digest(selected["plannerAttestationReceiptDigest"])
        selector = selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]
        if previous is not None and selector <= previous:
            raise RegistrationHistoryBootstrapError("registration history selectors must be sorted and unique")
        previous = selector
        execution._shape(selected["registrationExecution"])
        if (selected["registrationExecution"] is None
                or selected["registrationExecution"]["schema"] != execution.V3_SCHEMA):
            raise RegistrationHistoryBootstrapError("registration history requires exact execution v3 completion pins")


def _thaw(record, work):
    thaw = archive._Thaw(capture._SharedLedger(work), maximum_bytes=MAX_BYTES)
    return archive._HistoricalSnapshot(thaw.visit(record.payload), record.configuration_digest,
        thaw.visit(record.generation), thaw.visit(record.runtime_role_identities),
        record.valid_from_epoch_ns, record.valid_until_epoch_ns)


def _root(entry, work):
    work.charge(input_bytes=128)
    raw = archive.artifact.strict_base64url_decode(
        entry["configurationRootPublicKeyBase64Url"], name="registration historical root", decoded_size=32)
    # Called only after genuine current-entry or whole-archive authentication.
    return configuration.production._callback(work, lambda: Ed25519PublicKey.from_public_bytes(raw))


def _same_graph(actual, expected, work, label):
    left = configuration._configuration_wire(actual, capture._SharedLedger(work))
    right = configuration._configuration_wire(expected, capture._SharedLedger(work))
    plan._same(left, right, work, label)


def _admit_on_work(*, registration_history, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        current_interval, now_epoch_ns, work):
    """Startup only: parent root admission precedes this nested admission."""
    try:
        _shape(registration_history)
        if registration_history is None:
            return None
        if type(current_interval) is not tuple or len(current_interval) != 2:
            raise RegistrationHistoryBootstrapError("history requires the actual startup receipt interval")
        binding_start, binding_end = archive._interval(*current_interval)
        now = archive.cohort._positive(now_epoch_ns, "registration history current time")
        if not binding_start <= now < binding_end:
            raise RegistrationHistoryBootstrapError("registration history startup receipt is not current")
        execution.caller.authorization._public(runtime_root_public_key)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work),
            maximum_bytes=MAX_BYTES).visit(registration_history)
        _shape(owned)
        original = configuration._configuration_wire(owned, capture._SharedLedger(work))
        # Reserve finite startup archive read/decode/freeze representations on
        # the existing work before its non-metered, source-fixed startup API.
        # The enclosing parent and this entire nested original each retain the
        # same 4 MiB ceiling; this is not another request or heap allowance.
        work.charge(input_bytes=8 * len(original))
        current_record = configuration.production._callback(work,
            lambda: archive._entry(owned["currentEntry"]))
        current = _thaw(current_record, work)
        plan._same(current.configuration_digest, configuration_digest, work,
            "history current configuration differs from independent parent")
        _same_graph(current.payload, configuration_payload, work, "history current configuration payload")
        _same_graph(current.generation, generation, work, "history current generation")
        _same_graph(current.runtime_role_identities, runtime_role_identities, work,
            "history current attestation cohort")
        current_root = _root(owned["currentEntry"], work)
        plan._same(execution.caller.keys._spki_on_work(current_root, work),
            execution.caller.keys._spki_on_work(runtime_root_public_key, work), work,
            "history current root differs from independent runtime root")
        carrier = owned["archive"]
        archive_raw = execution.caller.authorization.transport._decode(
            carrier["base64Url"], carrier["byteCount"], MAX_BYTES, work)
        admitted = configuration.production._callback(work, lambda: archive._admit_on_startup(
            original_bytes=archive_raw, current_snapshot=current,
            current_root_public_key=runtime_root_public_key, now_epoch_ns=now))
        start = max(admitted.valid_from_epoch_ns, binding_start)
        end = min(admitted.valid_until_epoch_ns, binding_end)
        if not start <= now < end:
            raise RegistrationHistoryBootstrapError("registration history has no current independent intersection")
        # Decode only the already authenticated exact archive original. Root
        # bytes from these entries are retained for original signature replay,
        # not installed as current roots or taken from journal records.
        archive_document = configuration.production._callback(work,
            lambda: archive._canonical_document(archive_raw))
        entries = (owned["currentEntry"], *archive_document["payload"]["entries"])
        if len(entries) != len(admitted.records):
            raise RegistrationHistoryBootstrapError("historical root inventory differs from admitted archive")
        scopes = []
        for selected in owned["registrations"]:
            selector = selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]
            chosen = None
            for record, entry in zip(admitted.records, entries):
                work.charge(input_bytes=2 * 71, json_nodes=1)
                if selector == (record.configuration_digest, record.planner_receipt_digest):
                    if chosen is not None:
                        raise RegistrationHistoryBootstrapError("registration historical scope is ambiguous")
                    chosen = record, entry
            if chosen is None:
                raise RegistrationHistoryBootstrapError("registration historical scope is absent from admitted archive")
            record, entry = chosen
            historical = _thaw(record, work)
            old_root = _root(entry, work)
            issuer = enrollment_policy._capture_on_work(payload=historical.payload,
                configuration_digest=historical.configuration_digest, generation=historical.generation,
                runtime_role_identities=historical.runtime_role_identities, work=work)
            # This genuine original enrollment admission checks signatures,
            # purpose, generation, keys and predecessor/pending capacity. It
            # has no live wallclock-expiry bypass. Original control times are
            # still verified by the request's historical replay afterwards.
            held = execution._admit_on_work(registration_execution=selected["registrationExecution"],
                configuration_payload=historical.payload, configuration_digest=historical.configuration_digest,
                generation=historical.generation, runtime_role_identities=historical.runtime_role_identities,
                runtime_root_public_key=old_root, issuer_public_key=issuer.issuer_public_key, work=work)
            scope_raw = configuration._configuration_wire(selected, capture._SharedLedger(work))
            scopes.append(_RegistrationHistoryScope(record.configuration_digest, record.generation_digest,
                record.planner_receipt_digest, record.valid_from_epoch_ns, record.valid_until_epoch_ns,
                old_root, held.current_root_enrollment_bytes, held.grant_enrollment_bytes,
                held.authorization_enrollment_bytes, held.current_pending, held.completion_packet_digest,
                scope_raw))
        plan._same(configuration._configuration_wire(owned, capture._SharedLedger(work)), original, work,
            "registration history changed during cold admission")
        return _RegistrationHistoryMaterial(admitted, tuple(scopes), start, end, original)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationHistoryBootstrapError):
            raise
        raise RegistrationHistoryBootstrapError("registration historical cold admission failed") from exc


def _scope_on_work(material, *, snapshot, work):
    """Resolve only a cold-admitted operation scope; not a replay-success token."""
    if (type(material) is not _RegistrationHistoryMaterial
            or type(material.archive) is not archive.HistoryArchive
            or type(snapshot) is not archive._HistoricalSnapshot):
        raise RegistrationHistoryBootstrapError("registration history requires actual local material and snapshot")
    selector = (snapshot.configuration_digest, snapshot.generation["digest"],
        snapshot.runtime_role_identities["roles"]["planner"]["attestationReceiptDigest"],
        snapshot.valid_from_epoch_ns, snapshot.valid_until_epoch_ns)
    capture._JSONCapture(capture._SharedLedger(work), maximum_bytes=1024).visit(list(selector))
    selected = None
    if type(material.scopes) is not tuple or not 1 <= len(material.scopes) <= archive.MAX_ENTRIES + 1:
        raise RegistrationHistoryBootstrapError("registration history scope inventory changed")
    for scope in material.scopes:
        if type(scope) is not _RegistrationHistoryScope:
            raise RegistrationHistoryBootstrapError("registration history scope type changed")
        work.charge(input_bytes=3 * 71 + 32, json_nodes=1)
        if selector == (scope.configuration_digest, scope.generation_digest,
                scope.planner_attestation_receipt_digest, scope.valid_from_epoch_ns, scope.valid_until_epoch_ns):
            if selected is not None:
                raise RegistrationHistoryBootstrapError("registration historical selection is ambiguous")
            selected = scope
    if selected is None:
        raise RegistrationHistoryBootstrapError("registration historical operation is not independently configured")
    return selected
