"""Lossless original installation inputs for a later genuine admission replay.

This closed codec retains the signed installation envelope, installed bundle
and rollback-state bytes, the original observation instant and the supplied
committed-stage graph. Encoding or decoding does not authenticate any of them.
In particular, a retained stage graph is not proof of a committed transition,
and retained bytes do not establish physical installation or durable readback.

Installer keys, signer identity, target, lifetime/skew, current rows/roots and
fresh admission time are deliberately absent. A replay owner must admit those
independently and repeat the real installation admission over these originals.
No claims-only input, verification token, SQL, filesystem operation, signing,
clock, registry activation or fresh work allowance is provided here.
"""
from __future__ import annotations

from catchplate import authority_transition_webauthn_completion as completion
from catchplate import authority_webauthn_evidence_input_wire as wire


SCHEMA = "catchplate.policyAuthorityWebAuthnInstallationInputs/v1"
OPERATION = "webauthn.trust.installation.admit"
_FIELDS = frozenset({"schema", "sourceRevision", "operation",
    "installationEnvelope", "installedBundle", "installedState",
    "observedAtEpochUs", "expectedCommittedStage"})
_RAW_FIELDS = frozenset({"base64Url", "byteCount"})
_RAW_LIMITS = (
    ("installationEnvelope", completion.evidence.MAX_EVIDENCE_BYTES),
    ("installedBundle", completion.bundle_core.MAX_INSTALLATION_BYTES),
    ("installedState", completion.bundle_core.MAX_STATE_BYTES),
)
_shape = completion.evidence.plan.contract


class WebAuthnInstallationInputsError(ValueError):
    pass


def _stage(value):
    _shape._object(value, completion._STAGE_FIELDS, "retained committed installation stage")
    for field in completion._STAGE_FIELDS - {"witnessSequence"}:
        _shape._digest(value[field])
    _shape._integer(value["witnessSequence"], minimum=1)


def _observed_time(epoch_us):
    observed_at = wire._from_epoch_us(epoch_us)
    # The shared UTC codec admits positive I64 microseconds. Completion has
    # the narrower positive I64 nanosecond contract, which must not widen.
    if completion._now(observed_at) != epoch_us * 1000:
        raise WebAuthnInstallationInputsError("installation observation time did not round-trip")
    return observed_at


def _document_shape(document):
    _shape._object(document, _FIELDS, "retained installation inputs")
    _shape._literal(document["schema"], SCHEMA)
    _shape._literal(document["sourceRevision"], completion.authority.SOURCE_REVISION)
    _shape._literal(document["operation"], OPERATION)
    _stage(document["expectedCommittedStage"])
    observed_at = _observed_time(document["observedAtEpochUs"])
    # Admit all local original bounds before the first base64 decode. The
    # shared decoder separately checks alphabet, padding bits and exact bytes.
    for field, maximum in _RAW_LIMITS:
        value = document[field]
        _shape._object(value, _RAW_FIELDS, "retained installation original")
        _shape._integer(value["byteCount"], maximum, minimum=2)
        if (type(value["base64Url"]) is not str
                or len(value["base64Url"]) != (4 * value["byteCount"] + 2) // 3):
            raise WebAuthnInstallationInputsError("installation original encoding has an invalid length")
    return observed_at


def _encode_on_work(*, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, observed_at, expected_committed_stage, work):
    """Return canonical retention bytes without asserting input admission."""
    try:
        completion.evidence.capture._SharedLedger(work)
        originals = (installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes)
        for raw, (_, maximum) in zip(originals, _RAW_LIMITS):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise WebAuthnInstallationInputsError("installation retention requires bounded original bytes")
        observed_ns = completion._now(observed_at)
        observed_us = wire._to_epoch_us(observed_at)
        if observed_ns != observed_us * 1000:
            raise WebAuthnInstallationInputsError("installation observation time lost precision")
        _stage(expected_committed_stage)
        # This is the only caller-owned mutable graph. Detach it before any
        # actual byte codec; the originals and exact UTC datetime are immutable.
        stage = wire._capture(expected_committed_stage, work)
        _stage(stage)
        packed = {field: wire._pack_raw(raw, minimum=2, maximum=maximum, work=work)
            for raw, (field, maximum) in zip(originals, _RAW_LIMITS)}
        document = {"schema": SCHEMA, "sourceRevision": completion.authority.SOURCE_REVISION,
            "operation": OPERATION, **packed, "observedAtEpochUs": observed_us,
            "expectedCommittedStage": stage}
        _document_shape(document)
        return wire._encode_document(document, work)
    except ValueError as exc:
        if isinstance(exc, WebAuthnInstallationInputsError):
            raise
        raise WebAuthnInstallationInputsError("installation input retention encoding failed") from exc


def _decode_on_work(original_bytes, *, work):
    """Return five ordinary replay inputs, never a successful-proof object."""
    try:
        document = wire._decode_document(original_bytes, work)
        observed_at = _document_shape(document)
        originals = tuple(wire._unpack_raw(document[field], minimum=2, maximum=maximum, work=work)
            for field, maximum in _RAW_LIMITS)
        return {"installation_envelope_bytes": originals[0],
            "installed_bundle_bytes": originals[1], "installed_state_bytes": originals[2],
            "observed_at": observed_at, "expected_committed_stage": document["expectedCommittedStage"]}
    except ValueError as exc:
        if isinstance(exc, WebAuthnInstallationInputsError):
            raise
        raise WebAuthnInstallationInputsError("installation input retention decoding failed") from exc
