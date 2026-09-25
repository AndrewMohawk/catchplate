"""Fixed original-byte request and response codec for registration evidence.

The request retains the source exchange's original four bodies, the original
enrollment grant, both original browser byte strings and canonical metadata.
Metadata is transport data, not enrollment, source, time or signing authority.
The genuine signer and receiving consumer must authenticate the grant/source
and bind every original on their same work before using them.

Responses contain only the original evidence envelope and retained inputs.
No finalization arguments, sibling selection, caller identity, root, policy or
key override is transported. Bounds neither authenticate a response nor grant
business finalization, retry, custody or execution authority. No socket, clock,
signature, database or replacement work allowance is introduced here.
"""
from __future__ import annotations

from serverware import authority_webauthn_enrollment_authorization as enrollment
from serverware import authority_webauthn_evidence_input_wire as input_wire
from serverware import authority_webauthn_registration_source_request as source_request
from serverware import authority_webauthn_registration_source_response as source_response
from serverware import webauthn_attestation_core as attestation


evidence, authority = input_wire.evidence, source_request.authority
SCHEMA = "serverware.policyAuthorityWebAuthnRegistrationSignerRequest/v1"
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_METADATA_BYTES = attestation.MAX_AUTHORIZATION_BYTES
MAX_METADATA_NODES = evidence.MAX_EVIDENCE_NODES
MAX_METADATA_DEPTH = evidence.MAX_EVIDENCE_DEPTH
REQUEST_LIMITS = (source_request.MAX_CONTROL_BYTES, source_request.MAX_CONTEXT_BYTES,
    source_response.MAX_CONTROL_BYTES, source_response.MAX_SOURCE_BYTES,
    enrollment.MAX_BYTES, attestation.MAX_CLIENT_DATA_JSON_BYTES,
    attestation.MAX_ATTESTATION_OBJECT_BYTES, MAX_METADATA_BYTES)
REQUEST_MINIMUMS = (2, 2, 2, 2, 2, 1, 1, 2)
RESPONSE_LIMITS = (evidence.MAX_EVIDENCE_BYTES, input_wire.MAX_BYTES)
RESPONSE_MINIMUMS = (2, 2)
_FIELDS = frozenset({"schema", "sourceRevision", "credentialId", "transports", "verifiedAtEpochNs"})


class WebAuthnRegistrationSignerWireError(ValueError):
    pass


def _lengths(lengths, limits, minimums):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not minimum <= size <= maximum
                for size, minimum, maximum in zip(lengths, minimums, limits))
            or sum(lengths) > MAX_BYTES):
        raise WebAuthnRegistrationSignerWireError("registration signer body lengths exceed their fixed bounds")


def _request_lengths(lengths):
    """Validate all eight lengths before any request body allocation."""
    _lengths(lengths, REQUEST_LIMITS, REQUEST_MINIMUMS)


def _response_lengths(lengths):
    """Validate both lengths before any response body allocation."""
    _lengths(lengths, RESPONSE_LIMITS, RESPONSE_MINIMUMS)


def _originals(values, limits, minimums):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise WebAuthnRegistrationSignerWireError("registration signer bodies are not exact immutable originals")
    _lengths(tuple(len(raw) for raw in values), limits, minimums)
    return values


def _request_originals(originals):
    """Bound the fixed raw eight without decoding or authenticating them."""
    held = _originals(originals, REQUEST_LIMITS, REQUEST_MINIMUMS)
    source_request._raw2(held[0], held[1])
    source_response._raw2(held[2], held[3])
    return held


def _response_originals(originals):
    """Bound raw envelope/inputs; their genuine verification is downstream."""
    return _originals(originals, RESPONSE_LIMITS, RESPONSE_MINIMUMS)


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_METADATA_DEPTH or self.nodes >= MAX_METADATA_NODES:
            raise WebAuthnRegistrationSignerWireError("registration signer metadata exceeds its structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_METADATA_NODES:
            raise WebAuthnRegistrationSignerWireError("registration signer metadata exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=MAX_METADATA_BYTES).visit(value)


def _shape(value, work):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS, "registration signer metadata")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    # Preserve the actual existing original-input text and transport bounds,
    # including empty transport labels accepted by the browser input codec.
    attestation._text(value["credentialId"], "signer credential ID", 2048, _work=work)
    shape._array(value["transports"], 16, "registration signer transports")
    for transport in value["transports"]:
        attestation._text(transport, "signer transport", 2048, empty=True, _work=work)
    instant = value["verifiedAtEpochNs"]
    shape._integer(instant, 2**63 - 1, minimum=1)
    if instant % 1000:
        raise WebAuthnRegistrationSignerWireError("registration signer time is not exactly representable in microseconds")


def _produce_request_on_work(*, source_originals, enrollment_authorization_bytes,
        client_data_json, attestation_object, credential_id, transports, verified_at, work):
    """Preserve raw originals and encode privately owned metadata on work."""
    ledger = evidence.capture._SharedLedger(work)
    if type(source_originals) is not tuple or len(source_originals) != 4:
        raise WebAuthnRegistrationSignerWireError("registration signing requires the exact original source four")
    source = (source_request._raw2(source_originals[0], source_originals[1])
        + source_response._raw2(source_originals[2], source_originals[3]))
    held = _originals(source + (enrollment_authorization_bytes, client_data_json, attestation_object),
        REQUEST_LIMITS[:-1], REQUEST_MINIMUMS[:-1])
    if sum(len(raw) for raw in held) + REQUEST_MINIMUMS[-1] > MAX_BYTES:
        raise WebAuthnRegistrationSignerWireError("registration signer originals leave no metadata capacity")
    if type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnRegistrationSignerWireError("registration signer transports are not a bounded exact tuple")
    instant = verified_at
    work.prepare_copy(transports)
    metadata = _capture({"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "credentialId": credential_id, "transports": list(transports),
        "verifiedAtEpochNs": input_wire._to_epoch_us(instant) * 1000}, work)
    _shape(metadata, work)
    original_metadata = evidence.capability._wire(metadata, ledger,
        MAX_METADATA_BYTES, MAX_METADATA_NODES)
    return _request_originals(held + (original_metadata,))


def _decode_request_on_work(originals, *, work):
    """Return owned metadata only; no body becomes authenticated here."""
    ledger = evidence.capture._SharedLedger(work)
    held = _request_originals(originals)
    original_metadata = held[7]
    decoded = evidence.wire._decode_object(original_metadata, work=work,
        maximum_bytes=MAX_METADATA_BYTES, maximum_nodes=MAX_METADATA_NODES,
        maximum_depth=MAX_METADATA_DEPTH)
    metadata = _capture(decoded, work)
    _shape(metadata, work)
    evidence.capability._canonical(original_metadata, metadata, ledger,
        MAX_METADATA_BYTES, MAX_METADATA_NODES)
    nanoseconds = metadata["verifiedAtEpochNs"]
    instant = input_wire._from_epoch_us(nanoseconds // 1000)
    if input_wire._to_epoch_us(instant) * 1000 != nanoseconds:
        raise WebAuthnRegistrationSignerWireError("registration signer time did not round-trip exactly")
    work.prepare_copy(metadata["transports"])
    return metadata["credentialId"], tuple(metadata["transports"]), instant
