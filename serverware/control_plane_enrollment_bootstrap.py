"""Root-authorized, bounded cold bootstrap for the dedicated enrollment issuer.

This is an explicit additional purpose for the independently admitted runtime
root. The message is the ASCII result of the existing framed digest over the
canonical payload, under SCHEMA below; it is deliberately not the runtime
trust document's domain_digest protocol. A genuine signature over the original
canonical envelope precedes configuration, runtime-role and descriptor admission.
The embedded observations alone do not establish root or enclave provenance.

Both entrypoints use only the supplied work. The producer is for an independent
provisioner; it creates no key or descriptor. Admission returns privately owned
ordinary data, not a token accepted as proof by other components. The actual
trusted-host-local cold owner must admit the signed descriptor and real private
key against the returned issuer public pin. No descriptor, database, application,
clock, transport or replacement allowance is opened here.
"""
from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_writer_acknowledgment as keys
from serverware import authority_webauthn_enrollment_policy as enrollment_policy


capability = configuration.capability
capture, wire, plan, production = capability.capture, capability.wire, capability.plan, configuration.production
# v2 adds mandatory root-admitted endpoint authority. Do not silently accept
# a v1 payload under this exact shape, even with a current source revision.
SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v2"
PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v2"
V3_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v3"
V3_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v3"
V4_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v4"
V4_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v4"
MAX_BYTES = authority.MAX_REQUEST_BYTES
MAX_NODES = capture.MAX_TOTAL_JSON_NODES
MAX_DEPTH = capture.MAX_JSON_DEPTH
SIGNER_SOCKET_PATH = "/run/serverware/registration-evidence/signer.sock"
SIGNER_LISTENER_UID = SIGNER_LISTENER_GID = 0
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest",
    "configurationPayload", "generation", "runtimeRoleIdentities", "issuerPrivateKeyFd", "signerEndpoint"})
_V3_PAYLOAD_FIELDS = _PAYLOAD_FIELDS | frozenset({"registrationExecution"})
_V4_PAYLOAD_FIELDS = _V3_PAYLOAD_FIELDS | frozenset({"registrationFinalization"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_GENERATION_FIELDS = frozenset(configuration._GENERATION_FIELDS)
_NUMBER_BYTES = frozenset(b"0123456789.eE+-")


class EnrollmentBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _EnrollmentMaterial:
    """Owned cold inputs; construction alone proves no bootstrap admission."""

    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    issuer_private_key_fd: int | None
    issuer_policy: dict | None
    issuer_public_key: object | None
    signer_endpoint: tuple | None
    execution: object | None = None
    finalization: object | None = None
    finalization_slot_reserved: bool = False


def _preflight(raw, work):
    """Reserve parsing with the existing lossless lexical rules plus floats.

    The service configuration permits finite fractional timeouts. Only this
    local configuration-containing wire admits float tokens; retained proof
    and control decoders remain integer-only. No input-sized token collection
    or graph is allocated before the original-work reservation.
    """
    work.charge(input_bytes=len(raw))
    remaining_nodes = work.limits.max_json_nodes - work.json_nodes
    position = nodes = objects = pairs = 0
    stack = []

    def check():
        if nodes > MAX_NODES or nodes + objects + 2 * pairs > remaining_nodes:
            raise EnrollmentBootstrapError("bootstrap parser exceeds remaining node work")

    while position < len(raw):
        point = raw[position]
        if point in (32, 9, 10, 13, 44):
            position += 1
            continue
        if point == 58:
            pairs += 1
            check()
            position += 1
            continue
        if point in (93, 125):
            if not stack or stack.pop() != point:
                raise EnrollmentBootstrapError("bootstrap JSON delimiters do not match")
            position += 1
            continue
        if len(stack) > MAX_DEPTH:
            raise EnrollmentBootstrapError("bootstrap JSON exceeds its source depth")
        nodes += 1
        objects += int(point == 123)
        check()
        if point in (91, 123):
            stack.append(93 if point == 91 else 125)
            position += 1
        elif point == 34:
            position = wire._string_end(raw, position)
        elif point == 45 or 48 <= point <= 57:
            start = position
            while position < len(raw) and raw[position] in _NUMBER_BYTES:
                position += 1
                if position - start > wire._MAX_INTEGER_DIGITS + 1:
                    raise EnrollmentBootstrapError("bootstrap numeric token exceeds its source bound")
        elif raw.startswith(b"true", position):
            position += 4
        elif raw.startswith(b"false", position):
            position += 5
        elif raw.startswith(b"null", position):
            position += 4
        else:
            raise EnrollmentBootstrapError("bootstrap JSON token is not supported")
    if stack:
        raise EnrollmentBootstrapError("bootstrap JSON delimiters are incomplete")
    return nodes, objects + 2 * pairs


def _float(token):
    # Every canonical finite Python float spelling is shorter than this fixed
    # bound. Longer/noncanonical transports cannot match the signed original.
    if len(token) > 64:
        raise EnrollmentBootstrapError("bootstrap float token exceeds its canonical bound")
    value = float(token)
    if not math.isfinite(value):
        raise EnrollmentBootstrapError("bootstrap configuration float is not finite")
    return value


def _decode(raw, work):
    nodes, hook_nodes = _preflight(raw, work)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hook_nodes)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=wire._unique_object,
        parse_int=wire._parse_integer, parse_float=_float, parse_constant=wire._reject_number)
    return configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES).visit(value)


def _payload_shape(value):
    shape = capability.shape
    shape._object(value, _PAYLOAD_FIELDS, "enrollment bootstrap payload")
    shape._literal(value["schema"], PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("bootstrap configuration and runtime identities are not exact objects")


def _shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _payload_shape(value["payload"])


def _v3_payload_shape(value):
    from serverware import control_plane_registration_execution_bootstrap as execution

    shape = capability.shape
    shape._object(value, _V3_PAYLOAD_FIELDS, "v3 enrollment bootstrap payload")
    shape._literal(value["schema"], V3_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "v3 enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("v3 bootstrap configuration and runtime identities are not exact objects")
    execution._shape(value["registrationExecution"])
    if value["registrationExecution"] is not None:
        shape._integer(value["issuerPrivateKeyFd"], 1023, minimum=32)
        if value["issuerPrivateKeyFd"] == execution.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("enrollment and execution caller key descriptors must differ")


def _v3_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v3 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V3_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v3_payload_shape(value["payload"])


def _v4_payload_shape(value):
    from serverware import control_plane_registration_execution_bootstrap as execution
    from serverware import control_plane_registration_finalization_bootstrap as finalization

    shape = capability.shape
    shape._object(value, _V4_PAYLOAD_FIELDS, "v4 enrollment bootstrap payload")
    shape._literal(value["schema"], V4_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "v4 enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("v4 bootstrap configuration and runtime identities are not exact objects")
    execution._shape(value["registrationExecution"])
    finalization._shape(value["registrationFinalization"])
    descriptor = value["issuerPrivateKeyFd"]
    if descriptor is not None:
        shape._integer(descriptor, 1023, minimum=32)
        if descriptor == finalization.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("v4 reserves the finalization caller key descriptor")
    if value["registrationExecution"] is not None:
        shape._integer(descriptor, 1023, minimum=32)
        if descriptor == execution.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("enrollment and execution caller key descriptors must differ")
    if value["registrationFinalization"] is not None:
        shape._integer(descriptor, 1023, minimum=32)


def _v4_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v4 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V4_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v4_payload_shape(value["payload"])


def _canonical(raw, value, work):
    encoded = configuration._configuration_wire(value, capture._SharedLedger(work))
    work.charge(input_bytes=len(raw) + len(encoded))
    if encoded != raw:
        raise EnrollmentBootstrapError("bootstrap original bytes are not canonical or changed during admission")
    return encoded


def _signer_endpoint(value):
    """Fixed activation-peer binding, never child signer identity admission."""
    shape = capability.shape
    shape._object(value, _ENDPOINT_FIELDS, "enrollment signer endpoint")
    path, timeout = value["socketPath"], value["requestTimeoutSeconds"]
    uid, gid = value["listenerUid"], value["listenerGid"]
    shape._literal(path, SIGNER_SOCKET_PATH)
    for observed, expected in ((uid, SIGNER_LISTENER_UID), (gid, SIGNER_LISTENER_GID)):
        shape._integer(observed, 2**32 - 2)
        if observed != expected:
            raise EnrollmentBootstrapError("signer activated-listener peer differs from its fixed root identity")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0.05 <= timeout <= 30):
        raise EnrollmentBootstrapError("signer endpoint request timeout exceeds its service bound")
    # SO_PEERCRED binds the system manager's listen() identity, not the later
    # accepting process. The evidence signature/policy binds the actual signer.
    return path, timeout, uid, gid


def _material(payload, expected_digest, work):
    """Consistency only; the calling entrypoint supplies root provenance."""
    configured, generation = payload["configurationPayload"], payload["generation"]
    runtime, digest, descriptor = (payload["runtimeRoleIdentities"],
        payload["configurationDigest"], payload["issuerPrivateKeyFd"])
    endpoint = payload["signerEndpoint"]
    plan._same(digest, expected_digest, work, "bootstrap configuration differs from admitted runtime trust")
    if configured.get(enrollment_policy.FIELD) is None:
        if descriptor is not None or endpoint is not None:
            raise EnrollmentBootstrapError("disabled enrollment requires absent issuer key and signer endpoint")
        owned, launch = configuration._capture_configuration_on_work(payload=configured,
            configuration_digest=digest, generation=generation, work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime, owned_payload=owned,
            configuration_digest=digest, launch=launch, work=work)
        return _EnrollmentMaterial(owned, launch, identities, digest, None, None, None, None)
    capability.shape._integer(descriptor, 1023, minimum=32)
    held_endpoint = _signer_endpoint(endpoint)
    settings = enrollment_policy._capture_on_work(payload=configured,
        configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
    # The actual mapper has re-owned and checked all three graphs, the source
    # allowlist/manifest, dedicated issuer/audience and genuine raw32/SPKI keys.
    # These original owned graphs are retained, not an overlay of role pins.
    return _EnrollmentMaterial(configured, generation, runtime, digest, descriptor,
        settings.policy, settings.issuer_public_key, held_endpoint)


def _v3_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_registration_execution_bootstrap as execution

    material = _material(payload, expected_digest, work)
    held_execution = execution._admit_on_work(
        registration_execution=payload["registrationExecution"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, issuer_public_key=material.issuer_public_key,
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, held_execution)


def _v4_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_registration_finalization_bootstrap as finalization

    material = _v3_material(payload, expected_digest, root_public_key, work)
    held_finalization = finalization._admit_on_work(
        registration_finalization=payload["registrationFinalization"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, issuer_public_key=material.issuer_public_key,
        execution_caller_public_key=(None if material.execution is None
            else material.execution.caller_public_key), work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, held_finalization, True)


def _admit_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, work):
    """Authenticate exact originals before using their configuration or FD."""
    try:
        capture._SharedLedger(work)
        original, key, expected = bootstrap_bytes, runtime_root_public_key, expected_configuration_digest
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            raise EnrollmentBootstrapError("bootstrap originals exceed their exact byte bound")
        if not isinstance(key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("bootstrap requires the independently admitted Ed25519 runtime root")
        capability.shape._digest(expected)
        envelope = _decode(original, work)
        is_v3 = type(envelope) is dict and envelope.get("schema") == V3_SCHEMA
        is_v4 = type(envelope) is dict and envelope.get("schema") == V4_SCHEMA
        if is_v4:
            _v4_shape(envelope)
        elif is_v3:
            _v3_shape(envelope)
        else:
            _shape(envelope)
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        payload_bytes = configuration._configuration_wire(payload, capture._SharedLedger(work))
        capability._signature(key, envelope["signatureBase64Url"],
            V4_SCHEMA if is_v4 else V3_SCHEMA if is_v3 else SCHEMA,
            payload_bytes, capture._SharedLedger(work))
        _canonical(original, envelope, work)
        material = (_v4_material(payload, expected, key, work) if is_v4
            else _v3_material(payload, expected, key, work) if is_v3
            else _material(payload, expected, work))
        _canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("enrollment bootstrap admission failed") from exc


def _measure(value, work):
    measured = configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, retain=False)
    measured.visit(value)
    if measured.nodes > MAX_NODES:
        raise EnrollmentBootstrapError("bootstrap output exceeds its source node bound")
    return measured.bytes, measured.nodes


def _encode(value):
    # Every call is preceded by an actual configuration measurement and
    # reservation; unlike proof canonicalization this preserves finite floats.
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")


def _produce_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, runtime_root_private_key,
        runtime_root_public_key, work):
    """Produce a dedicated root statement for an independent provisioner."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint})
        _payload_shape(payload)
        envelope = {"schema": SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _shape(envelope)
        # Capture and canonicalize before every key/hash callback. Keep these
        # exact bytes through policy admission, pairing and native signing.
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _material(payload, digest, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        # Reserve post-native encoding+comparison, signature transport and
        # final envelope encoding before signing can occur. The real later
        # measurement stays separately charged and must fit before callback.
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        # Measurement itself still charges the original work; the encoding and
        # complete byte comparison were reserved above, never a fresh budget.
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("enrollment bootstrap production failed") from exc


def _produce_v3_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        runtime_root_private_key, runtime_root_public_key, work):
    """Produce opt-in v3 originals without changing the evidence-only v2 producer."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v3 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v3 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V3_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution})
        _v3_payload_shape(payload)
        envelope = {"schema": V3_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v3_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v3_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V3_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v3 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V3_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v3 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v3 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v3 enrollment bootstrap production failed") from exc


def _produce_v4_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, runtime_root_private_key, runtime_root_public_key, work):
    """Produce explicit v4 originals; never create or provision either caller key."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v4 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v4 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V4_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization})
        _v4_payload_shape(payload)
        envelope = {"schema": V4_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v4_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v4_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V4_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v4 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V4_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v4 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v4 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v4 enrollment bootstrap production failed") from exc
