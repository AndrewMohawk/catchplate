"""Private configured issuer composition for original revocation bytes.

This owner uses only the real capability-issuer connector, never a caller DSN
or planner-writer role. Configuration pins existing independently admitted
keys and identities; it does not enroll them. The verifier's public key and
identity also authenticate the service's capability and witness-request signer.
There is no issuer signing key, public route or new witness/execution protocol.

The private opener seam is for an already-admitted connection model, not an
ACL verdict. Actual configured calls lazy-bind the database connector after
owning invocation inputs. Driver/configuration admission is outside H/B/N;
variable graph ownership, genuine replay and returned-row checks share the
original work, including work consumed before this invocation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_invocation as invocation
from serverware import authority_revocation_persistence as persistence
from serverware.authority_store import revocation_capability as issuance


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_PIN_FIELDS = ("measurementDigest", "attestationReceiptDigest", "credentialIssuanceDigest",
               "maximumAgeNs", "maximumClockSkewNs")
_CONFIGURED = frozenset({"planner_public_key", "verifier_public_key",
                        "expected_planner_identity", "expected_verifier_identity"})
_CALL_INPUTS = capability.wire._EXPECTATIONS - _CONFIGURED


def _validate_configuration(configuration):
    """Bound fixed local custody without serializing keys or enrolling trust."""
    if type(configuration) is not tuple or len(configuration) != 11:
        raise ValueError("revocation issuer configuration is not an exact eleven-tuple")
    if any(not isinstance(key, Ed25519PublicKey) for key in configuration[:3]):
        raise ValueError("revocation issuer configuration requires Ed25519 public keys")
    for identity in configuration[3:5]:
        if type(identity) is not tuple or len(identity) != 3:
            raise ValueError("revocation issuer identity is not an exact triple")
        for digest in identity:
            capability.shape._digest(digest)
    for index in (5, 7, 8, 10):
        capability.shape._digest(configuration[index])
    pins = configuration[6]
    if type(pins) is not tuple or len(pins) != 5:
        raise ValueError("revocation issuer current pins are not an exact five-tuple")
    for digest in pins[:3]:
        capability.shape._digest(digest)
    capability.shape._integer(pins[3], minimum=1)
    capability.shape._integer(pins[4])
    capability.shape._integer(configuration[9], minimum=1)


def _inputs_from_configuration(configuration, expectations, execution_id, receipt_id, work):
    _validate_configuration(configuration)
    if (type(expectations) is not dict or len(expectations) != len(_CALL_INPUTS)
            or any(type(name) is not str for name in expectations)
            or set(expectations) != _CALL_INPUTS):
        raise ValueError("revocation issuer requires exactly fifteen external historical expectations")
    (planner_key, verifier_key, witness_key, planner_identity, verifier_identity,
        issuer_identity, issuer_pins, configuration_digest, witness_identity,
        generation_sequence, generation_digest) = configuration
    handles = {"planner_public_key": planner_key, "verifier_public_key": verifier_key,
               "database_now": expectations["database_now"]}
    capability.plan._verification_types(**handles)
    ledger = capability.capture._SharedLedger(work)
    owned = capability._capture_expectations(ledger, {
        **expectations, **handles,
        "expected_planner_identity": dict(zip(_IDENTITY_FIELDS, planner_identity)),
        "expected_verifier_identity": dict(zip(_IDENTITY_FIELDS, verifier_identity)),
    }, expected_signer_identity=dict(zip(_IDENTITY_FIELDS, verifier_identity)),
        expected_issuer_session_identity_digest=issuer_identity,
        expected_execution_envelope_id=execution_id,
        expected_witness_receipt_digest=receipt_id,
        expected_witness_identity_digest=witness_identity,
        expected_configuration_digest=configuration_digest,
        expected_generation_sequence=generation_sequence,
        expected_generation_digest=generation_digest)
    pins = capability.capture._JSONCapture(ledger).visit(dict(zip(_PIN_FIELDS, issuer_pins)), depth=0)
    # Fixed call scaffolding aliases only these owned graphs and captured key
    # handles. The genuine store repeats its own boundary capture on this same
    # work; this wrapper does not bypass or replace that existing work phase.
    return {
        "issuer_pins": pins, "signer_public_key": verifier_key, "witness_public_key": witness_key,
        "expected_signer_identity": owned["expectedSignerIdentity"],
        "expected_issuer_session_identity_digest": owned["expectedIssuerSessionIdentityDigest"],
        "expected_execution_envelope_id": owned["expectedExecutionEnvelopeId"],
        "expected_witness_receipt_digest": owned["expectedWitnessReceiptDigest"],
        "expected_witness_identity_digest": owned["expectedWitnessIdentityDigest"],
        "expected_configuration_digest": owned["expectedConfigurationDigest"],
        "expected_generation_sequence": owned["expectedGenerationSequence"],
        "expected_generation_digest": owned["expectedGenerationDigest"],
        "retention_expectations": {**owned["retention"], **handles},
    }


def _run_on_configuration(configuration, *, envelope_bytes, witness_request_bytes,
        expected_execution_envelope_id, expected_witness_receipt_digest,
        expectations, work, opener):
    """Own one outer connection scope around the actual private store worker.

    The explicit opener is a private test/composition seam, not a claim that a
    supplied connection passed role or TLS admission. No operation or successful
    verification callback can replace the store. The actual configured method
    below supplies only the real issuer connector, with no DSN override.
    """
    capability.capture._SharedLedger(work)
    for raw, maximum in ((envelope_bytes, capability.MAX_CAPABILITY_BYTES),
                         (witness_request_bytes, capability.MAX_WITNESS_REQUEST_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise ValueError("revocation issuer accepts only bounded original immutable bytes")
    inputs = _inputs_from_configuration(configuration, expectations,
        expected_execution_envelope_id, expected_witness_receipt_digest, work)
    connection = persistence._connect(work, opener)
    with persistence.store._context(connection, work):
        original = persistence.store._callback(work, lambda: connection.pgconn)
        issuance._call(connection, original, work, lambda: None)
        result = issuance._issue_on_connection(connection=connection, work=work,
            envelope_bytes=envelope_bytes, witness_request_bytes=witness_request_bytes, **inputs)
        # The real worker already verified and compared this identity. Retain
        # a detached, closed result before the outer connection's commit. No
        # second signature/proof is substituted for the first genuine replay.
        result = issuance._row(result, issuance._IDENTITY_FIELDS, work)
        for digest in result.values():
            capability.shape._digest(digest)
        persistence.store._match(result,
            {"capabilityId": inputs["retention_expectations"]["expected_capability_id"]}, work)
        issuance._call(connection, original, work, lambda: None)
    return result


def _issue_invocation_on_configuration(configuration, *, envelope_bytes, work, opener):
    """Authenticate original sender claims before the actual issuer can open.

    The sender is the independently configured verifier, not a key carried by
    the request. Its signed historical claims do not prove current roots or
    clock provenance. The genuine store still verifies all retained, capability
    and witness evidence; no caller-supplied observation can skip either body.
    """
    _validate_configuration(configuration)
    capability.capture._SharedLedger(work)
    if (type(envelope_bytes) is not bytes
            or not 2 <= len(envelope_bytes) <= capability.authority.MAX_REQUEST_BYTES):
        raise ValueError("revocation invocation requires bounded original immutable bytes")
    # Capture all immutable configuration before either actual clock callback.
    # The issuer's existing current age/skew policy also bounds this successor
    # handoff; it does not widen the legacy internal-envelope policy or route.
    verifier_key = configuration[1]
    configuration_digest = configuration[7]
    generation_sequence, generation_digest = configuration[9:11]
    maximum_age_ns, maximum_clock_skew_ns = configuration[6][3:5]
    now_monotonic_ns = persistence.store._callback(work, time.monotonic_ns)
    now_epoch_ns = persistence.store._callback(work, time.time_ns)
    received = invocation._verify_invocation_on_work(envelope_bytes=envelope_bytes,
        verifier_public_key=verifier_key, expected_configuration_digest=configuration_digest,
        expected_generation_sequence=generation_sequence, expected_generation_digest=generation_digest,
        now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    return _run_on_configuration(configuration, envelope_bytes=received.capability_bytes,
        witness_request_bytes=received.witness_request_bytes,
        expected_execution_envelope_id=received.execution_envelope_id,
        expected_witness_receipt_digest=received.witness_receipt_digest,
        expectations=received.historical_expectations, work=work, opener=opener)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationCapabilityIssuer:
    """Constructor-owned independent pins, not a configured public route.

    The eleven-tuple is captured once per invocation before any opener/key
    callback. It pins handles, not arbitrary mutable key internals or external
    provenance. Historical request, roots and clocks (including the original
    acquisition's database_now) remain mandatory caller inputs. Current age and
    skew policy belong to configuration and cannot be overridden per call.

    The genuine issuer connector has already started/admitted its transaction;
    its connection context commits only after the real store and result checks.
    Pre-commit body failures normally roll back/close that owner. Commit or
    connection-exit errors may be indeterminate; a post-exit work guard cannot
    undo an already committed transaction. An opener that never returns or a
    context entry that raises before entering retains the existing helper's
    driver-cleanup boundary. Observed status/pgconn guards do not prove history
    against a hostile driver that commits and begins another transaction.
    """

    _configuration: tuple

    def __init__(self, *, planner_public_key, verifier_public_key, witness_public_key,
                 expected_planner_identity, expected_verifier_identity,
                 expected_issuer_session_identity_digest, issuer_pins,
                 expected_configuration_digest, expected_witness_identity_digest,
                 expected_generation_sequence, expected_generation_digest):
        capability.shape.validate_identity_shape(expected_planner_identity)
        capability.shape.validate_identity_shape(expected_verifier_identity)
        issuance._closed(issuer_pins, _PIN_FIELDS)
        configuration = (planner_public_key, verifier_public_key, witness_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            expected_issuer_session_identity_digest, tuple(issuer_pins[name] for name in _PIN_FIELDS),
            expected_configuration_digest, expected_witness_identity_digest,
            expected_generation_sequence, expected_generation_digest)
        _validate_configuration(configuration)
        object.__setattr__(self, "_configuration", configuration)

    def _snapshot_configuration(self):
        if type(self) is not RevocationCapabilityIssuer:
            raise ValueError("revocation issuance requires its exact configured owner")
        configuration = self._configuration
        _validate_configuration(configuration)
        return configuration

    def issue(self, *, envelope_bytes, witness_request_bytes,
              expected_execution_envelope_id, expected_witness_receipt_digest, work, **expectations):
        configuration = self._snapshot_configuration()

        def open_issuer():
            # Lazy import preserves the real startup gate. There is no caller
            # connection, DSN, connector override or planner-writer fallback.
            from serverware import db
            return db._policy_authority_capability_issuer_pg_connect_raw()

        return _run_on_configuration(configuration, envelope_bytes=envelope_bytes,
            witness_request_bytes=witness_request_bytes,
            expected_execution_envelope_id=expected_execution_envelope_id,
            expected_witness_receipt_digest=expected_witness_receipt_digest,
            expectations=expectations, work=work, opener=open_issuer)

    def issue_authenticated(self, *, envelope_bytes, work):
        """Consume original verifier-signed invocation bytes, not an approval DTO.

        This private configured entry does not register a service purpose or
        retain invocation bytes durably. Cross-role transport admission, root
        provenance and restart custody remain separate prerequisites.
        """
        configuration = self._snapshot_configuration()

        def open_issuer():
            from serverware import db
            return db._policy_authority_capability_issuer_pg_connect_raw()

        return _issue_invocation_on_configuration(configuration, envelope_bytes=envelope_bytes,
            work=work, opener=open_issuer)
