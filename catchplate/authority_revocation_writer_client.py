"""Configured original-byte writer exchange with independently checked ACKs.

The actual planner service supplies root-admitted configuration and its active
launch generation. This private component checks those bindings but cannot
manufacture their provenance. Before transport it authenticates the original
controls and genuinely replays the original plan to derive ACK expectations.
Response fields supply neither expected values nor keys. A returned original
ACK establishes the pinned writer's custody statement, not current roots,
execution, historical recovery, hardware custody or database durability.
"""
from __future__ import annotations

import math
import time

from catchplate import authority_contract as authority
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_verifier as verifier
from catchplate import authority_revocation_writer_ack_expectation as expectation
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
from catchplate import authority_revocation_writer_commitment as commitment
from catchplate import authority_revocation_writer_transport as transport


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


class RevocationWriterClientError(ValueError):
    pass


def _send_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    """Authenticate one fixed exchange on the caller's existing allowance.

    Snapshot every endpoint/key/age scalar before any callback. The reused
    verifier mapper owns configuration and the seven launch bindings again,
    genuinely checks their commitment and binds planner/verifier keys and
    identities. This is configuration reuse, not acceptance of a prior proof.
    Only the writer raw32 public key is additionally constructed; its measured
    response pin is independent of the ACK and distinct from other roles.
    Native socket I/O does not spend H/B/N, and its callback must leave the
    existing meter untouched. A failure never retries or returns an ACK.
    """
    try:
        ledger = commitment.capture._SharedLedger(work)
        commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        # The fixed transport's aggregate admission is also required before
        # cryptographic callbacks, not first discovered after local replay.
        transport._validate_lengths((len(intent_bytes), len(relay_bytes), len(envelope_bytes),
            len(evaluation_context_bytes), len(historical_expectations_bytes)))
        commitment.plan.contract._digest(configuration_digest)
        if type(payload) is not dict:
            raise RevocationWriterClientError("writer client configuration is not an exact object")
        owned = configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
        roles = owned["roles"]
        if type(roles) is not dict:
            raise RevocationWriterClientError("writer client roles are not an exact object")
        planner, writer = roles["planner"], roles["planner-writer"]
        for name, role in (("planner", planner), ("planner-writer", writer)):
            if type(role) is not dict:
                raise RevocationWriterClientError("writer client role is not an exact object")
            commitment.plan.contract._literal(role["processMode"], "policy-authority-" + name)
            for field in ("serviceUid", "serviceGid"):
                commitment.plan.contract._integer(role[field], 0xFFFFFFFF, minimum=1)
            commitment.plan.contract._integer(role["maximumInternalAgeNs"], minimum=1)
            timeout = role["requestTimeoutSeconds"]
            if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                    or not 0.05 <= timeout <= 30):
                raise RevocationWriterClientError("writer client timeout is outside the source interval")
        for field in ("peerUid", "peerGid"):
            commitment.plan.contract._integer(writer[field], 0xFFFFFFFF, minimum=1)
        commitment.plan._same((writer["peerUid"], writer["peerGid"]),
            (planner["serviceUid"], planner["serviceGid"]), work,
            "writer client peer topology differs from the measured planner")
        path = writer["socketPath"]
        if (type(path) is not str or not 1 <= len(path) <= 107
                or not path.startswith("/") or "\x00" in path or len(path.encode("utf-8")) > 107):
            raise RevocationWriterClientError("writer client socket path is not bounded and absolute")
        peer_uid, peer_gid = writer["serviceUid"], writer["serviceGid"]
        timeout_seconds = min(planner["requestTimeoutSeconds"], writer["requestTimeoutSeconds"])
        maximum_age_ns = min(planner["maximumInternalAgeNs"], writer["maximumInternalAgeNs"])
        writer_key_bytes = writer["responseSigningPublicKeyBase64Url"]
        writer_pin = writer["responseSigningSpkiDigest"]
        commitment.plan.contract._digest(writer_pin)
        other_pins = tuple(roles[name]["responseSigningSpkiDigest"]
            for name in ("verifier", "planner", "issuer", "executor"))
        for pin in other_pins:
            commitment.plan.contract._digest(pin)
        if writer_pin in other_pins:
            raise RevocationWriterClientError("writer client response key reuses another role pin")
        # Both independently configured identities and historical age policy
        # come from this mapper, never from retained context or ACK fields.
        owner = verifier._verifier_from_configuration_on_work(payload=owned,
            configuration_digest=configuration_digest, generation=generation,
            runtime_role_identities=runtime_role_identities, work=work)
        fixed = owner._snapshot_configuration()
        writer_public_key = configuration._key(writer_key_bytes, work, expected_spki=writer_pin)
        now_monotonic_ns = configuration.production._callback(work, time.monotonic_ns)
        now_epoch_ns = configuration.production._callback(work, time.time_ns)
        request_fields, freshness_pins = expectation._expected_ack_request_and_freshness_on_work(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_planner_identity=dict(zip(_IDENTITY_FIELDS, fixed[2])),
            expected_verifier_identity=dict(zip(_IDENTITY_FIELDS, fixed[3])),
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=now_epoch_ns,
            now_monotonic_ns=now_monotonic_ns, maximum_age_ns=maximum_age_ns,
            maximum_assertion_age_ns=fixed[4], maximum_plan_age_ns=fixed[5],
            maximum_clock_skew_ns=fixed[6], work=work)
        # Genuine replay and key callbacks may consume the remaining lifetime.
        # Recheck held authenticated scalar clocks immediately before sending;
        # never retime history or infer rollback from a later delivery failure.
        before_send_monotonic = configuration.production._callback(work, time.monotonic_ns)
        before_send_epoch = configuration.production._callback(work, time.time_ns)
        commitment._check_freshness_pins(freshness_pins,
            now_epoch_ns=before_send_epoch, now_monotonic_ns=before_send_monotonic,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=fixed[6])
        acknowledgment_bytes = configuration.production._callback(work, lambda: transport._socket_request(
            path, intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            timeout_seconds=timeout_seconds, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
        acknowledgment._verify_on_work(acknowledgment_bytes=acknowledgment_bytes,
            request_fields=request_fields, writer_public_key=writer_public_key,
            expected_writer_spki_digest=writer_pin, work=work)
        return acknowledgment_bytes
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationWriterClientError):
            raise
        raise RevocationWriterClientError("configured writer exchange failed") from exc
