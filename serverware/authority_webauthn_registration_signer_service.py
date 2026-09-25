"""Private connection owner for the independently admitted evidence signer.

The future cold launcher must independently admit the root configuration,
generation/runtime cohort, this dedicated signer's identity and original
attestation interval, OS/peer identities, activated listener and replay storage.
The factory checks their consistency; dictionaries, key possession and this
ordinary owner do not establish that provenance or provide enclave assurance.
No startup entrypoint, environment discovery, listener creation or role-registry
extension is supplied here. Generic authority signing keys are not substitutes.

One private replay owner spans this signer lifetime; provisioning must preserve
the same replay domain across configuration/source generations and restarts.
Each connected Unix stream is owned and closed, has one original
deadline and one work allowance after bounded raw-eight EOF, and calls the real
grant/source/evidence composition. A consumed grant remains consumed on any
later failure. Only original evidence envelope and input bytes are returned.
Empty siblings here means evidence admission only, never a claim of complete
OIDC sibling selection or business registration finalization.
"""
from __future__ import annotations

import math
import os
import socket
import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_revocation_configuration as configuration
from serverware import authority_transport
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_enrollment_replay as replay
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_registration_exchange_signing as signing
from serverware import authority_webauthn_registration_signer_transport as transport
from serverware import authority_webauthn_registration_signer_wire as wire
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


evidence, authority = wire.evidence, wire.authority
clock = signing.wire.clock


class RegistrationEvidenceSignerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Binding:
    payload: dict
    configuration_digest: str
    generation: dict
    runtime_role_identities: dict
    private_key: object
    signer_identity: dict
    identity: tuple
    peer: tuple
    attestation_interval: tuple
    opening_sample: tuple
    clock_skew_ns: int
    timeout_seconds: int | float
    store: replay.EnrollmentReplayStore


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RegistrationEvidenceSignerError(label + " is not a bounded exact integer")


def _sample(work):
    if work is not None:
        return clock._sample_on_work(work)
    # Pre-ingress lifecycle checks allocate no request work. These are actual
    # clocks, not a caller callback or a renewal of the admitted receipt.
    before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
    for value in (before, epoch, after):
        _integer(value, 1, 2**63 - 1, "signer clock")
    if after < before:
        raise RegistrationEvidenceSignerError("signer monotonic sample reversed")
    return before, epoch, after


def _interval(interval):
    if type(interval) is not tuple or len(interval) != 2:
        raise RegistrationEvidenceSignerError("signer attestation interval is not an exact pair")
    for value in interval:
        _integer(value, 1, 2**63 - 1, "signer attestation bound")
    if interval[0] >= interval[1]:
        raise RegistrationEvidenceSignerError("signer attestation interval is empty")
    return interval


def _clock_binding(binding, sample):
    before, epoch, after = sample
    opened_before, opened_epoch, opened_after = binding.opening_sample
    lower, upper = binding.attestation_interval
    skew = binding.clock_skew_ns
    if (not lower <= epoch < upper or before < opened_after
            or after >= opened_before + upper - opened_epoch
            or not opened_epoch + before - opened_after - skew <= epoch
                <= opened_epoch + after - opened_before + skew):
        raise RegistrationEvidenceSignerError("signer original attestation interval or clock continuity expired")


class RegistrationEvidenceSigner:
    """One PID/identity-bound owner, not root or listener admission."""

    __slots__ = ("_pid", "_binding", "_serve_lock", "_closed", "_failed")

    def __init__(self):
        raise RegistrationEvidenceSignerError("use the independently admitted configuration factory")

    @classmethod
    def from_admitted_configuration(cls, *, payload, configuration_digest, generation,
            runtime_role_identities, evidence_private_key, evidence_signer_identity,
            signer_uid, signer_gid, peer_uid, peer_gid, attestation_interval,
            request_timeout_seconds, replay_directory_fd, replay_directory_device,
            replay_directory_inode, maximum_records, work):
        if cls is not RegistrationEvidenceSigner:
            raise RegistrationEvidenceSignerError("registration signer factory is fixed")
        ledger = evidence.capture._SharedLedger(work)
        pid = os.getpid()
        signer, digest = evidence_private_key, configuration_digest
        identity, peer = (signer_uid, signer_gid), (peer_uid, peer_gid)
        interval, timeout = _interval(attestation_interval), request_timeout_seconds
        directory = replay_directory_fd
        device, inode, capacity = replay_directory_device, replay_directory_inode, maximum_records
        for value, minimum, maximum, label in (
                (identity[0], 1, 2**32 - 2, "signer UID"),
                (identity[1], 1, 2**32 - 2, "signer GID"),
                (peer[0], 0, 2**32 - 2, "signer peer UID"),
                (peer[1], 0, 2**32 - 2, "signer peer GID"),
                (directory, 0, 2**31 - 1, "signer replay directory FD"),
                (device, 0, 2**64 - 1, "signer replay device"),
                (inode, 1, 2**64 - 1, "signer replay inode"),
                (capacity, 1, replay.MAX_RECORDS, "signer replay record limit")):
            _integer(value, minimum, maximum, label)
        if identity[0] == peer[0] or (os.geteuid(), os.getegid()) != identity:
            raise RegistrationEvidenceSignerError("signer process is not its independent nonroot identity")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0.05 <= timeout <= 30):
            raise RegistrationEvidenceSignerError("signer request timeout is outside the service bound")
        if not isinstance(signer, Ed25519PrivateKey):
            raise RegistrationEvidenceSignerError("signer requires its actual dedicated Ed25519 private key")
        evidence.plan.contract._digest(digest)
        configuration.capability.shape._bounded_object(generation, 24, "signer launch context")
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
        launch = evidence.capture._JSONCapture(ledger).visit(
            {name: generation[name] for name in configuration._GENERATION_FIELDS})
        runtime = evidence.capture._JSONCapture(ledger,
            maximum_bytes=8192).visit(runtime_role_identities)
        signer_identity = evidence.capture._JSONCapture(ledger,
            maximum_bytes=8192).visit(evidence_signer_identity)
        evidence._identity(signer_identity)
        evidence_policy._shape(owned.get(evidence_policy.FIELD), webauthn=owned["webauthn"])
        selected = owned[evidence_policy.FIELD]["registration"]
        if selected is None or owned.get(enrollment_policy.FIELD) is None:
            raise RegistrationEvidenceSignerError("registration signing requires enabled evidence and enrollment policies")
        encoded, spki, expected_identity = (selected["signingPublicKeyBase64Url"],
            selected["signingSpkiDigest"], selected["signerIdentity"])
        skew = selected["maximumClockSkewNs"]
        roles = owned["roles"]
        evidence.plan.contract._object(roles, frozenset(configuration._ROLE_NAMES), "signer authority roles")
        forbidden = []
        for name in configuration._ROLE_NAMES:
            role = roles[name]
            if type(role) is not dict:
                raise RegistrationEvidenceSignerError("signer configured role is not exact data")
            _integer(role["serviceUid"], 0, 2**32 - 2, "authority role UID")
            if identity[0] == role["serviceUid"]:
                raise RegistrationEvidenceSignerError("evidence signer cannot share an authority role UID")
            pin = role["responseSigningSpkiDigest"]
            evidence.plan.contract._digest(pin)
            forbidden.append(pin)
            if name in ("verifier", "planner"):
                evidence.plan.contract._digest(role["signingSpkiDigest"])
                forbidden.append(role["signingSpkiDigest"])
        # Every graph, key reference, OS/receipt/store pin and timeout is held
        # before the first genuine native configuration/key/hash callback.
        work.prepare_scan(forbidden)
        if spki in forbidden:
            raise RegistrationEvidenceSignerError("evidence key is not independent of generic authority keys")
        evidence.plan._same(signer_identity, expected_identity, work,
            "actual evidence signer identity differs from its admitted purpose")
        enrollment_policy._capture_on_work(payload=owned, configuration_digest=digest,
            generation=launch, runtime_role_identities=runtime, work=work)
        public_key = configuration._key(encoded, work, expected_spki=spki)
        evidence.keys._pair_on_work(signer, public_key, work)
        opening = _sample(work)
        if not interval[0] <= opening[1] < interval[1]:
            raise RegistrationEvidenceSignerError("signer attestation is not currently live")
        store = None
        try:
            def open_store():
                # Retain the acquired owner even if the callback's finally
                # guard rejects work continuity after successful construction.
                nonlocal store
                store = replay.EnrollmentReplayStore(directory_fd=directory,
                    expected_device=device, expected_inode=inode,
                    expected_uid=identity[0], expected_gid=identity[1], maximum_records=capacity)

            evidence.production._callback(work, open_store)
            result = object.__new__(cls)
            result._pid, result._serve_lock = pid, threading.Lock()
            result._closed, result._failed = False, False
            result._binding = _Binding(owned, digest, launch, runtime, signer, signer_identity,
                identity, peer, interval, opening, skew, timeout, store)
            result._live(result._binding, work=work)
            return result
        except BaseException:
            if store is not None:
                replay.EnrollmentReplayStore.close(store)
            raise

    def _require_pid(self):
        if os.getpid() != self._pid:
            raise RegistrationEvidenceSignerError("forked process cannot use or close the evidence signer")

    def _continuity(self, binding):
        self._require_pid()
        if (self._closed or self._failed or type(binding) is not _Binding
                or self._binding is not binding
                or (os.geteuid(), os.getegid()) != binding.identity
                or type(binding.store) is not replay.EnrollmentReplayStore):
            raise RegistrationEvidenceSignerError("evidence signer ownership changed")
        replay.EnrollmentReplayStore._require_ready(binding.store)

    def _live(self, binding, *, work=None):
        try:
            if work is None:
                self._continuity(binding)
            else:
                evidence.production._callback(work, lambda: self._continuity(binding))
            _clock_binding(binding, _sample(work))
            if work is None:
                self._continuity(binding)
            else:
                evidence.production._callback(work, lambda: self._continuity(binding))
        except BaseException:
            self._failed = True
            raise

    def serve_connection(self, connection, *, deadline_ns=None):
        """Own one connected stream; no error echo, retry or accept loop."""
        acquired = False
        try:
            self._require_pid()  # Never touch an inherited thread lock first.
            if type(connection) is not socket.socket:
                raise RegistrationEvidenceSignerError("signer requires an actual owned Unix socket")
            if not self._serve_lock.acquire(blocking=False):
                raise RegistrationEvidenceSignerError("evidence signer already has an active connection")
            acquired = True
            binding = self._binding
            if type(binding) is not _Binding:
                raise RegistrationEvidenceSignerError("evidence signer has no live owned binding")
            bounded_deadline = min(transport._deadline_ns(binding.timeout_seconds),
                binding.opening_sample[0] + binding.attestation_interval[1] - binding.opening_sample[1])
            if deadline_ns is not None:
                transport._check_deadline(deadline_ns)
                bounded_deadline = min(bounded_deadline, deadline_ns)
            self._live(binding)
            transport._check_deadline(bounded_deadline)
            if (connection.family != socket.AF_UNIX
                    or connection.type & socket.SOCK_STREAM != socket.SOCK_STREAM
                    or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0):
                raise RegistrationEvidenceSignerError("signer connection is not a connected Unix stream")
            peer_uid, peer_gid, _peer_pid = transport.io._call_until(connection, bounded_deadline,
                lambda: authority_transport._peer_identity(connection))
            if (peer_uid, peer_gid) != binding.peer:
                raise RegistrationEvidenceSignerError("registration signer caller peer differs")
            prefix = transport._recv_prefix(connection, deadline_ns=bounded_deadline)
            originals = transport._recv_request(connection, prefix=prefix, deadline_ns=bounded_deadline)
            # EOF and the complete fixed length inventory precede the sole
            # request allowance. No child helper receives replacement work.
            work = _ValidationWork(QueryReadValidationLimits())
            ledger = evidence.capture._SharedLedger(work)
            owned = configuration._ConfigurationCapture(ledger,
                maximum_bytes=authority.MAX_REQUEST_BYTES).visit(binding.payload)
            launch = evidence.capture._JSONCapture(ledger).visit(binding.generation)
            runtime = evidence.capture._JSONCapture(ledger,
                maximum_bytes=8192).visit(binding.runtime_role_identities)
            signer_identity = evidence.capture._JSONCapture(ledger,
                maximum_bytes=8192).visit(binding.signer_identity)
            signer, digest, store = binding.private_key, binding.configuration_digest, binding.store
            self._live(binding, work=work)
            transport._check_deadline(bounded_deadline)
            credential, transports, instant = wire._decode_request_on_work(originals, work=work)
            result = signing._produce_on_configuration(payload=owned, configuration_digest=digest,
                generation=launch, runtime_role_identities=runtime,
                request_control_bytes=originals[0], request_context_bytes=originals[1],
                response_control_bytes=originals[2], source_bytes=originals[3],
                evidence_private_key=signer, evidence_signer_identity=signer_identity,
                enrollment_authorization_bytes=originals[4], enrollment_replay_store=store,
                client_data_json=originals[5], attestation_object=originals[6],
                credential_id=credential, transports=transports,
                sibling_challenge_ids=[], verified_at=instant, work=work)
            if type(result) is not tuple or len(result) != 4:
                raise RegistrationEvidenceSignerError("actual evidence producer returned an invalid result inventory")
            response = wire._response_originals((result[0], result[3]))
            del result  # No unsigned finalization arguments or request leave.
            self._live(binding, work=work)
            transport._check_deadline(bounded_deadline)
            transport._send_response(connection, response, deadline_ns=bounded_deadline)
            self._live(binding, work=work)
            transport._check_deadline(bounded_deadline)
        finally:
            try:
                if type(connection) is socket.socket:
                    connection.close()
            finally:
                if acquired:
                    self._serve_lock.release()

    def close(self):
        """Clear this PID's key and close only its private replay description."""
        self._require_pid()
        if not self._serve_lock.acquire(blocking=False):
            raise RegistrationEvidenceSignerError("cannot close an active evidence signer connection")
        try:
            if self._closed:
                return
            binding = self._binding
            self._closed, self._failed, self._binding = True, True, None
            if type(binding) is _Binding:
                replay.EnrollmentReplayStore.close(binding.store)
        finally:
            self._serve_lock.release()
