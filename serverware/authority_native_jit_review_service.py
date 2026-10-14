"""Measured authorize service: current reads before purpose-key signing.

Actual startup supplies signed reviewer policy and a separately retained signed
current-root enrollment. Keeping the latter outside configuration avoids a
configuration/generation/enrollment cycle. No request supplies a policy, reader,
key, successful plan or replacement deadline. The session token only traverses
this live exchange; it is not included in plans, responses or durable records.

This connects authorize only. Receipt execution and the control-plane selector
remain unavailable until their complete cold assembly exists. A signed opening
authorization permits private preparation, not disclosure, approval or release.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import os
import threading

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_native_jit_review_service_policy as policy
from serverware import authority_native_jit_review_transport as transport
from serverware import authority_native_jit_review_open_signers as signers
from serverware import authority_native_jit_review_plan_owner as planning
from serverware import authority_current_root_authorization as enrollment
from serverware import authority_release_private_request as requests
from serverware import registration_execution_authorizer_entrypoint as sealed
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

wire, reads = planning.wire, planning.reads
ENVIRONMENT = "SERVERWARE_NATIVE_JIT_REVIEW_CURRENT_ROOT_ENROLLMENT_FD"
_OWNERS = {}
_LOCK = threading.RLock()


class NativeReviewServiceError(ValueError):
    def __init__(self):
        super().__init__("Native review authority is unavailable")


def _need(value):
    if not value:
        raise NativeReviewServiceError()


def _descriptor():
    from serverware import authority_launch_guard as launch
    value = os.environ.get(ENVIRONMENT, "")
    _need(value.isascii() and value.isdecimal() and len(value) <= 10
        and str(int(value)) == value and int(value) >= 3
        and int(value) in launch.retained_descriptors()
        and not os.environ.get(ENVIRONMENT.removesuffix("_FD") + "_PATH"))
    return int(value)


def _public(key):
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


@dataclass(slots=True, repr=False, eq=False)
class _Owner:
    process: object
    configuration: object
    configuration_original: bytes
    configuration_digest: str
    root_original: bytes
    role: str
    generation: dict
    identity: tuple
    descriptor: int
    descriptor_identity: tuple
    material: object
    reader_settings: tuple | None
    lock: object
    failed: bool = False

    def check(self, work):
        from serverware import authority_launch_guard as launch
        from serverware import authority_service as service
        try:
            _need(not self.failed and _OWNERS.get(self.process) is self
                and type(self.process) is service.AuthorityProcess
                and self.process.configuration is self.configuration
                and self.process.role_name == self.role
                and self.process.process_mode == "policy-authority-" + self.role
                and (os.getpid(), os.geteuid(), os.getegid()) == self.identity
                and self.configuration.digest == self.configuration_digest
                and _public(self.configuration.root_key) == self.root_original)
            launch.require_active(self.role)
            assurance = launch.launch_assurance()
            _need(assurance.get("nativeStageZero") is True
                and assurance.get("trustMode") in ("external-production", "tee-hardware")
                and dict(launch.generation()) == self.generation
                and _descriptor() == self.descriptor
                and sealed._sealed_identity(self.descriptor, enrollment.MAX_ENROLLMENT_BYTES, private=True)
                    == self.descriptor_identity)
            original = service._canonical(self.configuration.payload)
            work.charge(input_bytes=len(original) + len(self.configuration_original))
            _need(original == self.configuration_original)
        except BaseException:
            self.failed = True
            raise NativeReviewServiceError() from None


def initialize(process):
    """Actual AuthorityProcess startup; missing policy never enables a route."""
    from serverware import authority_launch_guard as launch
    from serverware import authority_service as service
    _need(type(process) is service.AuthorityProcess
        and type(process.configuration) is service.MeasuredConfiguration)
    with _LOCK:
        _need(process not in _OWNERS)
        configured, role = process.configuration, process.role_name
        if policy.FIELD not in configured.payload or role not in {"planner", "verifier"}:
            _need(not os.environ.get(ENVIRONMENT)
                and not os.environ.get(ENVIRONMENT.removesuffix("_FD") + "_PATH"))
            _OWNERS[process] = None
            return
        launch.require_active(role)
        assurance = launch.launch_assurance()
        _need(assurance.get("nativeStageZero") is True
            and assurance.get("trustMode") in ("external-production", "tee-hardware"))
        work = _ValidationWork(QueryReadValidationLimits())
        generation = dict(launch.generation())
        descriptor = _descriptor()
        original, identity = sealed._read_original(descriptor, enrollment.MAX_ENROLLMENT_BYTES, private=True)
        material = policy.admit_on_work(configured.payload[policy.FIELD],
            configuration_payload=configured.payload, configuration_root_key=configured.root_key,
            enrollment_original=original, expected_generation_digest=generation["digest"], work=work)
        settings = None
        if role == "planner":
            from serverware import authority_webauthn_transition_configuration as read_configuration
            # The separate signed service policy selects only this read path.
            # Do not add native operations to the legacy planning inventory.
            dsn = service._read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN")
            dsn, timeout, database = read_configuration._read_settings(
                configured.payload, configured.runtime_role_identities, dsn)
            settings = (dsn, timeout, *database[:4], configured.payload["queryManifestDigest"])
            reads.connection_owner._validate_configuration(settings)
            # This proves real startup holds the purpose key; nothing is signed.
            with signers._borrow(process, purpose="authorize"):
                pass
        held = _Owner(process, configured, service._canonical(configured.payload), configured.digest,
            _public(configured.root_key), role, generation, (os.getpid(), os.geteuid(), os.getegid()),
            descriptor, identity, material, settings, threading.RLock())
        _OWNERS[process] = held
        try:
            held.check(work)
        except BaseException:
            _OWNERS[process] = None
            raise


def _started(process, work):
    with _LOCK:
        held = _OWNERS.get(process)
        _need(type(held) is _Owner)
        held.check(work)
        return held


def _authorize(held, *, challenge_original, session_id, token, window, deadline_ns, work):
    """One actual acquisition/replay feeds signing; no successful DTO input."""
    _need(held.role == "planner" and held.reader_settings is not None)
    held.check(work)
    challenge = wire.validate_challenge_original(challenge_original)["statement"]
    _need(challenge["expiresAtEpochNs"] >= window[3])
    arguments = {"approval_request_id": challenge["approvalRequestId"], "session_id": session_id,
        "challenge_sha256": "sha256:" + hashlib.sha256(challenge_original.encode("ascii")).hexdigest()}
    work.charge(input_bytes=4 * len(challenge_original), hashes=1)
    work.prepare_copy(arguments)
    request = requests._derive_request(wire.AUTHORIZE, arguments)
    work.prepare_copy(request)
    settings, material = held.reader_settings, held.material
    state = material.state_configuration
    current = reads.transport.CurrentRootDecisionClient(path=state[0], timeout_seconds=state[1],
        expected_peer_uid=state[2], expected_peer_gid=state[3])
    reader = reads.NativeJitReviewCurrentReader(operation=wire.AUTHORIZE,
        dsn=settings[0], connect_timeout_seconds=settings[1], database_role=settings[2],
        tls_client_dn=settings[3], tls_client_serial=settings[4], tls_issuer_dn=settings[5],
        query_manifest_digest=settings[6], root_public_key=held.configuration.root_key,
        enrollment_original=material.enrollment_original, current_root_client=current)
    owner = planning.NativeJitReviewPlanOwner(read_planner=reader,
        configuration_payload=held.configuration.payload, configuration_root_key=held.configuration.root_key,
        authn_policy=material.authentication_policy, trust_policy=material.trust_policy,
        live_window=window, deadline_ns=deadline_ns, work=work)
    prepared = owner.produce(request, session_token_original=token, challenge_original=challenge_original)
    result = planning._json(prepared.result_original, wire.MAX_AUTHORITY_ORIGINAL, work)
    _need(result["operation"] == wire.AUTHORIZE and result["requestDigest"] == request["requestDigest"]
        and result["canDecide"] is False and prepared.mutations_original == b"[]"
        and prepared.before_vector_original == prepared.after_vector_original)
    payload = {name: result[name] for name in wire.AUTHORIZATION_FIELDS - {"schema"}}
    payload["schema"] = wire.AUTHORIZATION_SCHEMA
    payload_original = planning._json_original(payload, wire.MAX_AUTHORITY_ORIGINAL, work)
    message = wire.AUTHORIZATION_SCHEMA.encode("ascii") + b"\0" + payload_original
    held.check(work)
    _need(reads.head.clock._check_on_work(window, work=work) < result["expiresAtEpochNs"])
    transport.io._check_deadline(deadline_ns)
    with signers._borrow(held.process, purpose="authorize") as key:
        signature = planning.configuration_capture.production._callback(work, lambda: key.sign(message))
        envelope = {"schema": wire.AUTHORIZATION_SCHEMA.replace("serverware.native", "serverware.signedNative", 1),
            "payload": payload, "signatureBase64Url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")}
        original = planning._json_original(envelope, wire.MAX_AUTHORITY_ORIGINAL, work).decode("ascii")
        wire.verify_authorization_original(original, public_key=key.public_key(),
            now_epoch_ns=reads.head.clock._check_on_work(window, work=work))
    held.check(work)
    _need(reads.head.clock._check_on_work(window, work=work) < result["expiresAtEpochNs"])
    transport.io._check_deadline(deadline_ns)
    return (original, *prepared.retained_originals)


def serve_process(process, connection, *, deadline_ns, prefix):
    """Called only after AuthorityServer checks its configured immediate peer."""
    from serverware import authority_custody_caller_service as custody
    from serverware import authority_webauthn_registration_custody_caller as registration
    work = _ValidationWork(QueryReadValidationLimits())
    held = _started(process, work)  # Admit owner before reading token/body.
    with held.lock:
        held.check(work)
        receipt = held.configuration.attestation_evidence
        interval = registration._receipt_interval(receipt)
        deadline_ns = custody._relay_deadline(interval, deadline_ns)
        digest, expires, challenge, session_id, token = transport.recv_request(connection,
            deadline_ns=deadline_ns, prefix=prefix)
        _need(digest == held.configuration_digest)
        statement = wire.validate_challenge_original(challenge)["statement"]
        window = reads.head.clock._open_on_work(deadline_epoch_ns=min(expires, statement["expiresAtEpochNs"]),
            maximum_lifetime_ns=wire.MAX_INTERVAL_NS, maximum_clock_skew_ns=0, work=work)
        deadline_ns = min(deadline_ns, window[4])
        if held.role == "verifier":
            role = held.configuration.role("planner")
            response = transport.exchange(role["socketPath"], configuration_digest=digest,
                deadline_epoch_ns=window[3], challenge_original=challenge, session_id=session_id,
                session_token_original=token, deadline_ns=deadline_ns,
                expected_peer_uid=role["serviceUid"], expected_peer_gid=role["serviceGid"])
        else:
            response = _authorize(held, challenge_original=challenge, session_id=session_id, token=token,
                window=window, deadline_ns=deadline_ns, work=work)
        del token
        held.check(work)
        _need(held.configuration.attestation_evidence is receipt
            and registration._receipt_interval(receipt) == interval)
        deadline_ns = custody._relay_deadline(interval, deadline_ns)
        # The actual planner may have clipped the authorization further to a
        # session, assignment or current-head lifetime. Keep that shorter bound
        # through the response send, without creating a new clock window.
        from serverware import authority_successor_execution_window as windows
        authorization = wire.validate_authorization_original(response[0])["payload"]
        window = windows._narrow(window, deadline_epoch_ns=authorization["expiresAtEpochNs"],
            maximum_lifetime_ns=wire.MAX_INTERVAL_NS, maximum_clock_skew_ns=0)
        deadline_ns = min(deadline_ns, window[4])
        reads.head.clock._check_on_work(window, work=work)
        transport.send_response(connection, response, deadline_ns=deadline_ns)


def serve_relay(trust, connection, *, deadline_ns, prefix):
    """Opaque control-plane -> runtime -> verifier forwarding, without keys."""
    from serverware import authority_service as service
    from serverware import authority_launch_guard as launch
    from serverware import authority_custody_caller_service as custody
    from serverware import authority_webauthn_registration_custody_caller as registration
    _need(type(trust) is service.AuthorityRuntimeClient
        and os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() == service.RUNTIME_RELAY_PROCESS_MODE
        and (os.geteuid(), os.getegid()) == (trust.server_uid, trust.server_gid))
    launch.require_active("runtime")
    generation = dict(launch.generation())
    pinned = (trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid, trust.configuration_digest)
    receipt = trust.attestation_evidence
    interval = registration._receipt_interval(receipt)
    deadline_ns = custody._relay_deadline(interval, deadline_ns)
    digest, expiry, challenge, session_id, token = transport.recv_request(connection,
        deadline_ns=deadline_ns, prefix=prefix)
    _need(digest == pinned[3])
    response = transport.exchange(pinned[0], configuration_digest=digest, deadline_epoch_ns=expiry,
        challenge_original=challenge, session_id=session_id, session_token_original=token,
        deadline_ns=deadline_ns, expected_peer_uid=pinned[1], expected_peer_gid=pinned[2])
    del token
    launch.require_active("runtime")
    _need(dict(launch.generation()) == generation and trust.attestation_evidence is receipt
        and registration._receipt_interval(receipt) == interval
        and (trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid, trust.configuration_digest) == pinned)
    deadline_ns = custody._relay_deadline(interval, deadline_ns)
    transport.send_response(connection, response, deadline_ns=deadline_ns)
