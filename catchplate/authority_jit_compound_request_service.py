"""Private measured signed-request owner, without a route or transport.

The receiver borrows one already peer-admitted Unix socket and one ACTUALLY
sampled receiving window. Its factory authenticates sender PID, kernel boot,
runtime generation, role keys and the signed original bracket before the fixed
producer sees that bracket. The bracket remains a sender observation, not a
fresh receiver sample. Both windows and the borrowed socket stay held through
the final send while this context is entered. No connection or window is made.

Returned raw4 is same-invocation custody/planning output. The receiving verifier
still needs independently admitted policy/root/cutoff expectations and actual
raw-page replay. Neither response context nor this owner supplies current-root,
request authorization, witness reservation, an execution grant or completion.
The existing production and measured imports remain genuinely runtime-gated.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import socket
import threading

from catchplate import authority_jit_compound_request as request
from catchplate import authority_jit_original_service as pages
from catchplate import authority_transport as transport
from catchplate.authority_query_read_work import _ValidationWork


evidence, clock = request.evidence, request.clock
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


class JitCompoundRequestServiceError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundRequestServiceError("JIT planning request lost its original measured caller")


def _boot_id():
    # A process cannot survive a boot. Capture this once in each actual local
    # process, alongside SO_PEERCRED PID and the admitted launch generation.
    # This kernel observation alone is not configuration or signer authority.
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        raw = stream.read(38)
    _require(type(raw) is bytes and len(raw) == 37 and raw[-1:] == b"\n")
    return request._boot(raw[:-1].decode("ascii"))


def _peer(connection):
    _require(type(connection) is socket.socket and hasattr(socket, "SO_PEERCRED")
        and hasattr(socket, "SO_DOMAIN"))
    descriptor = socket.socket.fileno(connection)
    _require(type(descriptor) is int and descriptor >= 0
        and connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
        and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
        and connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0)
    connection.getpeername()
    metadata = os.fstat(descriptor)
    uid, gid, pid = transport._peer_identity(connection)
    _require(type(uid) is int and 0 <= uid <= 0xFFFFFFFF
        and type(gid) is int and 0 <= gid <= 0xFFFFFFFF
        and type(pid) is int and 1 <= pid <= 2**31 - 1)
    return descriptor, metadata.st_dev, metadata.st_ino, uid, gid, pid


def _pins(configured, work):
    pages.configuration._snapshot(configured)
    work.charge(input_bytes=8192, json_nodes=256)
    return {"configurationDigest": configured.configuration_digest,
        "generationSequence": configured.generation_sequence, "generationDigest": configured.generation_digest,
        "verifierIdentity": dict(zip(_IDENTITY_FIELDS, configured.verifier_identity, strict=True)),
        "verifierSpkiDigest": configured.verifier_spki_digest,
        "plannerIdentity": dict(zip(_IDENTITY_FIELDS, configured.planner_identity, strict=True)),
        "plannerSpkiDigest": configured.planner_spki_digest}


class _Caller:
    """Fixed process/peer metadata; native observations do not spend proof work."""

    def __init__(self, process, local_role, connection, window, deadline, check, work):
        from catchplate import authority_service as service

        _require(type(work) is _ValidationWork and callable(check)
            and type(process) is service.AuthorityProcess
            and process.role_name == local_role
            and process.process_mode == "policy-authority-" + local_role
            and type(process.configuration) is service.MeasuredConfiguration)
        work.charge(input_bytes=65536, json_nodes=2048)
        self.process, self.role, self.connection = process, local_role, connection
        self.window = clock._validate(window)
        request.source.shape._integer(deadline, minimum=1)
        _require(self.window[2] < deadline)
        self.deadline, self.callback, self.parent = min(deadline, self.window[4]), check, work
        self.expires = self.window[0] + self.deadline - self.window[1]
        self.configuration = process.configuration
        self.payload, self.runtime = self.configuration.payload, self.configuration.runtime_role_identities
        self.key, self.identity = process.signing_key, (os.getpid(), threading.get_ident())
        self.limits = work.limits
        self.bounds = self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes
        self.previous = work.hash_work, work.input_bytes, work.json_nodes
        self.failed = self.busy = False
        self.configured = self.check_owner = self.selection = None
        self.peer = None
        # Capture static UID/GID values before any launch/key/native callback;
        # actual configuration capture below repeats its complete commitment.
        role = self.payload["roles"]["verifier"]
        _require(type(role) is dict)
        self.peer_role = role
        self.peer_ids = role["serviceUid"], role["serviceGid"]
        for value in self.peer_ids:
            request.source.shape._integer(value, 0xFFFFFFFF, minimum=1)
        self.held = (process, local_role, connection, self.window, self.deadline, self.expires, check, work,
            self.configuration, self.payload, self.runtime, self.key, self.identity,
            self.limits, self.bounds, self.peer_role, self.peer_ids)
        self.local()
        if local_role == "planner":
            self.peer = evidence.production._callback(work, lambda: _peer(connection))
            _require(self.peer[3:5] == self.peer_ids)
        else:
            _require(local_role == "verifier" and connection is None)
        self.boot = evidence.production._callback(work, _boot_id)
        self.local()
        configured, check_owner = pages._configured_on_work(process, local_role=local_role, work=work)
        self.configured, self.check_owner = configured, check_owner
        self.selection = pages.configuration._snapshot(configured)
        _require(self.window[5] <= configured.maximum_age_ns
            and self.window[6] <= configured.maximum_clock_skew_ns)
        self.check(work)

    def local(self):
        evidence.capture._SharedLedger(self.parent)
        _require(not self.failed and self.identity == (os.getpid(), threading.get_ident())
            and self.process.configuration is self.configuration
            and self.configuration.payload is self.payload
            and self.configuration.runtime_role_identities is self.runtime
            and self.process.signing_key is self.key
            and self.process.role_name == self.role
            and self.process.process_mode == "policy-authority-" + self.role
            and self.payload["roles"]["verifier"] is self.peer_role
            and all(type(self.peer_role[name]) is int and self.peer_role[name] == value
                for name, value in zip(("serviceUid", "serviceGid"), self.peer_ids, strict=True))
            and self.parent.limits is self.limits
            and (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes) == self.bounds)
        _require(all(actual is original for actual, original in zip(
            (self.process, self.role, self.connection, self.window, self.deadline, self.expires, self.callback, self.parent,
                self.configuration, self.payload, self.runtime, self.key, self.identity,
                self.limits, self.bounds, self.peer_role, self.peer_ids), self.held, strict=True)))
        actual = self.parent.hash_work, self.parent.input_bytes, self.parent.json_nodes
        _require(all(type(value) is int and before <= value <= maximum
            for before, value, maximum in zip(self.previous, actual, self.bounds, strict=True)))
        self.previous = actual
        if self.configured is not None:
            _require(pages.configuration._snapshot(self.configured) is self.selection)

    def check(self, work):
        try:
            _require(type(work) is _ValidationWork and not self.busy)
            self.busy = True
            self.local()
            if self.check_owner is not None:
                _require(evidence.production._callback(work, lambda: self.check_owner(work)) is None)
            _require(clock._check_on_work(self.window, work=work) < self.expires)
            evidence.production._callback(work, lambda: pages.wire.transport._deadline(self.deadline))
            if self.connection is not None:
                _require(evidence.production._callback(work, lambda: _peer(self.connection)) == self.peer)
            _require(evidence.production._callback(work, lambda: self.callback(work)) is None)
            self.local()
            _require(clock._check_on_work(self.window, work=work) < self.expires)
            evidence.production._callback(work, lambda: pages.wire.transport._deadline(self.deadline))
            if self.connection is not None:
                _require(evidence.production._callback(work, lambda: _peer(self.connection)) == self.peer)
            self.local()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False


def sign_request_on_work(process, *, request_bytes, business_before_roots,
        authorization_before_roots, expected_counted_heads, live_window,
        original_deadline_ns, check, work):
    """Actual verifier signer, with source originals owned before callbacks."""
    _owned_request, business, authorization, heads = request._inputs(request_bytes,
        business_before_roots, authorization_before_roots, expected_counted_heads, work)
    # Keep the exact immutable request wire; no request re-signing/rewriting.
    caller = _Caller(process, "verifier", None, live_window, original_deadline_ns, check, work)
    pins = _pins(caller.configured, work)
    caller.check(work)
    result = request.sign_request(request_bytes=request_bytes, business_before_roots=business,
        authorization_before_roots=authorization, expected_counted_heads=heads, pins=pins,
        verifier_private_key=caller.configured.private_key,
        verifier_public_key=caller.configured.verifier_public_key,
        original_window=caller.window, original_deadline_ns=original_deadline_ns,
        sender_process_id=caller.identity[0], sender_boot_id=caller.boot, work=work)
    caller.check(work)
    return result


class _RequestOwner:
    """Entered same-call owner only; no entrypoint accepts this as authority."""

    def __init__(self, caller, verified, pins, raw2):
        self.caller, self.verified, self.pins, self.raw2 = caller, verified, pins, raw2
        self.original = verified.original_window
        self.original_deadline = verified.payload["originalDeadlineNs"]
        self._deadline_ns = min(caller.deadline, self.original_deadline)
        # Processing bounds only: retain both independently observed brackets
        # and the signed original interval. Never rewrite parent/control times.
        self._epoch_bound = min(verified.payload["expiresAtEpochNs"], caller.window[3],
            caller.window[0] + self._deadline_ns - caller.window[1])
        self.held = (caller, verified, pins, raw2, self.original, self.original_deadline,
            self._deadline_ns, self._epoch_bound)
        self.active, self.used, self.failed = True, False, False

    @property
    def deadline_ns(self):
        self._local()
        return self._deadline_ns

    def _local(self):
        _require(self.active and not self.failed and all(actual is original
            for actual, original in zip((self.caller, self.verified, self.pins, self.raw2,
                self.original, self.original_deadline, self._deadline_ns, self._epoch_bound),
                self.held, strict=True)))
        self.caller.local()

    def check(self, work):
        try:
            self._local()
            _require(request._live(self.original, self.caller.window,
                self.original_deadline, work) < self._epoch_bound)
            self.caller.check(work)
            _require(request._live(self.original, self.caller.window,
                self.original_deadline, work) < self._epoch_bound)
            self._local()
        except BaseException:
            self.failed = True
            raise

    def produce(self, *, work):
        from catchplate import authority_service as service
        from catchplate import authority_jit_compound_production as production

        try:
            self._local()
            _require(not self.used and work is self.caller.parent)
            self.used = True
            self.check(work)
            payload = self.verified.payload
            work.charge(input_bytes=32768, json_nodes=1024)
            business, authorization, heads = (tuple(payload[name]) for name in (
                "businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads"))

            def current(stage):
                _require(type(stage) in (production._ProductionStage, request.parent.compound._Stage))
                self.check(stage.work)

            produced = service.AuthorityProcess._produce_jit_compound(self.caller.process,
                request=self.verified.request, business_before_roots=business,
                authorization_before_roots=authorization, expected_counted_heads=heads,
                live_window=self.original, original_deadline_ns=self.original_deadline,
                check=current, work=work, processing_owner=self)
            self.check(work)
            _require(type(produced) is production.ProducedJitCompoundPlan
                and type(produced.verified) is request.parent.VerifiedJitCompoundPlan)
            actual = produced.verified
            work.charge(input_bytes=512, json_nodes=16)
            originals = actual.envelope_bytes, actual.request_bytes, actual.context_bytes, actual.manifest_bytes
            request.parent._same_bytes(originals[1], self.raw2[1], work)
            request._join_parent(originals, payload, self.pins,
                self.caller.configured.planner_public_key, work)
            self.check(work)
            return originals
        except BaseException:
            self.failed = True
            raise


def _page_bounds(owner, *, original_window, original_deadline_ns, work):
    """Narrow nested custody processing from this entered same-call owner.

    This is not a caller clock/callback or successful authority DTO. The page
    stack must retain the exact owner and call this around actual native I/O;
    only its child authorization expiry may narrow, never parent/control bytes.
    """
    _require(type(owner) is _RequestOwner)
    try:
        owner._local()
        _require(type(work) is _ValidationWork and original_window is owner.original
            and type(original_deadline_ns) is int
            and original_deadline_ns == owner.original_deadline)
        owner.check(work)
        return owner._deadline_ns, owner._epoch_bound
    except BaseException:
        owner.failed = True
        raise


@contextmanager
def receive_request_on_work(process, connection, *, control_bytes, request_bytes,
        receiver_window, transport_deadline_ns, check, work):
    """Borrow the genuine peer/window until the caller's final response send.

    The caller must have admitted the peer before framing and supply its actual
    independent receiver sample. Native socket/boot observations are fixed OS
    identity checks, not proof/JSON accounting. Raw wire accounting stays with
    the transport. All signature/output graph work uses the supplied remainder.
    """
    raw2 = request._raw(control_bytes, request.MAX_CONTROL_BYTES), request._raw(request_bytes, request.MAX_REQUEST_BYTES)
    caller = _Caller(process, "planner", connection, receiver_window, transport_deadline_ns, check, work)
    pins = _pins(caller.configured, work)
    caller.check(work)
    verified = request.verify_request(control_bytes=raw2[0], request_bytes=raw2[1], pins=pins,
        verifier_public_key=caller.configured.verifier_public_key, receiver_window=caller.window,
        expected_sender_process_id=caller.peer[5], expected_boot_id=caller.boot, work=work)
    caller.check(work)
    work.charge(input_bytes=4096, json_nodes=128)
    owner = _RequestOwner(caller, verified, pins, raw2)
    try:
        owner.check(work)
        yield owner
        owner.check(work)
    except BaseException:
        owner.failed = True
        raise
    finally:
        owner.active = False
