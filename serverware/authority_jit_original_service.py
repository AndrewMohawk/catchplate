"""Measured role ingress for signed, opaque JIT original-page custody.

The listener has already admitted the configured peer before reading a prefix.
Planner ingress accepts only verifier-signed reads and relays them to the
writer; writer ingress accepts only planner-signed reads/persistence. Neither
the returned page nor its digest is a proof result or current-root authority.

The receiving clock bracket limits this one transport, never replaces the
original page context deadline or the original signed issue/expiry. Each call
owns one fixed allowance after complete bounded framing. No connection,
listener, signer, role, key, or database identity is selected by incoming data.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from serverware import authority_jit_original_actions as actions
from serverware import authority_jit_original_configuration as configuration
from serverware import authority_jit_original_wire as wire
from serverware import authority_webauthn_transition_service as measured
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


OPERATION = "jit.assertion.issue"
_WRITER_DSN = "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
evidence, clock = wire.evidence, wire.authorization.clock


class JitOriginalServiceError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalServiceError("JIT original page lost its measured service owner")


def _configured_on_work(process, *, local_role, work):
    """Own the real admitted launch, descriptor and role pins, without I/O."""
    from serverware import authority_service as service

    _require(type(local_role) is str and local_role in ("planner", "verifier", "planner-writer")
        and type(process) is service.AuthorityProcess
        and process.role_name == local_role
        and process.process_mode == "policy-authority-" + local_role
        and type(process.configuration) is service.MeasuredConfiguration)
    original = process.configuration
    original_payload, original_runtime = original.payload, original.runtime_role_identities
    original_key = process.signing_key if local_role != "planner-writer" else None
    owned, digest, generation, dsn, private, runtime = measured._measured_context_on_work(
        process, role=local_role, signing=local_role != "planner-writer",
        read_descriptor=_WRITER_DSN if local_role == "planner-writer" else None, work=work)
    configured = configuration._from_configuration_on_work(local_role=local_role,
        payload=owned, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, private_key=private, writer_dsn=dsn, work=work)
    # The genuine mapper above joined the complete nested launch document.
    # Pin its actual process owner as well as every generation identity scalar;
    # neutral driver guards must not deep-copy a second configuration graph.
    original_generation = service.authority_launch_guard._generation
    fields = ("schema", "sequence", "digest", "predecessorDigest",
        "minimumRollbackSequence", "operationManifestDigest", "configurationBindingDigest")
    held_generation = tuple((name, type(generation[name]), generation[name]) for name in fields)
    _require(all(kind in (str, int, type(None)) for _name, kind, _value in held_generation))
    identity = os.getpid(), threading.get_ident()

    def check_on_work(current_work):
        evidence.capture._SharedLedger(current_work)
        _require(identity == (os.getpid(), threading.get_ident())
            and process.configuration is original
            and original.payload is original_payload
            and original.runtime_role_identities is original_runtime
            and type(original.digest) is str and original.digest == digest
            and process.role_name == local_role
            and process.process_mode == "policy-authority-" + local_role
            and (local_role == "planner-writer" or process.signing_key is original_key))
        evidence.production._callback(current_work,
            lambda: service.authority_launch_guard.require_active(local_role))
        observed = service.authority_launch_guard._generation
        _require(observed is original_generation)
        _require(all(name in observed and type(observed[name]) is kind and observed[name] == value
            for name, kind, value in held_generation))
        _require(process.configuration is original and original.digest == digest)

    check_on_work(work)
    return configured, check_on_work


def _receiving_window(*, deadline_ns, configured, work):
    """One real bracket, clipped by this already owned socket deadline."""
    _require(type(deadline_ns) is int and 0 < deadline_ns < 2**63)
    configuration._snapshot(configured)
    before, epoch, after = clock._sample_on_work(work)
    monotonic_deadline = min(deadline_ns, before + configured.maximum_age_ns)
    epoch_deadline = epoch + monotonic_deadline - before
    # No caller clock, fabricated sample, or new relative transport timeout.
    return clock._validate((epoch, before, after, epoch_deadline, monotonic_deadline,
        configured.maximum_age_ns, configured.maximum_clock_skew_ns))


def _original_interval_on_work(window, issued, expires, deadline_ns, work):
    """Retain authenticated scalars through final response, not a new window."""
    _require(type(issued) is int and type(expires) is int and type(deadline_ns) is int
        and 0 < issued < expires and expires - issued <= window[5])
    epoch = clock._check_on_work(window, work=work)
    _require(issued <= epoch + window[6] and epoch - issued <= window[5] and epoch < expires)
    # Use the actual existing receiving bracket, never now plus a duration.
    effective = min(deadline_ns, window[4], window[1] + expires - window[0])
    evidence.production._callback(work, lambda: wire.transport._deadline(effective))
    return effective


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class _PageCaller:
    """Borrow the actual process/configuration and original caller window."""

    _configured: object
    _check_owner: object
    _window: tuple
    _held: tuple
    _identity: tuple

    def _live(self, work):
        _require(type(self) is _PageCaller)
        _require(type(self._held) is tuple and len(self._held) in (3, 4))
        _require(self._identity == (os.getpid(), threading.get_ident())
            and self._configured is self._held[0] and self._check_owner is self._held[1]
            and self._window is self._held[2])
        configuration._snapshot(self._configured)
        self._check_owner(work)
        clock._check_on_work(self._window, work=work)
        if len(self._held) == 4:
            from serverware.authority_jit_compound_request_service import _RequestOwner, _page_bounds

            processing = self._held[3]
            _require(type(processing) is _RequestOwner)
            _page_bounds(processing, original_window=self._window,
                original_deadline_ns=processing.original_deadline, work=work)

    def persist(self, *, context, body_bytes, descriptor, original_deadline_ns, work):
        """One fixed measured planner request, never caller-selected SQL."""
        _require(self._configured.local_role == "planner")
        _PageCaller._live(self, work)
        encoded = wire.control.encode_control(action="persist", context=context,
            original_deadline_ns=original_deadline_ns, descriptor=descriptor, work=work)
        returned = actions.persist_page(configuration=self._configured, control_bytes=encoded,
            body_bytes=body_bytes, live_window=self._window, work=work,
            check=lambda: _PageCaller._live(self, work),
            processing_owner=self._held[3] if len(self._held) == 4 else None)
        _require(type(returned) is wire.PageExchange and type(returned.body_bytes) is bytes)
        # The actual exchange requires a literal echo after writer closure.
        work.charge(input_bytes=len(body_bytes) + len(returned.body_bytes))
        _require(returned.body_bytes == body_bytes)
        _PageCaller._live(self, work)

    def read(self, *, context, original_deadline_ns, work):
        """Raw storage framing only; the parent must replay every original."""
        _require(self._configured.local_role in ("planner", "verifier"))
        _PageCaller._live(self, work)
        encoded = wire.control.encode_control(action="read", context=context,
            original_deadline_ns=original_deadline_ns, descriptor=None, work=work)
        returned = actions.read_page(configuration=self._configured, control_bytes=encoded,
            live_window=self._window, work=work, check=lambda: _PageCaller._live(self, work),
            processing_owner=self._held[3] if len(self._held) == 4 else None)
        _require(type(returned) is wire.PageExchange and type(returned.body_bytes) is bytes)
        _PageCaller._live(self, work)
        return returned.body_bytes


def _caller_on_work(process, *, live_window, work, processing_owner=None):
    """Configure real planner/verifier page calls under an existing window."""
    from serverware import authority_service as service

    _require(type(process) is service.AuthorityProcess and process.role_name in ("planner", "verifier"))
    window = clock._validate(live_window)
    if processing_owner is not None:
        from serverware.authority_jit_compound_request_service import _RequestOwner, _page_bounds

        _require(type(processing_owner) is _RequestOwner
            and processing_owner.caller.process is process and process.role_name == "planner")
        _page_bounds(processing_owner, original_window=window,
            original_deadline_ns=processing_owner.original_deadline, work=work)
    configured, check = _configured_on_work(process, local_role=process.role_name, work=work)
    _require(window[3] - window[0] <= configured.maximum_age_ns
        and window[6] <= configured.maximum_clock_skew_ns)
    result = object.__new__(_PageCaller)
    object.__setattr__(result, "_configured", configured)
    object.__setattr__(result, "_check_owner", check)
    object.__setattr__(result, "_window", window)
    object.__setattr__(result, "_held", (configured, check, window) if processing_owner is None
        else (configured, check, window, processing_owner))
    object.__setattr__(result, "_identity", (os.getpid(), threading.get_ident()))
    _PageCaller._live(result, work)
    return result


def serve_process(process, connection, *, prefix, deadline_ns):
    """Called solely after the real AuthorityServer's exact peer admission."""
    from serverware import authority_service as service

    _require(type(process) is service.AuthorityProcess
        and process.role_name in ("planner", "planner-writer")
        and process.process_mode == "policy-authority-" + process.role_name)
    request = wire.transport._recv_request(connection, prefix=prefix, deadline_ns=deadline_ns)
    _require(type(request) is wire.transport.RawRequest
        and type(request.control_bytes) is bytes
        and 2 <= len(request.control_bytes) <= wire.MAX_REQUEST_BYTES)
    if process.role_name == "planner":
        _require(request.action == "read" and request.body_bytes is None)
    work = _ValidationWork(QueryReadValidationLimits())
    work.charge(input_bytes=request.metrics.wire_bytes)
    originals = wire.decode_request(request.control_bytes, expected_action=request.action, work=work)
    selected = wire.control.decode_control(originals.control_bytes,
        expected_action=request.action, work=work)
    # The raw context cannot extend the actual accepted socket's deadline.
    # It can only narrow processing, before independent signature admission.
    effective_deadline = min(deadline_ns, selected["originalDeadlineNs"])
    configured, check_owner = _configured_on_work(process, local_role=process.role_name, work=work)
    window = _receiving_window(deadline_ns=effective_deadline, configured=configured, work=work)
    # Actions retain this interval through relay/storage; independently admit
    # the actual original here too so final encoding/send remains inside it.
    signed = actions._verify(configured,
        role="verifier" if process.role_name == "planner" else "planner", action=request.action,
        authorization_bytes=originals.authorization_bytes, control_bytes=originals.control_bytes,
        window=window, work=work)
    issued, expires = signed.issued_at_epoch_ns, signed.expires_at_epoch_ns
    effective_deadline = _original_interval_on_work(window, issued, expires, effective_deadline, work)

    def current():
        check_owner(work)
        _require(_original_interval_on_work(window, issued, expires, effective_deadline, work)
            == effective_deadline)

    current()
    if process.role_name == "planner":
        returned = actions.relay_read(configuration=configured,
            authorization_bytes=originals.authorization_bytes, control_bytes=originals.control_bytes,
            live_window=window, work=work, check=current)
        _require(type(returned) is wire.PageExchange)
        body = returned.body_bytes
    else:
        body = actions.receive_writer(configuration=configured, action=request.action,
            authorization_bytes=originals.authorization_bytes, control_bytes=originals.control_bytes,
            body_bytes=request.body_bytes, live_window=window, work=work, check=current)
    current()
    response = wire.encode_response(authorization_bytes=originals.authorization_bytes,
        control_bytes=originals.control_bytes, body_bytes=body, work=work)
    expected_metrics = wire.transport._metrics(len(response), len(body), 16)
    work.charge(input_bytes=expected_metrics.wire_bytes)
    current()
    metrics = evidence.production._callback(work, lambda: wire.transport._send_response(connection,
        control_bytes=response, body_bytes=body, deadline_ns=effective_deadline))
    _require(type(metrics) is wire.transport.FrameMetrics and metrics == expected_metrics)
    current()
