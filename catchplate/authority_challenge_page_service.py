"""Measured role ingress for signed, opaque maintenance-page custody.

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

from catchplate import authority_challenge_page_actions as actions
from catchplate import authority_challenge_page_configuration as configuration
from catchplate import authority_challenge_page_wire as wire
from catchplate import authority_webauthn_transition_service as measured
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


OPERATION = "webauthn.challenge.maintain"
_WRITER_DSN = "CATCHPLATE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
evidence, clock = wire.evidence, wire.authorization.clock


class ChallengePageServiceError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePageServiceError("maintenance page lost its measured service owner")


def _configured_on_work(process, *, local_role, work):
    """Own the real admitted launch, descriptor and role pins, without I/O."""
    from catchplate import authority_service as service

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
        _require(self._identity == (os.getpid(), threading.get_ident())
            and self._configured is self._held[0] and self._check_owner is self._held[1]
            and self._window is self._held[2])
        configuration._snapshot(self._configured)
        self._check_owner(work)
        clock._check_on_work(self._window, work=work)

    def retain(self, parent_digest, manifest_digest, context, phase, kind,
            index_id, ordinal, body, descriptor, stage):
        """Exact producer callback; context comes from its genuine SQL pass."""
        from catchplate import authority_challenge_compound as compounds

        _require(type(stage) is compounds._Stage and self._configured.local_role == "planner")
        stage.check()
        _PageCaller._live(self, stage.work)
        encoded = wire.control.encode_control(action="persist", parent_plan_digest=parent_digest,
            maintenance_manifest_digest=manifest_digest, context=context, phase_ordinal=phase,
            page_kind=kind, index_id=index_id, page_ordinal=ordinal, descriptor=descriptor, work=stage.work)
        result = actions.persist_page(configuration=self._configured, control_bytes=encoded,
            body_bytes=body, live_window=self._window, work=stage.work,
            check=lambda: _PageCaller._live(self, stage.work))
        _require(type(result) is wire.PageExchange and type(result.body_bytes) is bytes)
        # The actual wire/action independently requires literal persistence
        # echo. No transport observation is returned as a retained proof.
        _PageCaller._live(self, stage.work)
        stage.check()

    def reader(self, *, context, work):
        """Own the independently held parent context, not a replay verdict."""
        _require(self._configured.local_role in ("planner", "verifier"))
        _PageCaller._live(self, work)
        owned = wire.control.binding.manifests._context(context, work)
        context_bytes = work.wire(owned)

        def read(parent_digest, manifest_digest, phase, kind, index_id, ordinal, stage):
            from catchplate import authority_challenge_compound as compounds

            _require(type(stage) is compounds._Stage)
            stage.check()
            _PageCaller._live(self, stage.work)
            # Hold only canonical immutable context bytes between stages.
            # Each stage owns its bounded decode; no callback can mutate the
            # parent verifier's graph or select a different cutoff/head.
            selected = evidence.wire._decode_object(context_bytes, work=stage.work,
                maximum_bytes=wire.control.MAX_CONTROL_BYTES,
                maximum_nodes=wire.control.MAX_CONTROL_NODES,
                maximum_depth=wire.control.MAX_CONTROL_DEPTH)
            encoded = wire.control.encode_control(action="read", parent_plan_digest=parent_digest,
                maintenance_manifest_digest=manifest_digest, context=selected, phase_ordinal=phase,
                page_kind=kind, index_id=index_id, page_ordinal=ordinal, descriptor=None, work=stage.work)
            returned = actions.read_page(configuration=self._configured, control_bytes=encoded,
                live_window=self._window, work=stage.work,
                check=lambda: _PageCaller._live(self, stage.work))
            _require(type(returned) is wire.PageExchange and type(returned.body_bytes) is bytes)
            _PageCaller._live(self, stage.work)
            stage.check()
            return returned.body_bytes

        return read


def _caller_on_work(process, *, live_window, work):
    """Configure real planner/verifier page calls under an existing window."""
    from catchplate import authority_service as service

    _require(type(process) is service.AuthorityProcess and process.role_name in ("planner", "verifier"))
    configured, check = _configured_on_work(process, local_role=process.role_name, work=work)
    window = clock._validate(live_window)
    _require(window[3] - window[0] <= configured.maximum_age_ns
        and window[6] <= configured.maximum_clock_skew_ns)
    result = object.__new__(_PageCaller)
    object.__setattr__(result, "_configured", configured)
    object.__setattr__(result, "_check_owner", check)
    object.__setattr__(result, "_window", window)
    object.__setattr__(result, "_held", (configured, check, window))
    object.__setattr__(result, "_identity", (os.getpid(), threading.get_ident()))
    _PageCaller._live(result, work)
    return result


def serve_process(process, connection, *, prefix, deadline_ns):
    """Called solely after the real AuthorityServer's exact peer admission."""
    from catchplate import authority_service as service

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
    effective_deadline = min(deadline_ns, selected["context"]["originalDeadlineNs"])
    configured, check_owner = _configured_on_work(process, local_role=process.role_name, work=work)
    window = _receiving_window(deadline_ns=effective_deadline, configured=configured, work=work)

    def current():
        check_owner(work)
        clock._check_on_work(window, work=work)
        evidence.production._callback(work, lambda: wire.transport._deadline(effective_deadline))

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
    metrics = evidence.production._callback(work, lambda: wire.transport._send_response(connection,
        control_bytes=response, body_bytes=body, deadline_ns=effective_deadline))
    _require(type(metrics) is wire.transport.FrameMetrics and metrics == expected_metrics)
    current()
