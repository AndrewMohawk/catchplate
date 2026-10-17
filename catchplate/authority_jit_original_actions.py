"""Source-fixed signed page hops under admitted immutable process selection.

The measured service owns configuration/peer admission. These actions repeat
its immutable selection, sign or verify actual originals, and use only the
fixed planner/writer topology. They open no clock window or work allowance.
Every path is literal jit.assertion.issue; application jit.decide is distinct.

Relay signatures preserve the verifier's original issue/expiry/context deadline
exactly. Actual receiving clocks are never shifted to manufacture that window;
local checks and I/O use the earlier original/receiver bound. Raw returned page
bytes remain untrusted until independent whole-parent proof replay.
"""
from __future__ import annotations

import os
import threading
import time

from catchplate import authority_jit_original_authorization as authorization
from catchplate import authority_jit_original_configuration as selections
from catchplate import authority_jit_original_wire as wire
from catchplate.authority_query_read_work import _ValidationWork


OPERATION = "jit.assertion.issue"
evidence, clock = authorization.evidence, authorization.clock


class JitOriginalActionError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalActionError("JIT original page action differs from its original role custody")


def _start(configuration, *, roles, action, control_bytes, live_window, work, check,
        processing_owner=None):
    original = selections._snapshot(configuration)
    _require(configuration.local_role in roles and type(work) is _ValidationWork and callable(check))
    evidence.capture._SharedLedger(work)
    selected = wire.control.decode_control(control_bytes, expected_action=action, work=work)
    _require(selected["context"]["operation"] == OPERATION)
    authorization.parent._same(selected["context"]["configuration_digest"],
        configuration.configuration_digest, work)
    window = clock._validate(live_window)
    _require(window[3] - window[0] <= configuration.maximum_age_ns
        and window[6] <= configuration.maximum_clock_skew_ns)
    deadline = min(selected["originalDeadlineNs"], window[4])
    processing_epoch = None
    if processing_owner is not None:
        from catchplate.authority_jit_compound_request_service import _page_bounds

        processing_mono, processing_epoch = _page_bounds(processing_owner,
            original_window=window, original_deadline_ns=selected["originalDeadlineNs"], work=work)
        deadline = min(deadline, processing_mono)
    identity = os.getpid(), threading.get_ident()
    limits = work.limits
    bounds = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    previous_work = work.hash_work, work.input_bytes, work.json_nodes
    previous_time = 0
    busy = failed = False
    signed_interval = None

    def local():
        nonlocal previous_work, previous_time
        _require(not failed and selections._snapshot(configuration) is original
            and identity == (os.getpid(), threading.get_ident()) and work.limits is limits
            and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == bounds)
        values = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and before <= value <= maximum
            for before, value, maximum in zip(previous_work, values, bounds, strict=True)))
        epoch = clock._check_on_work(window, work=work)
        if processing_epoch is not None:
            _require(epoch < processing_epoch)
        if signed_interval is not None:
            issued, expires = signed_interval
            _require(issued <= epoch + window[6] and epoch - issued <= window[5] and epoch < expires)
        now = evidence.production._callback(work, time.monotonic_ns)
        _require(type(now) is int and previous_time <= now < deadline)
        previous_work, previous_time = values, now

    def guard():
        nonlocal busy, failed
        try:
            local()
            _require(not busy)
            busy = True
            _require(evidence.production._callback(work, check) is None)
            if processing_owner is not None:
                _page_bounds(processing_owner, original_window=window,
                    original_deadline_ns=selected["originalDeadlineNs"], work=work)
            local()
        except BaseException:
            failed = True
            raise
        finally:
            busy = False

    def bind_interval(issued, expires):
        nonlocal signed_interval, deadline
        _require(signed_interval is None and type(issued) is int and type(expires) is int
            and 0 < issued < expires and expires - issued <= configuration.maximum_age_ns)
        signed_interval = issued, expires
        deadline = min(deadline, window[1] + expires - window[0])
        guard()
        return deadline

    guard()
    return selected, window, guard, bind_interval


def _identity(configuration, role, work):
    values = configuration.planner_identity if role == "planner" else configuration.verifier_identity
    work.prepare_copy((selections._IDENTITY_FIELDS, values))
    return dict(zip(selections._IDENTITY_FIELDS, values, strict=True))


def _sign(configuration, *, action, control_bytes, window, work, processing_owner=None):
    role = configuration.local_role
    _require(role in ("planner", "verifier"))
    return authorization.sign_control(control_bytes=control_bytes, action=action,
        signer_role=role, signer_identity=_identity(configuration, role, work),
        signer_spki_digest=(configuration.planner_spki_digest if role == "planner"
            else configuration.verifier_spki_digest), signer_private_key=configuration.private_key,
        signer_public_key=(configuration.planner_public_key if role == "planner"
            else configuration.verifier_public_key), configuration_digest=configuration.configuration_digest,
        live_window=window, work=work, processing_owner=processing_owner)


def _verify(configuration, *, role, action, authorization_bytes, control_bytes, window, work):
    observed = authorization.verify_control(authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, action=action, expected_role=role,
        expected_identity=_identity(configuration, role, work),
        expected_spki_digest=(configuration.planner_spki_digest if role == "planner"
            else configuration.verifier_spki_digest), public_key=(configuration.planner_public_key
            if role == "planner" else configuration.verifier_public_key),
        configuration_digest=configuration.configuration_digest, live_window=window, work=work)
    _require(observed.control["context"]["operation"] == OPERATION
        and 0 < observed.expires_at_epoch_ns - observed.issued_at_epoch_ns <= configuration.maximum_age_ns)
    return observed


def _exchange(configuration, *, endpoint, action, authorization_bytes, control_bytes,
        body_bytes, selected, window, work, guard, local_deadline_ns=None, processing_owner=None):
    guard()
    if processing_owner is not None:
        from catchplate.authority_jit_compound_request_service import _page_bounds

        bounded, _epoch = _page_bounds(processing_owner, original_window=window,
            original_deadline_ns=selected["originalDeadlineNs"], work=work)
        local_deadline_ns = bounded if local_deadline_ns is None else min(local_deadline_ns, bounded)
    path, uid, gid = endpoint
    result = wire.exchange(path=path, action=action, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, body_bytes=body_bytes,
        original_deadline_ns=selected["originalDeadlineNs"],
        transport_deadline_ns=(window[4] if local_deadline_ns is None else min(window[4], local_deadline_ns)),
        expected_peer_uid=uid, expected_peer_gid=gid, work=work, processing_owner=processing_owner)
    guard()
    _require(type(result) is wire.PageExchange)
    return result


def persist_page(*, configuration, control_bytes, body_bytes, live_window, work, check,
        processing_owner=None) -> wire.PageExchange:
    selected, window, guard, bind_interval = _start(configuration, roles=("planner",), action="persist",
        control_bytes=control_bytes, live_window=live_window, work=work, check=check,
        processing_owner=processing_owner)
    wire.control._body(selected, body_bytes, work)
    signed = _sign(configuration, action="persist", control_bytes=control_bytes, window=window,
        work=work, processing_owner=processing_owner)
    guard()
    return _exchange(configuration, endpoint=configuration.writer_endpoint, action="persist",
        authorization_bytes=signed, control_bytes=control_bytes, body_bytes=body_bytes,
        selected=selected, window=window, work=work, guard=guard, processing_owner=processing_owner)


def read_page(*, configuration, control_bytes, live_window, work, check,
        processing_owner=None) -> wire.PageExchange:
    selected, window, guard, bind_interval = _start(configuration, roles=("planner", "verifier"), action="read",
        control_bytes=control_bytes, live_window=live_window, work=work, check=check,
        processing_owner=processing_owner)
    signed = _sign(configuration, action="read", control_bytes=control_bytes, window=window,
        work=work, processing_owner=processing_owner)
    guard()
    endpoint = (configuration.writer_endpoint if configuration.local_role == "planner"
        else configuration.planner_endpoint)
    return _exchange(configuration, endpoint=endpoint, action="read", authorization_bytes=signed,
        control_bytes=control_bytes, body_bytes=None, selected=selected, window=window, work=work,
        guard=guard, processing_owner=processing_owner)


def _relay_authorization(configuration, *, authorization_bytes, control_bytes, window, work, guard, bind_interval):
    """The actual verifier signature, not caller-supplied claims, supplies time."""
    observed = _verify(configuration, role="verifier", action="read", authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, window=window, work=work)
    local_deadline = bind_interval(observed.issued_at_epoch_ns, observed.expires_at_epoch_ns)
    guard()
    pins = authorization._pins("planner", _identity(configuration, "planner", work),
        configuration.planner_spki_digest, configuration.configuration_digest, work)
    evidence.keys._public_binding(configuration.planner_public_key, configuration.planner_spki_digest, work)
    evidence.keys._pair_on_work(configuration.private_key, configuration.planner_public_key, work)
    work.charge(input_bytes=8192, json_nodes=256)
    payload = {"schema": authorization.SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
        "role": "planner", "identity": pins[1], "spkiDigest": pins[2], "configurationDigest": pins[3],
        "controlDigest": evidence.plan._frame(authorization.CONTROL_DOMAIN, (control_bytes,), work),
        "controlByteCount": len(control_bytes), "issuedAtEpochNs": observed.issued_at_epoch_ns,
        "expiresAtEpochNs": observed.expires_at_epoch_ns, "originalDeadlineNs": observed.original_deadline_ns}
    authorization._bind(payload, control_bytes, observed.control, pins, window, work)
    guard()
    signed = authorization._sign(payload, configuration.private_key, configuration.planner_public_key, work)
    authorization._bind(payload, control_bytes, observed.control, pins, window, work)
    guard()
    return signed, local_deadline


def relay_read(*, configuration, authorization_bytes, control_bytes, live_window, work, check) -> wire.PageExchange:
    selected, window, guard, bind_interval = _start(configuration, roles=("planner",), action="read",
        control_bytes=control_bytes, live_window=live_window, work=work, check=check)
    signed, local_deadline = _relay_authorization(configuration, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, window=window, work=work, guard=guard, bind_interval=bind_interval)
    return _exchange(configuration, endpoint=configuration.writer_endpoint, action="read",
        authorization_bytes=signed, control_bytes=control_bytes, body_bytes=None,
        selected=selected, window=window, work=work, guard=guard, local_deadline_ns=local_deadline)


def receive_writer(*, configuration, action, authorization_bytes, control_bytes,
        body_bytes, live_window, work, check) -> bytes:
    selected, window, guard, bind_interval = _start(configuration, roles=("planner-writer",), action=action,
        control_bytes=control_bytes, live_window=live_window, work=work, check=check)
    _require(action in ("persist", "read") and (type(body_bytes) is bytes if action == "persist" else body_bytes is None))
    observed = _verify(configuration, role="planner", action=action, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, window=window, work=work)
    local_deadline = bind_interval(observed.issued_at_epoch_ns, observed.expires_at_epoch_ns)
    guard()
    work.charge(input_bytes=2048, json_nodes=32)
    arguments = dict(context=selected["context"],
        original_deadline_ns=local_deadline, check=guard, work=work)
    if action == "persist":
        result = configuration.persistence.persist(**arguments, body_bytes=body_bytes, descriptor=selected["descriptor"])
        _require(result is None)
        raw = body_bytes
    else:
        raw = configuration.persistence.read(**arguments)
    guard()
    _require(type(raw) is bytes and 2 <= len(raw) <= wire.MAX_BODY_BYTES)
    return raw
