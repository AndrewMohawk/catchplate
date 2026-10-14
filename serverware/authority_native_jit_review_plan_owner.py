"""One native-review acquisition and literal replay, not service admission.

The constructor takes independently admitted read/configuration/trust inputs;
it does not establish their cold provenance. An actual service must provide
that missing assembly before using this prerequisite. No signer, SQL writer,
commit receipt, disclosure, selector or executable registry is added here.

The source-fixed real reader closes before framing. The actual kernel then
replays decoded original bytes, including current roots, native evidence and
transient session possession. Returned immutable material is uncommitted data,
never an accepted success carrier. Replaying it requires the original token
again under the unchanged live window; it cannot support unattended recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_native_jit_review_current_read as reads
from serverware import authority_native_jit_review_plan_stream as stream
from serverware import authority_transition_native_jit_review_open as kernel
from serverware.authority_query_read_work import _ValidationWork


wire = reads.contract
MAX_REQUEST_BYTES = 64 * 1024
_READER_FIELDS = ("_operation", "_configuration", "_root_public_key", "_enrollment",
    "_client_configuration", "_pid")


class NativeJitReviewPlanOwnerError(ValueError):
    def __init__(self):
        super().__init__("Native review plan preparation is unavailable")


def _require(value):
    if not value:
        raise NativeJitReviewPlanOwnerError()


def _json_original(value, maximum, work):
    size, _nodes = work.prepare_encoding(value)
    _require(size <= maximum)
    raw = reads.core.canonical_bytes(value)
    _require(len(raw) <= maximum)
    return raw


def _json(raw, maximum, work):
    _require(type(raw) is bytes and 2 <= len(raw) <= maximum and raw.isascii())
    work.charge(input_bytes=3 * len(raw))
    value = wire.grammar.document(raw.decode("ascii"), maximum)
    work.prepare_copy(value)
    return value


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PreparedNativeJitReviewPlan:
    """Output-only literal material, deliberately unsigned and uncommitted."""

    operation: str
    request_original: bytes
    challenge_original: str
    authorization_original: str | None
    preparation_original: str | None
    read_manifest_original: bytes
    read_frames: tuple[bytes, ...]
    result_original: bytes
    mutations_original: bytes


class NativeJitReviewPlanOwner:
    """Inert explicit configuration boundary; one invocation, with no retries."""

    __slots__ = ("_reader", "_reader_pins", "_configuration_original", "_root_key",
        "_authn_original", "_trust_original", "_window", "_deadline", "_work",
        "_limits", "_identity", "_held", "_used", "_failed", "_previous", "_last_epoch", "_last_monotonic")

    def __init__(self, *, read_planner, configuration_payload, configuration_root_key,
            authn_policy, trust_policy, live_window, deadline_ns, work):
        _require(type(read_planner) is reads.NativeJitReviewCurrentReader
            and isinstance(configuration_root_key, Ed25519PublicKey)
            and type(work) is _ValidationWork and type(deadline_ns) is int and deadline_ns > 0)
        window = reads.head.clock._validate(live_window)
        pins = tuple(getattr(read_planner, name) for name in _READER_FIELDS)
        _require(pins[0] in wire.OPERATIONS and pins[-1] == os.getpid())
        reads.connection_owner._validate_configuration(pins[1])
        # Detach every mutable caller policy before any read/native/key callback.
        configuration = _json_original(configuration_payload, reads.vector.authority.MAX_REQUEST_BYTES, work)
        authn = _json_original(authn_policy, reads.vector.authority.MAX_REQUEST_BYTES, work)
        trust = _json_original(trust_policy, reads.vector.authority.MAX_REQUEST_BYTES, work)
        _require(len(configuration) + len(authn) + len(trust) <= reads.vector.authority.MAX_REQUEST_BYTES)
        self._reader, self._reader_pins = read_planner, pins
        self._configuration_original, self._root_key = configuration, configuration_root_key
        self._authn_original, self._trust_original = authn, trust
        self._window, self._deadline = window, min(deadline_ns, window[4])
        self._work, self._limits = work, reads._pin(work)[:4]
        self._previous = reads._pin(work)[4:]
        self._identity = os.getpid(), threading.get_ident()
        self._used = self._failed = False
        self._last_epoch, self._last_monotonic = window[0], window[2]
        self._held = (read_planner, pins, configuration, configuration_root_key, authn, trust,
            window, self._deadline, work, self._limits, self._identity)
        self._check()

    def _check(self):
        _require(type(self) is NativeJitReviewPlanOwner and not self._failed
            and self._identity == (os.getpid(), threading.get_ident())
            and all(actual is original for actual, original in zip(
                (self._reader, self._reader_pins, self._configuration_original, self._root_key,
                 self._authn_original, self._trust_original, self._window, self._deadline,
                 self._work, self._limits, self._identity), self._held, strict=True))
            and reads._pin(self._work)[:4] == self._limits and self._work.limits is self._limits[0]
            and all(getattr(self._reader, name) is value for name, value in
                zip(_READER_FIELDS, self._reader_pins, strict=True)))
        current = reads._pin(self._work)[4:]
        _require(all(type(value) is int and previous <= value <= maximum for previous, value, maximum
            in zip(self._previous, current, self._limits[1:], strict=True)))
        now = reads.head.clock._check_on_work(self._window, work=self._work)
        mono = time.monotonic_ns()
        _require(now >= self._last_epoch and mono >= self._last_monotonic and mono < self._deadline)
        observed = reads._pin(self._work)[4:]
        _require(all(type(value) is int and before <= value <= maximum for before, value, maximum
            in zip(current, observed, self._limits[1:], strict=True)))
        self._previous = observed
        self._last_epoch, self._last_monotonic = now, mono

    def produce(self, request, *, session_token_original, challenge_original,
            authorization_original=None, preparation_original=None):
        """Acquire through the actual reader, frame, then genuinely replay once."""
        return self._run(request, session_token_original=session_token_original,
            challenge_original=challenge_original, authorization_original=authorization_original,
            preparation_original=preparation_original, read_manifest_original=None, read_frames=None)

    def replay(self, request, *, session_token_original, challenge_original,
            read_manifest_original, read_frames, authorization_original=None, preparation_original=None):
        """Replay literal frames, not a PreparedNativeJitReviewPlan or verdict.

        This read-free entrypoint still requires fresh possession under the
        original window. It is not historical completion or retry authority.
        """
        if read_manifest_original is None or read_frames is None:
            self._failed = True
            raise NativeJitReviewPlanOwnerError()
        return self._run(request, session_token_original=session_token_original,
            challenge_original=challenge_original, authorization_original=authorization_original,
            preparation_original=preparation_original, read_manifest_original=read_manifest_original,
            read_frames=read_frames)

    def _run(self, request, *, session_token_original, challenge_original, authorization_original,
            preparation_original, read_manifest_original, read_frames):
        try:
            self._check()
            _require(not self._used)
            self._used = True  # Any accepted attempt is terminal, including malformed input.
            work, operation = self._work, self._reader_pins[0]
            request_original = _json_original(request, MAX_REQUEST_BYTES, work)
            request = _json(request_original, MAX_REQUEST_BYTES, work)
            kernel._arguments(request, operation, work)
            wire.validate_challenge_original(challenge_original)
            reads._token_digest(session_token_original, work)  # Never retained, returned or logged.
            if operation == wire.AUTHORIZE:
                _require(authorization_original is None and preparation_original is None)
            else:
                wire.validate_authorization_original(authorization_original)
                wire.validate_preparation_original(preparation_original)
            self._check()
            if read_manifest_original is None:
                _require(read_frames is None)
                originals = reads.NativeJitReviewCurrentReader.acquire(self._reader, request,
                    session_token_original=session_token_original, live_window=self._window,
                    deadline_ns=self._deadline, work=work)
                self._check()
                read_manifest_original, read_frames = stream.encode_on_work(originals,
                    operation=operation, request_digest=request["requestDigest"],
                    live_window=self._window, deadline_ns=self._deadline, work=work)
                del originals
            originals = stream.decode_on_work(read_manifest_original, read_frames,
                operation=operation, request_digest=request["requestDigest"],
                live_window=self._window, deadline_ns=self._deadline, work=work)
            self._check()
            configuration = _json(self._configuration_original, reads.vector.authority.MAX_REQUEST_BYTES, work)
            authn = _json(self._authn_original, reads.vector.authority.MAX_REQUEST_BYTES, work)
            trust = _json(self._trust_original, reads.vector.authority.MAX_REQUEST_BYTES, work)
            budget = reads.NativeJitReviewReadBudget(operation, parent_work=work,
                live_window=self._window, deadline_ns=self._deadline)
            effects = kernel.evaluate_on_work(operation=operation, request=request,
                read_originals=originals, session_token_original=session_token_original,
                challenge_original=challenge_original, configuration_payload=configuration,
                configuration_root_key=self._root_key, current_root_public_key=self._reader_pins[2],
                current_root_enrollment_original=self._reader_pins[3], authn_policy=authn, trust_policy=trust,
                live_window=self._window, read_budget=budget, work=work,
                authorization_original=authorization_original, preparation_original=preparation_original)
            budget._check()
            self._check()
            _require(type(effects) is reads.core.KernelTransition
                and len(effects.mutations) == (0 if operation == wire.AUTHORIZE else 4)
                and effects.result["schema"] == (kernel.AUTHORIZE_RESULT
                    if operation == wire.AUTHORIZE else kernel.RECEIPT_RESULT)
                and effects.result["operation"] == operation
                and effects.result["requestDigest"] == request["requestDigest"]
                and effects.result["canDecide"] is False)
            result = _json_original(effects.result, wire.MAX_AUTHORITY_ORIGINAL, work)
            mutations = _json_original(list(effects.mutations), reads.vector.authority.MAX_RESULT_BYTES, work)
            self._check()
            return PreparedNativeJitReviewPlan(operation, request_original, challenge_original,
                authorization_original, preparation_original, read_manifest_original, read_frames, result, mutations)
        except BaseException as exc:
            self._failed = True
            if isinstance(exc, Exception):
                raise NativeJitReviewPlanOwnerError() from None
            raise
