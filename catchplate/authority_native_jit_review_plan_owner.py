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
The receipt's complete after vector is reconstructed from those same authenticated
rows and four effects, not a caller-proposed root or a previous plan result.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_current_root_delta as delta
from catchplate import authority_current_root_plan_replay as root_replay
from catchplate import authority_native_jit_review_current_read as reads
from catchplate import authority_native_jit_review_plan_stream as stream
from catchplate import authority_radix_mutation as primary
from catchplate import authority_revocation_configuration as configuration_capture
from catchplate import authority_transition_native_jit_review_open as kernel
from catchplate.authority_query_read_work import _ValidationWork


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


def _configuration(raw, work):
    """Decode only configuration with its existing finite-number grammar."""
    maximum = reads.vector.authority.MAX_REQUEST_BYTES
    _require(type(raw) is bytes and 2 <= len(raw) <= maximum and raw.isascii())
    work.charge(input_bytes=3 * len(raw))
    value = wire.grammar.document(raw.decode("ascii"), maximum)
    return configuration_capture._ConfigurationCapture(
        configuration_capture.capability.capture._SharedLedger(work), maximum_bytes=maximum).visit(value)


def _complete_vectors(operation, acquired, effects, budget):
    """Pure continuation of this invocation's actual original replay, not admission."""
    before_original = acquired.complete_root_vector_original
    if operation == wire.AUTHORIZE:
        _require(effects.mutations == ())
        return before_original, before_original
    with budget.stage("receipt-roots") as work:
        _require(budget.current(work) < effects.result["expiresAtEpochNs"])
        contracts = reads.primary_contract.primary_table_contracts(operation)
        writable = frozenset(item.table for item in contracts if item.write_access)
        _require(writable == {"approval_review_receipts", "metadata_audit_outbox",
            reads.audit_capacity.AGGREGATE_TABLE}
            and all(not reads.vector.projection.index_ids_for_table(table) for table in writable))
        # The other nine rows were already authenticated by the same kernel.
        # Only select pointers by their bounded identities here: do not copy or
        # encode large retained ciphertext/trust documents in a generic batch.
        work.charge(input_bytes=512 * (len(acquired.selected_rows) + len(acquired.before_proofs)),
            json_nodes=5 * (len(acquired.selected_rows) + len(acquired.before_proofs)))
        selected = tuple(row for row in acquired.selected_rows if row["table"] in writable)
        proofs = tuple(proof for proof in acquired.before_proofs if proof["table"] in writable)
        _require(len(selected) == len(proofs) == len(effects.mutations) == 4)
        business = root_replay._primary_documents(acquired.business_before_roots, work)
        authorization = root_replay._primary_documents(acquired.authorization_before_roots, work)
        work.charge(input_bytes=512 * len(contracts), json_nodes=12 * len(contracts))
        sizes = {"contracts": [item.json_projection() for item in contracts],
            "businessRoots": business, "authorizationRoots": authorization,
            "selected": selected, "proofs": proofs, "mutations": effects.mutations}
        size, nodes = work.measure(sizes)
        # The radix engine's historical metrics count one input snapshot, not
        # its hidden scalar encodings, full-row CAS/key comparisons or hash
        # material. Reserve those walks plus four cold proof/union paths before
        # entering it, then debit its actual metrics without a refund/reset.
        work.charge(input_bytes=8 * size + 4 * 2 * 1024 * 1024,
            json_nodes=4 * nodes + 4 * 16384)
        limits = primary.PrimaryRadixLimits(4, 4, 4 * 64, 4 * 1024,
            min(66 + 4 * 136, work.limits.max_hashes - work.hash_work),
            min(reads.vector.authority.MAX_RESULT_BYTES, work.limits.max_input_bytes - work.input_bytes),
            128, work.limits.max_json_nodes - work.json_nodes)
        written = primary.evaluate_primary_radix_batch(table_contracts=contracts,
            business_before_roots=acquired.business_before_roots,
            authorization_before_roots=acquired.authorization_before_roots,
            selected_rows=selected, before_proofs=proofs, mutations=effects.mutations, limits=limits)
        metrics = written.metrics
        work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
        _require(metrics.selected_rows == metrics.mutations == 4
            and budget.current(work) < effects.result["expiresAtEpochNs"])
    with budget.stage("complete-vector") as work:
        _require(budget.current(work) < effects.result["expiresAtEpochNs"])
        before = reads.vector._decode_on_work(before_original, work=work)
        after = root_replay._merge(operation, before, business, authorization,
            root_replay._primary_documents(written.business_after_roots, work),
            root_replay._primary_documents(written.authorization_after_roots, work), [], [], work)
        after_original = reads.vector._encode_on_work(after, work=work)
        delta._validate_on_work(operation=operation, before_vector_bytes=before_original,
            after_vector_bytes=after_original, work=work)
        _require(budget.current(work) < effects.result["expiresAtEpochNs"])
    return before_original, after_original


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
    before_vector_original: bytes
    after_vector_original: bytes
    retained_originals: tuple[str, str, str, str]


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
        configuration = configuration_capture._configuration_wire(configuration_payload,
            configuration_capture.capability.capture._SharedLedger(work))
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

    def _bind_execution_context_on_work(self, *, root_public_key,
            current_root_enrollment_bytes, work):
        """Bind the actual generic consumer to this reader's admitted originals."""
        self._check()
        _require(work is self._work and self._reader_pins[0] == wire.RECEIPT
            and isinstance(root_public_key, Ed25519PublicKey)
            and type(current_root_enrollment_bytes) is bytes)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        actual = root_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        wanted = self._reader_pins[2].public_bytes(Encoding.Raw, PublicFormat.Raw)
        work.charge(input_bytes=len(actual) + len(wanted)
            + len(current_root_enrollment_bytes) + len(self._reader_pins[3]))
        _require(actual == wanted and current_root_enrollment_bytes == self._reader_pins[3])
        self._check()

    def _replay_for_execution_on_work(self, *, originals, expectations,
            before_vector_bytes, session_token_original, read_frames,
            live_window, transport_deadline_ns, work):
        """Original-only continuation into the existing successor replay owner.

        The service supplies a new one-shot owner for each distinct processing
        stage, never a cached successful verdict or retained possession token.
        All stages retain the original opening bracket; a narrower deadline
        cannot be renewed by constructing another owner.
        """
        try:
            self._check()
            window = reads.head.clock._validate(live_window)
            _require(work is self._work and self._reader_pins[0] == wire.RECEIPT
                and window[:3] == self._window[:3] and window[3] <= self._window[3]
                and window[4] <= self._window[4] and window[5] <= self._window[5]
                and window[6] <= self._window[6]
                and type(transport_deadline_ns) is int
                and 0 < transport_deadline_ns <= min(self._deadline, window[4]))
            root_replay._originals(wire.RECEIPT, originals, before_vector_bytes)
            _require(type(expectations) is dict and set(expectations) == {"request"})
            request = _json(originals[0], MAX_REQUEST_BYTES, work)
            root_replay.framing._same(request, expectations["request"], work,
                "native receipt differs from independent request")
            _require(time.monotonic_ns() < transport_deadline_ns)
            result = self._run(request, session_token_original=session_token_original,
                challenge_original=originals[1].decode("ascii"),
                authorization_original=originals[2].decode("ascii"),
                preparation_original=originals[3].decode("ascii"),
                read_manifest_original=originals[4], read_frames=read_frames,
                execution_originals=originals)
            work.charge(input_bytes=len(before_vector_bytes) + len(result.before_vector_bytes))
            _require(result.before_vector_bytes == before_vector_bytes
                and reads.head.clock._check_on_work(window, work=work) < result.original_interval[1]
                and time.monotonic_ns() < transport_deadline_ns)
            self._check()
            return result
        except BaseException as exc:
            self._failed = True
            if isinstance(exc, Exception):
                raise NativeJitReviewPlanOwnerError() from None
            raise

    def _run(self, request, *, session_token_original, challenge_original, authorization_original,
            preparation_original, read_manifest_original, read_frames, execution_originals=None):
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
            configuration = _configuration(self._configuration_original, work)
            authn = _json(self._authn_original, reads.vector.authority.MAX_REQUEST_BYTES, work)
            trust = _json(self._trust_original, reads.vector.authority.MAX_REQUEST_BYTES, work)
            budget = reads.NativeJitReviewReadBudget(operation, parent_work=work,
                live_window=self._window, deadline_ns=self._deadline)
            effects, acquired = kernel._evaluate_with_reads_on_work(operation=operation, request=request,
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
            before, after = _complete_vectors(operation, acquired, effects, budget)
            budget._check()
            self._check()
            result = _json_original(effects.result, wire.MAX_AUTHORITY_ORIGINAL, work)
            mutations = _json_original(list(effects.mutations), reads.vector.authority.MAX_RESULT_BYTES, work)
            self._check()
            _require(self._last_epoch < effects.result["expiresAtEpochNs"])
            if execution_originals is not None:
                # These are this invocation's actual authenticated rows and
                # effects. Large read-only originals remain in the bounded
                # stream, not in the generic four-row CAS packet.
                _require(operation == wire.RECEIPT)
                writable = {"approval_review_receipts", "metadata_audit_outbox",
                    reads.audit_capacity.AGGREGATE_TABLE}
                selected = [row for row in acquired.selected_rows if row["table"] in writable]
                _require(len(selected) == len(effects.mutations) == 4)
                work.prepare_copy(selected)
                owned = root_replay.capture._JSONCapture(
                    root_replay.capture._SharedLedger(work)).visit({"request": request,
                        "result": effects.result, "selectedRows": selected,
                        "mutations": list(effects.mutations)})
                frame = root_replay.framing._frame
                plan_digest = frame("catchplate.nativeJitReviewReceiptPlanIdentity/v1",
                    execution_originals, work)
                record_digest = frame("catchplate.nativeJitReviewReceiptOriginalsIdentity/v1",
                    execution_originals, work)
                interval = (kernel.quota._database_epoch_ns(acquired.database_now),
                    effects.result["expiresAtEpochNs"])
                _require(interval[0] < interval[1])
                root_replay.shape._integer(effects.work_units,
                    reads.vector.authority.operation_spec(operation)["maximumWorkUnits"], minimum=1)
                return root_replay._ReplayedPlan(operation, owned["request"], execution_originals,
                    record_digest, before, after, frame(reads.vector.IDENTITY_DOMAIN, (before,), work),
                    frame(reads.vector.IDENTITY_DOMAIN, (after,), work), owned["result"], interval,
                    plan_digest, None, None, tuple(owned["selectedRows"]),
                    tuple(owned["mutations"]), effects.work_units)
            retained = kernel._row(kernel.core.KernelContext(operation, request["arguments"],
                acquired.selected_rows, acquired.database_now, request["requestDigest"]),
                kernel.storage.TABLE, {"approval_request_id": request["arguments"]["approval_request_id"]})
            retained_originals = tuple(retained[name] for name in (
                "parent_request_original", "child_request_original", "pair_original", "proof_original"))
            return PreparedNativeJitReviewPlan(operation, request_original, challenge_original,
                authorization_original, preparation_original, read_manifest_original, read_frames,
                result, mutations, before, after, retained_originals)
        except BaseException as exc:
            self._failed = True
            if isinstance(exc, Exception):
                raise NativeJitReviewPlanOwnerError() from None
            raise
