"""Protected original-byte issuance and identifier-only successor execution.

These owners use real PostgreSQL connections, distinct fixed roles and exact
TLS identities. The independently admitted eighth configuration value is the
SOURCE-GENERATED complete structural-manifest digest, including functions,
ACLs and all business triggers. Actual catalog observations are compared before
the fixed call and again before normal outer commit; they never enroll their
own expected digest. Runtime creates no scratch schema or provisioning.

The issuer genuinely admits original grant/pending/plan bytes once and retains
only its same-call packet. The executor accepts only two custody identifiers,
and irrevocably records its attempt in a separate actual journal BEFORE opening
the database. A failed/uncertain attempt is never automatically retried, even
after restart: recovery requires that journal's independently current exact
checkpoint. Its durability is not a hostile-host antirollback guarantee.

The separate recovery reader has only one protected read function and no
direct table access. Historical packet/control expiry is not a read denial or
fresh execution grant: it returns exact originals under a new independently
admitted live retrieval window for downstream genuine historical replay.

Returned observations follow normal actual connection closure, but are not
signed completion evidence. The independent read-only completion producer must
still match the committed marker/full vector and original controls. Driver,
catalog and PostgreSQL work are outside H/B/N; genuine packet/response work uses
the caller's unchanged allowance. Deadline checks and bounded per-statement
waits are not a hard syscall watchdog. Late errors may follow a committed write.
No opener override, public packet/candidate input, retry or legacy gate exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import os
import time

from catchplate import authority_contract as authority
from catchplate import authority_current_root_authorization as authorization
from catchplate import authority_current_root_vector as vector
from catchplate import authority_revocation_root_reader as connection_owner
from catchplate import authority_successor_execution_attempts as attempts
from catchplate import authority_successor_execution_packet as packet
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_store import current_root_commit_observation as markers
from catchplate.authority_store.successor_execution_privileges import successor_execution_privilege_check


class SuccessorExecutionOwnerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SuccessorCustodyObservation:
    """Unsigned durable custody locators, not a new execution grant."""

    pending_decision_digest: str
    packet_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuedDelivery:
    """Actual same-call insertion output, never an accepted authority input."""

    observation: SuccessorCustodyObservation
    marker_expectation: dict
    live_window: tuple
    deadline_ns: int
    live: object


@dataclass(frozen=True, slots=True)
class SuccessorExecutionObservation:
    """Normal outer-commit observation, not external signed completion."""

    pending_decision_digest: str
    packet_digest: str
    marker_bytes: bytes


_SET_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE"
_READ_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
_SEARCH_PATH = "SET LOCAL search_path TO catchplate_metadata, pg_catalog, pg_temp"
_WAIT_TIMEOUTS = ("lock_timeout", "idle_in_transaction_session_timeout", "statement_timeout")
_ISSUE_SQL = ("SELECT * FROM catchplate_metadata."
    "catchplate_policy_authority_issue_successor_execution(%s, %s)")
_FRAME_SQL = ("SELECT * FROM catchplate_metadata."
    "catchplate_policy_authority_issue_successor_frame(%s, %s, %s, %s)")
_EXECUTE_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_execute_successor(%s, %s) "
    "AS marker_json")
_READ_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_read_successor_execution(%s, %s) "
    "AS packet_json")
_BOUNDED_READ_SQL = ("WITH held AS MATERIALIZED (SELECT catchplate_metadata."
    "catchplate_policy_authority_read_successor_execution(%s, %s) AS packet_json) "
    "SELECT CASE WHEN octet_length(packet_json) <= %s THEN packet_json ELSE NULL END "
    "AS packet_json FROM held")
_ISSUE_FIELDS = frozenset({"pending_decision_digest", "packet_digest",
    "issued_at_epoch_ns", "expires_at_epoch_ns"})


def _issue_native_frames_on_work(prepared, *, one, window, bound, work):
    """Fixed same-transaction suffix after genuine replay, not a packet API.

    Keep the existing per-original source budget: a large stream never enters
    one aggregate work or SQL parameter. This function receives only this
    issuer invocation's private prepared output and fixed SQL continuation.
    """
    from catchplate import authority_native_jit_review_plan_stream as stream

    if prepared.native_manifest_original is None:
        if prepared.native_frames != ():
            raise SuccessorExecutionOwnerError("native frame inventory has no original manifest")
        return
    # Request identity is part of the manifest already genuinely replayed by
    # packet preparation. SQL independently rejoins it to the signed packet.
    work.charge(input_bytes=3 * len(prepared.native_manifest_original))
    manifest = stream.reads.contract.grammar.document(
        prepared.native_manifest_original.decode("ascii"), stream.MAX_MANIFEST_BYTES)
    manifest, count = stream._manifest(prepared.native_manifest_original,
        packet.pending.replay.NATIVE_REVIEW_OPERATION, manifest["read"]["requestDigest"], work)
    if len(prepared.native_frames) != count:
        raise SuccessorExecutionOwnerError("native frame inventory changed after genuine replay")
    budget = stream._StreamWork(work, window, bound, len(manifest["originals"]))
    ordinal = 0
    for leaf_index, leaf in enumerate(manifest["originals"]):
        with budget.stage(leaf_index) as child:
            offset = 0
            while offset < leaf["byteCount"]:
                raw = prepared.native_frames[ordinal]
                size = min(stream.FRAME_BYTES, leaf["byteCount"] - offset)
                if len(raw) != size:
                    raise SuccessorExecutionOwnerError("native original frame schedule changed")
                child.charge(hashes=1, input_bytes=len(raw))
                digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                row = one(_FRAME_SQL, (prepared.pending_decision_digest,
                    prepared.packet_digest, ordinal, raw))
                wanted = {"frame_ordinal": ordinal, "byte_count": size, "bytes_digest": digest}
                authorization.shape._object(row, frozenset(wanted), "native frame durable readback")
                if any(type(row[name]) is not type(value) for name, value in wanted.items()):
                    raise SuccessorExecutionOwnerError("native frame readback type changed")
                authorization.plan._same(row, wanted, child, "native frame literal readback changed")
                offset += size
                ordinal += 1
    budget.finish()
    if ordinal != count:
        raise SuccessorExecutionOwnerError("native frame upload is incomplete")


def _configuration(config, role):
    if type(config) is not tuple or len(config) != 8:
        raise SuccessorExecutionOwnerError("successor database configuration is not an exact eight-tuple")
    connection_owner._validate_configuration(config[:7])
    if config[2] != role or "\r" in config[0] or "\n" in config[0]:
        raise SuccessorExecutionOwnerError("successor database role or DSN differs from its fixed purpose")
    authorization.shape._digest(config[7])
    return config


def _window(live_window, inherited):
    window = clock._validate(live_window)
    if inherited is not None:
        authorization.shape._integer(inherited, minimum=1)
    return window, window[4] if inherited is None else min(window[4], inherited)


def _identity(row, config, *, recovery=False):
    authorization.shape._object(row, connection_owner._IDENTITY_FIELDS, "successor database identity")
    expected = {"role": config[2], "session_role": config[2], "client_dn": config[3],
        "client_serial": config[4], "issuer_dn": config[5], "transaction_isolation": "serializable",
        "transaction_read_only": "on" if recovery else "off",
        "transaction_deferrable": "on" if recovery else "off"}
    if (type(row["server_version_num"]) is not int
            or not 160000 <= row["server_version_num"] < 170000
            or any(type(row[name]) is not str or row[name] != value for name, value in expected.items())
            or row["ssl"] is not True or row["rolcanlogin"] is not True
            or any(row[name] is not False for name in connection_owner._FALSE_FIELDS)):
        raise SuccessorExecutionOwnerError("successor actual role, TLS or transaction identity differs")


def _marker_on_work(value, pending_digest, work):
    if type(value) is not str or not 2 <= len(value) <= 4096 or not value.isascii():
        raise SuccessorExecutionOwnerError("successor marker response exceeds its canonical byte bound")
    work.charge(input_bytes=len(value))
    original = value.encode("ascii")
    owned = authorization.wire._decode_object(original, work=work,
        maximum_bytes=4096, maximum_nodes=64, maximum_depth=2)
    authorization.shape._object(owned, frozenset(markers.FIELDS), "successor committed marker")
    for name in markers.FIELDS:
        item = owned[name]
        if name in markers._COUNTERS:
            authorization.shape._integer(item)
        elif (type(item) is not str or not 1 <= len(item) <= markers._SCALAR_BYTES[name]
                or not item.isascii() or "\x00" in item):
            raise SuccessorExecutionOwnerError("successor marker scalar is not source bounded")
        elif name in markers._DIGEST_FIELDS:
            authorization.shape._digest(item)
    if (owned["source_revision"] != authority.SOURCE_REVISION
            or owned["operation"] not in markers._OPERATIONS
            or markers._TOKEN.fullmatch(owned["database_id"]) is None
            or owned["pending_sequence"] != owned["predecessor_sequence"] + 1
            or owned["fence"] < 1):
        raise SuccessorExecutionOwnerError("successor marker source or sequence differs")
    authorization.plan._same(owned["pending_decision_digest"], pending_digest, work,
        "successor marker names another admitted pending decision")
    authorization.capability._canonical(original, owned,
        evidence.capture._SharedLedger(work), 4096, 64)
    return original


def _run_on_configuration(config, *, purpose, parameters, expected, live_window, work,
        transport_deadline_ns=None, _current=None, maximum_packet_bytes=None):
    """Private fixed continuation; public owners cannot accept SQL or packets."""
    if purpose not in ("issue", "execute", "read"):
        raise SuccessorExecutionOwnerError("successor database purpose is not source fixed")
    role = (authority.SUCCESSOR_ISSUER_ROLE if purpose == "issue"
        else authority.SUCCESSOR_EXECUTOR_ROLE if purpose == "execute"
        else authority.SUCCESSOR_RECOVERY_ROLE)
    recovery = purpose == "read"
    if not recovery and (_current is not None or maximum_packet_bytes is not None):
        raise SuccessorExecutionOwnerError("successor optional read bounds cannot select a write purpose")
    packet_maximum = packet.MAX_BYTES if maximum_packet_bytes is None else maximum_packet_bytes
    if type(packet_maximum) is not int or not 2 <= packet_maximum <= packet.MAX_BYTES:
        raise SuccessorExecutionOwnerError("successor packet capacity may only tighten its fixed maximum")
    configured = _configuration(config, role)
    evidence.capture._SharedLedger(work)
    window, bound = _window(live_window, transport_deadline_ns)
    expires = min(window[3], expected.expires_at_epoch_ns) if purpose == "issue" else window[3]
    raw_callback = evidence.production._callback
    last_epoch, last_monotonic = window[0], window[2]
    from catchplate import oidc_session_activation_delivery as guarded_delivery
    current = guarded_delivery._join_current(
        lambda: clock._check_on_work(window, work=work), _current, work)

    def remaining():
        nonlocal last_epoch, last_monotonic
        epoch = current()
        monotonic = raw_callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if epoch < last_epoch or monotonic < last_monotonic or monotonic >= bound or epoch >= expires:
            raise SuccessorExecutionOwnerError("successor original transaction window expired or clock reversed")
        last_epoch, last_monotonic = epoch, monotonic
        return min(expires - epoch, bound - monotonic)

    def callback(active_work, operation, *args):
        if _current is None:
            return raw_callback(active_work, operation, *args)
        remaining()
        try:
            return raw_callback(active_work, operation, *args)
        finally:
            remaining()

    @contextmanager
    def owned_context(manager):
        if _current is None:
            with connection_owner._context(manager, work) as value:
                yield value
            return
        remaining()
        try:
            with connection_owner._context(manager, work) as value:
                remaining()
                yield value
                remaining()
        finally:
            # The actual owner context always gets its unconditional failure
            # cleanup before a final currentness failure can escape.
            remaining()

    remaining()
    bindings = vector._source_bindings_on_work(work=work)
    authorization.plan._same(configured[6], bindings["queryManifestDigest"], work,
        "successor owner query manifest differs from actual source")
    import psycopg
    from psycopg.rows import dict_row
    from catchplate import db

    available = remaining()
    connect_timeout = min(configured[1], available // 1_000_000_000)
    if connect_timeout < 2:
        raise SuccessorExecutionOwnerError("successor owner has less than the minimum connection budget")
    options = "-c search_path=pg_catalog" + "".join(
        " -c " + name + "=" + str(available // 1_000_000) for name in _WAIT_TIMEOUTS)
    connection = connection_owner._connect(work, lambda: psycopg.connect(configured[0],
        row_factory=dict_row, connect_timeout=connect_timeout, autocommit=False, options=options))
    try:
        remaining()
        physical = callback(work, connection_owner._connection_identity, connection, 0)
        with owned_context(connection) as active_connection:
            if active_connection is not connection:
                raise SuccessorExecutionOwnerError("successor connection context replaced its actual handle")
            callback(work, connection_owner._require_connection, connection, physical, 0)
            cursor = callback(work, lambda: connection.cursor())
            with owned_context(cursor) as active_cursor:
                if active_cursor is not cursor:
                    raise SuccessorExecutionOwnerError("successor cursor context replaced its actual handle")
                remaining()
                callback(work, lambda: cursor.execute(_READ_TRANSACTION if recovery else _SET_TRANSACTION))
                callback(work, connection_owner._require_connection, connection, physical, 2)

                def active(call):
                    def invoke():
                        connection_owner._require_connection(connection, physical, 2)
                        result = call()
                        connection_owner._require_connection(connection, physical, 2)
                        return result
                    remaining()
                    result = callback(work, invoke)
                    remaining()
                    return result

                def one(sql, values=None):
                    result = active(lambda: cursor.execute(sql) if values is None else cursor.execute(sql, values))
                    return active(lambda: result.fetchone())

                def waits():
                    milliseconds = remaining() // 1_000_000
                    if milliseconds < 1:
                        raise SuccessorExecutionOwnerError("successor owner has no positive database wait budget")
                    for name in _WAIT_TIMEOUTS:
                        active(lambda name=name: cursor.execute("SET LOCAL " + name + " = " + str(milliseconds)))

                waits()
                _identity(one(connection_owner._IDENTITY_SQL), configured, recovery=recovery)
                if one(*successor_execution_privilege_check(role=role, namespace="catchplate_metadata")) is not None:
                    raise SuccessorExecutionOwnerError("successor database role has unexpected effective privileges")
                active(lambda: cursor.execute(_SEARCH_PATH))
                facade = db.PostgresMetadataConnection(connection)

                def catalog():
                    # This is the ACTUAL complete catalog producer, not a
                    # caller-provided checker or a digest read from a DB row.
                    # Expected digest comes from independent source-generated
                    # installation/release admission, never from this result.
                    manifest = active(lambda: db._policy_candidate_authority_structure_manifest(facade))
                    _json, actual = active(lambda: db._policy_candidate_authority_manifest_digest(manifest))
                    authorization.plan._same(actual, configured[7], work,
                        "successor installed schema/functions/triggers differ from independent source catalog")

                catalog()
                waits()
                if purpose == "issue":
                    if type(expected) is packet._PreparedCustody:
                        _issue_native_frames_on_work(expected, one=one, window=window, bound=bound, work=work)
                    row = one(_ISSUE_SQL, parameters)
                    authorization.shape._object(row, _ISSUE_FIELDS, "successor custody readback")
                    wanted = {"pending_decision_digest": expected.pending_decision_digest,
                        "packet_digest": expected.packet_digest, "issued_at_epoch_ns": expected.issued_at_epoch_ns,
                        "expires_at_epoch_ns": expected.expires_at_epoch_ns}
                    for field, value in wanted.items():
                        if type(row[field]) is not type(value):
                            raise SuccessorExecutionOwnerError("successor custody readback scalar type differs")
                        authorization.plan._same(row[field], value, work, "successor actual custody readback")
                    result = SuccessorCustodyObservation(**wanted)
                elif purpose == "execute":
                    row = one(_EXECUTE_SQL, parameters)
                    authorization.shape._object(row, frozenset({"marker_json"}), "successor execution response")
                    marker = _marker_on_work(row["marker_json"], parameters[0], work)
                    result = SuccessorExecutionObservation(parameters[0], parameters[1], marker)
                else:
                    # Bound the driver's returned text before client receive/
                    # decode, not merely after psycopg allocated the full row.
                    row = (one(_READ_SQL, parameters) if maximum_packet_bytes is None
                        else one(_BOUNDED_READ_SQL, (*parameters, packet_maximum)))
                    authorization.shape._object(row, frozenset({"packet_json"}), "successor recovery response")
                    original = row["packet_json"]
                    if (type(original) is not str or not 2 <= len(original) <= packet_maximum
                            or not original.isascii()):
                        raise SuccessorExecutionOwnerError("successor recovery original exceeds its byte bound")
                    work.charge(input_bytes=len(original))
                    result = original.encode("ascii")
                    digest = vector.framing._frame(packet.IDENTITY_DOMAIN, (result,), work)
                    authorization.plan._same(digest, parameters[1], work,
                        "successor recovery original differs from the independent packet identity")
                waits()
                catalog()
                remaining()
            if callback(work, lambda: cursor.closed) is not True:
                raise SuccessorExecutionOwnerError("successor cursor did not close normally")
            callback(work, connection_owner._require_connection, connection, physical, 2)
            remaining()
        if callback(work, lambda: connection.closed) is not True:
            raise SuccessorExecutionOwnerError("successor connection did not close normally")
        remaining()
        return result
    except BaseException:
        connection_owner._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class SuccessorExecutionIssuer:
    """Previously admitted issuer configuration; construction does no I/O."""

    _configuration: tuple
    _pid: int

    def __init__(self, *, dsn, connect_timeout_seconds, tls_client_dn, tls_client_serial,
            tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest):
        configured = _configuration((dsn, connect_timeout_seconds, authority.SUCCESSOR_ISSUER_ROLE,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest,
            expected_structure_manifest_digest), authority.SUCCESSOR_ISSUER_ROLE)
        object.__setattr__(self, "_configuration", configured)
        object.__setattr__(self, "_pid", os.getpid())

    def _snapshot_configuration(self):
        """Hold actual cold inputs across a composed original-only request."""
        if type(self) is not SuccessorExecutionIssuer or os.getpid() != self._pid:
            raise SuccessorExecutionOwnerError("successor issuance requires its actual process-bound owner")
        return _configuration(self._configuration, authority.SUCCESSOR_ISSUER_ROLE)

    def issue(self, *, operation, originals, expectations, planner_public_key,
            operation_public_key, enrollment_bytes, root_public_key,
            reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
            grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
            expected_database_id, expected_generation_digest, expected_pending_sequence,
            expected_pending_head_digest, expected_fence, live_window, work,
            transport_deadline_ns=None, activation_custody=None, native_review_owner=None,
            native_review_frames=None, session_token_original=None):
        held_custody = activation_custody
        if type(operation) is str and operation == packet.pending.replay.ACTIVATION_OPERATION:
            authorization.shape._integer(transport_deadline_ns, minimum=1)
        configured = SuccessorExecutionIssuer._snapshot_configuration(self)
        window, bound = _window(live_window, transport_deadline_ns)
        prepared = packet._prepare_on_work(operation=operation, originals=originals, expectations=expectations,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key,
            enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
            reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
            snapshot_bytes=snapshot_bytes, grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
            expected_authorization_digest=expected_authorization_digest, expected_database_id=expected_database_id,
            expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
            expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
            live_window=window, work=work, transport_deadline_ns=bound,
            activation_custody=held_custody, native_review_owner=native_review_owner,
            native_review_frames=native_review_frames, session_token_original=session_token_original)
        work.charge(input_bytes=len(prepared.packet_bytes))
        text = prepared.packet_bytes.decode("ascii")
        work.prepare_utf8(prepared.packet_digest)
        return _run_on_configuration(configured, purpose="issue", parameters=(text, prepared.packet_digest),
            expected=prepared, live_window=window, work=work, transport_deadline_ns=bound)

    def _issue_delivery_on_work(self, *, originals, expectations, before_vector_bytes, authorization_bytes,
            grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
            current_root_enrollment_bytes, root_public_key, planner_public_key,
            operation_public_key, configuration_digest, expected_predecessor_sequence,
            expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
            expected_pending_sequence, expected_pending_head_digest, expected_fence,
            receiving_custody, live_window, transport_deadline_ns, work):
        """Genuinely admit consume originals once and insert their exact custody."""
        from catchplate import authority_oidc_session_activation_delivery_execution_packet as delivery_packet

        configured = SuccessorExecutionIssuer._snapshot_configuration(self)
        prepared = delivery_packet._prepare_on_work(originals=originals, expectations=expectations,
            before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
            grant_bytes=grant_bytes, response_originals=response_originals,
            authorization_enrollment_bytes=authorization_enrollment_bytes,
            grant_enrollment_bytes=grant_enrollment_bytes,
            current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key,
            configuration_digest=configuration_digest, expected_predecessor_sequence=expected_predecessor_sequence,
            expected_predecessor_head_digest=expected_predecessor_head_digest,
            expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
            expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
            expected_fence=expected_fence, receiving_custody=receiving_custody,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)

        def live():
            now = prepared.live()
            if (SuccessorExecutionIssuer._snapshot_configuration(self) is not configured
                    or now >= prepared.expires_at_epoch_ns):
                raise SuccessorExecutionOwnerError("consume custody issuer changed or original reserve expired")
            return now

        live()
        work.prepare_copy(prepared.marker_expectation)
        marker = prepared.marker_expectation.copy()
        work.charge(input_bytes=len(prepared.packet_bytes))
        text = prepared.packet_bytes.decode("ascii")
        work.prepare_utf8(prepared.packet_digest)
        live()
        observed = _run_on_configuration(configured, purpose="issue",
            parameters=(text, prepared.packet_digest), expected=prepared,
            live_window=prepared.live_window, work=work, transport_deadline_ns=prepared.deadline_ns)
        live()
        if type(observed) is not SuccessorCustodyObservation:
            raise SuccessorExecutionOwnerError("consume custody lacks its actual insertion observation")
        result = _IssuedDelivery(observed, marker, prepared.live_window, prepared.deadline_ns, live)
        live()
        return result


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class SuccessorExecutionExecutor:
    """One irreversibly recorded attempt per protected custody identity.

    The caller owns the attempts object's lifetime. No database connection is
    opened until that actual owner's durable claim completes. Even a provable
    SQL abort does not release a claim here; recovery is a separate authority.
    """

    _configuration: tuple
    _attempts: attempts.SuccessorExecutionAttempts
    _pid: int

    def __init__(self, *, dsn, connect_timeout_seconds, tls_client_dn, tls_client_serial,
            tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest, attempt_owner):
        configured = _configuration((dsn, connect_timeout_seconds, authority.SUCCESSOR_EXECUTOR_ROLE,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest,
            expected_structure_manifest_digest), authority.SUCCESSOR_EXECUTOR_ROLE)
        if (type(attempt_owner) is not attempts.SuccessorExecutionAttempts
                or attempt_owner.structure_manifest_digest != configured[7]):
            raise SuccessorExecutionOwnerError("successor executor requires its actual catalog-bound attempt journal")
        object.__setattr__(self, "_configuration", configured)
        object.__setattr__(self, "_attempts", attempt_owner)
        object.__setattr__(self, "_pid", os.getpid())

    def _snapshot_configuration(self):
        """Require the actual process, catalog pin and ready attempt owner.

        This observation does not claim an attempt or create a checkpoint.
        Execution still performs its own durable claim before opening SQL.
        """
        if type(self) is not SuccessorExecutionExecutor or os.getpid() != self._pid:
            raise SuccessorExecutionOwnerError("successor execution requires its actual process-bound owner")
        configured = _configuration(self._configuration, authority.SUCCESSOR_EXECUTOR_ROLE)
        owner = self._attempts
        if (type(owner) is not attempts.SuccessorExecutionAttempts
                or owner.structure_manifest_digest != configured[7]):
            raise SuccessorExecutionOwnerError("successor execution attempt owner changed")
        return configured

    def execute(self, *, pending_decision_digest, packet_digest, live_window, work,
            transport_deadline_ns=None):
        configured = SuccessorExecutionExecutor._snapshot_configuration(self)
        owner = self._attempts
        evidence.capture._SharedLedger(work)
        authorization.shape._digest(pending_decision_digest)
        authorization.shape._digest(packet_digest)
        parameters = pending_decision_digest, packet_digest
        window, bound = _window(live_window, transport_deadline_ns)
        for value in parameters:
            work.prepare_utf8(value)
        attempts.SuccessorExecutionAttempts._claim_on_work(owner,
            pending_decision_digest=parameters[0], packet_digest=parameters[1],
            live_window=window, work=work, transport_deadline_ns=bound)
        return _run_on_configuration(configured, purpose="execute", parameters=parameters,
            expected=None, live_window=window, work=work, transport_deadline_ns=bound)


def _read_on_configuration(config, *, pending_decision_digest, packet_digest,
        live_window, work, transport_deadline_ns=None, _current=None, maximum_packet_bytes=None):
    """Fixed read continuation using configuration held before other callbacks."""
    configured = _configuration(config, authority.SUCCESSOR_RECOVERY_ROLE)
    evidence.capture._SharedLedger(work)
    authorization.shape._digest(pending_decision_digest)
    authorization.shape._digest(packet_digest)
    parameters = pending_decision_digest, packet_digest
    window, bound = _window(live_window, transport_deadline_ns)
    for value in parameters:
        work.prepare_utf8(value)
    return _run_on_configuration(configured, purpose="read", parameters=parameters,
        expected=None, live_window=window, work=work, transport_deadline_ns=bound,
        _current=_current, maximum_packet_bytes=maximum_packet_bytes)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class SuccessorExecutionRecoveryReader:
    """Process-bound historical originals reader, never execution authority.

    The caller independently admits both selectors and the live retrieval
    window. Returned packet originals still require genuine signature/proof
    replay and a separately admitted current pending checkpoint.
    """

    _configuration: tuple
    _pid: int

    def __init__(self, *, dsn, connect_timeout_seconds, tls_client_dn, tls_client_serial,
            tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest):
        configured = _configuration((dsn, connect_timeout_seconds, authority.SUCCESSOR_RECOVERY_ROLE,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest,
            expected_structure_manifest_digest), authority.SUCCESSOR_RECOVERY_ROLE)
        object.__setattr__(self, "_configuration", configured)
        object.__setattr__(self, "_pid", os.getpid())

    def _snapshot_configuration(self):
        if type(self) is not SuccessorExecutionRecoveryReader or os.getpid() != self._pid:
            raise SuccessorExecutionOwnerError("successor recovery requires its actual process-bound owner")
        return _configuration(self._configuration, authority.SUCCESSOR_RECOVERY_ROLE)

    def read(self, *, pending_decision_digest, packet_digest, live_window, work,
            transport_deadline_ns=None, _current=None, maximum_packet_bytes=None):
        configured = SuccessorExecutionRecoveryReader._snapshot_configuration(self)
        return _read_on_configuration(configured, pending_decision_digest=pending_decision_digest,
            packet_digest=packet_digest, live_window=live_window, work=work,
            transport_deadline_ns=transport_deadline_ns, _current=_current,
            maximum_packet_bytes=maximum_packet_bytes)
