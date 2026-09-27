"""Fixed root-original consume planning lifecycle; not a cold service launcher.

The private wrapper owns genuine read/history/journal/retained-plan/export owners. It
reauthenticates root originals, resource continuity and original current bounds
around each fixed call. No bare configured owner, arbitrary callback, plaintext
token result, execution capability or automatic retry is exported.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import threading

from serverware import authority_current_root_transport as transport
from serverware import authority_oidc_session_activation_delivery_execution_export as export_module
from serverware import authority_oidc_session_activation_delivery_execution_store as store_module
from serverware import authority_oidc_session_activation_delivery_journal as journal_module
from serverware import authority_oidc_session_activation_delivery_plan_owner as owner_module
from serverware import authority_oidc_session_activation_history_custody as history_module
from serverware import authority_successor_execution_window as processing
from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap


registration, assertion, evidence = owner_module.registration, owner_module.assertion, owner_module.evidence
planning, plan, state = owner_module.planning, owner_module.plan, owner_module.state
clock, production = assertion.clock, evidence.production
_LOCK_TYPE = type(threading.Lock())
_SUBJECT = (("delivery_id", "deliveryId"), ("user_id", "userId"), ("session_id", "sessionId"),
    ("credential_id", "credentialId"), ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId"))


class OidcSessionActivationDeliveryColdPlanningError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationDeliveryColdPlanningError(message)


def _process():
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (bootstrap.SERVICE_UID,) * 4:
        _fail("consume cold planner requires its fixed unprivileged process identity")
    if any(group != bootstrap.SERVICE_GID for group in os.getgroups()):
        _fail("consume cold planner has an unrelated supplementary group")


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _parent(path, work, current):
    """Open fixed root-controlled ancestors without following symlinks."""
    current()
    descriptor = production._callback(work, lambda: os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
    try:
        for component in path.split("/")[1:-1]:
            current()
            child = production._callback(work, lambda: os.open(component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor))
            os.close(descriptor)
            descriptor = child
            info = production._callback(work, lambda: os.fstat(descriptor))
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                _fail("consume TLS ancestor is not an independently protected root directory")
        current()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _tls_snapshot(material, work, current, expected=None):
    """Read exact pinned files once; later checks require unchanged identities."""
    result = []
    for index, name in enumerate(("ca", "clientCertificate", "clientKey")):
        path = bootstrap.TLS_PATHS[name]
        pin = material.payload["tlsFiles"][name]
        parent = _parent(path, work, current)
        descriptor = None
        try:
            current()
            descriptor = production._callback(work, lambda: os.open(path.rsplit("/", 1)[1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent))
            info = production._callback(work, lambda: os.fstat(descriptor))
            identity = _identity(info)
            mode, gid = (0o440, bootstrap.SERVICE_GID) if name == "clientKey" else (0o444, 0)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != gid
                    or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size != pin["byteCount"]):
                _fail("consume TLS file identity, privacy or size differs")
            named = production._callback(work, lambda: os.stat(path.rsplit("/", 1)[1],
                dir_fd=parent, follow_symlinks=False))
            if _identity(named) != identity:
                _fail("consume TLS path changed while opening")
            if expected is None:
                # Precharge cumulative original bytes, reads and exact EOF.
                work.charge(input_bytes=pin["byteCount"] + 1)
                pieces, remaining = [], pin["byteCount"]
                while remaining:
                    current()
                    block = production._callback(work, lambda: os.read(descriptor, min(4096, remaining)))
                    if not block:
                        _fail("consume TLS original ended early")
                    pieces.append(block)
                    remaining -= len(block)
                if production._callback(work, lambda: os.read(descriptor, 1)):
                    _fail("consume TLS original has a trailing suffix")
                work.charge(input_bytes=pin["byteCount"])
                original = b"".join(pieces)
                registration._same(bootstrap._sha(original, work), pin["bytesDigest"], work,
                    "consume TLS original digest differs")
            elif identity != expected[index]:
                _fail("consume TLS resource changed after original admission")
            current()
            final_fd = production._callback(work, lambda: os.fstat(descriptor))
            final_path = production._callback(work, lambda: os.stat(path.rsplit("/", 1)[1],
                dir_fd=parent, follow_symlinks=False))
            if _identity(final_fd) != identity or _identity(final_path) != identity:
                _fail("consume TLS original changed during admission")
            result.append(identity)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    return tuple(result)


def _directory_path(material, work, current, supplied_descriptor=None, *, execution=False):
    """Join one of two source-fixed directory purposes; no supplied path/profile."""
    if type(execution) is not bool:
        _fail("consume directory purpose must select an exact source-fixed role")
    path = bootstrap.EXECUTION_STORE_PATH if execution else bootstrap.JOURNAL_PATH
    prefix = "executionStoreDirectory" if execution else "journalDirectory"
    launch = material.payload["launch"]
    parent = _parent(path, work, current)
    descriptor = None
    try:
        descriptor = production._callback(work, lambda: os.open(path.rsplit("/", 1)[1],
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent))
        info = production._callback(work, lambda: os.fstat(descriptor))
        expected = (launch[prefix + "Device"], launch[prefix + "Inode"],
            bootstrap.SERVICE_UID, bootstrap.SERVICE_GID, 0o700)
        actual = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
        if not stat.S_ISDIR(info.st_mode) or actual != expected:
            _fail("consume storage path differs from its root-admitted directory")
        if supplied_descriptor is not None:
            held = production._callback(work, lambda: os.fstat(supplied_descriptor))
            if (not stat.S_ISDIR(held.st_mode) or
                    (held.st_dev, held.st_ino, held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)) != expected):
                _fail("consume storage descriptor and fixed path differ")
        named = production._callback(work, lambda: os.stat(path.rsplit("/", 1)[1],
            dir_fd=parent, follow_symlinks=False))
        if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino, named.st_uid,
                named.st_gid, stat.S_IMODE(named.st_mode)) != expected:
            _fail("consume storage directory changed during its path join")
        current()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _scope(material, deadline, work):
    payload = material.payload
    request = payload["consumeRequest"]
    subject = {name: request["arguments"][argument] for argument, name in _SUBJECT}
    return assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({**subject,
        "authenticationPolicy": payload["authenticationPolicy"], "trustPolicy": payload["trustPolicy"],
        "configurationDigest": payload["configurationDigest"], "plannerIdentity": payload["planner"]["identity"],
        "plannerSpkiDigest": payload["planner"]["spkiDigest"], "maximumPlanAgeNs": payload["maximumPlanAgeNs"],
        "maximumClockSkewNs": payload["maximumClockSkewNs"], "deadlineEpochNs": deadline})


def _bounds(material, historical, window, bound, work):
    payload = material.payload
    if window[0] < max(material.attestation_interval[0], material.history_material.attestation_interval[0]):
        _fail("consume processing opened before its independently signed launch purposes")
    narrowed = processing._narrow(window, deadline_epoch_ns=material.attestation_interval[1],
        maximum_lifetime_ns=payload["maximumPlanAgeNs"], maximum_clock_skew_ns=payload["maximumClockSkewNs"])
    bound = min(bound, window[4], narrowed[4])
    narrowed, bound = history_module.OidcSessionActivationHistoryCustody.processing_bounds_on_work(
        historical, live_window=narrowed, transport_deadline_ns=bound, work=work)
    # The actual reader's configured skew is exact. A stricter caller cannot
    # silently select a different read profile or cause an allowance reset.
    if narrowed[6] != material.reader_configuration[3]:
        _fail("consume processing skew differs from the fixed actual read profile")
    return narrowed, bound


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ExportedDeliveryPlan:
    """Ciphertext-only handoff data, never receiving proof or execution authority."""

    request_bytes: bytes
    scope_bytes: bytes
    envelope_bytes: bytes
    bundle_bytes: bytes
    plan_digest: str
    journal_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    material: object
    root_public_key: object
    owner: object
    owner_configuration: object
    historical: object
    historical_configuration: object
    journal: object
    journal_configuration: tuple
    execution_store: object
    execution_store_configuration: tuple
    tls_identity: tuple


def _join(configured, material, work):
    actual = owner_module.OidcSessionActivationDeliveryPlanOwner._snapshot_configuration(configured.owner)
    history = history_module.OidcSessionActivationHistoryCustody._snapshot_configuration(configured.historical)
    journal = journal_module.DeliveryOriginalJournal._snapshot_configuration(configured.journal)
    store = store_module.DeliveryExecutionBundleStore._snapshot_configuration(configured.execution_store)
    if (actual is not configured.owner_configuration or history is not configured.historical_configuration
            or journal is not configured.journal_configuration
            or store is not configured.execution_store_configuration):
        _fail("consume held owner, history, journal or export store configuration changed")
    payload, launch = material.payload, material.payload["launch"]
    expected_scope = _scope(material, material.attestation_interval[1], work)
    work.prepare_copy(expected_scope)
    fixed = {name: expected_scope[name] for name in ("authenticationPolicy", "trustPolicy", "configurationDigest",
        "plannerIdentity", "plannerSpkiDigest", "maximumPlanAgeNs", "maximumClockSkewNs")}
    registration._same(owner_module._fixed_scope(actual, work), fixed, work, "consume cold owner scope differs")
    registration._same(actual.read_configuration, material.reader_configuration, work, "consume read configuration differs")
    evidence.keys._public_binding(actual.planner_public_key, payload["planner"]["spkiDigest"], work)
    evidence.keys._public_binding(actual.activation_planner_public_key, material.history_material.planner.planner_spki_digest, work)
    evidence.keys._public_binding(actual.operation_public_key, evidence.keys._spki_on_work(configured.root_public_key, work), work)
    bootstrap._same_bytes(actual.state_enrollment_bytes, material.state_enrollment_bytes, work,
        "consume state enrollment original changed")
    bootstrap._same_bytes(actual.complete_root_vector_bytes, material.complete_root_vector_bytes, work,
        "consume complete vector original changed")
    registration._same(owner_module._json(actual.activation_expectations_bytes, work), payload["activationExpectations"],
        work, "consume activation expectations changed")
    registration._same(owner_module._json(actual.activation_scope_bytes, work), payload["activationScope"],
        work, "consume activation provenance scope changed")
    registration._same((journal[0], journal[1], journal[5], journal[6], journal[7]),
        (bootstrap.authority.SOURCE_REVISION, payload["configurationDigest"],
        (launch["journalDirectoryDevice"], launch["journalDirectoryInode"], bootstrap.SERVICE_UID, bootstrap.SERVICE_GID),
        launch["journalMaximumRecords"], launch["journalQuotaBytes"]), work, "consume journal root pins differ")
    registration._same((store[0], store[1], store[3], store[4], store[5]),
        (bootstrap.authority.SOURCE_REVISION, payload["configurationDigest"],
        (launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"],
            bootstrap.SERVICE_UID, bootstrap.SERVICE_GID),
        launch["executionStoreMaximumRecords"], launch["executionStoreQuotaBytes"]), work,
        "consume execution store root pins differ")
    work.charge(input_bytes=6 * export_module.bundle.KEY_BYTES)
    if store[2] in (journal[2], journal[3], journal[4]) or store[3][:2] == journal[5][:2]:
        _fail("consume execution key or directory overlaps another held custody purpose")
    for key, digest in ((journal[2], payload["journalKeyDigest"]), (journal[3], material.history_material.bundle_key_digest),
            (journal[4], material.history_material.delivery_key_digest), (store[2], material.execution_bundle_key_digest)):
        registration._same(bootstrap._sha(key, work), digest, work, "consume held AES key pin differs")
    history_module.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(configured.historical,
        expected_consume_request=payload["consumeRequest"], work=work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class _ColdPlanner:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool

    def __init__(self):
        _fail("consume cold planners require original root admission")

    def _snapshot(self):
        _process()
        if (type(self) is not _ColdPlanner or self._closed or self._pid != os.getpid()
                or type(self._lock) is not _LOCK_TYPE or type(self._configured) is not _Configuration
                or self._configured is not self._seal):
            _fail("consume cold planner is closed, changed or belongs to another process")
        return self._configured

    def _admit(self, configured, window, bound, work):
        material = bootstrap._verify_on_work(bootstrap_bytes=configured.material.bootstrap_bytes,
            history_custody_bytes=configured.material.history_custody_bytes,
            root_public_key=configured.root_public_key, live_window=window, transport_deadline_ns=bound, work=work)
        _join(configured, material, work)
        narrowed, bound = _bounds(material, configured.historical, window, bound, work)
        _window, inherited = planning.transition.delivery._window(narrowed, bound, work)
        current = bootstrap.shared._launch_guard(material.attestation_interval,
            configured.material.opening_sample, inherited, work)
        historical_live = history_module.OidcSessionActivationHistoryCustody.check_on_work(
            configured.historical, live_window=narrowed, transport_deadline_ns=bound, work=work)

        def live():
            if self._snapshot() is not configured:
                _fail("consume lifecycle changed during a current check")
            now = current()
            historical_live()
            if self._snapshot() is not configured:
                _fail("consume lifecycle changed during historical custody check")
            return max(now, current())

        live()
        _tls_snapshot(material, work, live, expected=configured.tls_identity)
        _directory_path(material, work, live)
        _directory_path(material, work, live, execution=True)
        live()
        return material, narrowed, bound, live

    def prepare(self, *, old_token_bytes, activation_originals, live_window, transport_deadline_ns, work):
        configured = self._snapshot()
        if not self._lock.acquire(blocking=False):
            _fail("consume cold planner is already in use")
        try:
            # Immutable originals and the original time tuple are held before
            # root/key/filesystem/socket callbacks; no successful DTO is input.
            old = assertion._token(old_token_bytes, work)
            originals = plan._activation_originals(activation_originals, work)
            window = clock._validate(live_window)
            registration._integer(transport_deadline_ns, "consume inherited deadline", 1)
            bound = min(window[4], transport_deadline_ns)
            material, window, bound, live = self._admit(configured, window, bound, work)
            scope = _scope(material, window[3], work)
            request = material.payload["consumeRequest"]
            projected = state._project_on_work(vector_bytes=material.complete_root_vector_bytes,
                expected_vector_digest=material.complete_root_vector_digest, work=work)
            context = state._context_digest_on_work(request=request, scope=scope, old_token_bytes=old,
                complete_root_vector_bytes=material.complete_root_vector_bytes, work=work)
            live()
            work.charge(input_bytes=96)
            nonce = production._callback(work, lambda: os.urandom(32))
            if type(nonce) is not bytes or len(nonce) != 32:
                _fail("consume state query lacks a genuine fixed-size challenge")
            query = state.head._encode_query_on_work(enrollment_digest=material.state_enrollment_digest,
                context_digest=context, expected_vector_digest=projected.vector_digest, challenge=nonce.hex(), work=work)
            live()
            work.charge(input_bytes=len(query))
            observation = production._callback(work, lambda: transport._delivery_head_on_configuration(
                material.state_endpoint, query_bytes=query, deadline_ns=bound))
            observation = state._original(observation, state.head.MAX_BYTES, "fresh observation")
            work.charge(input_bytes=len(observation))
            live()
            result = owner_module.OidcSessionActivationDeliveryPlanOwner.prepare(configured.owner,
                request=request, old_token_bytes=old, expected_delivery_id=scope["deliveryId"],
                expected_user_id=scope["userId"], expected_session_id=scope["sessionId"],
                expected_credential_id=scope["credentialId"], expected_credential_record_id=scope["credentialRecordId"],
                expected_challenge_id=scope["challengeId"], business_before_roots=projected.business_before_roots,
                authorization_before_roots=projected.authorization_before_roots,
                expected_counted_heads=projected.expected_counted_heads, head_query_bytes=query,
                head_observation_bytes=observation, activation_originals=originals,
                live_window=window, transport_deadline_ns=bound, work=work)
            live()
            self._admit(configured, window, bound, work)
            if type(result) is not owner_module.PreparedDeliveryPlan:
                _fail("consume actual owner returned another result type")
            signed = plan.contract._decode_on_work(result.envelope_bytes, envelope=True, work=work)["payload"]
            if live() >= signed["expiresAtEpochNs"]:
                _fail("consume plan expired after durable original retention")
            return result
        finally:
            self._lock.release()

    def verify_retained(self, *, envelope_bytes, expected_deadline_epoch_ns, expected_journal_digest,
            live_window, transport_deadline_ns, work):
        return self._retained_on_work(envelope_bytes=envelope_bytes,
            expected_deadline_epoch_ns=expected_deadline_epoch_ns,
            expected_journal_digest=expected_journal_digest, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, export=False)

    def export_retained(self, *, envelope_bytes, expected_deadline_epoch_ns, expected_journal_digest,
            live_window, transport_deadline_ns, work):
        return self._retained_on_work(envelope_bytes=envelope_bytes,
            expected_deadline_epoch_ns=expected_deadline_epoch_ns,
            expected_journal_digest=expected_journal_digest, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, export=True)

    def _retained_on_work(self, *, envelope_bytes, expected_deadline_epoch_ns, expected_journal_digest,
            live_window, transport_deadline_ns, work, export):
        if type(export) is not bool:
            _fail("consume retained operation requires a fixed source purpose")
        configured = self._snapshot()
        if not self._lock.acquire(blocking=False):
            _fail("consume cold planner is already in use")
        try:
            original = state._original(envelope_bytes, plan.contract.MAX_BYTES, "known signed consume plan")
            original_deadline, expected_digest = expected_deadline_epoch_ns, expected_journal_digest
            registration._integer(original_deadline, "independent original consume deadline", 1)
            registration._digest(expected_digest)
            window = clock._validate(live_window)
            registration._integer(transport_deadline_ns, "consume retained deadline", 1)
            material, window, bound, live = self._admit(configured, window,
                min(window[4], transport_deadline_ns), work)
            scope = _scope(material, original_deadline, work)
            projected = state._project_on_work(vector_bytes=material.complete_root_vector_bytes,
                expected_vector_digest=material.complete_root_vector_digest, work=work)
            if export:
                cipher = export_module._export_on_work(configured.owner, configured.execution_store,
                    envelope_bytes=original, expected_request=material.payload["consumeRequest"], expected_scope=scope,
                    business_before_roots=projected.business_before_roots,
                    authorization_before_roots=projected.authorization_before_roots,
                    expected_counted_heads=projected.expected_counted_heads, expected_journal_digest=expected_digest,
                    bundle_key=configured.execution_store_configuration[2],
                    live_window=window, transport_deadline_ns=bound, work=work)
                live()
                # This output is ordinary data. Genuine replay happened inside
                # the exporter; no successful carrier can be fed back as proof.
                result = ExportedDeliveryPlan(registration._wire(material.payload["consumeRequest"], work),
                    registration._wire(scope, work), original, cipher,
                    evidence.plan._frame(plan.contract.IDENTITY_DOMAIN, (original,), work), expected_digest)
            else:
                result = owner_module.OidcSessionActivationDeliveryPlanOwner.verify_retained(configured.owner,
                    envelope_bytes=original, expected_request=material.payload["consumeRequest"], expected_scope=scope,
                    business_before_roots=projected.business_before_roots,
                    authorization_before_roots=projected.authorization_before_roots,
                    expected_counted_heads=projected.expected_counted_heads, expected_journal_digest=expected_digest,
                    live_window=window, transport_deadline_ns=bound, work=work)
            live()
            self._admit(configured, window, bound, work)
            signed = plan.contract._decode_on_work(original, envelope=True, work=work)["payload"]
            if live() >= min(signed["expiresAtEpochNs"], original_deadline):
                _fail("retained consume plan expired before current verification return")
            return result
        finally:
            self._lock.release()

    def close(self):
        configured = self._snapshot()
        if not self._lock.acquire(blocking=False):
            _fail("consume cold planner is already in use")
        try:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
            try:
                owner_module.OidcSessionActivationDeliveryPlanOwner.close(configured.owner)
            finally:
                try:
                    store_module.DeliveryExecutionBundleStore.close(configured.execution_store)
                finally:
                    history_module.OidcSessionActivationHistoryCustody.close(configured.historical)
        finally:
            self._lock.release()


def _create_on_work(*, bootstrap_bytes, history_custody_bytes, root_public_key, planner_private_key,
        bundle_key, delivery_custody_key, journal_key, journal_directory_fd,
        execution_bundle_key, execution_store_directory_fd, live_window, transport_deadline_ns, work):
    """Construct real owners only after authenticating the original root scope."""
    original, custody, root, private = bootstrap_bytes, history_custody_bytes, root_public_key, planner_private_key
    bundle, delivery, journal_key_original, descriptor = bundle_key, delivery_custody_key, journal_key, journal_directory_fd
    execution_key, execution_descriptor = execution_bundle_key, execution_store_directory_fd
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "consume construction deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    for key in (bundle, delivery, journal_key_original, execution_key):
        if type(key) is not bytes or len(key) != 32:
            _fail("consume cold custody keys must be exact immutable originals")
    work.charge(input_bytes=384)
    if (bundle == delivery or journal_key_original in (bundle, delivery)
            or execution_key in (bundle, delivery, journal_key_original)):
        _fail("consume cold AES custody purposes are not separate")
    if type(descriptor) is not int or descriptor != bootstrap.JOURNAL_FD:
        _fail("consume journal must use its fixed independently delivered descriptor")
    if type(execution_descriptor) is not int or execution_descriptor != bootstrap.EXECUTION_STORE_FD:
        _fail("consume execution store must use its fixed independently delivered descriptor")
    if not isinstance(private, evidence.Ed25519PrivateKey):
        _fail("consume cold signing requires an actual Ed25519 private key")
    bootstrap.authorization._public(root)
    _process()
    material = bootstrap._verify_on_work(bootstrap_bytes=original, history_custody_bytes=custody,
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    payload, launch = material.payload, material.payload["launch"]
    current = bootstrap.shared._launch_guard(material.attestation_interval, material.opening_sample,
        bootstrap.shared._processing(window, bound, work), work)
    for raw, digest in ((bundle, material.history_material.bundle_key_digest),
            (delivery, material.history_material.delivery_key_digest), (journal_key_original, payload["journalKeyDigest"]),
            (execution_key, material.execution_bundle_key_digest)):
        registration._same(bootstrap._sha(raw, work), digest, work, "consume actual AES key differs from root pin")
        current()
    evidence.keys._pair_on_work(private, material.planner_public_key, work)
    current()
    tls = _tls_snapshot(material, work, current)
    _directory_path(material, work, current, supplied_descriptor=descriptor)
    _directory_path(material, work, current, supplied_descriptor=execution_descriptor, execution=True)
    historical = storage = owner = execution_store = None
    try:
        historical = history_module.OidcSessionActivationHistoryCustody.for_consume_planning(
            custody_bytes=custody, root_public_key=root, expected_receiver_identity=payload["historyReceiverIdentity"],
            expected_consume_request=payload["consumeRequest"], bundle_key=bundle, delivery_custody_key=delivery,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        window, bound = _bounds(material, historical, window, bound, work)
        current = bootstrap.shared._launch_guard(material.attestation_interval, material.opening_sample,
            bootstrap.shared._processing(window, bound, work), work)
        reader = planning.OidcSessionActivationDeliveryReadPlanner(read_dsn=material.reader_configuration[0],
            connect_timeout_seconds=material.reader_configuration[1], database_identity=material.reader_configuration[2],
            maximum_clock_skew_ns=material.reader_configuration[3])
        current()
        storage = journal_module.DeliveryOriginalJournal(directory_fd=descriptor,
            expected_device=launch["journalDirectoryDevice"], expected_inode=launch["journalDirectoryInode"],
            expected_uid=bootstrap.SERVICE_UID, expected_gid=bootstrap.SERVICE_GID,
            maximum_records=launch["journalMaximumRecords"], quota_bytes=launch["journalQuotaBytes"],
            configuration_digest=payload["configurationDigest"], journal_key=journal_key_original,
            bundle_key=bundle, delivery_key=delivery, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        execution_store = store_module.DeliveryExecutionBundleStore(directory_fd=execution_descriptor,
            expected_device=launch["executionStoreDirectoryDevice"], expected_inode=launch["executionStoreDirectoryInode"],
            expected_uid=bootstrap.SERVICE_UID, expected_gid=bootstrap.SERVICE_GID,
            maximum_records=launch["executionStoreMaximumRecords"], quota_bytes=launch["executionStoreQuotaBytes"],
            configuration_digest=payload["configurationDigest"], bundle_key=execution_key,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        owner = owner_module.OidcSessionActivationDeliveryPlanOwner(read_planner=reader, journal=storage,
            planner_private_key=private, planner_public_key=material.planner_public_key,
            expected_planner_identity=payload["planner"]["identity"], expected_planner_spki_digest=payload["planner"]["spkiDigest"],
            configuration_digest=payload["configurationDigest"], authn_policy=payload["authenticationPolicy"],
            trust_policy=payload["trustPolicy"], maximum_plan_age_ns=payload["maximumPlanAgeNs"],
            maximum_clock_skew_ns=payload["maximumClockSkewNs"], state_enrollment_bytes=material.state_enrollment_bytes,
            state_root_public_key=root, complete_root_vector_bytes=material.complete_root_vector_bytes,
            historical_custody=historical, activation_expectations=payload["activationExpectations"],
            activation_scope=payload["activationScope"], activation_planner_public_key=material.history_material.planner.planner_public_key,
            operation_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        configured = _Configuration(material, root, owner,
            owner_module.OidcSessionActivationDeliveryPlanOwner._snapshot_configuration(owner), historical,
            history_module.OidcSessionActivationHistoryCustody._snapshot_configuration(historical), storage,
            journal_module.DeliveryOriginalJournal._snapshot_configuration(storage), execution_store,
            store_module.DeliveryExecutionBundleStore._snapshot_configuration(execution_store), tls)
        result = object.__new__(_ColdPlanner)
        object.__setattr__(result, "_configured", configured)
        object.__setattr__(result, "_seal", configured)
        object.__setattr__(result, "_pid", os.getpid())
        object.__setattr__(result, "_lock", threading.Lock())
        object.__setattr__(result, "_closed", False)
        result._admit(configured, window, bound, work)
        current()
        return result
    except BaseException:
        try:
            if owner is not None:
                owner_module.OidcSessionActivationDeliveryPlanOwner.close(owner)
            elif storage is not None:
                journal_module.DeliveryOriginalJournal.close(storage)
        finally:
            try:
                if execution_store is not None:
                    store_module.DeliveryExecutionBundleStore.close(execution_store)
            finally:
                if historical is not None:
                    history_module.OidcSessionActivationHistoryCustody.close(historical)
        raise
