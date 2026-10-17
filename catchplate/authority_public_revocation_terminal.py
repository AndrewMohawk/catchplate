"""Genuine cold owners for public revocation's actual terminal mechanisms.

The optional source-fixed sealed bootstrap is authenticated against the active
measured process root, configuration, generation and role before any new TLS
or journal original is opened. Old launches without this input remain disabled.
The root supplies exact independent checkpoints; empty/stale storage never
enrolls itself. Journals are separate, preprovisioned and never repaired here.
The actual issuer/executor/recovery/commit-reader classes are retained, not
callbacks or caller-provided successful observations.
"""
from __future__ import annotations

import hashlib
import os
import stat
import threading
import time

from catchplate import authority_public_revocation_terminal_bootstrap as bootstrap
from catchplate import authority_public_revocation_preparation as preparation
from catchplate import authority_successor_execution_owner as execution
from catchplate import authority_successor_execution_attempts as attempts
from catchplate import authority_current_root_journal as journals
from catchplate import authority_current_root_delivery as deliveries
from catchplate import authority_current_root_commit_reader as commits
from catchplate import authority_current_root_transport as transport
from catchplate import registration_execution_authorizer_entrypoint as sealed


_OWNERS = {}
_PID = os.getpid()
_LOCK = threading.RLock()
caller, clock = bootstrap.caller, bootstrap.caller.clock


def _identity(value, *, file=False):
    stable = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
    return (*stable, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns) if file else stable


def _open_original(path, *, directory=False, service_uid, expected_size=None, expected_digest=None):
    """Retain every actual parent and the exact named leaf; no generic writes."""
    allowed = set(bootstrap.JOURNAL_PATHS.values()) | set().union(
        *(set(bootstrap.tls_paths(role).values()) for role in bootstrap.ROLES))
    if path not in allowed:
        raise RuntimeError("public terminal original path is not source fixed")
    held = []
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        root = os.open("/", flags | os.O_DIRECTORY)
        value = os.fstat(root)
        held.append((None, None, root, _identity(value)))
        if value.st_uid != 0 or value.st_mode & 0o022:
            raise RuntimeError("public terminal root ancestor is not protected")
        parent = root
        parts = path.split("/")[1:]
        for index, name in enumerate(parts):
            final = index == len(parts) - 1
            descriptor = os.open(name, flags | (os.O_DIRECTORY if directory or not final else 0), dir_fd=parent)
            value = os.fstat(descriptor)
            held.append((parent, name, descriptor, _identity(value, file=final and not directory)))
            if not final:
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
                    raise RuntimeError("public terminal original ancestor is not protected")
            elif directory:
                if (not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700
                        or (value.st_uid, value.st_gid) != (service_uid, service_uid)):
                    raise RuntimeError("public terminal journal is not the exact private service directory")
            else:
                if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1
                        or value.st_uid not in (0, service_uid) or value.st_gid not in (0, service_uid)
                        or value.st_mode & 0o222 or value.st_size != expected_size
                        or not 2 <= value.st_size <= 64 * 1024):
                    raise RuntimeError("public terminal TLS original is not protected bounded material")
                if name.endswith(".key") and stat.S_IMODE(value.st_mode) != 0o400:
                    raise RuntimeError("public terminal TLS private key is not owner-only")
                raw = bytearray()
                while len(raw) < value.st_size:
                    chunk = os.read(descriptor, min(16384, value.st_size - len(raw)))
                    if not chunk:
                        raise RuntimeError("public terminal TLS original was truncated")
                    raw.extend(chunk)
                if os.read(descriptor, 1) or "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
                    raise RuntimeError("public terminal TLS original differs from its independent pin")
                if _identity(os.fstat(descriptor), file=True) != held[-1][3]:
                    raise RuntimeError("public terminal TLS original changed during admission")
            parent = descriptor
        return tuple(held)
    except BaseException:
        for _parent, _name, descriptor, _metadata in reversed(held):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _check_original(held):
    for parent, name, descriptor, expected in held:
        file = len(expected) == 9
        if (_identity(os.fstat(descriptor), file=file) != expected
                or parent is not None and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False), file=file) != expected):
            raise RuntimeError("public terminal retained or named original changed")


def _sql_arguments(config):
    return dict(dsn=config[0], connect_timeout_seconds=config[1], tls_client_dn=config[3],
        tls_client_serial=config[4], tls_issuer_dn=config[5], query_manifest_digest=config[6],
        expected_structure_manifest_digest=config[7])


class _TerminalOwner:
    def __init__(self):
        raise RuntimeError("public terminal owner requires genuine cold process admission")

    def configuration_arguments(self):
        return dict(payload=self.configuration_payload, configuration_digest=self.configuration_digest,
            generation=self.generation, runtime_role_identities=self.runtime_role_identities,
            root_public_key=self.root)

    def require_role(self, role):
        if self.role != role:
            raise RuntimeError("public revocation terminal has another actual process role")

    def require_originals(self, originals, *, work):
        caller.plan._same(originals, (self.scope.current_root_enrollment_bytes,
            self.scope.grant_enrollment_bytes, self.scope.authorization_enrollment_bytes), work,
            "public revocation originals differ from actual cold terminal enrollment")

    def check(self, *, work):
        from catchplate import authority_launch_guard as launch
        if (os.getpid() != _PID or self.closed or self.failed
                or _OWNERS.get(self.process) is not self or self.process.configuration is not self.configuration
                or self.process.role_name != self.role or (os.geteuid(), os.getegid()) != (self.uid, self.uid)
                or (self.process.signing_key if self.role == "verifier" else self.process.launch_identity_key) is not self.signer
                or os.environ.get(bootstrap.ENVIRONMENT) != str(bootstrap.DESCRIPTOR)
                or tuple(sorted(os.environ.items())) != self.environment):
            raise RuntimeError("public terminal actual cold lifetime changed")
        caller.production._callback(work, lambda: launch.require_active(self.role))
        generation = caller.production._callback(work, lambda: dict(launch.generation()))
        caller.plan._same(generation, self.generation, work, "public terminal active generation changed")
        if sealed._sealed_identity(bootstrap.DESCRIPTOR, bootstrap.MAX_BYTES) != self.sealed_identity:
            raise RuntimeError("public terminal sealed bootstrap descriptor changed")
        for held in self.files:
            caller.production._callback(work, lambda held=held: _check_original(held))
        now = clock._check_on_work(self.window, work=work)
        mono = caller.production._callback(work, time.monotonic_ns)
        if now < self.last_epoch or mono < self.last_mono or mono >= self.window[4]:
            raise RuntimeError("public terminal original cold clock expired or reversed")
        self.last_epoch, self.last_mono = now, mono
        if self.role == "issuer":
            actual = execution.SuccessorExecutionIssuer._snapshot_configuration(self.issuer)
            if actual != self.database_configurations["issue"]:
                raise RuntimeError("public terminal issuer changed its actual database configuration")
        elif self.role == "executor":
            for actual, expected in ((execution.SuccessorExecutionExecutor._snapshot_configuration(self.executor),
                    self.database_configurations["execute"]),
                    (execution.SuccessorExecutionRecoveryReader._snapshot_configuration(self.recovery_reader),
                    self.database_configurations["recover"]),
                    (commits.CurrentRootCommitReader._snapshot_configuration(self.commit_reader),
                    self.database_configurations["commit"])):
                if actual != expected:
                    raise RuntimeError("public terminal retained reader/executor configuration changed")
            attempts.SuccessorExecutionAttempts.inspect(self.attempts)
            deliveries.CurrentRootCompletionDelivery.inspect(self.delivery)
        if transport.CurrentRootDecisionClient._snapshot_configuration(self.state) != self.state_configuration:
            raise RuntimeError("public terminal current-root transport configuration changed")


def initialize(process):
    """Actual measured process startup only; absence is explicit disabled state."""
    from catchplate import authority_service as service
    from catchplate import authority_launch_guard as launch
    from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
    if type(process) is not service.AuthorityProcess:
        raise RuntimeError("public terminal requires the actual authority process")
    with _LOCK:
        if os.getpid() != _PID or process in _OWNERS:
            raise RuntimeError("public terminal cold admission cannot be repeated")
        selected = os.environ.get(bootstrap.ENVIRONMENT)
        if selected is None:
            _OWNERS[process] = None
            return
        if selected != str(bootstrap.DESCRIPTOR) or process.role_name not in bootstrap.ROLES:
            raise RuntimeError("public terminal selected descriptor/role differs")
        work = _ValidationWork(QueryReadValidationLimits())
        original, identity = sealed._read_original(bootstrap.DESCRIPTOR, bootstrap.MAX_BYTES)
        configuration = process.configuration
        payload = bootstrap.decode(original, root_public_key=configuration.root_key, work=work)
        role = process.role_name
        launch.require_active(role)
        generation = dict(launch.generation())
        runtime = configuration.runtime_role_identities
        for actual, expected in ((payload["role"], role), (payload["configurationDigest"], configuration.digest),
                (payload["generationDigest"], generation["digest"]),
                (payload["measurementDigest"], runtime["roles"][role]["measurementDigest"]),
                (payload["queryManifestDigest"], configuration.payload["queryManifestDigest"])):
            caller.plan._same(actual, expected, work, "public terminal independent cold scope differs")
        material = bootstrap.scope._admit_on_work(public_revocation=payload["scope"],
            configuration_payload=configuration.payload, configuration_digest=configuration.digest,
            generation=generation, runtime_role_identities=runtime,
            runtime_root_public_key=configuration.root_key, work=work)
        window = clock._open_on_work(deadline_epoch_ns=payload["expiresAtEpochNs"],
            maximum_lifetime_ns=bootstrap.MAX_AGE_NS, maximum_clock_skew_ns=0, work=work)
        if not payload["issuedAtEpochNs"] <= window[0] < payload["expiresAtEpochNs"]:
            raise RuntimeError("public terminal bootstrap is not currently admitted")
        owner = object.__new__(_TerminalOwner)
        owner.process, owner.configuration = process, configuration
        owner.configuration_payload, owner.configuration_digest = configuration.payload, configuration.digest
        owner.generation, owner.runtime_role_identities, owner.root = generation, runtime, configuration.root_key
        owner.role, owner.uid, owner.scope = role, bootstrap.ROLES[role], material
        owner.window, owner.last_epoch, owner.last_mono = window, window[0], window[2]
        owner.environment, owner.sealed_identity = tuple(sorted(os.environ.items())), identity
        if any(name.startswith("PG") for name, _value in owner.environment):
            raise RuntimeError("ambient PostgreSQL settings cannot amend public terminal connections")
        owner.closed, owner.failed, owner.files, owner.lock = False, False, [], threading.RLock()
        owner.signer = process.signing_key if role == "verifier" else process.launch_identity_key
        enrolled = caller.authorization._admit_enrollment_on_work(
            enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=owner.root, work=work)
        grants = caller.grants._admit_enrollment_on_work(grant_enrollment_bytes=material.grant_enrollment_bytes,
            current_root_enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=owner.root, work=work)
        public_key = (enrolled.computation_public_key if role == "verifier"
            else grants.authorizer_public_key if role == "issuer" else enrolled.completion_public_key)
        caller.keys._pair_on_work(owner.signer, public_key, work)
        owner.database_configurations = bootstrap.database_configurations(payload)
        owner.state = transport.CurrentRootDecisionClient(path=material.state_endpoint[0],
            timeout_seconds=material.state_endpoint[1], expected_peer_uid=material.state_endpoint[2],
            expected_peer_gid=material.state_endpoint[3])
        owner.state_configuration = transport.CurrentRootDecisionClient._snapshot_configuration(owner.state)
        owner.attempts = owner.delivery = owner.issuer = owner.executor = owner.recovery_reader = owner.commit_reader = None
        _OWNERS[process] = owner
        opened = {}
        try:
            for name, path in bootstrap.tls_paths(role).items():
                pin = payload["tlsFiles"][name]
                work.charge(input_bytes=pin["byteCount"], hashes=1)
                owner.files.append(_open_original(path, service_uid=owner.uid,
                    expected_size=pin["byteCount"], expected_digest=pin["bytesDigest"]))
            if role == "issuer":
                owner.issuer = execution.SuccessorExecutionIssuer(**_sql_arguments(owner.database_configurations["issue"]))
            elif role == "executor":
                for name in bootstrap.JOURNAL_PATHS:
                    pin = payload[name]
                    held = _open_original(pin["path"], directory=True, service_uid=owner.uid)
                    owner.files.append(held)
                    descriptor = held[-1][2]
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) != (pin["device"], pin["inode"]):
                        raise RuntimeError("public terminal journal identity differs from independent cold pin")
                    opened[name] = journals.CurrentRootJournal(directory_fd=descriptor,
                        expected_device=pin["device"], expected_inode=pin["inode"],
                        expected_uid=owner.uid, expected_gid=owner.uid, maximum_records=pin["maximumRecords"])
                pin = payload["attemptJournal"]
                owner.attempts = attempts.SuccessorExecutionAttempts(journal=opened["attemptJournal"],
                    expected_structure_manifest_digest=payload["structureManifestDigest"],
                    expected_local_sequence=pin["sequence"], expected_local_head_digest=pin["headDigest"],
                    live_window=window, work=work, transport_deadline_ns=window[4])
                pin = payload["completionJournal"]
                owner.delivery = deliveries.CurrentRootCompletionDelivery(journal=opened["completionJournal"],
                    enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=owner.root,
                    expected_local_sequence=pin["sequence"], expected_local_head_digest=pin["headDigest"],
                    live_window=window, work=work, transport_deadline_ns=window[4])
                owner.executor = execution.SuccessorExecutionExecutor(
                    **_sql_arguments(owner.database_configurations["execute"]), attempt_owner=owner.attempts)
                owner.recovery_reader = execution.SuccessorExecutionRecoveryReader(
                    **_sql_arguments(owner.database_configurations["recover"]))
                owner.commit_reader = commits.CurrentRootCommitReader(
                    **_sql_arguments(owner.database_configurations["commit"]),
                    database_role=bootstrap.SQL_ROLES["commit"])
            owner.check(work=work)
        except BaseException:
            owner.failed = True
            for owned in (owner.attempts, owner.delivery):
                if owned is not None:
                    try:
                        owned.close()
                    except BaseException:
                        pass
            for journal in opened.values():
                try:
                    journals.CurrentRootJournal.close(journal)
                except BaseException:
                    pass
            for held in reversed(owner.files):
                for _parent, _name, descriptor, _metadata in reversed(held):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            raise


def require_started(process):
    with _LOCK:
        owner = _OWNERS.get(process)
        if type(owner) is not _TerminalOwner or owner.process is not process or owner.failed or owner.closed:
            raise RuntimeError("public revocation terminal is not genuinely cold admitted")
        return owner
