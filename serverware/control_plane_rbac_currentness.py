"""Cold, purpose-separated RBAC witness ownership and current read brackets.

No caller chooses a root, endpoint, database role or observed head. Importing
this module performs no admission. Missing production material is a refusal.
Legacy profiles require independently administered witness storage. The
explicit local successor is separately signed and makes no such claim; it
still requires distinct real clusters and the same currentness checks.
"""
import contextlib
import fcntl
import os
import signal
import stat
import threading
import time
from serverware import authority_rbac_currentness as profile
from serverware.authority_rbac_witness import Connection
# Only this sealed-original primitive is reused, not OAuth authority.
from serverware.oauth_application_owner import _Original

CONFIG_ENV = "SERVERWARE_RBAC_WITNESS_CONFIG_FD"
MAX_OPERATION_NS = 30_000_000_000
_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower(),
        tuple(sorted((key, value) for key, value in os.environ.items() if key.startswith("SERVERWARE_RBAC_WITNESS_"))))


def _development(value):
    return value[0] in {"dev", "development", "local", "test"} and not value[1]


class _Owner:
    def check(self):
        profile.require(os.getpid() == self.pid == _PID and not self.closed and _environment() == self.environment
            and time.monotonic_ns() < self.deadline and self.opening_epoch <= time.time_ns() < self.expires_epoch)
        for original in self.originals: original.check()
        if self.process is None:
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_custody_startup as startup
            profile.require(startup.require_started() is self.custody and client._snapshot(self.custody) is self.binding)
            client._receipt_now(self.binding)
        else:
            from serverware import authority_launch_guard as launch
            profile.require(launch.require_active(self.process.role_name) == self.launch
                and self.process.configuration is self.configuration and self.configuration.digest == self.configuration_digest)
            profile.require(time.time_ns() < self.attestation_expires)
        if self.local:
            _require_local_owner(self)

    def require_writer(self):
        self.check()
        profile.require(self.recovery is None and self.writer and self.process is not None and self.process.role_name == "verifier",
            "only the genuinely admitted RBAC verifier owns witness write permission")

    @contextlib.contextmanager
    def connection_parameters(self):
        """Role-readable sealed TLS copies, scoped to synchronous connect only."""
        self.check()
        # libpq treats service="" as a named-service lookup, not an opt-out.
        # Omit it and refuse ambient overrides instead of mutating global env.
        profile.require(not any(name.startswith("PG") for name in os.environ),
            "ambient PostgreSQL configuration is forbidden")
        endpoint = self.policy["endpoint"]
        parameters = {"host": endpoint["host"], "hostaddr": endpoint["address"], "port": endpoint["port"],
            "dbname": endpoint["database"], "user": self.policy["writer" if self.writer else "reader"]["role"],
            "sslmode": "verify-full", "ssl_min_protocol_version": "TLSv1.3", "ssl_max_protocol_version": "TLSv1.3",
            "passfile": "/dev/null", "password": "", "gssencmode": "disable", "application_name": "serverware-rbac-witness-v1"}
        held, projected = [], []
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        cancellation = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}

        def identity(fd, raw):
            info = os.fstat(fd)
            actual_seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            profile.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 0
                and (info.st_uid, info.st_gid) == (os.geteuid(), os.getegid())
                and stat.S_IMODE(info.st_mode) == 0o400 and info.st_size == len(raw)
                and actual_seals == seals and flags & fcntl.FD_CLOEXEC
                and os.pread(fd, len(raw) + 1, 0) == raw)
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, actual_seals, flags)

        try:
            for name, original, maximum in (("sslrootcert", self.tls_root, 65536),
                    ("sslcert", self.certificate, 65536), ("sslkey", self.key, 16384)):
                self.check()
                raw = original.raw
                profile.require(type(raw) is bytes and 2 <= len(raw) <= maximum)
                # Register ownership before writes, including cancellation at
                # the acquisition/registration boundary. Originals never change.
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
                try:
                    fd = os.memfd_create("serverware-rbac-tls-" + name,
                        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                    try:
                        held.append(fd)
                    except BaseException:
                        with contextlib.suppress(OSError): os.close(fd)
                        raise
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:])
                    profile.require(count > 0)
                    offset += count
                os.fchmod(fd, 0o400)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
                projected.append((fd, raw, identity(fd, raw)))
                parameters[name] = "/proc/self/fd/" + str(fd)
            self.check()
            for fd, raw, expected in projected:
                profile.require(identity(fd, raw) == expected)
            yield parameters
            self.check()
            for fd, raw, expected in projected:
                profile.require(identity(fd, raw) == expected)
        finally:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
            try:
                for fd in reversed(held):
                    with contextlib.suppress(OSError): os.close(fd)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def limit(self, deadline=None):
        self.check()
        selected = min(self.deadline, time.monotonic_ns() + MAX_OPERATION_NS)
        if deadline is not None:
            profile.require(type(deadline) is int)
            selected = min(selected, deadline)
        profile.require(time.monotonic_ns() < selected)
        return selected


def _require_local_owner(owner):
    """Only the already admitted owner may select the co-located profile."""
    profile.require_local_development()
    from serverware import authority_service as service
    claims = {"trustMode": "trusted-host-local", "coLocated": True,
        "hardwareBacked": False, "nativeStageZero": False, "hsmBackedKeys": False,
        "teeVerified": False, "externalWitnessVerified": False}
    if owner.process is None:
        # This binding is captured only after genuine custody/runtime-FD
        # admission; a directly constructed runtime client is not accepted.
        from serverware import control_plane_custody_client as client
        from serverware import control_plane_custody_startup as startup
        profile.require(startup.require_started() is owner.custody
            and client._snapshot(owner.custody) is owner.binding)
        client._receipt_now(owner.binding)
        runtime = owner.binding.runtime_client
        profile.require(type(runtime) is service.AuthorityRuntimeClient
            and runtime.configuration_digest == owner.configuration_digest)
        evidence, policy = runtime.attestation_evidence, runtime.attestation_verification_policy
        profile.require(type(evidence) is dict and evidence.get("schema") == service.TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            and type(evidence.get("payload")) is dict and type(policy) is dict)
        actual = evidence["payload"]
        profile.require(all(type(value.get(name)) is type(expected) and value[name] == expected
            for value in (actual, policy) for name, expected in claims.items()))
    else:
        from serverware import authority_launch_guard as launch
        profile.require(type(owner.process) is service.AuthorityProcess
            and owner.process.configuration is owner.configuration
            and launch.require_active(owner.process.role_name) == owner.launch)
        assurance = dict(launch.launch_assurance())
        profile.require(assurance == dict(schema="serverware.authorityLaunchAssurance/v1", **claims))
        selected = owner.configuration.payload.get("credentialReleaseTrust")
        profile.require(type(selected) is dict and set(selected) == {"schema", "trustMode", "maximumReceiptAgeNs"}
            and selected["schema"] == "serverware.trustedHostLocalCredentialReleaseTrust/v1"
            and selected["trustMode"] == "trusted-host-local")


def _initialize(process=None):
    global _state, _owner, _namespace
    profile.require(os.getpid() == _PID)
    with _LOCK:
        profile.require(_state == "new", "RBAC cold admission cannot restart or renew")
        _state, _namespace = "initializing", _environment()
        try:
            if process is None and _development(_namespace):
                _state = "disabled"; return None
            settings = dict(_namespace[1])
            required_names = {CONFIG_ENV} if process is None else {CONFIG_ENV, "SERVERWARE_RBAC_WITNESS_ROOT_FD",
                "SERVERWARE_RBAC_WITNESS_TLS_ROOT_FD", "SERVERWARE_RBAC_WITNESS_CLIENT_CERTIFICATE_FD", "SERVERWARE_RBAC_WITNESS_CLIENT_KEY_FD"}
            profile.require(set(settings) == required_names)
            text = settings[CONFIG_ENV]
            profile.require(text.isascii() and text.isdecimal() and str(int(text)) == text)
            descriptor = int(text)
            from serverware import authority_contract
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            value = object.__new__(_Owner)
            value.pid, value.environment, value.closed, value.process = _PID, _namespace, False, process
            if process is None:
                from serverware import control_plane_custody_client as client
                from serverware import control_plane_custody_startup as startup
                value.custody = startup.require_started(); value.binding = client._snapshot(value.custody)
                current_digest = value.binding.configuration_digest
                inherited = value.binding.inherited_descriptors
                independent_root = value.binding.runtime_root_public_key
                current_epoch = client._receipt_now(value.binding)
                opening_mono = time.monotonic_ns()
                maximum_expiry = value.binding.attestation_interval[1]
                value.writer = False
            else:
                from serverware import authority_service, authority_launch_guard as launch
                profile.require(type(process) is authority_service.AuthorityProcess
                    and process.role_name in {"verifier", "planner", "planner-writer", "issuer", "executor"})
                value.configuration = process.configuration
                value.launch = launch.require_active(process.role_name)
                inherited = launch.retained_descriptors()
                current_digest = process.configuration.digest
                independent_root = process.configuration.root_key
                current_epoch = time.time_ns()
                opening_mono = time.monotonic_ns()
                evidence = process.configuration.attestation_evidence
                # The already admitted receipt retains its signed envelope;
                # local and provider expiry both belong to its payload.
                maximum_expiry = evidence["payload"]["expiresAtEpochNs"]
                maximum_expiry = min(maximum_expiry, process.configuration.history_archive.valid_until_epoch_ns)
                value.attestation_expires = maximum_expiry
                value.writer = process.role_name == "verifier"
            profile.require(descriptor in inherited)
            config_original = _Original(descriptor, 96 * 1024)
            config = profile.document(config_original.raw, 96 * 1024)
            profile.require(type(config) is dict and config.get("schema") in {
                profile.STARTUP_SCHEMA, profile.STARTUP_V2_SCHEMA, profile.LOCAL_STARTUP_SCHEMA})
            second = config["schema"] == profile.STARTUP_V2_SCHEMA
            value.local = config["schema"] == profile.LOCAL_STARTUP_SCHEMA
            profile.require(set(config) == {"schema", "sourceRevision", "configurationDigest",
                "root", "enrollment", "tlsRoot", "clientCertificate", "clientKey"} | ({"recoveryAuthorization"} if second else set())
                and config["sourceRevision"] == authority_contract.SOURCE_REVISION
                and config["configurationDigest"] == current_digest)
            originals, used = [config_original], {descriptor}
            materials = {}
            for name, maximum in (("root", 4096), ("tlsRoot", 65536), ("clientCertificate", 65536), ("clientKey", 16384)):
                item = config[name]
                profile.require(type(item) is dict and set(item) == {"fd", "sha256"}
                    and type(item["fd"]) is int and 32 <= item["fd"] <= 1023
                    and item["fd"] in inherited and item["fd"] not in used)
                if process is not None:
                    environment_name = {"root":"SERVERWARE_RBAC_WITNESS_ROOT_FD", "tlsRoot":"SERVERWARE_RBAC_WITNESS_TLS_ROOT_FD",
                        "clientCertificate":"SERVERWARE_RBAC_WITNESS_CLIENT_CERTIFICATE_FD", "clientKey":"SERVERWARE_RBAC_WITNESS_CLIENT_KEY_FD"}[name]
                    profile.require(settings[environment_name] == str(item["fd"]))
                used.add(item["fd"])
                original = _Original(item["fd"], maximum, name == "clientKey")
                profile.require(profile.sha256(original.raw) == profile.digest(item["sha256"]))
                originals.append(original); materials[name] = original
            root = serialization.load_pem_public_key(materials["root"].raw)
            profile.require(isinstance(root, Ed25519PublicKey)
                and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == materials["root"].raw
                and root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    != independent_root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            value.enrollment_original = profile.canonical(config["enrollment"])
            value.policy = profile.enrollment(value.enrollment_original, root)
            value.enrollment_sha256 = profile.sha256(value.enrollment_original)
            profile.require(value.policy["schema"] == (profile.ENROLLMENT_V2_SCHEMA if second else
                profile.LOCAL_ENROLLMENT_SCHEMA if value.local else profile.ENROLLMENT_SCHEMA))
            value.recovery, value.recovery_original = None, None
            if second:
                from serverware import authority_rbac_recovery as recovery
                recovery_key = Ed25519PublicKey.from_public_bytes(recovery.decode(value.policy["recoveryPublicKeyBase64Url"], 32))
                profile.require(recovery_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    != independent_root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
                if config["recoveryAuthorization"] is not None:
                    profile.require(process is not None and process.role_name == "verifier" and value.writer,
                        "recovery-only startup requires the actual fresh verifier role")
                    value.recovery_original = profile.canonical(config["recoveryAuthorization"])
                    value.recovery = recovery.authorization(value.recovery_original, value.policy)
                    profile.require(value.recovery["sourceRevision"] == authority_contract.SOURCE_REVISION
                        and value.recovery["configurationDigest"] == current_digest
                        and value.recovery["enrollmentSha256"] == value.enrollment_sha256
                        and value.recovery["issuedAtEpochNs"] <= current_epoch < value.recovery["expiresAtEpochNs"])
            if value.recovery is None:
                profile.require(value.policy["sourceRevision"] == authority_contract.SOURCE_REVISION
                    and current_digest in value.policy["configurationDigests"]
                    and value.policy["issuedAtEpochNs"] <= current_epoch < value.policy["expiresAtEpochNs"])
            identity = value.policy["writer" if value.writer else "reader"]
            value.tls_root, value.certificate, value.key = materials["tlsRoot"], materials["clientCertificate"], materials["clientKey"]
            profile.require(profile.sha256(value.tls_root.raw) == value.policy["tlsRootSha256"]
                and profile.sha256(value.certificate.raw) == identity["certificateSha256"])
            certificate = x509.load_pem_x509_certificate(value.certificate.raw)
            key = serialization.load_pem_private_key(value.key.raw, password=None)
            profile.require(certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                == key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            value.originals, value.configuration_digest = tuple(originals), current_digest
            if value.local:
                _require_local_owner(value)
            value.opening_epoch, value.opening_mono = current_epoch, opening_mono
            value.expires_epoch = min(maximum_expiry,
                value.policy["expiresAtEpochNs"] if value.recovery is None else value.recovery["expiresAtEpochNs"])
            value.deadline = opening_mono + value.expires_epoch - current_epoch
            _owner, _state = value, "started"
            value.check()
            # Cold connectivity verifies identity, not current business state.
            # Pending must not be treated as a missing head or fresh genesis.
            with Connection(value, value.limit()) as connection: connection.head(allow_pending=True)
            return value
        except BaseException:
            _state = "failed"; raise


def initialize_from_environment(): return _initialize()
def initialize_authority(process): return _initialize(process)


def require_started():
    profile.require(os.getpid() == _PID)
    with _LOCK:
        namespace = _environment()
        if _state == "new" and _development(namespace): return None
        profile.require(namespace == _namespace)
        if _state == "disabled":
            profile.require(_development(namespace)); return None
        profile.require(_state == "started" and _owner is not None)
        profile.require(_owner.recovery is None, "recovery-only admission cannot serve current authorization or execution")
        _owner.check(); return _owner


def close():
    global _state
    profile.require(os.getpid() == _PID)
    with _LOCK:
        if _owner is not None: _owner.closed = True
        _state = "closed"


def _matching_roots(head, roots):
    selected = [dict(root) for root in roots if root["table"] in profile.TABLES]
    profile.require(len({root["table"] for root in selected}) == len(selected))
    expected = {root["table"]: root for root in head["state"]["roots"]}
    for root in selected: profile.require(root == expected[root["table"]], "RBAC root differs from independently retained current head")


def require_roots(roots, *, cursor, deadline_epoch_ns, deadline_ns=None):
    if not any(root["table"] in profile.TABLES for root in roots): return
    owner = require_started()
    if owner is None: return  # explicit unconfigured development only
    profile.require(type(deadline_epoch_ns) is int and time.time_ns() < deadline_epoch_ns)
    original_deadline = owner.opening_mono + deadline_epoch_ns - owner.opening_epoch
    if deadline_ns is not None: original_deadline = min(original_deadline, deadline_ns)
    with Connection(owner, owner.limit(original_deadline)) as connection:
        head, _ = connection.head()
        _matching_roots(head, roots)
        _matching_roots(head, metadata_roots(cursor, owner))
        profile.require(time.time_ns() < deadline_epoch_ns)


def metadata_roots(cursor, owner):
    # The existing identity primitive is read-only and requires its separately
    # provisioned pg_control_system privilege; no SQL/DML role is promoted.
    identity = cursor.execute("SELECT (pg_catalog.pg_control_system()).system_identifier::text AS cluster_id,pg_catalog.current_database() AS database").fetchone()
    profile.require(identity is not None and identity["cluster_id"] == owner.policy["metadataClusterId"]
        and identity["database"] == owner.policy["metadataDatabase"])
    rows = cursor.execute("SELECT table_name,root_revision,root_digest,leaf_count FROM serverware_metadata."
        "policy_authority_authenticated_table_roots WHERE table_name IN ('rbac_authority_state','rbac_role_bindings') ORDER BY table_name").fetchall()
    roots = [{"table": row["table_name"], "rootRevision": row["root_revision"], "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]} for row in rows]
    profile.require([root["table"] for root in roots] == list(profile.TABLES))
    return roots


def require_metadata(conn, authority):
    owner = require_started()
    if owner is None: return
    with Connection(owner, owner.limit()) as connection:
        head, _ = connection.head()
        with conn.raw_connection.cursor() as cursor: roots = metadata_roots(cursor, owner)
        _matching_roots(head, roots)
        profile.require(head["state"]["generation"] == authority["generation"]
            and head["state"]["stateDigest"] == authority["state_digest"])


@contextlib.contextmanager
def execution_guard(request, result, capability_id, deadline_ns):
    from serverware import authority_contract
    spec = authority_contract.operation_spec(request["operation"])
    if not set(profile.TABLES) & (set(spec["businessReads"]) | set(spec["authorizationReads"])):
        yield None; return
    owner = require_started()
    profile.require(owner is not None and owner.process is not None and owner.process.role_name == "executor")
    with Connection(owner, owner.limit(deadline_ns)) as connection:
        head, pending = connection.head(allow_pending=request["operation"] == "rbac.binding.mutate")
        if request["operation"] == "rbac.binding.mutate":
            record = connection.record(request["requestDigest"])
            profile.require(record is not None and pending == record["intent_sha256"] and record["completion_original"] is None)
            intent = profile.document(record["intent_original"].encode("ascii"))
            profile.require(intent["beforeHead"] == head and intent["capabilityId"] == capability_id
                and intent["afterHead"]["state"]["generation"] == result["generation"]
                and intent["afterHead"]["state"]["stateDigest"] == result["state_digest"]
                and time.time_ns() < intent["expiresAtEpochNs"])
        # The actual caller keeps this SHARE lock until metadata COMMIT has
        # returned. No RBAC reserve can cross this effect's linearization point.
        yield (owner, head)
        connection.check()


def reserve_plan(process, payload, request_digest, capability_id, deadline_ns, deadline_epoch_ns):
    if payload["measuredPlan"]["operation"] != "rbac.binding.mutate": return None
    owner = require_started(); profile.require(owner is not None and owner.process is process); owner.require_writer()
    transition, result = payload["rootTransition"], payload["expectedResult"]
    original_deadline = owner.limit(deadline_ns)
    with Connection(owner, original_deadline) as connection:
        before, _ = connection.head()
        _matching_roots(before, transition["businessBeforeRoots"])
        roots = [root for root in transition["businessAfterRoots"] if root["table"] in profile.TABLES]
        after = profile.after_head(before, {"generation": result["generation"], "stateDigest": result["state_digest"], "roots": roots})
        original = profile.canonical({"schema": profile.INTENT_SCHEMA, "enrollmentSha256": owner.enrollment_sha256,
            "requestSha256": request_digest, "capabilityId": capability_id, "beforeHeadSha256": profile.sha256(profile.canonical(before)),
            "beforeHead": before, "afterHead": after, "expiresAtEpochNs": min(deadline_epoch_ns, owner.expires_epoch), "planSha256": profile.sha256(profile.canonical(payload))})
    # Do not upgrade two simultaneous SHARE readers to writers. The separate
    # reserve transaction locks once and compares the exact original head.
    with Connection(owner, original_deadline) as connection:
        connection.reserve(original)
    # Reaching here means COMMIT and the owner's closing checks returned. An
    # exception never yields a permit, and no same-request retry is attempted.
    return (owner, original, after, deadline_ns)


def complete_plan(process, attempt, executed):
    if attempt is None: return
    owner, intent_original, after, deadline_ns = attempt
    profile.require(owner is require_started() and owner.process is process); owner.require_writer()
    intent = profile.document(intent_original)
    receipt = executed["receipt"]
    profile.require(receipt["operation"] == "rbac.binding.mutate" and receipt["capabilityId"] == intent["capabilityId"]
        and receipt["requestDigest"] == intent["requestSha256"])
    import base64
    result_original = profile.canonical(executed["result"])
    original = profile.canonical({"schema": profile.COMPLETION_SCHEMA, "enrollmentSha256": owner.enrollment_sha256,
        "intentSha256": profile.sha256(intent_original), "requestSha256": intent["requestSha256"],
        "writerReceipt": receipt, "writerReceiptSha256": profile.sha256(profile.canonical(receipt)),
        "resultBase64Url": base64.urlsafe_b64encode(result_original).rstrip(b"=").decode("ascii"), "resultSha256": profile.sha256(result_original)})
    with Connection(owner, owner.limit(deadline_ns)) as connection:
        connection.complete(profile.sha256(intent_original), original, after)
