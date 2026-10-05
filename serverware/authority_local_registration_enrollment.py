"""Issue the fixed local first-registration root delegations and bootstrap.

The approved complete initial vector is an independent root enrollment input,
not a claim that this offline producer observed a database. Signed Service6 and
all five original cohort receipts are authenticated before signing. No grant,
current-root receipt, execution context, hardware ceremony, key or SQL state
is generated. The actual startup still admits its own launch and private FDs.
"""
from __future__ import annotations

import os
import stat
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_local_configuration as local
from serverware import authority_local_keys as keys
from serverware import authority_attestation_cohort as cohort
from serverware import authority_revocation_configuration as configuration
from serverware import authority_current_root_authorization as current
from serverware import authority_successor_execution_grant_enrollment as grant
from serverware import authority_registration_execution_authorization as execution
from serverware import authority_registration_finalization_authorization as finalization
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import control_plane_enrollment_bootstrap as bootstrap
from serverware import control_plane_registration_execution_bootstrap as execution_profile
from serverware import control_plane_registration_finalization_bootstrap as finalization_profile
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from serverware import authority_query_read_work as accounting
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

io, spec = local.io, local.spec
canonical, document, sha = spec.canonical_json_bytes, local.document, local.sha
SCHEMA = "serverware.authorityTrustedHostLocalRegistrationEnrollmentApproval/v1"
BUNDLE_SCHEMA = "serverware.authorityTrustedHostLocalRegistrationEnrollments/v1"
PURPOSE = "enroll-fixed-first-registration-chain"
DELEGATION = "configuration-root-signs-current-root-grant-callers-and-local-bootstrap-v4"
DIRECTORY = "/run/serverware/registration-contexts"
INVENTORIES = ("pilotKeyInventory", "genesisAuditKeyInventory", "enrollmentKeyInventory", "registrationChainKeyInventory")
ORIGINALS = ("serviceConfiguration", "cohort", "initialVector")
OUTPUTS = ("currentRootEnrollment", "grantEnrollment", "executionAuthorizationEnrollment",
           "finalizationAuthorizationEnrollment", "controlPlaneBootstrap")
WORK_STAGES = ("acquire-public-inputs", "recheck-public-inputs", *OUTPUTS)
# Seven source-fixed, separately bounded operations: public admission, custody recheck and
# five distinct signed originals (the last includes its full consumer check).
# Never refill a producer's allowance or retry a failed stage. Aggregate maxima
# are 56M hashes, 448MiB metered bytes and 7M JSON nodes; all seven operations
# retain the SAME original approval/receipt clocks. Generic caps stay unchanged.
MAX_AGGREGATE_WORK = (len(WORK_STAGES) * accounting.MAX_HASHES,
    len(WORK_STAGES) * accounting.MAX_INPUT_BYTES, len(WORK_STAGES) * accounting.MAX_JSON_NODES)
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "configurationRootPublicKeyBase64Url",
    "generation", "artifactPackageDigest", "databaseId", "measurements", "callerIds", "contextDirectory",
    "issuerPrivateKeyFd", "requestTimeoutSeconds", "maximumControlAgeNs", "maximumGrantAgeNs",
    "maximumAuthorizationAgeNs", "maximumClockSkewNs", "maximumRecords", "bootIdDigest",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
    | {name + "Original" for name in INVENTORIES + ORIGINALS}
    | {name + "Sha256" for name in ORIGINALS})


def require(value):
    if not value:
        raise ValueError("local registration enrollment refused")


class _WorkPlan:
    """Fixed composition schedule; issuing a ledger consumes that stage once."""

    def __init__(self):
        self.next_stage = 0

    def take(self, name):
        require(type(name) is str and self.next_stage < len(WORK_STAGES)
            and name == WORK_STAGES[self.next_stage])
        self.next_stage += 1
        return _ValidationWork(QueryReadValidationLimits())


def _original(value, name, maximum=io.MAX_PUBLIC):
    text = value[name + "Original"]
    require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    require(sha(raw) == value[name + "Sha256"])
    return raw


def _key(row):
    return Ed25519PublicKey.from_public_bytes(local._public(row["publicKeyBase64Url"]))


def _endpoint(path, timeout):
    return dict(socketPath=path, requestTimeoutSeconds=timeout, listenerUid=0, listenerGid=0)


def _transport(raw):
    return dict(base64Url=spec.strict_base64url_encode(raw), byteCount=len(raw))


def _nested(module, caller_field, current_raw, grant_raw, authorization_raw, selected):
    result = dict(schema=module.LOCAL_SCHEMA, currentRootEnrollment=_transport(current_raw),
        grantEnrollment=_transport(grant_raw), authorizationEnrollment=_transport(authorization_raw),
        contextDirectory=selected["contextDirectory"])
    result[caller_field] = module.CALLER_KEY_FD
    for name, path in (("authorizerEndpoint", module.AUTHORIZER_SOCKET_PATH),
            ("reserverEndpoint", module.RESERVER_SOCKET_PATH), ("sqlEndpoint", module.SQL_SOCKET_PATH),
            ("completionEndpoint", module.COMPLETION_SOCKET_PATH)):
        result[name] = _endpoint(path, selected["requestTimeoutSeconds"])
    module._shape(result)
    return result


def prepare(raw, *, boot, now_boottime_ns, now_unix_ns, work):
    """Validate public originals and explicit delegation; never accept verdict DTOs."""
    value = document(raw, io.MAX_PUBLIC)
    require(set(value) == FIELDS and value["schema"] == SCHEMA and value["purpose"] == PURPOSE
        and value["rootDelegation"] == DELEGATION and value["bootIdDigest"] == boot)
    spec._require_digest(boot, name="registration enrollment boot")
    for first, last, now in (("issuedAtBoottimeNs", "deadlineBoottimeNs", now_boottime_ns),
                             ("issuedAtUnixNanos", "expiresAtUnixNanos", now_unix_ns)):
        require(type(now) is int and type(value[first]) is type(value[last]) is int
            and 0 < value[first] <= now < value[last] < 2**63
            and value[last] - value[first] <= LOCAL_SETUP_MAX_NS)
    pilot, _ = keys._pilot_inventory(value["pilotKeyInventoryOriginal"])
    audit, _ = keys.genesis_audit_inventory(value["genesisAuditKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"])
    enrolled, _ = keys.enrollment_inventory(value["enrollmentKeyInventoryOriginal"],
        value["pilotKeyInventoryOriginal"], value["genesisAuditKeyInventoryOriginal"])
    chain, _ = keys.chain_inventory(value["registrationChainKeyInventoryOriginal"],
        value["pilotKeyInventoryOriginal"], value["genesisAuditKeyInventoryOriginal"], value["enrollmentKeyInventoryOriginal"])
    existing = {(row["family"], row["purpose"]): row for row in pilot["keys"]}
    added = {row["purpose"]: row for row in enrolled["keys"]}
    selected_keys = {row["purpose"]: row for row in chain["keys"]}
    root_row = existing[("configuration", "configuration-root")]
    require(value["configurationRootPublicKeyBase64Url"] == root_row["publicKeyBase64Url"])
    root = _key(root_row)
    source_raw = _original(value, "serviceConfiguration", configuration.authority.MAX_REQUEST_BYTES)
    signed = document(source_raw, configuration.authority.MAX_REQUEST_BYTES)
    require(set(signed) == {"schema", "payload", "signature"}
        and signed["schema"] == local.generator.SERVICE_CONFIGURATION_SCHEMA)
    root.verify(spec.strict_base64url_decode(signed["signature"], name="Service6 signature", decoded_size=64),
        local.signature_message("authority-service", signed["payload"]))
    payload = signed["payload"]
    digest = configuration.capability.plan._frame(configuration.CONFIG_SCHEMA, (canonical(payload),), work)
    require(type(value["generation"]) is dict and set(value["generation"]) == set(configuration._GENERATION_FIELDS))
    payload, generation = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=digest, generation=value["generation"], work=work)
    # This connector is initial-local only. Existing later/native producers are
    # separate; a caller cannot select this path by merely supplying sequence0.
    require(configuration._initial_trusted_host_local(payload, generation))
    for role in cohort.ROLES:
        row = existing[("service", role)]
        configured = payload["roles"][role]
        require(configured["responseSigningSpkiDigest"] == row["publicKeySpkiSha256"])
        for name in ("signingPublicKeyBase64Url", "responseSigningPublicKeyBase64Url"):
            if name in configured: require(configured[name] == row["publicKeyBase64Url"])
    require(payload["policyGenesis"]["auditSignerPublicKeyDigest"] == audit["keys"][0]["publicKeySpkiSha256"]
        and payload[bootstrap.enrollment_policy.FIELD]["signingPublicKeyBase64Url"] == added["authorization"]["publicKeyBase64Url"]
        and payload[evidence_policy.FIELD]["registration"]["signingPublicKeyBase64Url"] == added["registration-evidence"]["publicKeyBase64Url"])
    spec._require_digest(value["artifactPackageDigest"], name="approved installed package")
    cohort_raw = _original(value, "cohort", cohort.MAX_BYTES)
    admitted, _body, receipt_payloads = cohort._verify_cohort_against_scope(held_bytes=cohort_raw,
        held_digest=digest, held_key=root, static_configuration=cohort._static_configuration(payload),
        generation_sequence=generation["sequence"], generation_digest=generation["digest"],
        package_digest=value["artifactPackageDigest"], local_binding=None, evaluation_epoch_ns=now_unix_ns)
    require(admitted.valid_from_epoch_ns <= value["issuedAtUnixNanos"]
        and value["expiresAtUnixNanos"] <= admitted.valid_until_epoch_ns)
    receipt_digests = {role: pin for role, _raw, pin in admitted.receipts}
    runtime = dict(schema=configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA, configurationDigest=digest,
        generationSequence=admitted.generation_sequence, generationDigest=admitted.generation_digest,
        cohortDigest=admitted.cohort_digest, roles={row["role"]: dict(measurementDigest=row["measurementDigest"],
            responseSigningSpkiDigest=row["responseSigningSpkiDigest"], attestationReceiptDigest=receipt_digests[row["role"]])
            for row in receipt_payloads})
    runtime = configuration._capture_runtime_role_identities_on_work(runtime_role_identities=runtime,
        owned_payload=payload, configuration_digest=digest, launch=generation, work=work)
    vector = current.vector._decode_on_work(_original(value, "initialVector", current.vector.MAX_BYTES), work=work)
    current._token(value["databaseId"])
    require(type(value["measurements"]) is dict and set(value["measurements"]) == set(selected_keys))
    for pin in value["measurements"].values(): spec._require_digest(pin, name="independently enrolled cold role")
    require(type(value["callerIds"]) is dict and set(value["callerIds"]) == {"execution", "finalization"})
    for identity in value["callerIds"].values(): current._token(identity)
    require(value["callerIds"]["execution"] != value["callerIds"]["finalization"])
    for name in ("maximumControlAgeNs", "maximumGrantAgeNs", "maximumAuthorizationAgeNs"):
        current.shape._integer(value[name], current.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    current.shape._integer(value["maximumClockSkewNs"], current.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    current.shape._integer(value["maximumRecords"], current.MAX_RECORDS, minimum=2)
    current.shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    current.shape._integer(value["issuerPrivateKeyFd"], 1023, minimum=32)
    require(value["issuerPrivateKeyFd"] not in (execution_profile.CALLER_KEY_FD, finalization_profile.CALLER_KEY_FD))
    directory = value["contextDirectory"]
    require(type(directory) is dict and set(directory) == {"path", "device", "inode"}
        and directory["path"] == DIRECTORY and type(directory["device"]) is type(directory["inode"]) is int
        and 0 <= directory["device"] < 2**64 and 0 < directory["inode"] < 2**64)
    return dict(selected=value, payload=payload, generation=generation, runtime=runtime, root=root,
        configurationDigest=digest, vector=vector, chain=selected_keys,
        planner=_key(existing[("service", "planner")]), evidence=_key(added["registration-evidence"]),
        deadline=value["deadlineBoottimeNs"], epochLimit=value["expiresAtUnixNanos"])


def _capture_prepared(value, work):
    """Retain actual admitted entries, never an aliased mutable verdict.

    The immutable tree pins each original container and scalar/key object.
    Text is measured once without encoding; its exact canonical size is held
    for the later comparison/copy reservation. Floats are immutable leaves,
    not fed into the generic lossless-JSON encoder or normalized to integers.
    """
    kind = type(value)
    if kind is dict:
        work.charge(json_nodes=1 + 2 * len(value))
        entries = []
        for name, child in value.items():
            require(type(name) is str)
            size, _ = work.measure(name)
            entries.append((name, size, _capture_prepared(child, work)))
        return kind, value, tuple(entries), 0
    if kind in (list, tuple):
        work.charge(json_nodes=1 + len(value))
        return kind, value, tuple(_capture_prepared(child, work) for child in value), 0
    require(kind in (str, int, float, bool, type(None)) or isinstance(value, Ed25519PublicKey))
    if kind is str:
        size, _ = work.measure(value)
    else:
        work.charge(json_nodes=1)
        size = 0
    return kind, value, None, size


def _copy_prepared(binding, value, work):
    """Compare original identity and reconstruct only held immutable entries."""
    kind, original, entries, size = binding
    require(value is original and type(value) is kind)
    if kind is dict:
        work.charge(json_nodes=1 + 2 * len(entries))
        require(len(value) == len(entries))
        result = {}
        for (name, child), (held_name, key_size, held_child) in zip(value.items(), entries, strict=True):
            work.charge(input_bytes=key_size, json_nodes=1)
            require(name is held_name)
            result[held_name] = _copy_prepared(held_child, child, work)
        return result
    if kind in (list, tuple):
        work.charge(json_nodes=1 + len(entries))
        require(len(value) == len(entries))
        result = [_copy_prepared(held, child, work) for child, held in zip(value, entries, strict=True)]
        return tuple(result) if kind is tuple else result
    # Immutable strings and public-key objects are retained, not re-encoded or
    # read from a caller-supplied replacement. Charge the held text size even
    # though an identity comparison can itself avoid a full character walk.
    work.charge(input_bytes=size, json_nodes=1)
    return original


def _compose(context, key, work_plan, check):
    """Five distinct outputs on fixed one-use ledgers, in dependency order."""
    value, rows, root = context["selected"], context["chain"], context["root"]
    require(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        == root.public_bytes(Encoding.Raw, PublicFormat.Raw))
    current_payload = dict(schema=current.ENROLLMENT_PAYLOAD_SCHEMA, sourceRevision=current.authority.SOURCE_REVISION,
        databaseId=value["databaseId"], generationDigest=context["generation"]["digest"],
        initialVector=context["vector"], maxControlAgeNs=value["maximumControlAgeNs"],
        maxClockSkewNs=value["maximumClockSkewNs"], maxRecords=value["maximumRecords"])
    for role in current._ROLES:
        current_payload[role] = dict(publicKeyPem=_key(rows[role]).public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            spkiDigest=rows[role]["publicKeySpkiSha256"], measurementDigest=value["measurements"][role])
    check()
    current_raw = current._produce_enrollment_on_work(payload=current_payload,
        root_private_key=key, root_public_key=root, work=work_plan.take("currentRootEnrollment"))
    check()
    grant_raw = grant._produce_on_work(current_root_enrollment_bytes=current_raw,
        root_private_key=key, root_public_key=root, authorizer_public_key=_key(rows["grant-authorizer"]),
        authorizer_measurement_digest=value["measurements"]["grant-authorizer"],
        maximum_grant_age_ns=value["maximumGrantAgeNs"], maximum_clock_skew_ns=value["maximumClockSkewNs"],
        work=work_plan.take("grantEnrollment"))
    authorizations = {}
    for purpose, module in (("execution", execution), ("finalization", finalization)):
        check()
        role = purpose + "-caller"
        authorizations[purpose] = module._produce_enrollment_on_work(current_root_enrollment_bytes=current_raw,
            grant_enrollment_bytes=grant_raw, root_private_key=key, root_public_key=root,
            configuration_digest=context["configurationDigest"], caller_public_key=_key(rows[role]),
            caller_measurement_digest=value["measurements"][role], caller_id=value["callerIds"][purpose],
            planner_public_key=context["planner"], evidence_public_key=context["evidence"],
            maximum_age_ns=value["maximumAuthorizationAgeNs"], maximum_clock_skew_ns=value["maximumClockSkewNs"],
            work=work_plan.take(purpose + "AuthorizationEnrollment"))
    execution_input = _nested(execution_profile, "executionCallerPrivateKeyFd", current_raw, grant_raw, authorizations["execution"], value)
    finalization_input = _nested(finalization_profile, "finalizationCallerPrivateKeyFd", current_raw, grant_raw, authorizations["finalization"], value)
    check()
    bootstrap_raw = bootstrap._produce_v4_on_work(configuration_payload=context["payload"], generation=context["generation"],
        runtime_role_identities=context["runtime"], configuration_digest=context["configurationDigest"],
        issuer_private_key_fd=value["issuerPrivateKeyFd"], signer_endpoint=_endpoint(bootstrap.SIGNER_SOCKET_PATH, value["requestTimeoutSeconds"]),
        registration_execution=execution_input, registration_finalization=finalization_input,
        runtime_root_private_key=key, runtime_root_public_key=root, work=work_plan.take("controlPlaneBootstrap"))
    check()
    return dict(zip(OUTPUTS, (current_raw, grant_raw, authorizations["execution"], authorizations["finalization"], bootstrap_raw)))


class LocalRegistrationEnrollment:
    """Borrow three retained descriptors; acquire no child, socket, SQL or key FD."""

    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd, context_directory_fd):
        io._process()
        from serverware import config
        require(type(self) is LocalRegistrationEnrollment and not config.PRODUCTION_IMAGE
            and os.environ.get("SERVERWARE_RELEASE_CHANNEL") == "dev"
            and os.environ.get("SERVERWARE_PROCESS_MODE") == "metadata-bootstrap")
        require(all(type(fd) is int and fd >= 3 for fd in (approval_fd, signing_key_fd, context_directory_fd))
            and len({approval_fd, signing_key_fd, context_directory_fd}) == 3)
        self.origin = os.getpid(), tuple(sorted(os.environ.items()))
        self.fd, self.key_fd, self.directory_fd = approval_fd, signing_key_fd, context_directory_fd
        self.identity, self.key_identity = io._input(approval_fd, io.MAX_PUBLIC), io._input(signing_key_fd, 32, private=True)
        require(self.identity[:2] != self.key_identity[:2])
        self.raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        spec._require_digest(approval_sha256, name="registration enrollment approval")
        require(sha(self.raw) == approval_sha256)
        self.boot = local.launcher._boot_identity_digest()
        self._process_identity = local.launcher._process_identity(os.getpid())
        self.last_boot, self.last_unix = io._clock(), time.time_ns()
        self.work_plan = _WorkPlan()
        acquisition = self.work_plan.take("acquire-public-inputs")
        self.context = prepare(self.raw, boot=self.boot, now_boottime_ns=self.last_boot, now_unix_ns=self.last_unix,
            work=acquisition)
        self._prepared = _capture_prepared(self.context, acquisition)
        selected = self.context["selected"]
        self._window = (selected["issuedAtBoottimeNs"], selected["deadlineBoottimeNs"],
            selected["issuedAtUnixNanos"], selected["expiresAtUnixNanos"])
        directory = selected["contextDirectory"]
        self._directory = (directory["device"], directory["inode"])
        self._retained = self._retained_pin = (self.fd, self.key_fd, self.directory_fd,
            self.identity, self.key_identity, self.raw, self.boot, self.origin,
            self.context, self.work_plan, self._prepared, self._window, self._directory, self._process_identity,
            selected, directory, self.context["root"], self.context["planner"], self.context["evidence"])
        self._previous = self._previous_pin = (self.last_boot, self.last_unix)
        self.used, self.closed = False, False
        self.check()

    def _held(self):
        retained = self._retained
        require(type(self) is LocalRegistrationEnrollment and type(retained) is tuple
            and len(retained) == 19 and retained is self._retained_pin
            and all(value is held for value, held in zip((self.fd, self.key_fd, self.directory_fd,
                self.identity, self.key_identity, self.raw, self.boot, self.origin,
                self.context, self.work_plan, self._prepared, self._window, self._directory,
                self._process_identity), retained[:14], strict=True)))
        selected = self.context.get("selected")
        require(selected is retained[14])
        directory = selected.get("contextDirectory")
        require(directory is retained[15]
            and all(self.context.get(name) is held for name, held in zip(
                ("root", "planner", "evidence"), retained[16:], strict=True)))
        require(self.context.get("deadline") is self._window[1] and self.context.get("epochLimit") is self._window[3]
            and all(selected.get(name) is held for name, held in zip(
                ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"), self._window, strict=True))
            and directory.get("device") is self._directory[0] and directory.get("inode") is self._directory[1])
        previous = self._previous
        require(type(previous) is tuple and len(previous) == 2 and previous is self._previous_pin
            and self.last_boot is previous[0] and self.last_unix is previous[1])
        return previous

    def check(self):
        io._process()
        previous = self._held()
        require(not self.closed and self.origin == (os.getpid(), tuple(sorted(os.environ.items())))
            and local.launcher._process_identity(os.getpid()) == self._process_identity
            and local.launcher._boot_identity_digest() == self.boot
            and io._input(self.fd, io.MAX_PUBLIC) == self.identity
            and io._input(self.key_fd, 32, private=True) == self.key_identity)
        now_boot, now_unix = io._clock(), time.time_ns()
        require(self._window[0] <= previous[0] <= now_boot < self._window[1]
            and self._window[2] <= previous[1] <= now_unix < self._window[3]
            and io.read_public(self.fd, io.MAX_PUBLIC) == self.raw)
        held, named = os.fstat(self.directory_fd), os.stat(DIRECTORY, follow_symlinks=False)
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode)
            and (held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)) == (0, 65532, 0o750)
            and (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) == (0, 65532, 0o750)
            and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) == self._directory
            and os.path.realpath(DIRECTORY) == DIRECTORY)
        require(self._held() is previous
            and self.origin == (os.getpid(), tuple(sorted(os.environ.items())))
            and local.launcher._process_identity(os.getpid()) == self._process_identity
            and local.launcher._boot_identity_digest() == self.boot
            and io._input(self.fd, io.MAX_PUBLIC) == self.identity
            and io._input(self.key_fd, 32, private=True) == self.key_identity)
        after_boot, after_unix = io._clock(), time.time_ns()
        require(now_boot <= after_boot < self._window[1] and now_unix <= after_unix < self._window[3]
            and self._held() is previous)
        self.last_boot, self.last_unix = after_boot, after_unix
        self._previous = self._previous_pin = (after_boot, after_unix)

    def issue(self):
        self.check(); require(not self.used); self.used = True
        # Constructor admission proves the whole approval interval lies inside
        # every signed cohort receipt. The unchanged current clocks/FDs plus
        # exact held entries preserve that admission without fresh signatures.
        # A fresh detached graph, never self.context, enters the real producers.
        context = _copy_prepared(self._prepared, self.context,
            self.work_plan.take("recheck-public-inputs"))
        self.check()
        key = io.signing_key(self.key_fd)
        self.check()
        outputs = _compose(context, key, self.work_plan, self.check)
        raw = canonical(dict(schema=BUNDLE_SCHEMA, approvalSha256=sha(self.raw),
            configurationDigest=context["configurationDigest"], generationDigest=context["generation"]["digest"],
            cohortDigest=context["runtime"]["cohortDigest"],
            originals={name: value.decode("ascii") for name, value in outputs.items()},
            sha256={name: sha(value) for name, value in outputs.items()},
            bootIdDigest=self.boot, deadlineBoottimeNs=context["deadline"], expiresAtUnixNanos=context["epochLimit"],
            databaseObserved=False, hardwareCeremonyPerformed=False, grantsIssued=False))
        require(len(raw) <= io.MAX_PUBLIC)
        self.check()
        return raw

    def publish(self):
        io.write_public(self.issue(), deadline_boottime_ns=self._window[1], check=self.check)
        self.check()

    def close(self):
        # No acquisition occurred: all three descriptors remain caller-owned.
        # Closing this borrowed view never requires an unexpired authority window.
        io._process()
        require(self.origin[0] == os.getpid())
        self.closed = True
