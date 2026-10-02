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
            and value[last] - value[first] <= 300_000_000_000)
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


def _compose(context, key, work, check):
    """Five existing producers on one cumulative allowance, in dependency order."""
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
        root_private_key=key, root_public_key=root, work=work)
    check()
    grant_raw = grant._produce_on_work(current_root_enrollment_bytes=current_raw,
        root_private_key=key, root_public_key=root, authorizer_public_key=_key(rows["grant-authorizer"]),
        authorizer_measurement_digest=value["measurements"]["grant-authorizer"],
        maximum_grant_age_ns=value["maximumGrantAgeNs"], maximum_clock_skew_ns=value["maximumClockSkewNs"], work=work)
    authorizations = {}
    for purpose, module in (("execution", execution), ("finalization", finalization)):
        check()
        role = purpose + "-caller"
        authorizations[purpose] = module._produce_enrollment_on_work(current_root_enrollment_bytes=current_raw,
            grant_enrollment_bytes=grant_raw, root_private_key=key, root_public_key=root,
            configuration_digest=context["configurationDigest"], caller_public_key=_key(rows[role]),
            caller_measurement_digest=value["measurements"][role], caller_id=value["callerIds"][purpose],
            planner_public_key=context["planner"], evidence_public_key=context["evidence"],
            maximum_age_ns=value["maximumAuthorizationAgeNs"], maximum_clock_skew_ns=value["maximumClockSkewNs"], work=work)
    execution_input = _nested(execution_profile, "executionCallerPrivateKeyFd", current_raw, grant_raw, authorizations["execution"], value)
    finalization_input = _nested(finalization_profile, "finalizationCallerPrivateKeyFd", current_raw, grant_raw, authorizations["finalization"], value)
    check()
    bootstrap_raw = bootstrap._produce_v4_on_work(configuration_payload=context["payload"], generation=context["generation"],
        runtime_role_identities=context["runtime"], configuration_digest=context["configurationDigest"],
        issuer_private_key_fd=value["issuerPrivateKeyFd"], signer_endpoint=_endpoint(bootstrap.SIGNER_SOCKET_PATH, value["requestTimeoutSeconds"]),
        registration_execution=execution_input, registration_finalization=finalization_input,
        runtime_root_private_key=key, runtime_root_public_key=root, work=work)
    check()
    return dict(zip(OUTPUTS, (current_raw, grant_raw, authorizations["execution"], authorizations["finalization"], bootstrap_raw)))


class LocalRegistrationEnrollment:
    """Borrow three retained descriptors; acquire no child, socket, SQL or key FD."""

    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd, context_directory_fd):
        io._process()
        from serverware import config
        require(not config.PRODUCTION_IMAGE and os.environ.get("SERVERWARE_RELEASE_CHANNEL") == "dev"
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
        self.last_boot, self.last_unix = io._clock(), time.time_ns()
        self.work = _ValidationWork(QueryReadValidationLimits())
        self.context = prepare(self.raw, boot=self.boot, now_boottime_ns=self.last_boot, now_unix_ns=self.last_unix, work=self.work)
        self.used, self.closed = False, False
        self.check()

    def check(self):
        io._process()
        require(not self.closed and self.origin == (os.getpid(), tuple(sorted(os.environ.items())))
            and local.launcher._boot_identity_digest() == self.boot
            and io._input(self.fd, io.MAX_PUBLIC) == self.identity
            and io._input(self.key_fd, 32, private=True) == self.key_identity
            and io.read_public(self.fd, io.MAX_PUBLIC) == self.raw)
        now_boot, now_unix = io._clock(), time.time_ns()
        require(self.last_boot <= now_boot < self.context["deadline"]
            and self.last_unix <= now_unix < self.context["epochLimit"])
        self.last_boot, self.last_unix = now_boot, now_unix
        selected = self.context["selected"]["contextDirectory"]
        held, named = os.fstat(self.directory_fd), os.stat(DIRECTORY, follow_symlinks=False)
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(named.st_mode)
            and (held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)) == (0, 65532, 0o750)
            and (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) == (0, 65532, 0o750)
            and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino) == (selected["device"], selected["inode"])
            and os.path.realpath(DIRECTORY) == DIRECTORY)

    def issue(self):
        self.check(); require(not self.used); self.used = True
        # Re-authenticate the same originals/current cohort before private access.
        context = prepare(self.raw, boot=self.boot, now_boottime_ns=self.last_boot, now_unix_ns=self.last_unix, work=self.work)
        outputs = _compose(context, io.signing_key(self.key_fd), self.work, self.check)
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
        io.write_public(self.issue(), deadline_boottime_ns=self.context["deadline"], check=self.check)
        self.check()

    def close(self):
        # No acquisition occurred: all three descriptors remain caller-owned.
        # Closing this borrowed view never requires an unexpired authority window.
        io._process()
        require(self.origin[0] == os.getpid())
        self.closed = True
