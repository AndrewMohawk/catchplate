"""Original-only native start constraints, with explicitly selected retirement.

Signing is not a process, cgroup or network operation. The native start owner
must independently verify the exact original, pinned root, token, manifests,
host and retained parents before its one-use claims. Returned material is not
a start/cleanup permit and never projects or renews a runtime BOOTTIME deadline.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from catchplate import native_egress_installation_authorization as egress
from catchplate import native_enrollment_assignment as assignment
from catchplate import workload_identity_issuer_bootstrap as shared
from catchplate_agent_trust import _workload_signed_packet as packets


SCHEMA = "catchplate.signedNativeWorkloadStartAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.nativeWorkloadStartAuthorization/v1"
RETIREMENT_SCHEMA = "catchplate.signedNativeWorkloadStartAuthorization/v2"
RETIREMENT_PAYLOAD_SCHEMA = "catchplate.nativeWorkloadStartAuthorization/v2"
START_PROFILE = "native-workload-start-v1"
RETIREMENT_PROFILE = "native-workload-start-retirement-v2"
OUTCOME_PROFILE = "native-workload-start-outcome-v3"
OUTCOME_SCHEMA = "catchplate.signedNativeWorkloadStartAuthorization/v3"
OUTCOME_PAYLOAD_SCHEMA = "catchplate.nativeWorkloadStartAuthorization/v3"
APPLICATION_PROFILE = "native-workload-start-application-proxy-v4"
APPLICATION_SCHEMA = "catchplate.signedNativeWorkloadStartAuthorization/v4"
APPLICATION_PAYLOAD_SCHEMA = "catchplate.nativeWorkloadStartAuthorization/v4"
MAX_BYTES = 32 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_U64 = (1 << 64) - 1
MAX_EPOCH_NS = (1 << 63) - 1
MAX_EPOCH_MS = 9_223_372_036_854
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "creationMode", "authorizationId",
    "egressAuthorizationSha256", "attachmentAuthorizationSha256", "launchManifestSha256",
    "executionManifestSha256", "launcherBinarySha256", "machineIdSha256", "networkOwner",
    "isolation", "resources", "containment", "capability", "journal",
    "issuedAtEpochNs", "startBeforeEpochNs", "stopAtEpochNs", "cleanupBeforeEpochNs",
})
_DIGEST_FIELDS = ("egressAuthorizationSha256", "attachmentAuthorizationSha256",
    "launchManifestSha256", "executionManifestSha256", "launcherBinarySha256", "machineIdSha256")
_CONTAINMENT_FIELDS = frozenset({"profile", "parentPath", "parentDevice", "parentInode",
    "childName", "guardianProfile"})
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_CHILD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")


class NativeWorkloadStartAuthorizationError(ValueError):
    pass


def _fail():
    raise NativeWorkloadStartAuthorizationError("native workload start authorization is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _StartAuthorizationMaterial:
    authorization_bytes: bytes
    authorization_digest: str
    payload_bytes: bytes
    root_pem_digest: str
    root_spki_digest: str
    requested_profile: str
    authorization_id: str
    issued_at_epoch_ns: int
    start_before_epoch_ns: int
    stop_at_epoch_ns: int
    cleanup_before_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _profile(requested_profile):
    # Caller-selected cold policy, never selected by untrusted incoming bytes.
    if type(requested_profile) is not str:
        _fail()
    if requested_profile == START_PROFILE:
        return SCHEMA, PAYLOAD_SCHEMA, False, False
    if requested_profile == RETIREMENT_PROFILE:
        return RETIREMENT_SCHEMA, RETIREMENT_PAYLOAD_SCHEMA, True, False
    if requested_profile == OUTCOME_PROFILE:
        return OUTCOME_SCHEMA, OUTCOME_PAYLOAD_SCHEMA, True, True
    if requested_profile == APPLICATION_PROFILE:
        return APPLICATION_SCHEMA, APPLICATION_PAYLOAD_SCHEMA, True, True
    _fail()


def _path(value):
    path = assignment._ascii(value, 4096)
    parts = path[1:].split("/")
    if (not path.startswith("/") or path == "/" or "\\" in path or len(parts) > 64
            or any(part in ("", ".", "..") or len(part) > 255 for part in parts)):
        _fail()


def _host(value):
    shared._object(value, {"hostId", "bootId", "namespaceDevice", "namespaceInode", "ownerUid"})
    shared._identifier(value["hostId"])
    if type(value["bootId"]) is not str or _BOOT_ID.fullmatch(value["bootId"]) is None:
        _fail()
    for field in ("namespaceDevice", "namespaceInode"):
        shared._integer(value[field], MAX_U64, 1)
    shared._integer(value["ownerUid"], 0, 0)


def _isolation(value):
    shared._object(value, {"profile", "uid", "gid", "supplementaryGroups",
        "noNewPrivileges", "namespaces", "umask", "stdio"})
    for field in ("uid", "gid"):
        shared._integer(value[field], (1 << 32) - 2, 1)
    shared._integer(value["umask"], 63, 63)
    if (value["profile"] != "non-root-empty-capabilities-v1"
            or type(value["supplementaryGroups"]) is not list or value["supplementaryGroups"]
            or value["noNewPrivileges"] is not True
            or type(value["namespaces"]) is not list
            or value["namespaces"] != ["mount", "ipc", "uts", "network", "pid"]
            or value["stdio"] != "null-input-bounded-output-v1"):
        _fail()


def _resources(value):
    bounds = {
        "memoryMaxBytes": (16 * 1024 * 1024, 1_099_511_627_776),
        "memorySwapMaxBytes": (0, 0), "pidsMax": (1, 4096),
        "cpuMaxQuotaUs": (1000, 6_400_000), "cpuMaxPeriodUs": (100_000, 100_000),
        "outputMaxBytes": (4096, 67_108_864),
    }
    shared._object(value, bounds.keys())
    for field, (minimum, maximum) in bounds.items():
        shared._integer(value[field], maximum, minimum)


def _containment(value, journal, retirement, outcome):
    shared._object(value, _CONTAINMENT_FIELDS | {"retirementProfile"}
        if retirement else _CONTAINMENT_FIELDS)
    if (value["profile"] != "cgroup-v2-new-leaf-kill-v1"
            or value["guardianProfile"] != "independent-cgroup-guardian-v1"
            or retirement and value["retirementProfile"] != "remove-empty-owned-leaf-v1"):
        _fail()
    _path(value["parentPath"])
    for field in ("parentDevice", "parentInode"):
        shared._integer(value[field], MAX_U64, 1)
    if type(value["childName"]) is not str or _CHILD_NAME.fullmatch(value["childName"]) is None:
        _fail()
    shared._object(journal, {"path", "device", "inode", "namespace", "outcomeProfile"}
        if outcome else {"path", "device", "inode", "namespace"})
    if outcome and journal["outcomeProfile"] != "durable-terminal-retirement-v1":
        _fail()
    _path(journal["path"])
    shared._identifier(journal["namespace"])
    for field in ("device", "inode"):
        shared._integer(journal[field], MAX_U64, 1)
    if (journal["path"] == value["parentPath"]
            or (journal["device"], journal["inode"]) == (value["parentDevice"], value["parentInode"])):
        _fail()


def _payload(value, budget, requested_profile):
    _, payload_schema, retirement, outcome = _profile(requested_profile)
    application = requested_profile == APPLICATION_PROFILE
    shared._object(value, _FIELDS | {"applicationProxySha256"} if application else _FIELDS)
    if application:
        assignment._digest(value["applicationProxySha256"])
    if (value["schema"] != payload_schema
            or value["sourceRevision"] != shared.authority.SOURCE_REVISION
            or value["purpose"] != "native-workload-start"
            or value["trustMode"] != "trusted-host-local"
            or value["creationMode"] != "new-execution-child-v1"):
        _fail()
    shared._identifier(value["authorizationId"])
    for field in _DIGEST_FIELDS:
        assignment._digest(value[field])
    if (value["egressAuthorizationSha256"] == value["attachmentAuthorizationSha256"]
            or value["launchManifestSha256"] == value["executionManifestSha256"]):
        _fail()
    _host(value["networkOwner"])
    _isolation(value["isolation"])
    _resources(value["resources"])
    _containment(value["containment"], value["journal"], retirement, outcome)
    capability = shared._object(value["capability"],
        {"capabilityId", "capabilityTokenSha256", "expiresAtEpochMs"})
    shared._identifier(capability["capabilityId"])
    assignment._digest(capability["capabilityTokenSha256"])
    expiry_ms = shared._integer(capability["expiresAtEpochMs"], MAX_EPOCH_MS, 1)
    issued, start, stop, cleanup = (
        shared._integer(value[field], MAX_EPOCH_NS, 1)
        for field in ("issuedAtEpochNs", "startBeforeEpochNs", "stopAtEpochNs", "cleanupBeforeEpochNs"))
    if (not issued < start < stop < cleanup or start - issued > 300_000_000_000
            or start > expiry_ms * 1_000_000 or stop - start > 86_400_000_000_000
            or not 100_000_000 <= cleanup - stop <= 30_000_000_000):
        _fail()
    # Only the signed preparation boundary narrows the existing budget. Later
    # stop/cleanup epochs do not create a fresh preparation or signing lifetime.
    budget.interval(issued, start)


def _admit(original, public, root_pin, budget, requested_profile):
    schema, payload_schema, _, _ = _profile(requested_profile)
    egress._structure(original, budget)
    payload = shared._signed(original, schema, payload_schema, public, MAX_BYTES, budget)
    _payload(payload, budget, requested_profile)
    material = _StartAuthorizationMaterial(
        authorization_bytes=original, authorization_digest=packets._digest(original, budget),
        payload_bytes=packets._canonical(payload, MAX_BYTES, budget), root_pem_digest=root_pin,
        root_spki_digest=packets._digest(shared._spki(public, budget), budget),
        requested_profile=requested_profile, authorization_id=payload["authorizationId"],
        issued_at_epoch_ns=payload["issuedAtEpochNs"], start_before_epoch_ns=payload["startBeforeEpochNs"],
        stop_at_epoch_ns=payload["stopAtEpochNs"], cleanup_before_epoch_ns=payload["cleanupBeforeEpochNs"],
        window=budget.window, deadline_ns=budget.bound, live=budget.current)
    material.live()
    return material


def _verify_on_work(*, authorization_bytes, root_public_key_bytes, expected_root_pem_sha256,
        work, live_window, transport_deadline_ns, requested_profile=START_PROFILE,
        _current=None, _additional_original_bytes=0):
    """Verify exact originals on existing work; default v1 refuses any v2 field."""
    try:
        _profile(requested_profile)
        egress._preflight(((authorization_bytes, MAX_BYTES), (root_public_key_bytes, MAX_KEY_BYTES)),
            work, _additional_original_bytes)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        return _admit(authorization_bytes, public, expected_root_pem_sha256, budget, requested_profile)
    except NativeWorkloadStartAuthorizationError:
        raise
    except Exception:
        raise NativeWorkloadStartAuthorizationError("native workload start authorization verification failed") from None


def _produce_on_work(*, payload_bytes, root_private_key_bytes, root_public_key_bytes,
        expected_root_pem_sha256, work, live_window, transport_deadline_ns,
        requested_profile=START_PROFILE, _current=None, _additional_original_bytes=0):
    """Sign supplied canonical PKCS8 originals; no key generation, file or effect."""
    try:
        schema, payload_schema, _, _ = _profile(requested_profile)
        egress._preflight(((payload_bytes, MAX_BYTES), (root_private_key_bytes, MAX_KEY_BYTES),
            (root_public_key_bytes, MAX_KEY_BYTES)), work, _additional_original_bytes, producing=True)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        egress._structure(payload_bytes, budget)
        payload = shared._decode(payload_bytes, MAX_BYTES, budget)
        _payload(payload, budget, requested_profile)
        budget.charge(input_bytes=len(root_private_key_bytes))
        private = serialization.load_pem_private_key(root_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) != root_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        original = shared._produce(payload_bytes, schema, payload_schema,
            private, public, MAX_BYTES, budget)
        admitted = _admit(original, public, expected_root_pem_sha256, budget, requested_profile)
        admitted.live()
        budget.check()
        return original
    except NativeWorkloadStartAuthorizationError:
        raise
    except Exception:
        raise NativeWorkloadStartAuthorizationError("native workload start authorization production failed") from None
