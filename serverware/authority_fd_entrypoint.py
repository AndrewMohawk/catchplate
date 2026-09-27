from __future__ import annotations

import errno
import fcntl
import json
import os
import socket
import stat
import sys


MAX_SOURCE_BYTES = 64 * 1024 * 1024
CONTROL_PLANE_CUSTODY_CONFIG_NAME = "SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD"
CONTROL_PLANE_CUSTODY_CONFIG_SCHEMA = "serverware.controlPlaneCustodyStartup/v1"
CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES = 16384
CONTROL_PLANE_CUSTODY_DIRECTORY = "/var/lib/serverware/control-plane-custody"
CONTROL_PLANE_CUSTODY_FD_MIN = 32
CONTROL_PLANE_CUSTODY_FD_MAX = 1023
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME = "SERVERWARE_CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_FD"
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v2"
CONTROL_PLANE_ENROLLMENT_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v2"
CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v3"
CONTROL_PLANE_ENROLLMENT_V3_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v3"
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES = 4 * 1024 * 1024
CONTROL_PLANE_ENROLLMENT_KEY_MAX_BYTES = 4096
CONTROL_PLANE_ENROLLMENT_KEY_NAME = "serverware-control-plane-enrollment-signing-key"
CONTROL_PLANE_EXECUTION_SCHEMA = "serverware.controlPlaneRegistrationExecution/v1"
CONTROL_PLANE_EXECUTION_KEY_NAME = "serverware-registration-execution-caller-key"
CONTROL_PLANE_EXECUTION_KEY_FD = 203
CONTROL_PLANE_EXECUTION_SOCKET = "/run/serverware/registration-execution/authorizer.sock"
TRUSTED_HOST_LOCAL_WITNESS_STATE_PATH = (
    "/var/lib/serverware/authority-witness"
)
TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MIN = 32
TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MAX = 1023
BOOTSTRAP_LAUNCHER_PATH = (
    "/runtime/authority-bootstrap/authority_launcher.py"
)
ROLE_IDENTITIES = {
    "control-plane": (65532, 65532),
    "runtime": (65524, 65524),
    "verifier": (65520, 65520),
    "planner": (65518, 65518),
    "planner-writer": (65519, 65519),
    "issuer": (65521, 65521),
    "executor": (65522, 65522),
    "witness": (65523, 65523),
}
ROLE_SUPPLEMENTARY_GIDS = {
    "control-plane": (65530, 65524),
    "runtime": (65520,),
    "verifier": (65518, 65521, 65522, 65523),
    "planner": (65519,),
    "planner-writer": (),
    "issuer": (65523,),
    "executor": (65523,),
    "witness": (),
}
ROLE_SOCKET_PATHS = {
    "runtime": "/run/serverware/authority-runtime/authority.sock",
    "verifier": "/run/serverware/authority-verifier/authority.sock",
    "planner": "/run/serverware/authority-planner/authority.sock",
    "planner-writer":
        "/run/serverware/authority-planner-writer/authority.sock",
    "issuer": "/run/serverware/authority-issuer/authority.sock",
    "executor": "/run/serverware/authority-executor/authority.sock",
    "witness": "/run/serverware/authority-witness/authority.sock",
}
ROLE_LISTENER_NAMES = {
    role: f"serverware-authority-{role}"
    for role in ROLE_SOCKET_PATHS
}
STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME = (
    "SERVERWARE_AUTHORITY_NATIVE_STAGE_ZERO_HANDOFF_FD"
)
OBSOLETE_STATIC_RELEASE_CONSUMER_NAMES = (
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_PATH",
)

# Delivery inventory, not the stage-zero ordinary credential inventory. The
# launch manifest is delivered here as a separately root-verified bootstrap
# control document; its bytes must never be hashed into their own payload.
# Attestation is separately retained runtime evidence, not an ordinary
# credential. Delivery preserves its original bytes; receipt admission remains
# in the service and is not granted by opening the systemd credential.
ROLE_SOURCES = {
    "control-plane": (
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "/run/serverware/authority-trust/runtime-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
            "/run/serverware/authority-trust/runtime-trust.json",
        ),
        (
            CONTROL_PLANE_CUSTODY_CONFIG_NAME,
            "/run/serverware/authority-trust/control-plane-custody.json",
        ),
        (
            CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME,
            "/run/serverware/authority-trust/control-plane-enrollment.json",
        ),
    ),
    "runtime": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-runtime-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-runtime-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
            "/run/secrets/serverware-authority-runtime-trust",
        ),
    ),
    "verifier": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-verifier-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-verifier-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-verifier-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-verifier-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-verifier-read-dsn",
        ),
    ),
    "planner": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-planner-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-planner-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-planner-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-planner-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-planner-read-dsn",
        ),
    ),
    "planner-writer": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-planner-writer-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-planner-writer-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-planner-writer-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-planner-writer-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-planner-writer-dsn",
        ),
    ),
    "issuer": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-issuer-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-issuer-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-issuer-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-issuer-dsn",
        ),
    ),
    "executor": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-executor-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-executor-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-executor-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-executor-dsn",
        ),
    ),
    "witness": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-witness-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-witness-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_CONFIG_FD",
            "/run/secrets/serverware-authority-witness-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-witness-signing-key",
        ),
    ),
}

PROCESS_MODES = {
    "control-plane": "serverware-control-plane",
    "runtime": "policy-authority-runtime",
    "verifier": "policy-authority-verifier",
    "planner": "policy-authority-planner",
    "planner-writer": "policy-authority-planner-writer",
    "issuer": "policy-authority-issuer",
    "executor": "policy-authority-executor",
    "witness": "policy-authority-replay-witness",
}
CONTROL_PLANE_HEALTH_CODE = (
    "import json,ssl,sys,urllib.request; "
    "from pathlib import Path; "
    "from serverware.response_identity import "
    "validate_response_signing_key_custody; "
    "validate_response_signing_key_custody("
    "Path('/run/secrets/serverware-response-signing-key'),"
    "Path('/run/serverware/custody-trust/"
    "control-plane-response-signing.pub.pem'),"
    "Path('/run/serverware/custody-trust/"
    "control-plane-response-signing.key-id')); "
    "context=ssl.create_default_context("
    "cafile='/run/serverware/tls/ca.pem'); "
    "response=urllib.request.urlopen("
    "'https://serverware:3000/healthz',"
    "context=context,timeout=2); "
    "response.status == 200 or sys.exit(1); "
    "json.load(response).get('ok') is True or sys.exit(1)"
)


def _read_exact_source(descriptor: int, size: int) -> bytes:
    if not 0 <= size <= MAX_SOURCE_BYTES:
        raise RuntimeError("authority descriptor source exceeds 64 MiB")
    value = bytearray()
    offset = 0
    while len(value) < size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, size - len(value)),
            offset,
        )
        if not chunk:
            raise RuntimeError("authority descriptor source was truncated")
        value.extend(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise RuntimeError("authority descriptor source grew while read")
    return bytes(value)


def _seal_bytes(
    descriptor_number: int,
    *,
    name: str,
    value: bytes,
    mode: int,
) -> int:
    if not hasattr(os, "memfd_create"):
        raise RuntimeError("authority bootstrap requires sealed memfd support")
    sealed = os.memfd_create(
        name,
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(value):
            written = os.write(sealed, value[offset:])
            if written <= 0:
                raise RuntimeError(
                    "authority bootstrap memfd write was incomplete"
                )
            offset += written
        os.fchmod(sealed, mode)
        fcntl.fcntl(
            sealed,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        os.dup2(sealed, descriptor_number, inheritable=True)
    finally:
        os.close(sealed)
    return descriptor_number


def _open_source(
    path: str,
    *,
    expected_owner_uid: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
    required_mode: int | None = None,
    directory_fd: int | None = None,
) -> int:
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_SOURCE_BYTES:
        raise RuntimeError("authority descriptor source bound is invalid")
    if required_mode is not None and (type(required_mode) is not int or required_mode != 0o400):
        raise RuntimeError("authority private source mode is not exact")
    if directory_fd is not None and (type(directory_fd) is not int or directory_fd < 0):
        raise RuntimeError("authority source parent descriptor is invalid")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        | (os.O_NONBLOCK if required_mode is not None else 0),
        dir_fd=directory_fd,
    )
    try:
        metadata_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata_before.st_uid != expected_owner_uid
            or metadata_before.st_nlink != 1
            or not 0 <= metadata_before.st_size <= maximum_bytes
            or required_mode is not None and (
                stat.S_IMODE(metadata_before.st_mode) != required_mode
                or metadata_before.st_size < 1)
        ):
            raise RuntimeError("authority descriptor source is not trusted")
        value = _read_exact_source(descriptor, metadata_before.st_size)
        metadata_after = os.fstat(descriptor)
        if (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        ):
            raise RuntimeError(
                "authority descriptor source changed while sealing"
            )
        if required_mode is not None and _material_identity(metadata_before) != _material_identity(metadata_after):
            raise RuntimeError("authority private source identity changed while sealing")
        return _seal_bytes(
            descriptor,
            name="serverware-authority-material",
            value=value,
            mode=stat.S_IMODE(metadata_before.st_mode),
        )
    except BaseException:
        os.close(descriptor)
        raise


def _material_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _control_plane_execution_key_slot(value, *, issuer_descriptor, bootstrap_descriptor):
    """Closed v3 delivery projection, not signature or purpose admission."""
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {"schema", "executionCallerPrivateKeyFd",
            "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"}
            or value["schema"] != CONTROL_PLANE_EXECUTION_SCHEMA
            or type(value["executionCallerPrivateKeyFd"]) is not int
            or value["executionCallerPrivateKeyFd"] != CONTROL_PLANE_EXECUTION_KEY_FD
            or issuer_descriptor is None
            or CONTROL_PLANE_EXECUTION_KEY_FD in (issuer_descriptor, bootstrap_descriptor)):
        raise RuntimeError("registration execution caller key delivery scope is invalid")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name, maximum in (("currentRootEnrollment", 128 * 1024),
            ("grantEnrollment", 16 * 1024), ("authorizationEnrollment", 16 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("registration execution enrollment record is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("registration execution enrollment original exceeds its delivery bound")
    endpoint = value["authorizerEndpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"socketPath", "requestTimeoutSeconds",
            "listenerUid", "listenerGid"}
            or endpoint["socketPath"] != CONTROL_PLANE_EXECUTION_SOCKET
            or type(endpoint["requestTimeoutSeconds"]) is not int
            or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0
                for name in ("listenerUid", "listenerGid"))):
        raise RuntimeError("registration execution endpoint differs from its fixed delivery contract")
    return CONTROL_PLANE_EXECUTION_KEY_FD


def _control_plane_enrollment_key_slots(descriptor: int) -> tuple[int | None, int | None]:
    """Project exact v2/v3 slots; only the child admits root authority and keys."""
    if type(descriptor) is not int or not 3 <= descriptor <= 1023:
        raise RuntimeError("control-plane enrollment bootstrap descriptor is outside its range")
    metadata = os.fstat(descriptor)
    seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= metadata.st_size <= CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("control-plane enrollment bootstrap is not bounded root-owned sealed material")
    original = _read_exact_source(descriptor, metadata.st_size)
    if _material_identity(os.fstat(descriptor)) != _material_identity(metadata):
        raise RuntimeError("control-plane enrollment bootstrap changed while reading")
    try:
        value = json.loads(original)
        if (type(value) is not dict or set(value) != {"schema", "payload", "signatureBase64Url"}
                or value["schema"] not in (CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA)):
            raise RuntimeError("control-plane enrollment bootstrap envelope is not closed")
        is_v3 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA
        payload_fields = {"schema", "sourceRevision", "configurationDigest", "configurationPayload",
            "generation", "runtimeRoleIdentities", "issuerPrivateKeyFd", "signerEndpoint"}
        if is_v3:
            payload_fields.add("registrationExecution")
        payload = value["payload"]
        if (type(payload) is not dict or set(payload) != payload_fields
                or payload["schema"] != (CONTROL_PLANE_ENROLLMENT_V3_PAYLOAD_SCHEMA if is_v3
                    else CONTROL_PLANE_ENROLLMENT_PAYLOAD_SCHEMA)):
            raise RuntimeError("control-plane enrollment bootstrap payload is not closed")
        signature = value["signatureBase64Url"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        if (type(signature) is not str or len(signature) != 86
                or any(character not in alphabet for character in signature)):
            raise RuntimeError("control-plane enrollment bootstrap signature encoding is invalid")
        revision = payload["sourceRevision"]
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
        if (type(revision) is not str or not 1 <= len(revision) <= 256
                or not revision[0].isascii() or not revision[0].isalnum()
                or any(character not in allowed for character in revision)):
            raise RuntimeError("control-plane enrollment source revision is not a bounded ASCII token")
        digest = payload["configurationDigest"]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("control-plane enrollment configuration identity is not canonical")
        if any(type(payload[name]) is not dict
                for name in ("configurationPayload", "generation", "runtimeRoleIdentities")):
            raise RuntimeError("control-plane enrollment bootstrap graphs are not objects")
        target = payload["issuerPrivateKeyFd"]
        if target is not None and (type(target) is not int or not 32 <= target <= 1023):
            raise RuntimeError("control-plane enrollment key descriptor is outside its exact range")
        execution_target = (_control_plane_execution_key_slot(payload["registrationExecution"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor) if is_v3 else None)
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True).encode("ascii")
        if canonical != original:
            raise RuntimeError("control-plane enrollment bootstrap is not original canonical JSON")
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise RuntimeError("control-plane enrollment bootstrap is invalid") from exc
    return target, execution_target


def _control_plane_enrollment_key_slot(descriptor: int) -> int | None:
    """Retain the existing evidence-issuer slot projection API."""
    return _control_plane_enrollment_key_slots(descriptor)[0]


def _open_control_plane_enrollment_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver original key bytes at one declared free slot, never authorize it.

    The full original signed runtime inventory must already include bootstrap
    and key. Root signature, policy/null correspondence and actual key admission
    belong to the child; no inventory or key environment is synthesized here.
    """
    target = _control_plane_enrollment_key_slot(bootstrap_descriptor)
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_ENROLLMENT_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_registration_execution_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver only the opt-in dedicated caller key; never infer its inventory."""
    target = _control_plane_enrollment_key_slots(bootstrap_descriptor)[1]
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_EXECUTION_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_purpose_key(bootstrap_descriptor: int, *, target,
        source_name: str, occupied_descriptors: set[int]) -> int | None:
    if source_name not in (CONTROL_PLANE_ENROLLMENT_KEY_NAME, CONTROL_PLANE_EXECUTION_KEY_NAME):
        raise RuntimeError("control-plane private-key source is not a fixed purpose")
    if target is None:
        return None
    if (type(target) is not int or not 32 <= target <= 1023 or target == bootstrap_descriptor
            or source_name == CONTROL_PLANE_EXECUTION_KEY_NAME and target != CONTROL_PLANE_EXECUTION_KEY_FD):
        raise RuntimeError("control-plane private-key target differs from its fixed purpose")
    if target in occupied_descriptors:
        raise RuntimeError("control-plane enrollment key descriptor is already assigned")
    owned: list[int] = []
    try:
        # This non-overwriting reservation also detects undeclared open FDs.
        reserved = fcntl.fcntl(bootstrap_descriptor, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(reserved)
        if reserved != target:
            raise RuntimeError("control-plane enrollment key descriptor is occupied")
        reservation_identity = _material_identity(os.fstat(reserved))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent = os.open("/", flags)
        owned.append(parent)
        for component in (None, "run", "secrets"):
            if component is not None:
                parent = os.open(component, flags, dir_fd=parent)
                owned.append(parent)
            metadata = os.fstat(parent)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("control-plane enrollment key ancestor is not root-owned nonwritable material")
        key = _open_source(source_name, expected_owner_uid=0,
            maximum_bytes=CONTROL_PLANE_ENROLLMENT_KEY_MAX_BYTES,
            required_mode=0o400, directory_fd=parent)
        owned.append(key)
        if _material_identity(os.fstat(reserved)) != reservation_identity:
            # Do not close a slot which no longer belongs to our reservation.
            owned.remove(reserved)
            raise RuntimeError("control-plane enrollment key reservation changed")
        owned.remove(reserved)
        os.close(reserved)
        retained = fcntl.fcntl(key, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(retained)
        if retained != target:
            raise RuntimeError("control-plane enrollment reserved key slot changed")
        os.set_inheritable(retained, True)
        for descriptor in tuple(reversed(owned)):
            if descriptor != retained:
                owned.remove(descriptor)
                os.close(descriptor)
        owned.clear()
        return retained
    except BaseException:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _control_plane_custody_configuration(descriptor: int) -> dict:
    """Read only the closed root-delivered startup document, without app imports."""
    metadata = os.fstat(descriptor)
    seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= metadata.st_size <= CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("control-plane custody startup configuration is not root-owned sealed material")
    original = _read_exact_source(descriptor, metadata.st_size)
    try:
        value = json.loads(original)
        fields = {"schema", "sourceRevision", "configurationDigest", "directoryFd",
            "device", "inode", "uid", "gid", "quotaBytes", "maximumRecords"}
        if type(value) is not dict or set(value) != fields:
            raise RuntimeError("control-plane custody startup configuration is not closed")
        if value["schema"] != CONTROL_PLANE_CUSTODY_CONFIG_SCHEMA:
            raise RuntimeError("control-plane custody startup schema is not supported")
        revision = value["sourceRevision"]
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
        if (type(revision) is not str or not 1 <= len(revision) <= 256
                or not revision[0].isascii() or not revision[0].isalnum()
                or any(character not in allowed for character in revision)):
            raise RuntimeError("control-plane custody source revision is not a bounded ASCII token")
        digest = value["configurationDigest"]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("control-plane custody configuration identity is not canonical")
        uid, gid = ROLE_IDENTITIES["control-plane"]
        for name, minimum, maximum in (
            ("directoryFd", CONTROL_PLANE_CUSTODY_FD_MIN, CONTROL_PLANE_CUSTODY_FD_MAX),
            ("device", 0, 2**64 - 1), ("inode", 1, 2**64 - 1),
            ("uid", uid, uid), ("gid", gid, gid),
            ("quotaBytes", 1, 8 * 1024**3), ("maximumRecords", 1, 4096),
        ):
            if type(value[name]) is not int or not minimum <= value[name] <= maximum:
                raise RuntimeError("control-plane custody " + name + " is not an exact bounded scalar")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True).encode("ascii")
        if canonical != original:
            raise RuntimeError("control-plane custody startup configuration is not original canonical JSON")
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise RuntimeError("control-plane custody startup configuration is invalid") from exc
    return value


def _open_control_plane_custody(
    configuration_descriptor: int,
    *,
    occupied_descriptors: set[int],
) -> tuple[int, int]:
    """Retain the exact preprovisioned directory and sealed startup config.

    This is descriptor delivery only. The cold caller still admits the full
    runtime-root-signed inherited inventory, current configuration identity
    and original source before acquiring the journal's real owner/lease.
    """
    configuration = _control_plane_custody_configuration(configuration_descriptor)
    target = configuration["directoryFd"]
    if target in occupied_descriptors:
        raise RuntimeError("control-plane custody directory descriptor is already assigned")
    owned: list[int] = []
    try:
        # F_DUPFD_CLOEXEC never overwrites an existing slot. A result above the
        # requested number proves collision, even with an undeclared open FD.
        reserved = fcntl.fcntl(configuration_descriptor, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(reserved)
        if reserved != target:
            raise RuntimeError("control-plane custody directory descriptor is occupied")
        retained_configuration = fcntl.fcntl(configuration_descriptor,
            fcntl.F_DUPFD_CLOEXEC, CONTROL_PLANE_CUSTODY_FD_MIN)
        owned.append(retained_configuration)
        if retained_configuration > CONTROL_PLANE_CUSTODY_FD_MAX:
            raise RuntimeError("control-plane custody configuration descriptor exceeds its range")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent = os.open("/", flags)
        owned.append(parent)
        # Each component is opened relative to its already checked parent.
        # No symlink traversal or caller-selected path is allowed.
        for component in (None, "var", "lib", "serverware"):
            if component is not None:
                parent = os.open(component, flags, dir_fd=parent)
                owned.append(parent)
            metadata = os.fstat(parent)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("control-plane custody directory ancestor is not root-owned nonwritable material")
        directory = os.open(os.path.basename(CONTROL_PLANE_CUSTODY_DIRECTORY),
            flags, dir_fd=parent)
        owned.append(directory)
        metadata = os.fstat(directory)
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                != (configuration["device"], configuration["inode"],
                    configuration["uid"], configuration["gid"])):
            raise RuntimeError("control-plane custody directory differs from its provisioned identity")
        # Release only our reservation, then duplicate without overwriting.
        # If another descriptor appeared in that slot, fail and close only
        # the new duplicate; never clobber the conflicting descriptor.
        owned.remove(reserved)
        os.close(reserved)
        retained_directory = fcntl.fcntl(directory, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(retained_directory)
        if retained_directory != target:
            raise RuntimeError("control-plane custody reserved directory slot changed")
        os.set_inheritable(retained_configuration, True)
        os.set_inheritable(retained_directory, True)
        result = retained_configuration, retained_directory
        for descriptor in tuple(reversed(owned)):
            if descriptor not in result:
                owned.remove(descriptor)
                os.close(descriptor)
        owned.clear()
        return result
    except BaseException:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _open_systemd_credential(name: str) -> int:
    directory_path = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if (
        not directory_path
        or not os.path.isabs(directory_path)
        or not name
        or name != os.path.basename(name)
        or "/" in name
    ):
        raise RuntimeError(
            "trusted-host-local requires an exact systemd credential key"
        )
    directory = os.open(
        directory_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    descriptor = -1
    try:
        directory_metadata = os.fstat(directory)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != 0
            or directory_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "systemd credential directory is not trusted"
            )
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        metadata_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_uid != 0
            or metadata_before.st_nlink != 1
            or metadata_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "systemd credential source is not an exact root-owned file"
            )
        value = _read_exact_source(
            descriptor,
            metadata_before.st_size,
        )
        metadata_after = os.fstat(descriptor)
        if (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        ):
            raise RuntimeError(
                "systemd credential changed while it was sealed"
            )
        sealed_descriptor = _seal_bytes(
            descriptor,
            name=f"serverware-{name}",
            value=value,
            mode=stat.S_IMODE(metadata_before.st_mode),
        )
        descriptor = -1
        return sealed_descriptor
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _open_trusted_host_local_witness_state(
    launch_manifest_descriptor: int,
    *,
    occupied_descriptors: set[int],
) -> int:
    metadata = os.fstat(launch_manifest_descriptor)
    try:
        manifest_value = _read_exact_source(
            launch_manifest_descriptor,
            metadata.st_size,
        )
        manifest = json.loads(manifest_value)
        canonical_manifest = json.dumps(
            manifest,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise RuntimeError(
            "witness launch manifest is not readable canonical JSON"
        ) from exc
    payload = manifest.get("payload") if isinstance(manifest, dict) else None
    request = (
        payload.get("stageZeroRequest")
        if isinstance(payload, dict)
        else None
    )
    mutable_state = (
        request.get("mutableStateDescriptors")
        if isinstance(request, dict)
        else None
    )
    state = (
        mutable_state[0]
        if isinstance(mutable_state, list) and len(mutable_state) == 1
        else None
    )
    target_descriptor = (
        state.get("fd") if isinstance(state, dict) else None
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "payload", "signature"}
        or canonical_manifest != manifest_value
        or manifest.get("schema")
            != "serverware.signedPolicyAuthorityLaunchManifest/v7"
        or not isinstance(payload, dict)
        or payload.get("role") != "witness"
        or payload.get("processMode") != "policy-authority-replay-witness"
        or not isinstance(request, dict)
        or request.get("trustMode") != "trusted-host-local"
        or not isinstance(state, dict)
        or set(state)
            != {
                "name",
                "ownerRole",
                "fd",
                "runtimePath",
                "device",
                "inode",
                "generation",
                "mountId",
                "uid",
                "gid",
                "mode",
                "singletonLeaseRequired",
                "leaseIdentityDigest",
                "leaseHeld",
                "atomicRecordProtocol",
                "quotaBytes",
                "networkAllowed",
                "surviveExec",
            }
        or state.get("name") != "witness"
        or state.get("ownerRole") != "witness"
        or state.get("runtimePath")
            != TRUSTED_HOST_LOCAL_WITNESS_STATE_PATH
        or state.get("singletonLeaseRequired") is not True
        or state.get("leaseHeld") is not True
        or state.get("networkAllowed") is not False
        or state.get("surviveExec") is not True
        or not isinstance(target_descriptor, int)
        or isinstance(target_descriptor, bool)
        or not (
            TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MIN
            <= target_descriptor
            <= TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MAX
        )
        or target_descriptor in occupied_descriptors
    ):
        raise RuntimeError(
            "trusted-host-local witness state descriptor is not exact"
        )
    try:
        os.fstat(target_descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise RuntimeError(
                "trusted-host-local witness target descriptor is invalid"
            ) from exc
    else:
        raise RuntimeError(
            "trusted-host-local witness target descriptor is occupied"
        )
    os.dup2(
        launch_manifest_descriptor,
        target_descriptor,
        inheritable=False,
    )
    target_reserved = True
    parent = -1
    descriptor = -1
    try:
        parent = os.open(
            "/var/lib/serverware",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent_metadata = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != 0
            or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "trusted-host-local witness state parent is not trusted"
            )
        descriptor = os.open(
            "authority-witness",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        state_metadata = os.fstat(descriptor)
        mount_id: int | None = None
        with open(
            f"/proc/self/fdinfo/{descriptor}",
            "r",
            encoding="ascii",
        ) as handle:
            for line in handle:
                name, separator, value = line.partition(":")
                if separator and name == "mnt_id":
                    try:
                        mount_id = int(value.strip(), 10)
                    except ValueError as exc:
                        raise RuntimeError(
                            "trusted-host-local witness mount ID is invalid"
                        ) from exc
        witness_uid, witness_gid = ROLE_IDENTITIES["witness"]
        if (
            not stat.S_ISDIR(state_metadata.st_mode)
            or state_metadata.st_uid != witness_uid
            or state_metadata.st_gid != witness_gid
            or stat.S_IMODE(state_metadata.st_mode) != 0o700
            or state_metadata.st_dev != state.get("device")
            or state_metadata.st_ino != state.get("inode")
            or state_metadata.st_uid != state.get("uid")
            or state_metadata.st_gid != state.get("gid")
            or stat.S_IMODE(state_metadata.st_mode) != state.get("mode")
            or mount_id != state.get("mountId")
        ):
            raise RuntimeError(
                "trusted-host-local witness state identity changed"
            )
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            raise RuntimeError(
                "trusted-host-local witness state lease is unavailable"
            ) from exc
        if descriptor == target_descriptor:
            raise RuntimeError(
                "trusted-host-local witness state descriptor overlaps"
            )
        os.dup2(descriptor, target_descriptor, inheritable=True)
        source_descriptor = descriptor
        descriptor = -1
        os.close(source_descriptor)
        descriptor = target_descriptor
        parent_descriptor = parent
        parent = -1
        os.close(parent_descriptor)
        target_reserved = False
        return descriptor
    except Exception:
        if descriptor >= 0 and descriptor != target_descriptor:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if target_reserved:
            try:
                os.close(target_descriptor)
            except OSError:
                pass
        raise
    finally:
        if parent >= 0:
            try:
                os.close(parent)
            except OSError:
                pass


def _drop_identity(role: str) -> None:
    uid, gid = ROLE_IDENTITIES[role]
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError("authority bootstrap must begin as root")
    os.setgroups(list(ROLE_SUPPLEMENTARY_GIDS[role]))
    os.setgid(gid)
    os.setuid(uid)
    if (
        os.geteuid() != uid
        or os.getegid() != gid
        or tuple(sorted(os.getgroups()))
        != tuple(sorted(ROLE_SUPPLEMENTARY_GIDS[role]))
    ):
        raise RuntimeError("authority bootstrap identity drop was not exact")
    _require_unprivileged_process()


def _require_unprivileged_process() -> None:
    values: dict[str, str] = {}
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            name, separator, value = line.partition(":")
            if separator and name in {
                "CapEff",
                "CapInh",
                "CapPrm",
                "CapAmb",
                "NoNewPrivs",
            }:
                values[name] = value.strip()
    if (
        set(values)
        != {"CapEff", "CapInh", "CapPrm", "CapAmb", "NoNewPrivs"}
        or any(
            int(values[name], 16) != 0
            for name in {"CapEff", "CapInh", "CapPrm", "CapAmb"}
        )
        or values["NoNewPrivs"] != "1"
    ):
        raise RuntimeError(
            "authority runtime retained privilege after identity drop"
        )


def _socket_directory_descriptor(role: str) -> tuple[int, str]:
    path = ROLE_SOCKET_PATHS[role]
    parent, name = os.path.split(path)
    descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    uid, gid = ROLE_IDENTITIES[role]
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_mode & stat.S_IWOTH
    ):
        os.close(descriptor)
        raise RuntimeError("authority socket directory is not trusted")
    return descriptor, name


def _consume_socket_activation(role: str) -> int:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES")
        != ROLE_LISTENER_NAMES[role]
    ):
        raise RuntimeError(
            "authority requires exactly one named service-manager listener"
        )
    descriptor = 3
    metadata = os.fstat(descriptor)
    activated = socket.fromfd(
        descriptor,
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    try:
        socket_path = activated.getsockname()
        if isinstance(socket_path, bytes):
            socket_path = os.fsdecode(socket_path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or activated.family != socket.AF_UNIX
            or activated.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or activated.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ACCEPTCONN,
            )
            != 1
            or socket_path != ROLE_SOCKET_PATHS[role]
        ):
            raise RuntimeError(
                "authority service-manager listener binding changed"
            )
    finally:
        activated.close()
    path_metadata = os.stat(
        ROLE_SOCKET_PATHS[role],
        follow_symlinks=False,
    )
    uid, gid = ROLE_IDENTITIES[role]
    if (
        not stat.S_ISSOCK(path_metadata.st_mode)
        or path_metadata.st_uid != uid
        or path_metadata.st_gid != gid
        or stat.S_IMODE(path_metadata.st_mode) != 0o660
    ):
        raise RuntimeError(
            "authority service-manager socket path is not exact"
        )
    os.set_inheritable(descriptor, True)
    return descriptor


def _socket_health(role: str) -> int:
    directory, name = _socket_directory_descriptor(role)
    try:
        metadata = os.stat(
            name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        uid, gid = ROLE_IDENTITIES[role]
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise RuntimeError("authority health socket identity changed")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            probe.connect(f"/proc/self/fd/{directory}/{name}")
        finally:
            probe.close()
    finally:
        os.close(directory)
    return 0


def _control_plane_health() -> int:
    _drop_identity("control-plane")
    os.execve(
        "/usr/bin/python3",
        [
            "/usr/bin/python3",
            "-P",
            "-s",
            "-c",
            CONTROL_PLANE_HEALTH_CODE,
        ],
        dict(os.environ),
    )
    return 1


def _normal_main(role: str) -> int:
    trusted_host_local = (
        os.environ.get("SERVERWARE_AUTHORITY_TRUST_MODE")
        == "trusted-host-local"
    )
    if role != "control-plane" and not trusted_host_local:
        raise RuntimeError(
            "native-stage-zero-required: authority roles must be entered "
            "by the unavailable native stage-zero entrypoint, or explicitly "
            "use trusted-host-local with systemd credential keys"
        )
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError("authority descriptor bootstrap must start as root")
    environment = dict(os.environ)
    if any(
        environment.get(name)
        for name in OBSOLETE_STATIC_RELEASE_CONSUMER_NAMES
    ):
        raise RuntimeError(
            "static release-consumer credentials are forbidden in .19"
        )
    inherited_descriptors: list[int] = []
    if role != "control-plane":
        listener_descriptor = _consume_socket_activation(role)
        inherited_descriptors.append(listener_descriptor)
        launch_private_descriptor = _open_systemd_credential(
            "serverware-authority-launch-private-key"
        )
        launch_certificate_descriptor = _open_systemd_credential(
            "serverware-authority-launch-certificate"
        )
        inherited_descriptors.extend(
            (
                launch_private_descriptor,
                launch_certificate_descriptor,
            )
        )
        environment[
            "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD"
        ] = str(launch_private_descriptor)
        environment[
            "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD"
        ] = str(launch_certificate_descriptor)
        if len(set(inherited_descriptors)) != len(inherited_descriptors):
            raise RuntimeError(
                "authority inherited descriptor identities overlap"
            )
        environment.pop(STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME, None)
        environment.pop(
            STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME.removesuffix("_FD")
            + "_PATH",
            None,
        )
        environment.pop(
            "SERVERWARE_POLICY_AUTHORITY_LISTENER_FD",
            None,
        )
    for role_sources in ROLE_SOURCES.values():
        for descriptor_name, _path in role_sources:
            environment.pop(descriptor_name, None)
            environment.pop(
                descriptor_name.removesuffix("_FD") + "_PATH",
                None,
            )
    for name in tuple(environment):
        if name.startswith(("SERVERWARE_CONTROL_PLANE_CUSTODY_",
                "SERVERWARE_CONTROL_PLANE_ENROLLMENT_")):
            environment.pop(name, None)
    environment.pop("SERVERWARE_AUTHORITY_BOOTSTRAP_FD", None)
    environment.pop("SERVERWARE_PROCESS_MODE", None)
    environment.pop("LISTEN_PID", None)
    environment.pop("LISTEN_FDS", None)
    environment.pop("LISTEN_FDNAMES", None)
    environment.pop("CREDENTIALS_DIRECTORY", None)
    environment.pop("SERVERWARE_AUTHORITY_TRUST_MODE", None)
    descriptors: list[int] = list(inherited_descriptors)
    descriptor_assignments: list[tuple[str, int]] = []
    launch_manifest_descriptor: int | None = None
    custody_configuration_descriptor: int | None = None
    enrollment_bootstrap_descriptor: int | None = None
    control_plane_source_limits = {
        CONTROL_PLANE_CUSTODY_CONFIG_NAME: CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES,
        CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME: CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES,
    }
    try:
        for environment_name, path in ROLE_SOURCES[role]:
            descriptor = (
                _open_source(path, expected_owner_uid=0,
                    maximum_bytes=control_plane_source_limits.get(environment_name, MAX_SOURCE_BYTES))
                if role == "control-plane"
                else _open_systemd_credential(
                    os.path.basename(path)
                )
            )
            descriptors.append(descriptor)
            if role == "control-plane":
                environment[environment_name] = str(descriptor)
                if environment_name == CONTROL_PLANE_CUSTODY_CONFIG_NAME:
                    custody_configuration_descriptor = descriptor
                elif environment_name == CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME:
                    enrollment_bootstrap_descriptor = descriptor
            else:
                descriptor_assignments.append(
                    (environment_name, descriptor)
                )
                if environment_name == (
                    "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
                ):
                    launch_manifest_descriptor = descriptor
        if role == "witness":
            if launch_manifest_descriptor is None:
                raise RuntimeError(
                    "trusted-host-local witness launch manifest is unavailable"
                )
            descriptors.append(
                _open_trusted_host_local_witness_state(
                    launch_manifest_descriptor,
                    occupied_descriptors=set(descriptors),
                )
            )
        if role == "control-plane":
            if custody_configuration_descriptor is None:
                raise RuntimeError("control-plane custody startup configuration is unavailable")
            custody_configuration, custody_directory = _open_control_plane_custody(
                custody_configuration_descriptor, occupied_descriptors=set(descriptors))
            descriptors.extend((custody_configuration, custody_directory))
            environment[CONTROL_PLANE_CUSTODY_CONFIG_NAME] = str(custody_configuration)
            descriptors.remove(custody_configuration_descriptor)
            os.close(custody_configuration_descriptor)
            if enrollment_bootstrap_descriptor is None:
                raise RuntimeError("control-plane enrollment bootstrap is unavailable")
            enrollment_key = _open_control_plane_enrollment_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if enrollment_key is not None:
                descriptors.append(enrollment_key)
            execution_key = _open_control_plane_registration_execution_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if execution_key is not None:
                descriptors.append(execution_key)
            environment["SERVERWARE_PROCESS_MODE"] = PROCESS_MODES[role]
            _drop_identity(role)
            os.execve(
                "/runtime/python/bin/python3",
                [
                    "/runtime/python/bin/python3",
                    "-P",
                    "-s",
                    "-m",
                    "serverware.control_plane_runner",
                ],
                environment,
            )
        launcher_descriptor = _open_source(
            BOOTSTRAP_LAUNCHER_PATH,
            expected_owner_uid=0,
        )
        descriptors.append(launcher_descriptor)
        launcher_arguments = [
            "/runtime/python/bin/python3",
            "-I",
            "-P",
            "-s",
            "-S",
            "-E",
            f"/proc/self/fd/{launcher_descriptor}",
            "--bootstrap-fd",
            str(launcher_descriptor),
            "--trusted-host-local",
        ]
        for environment_name, descriptor in descriptor_assignments:
            launcher_arguments.extend(
                [
                    "--descriptor",
                    f"{environment_name}={descriptor}",
                ]
            )
        launcher_arguments.append(role)
        os.execve(
            "/runtime/python/bin/python3",
            launcher_arguments,
            environment,
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return 1


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "witness-init":
        raise RuntimeError(
            "legacy witness ledger initialization is forbidden; "
            "native stage zero must retain the signed mutable-state directory"
        )
    if len(sys.argv) == 2 and sys.argv[1] == "control-plane-health":
        return _control_plane_health()
    if (
        len(sys.argv) >= 3
        and sys.argv[1] == "socket-health"
        and all(role in ROLE_SOCKET_PATHS for role in sys.argv[2:])
    ):
        if os.geteuid() == 0:
            _drop_identity(sys.argv[2])
        for role in sys.argv[2:]:
            _socket_health(role)
        return 0
    if len(sys.argv) != 2 or sys.argv[1] not in ROLE_SOURCES:
        raise RuntimeError("authority descriptor role is invalid")
    return _normal_main(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
