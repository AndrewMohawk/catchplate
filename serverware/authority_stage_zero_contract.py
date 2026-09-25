from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from . import authority_contract
from .authority_artifact_spec import (
    ALLOWED_MUTABLE_STATE_PROTOCOLS,
    ArtifactContractError,
    VerifiedArtifactPackage,
    canonical_json_bytes,
    domain_digest,
    ed25519_public_key_from_seed,
    strict_base64url_decode,
    verify_ed25519_signature,
)


STAGE_ZERO_REQUEST_SCHEMA = "serverware.authorityNativeStageZeroRequest/v3"
LAUNCH_IDENTITY_PAYLOAD_SCHEMA = (
    "serverware.authorityLaunchIdentityCertificatePayload/v3"
)
SIGNED_LAUNCH_IDENTITY_SCHEMA = (
    "serverware.signedAuthorityLaunchIdentityCertificate/v3"
)
STAGE_ZERO_HANDOFF_SCHEMA = "serverware.authorityNativeStageZeroHandoff/v3"
STAGE_ZERO_INTERFACE_SCHEMA = "serverware.authorityNativeStageZeroInterface/v3"
STAGE_ZERO_REQUEST_DIGEST_DOMAIN = (
    "serverware.authorityNativeStageZeroRequestDigest/v3"
)
LAUNCH_ID_DOMAIN = "serverware.authorityLaunchIdentity/v3"
LAUNCH_CERTIFICATE_SIGNATURE_DOMAIN = (
    "serverware.authorityLaunchIdentityCertificateSignature/v3"
)
BOOTSTRAP_CONTROL_NAME = "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
BOOTSTRAP_CONTROL_ENVELOPE_SCHEMA = "serverware.signedPolicyAuthorityLaunchManifest/v5"
MAX_BOOTSTRAP_CONTROL_BYTES = 64 * 1024 * 1024
LISTENER_IDENTITY_DOMAIN = "serverware.authorityListenerIdentity/v1"
CREDENTIAL_SET_DOMAIN = "serverware.authorityCredentialSet/v1"
ENVIRONMENT_DOMAIN = "serverware.authorityLaunchEnvironment/v1"
ARGUMENT_VECTOR_DOMAIN = "serverware.authorityLaunchArgumentVector/v1"
WORKING_DIRECTORY_DOMAIN = "serverware.authorityLaunchWorkingDirectory/v1"
IDENTITY_FD_DOMAIN = "serverware.authorityLaunchIdentityFdSet/v1"
MUTABLE_STATE_SET_DOMAIN = "serverware.authorityMutableStateSet/v1"
PIDFD_IDENTITY_DOMAIN = "serverware.authorityPidfdIdentity/v1"
MAX_RETAINED_DIRECTORIES = 64
MAX_RETAINED_FILES = 32768
MAX_CREDENTIALS = 256
MAX_MUTABLE_STATE_DESCRIPTORS = 16
MAX_ENVIRONMENT_ENTRIES = 256
MAX_ARGUMENTS = 256
MAX_ARGUMENT_BYTES = 65536
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
REQUIRED_MEMFD_SEALS = (
    0x0001  # F_SEAL_SEAL
    | 0x0002  # F_SEAL_SHRINK
    | 0x0004  # F_SEAL_GROW
    | 0x0008  # F_SEAL_WRITE
)
ALLOWED_DIRECTORY_PURPOSES = frozenset(
    {
        "artifact-generation-root",
        "configuration-root",
        "migration-receipt-root",
        "runtime-root",
        "state-root",
    }
)
ALLOWED_FILE_PURPOSES = frozenset(
    {
        "artifact-bundle",
        "authority-role-entrypoint",
        "configuration",
        "generation-statement",
        "native-loader",
        "native-shared-object",
        "native-stage-zero",
        "operation-manifest",
        "python-import",
        "role-manifest",
        "schema",
    }
)
ALLOWED_CREDENTIAL_PURPOSES = frozenset(
    {
        "attestation-evidence",
        "configuration-signing-root",
        "database-credential",
        "external-witness-credential",
        "generation-trust-root",
        "role-signing-key",
        "service-client-credential",
    }
)
ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "SERVERWARE_ARTIFACT_BUNDLE_DIGEST",
        "SERVERWARE_AUTHORITY_GENERATION_DIGEST",
        "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD",
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD",
        "SERVERWARE_AUTHORITY_ROLE",
        "SERVERWARE_OPERATION_MANIFEST_DIGEST",
        BOOTSTRAP_CONTROL_NAME,
        "TZ",
    }
)
DENIED_ENVIRONMENT_KEYS = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
    }
)
REQUIRED_PYTHON_ISOLATION_FLAGS = (
    "-I",
    "-P",
    "-s",
    "-S",
    "-E",
)
REQUIRED_EXECVEAT_FLAGS = ("AT_EMPTY_PATH",)
TRUST_MODES = frozenset(
    {"trusted-host-local", "external-production", "tee-hardware"}
)

NATIVE_STAGE_ZERO_REQUIREMENTS = (
    "The stage-zero binary is a generation-pinned static ELF with no "
    "PT_INTERP or DT_NEEDED entries.",
    "The native binary verifies artifact and generation signatures before "
    "starting Python or any authority role code.",
    "All directories and files are opened without symlink traversal and "
    "retained by descriptor through verification and execveat.",
    "Every content-committed retained descriptor is revalidated by device, inode, generation, "
    "ownership, mode, size, and digest immediately before handoff.",
    "The inherited listener is supplied by the service manager and validated "
    "for LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES, AF_UNIX, SOCK_STREAM, "
    "SO_ACCEPTCONN, path, ownership, mode, and stable identity.",
    "Credential descriptors are allowlisted, sealed where representable, "
    "never pathname reopened, and delivered only to the assigned role.",
    "The launch manifest is a separate mandatory bootstrap control slot, not "
    "a content-committed credential. Its original bounded bytes, seals, and "
    "root signature must be admitted by the launcher; this request alone "
    "does not authenticate that control document.",
    "The witness mutable-state directory is retained by FD, mount-bound, "
    "lease-exclusive, quota-enforced, local-only, and limited to the signed "
    "atomic append-record protocol; no other role receives mutable state.",
    "The native launcher validates pidfd identity against the expected PID, "
    "boot ID, and /proc start ticks before certification and immediately "
    "before execveat.",
    "Any [vsyscall] mapping is a hard failure; [vdso] remains measured and "
    "bound to kernel and boot identity.",
    "Stage zero creates a fresh Ed25519 key per launch, seals its private key "
    "into a retained memfd, and obtains a generation-authorized certificate.",
    "Only explicitly allowlisted environment variables survive, and loader "
    "or Python path-injection variables are always absent.",
    "The verified entrypoint is executed through execveat with AT_EMPTY_PATH "
    "after privilege, namespace, no-new-privileges, descriptor, and "
    "environment policy are established.",
    "TEE, HSM, IMA/EVM, and external-witness claims are accepted only when "
    "their independently verified evidence is bound into the generation.",
)


class StageZeroContractError(ArtifactContractError):
    pass


def _mapping(
    value: object,
    *,
    name: str,
    keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise StageZeroContractError(f"{name} is not a closed object")
    return value


def _list(
    value: object,
    *,
    name: str,
    maximum: int,
    minimum: int = 0,
) -> Sequence[Any]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
    ):
        raise StageZeroContractError(f"{name} has an invalid item count")
    return value


def _ascii(
    value: object,
    *,
    name: str,
    maximum: int = 4096,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or len(value) > maximum
        or (not allow_empty and not value)
    ):
        raise StageZeroContractError(f"{name} must be bounded ASCII")
    return value


def _identifier(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=256)
    if (
        text[0]
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        or any(
            character
            not in (
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789._-:/"
            )
            for character in text
        )
    ):
        raise StageZeroContractError(f"{name} is not a canonical identifier")
    return text


def _integer(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise StageZeroContractError(f"{name} is outside its integer bound")
    return value


def _digest(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=71)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise StageZeroContractError(f"{name} is not a SHA-256 digest")
    return text


def _runtime_path(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise StageZeroContractError(
            f"{name} is not a canonical absolute path"
        )
    return text


def _timestamp(value: object, *, name: str) -> datetime:
    text = _ascii(value, name=name, maximum=64)
    if not text.endswith("Z"):
        raise StageZeroContractError(f"{name} must use canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise StageZeroContractError(f"{name} is not RFC3339") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.microsecond != 0
        or text != parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    ):
        raise StageZeroContractError(f"{name} is not canonical RFC3339")
    return parsed


def _base64url(
    value: object,
    *,
    name: str,
    decoded_size: int,
) -> bytes:
    try:
        return strict_base64url_decode(
            value,
            name=name,
            decoded_size=decoded_size,
        )
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc


def _sorted_unique(values: Sequence[Any], *, name: str, key) -> None:
    observed = [key(value) for value in values]
    if observed != sorted(observed) or len(observed) != len(set(observed)):
        raise StageZeroContractError(f"{name} is not sorted and unique")


def _validate_stat_identity(
    value: Mapping[str, Any],
    *,
    name: str,
    require_regular: bool,
) -> None:
    _integer(value["fd"], name=f"{name} fd", minimum=3, maximum=2**31 - 1)
    _integer(
        value["device"], name=f"{name} device", minimum=0, maximum=2**64 - 1
    )
    _integer(
        value["inode"], name=f"{name} inode", minimum=1, maximum=2**64 - 1
    )
    _integer(
        value["generation"],
        name=f"{name} generation",
        minimum=1,
        maximum=2**64 - 1,
    )
    mode = _integer(
        value["mode"], name=f"{name} mode", minimum=0, maximum=0o7777
    )
    if mode & 0o7000 or mode & 0o022:
        raise StageZeroContractError(
            f"{name} is special-mode or group/world-writable"
        )
    _integer(
        value["uid"], name=f"{name} uid", minimum=0, maximum=2**32 - 2
    )
    _integer(
        value["gid"], name=f"{name} gid", minimum=0, maximum=2**32 - 2
    )
    if require_regular:
        _integer(
            value["size"],
            name=f"{name} size",
            minimum=0,
            maximum=MAX_FILE_BYTES,
        )
        _digest(value["sha256"], name=f"{name} digest")


def _validate_retained_directory(value: object) -> None:
    entry = _mapping(
        value,
        name="retained directory",
        keys={
            "name",
            "fd",
            "purpose",
            "runtimePath",
            "device",
            "inode",
            "generation",
            "mode",
            "uid",
            "gid",
            "surviveExec",
        },
    )
    _identifier(entry["name"], name="retained directory name")
    if entry["purpose"] not in ALLOWED_DIRECTORY_PURPOSES:
        raise StageZeroContractError(
            "retained directory purpose is not recognized"
        )
    _runtime_path(entry["runtimePath"], name="retained directory path")
    _validate_stat_identity(entry, name="retained directory", require_regular=False)
    if not isinstance(entry["surviveExec"], bool):
        raise StageZeroContractError(
            "retained directory surviveExec is not boolean"
        )


def _validate_retained_file(value: object) -> None:
    entry = _mapping(
        value,
        name="retained file",
        keys={
            "name",
            "fd",
            "purpose",
            "runtimePath",
            "device",
            "inode",
            "generation",
            "mode",
            "uid",
            "gid",
            "size",
            "sha256",
            "fsVerityDigest",
            "surviveExec",
        },
    )
    _identifier(entry["name"], name="retained file name")
    if entry["purpose"] not in ALLOWED_FILE_PURPOSES:
        raise StageZeroContractError("retained file purpose is not recognized")
    _runtime_path(entry["runtimePath"], name="retained file path")
    _validate_stat_identity(entry, name="retained file", require_regular=True)
    if entry["fsVerityDigest"] is not None:
        _digest(entry["fsVerityDigest"], name="fs-verity digest")
    if not isinstance(entry["surviveExec"], bool):
        raise StageZeroContractError(
            "retained file surviveExec is not boolean"
        )


def _validate_listener(
    value: object,
    *,
    expected_listen_pid: int | None = None,
) -> None:
    listener = _mapping(
        value,
        name="inherited listener",
        keys={
            "name",
            "fd",
            "runtimePath",
            "activationName",
            "family",
            "socketType",
            "accepting",
            "listenPid",
            "listenFds",
            "listenFdNames",
            "device",
            "inode",
            "mode",
            "uid",
            "gid",
        },
    )
    _identifier(listener["name"], name="listener name")
    _integer(
        listener["fd"], name="listener fd", minimum=3, maximum=2**31 - 1
    )
    _runtime_path(listener["runtimePath"], name="listener path")
    _identifier(listener["activationName"], name="listener activation name")
    if listener["family"] != "AF_UNIX":
        raise StageZeroContractError("listener must be AF_UNIX")
    if listener["socketType"] != "SOCK_STREAM":
        raise StageZeroContractError("listener must be SOCK_STREAM")
    if listener["accepting"] is not True:
        raise StageZeroContractError("listener is not accepting")
    listen_pid = _integer(
        listener["listenPid"],
        name="LISTEN_PID",
        minimum=1,
        maximum=2**31 - 1,
    )
    if (
        expected_listen_pid is not None
        and listen_pid != expected_listen_pid
    ):
        raise StageZeroContractError(
            "LISTEN_PID does not name the stage-zero process"
        )
    if listener["listenFds"] != 1:
        raise StageZeroContractError("exactly one listening FD is required")
    names = _list(
        listener["listenFdNames"],
        name="LISTEN_FDNAMES",
        minimum=1,
        maximum=1,
    )
    if names != [listener["activationName"]]:
        raise StageZeroContractError("LISTEN_FDNAMES binding changed")
    _integer(
        listener["device"],
        name="listener device",
        minimum=0,
        maximum=2**64 - 1,
    )
    _integer(
        listener["inode"],
        name="listener inode",
        minimum=1,
        maximum=2**64 - 1,
    )
    mode = _integer(
        listener["mode"], name="listener mode", minimum=0, maximum=0o7777
    )
    if mode & 0o007:
        raise StageZeroContractError("listener is accessible to other users")
    _integer(
        listener["uid"], name="listener uid", minimum=0, maximum=2**32 - 2
    )
    _integer(
        listener["gid"], name="listener gid", minimum=0, maximum=2**32 - 2
    )


def _validate_credential(value: object) -> None:
    credential = _mapping(
        value,
        name="credential descriptor",
        keys={
            "name",
            "fd",
            "purpose",
            "ownerRole",
            "size",
            "sha256",
            "mode",
            "ownerUid",
            "seals",
            "delivery",
        },
    )
    _identifier(credential["name"], name="credential name")
    if credential["name"] == BOOTSTRAP_CONTROL_NAME:
        raise StageZeroContractError("launch manifest is a bootstrap control, not a credential")
    _integer(
        credential["fd"],
        name="credential fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    if credential["purpose"] not in ALLOWED_CREDENTIAL_PURPOSES:
        raise StageZeroContractError("credential purpose is not recognized")
    _identifier(credential["ownerRole"], name="credential owner role")
    _integer(
        credential["size"],
        name="credential size",
        minimum=0,
        maximum=64 * 1024 * 1024,
    )
    _digest(credential["sha256"], name="credential digest")
    mode = _integer(
        credential["mode"],
        name="credential mode",
        minimum=0,
        maximum=0o7777,
    )
    if mode & 0o077:
        raise StageZeroContractError("credential mode is not private")
    _integer(
        credential["ownerUid"],
        name="credential owner uid",
        minimum=0,
        maximum=2**32 - 2,
    )
    seals = _integer(
        credential["seals"],
        name="credential seals",
        minimum=0,
        maximum=2**31 - 1,
    )
    if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        raise StageZeroContractError("credential memfd is not fully sealed")
    if credential["delivery"] != "retained-sealed-memfd":
        raise StageZeroContractError("credential delivery mode changed")


def _validate_bootstrap_control(value: object) -> Mapping[str, Any]:
    control = _mapping(
        value,
        name="bootstrap control",
        keys={"name", "fd", "envelopeSchema", "maximumBytes"},
    )
    if (
        control["name"] != BOOTSTRAP_CONTROL_NAME
        or control["envelopeSchema"] != BOOTSTRAP_CONTROL_ENVELOPE_SCHEMA
    ):
        raise StageZeroContractError("bootstrap control name or schema changed")
    _integer(control["fd"], name="bootstrap control fd", minimum=3, maximum=2**31 - 1)
    maximum = _integer(
        control["maximumBytes"], name="bootstrap control byte limit",
        minimum=1, maximum=MAX_BOOTSTRAP_CONTROL_BYTES,
    )
    if maximum != MAX_BOOTSTRAP_CONTROL_BYTES:
        raise StageZeroContractError("bootstrap control byte limit changed")
    return control


def _validate_mutable_state_descriptor(value: object) -> None:
    state = _mapping(
        value,
        name="mutable-state descriptor",
        keys={
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
        },
    )
    _identifier(state["name"], name="mutable-state descriptor name")
    _identifier(state["ownerRole"], name="mutable-state owner role")
    _integer(
        state["fd"],
        name="mutable-state directory fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    _runtime_path(
        state["runtimePath"],
        name="mutable-state runtime path",
    )
    for field, minimum, maximum in (
        ("device", 0, 2**64 - 1),
        ("inode", 1, 2**64 - 1),
        ("generation", 1, 2**64 - 1),
        ("mountId", 1, 2**64 - 1),
        ("uid", 0, 2**32 - 2),
        ("gid", 0, 2**32 - 2),
        ("mode", 0, 0o7777),
    ):
        _integer(
            state[field],
            name=f"mutable-state {field}",
            minimum=minimum,
            maximum=maximum,
        )
    if state["mode"] & 0o7077:
        raise StageZeroContractError(
            "mutable-state directory mode is not private and nonspecial"
        )
    if state["atomicRecordProtocol"] not in (
        ALLOWED_MUTABLE_STATE_PROTOCOLS
    ):
        raise StageZeroContractError(
            "mutable-state atomic record protocol is not allowed"
        )
    _digest(
        state["leaseIdentityDigest"],
        name="mutable-state singleton lease identity",
    )
    _integer(
        state["quotaBytes"],
        name="mutable-state quota",
        minimum=1,
        maximum=64 * 1024**3,
    )
    if (
        state["singletonLeaseRequired"] is not True
        or state["leaseHeld"] is not True
        or state["networkAllowed"] is not False
        or state["surviveExec"] is not True
    ):
        raise StageZeroContractError(
            "mutable state requires lease, local-only access, and FD custody"
        )


def _validate_host_evidence(value: object, trust_mode: str) -> None:
    host = _mapping(
        value,
        name="host evidence",
        keys={
            "bootIdDigest",
            "kernelReleaseDigest",
            "kernelCommandLineDigest",
            "vdsoDigest",
            "vsyscallMode",
            "imaAppraisal",
            "teeEvidenceDigest",
            "externalWitnessCheckpointDigest",
        },
    )
    for field in (
        "bootIdDigest",
        "kernelReleaseDigest",
        "kernelCommandLineDigest",
        "vdsoDigest",
    ):
        _digest(host[field], name=field)
    if host["vsyscallMode"] != "none":
        raise StageZeroContractError("host must enforce vsyscall=none")
    if host["imaAppraisal"] not in {"not-enforced", "enforced-and-verified"}:
        raise StageZeroContractError("IMA appraisal mode is not recognized")
    for field in ("teeEvidenceDigest", "externalWitnessCheckpointDigest"):
        if host[field] is not None:
            _digest(host[field], name=field)
    if trust_mode == "trusted-host-local":
        if (
            host["teeEvidenceDigest"] is not None
            or host["externalWitnessCheckpointDigest"] is not None
        ):
            raise StageZeroContractError(
                "local trusted-host mode cannot claim external evidence"
            )
    elif trust_mode == "external-production":
        raise StageZeroContractError(
            "external-production is unavailable until the external witness, "
            "IMA/EVM, and protected-key verifiers are installed"
        )
    elif trust_mode == "tee-hardware":
        raise StageZeroContractError(
            "tee-hardware is unavailable until the TEE quote, endorsement, "
            "revocation, freshness, HSM, and external-witness verifiers are "
            "installed"
        )
    else:
        raise StageZeroContractError("trust mode is not recognized")


def validate_stage_zero_request(
    request: Mapping[str, Any],
    *,
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> None:
    if not isinstance(verified_package, VerifiedArtifactPackage):
        raise StageZeroContractError(
            "stage zero requires a cryptographically verified package"
        )
    validation_instant = _timestamp(
        validation_time,
        name="stage-zero validation time",
    )
    _integer(
        expected_listen_pid,
        name="expected stage-zero process id",
        minimum=1,
        maximum=2**31 - 1,
    )
    peer_pid = _integer(
        expected_peer_pid,
        name="expected peer process id",
        minimum=1,
        maximum=2**31 - 1,
    )
    peer_start_ticks = _integer(
        expected_peer_start_ticks,
        name="expected peer process start ticks",
        minimum=1,
        maximum=2**64 - 1,
    )
    if peer_pid != expected_listen_pid:
        raise StageZeroContractError(
            "socket-activated stage zero and launched peer PID differ"
        )
    value = _mapping(
        request,
        name="stage-zero request",
        keys={
            "schema",
            "generation",
            "role",
            "stageZero",
            "operationManifest",
            "retainedDirectories",
            "retainedFiles",
            "listener",
            "bootstrapControl",
            "credentials",
            "mutableStateDescriptors",
            "process",
            "hostEvidence",
            "environment",
            "execution",
            "launch",
            "trustMode",
        },
    )
    if value["schema"] != STAGE_ZERO_REQUEST_SCHEMA:
        raise StageZeroContractError("stage-zero request schema changed")
    if value["trustMode"] not in TRUST_MODES:
        raise StageZeroContractError("trust mode is not recognized")
    bootstrap_control = _validate_bootstrap_control(value["bootstrapControl"])

    generation = _mapping(
        value["generation"],
        name="generation reference",
        keys={
            "sequence",
            "digest",
            "packageDigest",
            "predecessorDigest",
            "artifactBundleDigest",
            "minimumRollbackSequence",
            "validFrom",
            "validUntil",
            "operationManifestDigest",
            "stageZeroDigest",
            "stageZeroContract",
            "roleSetDigest",
            "snapshotReceiptDigest",
            "closureReceiptDigest",
            "provenanceStatementDigest",
            "sourceTreeDigest",
            "ociManifestDigest",
            "keyAuthorizationsDigest",
            "keyRevocationsDigest",
            "witnessCheckpointDigest",
            "witnessRootDigest",
            "witnessTreeSize",
        },
    )
    sequence = _integer(
        generation["sequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    _digest(generation["digest"], name="generation digest")
    _digest(generation["packageDigest"], name="signed package digest")
    if generation["predecessorDigest"] is not None:
        _digest(
            generation["predecessorDigest"],
            name="predecessor generation digest",
        )
    _digest(
        generation["artifactBundleDigest"], name="artifact bundle digest"
    )
    for field in (
        "operationManifestDigest",
        "stageZeroDigest",
        "roleSetDigest",
        "snapshotReceiptDigest",
        "closureReceiptDigest",
        "provenanceStatementDigest",
        "sourceTreeDigest",
        "ociManifestDigest",
        "keyAuthorizationsDigest",
        "keyRevocationsDigest",
        "witnessCheckpointDigest",
        "witnessRootDigest",
    ):
        _digest(generation[field], name=field)
    _identifier(
        generation["stageZeroContract"],
        name="stage-zero contract",
    )
    _integer(
        generation["witnessTreeSize"],
        name="witness tree size",
        minimum=1,
        maximum=2**63 - 1,
    )
    rollback = _integer(
        generation["minimumRollbackSequence"],
        name="minimum rollback sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if rollback > sequence:
        raise StageZeroContractError("rollback floor exceeds generation")
    generation_from = _timestamp(
        generation["validFrom"], name="generation validFrom"
    )
    generation_until = _timestamp(
        generation["validUntil"], name="generation validUntil"
    )
    if generation_until <= generation_from:
        raise StageZeroContractError("generation validity is not increasing")
    if not generation_from <= validation_instant <= generation_until:
        raise StageZeroContractError(
            "stage-zero validation is outside generation validity"
        )

    package_generation = verified_package.package["generation"]
    expected_generation = {
        "sequence": verified_package.generation_sequence,
        "digest": verified_package.generation_digest,
        "packageDigest": verified_package.package_digest,
        "predecessorDigest": verified_package.predecessor_digest,
        "artifactBundleDigest": verified_package.artifact_bundle_digest,
        "minimumRollbackSequence": (
            verified_package.minimum_rollback_sequence
        ),
        "validFrom": package_generation["validFrom"],
        "validUntil": package_generation["validUntil"],
        "operationManifestDigest": (
            verified_package.operation_manifest_digest
        ),
        "stageZeroDigest": verified_package.stage_zero_digest,
        "stageZeroContract": verified_package.stage_zero_contract,
        "roleSetDigest": verified_package.role_set_digest,
        "snapshotReceiptDigest": package_generation[
            "snapshotReceiptDigest"
        ],
        "closureReceiptDigest": package_generation[
            "closureReceiptDigest"
        ],
        "provenanceStatementDigest": package_generation[
            "provenanceStatementDigest"
        ],
        "sourceTreeDigest": package_generation["sourceTreeDigest"],
        "ociManifestDigest": package_generation["ociManifestDigest"],
        "keyAuthorizationsDigest": (
            verified_package.key_authorizations_digest
        ),
        "keyRevocationsDigest": verified_package.key_revocations_digest,
        "witnessCheckpointDigest": (
            verified_package.witness_checkpoint_digest
        ),
        "witnessRootDigest": verified_package.witness_root_digest,
        "witnessTreeSize": verified_package.witness_tree_size,
    }
    if dict(generation) != expected_generation:
        raise StageZeroContractError(
            "stage-zero generation binding differs from verified package"
        )
    if value["trustMode"] != verified_package.trust_mode:
        raise StageZeroContractError(
            "stage-zero trust mode differs from verified generation"
        )

    role = _mapping(
        value["role"],
        name="role binding",
        keys={
            "path",
            "sha256",
            "role",
            "processMode",
            "runtimeUid",
            "runtimeGid",
            "supplementaryGids",
            "entrypointPath",
            "listenerName",
            "credentialNames",
            "cwd",
            "pathEntries",
            "argv",
            "environmentAllowlist",
            "mutableStateDescriptors",
        },
    )
    role_name = _identifier(role["role"], name="role")
    _runtime_path("/" + _ascii(role["path"], name="role manifest path"))
    _digest(role["sha256"], name="role manifest digest")
    _identifier(role["processMode"], name="process mode")
    _integer(
        role["runtimeUid"], name="runtime uid", minimum=1, maximum=2**32 - 2
    )
    _integer(
        role["runtimeGid"], name="runtime gid", minimum=1, maximum=2**32 - 2
    )
    supplementary = _list(
        role["supplementaryGids"],
        name="supplementary groups",
        maximum=64,
    )
    for gid in supplementary:
        _integer(
            gid, name="supplementary gid", minimum=1, maximum=2**32 - 2
        )
    if list(supplementary) != sorted(set(supplementary)):
        raise StageZeroContractError(
            "supplementary groups are not sorted and unique"
        )
    _runtime_path(role["entrypointPath"], name="role entrypoint path")
    _identifier(role["listenerName"], name="role listener name")
    for field, maximum, validator in (
        ("credentialNames", MAX_CREDENTIALS, _identifier),
        ("pathEntries", 64, _runtime_path),
        ("argv", MAX_ARGUMENTS, _ascii),
        ("environmentAllowlist", MAX_ENVIRONMENT_ENTRIES, _ascii),
    ):
        role_values = _list(
            role[field],
            name=f"role {field}",
            maximum=maximum,
            minimum=1 if field in {"pathEntries", "argv"} else 0,
        )
        for item in role_values:
            validator(item, name=f"role {field} entry")
    _runtime_path(role["cwd"], name="role working directory")
    if role["credentialNames"] != sorted(set(role["credentialNames"])):
        raise StageZeroContractError(
            "role credential names are not sorted and unique"
        )
    if BOOTSTRAP_CONTROL_NAME in role["credentialNames"]:
        raise StageZeroContractError("role credentials include the bootstrap control")
    if role["environmentAllowlist"] != sorted(
        set(role["environmentAllowlist"])
    ):
        raise StageZeroContractError(
            "role environment allowlist is not sorted and unique"
        )
    if role["pathEntries"] != list(dict.fromkeys(role["pathEntries"])):
        raise StageZeroContractError("role PATH entries are repeated")
    role_state_policies = _list(
        role["mutableStateDescriptors"],
        name="role mutable-state descriptor policies",
        maximum=MAX_MUTABLE_STATE_DESCRIPTORS,
    )
    for raw_policy in role_state_policies:
        policy = _mapping(
            raw_policy,
            name="role mutable-state policy",
            keys={
                "name",
                "runtimePath",
                "atomicRecordProtocol",
                "quotaBytes",
                "singletonLeaseRequired",
                "networkAllowed",
            },
        )
        _identifier(policy["name"], name="mutable-state policy name")
        _runtime_path(
            policy["runtimePath"],
            name="mutable-state policy path",
        )
        if policy["atomicRecordProtocol"] not in (
            ALLOWED_MUTABLE_STATE_PROTOCOLS
        ):
            raise StageZeroContractError(
                "role mutable-state protocol is not allowed"
            )
        _integer(
            policy["quotaBytes"],
            name="role mutable-state quota",
            minimum=1,
            maximum=64 * 1024**3,
        )
        if (
            policy["singletonLeaseRequired"] is not True
            or policy["networkAllowed"] is not False
        ):
            raise StageZeroContractError(
                "role mutable state requires a lease and no network"
            )
    _sorted_unique(
        role_state_policies,
        name="role mutable-state policies",
        key=lambda entry: entry["name"],
    )
    package_roles = [
        entry
        for entry in verified_package.package["bundle"]["roleManifests"]
        if entry["role"] == role_name
    ]
    if len(package_roles) != 1:
        raise StageZeroContractError(
            "role is not unique in the verified package"
        )
    exact_role = {
        key: role[key]
        for key in role
        if key != "supplementaryGids"
    }
    if exact_role != dict(package_roles[0]):
        raise StageZeroContractError(
            "role binding differs from exact signed role manifest"
        )

    stage_zero = _mapping(
        value["stageZero"],
        name="stage-zero binding",
        keys={
            "fd",
            "path",
            "sha256",
            "size",
            "interfaceSchema",
            "runtimePath",
            "staticElf",
            "ptInterp",
            "needed",
            "elfEvidenceDigest",
        },
    )
    _integer(
        stage_zero["fd"],
        name="stage-zero fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    _digest(stage_zero["sha256"], name="stage-zero digest")
    _ascii(stage_zero["path"], name="stage-zero artifact path")
    _integer(
        stage_zero["size"],
        name="stage-zero size",
        minimum=1,
        maximum=MAX_FILE_BYTES,
    )
    _runtime_path(stage_zero["runtimePath"], name="stage-zero runtime path")
    if stage_zero["interfaceSchema"] != STAGE_ZERO_INTERFACE_SCHEMA:
        raise StageZeroContractError("stage-zero interface schema changed")
    if (
        stage_zero["staticElf"] is not True
        or stage_zero["ptInterp"] is not None
        or stage_zero["needed"] != []
    ):
        raise StageZeroContractError("stage zero must be a static ELF")
    _digest(
        stage_zero["elfEvidenceDigest"],
        name="stage-zero ELF evidence",
    )
    exact_stage_zero = {
        key: stage_zero[key] for key in stage_zero if key != "fd"
    }
    if exact_stage_zero != dict(
        verified_package.package["bundle"]["stageZero"]
    ):
        raise StageZeroContractError(
            "stage-zero binary differs from verified package"
        )

    operation_manifest = _mapping(
        value["operationManifest"],
        name="operation manifest binding",
        keys={"path", "sha256", "manifestSchema", "contractDigest"},
    )
    _ascii(
        operation_manifest["path"],
        name="operation manifest path",
    )
    _digest(
        operation_manifest["sha256"],
        name="operation manifest file digest",
    )
    _digest(
        operation_manifest["contractDigest"],
        name="operation manifest contract digest",
    )
    _identifier(
        operation_manifest["manifestSchema"],
        name="operation manifest schema",
    )
    if (
        operation_manifest["contractDigest"]
        != authority_contract.OPERATION_MANIFEST_DIGEST
        or operation_manifest["contractDigest"]
        != generation["operationManifestDigest"]
    ):
        raise StageZeroContractError(
            "operation manifest contract differs from source or generation"
        )
    if dict(operation_manifest) != dict(
        verified_package.package["bundle"]["operationManifest"]
    ):
        raise StageZeroContractError(
            "operation manifest differs from verified package"
        )

    directories = _list(
        value["retainedDirectories"],
        name="retained directories",
        minimum=1,
        maximum=MAX_RETAINED_DIRECTORIES,
    )
    files = _list(
        value["retainedFiles"],
        name="retained files",
        minimum=1,
        maximum=MAX_RETAINED_FILES,
    )
    credentials = _list(
        value["credentials"],
        name="credentials",
        maximum=MAX_CREDENTIALS,
    )
    mutable_state = _list(
        value["mutableStateDescriptors"],
        name="mutable-state descriptors",
        maximum=MAX_MUTABLE_STATE_DESCRIPTORS,
    )
    for entry in directories:
        _validate_retained_directory(entry)
    for entry in files:
        _validate_retained_file(entry)
    for entry in credentials:
        _validate_credential(entry)
        if entry["ownerRole"] != role_name:
            raise StageZeroContractError(
                "credential is assigned to another role"
            )
        if entry["ownerUid"] != role["runtimeUid"]:
            raise StageZeroContractError(
                "credential owner UID differs from role runtime UID"
            )
    for entry in mutable_state:
        _validate_mutable_state_descriptor(entry)
        if (
            entry["ownerRole"] != role_name
            or entry["uid"] != role["runtimeUid"]
            or entry["gid"] != role["runtimeGid"]
        ):
            raise StageZeroContractError(
                "mutable-state ownership differs from exact role"
            )
    _sorted_unique(
        directories,
        name="retained directories",
        key=lambda entry: entry["name"],
    )
    _sorted_unique(
        files, name="retained files", key=lambda entry: entry["name"]
    )
    _sorted_unique(
        credentials, name="credentials", key=lambda entry: entry["name"]
    )
    _sorted_unique(
        mutable_state,
        name="mutable-state descriptors",
        key=lambda entry: entry["name"],
    )
    if [entry["name"] for entry in credentials] != role[
        "credentialNames"
    ]:
        raise StageZeroContractError(
            "credential descriptors differ from exact role manifest"
        )
    state_policy_projection = [
        {
            key: entry[key]
            for key in (
                "name",
                "runtimePath",
                "atomicRecordProtocol",
                "quotaBytes",
                "singletonLeaseRequired",
                "networkAllowed",
            )
        }
        for entry in mutable_state
    ]
    if state_policy_projection != role_state_policies:
        raise StageZeroContractError(
            "mutable-state descriptors differ from exact role manifest"
        )
    if (role_name == "witness") != bool(mutable_state):
        raise StageZeroContractError(
            "only the witness role may retain mutable state"
        )
    state_paths = {entry["runtimePath"] for entry in mutable_state}
    if state_paths & {
        entry["runtimePath"] for entry in directories
    }:
        raise StageZeroContractError(
            "mutable state must be separate from immutable retained roots"
        )
    _validate_listener(
        value["listener"],
        expected_listen_pid=expected_listen_pid,
    )
    if (
        value["listener"]["name"] != role["listenerName"]
        or value["listener"]["activationName"] != role["listenerName"]
    ):
        raise StageZeroContractError(
            "listener differs from exact role manifest"
        )
    _validate_host_evidence(value["hostEvidence"], value["trustMode"])
    process = _mapping(
        value["process"],
        name="launched process identity",
        keys={
            "processId",
            "processStartTicks",
            "bootIdDigest",
            "pidfd",
        },
    )
    _integer(
        process["processId"],
        name="launched process id",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        process["processStartTicks"],
        name="launched process start ticks",
        minimum=1,
        maximum=2**64 - 1,
    )
    if (
        process["processId"] != peer_pid
        or process["processStartTicks"] != peer_start_ticks
        or process["bootIdDigest"]
        != value["hostEvidence"]["bootIdDigest"]
    ):
        raise StageZeroContractError(
            "launched process identity differs from expected peer"
        )
    _digest(process["bootIdDigest"], name="process boot ID digest")
    pidfd = _mapping(
        process["pidfd"],
        name="pidfd identity",
        keys={
            "fd",
            "device",
            "inode",
            "processId",
            "processStartTicks",
            "bootIdDigest",
            "surviveExec",
        },
    )
    _integer(
        pidfd["fd"],
        name="pidfd",
        minimum=3,
        maximum=2**31 - 1,
    )
    _integer(
        pidfd["device"],
        name="pidfd device",
        minimum=0,
        maximum=2**64 - 1,
    )
    _integer(
        pidfd["inode"],
        name="pidfd inode",
        minimum=1,
        maximum=2**64 - 1,
    )
    _integer(
        pidfd["processId"],
        name="pidfd process id",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        pidfd["processStartTicks"],
        name="pidfd process start ticks",
        minimum=1,
        maximum=2**64 - 1,
    )
    _digest(pidfd["bootIdDigest"], name="pidfd boot ID digest")
    if (
        pidfd["processId"] != peer_pid
        or pidfd["processStartTicks"] != peer_start_ticks
        or pidfd["bootIdDigest"] != process["bootIdDigest"]
        or pidfd["surviveExec"] is not False
    ):
        raise StageZeroContractError(
            "pidfd does not bind the exact peer process lifetime"
        )

    environment = _mapping(
        value["environment"],
        name="environment",
        keys={"allowlist", "values"},
    )
    allowlist = _list(
        environment["allowlist"],
        name="environment allowlist",
        maximum=MAX_ENVIRONMENT_ENTRIES,
    )
    for key in allowlist:
        _identifier(key.lower(), name="environment key")
        if key not in ALLOWED_ENVIRONMENT_KEYS:
            raise StageZeroContractError(
                "environment key is not allowlisted by the interface"
            )
    if list(allowlist) != sorted(set(allowlist)):
        raise StageZeroContractError(
            "environment allowlist is not sorted and unique"
        )
    if list(allowlist) != role["environmentAllowlist"]:
        raise StageZeroContractError(
            "environment allowlist differs from exact role manifest"
        )
    values = environment["values"]
    if not isinstance(values, Mapping) or set(values) != set(allowlist):
        raise StageZeroContractError(
            "environment values do not match the allowlist"
        )
    if set(values) & DENIED_ENVIRONMENT_KEYS:
        raise StageZeroContractError(
            "environment contains a loader or Python injection key"
        )
    for key, entry in values.items():
        _ascii(key, name="environment key", maximum=256)
        _ascii(
            entry,
            name=f"environment value {key}",
            maximum=4096,
            allow_empty=True,
        )
    if values.get(BOOTSTRAP_CONTROL_NAME) != str(bootstrap_control["fd"]):
        raise StageZeroContractError("bootstrap control environment descriptor changed")
    if values.get("SERVERWARE_AUTHORITY_GENERATION_DIGEST") != generation[
        "digest"
    ]:
        raise StageZeroContractError(
            "environment generation digest changed"
        )
    if values.get("SERVERWARE_ARTIFACT_BUNDLE_DIGEST") != generation[
        "artifactBundleDigest"
    ]:
        raise StageZeroContractError(
            "environment artifact bundle digest changed"
        )
    if values.get("SERVERWARE_AUTHORITY_ROLE") != role_name:
        raise StageZeroContractError("environment role changed")
    if values.get("SERVERWARE_OPERATION_MANIFEST_DIGEST") != (
        generation["operationManifestDigest"]
    ):
        raise StageZeroContractError(
            "environment operation manifest digest changed"
        )
    if values.get("PATH") != ":".join(role["pathEntries"]):
        raise StageZeroContractError(
            "PATH differs from exact immutable role manifest binding"
        )
    retained_directory_paths = {
        entry["runtimePath"] for entry in directories
    }
    if not set(role["pathEntries"]).issubset(retained_directory_paths):
        raise StageZeroContractError(
            "PATH contains a directory without a retained identity"
        )
    if role["cwd"] not in retained_directory_paths:
        raise StageZeroContractError(
            "working directory has no retained immutable identity"
        )

    execution = _mapping(
        value["execution"],
        name="execution",
        keys={
            "executableFd",
            "executableDigest",
            "pathname",
            "argv",
            "cwd",
            "execveatFlags",
            "pythonIsolationFlags",
            "noNewPrivileges",
            "closeRangeFrom",
            "preserveFds",
        },
    )
    executable_fd = _integer(
        execution["executableFd"],
        name="executable fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    _digest(execution["executableDigest"], name="executable digest")
    if execution["pathname"] != "":
        raise StageZeroContractError(
            "execveat pathname must be the empty string"
        )
    argv = _list(
        execution["argv"],
        name="argv",
        minimum=1,
        maximum=MAX_ARGUMENTS,
    )
    argument_bytes = 0
    for argument in argv:
        argument_bytes += len(
            _ascii(argument, name="argument", maximum=4096).encode("ascii")
        ) + 1
    if argument_bytes > MAX_ARGUMENT_BYTES:
        raise StageZeroContractError("argv exceeds its byte limit")
    if list(argv) != role["argv"]:
        raise StageZeroContractError(
            "argv differs from exact signed role manifest"
        )
    isolation_positions = []
    for flag in REQUIRED_PYTHON_ISOLATION_FLAGS:
        if list(argv).count(flag) != 1:
            raise StageZeroContractError(
                "argv does not contain each isolation flag exactly once"
            )
        isolation_positions.append(list(argv).index(flag))
    if isolation_positions != sorted(isolation_positions):
        raise StageZeroContractError(
            "Python isolation flags are not in canonical order"
        )
    if execution["cwd"] != role["cwd"]:
        raise StageZeroContractError(
            "working directory differs from exact role manifest"
        )
    if execution["execveatFlags"] != list(REQUIRED_EXECVEAT_FLAGS):
        raise StageZeroContractError("execveat flags changed")
    if execution["pythonIsolationFlags"] != list(
        REQUIRED_PYTHON_ISOLATION_FLAGS
    ):
        raise StageZeroContractError("Python isolation flags changed")
    if execution["noNewPrivileges"] is not True:
        raise StageZeroContractError("no_new_privs is not required")
    close_from = _integer(
        execution["closeRangeFrom"],
        name="close-range lower bound",
        minimum=3,
        maximum=2**31 - 1,
    )
    if close_from != 3:
        raise StageZeroContractError(
            "descriptor closing must start at descriptor 3"
        )
    preserve = _list(
        execution["preserveFds"],
        name="preserved descriptors",
        minimum=1,
        maximum=(
            MAX_RETAINED_FILES
            + MAX_CREDENTIALS
            + MAX_RETAINED_DIRECTORIES
            + MAX_MUTABLE_STATE_DESCRIPTORS
            + 16
        ),
    )
    for descriptor in preserve:
        _integer(
            descriptor,
            name="preserved descriptor",
            minimum=3,
            maximum=2**31 - 1,
        )
    if list(preserve) != sorted(set(preserve)):
        raise StageZeroContractError(
            "preserved descriptors are not sorted and unique"
        )

    executable_bindings = [
        entry
        for entry in files
        if entry["fd"] == executable_fd
        and entry["purpose"] == "authority-role-entrypoint"
        and entry["sha256"] == execution["executableDigest"]
    ]
    if len(executable_bindings) != 1:
        raise StageZeroContractError(
            "execution is not bound to one retained role entrypoint"
        )
    executable_binding = executable_bindings[0]
    if (
        executable_binding["runtimePath"] != role["entrypointPath"]
        or executable_binding["surviveExec"] is not True
    ):
        raise StageZeroContractError(
            "role entrypoint identity or exec retention changed"
        )
    independent_descriptors = [
        stage_zero["fd"],
        value["listener"]["fd"],
        bootstrap_control["fd"],
        *(entry["fd"] for entry in directories),
        *(entry["fd"] for entry in files),
        *(entry["fd"] for entry in credentials),
        *(entry["fd"] for entry in mutable_state),
        pidfd["fd"],
    ]
    if len(independent_descriptors) != len(set(independent_descriptors)):
        raise StageZeroContractError("retained descriptor identity is reused")
    launch = _mapping(
        value["launch"],
        name="launch request",
        keys={
            "nonce",
            "validFrom",
            "validUntil",
            "identityIssuerKeyId",
            "identityIssuerAuthorizationDigest",
            "privateKeyTargetFd",
            "certificateTargetFd",
        },
    )
    _base64url(launch["nonce"], name="launch nonce", decoded_size=32)
    launch_from = _timestamp(launch["validFrom"], name="launch validFrom")
    launch_until = _timestamp(launch["validUntil"], name="launch validUntil")
    if (
        launch_until <= launch_from
        or launch_from < generation_from
        or launch_until > generation_until
    ):
        raise StageZeroContractError(
            "launch validity is outside the generation"
        )
    _identifier(
        launch["identityIssuerKeyId"], name="launch identity issuer key"
    )
    _digest(
        launch["identityIssuerAuthorizationDigest"],
        name="launch identity issuer authorization",
    )
    try:
        launch_issuer = verified_package.require_key(
            launch["identityIssuerKeyId"],
            "launch-certificate-issuer",
            at=validation_time,
        )
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc
    if (
        launch["identityIssuerAuthorizationDigest"]
        != launch_issuer.authorization_digest
    ):
        raise StageZeroContractError(
            "launch issuer authorization digest changed"
        )
    private_key_target = _integer(
        launch["privateKeyTargetFd"],
        name="launch private key target fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    certificate_target = _integer(
        launch["certificateTargetFd"],
        name="launch certificate target fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    if (
        private_key_target == certificate_target
        or private_key_target in independent_descriptors
        or certificate_target in independent_descriptors
    ):
        raise StageZeroContractError(
            "launch output descriptor target is reused"
        )
    expected_preserved = {
        value["listener"]["fd"],
        bootstrap_control["fd"],
        *(entry["fd"] for entry in directories if entry["surviveExec"]),
        *(entry["fd"] for entry in files if entry["surviveExec"]),
        *(entry["fd"] for entry in credentials),
        *(entry["fd"] for entry in mutable_state),
        private_key_target,
        certificate_target,
    }
    if set(preserve) != expected_preserved:
        raise StageZeroContractError(
            "preserved descriptor set is not exact"
        )
    if values.get(
        "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD"
    ) != str(private_key_target) or values.get(
        "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD"
    ) != str(certificate_target):
        raise StageZeroContractError(
            "launch output environment descriptor binding changed"
        )


def stage_zero_request_digest(
    request: Mapping[str, Any],
    *,
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> str:
    validate_stage_zero_request(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    return domain_digest(
        STAGE_ZERO_REQUEST_DIGEST_DOMAIN,
        canonical_json_bytes(request),
    )


def listener_identity_digest(listener: Mapping[str, Any]) -> str:
    _validate_listener(listener)
    return domain_digest(
        LISTENER_IDENTITY_DOMAIN,
        canonical_json_bytes(listener),
    )


def credential_set_digest(credentials: Sequence[Mapping[str, Any]]) -> str:
    values = list(credentials)
    for credential in values:
        _validate_credential(credential)
    _sorted_unique(
        values, name="credentials", key=lambda credential: credential["name"]
    )
    public_bindings = [
        {
            "name": credential["name"],
            "purpose": credential["purpose"],
            "ownerRole": credential["ownerRole"],
            "size": credential["size"],
            "sha256": credential["sha256"],
            "mode": credential["mode"],
            "ownerUid": credential["ownerUid"],
            "seals": credential["seals"],
            "delivery": credential["delivery"],
        }
        for credential in values
    ]
    return domain_digest(
        CREDENTIAL_SET_DOMAIN,
        canonical_json_bytes(public_bindings),
    )


def mutable_state_set_digest(
    descriptors: Sequence[Mapping[str, Any]],
) -> str:
    values = list(descriptors)
    for descriptor in values:
        _validate_mutable_state_descriptor(descriptor)
    _sorted_unique(
        values,
        name="mutable-state descriptors",
        key=lambda descriptor: descriptor["name"],
    )
    return domain_digest(
        MUTABLE_STATE_SET_DOMAIN,
        canonical_json_bytes(values),
    )


def pidfd_identity_digest(pidfd: Mapping[str, Any]) -> str:
    value = _mapping(
        pidfd,
        name="pidfd identity",
        keys={
            "fd",
            "device",
            "inode",
            "processId",
            "processStartTicks",
            "bootIdDigest",
            "surviveExec",
        },
    )
    return domain_digest(
        PIDFD_IDENTITY_DOMAIN,
        canonical_json_bytes(value),
    )


def environment_digest(environment: Mapping[str, Any]) -> str:
    value = _mapping(
        environment,
        name="environment",
        keys={"allowlist", "values"},
    )
    return domain_digest(
        ENVIRONMENT_DOMAIN,
        canonical_json_bytes(value),
    )


def argument_vector_digest(argv: Sequence[str]) -> str:
    values = _list(
        list(argv),
        name="argv",
        minimum=1,
        maximum=MAX_ARGUMENTS,
    )
    total = 0
    for argument in values:
        total += len(
            _ascii(
                argument,
                name="argument",
                maximum=4096,
            ).encode("ascii")
        ) + 1
    if total > MAX_ARGUMENT_BYTES:
        raise StageZeroContractError("argv exceeds its byte limit")
    return domain_digest(
        ARGUMENT_VECTOR_DOMAIN,
        canonical_json_bytes(values),
    )


def working_directory_digest(cwd: str) -> str:
    value = _runtime_path(cwd, name="working directory")
    return domain_digest(
        WORKING_DIRECTORY_DOMAIN,
        canonical_json_bytes(value),
    )


def identity_fd_digest(
    private_key_descriptor: Mapping[str, Any],
    certificate_descriptor: Mapping[str, Any],
) -> str:
    private_value = _mapping(
        private_key_descriptor,
        name="launch private key descriptor",
        keys={
            "fd",
            "size",
            "seals",
            "delivery",
            "purpose",
            "publicKeyDigest",
        },
    )
    certificate_value = _mapping(
        certificate_descriptor,
        name="certificate descriptor",
        keys={"fd", "size", "sha256", "seals", "delivery"},
    )
    return domain_digest(
        IDENTITY_FD_DOMAIN,
        canonical_json_bytes(
            {
                "privateKey": private_value,
                "certificate": certificate_value,
            }
        ),
    )


def derive_launch_id(
    request: Mapping[str, Any],
    launch_public_key_base64url: str,
    *,
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> str:
    validate_stage_zero_request(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    public_key = _base64url(
        launch_public_key_base64url,
        name="launch public key",
        decoded_size=32,
    )
    return domain_digest(
        LAUNCH_ID_DOMAIN,
        stage_zero_request_digest(
            request,
            verified_package=verified_package,
            expected_listen_pid=expected_listen_pid,
            expected_peer_pid=expected_peer_pid,
            expected_peer_start_ticks=expected_peer_start_ticks,
            validation_time=validation_time,
        ).encode("ascii"),
        public_key,
    )


def validate_launch_identity_payload(
    payload: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> None:
    value = _mapping(
        payload,
        name="launch identity payload",
        keys={
            "schema",
            "launchId",
            "generationSequence",
            "generationDigest",
            "packageDigest",
            "predecessorDigest",
            "artifactBundleDigest",
            "operationManifestDigest",
            "stageZeroDigest",
            "stageZeroContract",
            "roleSetDigest",
            "keyAuthorizationsDigest",
            "keyRevocationsDigest",
            "witnessCheckpointDigest",
            "role",
            "roleManifestDigest",
            "processMode",
            "runtimeUid",
            "runtimeGid",
            "supplementaryGids",
            "bootIdDigest",
            "kernelReleaseDigest",
            "kernelCommandLineDigest",
            "vdsoDigest",
            "listenerIdentityDigest",
            "credentialSetDigest",
            "mutableStateSetDigest",
            "processId",
            "processStartTicks",
            "pidfdIdentityDigest",
            "executableDigest",
            "argvDigest",
            "environmentDigest",
            "cwdDigest",
            "requestDigest",
            "publicKeyAlgorithm",
            "launchPublicKeyBase64Url",
            "issuedAt",
            "expiresAt",
            "trustMode",
            "coLocated",
            "hardwareBacked",
        },
    )
    if value["schema"] != LAUNCH_IDENTITY_PAYLOAD_SCHEMA:
        raise StageZeroContractError("launch identity payload schema changed")
    _digest(value["launchId"], name="launch identifier")
    _integer(
        value["generationSequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    for field in (
        "generationDigest",
        "packageDigest",
        "artifactBundleDigest",
        "operationManifestDigest",
        "stageZeroDigest",
        "roleSetDigest",
        "keyAuthorizationsDigest",
        "keyRevocationsDigest",
        "witnessCheckpointDigest",
        "roleManifestDigest",
        "bootIdDigest",
        "kernelReleaseDigest",
        "kernelCommandLineDigest",
        "vdsoDigest",
        "listenerIdentityDigest",
        "credentialSetDigest",
        "mutableStateSetDigest",
        "pidfdIdentityDigest",
        "executableDigest",
        "argvDigest",
        "environmentDigest",
        "cwdDigest",
        "requestDigest",
    ):
        _digest(value[field], name=field)
    _integer(
        value["processId"],
        name="certificate process id",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        value["processStartTicks"],
        name="certificate process start ticks",
        minimum=1,
        maximum=2**64 - 1,
    )
    if value["predecessorDigest"] is not None:
        _digest(
            value["predecessorDigest"],
            name="predecessor generation digest",
        )
    _identifier(value["stageZeroContract"], name="stage-zero contract")
    _identifier(value["role"], name="role")
    _identifier(value["processMode"], name="process mode")
    _integer(
        value["runtimeUid"],
        name="runtime uid",
        minimum=1,
        maximum=2**32 - 2,
    )
    _integer(
        value["runtimeGid"],
        name="runtime gid",
        minimum=1,
        maximum=2**32 - 2,
    )
    supplementary = _list(
        value["supplementaryGids"],
        name="supplementary groups",
        maximum=64,
    )
    for gid in supplementary:
        _integer(
            gid, name="supplementary gid", minimum=1, maximum=2**32 - 2
        )
    if list(supplementary) != sorted(set(supplementary)):
        raise StageZeroContractError(
            "supplementary groups are not sorted and unique"
        )
    if value["publicKeyAlgorithm"] != "Ed25519":
        raise StageZeroContractError("launch key algorithm changed")
    _base64url(
        value["launchPublicKeyBase64Url"],
        name="launch public key",
        decoded_size=32,
    )
    issued_at = _timestamp(value["issuedAt"], name="issuedAt")
    expires_at = _timestamp(value["expiresAt"], name="expiresAt")
    if expires_at <= issued_at:
        raise StageZeroContractError(
            "launch identity validity is not increasing"
        )
    if value["trustMode"] not in TRUST_MODES:
        raise StageZeroContractError("launch trust mode is not recognized")
    if (
        not isinstance(value["coLocated"], bool)
        or not isinstance(value["hardwareBacked"], bool)
    ):
        raise StageZeroContractError(
            "launch identity assurance claims must be boolean"
        )

    validate_stage_zero_request(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    role = request["role"]
    host = request["hostEvidence"]
    generation = request["generation"]
    expected = {
        "launchId": derive_launch_id(
            request,
            value["launchPublicKeyBase64Url"],
            verified_package=verified_package,
            expected_listen_pid=expected_listen_pid,
            expected_peer_pid=expected_peer_pid,
            expected_peer_start_ticks=expected_peer_start_ticks,
            validation_time=validation_time,
        ),
        "generationSequence": generation["sequence"],
        "generationDigest": generation["digest"],
        "packageDigest": generation["packageDigest"],
        "predecessorDigest": generation["predecessorDigest"],
        "artifactBundleDigest": generation["artifactBundleDigest"],
        "operationManifestDigest": generation["operationManifestDigest"],
        "stageZeroDigest": generation["stageZeroDigest"],
        "stageZeroContract": generation["stageZeroContract"],
        "roleSetDigest": generation["roleSetDigest"],
        "keyAuthorizationsDigest": generation[
            "keyAuthorizationsDigest"
        ],
        "keyRevocationsDigest": generation["keyRevocationsDigest"],
        "witnessCheckpointDigest": generation[
            "witnessCheckpointDigest"
        ],
        "role": role["role"],
        "roleManifestDigest": role["sha256"],
        "processMode": role["processMode"],
        "runtimeUid": role["runtimeUid"],
        "runtimeGid": role["runtimeGid"],
        "supplementaryGids": role["supplementaryGids"],
        "bootIdDigest": host["bootIdDigest"],
        "kernelReleaseDigest": host["kernelReleaseDigest"],
        "kernelCommandLineDigest": host["kernelCommandLineDigest"],
        "vdsoDigest": host["vdsoDigest"],
        "listenerIdentityDigest": listener_identity_digest(
            request["listener"]
        ),
        "credentialSetDigest": credential_set_digest(
            request["credentials"]
        ),
        "mutableStateSetDigest": mutable_state_set_digest(
            request["mutableStateDescriptors"]
        ),
        "processId": request["process"]["processId"],
        "processStartTicks": request["process"]["processStartTicks"],
        "pidfdIdentityDigest": pidfd_identity_digest(
            request["process"]["pidfd"]
        ),
        "executableDigest": request["execution"]["executableDigest"],
        "argvDigest": argument_vector_digest(
            request["execution"]["argv"]
        ),
        "environmentDigest": environment_digest(
            request["environment"]
        ),
        "cwdDigest": working_directory_digest(
            request["execution"]["cwd"]
        ),
        "requestDigest": stage_zero_request_digest(
            request,
            verified_package=verified_package,
            expected_listen_pid=expected_listen_pid,
            expected_peer_pid=expected_peer_pid,
            expected_peer_start_ticks=expected_peer_start_ticks,
            validation_time=validation_time,
        ),
        "issuedAt": request["launch"]["validFrom"],
        "expiresAt": request["launch"]["validUntil"],
        "trustMode": request["trustMode"],
        "coLocated": request["trustMode"] == "trusted-host-local",
        "hardwareBacked": request["trustMode"] == "tee-hardware",
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise StageZeroContractError(
                f"launch identity {field} changed"
            )


def validate_signed_launch_identity(
    certificate: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> None:
    value = _mapping(
        certificate,
        name="signed launch identity",
        keys={
            "schema",
            "payload",
            "issuerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    if value["schema"] != SIGNED_LAUNCH_IDENTITY_SCHEMA:
        raise StageZeroContractError("launch certificate schema changed")
    validate_launch_identity_payload(
        value["payload"],
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    _identifier(value["issuerKeyId"], name="certificate issuer key")
    if value["algorithm"] != "Ed25519":
        raise StageZeroContractError("certificate algorithm changed")
    _base64url(
        value["signatureBase64Url"],
        name="certificate signature",
        decoded_size=64,
    )
    if value["issuerKeyId"] != request["launch"][
        "identityIssuerKeyId"
    ]:
        raise StageZeroContractError(
            "certificate issuer is not generation-authorized"
        )
    try:
        issuer = verified_package.require_key(
            value["issuerKeyId"],
            "launch-certificate-issuer",
            at=validation_time,
        )
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc
    if issuer.authorization_digest != request["launch"][
        "identityIssuerAuthorizationDigest"
    ]:
        raise StageZeroContractError(
            "certificate issuer authorization digest changed"
        )
    validation_instant = _timestamp(
        validation_time,
        name="launch certificate validation time",
    )
    if not (
        _timestamp(value["payload"]["issuedAt"], name="issuedAt")
        <= validation_instant
        <= _timestamp(value["payload"]["expiresAt"], name="expiresAt")
    ):
        raise StageZeroContractError(
            "launch certificate is outside its validity interval"
        )
    try:
        verify_ed25519_signature(
            issuer.public_key,
            value["signatureBase64Url"],
            launch_certificate_signature_message(
                value["payload"],
                request=request,
                verified_package=verified_package,
                expected_listen_pid=expected_listen_pid,
                expected_peer_pid=expected_peer_pid,
                expected_peer_start_ticks=expected_peer_start_ticks,
                validation_time=validation_time,
            ),
            name="launch identity certificate",
        )
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc


def validate_trusted_host_local_launch_identity(
    *,
    request: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
    private_key_seed: bytes,
    certificate_bytes: bytes,
) -> Mapping[str, Any]:
    if (
        verified_package.trust_mode != "trusted-host-local"
        or request.get("trustMode") != "trusted-host-local"
        or not isinstance(private_key_seed, bytes)
        or len(private_key_seed) != 32
        or not isinstance(certificate_bytes, bytes)
        or not 1 <= len(certificate_bytes) <= 1024 * 1024
    ):
        raise StageZeroContractError(
            "trusted-host-local launch identity prerequisites changed"
        )
    validate_stage_zero_request(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    try:
        certificate = json.loads(certificate_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageZeroContractError(
            "trusted-host-local certificate is not JSON"
        ) from exc
    if (
        not isinstance(certificate, dict)
        or canonical_json_bytes(certificate) != certificate_bytes
    ):
        raise StageZeroContractError(
            "trusted-host-local certificate bytes are not canonical"
        )
    validate_signed_launch_identity(
        certificate,
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    try:
        public_key = ed25519_public_key_from_seed(private_key_seed)
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc
    certified_key = strict_base64url_decode(
        certificate["payload"]["launchPublicKeyBase64Url"],
        name="trusted-host-local certified launch public key",
        decoded_size=32,
    )
    if public_key != certified_key:
        raise StageZeroContractError(
            "trusted-host-local seed is not the certified launch key"
        )
    return certificate


def launch_certificate_signature_message(
    payload: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
) -> bytes:
    validate_launch_identity_payload(
        payload,
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    return domain_digest(
        LAUNCH_CERTIFICATE_SIGNATURE_DOMAIN,
        canonical_json_bytes(payload),
    ).encode("ascii")


def validate_stage_zero_handoff(
    handoff: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    expected_listen_pid: int,
    expected_peer_pid: int,
    expected_peer_start_ticks: int,
    validation_time: str,
    private_key_seed: bytes,
    certificate_bytes: bytes,
) -> None:
    validate_stage_zero_request(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )
    value = _mapping(
        handoff,
        name="stage-zero handoff",
        keys={
            "schema",
            "requestDigest",
            "launchIdentity",
            "launchPrivateKey",
            "certificateDescriptor",
            "identityFdDigest",
            "execveat",
        },
    )
    if value["schema"] != STAGE_ZERO_HANDOFF_SCHEMA:
        raise StageZeroContractError("stage-zero handoff schema changed")
    if value["requestDigest"] != stage_zero_request_digest(
        request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    ):
        raise StageZeroContractError("stage-zero handoff request changed")
    if (
        not isinstance(certificate_bytes, bytes)
        or not 1 <= len(certificate_bytes) <= 1024 * 1024
    ):
        raise StageZeroContractError(
            "launch certificate bytes are invalid"
        )
    try:
        parsed_certificate = json.loads(certificate_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageZeroContractError(
            "launch certificate bytes are not canonical JSON"
        ) from exc
    if (
        parsed_certificate != value["launchIdentity"]
        or canonical_json_bytes(value["launchIdentity"])
        != certificate_bytes
    ):
        raise StageZeroContractError(
            "launch certificate mapping differs from exact descriptor bytes"
        )
    validate_signed_launch_identity(
        value["launchIdentity"],
        request=request,
        verified_package=verified_package,
        expected_listen_pid=expected_listen_pid,
        expected_peer_pid=expected_peer_pid,
        expected_peer_start_ticks=expected_peer_start_ticks,
        validation_time=validation_time,
    )

    private_key = _mapping(
        value["launchPrivateKey"],
        name="launch private key descriptor",
        keys={
            "fd",
            "size",
            "seals",
            "delivery",
            "purpose",
            "publicKeyDigest",
        },
    )
    _integer(
        private_key["fd"],
        name="launch private key fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    if private_key["size"] != 32:
        raise StageZeroContractError("Ed25519 private seed size changed")
    _digest(
        private_key["publicKeyDigest"],
        name="launch public key digest",
    )
    seals = _integer(
        private_key["seals"],
        name="launch private key seals",
        minimum=0,
        maximum=2**31 - 1,
    )
    if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        raise StageZeroContractError(
            "launch private key descriptor is not sealed"
        )
    if (
        private_key["delivery"] != "retained-sealed-memfd"
        or private_key["purpose"] != "launch-identity-private-key"
    ):
        raise StageZeroContractError(
            "launch private key delivery contract changed"
        )
    if private_key["fd"] != request["launch"]["privateKeyTargetFd"]:
        raise StageZeroContractError(
            "launch private key target descriptor changed"
        )
    try:
        launch_public_key = ed25519_public_key_from_seed(private_key_seed)
    except ArtifactContractError as exc:
        raise StageZeroContractError(str(exc)) from exc
    expected_public_key_digest = (
        "sha256:" + hashlib.sha256(launch_public_key).hexdigest()
    )
    if private_key["publicKeyDigest"] != expected_public_key_digest:
        raise StageZeroContractError(
            "sealed seed public key digest changed"
        )
    certified_public_key = _base64url(
        value["launchIdentity"]["payload"]["launchPublicKeyBase64Url"],
        name="certified launch public key",
        decoded_size=32,
    )
    if launch_public_key != certified_public_key:
        raise StageZeroContractError(
            "sealed seed does not derive the certified launch public key"
        )

    certificate_fd = _mapping(
        value["certificateDescriptor"],
        name="certificate descriptor",
        keys={"fd", "size", "sha256", "seals", "delivery"},
    )
    _integer(
        certificate_fd["fd"],
        name="certificate fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    _integer(
        certificate_fd["size"],
        name="certificate size",
        minimum=1,
        maximum=1024 * 1024,
    )
    _digest(certificate_fd["sha256"], name="certificate digest")
    expected_certificate_digest = (
        "sha256:" + hashlib.sha256(certificate_bytes).hexdigest()
    )
    if (
        certificate_fd["size"] != len(certificate_bytes)
        or certificate_fd["sha256"] != expected_certificate_digest
    ):
        raise StageZeroContractError(
            "certificate descriptor differs from exact certificate bytes"
        )
    seals = _integer(
        certificate_fd["seals"],
        name="certificate seals",
        minimum=0,
        maximum=2**31 - 1,
    )
    if seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        raise StageZeroContractError(
            "launch certificate descriptor is not sealed"
        )
    if certificate_fd["delivery"] != "retained-sealed-memfd":
        raise StageZeroContractError(
            "launch certificate delivery contract changed"
        )
    if certificate_fd["fd"] != request["launch"]["certificateTargetFd"]:
        raise StageZeroContractError(
            "launch certificate target descriptor changed"
        )
    expected_identity_digest = identity_fd_digest(
        private_key,
        certificate_fd,
    )
    if value["identityFdDigest"] != expected_identity_digest:
        raise StageZeroContractError(
            "launch identity descriptor digest changed"
        )

    execution = _mapping(
        value["execveat"],
        name="execveat handoff",
        keys={
            "executableFd",
            "pathname",
            "flags",
            "argvDigest",
            "environmentDigest",
            "cwdDigest",
            "identityFdDigest",
            "preservedFds",
        },
    )
    if execution["executableFd"] != request["execution"]["executableFd"]:
        raise StageZeroContractError("handoff executable descriptor changed")
    if execution["pathname"] != "":
        raise StageZeroContractError(
            "handoff execveat pathname must be empty"
        )
    if execution["flags"] != list(REQUIRED_EXECVEAT_FLAGS):
        raise StageZeroContractError("handoff execveat flags changed")
    if execution["argvDigest"] != argument_vector_digest(
        request["execution"]["argv"]
    ):
        raise StageZeroContractError("handoff argv changed")
    if execution["environmentDigest"] != environment_digest(
        request["environment"]
    ):
        raise StageZeroContractError("handoff environment changed")
    if execution["cwdDigest"] != working_directory_digest(
        request["execution"]["cwd"]
    ):
        raise StageZeroContractError("handoff working directory changed")
    if execution["identityFdDigest"] != expected_identity_digest:
        raise StageZeroContractError(
            "handoff launch identity descriptors changed"
        )
    preserved = _list(
        execution["preservedFds"],
        name="handoff preserved descriptors",
        minimum=1,
        maximum=(
            MAX_RETAINED_FILES
            + MAX_CREDENTIALS
            + MAX_RETAINED_DIRECTORIES
            + MAX_MUTABLE_STATE_DESCRIPTORS
            + 18
        ),
    )
    if list(preserved) != sorted(set(preserved)):
        raise StageZeroContractError(
            "handoff descriptors are not sorted and unique"
        )
    if list(preserved) != request["execution"]["preserveFds"]:
        raise StageZeroContractError(
            "handoff preserved descriptor set changed"
        )


def _closed_schema(properties: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": dict(properties),
    }


def _closed_shape(keys: Sequence[str]) -> dict[str, Any]:
    return _closed_schema({key: {} for key in keys})


SHA256_JSON_SCHEMA = {
    "type": "string",
    "pattern": "^sha256:[0-9a-f]{64}$",
}
BOOTSTRAP_CONTROL_JSON_SCHEMA = _closed_schema(
    {
        "name": {"const": BOOTSTRAP_CONTROL_NAME},
        "fd": {"type": "integer", "minimum": 3, "maximum": 2**31 - 1},
        "envelopeSchema": {"const": BOOTSTRAP_CONTROL_ENVELOPE_SCHEMA},
        "maximumBytes": {"const": MAX_BOOTSTRAP_CONTROL_BYTES},
    }
)
STAGE_ZERO_REQUEST_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": STAGE_ZERO_REQUEST_SCHEMA},
        "generation": _closed_shape(
            [
                "sequence",
                "digest",
                "artifactBundleDigest",
                "minimumRollbackSequence",
                "validFrom",
                "validUntil",
            ]
        ),
        "role": _closed_shape(
            [
                "name",
                "manifestDigest",
                "processMode",
                "runtimeUid",
                "runtimeGid",
                "supplementaryGids",
            ]
        ),
        "stageZero": _closed_shape(
            ["fd", "sha256", "interfaceSchema", "staticElf"]
        ),
        "retainedDirectories": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_RETAINED_DIRECTORIES,
        },
        "retainedFiles": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_RETAINED_FILES,
        },
        "listener": _closed_shape(
            [
                "name",
                "fd",
                "runtimePath",
                "activationName",
                "family",
                "socketType",
                "accepting",
                "listenPid",
                "listenFds",
                "listenFdNames",
                "device",
                "inode",
                "mode",
                "uid",
                "gid",
            ]
        ),
        "credentials": {
            "type": "array",
            "maxItems": MAX_CREDENTIALS,
        },
        "bootstrapControl": BOOTSTRAP_CONTROL_JSON_SCHEMA,
        "hostEvidence": _closed_shape(
            [
                "bootIdDigest",
                "kernelReleaseDigest",
                "kernelCommandLineDigest",
                "vdsoDigest",
                "vsyscallMode",
                "imaAppraisal",
                "teeEvidenceDigest",
                "externalWitnessCheckpointDigest",
            ]
        ),
        "environment": _closed_shape(["allowlist", "values"]),
        "execution": _closed_shape(
            [
                "executableFd",
                "executableDigest",
                "argv",
                "cwd",
                "execveatFlags",
                "pythonIsolationFlags",
                "noNewPrivileges",
                "closeRangeFrom",
                "preserveFds",
            ]
        ),
        "launch": _closed_shape(
            [
                "nonce",
                "validFrom",
                "validUntil",
                "identityIssuerKeyId",
                "identityIssuerAuthorizationDigest",
                "privateKeyTargetFd",
                "certificateTargetFd",
            ]
        ),
        "trustMode": {"enum": sorted(TRUST_MODES)},
    }
)
LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA = _closed_shape(
    [
        "schema",
        "launchId",
        "generationSequence",
        "generationDigest",
        "artifactBundleDigest",
        "stageZeroDigest",
        "role",
        "roleManifestDigest",
        "processMode",
        "runtimeUid",
        "runtimeGid",
        "supplementaryGids",
        "bootIdDigest",
        "kernelReleaseDigest",
        "kernelCommandLineDigest",
        "vdsoDigest",
        "listenerIdentityDigest",
        "credentialSetDigest",
        "executableDigest",
        "environmentDigest",
        "requestDigest",
        "publicKeyAlgorithm",
        "launchPublicKeyBase64Url",
        "issuedAt",
        "expiresAt",
        "trustMode",
        "coLocated",
        "hardwareBacked",
    ]
)
SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": SIGNED_LAUNCH_IDENTITY_SCHEMA},
        "payload": LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA,
        "issuerKeyId": {"type": "string", "minLength": 1, "maxLength": 256},
        "algorithm": {"const": "Ed25519"},
        "signatureBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{86}$",
        },
    }
)
STAGE_ZERO_HANDOFF_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": STAGE_ZERO_HANDOFF_SCHEMA},
        "requestDigest": SHA256_JSON_SCHEMA,
        "launchIdentity": SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA,
        "launchPrivateKey": _closed_shape(
            ["fd", "size", "seals", "delivery", "purpose"]
        ),
        "certificateDescriptor": _closed_shape(
            ["fd", "size", "sha256", "seals", "delivery"]
        ),
        "execveat": _closed_shape(
            [
                "executableFd",
                "flags",
                "argvDigest",
                "environmentDigest",
                "preservedFds",
            ]
        ),
    }
)

# These final definitions intentionally replace the compact shape declarations
# above. Every object-valued field is closed here; cross-field equality and
# ordering remain enforced by the semantic validators.
INTEGER_JSON_SCHEMA = {"type": "integer"}
STRING_JSON_SCHEMA = {"type": "string"}
TIMESTAMP_JSON_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
NULLABLE_SHA256_JSON_SCHEMA = {
    "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
}
STRING_ARRAY_JSON_SCHEMA = {
    "type": "array",
    "items": STRING_JSON_SCHEMA,
}
INTEGER_ARRAY_JSON_SCHEMA = {
    "type": "array",
    "items": INTEGER_JSON_SCHEMA,
}
RETAINED_DIRECTORY_JSON_SCHEMA = _closed_schema(
    {
        "name": STRING_JSON_SCHEMA,
        "fd": INTEGER_JSON_SCHEMA,
        "purpose": {"enum": sorted(ALLOWED_DIRECTORY_PURPOSES)},
        "runtimePath": STRING_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "generation": INTEGER_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
        "surviveExec": {"type": "boolean"},
    }
)
RETAINED_FILE_JSON_SCHEMA = _closed_schema(
    {
        "name": STRING_JSON_SCHEMA,
        "fd": INTEGER_JSON_SCHEMA,
        "purpose": {"enum": sorted(ALLOWED_FILE_PURPOSES)},
        "runtimePath": STRING_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "generation": INTEGER_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
        "size": INTEGER_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "fsVerityDigest": NULLABLE_SHA256_JSON_SCHEMA,
        "surviveExec": {"type": "boolean"},
    }
)
LISTENER_JSON_SCHEMA = _closed_schema(
    {
        "name": STRING_JSON_SCHEMA,
        "fd": INTEGER_JSON_SCHEMA,
        "runtimePath": STRING_JSON_SCHEMA,
        "activationName": STRING_JSON_SCHEMA,
        "family": {"const": "AF_UNIX"},
        "socketType": {"const": "SOCK_STREAM"},
        "accepting": {"const": True},
        "listenPid": INTEGER_JSON_SCHEMA,
        "listenFds": {"const": 1},
        "listenFdNames": STRING_ARRAY_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
    }
)
CREDENTIAL_JSON_SCHEMA = _closed_schema(
    {
        "name": {"type": "string", "not": {"const": BOOTSTRAP_CONTROL_NAME}},
        "fd": INTEGER_JSON_SCHEMA,
        "purpose": {"enum": sorted(ALLOWED_CREDENTIAL_PURPOSES)},
        "ownerRole": STRING_JSON_SCHEMA,
        "size": INTEGER_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "ownerUid": INTEGER_JSON_SCHEMA,
        "seals": INTEGER_JSON_SCHEMA,
        "delivery": {"const": "retained-sealed-memfd"},
    }
)
ROLE_BINDING_JSON_SCHEMA = _closed_schema(
    {
        "path": STRING_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "role": STRING_JSON_SCHEMA,
        "processMode": STRING_JSON_SCHEMA,
        "runtimeUid": INTEGER_JSON_SCHEMA,
        "runtimeGid": INTEGER_JSON_SCHEMA,
        "supplementaryGids": INTEGER_ARRAY_JSON_SCHEMA,
        "entrypointPath": STRING_JSON_SCHEMA,
        "listenerName": STRING_JSON_SCHEMA,
        "credentialNames": {
            "type": "array", "maxItems": MAX_CREDENTIALS,
            "items": {"type": "string", "not": {"const": BOOTSTRAP_CONTROL_NAME}},
        },
        "cwd": STRING_JSON_SCHEMA,
        "pathEntries": STRING_ARRAY_JSON_SCHEMA,
        "argv": STRING_ARRAY_JSON_SCHEMA,
        "environmentAllowlist": STRING_ARRAY_JSON_SCHEMA,
        "mutableStateDescriptors": {
            "type": "array",
            "maxItems": MAX_MUTABLE_STATE_DESCRIPTORS,
            "items": _closed_schema(
                {
                    "name": STRING_JSON_SCHEMA,
                    "runtimePath": STRING_JSON_SCHEMA,
                    "atomicRecordProtocol": {
                        "enum": sorted(ALLOWED_MUTABLE_STATE_PROTOCOLS)
                    },
                    "quotaBytes": INTEGER_JSON_SCHEMA,
                    "singletonLeaseRequired": {"const": True},
                    "networkAllowed": {"const": False},
                }
            ),
        },
    }
)
MUTABLE_STATE_DESCRIPTOR_JSON_SCHEMA = _closed_schema(
    {
        "name": STRING_JSON_SCHEMA,
        "ownerRole": STRING_JSON_SCHEMA,
        "fd": INTEGER_JSON_SCHEMA,
        "runtimePath": STRING_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "generation": INTEGER_JSON_SCHEMA,
        "mountId": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "singletonLeaseRequired": {"const": True},
        "leaseIdentityDigest": SHA256_JSON_SCHEMA,
        "leaseHeld": {"const": True},
        "atomicRecordProtocol": {
            "enum": sorted(ALLOWED_MUTABLE_STATE_PROTOCOLS)
        },
        "quotaBytes": INTEGER_JSON_SCHEMA,
        "networkAllowed": {"const": False},
        "surviveExec": {"const": True},
    }
)
PIDFD_JSON_SCHEMA = _closed_schema(
    {
        "fd": INTEGER_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "processId": INTEGER_JSON_SCHEMA,
        "processStartTicks": INTEGER_JSON_SCHEMA,
        "bootIdDigest": SHA256_JSON_SCHEMA,
        "surviveExec": {"const": False},
    }
)
PROCESS_IDENTITY_JSON_SCHEMA = _closed_schema(
    {
        "processId": INTEGER_JSON_SCHEMA,
        "processStartTicks": INTEGER_JSON_SCHEMA,
        "bootIdDigest": SHA256_JSON_SCHEMA,
        "pidfd": PIDFD_JSON_SCHEMA,
    }
)
GENERATION_BINDING_JSON_SCHEMA = _closed_schema(
    {
        "sequence": INTEGER_JSON_SCHEMA,
        "digest": SHA256_JSON_SCHEMA,
        "packageDigest": SHA256_JSON_SCHEMA,
        "predecessorDigest": NULLABLE_SHA256_JSON_SCHEMA,
        "artifactBundleDigest": SHA256_JSON_SCHEMA,
        "minimumRollbackSequence": INTEGER_JSON_SCHEMA,
        "validFrom": TIMESTAMP_JSON_SCHEMA,
        "validUntil": TIMESTAMP_JSON_SCHEMA,
        "operationManifestDigest": SHA256_JSON_SCHEMA,
        "stageZeroDigest": SHA256_JSON_SCHEMA,
        "stageZeroContract": STRING_JSON_SCHEMA,
        "roleSetDigest": SHA256_JSON_SCHEMA,
        "snapshotReceiptDigest": SHA256_JSON_SCHEMA,
        "closureReceiptDigest": SHA256_JSON_SCHEMA,
        "provenanceStatementDigest": SHA256_JSON_SCHEMA,
        "sourceTreeDigest": SHA256_JSON_SCHEMA,
        "ociManifestDigest": SHA256_JSON_SCHEMA,
        "keyAuthorizationsDigest": SHA256_JSON_SCHEMA,
        "keyRevocationsDigest": SHA256_JSON_SCHEMA,
        "witnessCheckpointDigest": SHA256_JSON_SCHEMA,
        "witnessRootDigest": SHA256_JSON_SCHEMA,
        "witnessTreeSize": INTEGER_JSON_SCHEMA,
    }
)
STAGE_ZERO_BINDING_JSON_SCHEMA = _closed_schema(
    {
        "fd": INTEGER_JSON_SCHEMA,
        "path": STRING_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "size": INTEGER_JSON_SCHEMA,
        "interfaceSchema": {"const": STAGE_ZERO_INTERFACE_SCHEMA},
        "runtimePath": STRING_JSON_SCHEMA,
        "staticElf": {"const": True},
        "ptInterp": {"type": "null"},
        "needed": {"type": "array", "maxItems": 0},
        "elfEvidenceDigest": SHA256_JSON_SCHEMA,
    }
)
OPERATION_MANIFEST_BINDING_JSON_SCHEMA = _closed_schema(
    {
        "path": STRING_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "manifestSchema": STRING_JSON_SCHEMA,
        "contractDigest": SHA256_JSON_SCHEMA,
    }
)
HOST_EVIDENCE_JSON_SCHEMA = _closed_schema(
    {
        "bootIdDigest": SHA256_JSON_SCHEMA,
        "kernelReleaseDigest": SHA256_JSON_SCHEMA,
        "kernelCommandLineDigest": SHA256_JSON_SCHEMA,
        "vdsoDigest": SHA256_JSON_SCHEMA,
        "vsyscallMode": {"const": "none"},
        "imaAppraisal": {
            "enum": ["not-enforced", "enforced-and-verified"]
        },
        "teeEvidenceDigest": NULLABLE_SHA256_JSON_SCHEMA,
        "externalWitnessCheckpointDigest": NULLABLE_SHA256_JSON_SCHEMA,
    }
)
ENVIRONMENT_JSON_SCHEMA = _closed_schema(
    {
        "allowlist": STRING_ARRAY_JSON_SCHEMA,
        "values": {
            "type": "object",
            "propertyNames": {"type": "string"},
            "additionalProperties": {"type": "string"},
        },
    }
)
EXECUTION_JSON_SCHEMA = _closed_schema(
    {
        "executableFd": INTEGER_JSON_SCHEMA,
        "executableDigest": SHA256_JSON_SCHEMA,
        "pathname": {"const": ""},
        "argv": STRING_ARRAY_JSON_SCHEMA,
        "cwd": STRING_JSON_SCHEMA,
        "execveatFlags": {
            "const": list(REQUIRED_EXECVEAT_FLAGS)
        },
        "pythonIsolationFlags": {
            "const": list(REQUIRED_PYTHON_ISOLATION_FLAGS)
        },
        "noNewPrivileges": {"const": True},
        "closeRangeFrom": {"const": 3},
        "preserveFds": INTEGER_ARRAY_JSON_SCHEMA,
    }
)
LAUNCH_REQUEST_JSON_SCHEMA = _closed_schema(
    {
        "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
        "validFrom": TIMESTAMP_JSON_SCHEMA,
        "validUntil": TIMESTAMP_JSON_SCHEMA,
        "identityIssuerKeyId": STRING_JSON_SCHEMA,
        "identityIssuerAuthorizationDigest": SHA256_JSON_SCHEMA,
        "privateKeyTargetFd": INTEGER_JSON_SCHEMA,
        "certificateTargetFd": INTEGER_JSON_SCHEMA,
    }
)
STAGE_ZERO_REQUEST_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": STAGE_ZERO_REQUEST_SCHEMA},
        "generation": GENERATION_BINDING_JSON_SCHEMA,
        "role": ROLE_BINDING_JSON_SCHEMA,
        "stageZero": STAGE_ZERO_BINDING_JSON_SCHEMA,
        "operationManifest": OPERATION_MANIFEST_BINDING_JSON_SCHEMA,
        "retainedDirectories": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_RETAINED_DIRECTORIES,
            "items": RETAINED_DIRECTORY_JSON_SCHEMA,
        },
        "retainedFiles": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_RETAINED_FILES,
            "items": RETAINED_FILE_JSON_SCHEMA,
        },
        "listener": LISTENER_JSON_SCHEMA,
        "bootstrapControl": BOOTSTRAP_CONTROL_JSON_SCHEMA,
        "credentials": {
            "type": "array",
            "maxItems": MAX_CREDENTIALS,
            "items": CREDENTIAL_JSON_SCHEMA,
        },
        "mutableStateDescriptors": {
            "type": "array",
            "maxItems": MAX_MUTABLE_STATE_DESCRIPTORS,
            "items": MUTABLE_STATE_DESCRIPTOR_JSON_SCHEMA,
        },
        "process": PROCESS_IDENTITY_JSON_SCHEMA,
        "hostEvidence": HOST_EVIDENCE_JSON_SCHEMA,
        "environment": ENVIRONMENT_JSON_SCHEMA,
        "execution": EXECUTION_JSON_SCHEMA,
        "launch": LAUNCH_REQUEST_JSON_SCHEMA,
        "trustMode": {"enum": sorted(TRUST_MODES)},
    }
)
LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": LAUNCH_IDENTITY_PAYLOAD_SCHEMA},
        "launchId": SHA256_JSON_SCHEMA,
        "generationSequence": INTEGER_JSON_SCHEMA,
        "generationDigest": SHA256_JSON_SCHEMA,
        "packageDigest": SHA256_JSON_SCHEMA,
        "predecessorDigest": NULLABLE_SHA256_JSON_SCHEMA,
        "artifactBundleDigest": SHA256_JSON_SCHEMA,
        "operationManifestDigest": SHA256_JSON_SCHEMA,
        "stageZeroDigest": SHA256_JSON_SCHEMA,
        "stageZeroContract": STRING_JSON_SCHEMA,
        "roleSetDigest": SHA256_JSON_SCHEMA,
        "keyAuthorizationsDigest": SHA256_JSON_SCHEMA,
        "keyRevocationsDigest": SHA256_JSON_SCHEMA,
        "witnessCheckpointDigest": SHA256_JSON_SCHEMA,
        "role": STRING_JSON_SCHEMA,
        "roleManifestDigest": SHA256_JSON_SCHEMA,
        "processMode": STRING_JSON_SCHEMA,
        "runtimeUid": INTEGER_JSON_SCHEMA,
        "runtimeGid": INTEGER_JSON_SCHEMA,
        "supplementaryGids": INTEGER_ARRAY_JSON_SCHEMA,
        "bootIdDigest": SHA256_JSON_SCHEMA,
        "kernelReleaseDigest": SHA256_JSON_SCHEMA,
        "kernelCommandLineDigest": SHA256_JSON_SCHEMA,
        "vdsoDigest": SHA256_JSON_SCHEMA,
        "listenerIdentityDigest": SHA256_JSON_SCHEMA,
        "credentialSetDigest": SHA256_JSON_SCHEMA,
        "mutableStateSetDigest": SHA256_JSON_SCHEMA,
        "processId": INTEGER_JSON_SCHEMA,
        "processStartTicks": INTEGER_JSON_SCHEMA,
        "pidfdIdentityDigest": SHA256_JSON_SCHEMA,
        "executableDigest": SHA256_JSON_SCHEMA,
        "argvDigest": SHA256_JSON_SCHEMA,
        "environmentDigest": SHA256_JSON_SCHEMA,
        "cwdDigest": SHA256_JSON_SCHEMA,
        "requestDigest": SHA256_JSON_SCHEMA,
        "publicKeyAlgorithm": {"const": "Ed25519"},
        "launchPublicKeyBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{43}$",
        },
        "issuedAt": TIMESTAMP_JSON_SCHEMA,
        "expiresAt": TIMESTAMP_JSON_SCHEMA,
        "trustMode": {"enum": sorted(TRUST_MODES)},
        "coLocated": {"type": "boolean"},
        "hardwareBacked": {"type": "boolean"},
    }
)
SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": SIGNED_LAUNCH_IDENTITY_SCHEMA},
        "payload": LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA,
        "issuerKeyId": STRING_JSON_SCHEMA,
        "algorithm": {"const": "Ed25519"},
        "signatureBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{86}$",
        },
    }
)
PRIVATE_KEY_DESCRIPTOR_JSON_SCHEMA = _closed_schema(
    {
        "fd": INTEGER_JSON_SCHEMA,
        "size": {"const": 32},
        "seals": INTEGER_JSON_SCHEMA,
        "delivery": {"const": "retained-sealed-memfd"},
        "purpose": {"const": "launch-identity-private-key"},
        "publicKeyDigest": SHA256_JSON_SCHEMA,
    }
)
CERTIFICATE_DESCRIPTOR_JSON_SCHEMA = _closed_schema(
    {
        "fd": INTEGER_JSON_SCHEMA,
        "size": INTEGER_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "seals": INTEGER_JSON_SCHEMA,
        "delivery": {"const": "retained-sealed-memfd"},
    }
)
STAGE_ZERO_HANDOFF_JSON_SCHEMA = _closed_schema(
    {
        "schema": {"const": STAGE_ZERO_HANDOFF_SCHEMA},
        "requestDigest": SHA256_JSON_SCHEMA,
        "launchIdentity": SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA,
        "launchPrivateKey": PRIVATE_KEY_DESCRIPTOR_JSON_SCHEMA,
        "certificateDescriptor": CERTIFICATE_DESCRIPTOR_JSON_SCHEMA,
        "identityFdDigest": SHA256_JSON_SCHEMA,
        "execveat": _closed_schema(
            {
                "executableFd": INTEGER_JSON_SCHEMA,
                "pathname": {"const": ""},
                "flags": {"const": list(REQUIRED_EXECVEAT_FLAGS)},
                "argvDigest": SHA256_JSON_SCHEMA,
                "environmentDigest": SHA256_JSON_SCHEMA,
                "cwdDigest": SHA256_JSON_SCHEMA,
                "identityFdDigest": SHA256_JSON_SCHEMA,
                "preservedFds": INTEGER_ARRAY_JSON_SCHEMA,
            }
        ),
    }
)


__all__ = [
    "STAGE_ZERO_REQUEST_SCHEMA",
    "LAUNCH_IDENTITY_PAYLOAD_SCHEMA",
    "SIGNED_LAUNCH_IDENTITY_SCHEMA",
    "STAGE_ZERO_HANDOFF_SCHEMA",
    "STAGE_ZERO_INTERFACE_SCHEMA",
    "BOOTSTRAP_CONTROL_NAME",
    "BOOTSTRAP_CONTROL_ENVELOPE_SCHEMA",
    "MAX_BOOTSTRAP_CONTROL_BYTES",
    "NATIVE_STAGE_ZERO_REQUIREMENTS",
    "StageZeroContractError",
    "STAGE_ZERO_REQUEST_JSON_SCHEMA",
    "BOOTSTRAP_CONTROL_JSON_SCHEMA",
    "LAUNCH_IDENTITY_PAYLOAD_JSON_SCHEMA",
    "SIGNED_LAUNCH_IDENTITY_JSON_SCHEMA",
    "STAGE_ZERO_HANDOFF_JSON_SCHEMA",
    "argument_vector_digest",
    "credential_set_digest",
    "derive_launch_id",
    "environment_digest",
    "identity_fd_digest",
    "launch_certificate_signature_message",
    "listener_identity_digest",
    "mutable_state_set_digest",
    "pidfd_identity_digest",
    "stage_zero_request_digest",
    "validate_launch_identity_payload",
    "validate_signed_launch_identity",
    "validate_stage_zero_handoff",
    "validate_stage_zero_request",
    "working_directory_digest",
]
