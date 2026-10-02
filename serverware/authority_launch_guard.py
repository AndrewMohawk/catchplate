from __future__ import annotations

import errno
import fcntl
import os
import stat
from copy import deepcopy
from types import MappingProxyType
from typing import Any, Mapping


_active_role: str | None = None
_manifest_digest: str | None = None
_retained_descriptors: frozenset[int] = frozenset()
_bootstrap_control_identity: tuple = ()
_runtime_evidence_identity: tuple | None = None
_RUNTIME_EVIDENCE_ROLES = frozenset(
    {"verifier", "planner", "planner-writer", "issuer", "executor"}
)
_package_versions: Mapping[str, str] = MappingProxyType({})
_generation: Mapping[str, Any] = MappingProxyType({})
_native_stage_zero_handoff: Mapping[str, Any] = MappingProxyType({})
_listener_descriptor: int | None = None
_launch_identity_descriptors: Mapping[str, int] = MappingProxyType({})
_mutable_state_descriptors: Mapping[str, Mapping[str, Any]] = (
    MappingProxyType({})
)
_stage_zero_request: Mapping[str, Any] = MappingProxyType({})
_verified_artifact_package: Any | None = None
_artifact_package: Mapping[str, Any] = MappingProxyType({})
_artifact_trust_state: Mapping[str, Any] = MappingProxyType({})
_launch_assurance: Mapping[str, Any] = MappingProxyType({})
LOCAL_RUNTIME_DESCRIPTOR_POLICY_SCHEMA = "serverware.trustedHostLocalPostSealDescriptorPolicy/v1"
# Existing launcher bounds: originals + one sealed copy per closure entry,
# retained directories, and fixed runtime listener/control/credential handles.
MAX_LOCAL_RUNTIME_DESCRIPTORS = 2 * 32768 + 64 + 16
_local_runtime_observation: tuple | None = None


def _require_bootstrap_control_identity(identity: tuple) -> None:
    """Recheck immutable custody of already root-verified original control bytes."""
    if (
        type(identity) is not tuple or len(identity) != 10
        or any(type(value) is not int or value < 0 for value in identity[:9])
        or not 3 <= identity[0] <= 2**31 - 1
        or type(identity[9]) is not str or len(identity[9]) != 71
        or not identity[9].startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in identity[9][7:])
    ):
        raise RuntimeError("authority bootstrap control observation is invalid")
    descriptor = identity[0]
    if (
        os.environ.get("SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD") != str(descriptor)
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_PATH")
    ):
        raise RuntimeError("authority bootstrap control environment changed")
    try:
        metadata = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise RuntimeError("authority bootstrap control descriptor is unavailable") from exc
    required_seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    actual = (
        descriptor, metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )
    if (
        actual != identity[:9] or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0 or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 2 <= metadata.st_size <= 64 * 1024 * 1024
        or seals & required_seals != required_seals
    ):
        raise RuntimeError("authority bootstrap control custody changed")


def _require_runtime_evidence_identity(identity: tuple) -> None:
    """Check custody only; actual receipt verification belongs to the service."""
    if (
        type(identity) is not tuple or len(identity) != 10
        or any(type(value) is not int or value < 0 for value in identity[:9])
        or not 3 <= identity[0] <= 2**31 - 1
        or type(identity[9]) is not str or len(identity[9]) != 71
        or not identity[9].startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in identity[9][7:])
    ):
        raise RuntimeError("authority runtime evidence observation is invalid")
    descriptor = identity[0]
    if (
        os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD") != str(descriptor)
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_PATH")
    ):
        raise RuntimeError("authority runtime evidence environment changed")
    try:
        metadata = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise RuntimeError("authority runtime evidence descriptor is unavailable") from exc
    required_seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    actual = (
        descriptor, metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )
    if (
        actual != identity[:9] or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0 or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not 2 <= metadata.st_size <= 4 * 1024 * 1024
        or seals & required_seals != required_seals
    ):
        raise RuntimeError("authority runtime evidence custody changed")


def activate(
    *,
    role: str,
    manifest_digest: str,
    retained_descriptors: frozenset[int],
    bootstrap_control_identity: tuple,
    runtime_evidence_identity: tuple | None,
    package_versions: Mapping[str, str],
    generation: Mapping[str, Any],
    native_stage_zero_handoff: Mapping[str, Any],
    listener_descriptor: int,
    launch_identity_descriptors: Mapping[str, int],
    mutable_state_descriptors: Mapping[str, Mapping[str, Any]],
    stage_zero_request: Mapping[str, Any],
    verified_artifact_package: Any,
    artifact_package: Mapping[str, Any],
    artifact_trust_state: Mapping[str, Any],
    launch_assurance: Mapping[str, Any],
) -> None:
    global _active_role
    global _manifest_digest
    global _retained_descriptors
    global _bootstrap_control_identity
    global _runtime_evidence_identity
    global _package_versions
    global _generation
    global _native_stage_zero_handoff
    global _listener_descriptor
    global _launch_identity_descriptors
    global _mutable_state_descriptors
    global _stage_zero_request
    global _verified_artifact_package
    global _artifact_package
    global _artifact_trust_state
    global _launch_assurance
    local_assurance = {
        "schema": "serverware.authorityLaunchAssurance/v1",
        "trustMode": "trusted-host-local",
        "coLocated": True,
        "hardwareBacked": False,
        "nativeStageZero": False,
        "hsmBackedKeys": False,
        "teeVerified": False,
        "externalWitnessVerified": False,
    }
    if (
        _active_role is not None
        or not role
        or not manifest_digest.startswith("sha256:")
        or not retained_descriptors
        or any(descriptor < 3 for descriptor in retained_descriptors)
        or not isinstance(generation, Mapping)
        or not generation
        or not isinstance(native_stage_zero_handoff, Mapping)
        or listener_descriptor < 3
        or listener_descriptor not in retained_descriptors
        or set(launch_identity_descriptors)
        != {"privateKey", "certificate"}
        or any(
            not isinstance(descriptor, int)
            or isinstance(descriptor, bool)
            or descriptor < 3
            or descriptor not in retained_descriptors
            for descriptor in launch_identity_descriptors.values()
        )
        or not isinstance(mutable_state_descriptors, Mapping)
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, Mapping)
            or value.get("fd") not in retained_descriptors
            for name, value in mutable_state_descriptors.items()
        )
        or not isinstance(stage_zero_request, Mapping)
        or not stage_zero_request
        or verified_artifact_package is None
        or not isinstance(artifact_package, Mapping)
        or not artifact_package
        or not isinstance(artifact_trust_state, Mapping)
        or not artifact_trust_state
        or not isinstance(launch_assurance, Mapping)
        or (
            dict(launch_assurance) != local_assurance
            and (
                launch_assurance.get("schema")
                    != "serverware.authorityLaunchAssurance/v1"
                or launch_assurance.get("trustMode")
                    not in {"external-production", "tee-hardware"}
                or launch_assurance.get("nativeStageZero") is not True
            )
        )
        or (
            dict(launch_assurance) == local_assurance
            and native_stage_zero_handoff
        )
        or (
            dict(launch_assurance) != local_assurance
            and not native_stage_zero_handoff
        )
    ):
        raise RuntimeError("authority measured launch activation is invalid")
    _require_bootstrap_control_identity(bootstrap_control_identity)
    control = stage_zero_request.get("bootstrapControl")
    if (
        not isinstance(control, Mapping)
        or set(control) != {"name", "fd", "envelopeSchema", "maximumBytes"}
        or control["name"] != "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
        or type(control["fd"]) is not int
        or control["fd"] != bootstrap_control_identity[0]
        or control["envelopeSchema"] != "serverware.signedPolicyAuthorityLaunchManifest/v7"
        or type(control["maximumBytes"]) is not int
        or control["maximumBytes"] != 64 * 1024 * 1024
        or control["fd"] not in retained_descriptors
    ):
        raise RuntimeError("authority bootstrap control is not the admitted request descriptor")
    if "runtimeEvidence" not in stage_zero_request:
        raise RuntimeError("authority runtime evidence declaration is missing")
    evidence_slot = stage_zero_request["runtimeEvidence"]
    if role in _RUNTIME_EVIDENCE_ROLES:
        _require_runtime_evidence_identity(runtime_evidence_identity)
        if (
            not isinstance(evidence_slot, Mapping)
            or set(evidence_slot) != {"name", "fd", "purpose", "maximumBytes"}
            or evidence_slot["name"] != "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD"
            or type(evidence_slot["fd"]) is not int
            or evidence_slot["fd"] != runtime_evidence_identity[0]
            or evidence_slot["purpose"] != "authority-attestation"
            or type(evidence_slot["maximumBytes"]) is not int
            or evidence_slot["maximumBytes"] != 4 * 1024 * 1024
            or evidence_slot["fd"] not in retained_descriptors
        ):
            raise RuntimeError("authority runtime evidence is not the admitted request descriptor")
    elif (
        runtime_evidence_identity is not None or evidence_slot is not None
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD")
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_ATTESTATION_PATH")
    ):
        raise RuntimeError("authority runtime evidence is not permitted for this role")
    other_descriptors = {
        listener_descriptor,
        *launch_identity_descriptors.values(),
        *(value["fd"] for value in mutable_state_descriptors.values()),
        stage_zero_request["stageZero"]["fd"],
        stage_zero_request["process"]["pidfd"]["fd"],
        *(value["fd"] for value in stage_zero_request["retainedFiles"]),
        *(value["fd"] for value in stage_zero_request["retainedDirectories"]),
        *(value["fd"] for value in stage_zero_request["credentials"]),
    }
    if control["fd"] in other_descriptors:
        raise RuntimeError("authority bootstrap control aliases another descriptor")
    if runtime_evidence_identity is not None and (
        runtime_evidence_identity[0] == control["fd"]
        or runtime_evidence_identity[0] in other_descriptors
    ):
        raise RuntimeError("authority runtime evidence aliases another descriptor")
    # Non-preserved stage-zero declarations still participate in numeric
    # collision rejection, but may already be closed in this process.
    inherited_descriptors = {
        *stage_zero_request["execution"]["preserveFds"],
        listener_descriptor,
        *launch_identity_descriptors.values(),
        *(value["fd"] for value in stage_zero_request["credentials"]),
    }
    inherited_descriptors.discard(control["fd"])
    if runtime_evidence_identity is not None:
        inherited_descriptors.add(runtime_evidence_identity[0])
    for descriptor in inherited_descriptors:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == bootstrap_control_identity[1:3]:
            raise RuntimeError("authority bootstrap control inode aliases another descriptor")
    if runtime_evidence_identity is not None:
        evidence_others = inherited_descriptors - {runtime_evidence_identity[0]}
        evidence_others.add(control["fd"])
        for descriptor in evidence_others:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == runtime_evidence_identity[1:3]:
                raise RuntimeError("authority runtime evidence inode aliases another descriptor")
    _active_role = role
    _manifest_digest = manifest_digest
    _retained_descriptors = retained_descriptors
    # The raw SHA is an observation after root verification, not a declaration
    # accepted from the signed request. Seals and the exact stamp protect it.
    _bootstrap_control_identity = bootstrap_control_identity
    _runtime_evidence_identity = runtime_evidence_identity
    _package_versions = MappingProxyType(dict(package_versions))
    _generation = MappingProxyType(deepcopy(dict(generation)))
    _native_stage_zero_handoff = MappingProxyType(
        deepcopy(dict(native_stage_zero_handoff))
    )
    _listener_descriptor = listener_descriptor
    _launch_identity_descriptors = MappingProxyType(
        dict(launch_identity_descriptors)
    )
    _mutable_state_descriptors = MappingProxyType(
        {
            str(name): MappingProxyType(deepcopy(dict(value)))
            for name, value in mutable_state_descriptors.items()
        }
    )
    _stage_zero_request = MappingProxyType(
        deepcopy(dict(stage_zero_request))
    )
    _verified_artifact_package = verified_artifact_package
    _artifact_package = MappingProxyType(
        deepcopy(dict(artifact_package))
    )
    _artifact_trust_state = MappingProxyType(
        deepcopy(dict(artifact_trust_state))
    )
    _launch_assurance = MappingProxyType(
        deepcopy(dict(launch_assurance))
    )


def require_active(role: str) -> str:
    if _active_role != role or _manifest_digest is None:
        raise RuntimeError(
            "authority service was not entered by the measured launcher"
        )
    _require_bootstrap_control_identity(_bootstrap_control_identity)
    if role in _RUNTIME_EVIDENCE_ROLES:
        _require_runtime_evidence_identity(_runtime_evidence_identity)
    return _manifest_digest


def runtime_evidence_identity(role: str) -> tuple:
    require_active(role)
    if role not in _RUNTIME_EVIDENCE_ROLES or _runtime_evidence_identity is None:
        raise RuntimeError("authority role has no runtime evidence descriptor")
    return _runtime_evidence_identity


def retained_descriptors() -> frozenset[int]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _retained_descriptors


def _local_open_descriptors() -> frozenset[int]:
    result = set()
    for name in os.listdir("/proc/self/fd"):
        if not name.isdecimal() or int(name) < 3:
            continue
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
            continue  # The listdir handle itself has already closed.
        result.add(descriptor)
    return frozenset(result)


def _local_descriptor_identities(descriptors: frozenset[int]) -> tuple:
    if (type(descriptors) is not frozenset or not 1 <= len(descriptors) <= MAX_LOCAL_RUNTIME_DESCRIPTORS
            or any(type(fd) is not int or not 3 <= fd < 2**31 for fd in descriptors)):
        raise RuntimeError("local runtime descriptor roster is invalid")
    identities = []
    for descriptor in sorted(descriptors):
        info = os.fstat(descriptor)
        try:
            seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        except OSError as error:
            if error.errno not in {errno.EINVAL, errno.ENOTTY}:
                raise
            seals = None
        stable = (descriptor, info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        # Directory nlink/timestamps are not identities (e.g. procfs churn).
        content = () if stat.S_ISDIR(info.st_mode) else (
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        identities.append((*stable, content, seals, fcntl.fcntl(descriptor, fcntl.F_GETFD),
                           fcntl.fcntl(descriptor, fcntl.F_GETFL)))
    return tuple(identities)


def observe_local_runtime_descriptors() -> None:
    """Called once by the measured launcher after sealing and transport close.

    There is no caller-supplied roster or admission DTO. Native launches do not
    select this path. The root-signed v2 trust chooses whether its consumer may
    use this exact same-process observation instead of prospective FD numbers.
    """
    global _local_runtime_observation
    manifest = require_active("runtime")
    if (_local_runtime_observation is not None
            or _launch_assurance.get("trustMode") != "trusted-host-local"
            or _launch_assurance.get("nativeStageZero") is not False
            or _stage_zero_request.get("schema") != "serverware.authorityTrustedHostLocalBootstrapRequest/v1"
            or _stage_zero_request.get("process", {}).get("processId") != os.getpid()
            or _local_open_descriptors() != _retained_descriptors):
        raise RuntimeError("local post-seal runtime observation refused")
    identities = _local_descriptor_identities(_retained_descriptors)
    if _local_open_descriptors() != _retained_descriptors:
        raise RuntimeError("local runtime descriptors changed during observation")
    _local_runtime_observation = (os.getpid(), manifest, identities)


def local_runtime_descriptors(policy: Mapping[str, Any], *, configuration_digest: str) -> frozenset[int]:
    """Join root-signed policy to the actual admitted post-seal owner only."""
    manifest = require_active("runtime")
    fields = {"schema", "role", "roleBindingDigest", "generationBindingDigest", "generationDigest", "artifactPackageDigest"}
    if (not isinstance(policy, Mapping) or set(policy) != fields
            or policy.get("schema") != LOCAL_RUNTIME_DESCRIPTOR_POLICY_SCHEMA or policy.get("role") != "runtime"
            or _local_runtime_observation is None or _local_runtime_observation[:2] != (os.getpid(), manifest)
            or _launch_assurance.get("trustMode") != "trusted-host-local" or _launch_assurance.get("nativeStageZero") is not False
            or _generation.get("schema") != "serverware.authorityGenerationLaunchContext/v4"
            or policy.get("roleBindingDigest") != _generation.get("roleBindingDigests", {}).get("runtime")
            or policy.get("generationBindingDigest") != _generation.get("configurationBindingDigest")
            or policy.get("generationDigest") != _generation.get("digest")
            or policy.get("artifactPackageDigest") != _generation.get("packageDigest")
            or not any(row.get("role") == "authority-service" and row.get("payloadDigest") == configuration_digest
                and row.get("fileDigest") in _generation.get("configurationDigests", ())
                for row in _generation.get("configurationPayloadBindings", ()))
            or _local_open_descriptors() != _retained_descriptors
            or _local_descriptor_identities(_retained_descriptors) != _local_runtime_observation[2]):
        raise RuntimeError("local runtime post-seal descriptor admission changed")
    return _retained_descriptors


def package_versions() -> Mapping[str, str]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _package_versions


def generation() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_generation)))


def native_stage_zero_handoff() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(
        deepcopy(dict(_native_stage_zero_handoff))
    )


def listener_descriptor() -> int:
    if _active_role is None or _listener_descriptor is None:
        raise RuntimeError("authority measured launch is inactive")
    return _listener_descriptor


def launch_identity_descriptors() -> Mapping[str, int]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _launch_identity_descriptors


def mutable_state_descriptors() -> Mapping[str, Mapping[str, Any]]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(
        {
            name: MappingProxyType(deepcopy(dict(value)))
            for name, value in _mutable_state_descriptors.items()
        }
    )


def stage_zero_request() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_stage_zero_request)))


def verified_artifact_package() -> Any:
    if _active_role is None or _verified_artifact_package is None:
        raise RuntimeError("authority measured launch is inactive")
    return _verified_artifact_package


def artifact_package() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_artifact_package)))


def artifact_trust_state() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_artifact_trust_state)))


def launch_assurance() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_launch_assurance)))
