#!/usr/bin/env python3
"""Fixed offline pilot build preparation and artifact assembly, never launch.

Uses the production source/cache/context owner. Public guest closure originals
come from an independent operator. No authority, key, process identity, grant,
service readiness, or installation authorization is produced here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import build_production_images as build
import native_pilot_runtime_artifacts as conductor_runtime
import package_native_pilot_runtime as conductor_package
import native_pilot_tar_export as runtime_tar

DOCKERFILE = "data-plane/decision-gate-rs/Dockerfile.production"
PROFILES = {
    "nativeStartup": "serverware.nativeStartupConfiguration/v22",
    "nativeStartupSelector": "--native-workload-trust-startup-v22",
    "nativeEnclaveSelector": "--workload-trust-v22",
    "nativeWorkloadTrust": "serverware.nativeWorkloadIdentityTrustAuthorization/v1",
    "cohort": "serverware.nativeShadowProofCohortConfiguration/v7",
    "cohortRoles": ["retrieval", "persistence", "trustedTime", "generationInstall",
                    "commitRequest", "ingressAdmission", "terminalAppend", "dispatchBarrier",
                    "activeEffectBarrier", "activeEffectCommit"],
    "externalBridge": "serverware.nativeShadowDriverBootstrapConfiguration/v4",
    "bridgeLaunch": "serverware.nativeProofBridgeLaunch/v5",
    "bridgeRuntime": "serverware.policyCustodyProductionRpcRuntime/v9",
    "spool": "serverware.nativeSpoolServices/v3",
    "ordinaryLaunch": "serverware.custodyFiveServiceLaunch/v6",
    "ordinaryEffectsRuntime": "serverware.policyCustodyServiceRuntimeConfig/v8",
    "ordinaryEffectsSelector": "--guest-c9-effects-inspected",
}
ORDINARY_ROLES = ("durable-recovery-store", "recovery-target-provider", "current-signature-authority",
                  "cleanup-authorization-consumer", "bounded-cleanup-helper")
NATIVE_FILES = {
    "usr/local/bin/serverware-policy-shadow-custody-guest": (0o555, 64 * 1024 * 1024),
    "opt/serverware/serverware-native-shadow-proof-cohort": (0o555, 64 * 1024 * 1024),
    "opt/serverware/serverware-native-shadow-guest-supervisor": (0o555, 64 * 1024 * 1024),
    "opt/serverware/serverware-native-activation-relay": (0o555, 64 * 1024 * 1024),
    "opt/serverware/serverware-native-publication-genesis-controller": (0o555, 64 * 1024 * 1024),
    "opt/serverware/serverware-native-publication-adoption-validator": (0o555, 64 * 1024 * 1024),
    "usr/local/bin/serverware-native-shadow-worker": (0o555, 64 * 1024 * 1024),
    "usr/local/bin/serverware-native-publication-handoff": (0o555, 64 * 1024 * 1024),
    "opt/serverware/native-shadow-custody-runtime.squashfs": (0o444, 256 * 1024 * 1024),
    "usr/share/serverware/native-shadow-custody-runtime.json": (0o444, 4 * 1024 * 1024),
}
OPERATOR_FILE = "usr/local/bin/serverware-export-custody-seccomp"
OPERATOR_MAX_BYTES = 64 * 1024 * 1024
SIDECAR_BINARY = "usr/local/libexec/serverware-workload-sidecar"
SIDECAR_FILES = {
    SIDECAR_BINARY: (0o555, 64 * 1024 * 1024, None),
    "usr/share/serverware/install_workload_sidecar_unit.py":
        (0o444, 128 * 1024, "scripts/install_workload_sidecar_unit.py"),
    "usr/share/serverware/native-workload-sidecar.v1.schema.json":
        (0o444, 64 * 1024, "schemas/native-workload-sidecar.v1.schema.json"),
}


def preparation(metadata):
    return {
        "apiVersion": "serverware.nativePilotBuildPreparation/v1",
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
        "source": {key: metadata[key] for key in ("revision", "source_tree_digest", "source_manifest_digest",
                                                   "source_archive_digest", "source_date_epoch")},
        "profiles": PROFILES,
        "buildResourceProfile": build.native_pilot_build_resource_profile(metadata),
        "publicGuestBuildInputs": {
            "apiVersion": "serverware.nativeShadowCustodyImageInputs/v1",
            "sourceManifestSha256": metadata["source_manifest_digest"],
            "files": ["inputs.json", *build.PUBLIC_GUEST_FILES],
            "independentManifestSha256Required": True,
        },
        "requiredExternalOriginals": [
            "Public guest seccomp/runtime/build-recipe/provenance originals and their independently pinned manifest",
            "Protected endpoint cohort control/configuration-v7 and original precreation window; ten distinct actual child assignments plus the independently pinned retained DriverBootstrap bridge",
            "Protected custody-effects-five.json v6, five C9 configurations, service credentials and signed authority histories",
            "Driver bootstrap/configuration/window, actual post-drop measurement, independently signed phase-two scope and constructed admission",
            "Actual gate native startup-v22/lifecycle/receiving configuration, separately pinned independent native workload-trust grant, signed policy, assignment, compiler and canary inventory",
            "Exact head-v3/current-v3/cleanup-v1 grants, generation grants, encrypted independently assigned native keys and KMS context pins",
            "Independent trust/revocation/checkpoint/time/verifier/generation-origin authorities and their original transport/key custody",
            "Actual listeners, persistent fs-verity-capable stores, held locks, cgroups, IMA/LSM identities, UID separation and PIDFD support",
            "Control-plane database/OIDC/WebAuthn/protected-authority configuration and operator two-person approvals",
            "Independent Setup hardware/proxy/final issuer artifacts, protected configurations and sealed key delivery",
            "Independent admission/installation of the conductor runtime package, separately operated authority coordinator, exclusive stdin/stdout pipes and provisioned live services",
            "Independently authorized commissioning policy and automated supervisor; the coordinator and approval installer do not implement that decision service",
        ],
        "existingOwners": {
            "operatorConductor": "python3 -B scripts/run_native_pilot.py --run-native-pilot",
            "packagedOperatorConductor": "/runtime/python/bin/python3 -I -B /app/scripts/native_pilot_runtime_entrypoint.py --run-native-pilot",
            "operatorChannel": "serverware.native_pilot_operator_channel.Channel: exclusive machine pipes, canonical request/reply originals, original absolute deadlines, no authority or retries",
            "operatorPhases": "bootstrap-admission / endpoint-precreation / endpoint-inputs / endpoint-deliveries / service-originals / bridge-runtime / bridge-delivery / release / constructed-admission / generation-origin / shutdown",
            "liveComposition": "serverware.native_pilot_launch.NativePilotLaunch.start / start_endpoints / prepare_resources / prepare_bridge_connections / prepare_operational_inputs / release",
            "nativeCohort": "serverware.native_shadow_proof_cohort_control.ParkedProofCohort.start_for_driver",
            "ordinaryFive": "serverware.custody_generation_launch.FiveServiceLaunch.start_effects",
            "generationInputs": "serverware.custody_generation_business.BusinessResources.prepare_commitment(five).commitment_inputs()",
            "spoolResources": "serverware.native_shadow_spool_inputs.SpoolInputs.prepare",
            "driver": "serverware.native_shadow_driver_bootstrap.DriverBootstrap.start",
            "outgoingAndContinuation": "serverware.native_shadow_driver_outgoing.OutgoingResources.prepare / serverware.native_shadow_driver_resources.BridgeResources.prepare_native_peers / serverware.native_shadow_driver_inputs.OperationalInputs.prepare_pilot",
            "orderedRelease": "serverware.custody_generation_launch.FiveServiceLaunch.release_endpoint_cohort / ParkedProofCohort.continue_driver",
        },
        "boundary": "Preparation is build data only. Actual live owners must measure, admit, sign independently, retain and release under original deadlines; no launch is performed. The separate conductor-runtime command packages the Python operator rootfs, not its independent authority coordinator or service configuration. Independent admission, installation and provisioned live services remain required.",
    }


def read_original(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RuntimeError("expected a bounded regular build original")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise RuntimeError("build original changed during read")
        return raw
    finally:
        os.close(descriptor)


def write_bytes(path, data):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_original(path, value, *, terminal_lf=False):
    data = build.canonical_json(value).encode("ascii") + (b"\n" if terminal_lf else b"")
    write_bytes(path, data)


def new_output(path):
    if (not path.is_absolute() or path.parent.resolve() != path.parent
            or not path.parent.is_dir() or path == Path("/") or "," in str(path)):
        raise RuntimeError("output requires an absolute new directory under an existing non-symlink parent; commas are forbidden")
    # No overwrite, recovery, cleanup, recursive deletion or automatic retry.
    path.mkdir(mode=0o700)
    return path


def package_public_inputs(args, metadata, plan):
    paths = {
        "seccomp.bpf": args.seccomp,
        "runtime.json": args.runtime,
        "build-recipe.json": args.build_recipe,
        "provenance.json": args.provenance,
    }
    for path in (args.preparation, *paths.values()):
        if not path.is_absolute() or path.parent.resolve() != path.parent:
            raise RuntimeError("public input originals require absolute paths without symlink ancestors")
    if read_original(args.preparation, 128 * 1024) != build.canonical_json(plan).encode("ascii"):
        raise RuntimeError("preparation must be the exact fixed profile for this clean source snapshot")
    originals = {
        name: read_original(paths[name], maximum)
        for name, (_, maximum) in build.PUBLIC_GUEST_FILES.items()
    }
    if len(originals["seccomp.bpf"]) % 8:
        raise RuntimeError("seccomp artifact is not exact classic-BPF instructions")
    # The existing custody packager treats the other three originals as opaque
    # pinned bytes. Copying/hashing them is not runtime or provenance admission.
    manifest = {
        "apiVersion": "serverware.nativeShadowCustodyImageInputs/v1",
        "sourceManifestSha256": metadata["source_manifest_digest"],
        **{field: "sha256:" + hashlib.sha256(originals[name]).hexdigest()
           for name, (field, _) in build.PUBLIC_GUEST_FILES.items()},
    }
    output = new_output(args.out)
    for name, raw in originals.items():
        write_bytes(output / name, raw)
    # Only these five files belong in the existing packager's input directory.
    # The manifest is last; partial output is retained, never repaired/retried.
    write_original(output / "inputs.json", manifest, terminal_lf=True)
    manifest_raw = read_original(output / "inputs.json", 16384)
    if manifest_raw != (build.canonical_json(manifest) + "\n").encode("ascii"):
        raise RuntimeError("written public input manifest differs from its exact original")
    return {
        "measuredPublicInputsSha256": "sha256:" + hashlib.sha256(manifest_raw).hexdigest(),
        "independentPinAuthenticated": False,
        "independentPinAuthenticationRequired": True,
        "boundary": "Locally measured bytes only. Obtain independent authentication of this exact manifest pin before build admission; no policy, provenance, signature or release authority is created.",
    }


def native_inventory(output):
    root = output / "artifacts" / "native-install"
    entries = {}
    for relative, (mode, maximum) in NATIVE_FILES.items():
        path = root / relative
        if path.parent.resolve() != path.parent:
            raise RuntimeError("native artifact parent is a symlink")
        raw = read_original(path, maximum)
        if stat.S_IMODE(path.lstat().st_mode) != mode:
            raise RuntimeError("native artifact mode differs from fixed Docker target")
        entries[relative] = {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": format(mode, "04o")}
    manifest = json.loads(read_original(root / "usr/share/serverware/native-shadow-custody-runtime.json", 4 * 1024 * 1024))
    if (manifest.get("apiVersion") != "serverware.nativeShadowCustodyRuntimeBuild/v1"
            or manifest.get("releaseAuthority") is not False
            or manifest.get("imageSha256") != entries["opt/serverware/native-shadow-custody-runtime.squashfs"]["sha256"]
            or manifest.get("workerExecutableSha256") != entries["usr/local/bin/serverware-policy-shadow-custody-guest"]["sha256"]):
        raise RuntimeError("actual guest package manifest differs from exported artifacts")
    return entries, manifest


def operator_inventory(output):
    root = output / "artifacts"
    # Only the fixed export tree is admitted. Each enumeration stops at the
    # first extra entry; this is not a recursive artifact-directory scan.
    directories = {
        "": {"usr"}, "usr": {"local"}, "usr/local": {"bin"},
        "usr/local/bin": {"serverware-export-custody-seccomp"},
    }
    for relative, expected in directories.items():
        directory = root / relative
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.resolve() != directory:
            raise RuntimeError("operator artifact directory must be an actual non-symlink directory")
        names = set()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name not in expected or entry.name in names:
                    raise RuntimeError("operator export contains an unexpected artifact")
                names.add(entry.name)
        if names != expected:
            raise RuntimeError("operator export is missing its fixed artifact")
    path = root / OPERATOR_FILE
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o555 or before.st_nlink != 1:
        raise RuntimeError("operator executable type, mode or link count differs from the fixed target")
    raw = read_original(path, OPERATOR_MAX_BYTES)
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise RuntimeError("operator executable changed during inventory")
    if (len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(raw[16:18], "little") not in (2, 3)
            or int.from_bytes(raw[18:20], "little") != 62):
        raise RuntimeError("operator executable is not the fixed Linux/amd64 ELF artifact")
    return {OPERATOR_FILE: {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                            "bytes": len(raw), "mode": "0555"}}


def sidecar_inventory(output, metadata):
    """Inventory only the fixed workload artifact, never its cold credentials.

    The pinned musl Docker owner performs the static ELF/size checks; this
    consumer checks the exported ELF identity and binds both public companion
    files to the captured source manifest. Nothing is imported or executed.
    """
    root = output / "artifacts"
    directories = {
        "": {"usr"}, "usr": {"local", "share"}, "usr/local": {"libexec"},
        "usr/local/libexec": {"serverware-workload-sidecar"},
        "usr/share": {"serverware"},
        "usr/share/serverware": {"install_workload_sidecar_unit.py",
                                 "native-workload-sidecar.v1.schema.json"},
    }
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    identities = {}
    for relative, expected in directories.items():
        path = root / relative
        before = path.lstat()
        # materialize owns the private 0700 staging root; archive directories
        # below it retain the source-fixed traversable 0555 installation mode.
        expected_mode = 0o555 if relative else 0o700
        if (not stat.S_ISDIR(before.st_mode) or path.resolve() != path
                or stat.S_IMODE(before.st_mode) != expected_mode):
            raise RuntimeError("sidecar artifact directory type, path or fixed mode differs")
        identities[relative] = tuple(getattr(before, field) for field in fields)
        names = set()
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.name not in expected or entry.name in names:
                    raise RuntimeError("sidecar export contains an unexpected artifact")
                names.add(entry.name)
        if names != expected:
            raise RuntimeError("sidecar export is missing a fixed artifact")
    source_files = {entry["path"]: entry for entry in
                    metadata["source_contract"]["sourceTreeManifest"]["files"]
                    if entry.get("type") == "file"}
    artifacts = {}
    for relative, (mode, maximum, source_path) in SIDECAR_FILES.items():
        path = root / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1:
            raise RuntimeError("sidecar artifact type, mode or link count differs from its fixed target")
        raw = read_original(path, maximum)
        after = path.lstat()
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise RuntimeError("sidecar original changed during inventory")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if source_path is not None:
            original = source_files.get(source_path)
            if original is None or original["sha256"] != digest or original["bytes"] != len(raw):
                raise RuntimeError("sidecar companion differs from the captured source original")
        elif (len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01"
              or int.from_bytes(raw[16:18], "little") not in (2, 3)
              or int.from_bytes(raw[18:20], "little") != 62):
            raise RuntimeError("sidecar executable is not the fixed Linux/amd64 ELF artifact")
        artifacts[relative] = {"sha256": digest, "bytes": len(raw), "mode": format(mode, "04o")}
    for relative, expected_identity in identities.items():
        after = (root / relative).lstat()
        if tuple(getattr(after, field) for field in fields) != expected_identity:
            raise RuntimeError("sidecar artifact directory changed during inventory")
    return artifacts


def assemble_sidecar(metadata, output):
    profile = build.native_pilot_build_resource_profile(metadata)
    source = {key: metadata[key] for key in ("revision", "source_tree_digest", "source_manifest_digest",
                                           "source_archive_digest", "source_date_epoch")}
    target = build.NATIVE_WORKLOAD_SIDECAR_TARGET
    write_original(output / "attempt.json", {
        "apiVersion": "serverware.nativePilotWorkloadSidecarAttempt/v1", "source": source,
        "target": target, "buildResourceProfile": profile,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
    })
    _, exported = export_fixed_runtime(metadata, output, target)
    artifacts = sidecar_inventory(output, metadata)
    write_original(output / "workload-sidecar.json", {
        "apiVersion": "serverware.nativePilotWorkloadSidecarArtifacts/v1", "artifactBuildComplete": True,
        "source": source, "target": target, "buildResourceProfile": profile, "artifacts": artifacts,
        "rawExport": exported,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "boundary": "Unsigned workload-side static executable, unit-output helper and schema only. Independent artifact admission and protected installation remain required before separately provisioned cold originals, namespace, workload credentials, egress and explicit service start. No installer, binary, service or network request was executed.",
    })


def assemble_operator_tools(metadata, output):
    # This is a prerequisite of public-input preparation, so it takes no guest
    # inputs and never constructs a policy or chooses its independent author.
    profile = build.native_pilot_build_resource_profile(metadata)
    source = {key: metadata[key] for key in ("revision", "source_tree_digest", "source_manifest_digest",
                                           "source_archive_digest", "source_date_epoch")}
    write_original(output / "attempt.json", {
        "apiVersion": "serverware.nativePilotOperatorToolsAttempt/v1", "source": source,
        "target": build.NATIVE_PILOT_OPERATOR_TARGET, "buildResourceProfile": profile,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
    })
    _, exported = export_fixed_runtime(metadata, output, build.NATIVE_PILOT_OPERATOR_TARGET)
    artifacts = operator_inventory(output)
    write_original(output / "operator-tools.json", {
        "apiVersion": "serverware.nativePilotOperatorTools/v1", "artifactBuildComplete": True,
        "source": source, "target": build.NATIVE_PILOT_OPERATOR_TARGET,
        "buildResourceProfile": profile, "artifacts": artifacts,
        "rawExport": exported,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "boundary": "Unsigned local operator executable only, not a standalone runtime closure. Requires a compatible Linux/amd64 host and independently selected seccomp policy. No exporter, filter, guest or service was executed; no policy, provenance, signature or input-manifest approval was produced.",
    })


def export_fixed_runtime(metadata, output, target):
    """Stage exact exported modes without a privileged local-export client."""
    dockerfiles = {
        build.NATIVE_PILOT_CONDUCTOR_TARGET: "Dockerfile.production",
        build.NATIVE_PILOT_AUTHORITY_TARGET: "Dockerfile.production",
        build.NATIVE_PILOT_SUPERVISOR_TARGET: "Dockerfile.production",
        build.NATIVE_PILOT_OPERATOR_TARGET: DOCKERFILE,
        build.NATIVE_WORKLOAD_SIDECAR_TARGET: DOCKERFILE,
    }
    if target not in dockerfiles:
        raise RuntimeError("runtime export requires a fixed pilot prerequisite target")
    build.verify_dependency_cache()
    raw = output / "raw-rootfs.tar"
    root = output / "artifacts"
    with build.private_build_context(metadata) as context:
        command = build.artifact_build_command(dockerfiles[target], target,
            "type=tar,dest=" + str(raw), network="none", platform=build.PRODUCTION_PLATFORM,
            metadata=metadata, context=context, native_pilot_bounded_build=True)
        descriptor = os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            build.run_build(command)
        finally:
            os.close(descriptor)
    # Keep the original and any partial staging on failure; never run its code.
    exported = runtime_tar.materialize(raw, root)
    return root, exported


def assemble_conductor_runtime(metadata, output):
    """Build and package the fixed operator rootfs without invoking its CLI.

    This requires only the existing source/dependency owners, not native guest
    inputs or authority keys. The exact exported files are inventoried and then
    rechecked while creating a portable archive. Local hashes are not approval.
    """
    profile = build.native_pilot_build_resource_profile(metadata)
    source = {key: metadata[key] for key in ("revision", "source_tree_digest", "source_manifest_digest",
                                           "source_archive_digest", "source_date_epoch")}
    target = build.NATIVE_PILOT_CONDUCTOR_TARGET
    write_original(output / "attempt.json", {
        "apiVersion": "serverware.nativePilotConductorBuildAttempt/v1", "source": source,
        "target": target, "buildResourceProfile": profile,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
    })
    root, exported = export_fixed_runtime(metadata, output, target)
    runtime = conductor_runtime.inventory(root, metadata)
    package = conductor_package.package(root, runtime, output / "package")
    write_original(output / "conductor-runtime.json", {
        "apiVersion": "serverware.nativePilotConductorArtifacts/v1", "artifactBuildComplete": True,
        "source": source, "target": target, "buildResourceProfile": profile,
        "rawExport": exported,
        "runtimeInventorySha256": package["inventorySha256"], "package": package,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "boundary": "Unsigned local operator rootfs and portable package only. Independent admission, protected installation, native executables, configuration, resource environment and external authority coordinator remain required. No pilot, service or authority was launched.",
    })


def assemble_authority_runtime(metadata, output):
    """Package the fixed authority coordinator without approving or invoking it."""
    profile = build.native_pilot_build_resource_profile(metadata)
    source = {key: metadata[key] for key in ("revision", "source_tree_digest", "source_manifest_digest",
                                           "source_archive_digest", "source_date_epoch")}
    target = build.NATIVE_PILOT_AUTHORITY_TARGET
    write_original(output / "attempt.json", {
        "apiVersion": "serverware.nativePilotAuthorityBuildAttempt/v1", "source": source,
        "target": target, "buildResourceProfile": profile,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
    })
    root, exported = export_fixed_runtime(metadata, output, target)
    runtime = conductor_runtime.authority_inventory(root, metadata)
    package = conductor_package.package_authority(root, runtime, output / "package")
    write_original(output / "authority-runtime.json", {
        "apiVersion": "serverware.nativePilotAuthorityArtifacts/v1", "artifactBuildComplete": True,
        "source": source, "target": target, "buildResourceProfile": profile,
        "rawExport": exported,
        "runtimeInventorySha256": package["inventorySha256"], "package": package,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "boundary": "Unsigned local authority-coordinator rootfs and portable package only. The independent supervisor, separately approved conductor inventory, purpose keys, protected inputs and per-job approvals remain required. No signing, provisioning, pilot, service or authority was executed.",
    })


def assemble_supervisor_runtime(metadata, output):
    """Package the complete fixed supervisor, never exercise its authority."""
    profile = build.native_pilot_build_resource_profile(metadata)
    source = {key: metadata[key] for key in conductor_runtime.SOURCE_FIELDS}
    target = build.NATIVE_PILOT_SUPERVISOR_TARGET
    write_original(output / "attempt.json", {
        "apiVersion": "serverware.nativePilotSupervisorBuildAttempt/v1", "source": source,
        "target": target, "buildResourceProfile": profile,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
    })
    root, exported = export_fixed_runtime(metadata, output, target)
    runtime = conductor_runtime.supervisor_inventory(root, metadata)
    package = conductor_package.package_supervisor(root, runtime, output / "package")
    write_original(output / "supervisor-runtime.json", {
        "apiVersion": "serverware.nativePilotSupervisorArtifacts/v1", "artifactBuildComplete": True,
        "source": source, "target": target, "buildResourceProfile": profile,
        "rawExport": exported,
        "runtimeInventorySha256": package["inventorySha256"], "package": package,
        "profiles": {
            "supervisorPolicy": "serverware.nativePilotSupervisorCommissioningPolicy/v18",
            "bridgeLaunch": "serverware.nativeProofBridgeLaunch/v7",
            "bridgeRuntime": "serverware.policyCustodyProductionRpcRuntime/v11",
        },
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "boundary": "Unsigned local supervisor rootfs and portable package only. Independent admission of three inventories, protected v18 policy and measured recipe, exact purpose keys, authenticated late-approval peer and original live resources remain required. No approval, signing, provisioning, pilot or service was executed.",
    })


def assemble(args, metadata, plan, output):
    raw = read_original(args.preparation, 128 * 1024)
    if raw != build.canonical_json(plan).encode("ascii"):
        raise RuntimeError("preparation must be the exact fixed profile for this clean source snapshot")
    # The existing cache verifier never fetches. Base images/build tools must
    # already be available to the operator's independently managed builder.
    build.verify_dependency_cache()
    images = []
    with build.private_build_context(metadata) as context:
        build.copy_native_pilot_public_inputs(args.public_inputs, args.public_inputs_sha256, metadata, context)
        write_original(output / "attempt.json", {"apiVersion": "serverware.nativePilotBuildAttempt/v1",
            "source": plan["source"], "releaseAuthority": False, "liveReady": False,
            "buildResourceProfile": plan["buildResourceProfile"],
            "publicInputsSha256": args.public_inputs_sha256})
        for service, dockerfile in (("control", "Dockerfile.production"), ("gate", DOCKERFILE)):
            tag = "serverware/native-pilot-" + service + ":" + metadata["revision"]
            build.run_build(build.build_command(dockerfile, tag, platform=build.PRODUCTION_PLATFORM,
                metadata=metadata, context=context, native_pilot_bounded_build=True))
            image = build.image_id(tag)
            build.verify_image_platform(image, build.PRODUCTION_PLATFORM)
            paths = (["/usr/local/bin/serverware-decision-gate",
                      "/usr/local/bin/serverware-proof-client",
                      "/usr/local/libexec/serverware-native-response-verifier"] +
                     ["/usr/local/bin/serverware-policy-custody-" + role for role in ORDINARY_ROLES]) if service == "gate" else ["/app/serverware/app.py"]
            # Existing stopped-container export owner; no image entrypoint runs.
            originals = {path: build.image_file_sha256(image, path) for path in paths}
            images.append({"service": service, "imageId": image, "tag": tag, "originalSha256s": originals})
        build.run_build(build.artifact_build_command(DOCKERFILE, build.NATIVE_PILOT_TARGET,
            "type=local,dest=" + str(output / "artifacts"), network="none", platform=build.PRODUCTION_PLATFORM,
            metadata=metadata, context=context, public_inputs_sha256=args.public_inputs_sha256,
            native_pilot_bounded_build=True))
    artifacts, guest = native_inventory(output)
    if guest.get("sourceManifestSha256") != metadata["source_manifest_digest"] or guest.get("inputManifestSha256") != args.public_inputs_sha256:
        raise RuntimeError("guest artifact source/public-input pins differ from this attempt")
    result = {"apiVersion": "serverware.nativePilotArtifacts/v1", "artifactBuildComplete": True,
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False, "executionAccepted": False,
        "source": plan["source"], "profiles": PROFILES, "images": images, "nativeArtifacts": artifacts,
        "buildResourceProfile": plan["buildResourceProfile"],
        "publicInputsSha256": args.public_inputs_sha256, "requiredExternalOriginals": plan["requiredExternalOriginals"],
        "boundary": "Unsigned local build outputs only; independent reproducibility/admission, installation, live-owner preparation and connected pilot acceptance remain required."}
    write_original(output / "artifacts.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="emit source-bound public input requirements; no Docker or service execution")
    prepare.add_argument("--out", type=Path, required=True)
    operator_tools = sub.add_parser("operator-tools", help="build only the fixed offline seccomp exporter with strict source and per-RUN resource bounds; no guest inputs or execution")
    operator_tools.add_argument("--out", type=Path, required=True)
    conductor = sub.add_parser("conductor-runtime", help="build and package the fixed Python conductor rootfs; no guest inputs, installation or launch")
    conductor.add_argument("--out", type=Path, required=True)
    authority = sub.add_parser("authority-runtime", help="build and package the separate fixed authority coordinator; no approvals, keys, signing, installation or launch")
    authority.add_argument("--out", type=Path, required=True)
    supervisor = sub.add_parser("supervisor-runtime", help="build and package the fixed commissioning supervisor; no approvals, keys, signing, installation or launch")
    supervisor.add_argument("--out", type=Path, required=True)
    sidecar = sub.add_parser("workload-sidecar", help="build and inventory the fixed static workload sidecar and unit-output helper; no guest inputs, credentials, installation or launch")
    sidecar.add_argument("--out", type=Path, required=True)
    public_inputs = sub.add_parser("public-inputs", help="copy operator public originals and measure an unapproved manifest; never build or sign")
    public_inputs.add_argument("--out", type=Path, required=True)
    public_inputs.add_argument("--preparation", type=Path, required=True)
    public_inputs.add_argument("--seccomp", type=Path, required=True)
    public_inputs.add_argument("--runtime", type=Path, required=True)
    public_inputs.add_argument("--build-recipe", type=Path, required=True)
    public_inputs.add_argument("--provenance", type=Path, required=True)
    compile_command = sub.add_parser("build", help="assemble the fixed offline artifacts and local control/gate images; never launch")
    compile_command.add_argument("--out", type=Path, required=True)
    compile_command.add_argument("--preparation", type=Path, required=True)
    compile_command.add_argument("--public-inputs", type=Path, required=True)
    compile_command.add_argument("--public-inputs-sha256", required=True)
    args = parser.parse_args()
    metadata = build.build_metadata()  # strict clean committed source, no dirty-tree escape
    if args.command in ("operator-tools", "conductor-runtime", "authority-runtime", "supervisor-runtime", "workload-sidecar"):
        if args.command == "operator-tools":
            assemble_operator_tools(metadata, new_output(args.out))
        elif args.command == "conductor-runtime":
            assemble_conductor_runtime(metadata, new_output(args.out))
        elif args.command == "authority-runtime":
            assemble_authority_runtime(metadata, new_output(args.out))
        elif args.command == "supervisor-runtime":
            assemble_supervisor_runtime(metadata, new_output(args.out))
        else:
            assemble_sidecar(metadata, new_output(args.out))
        print(build.canonical_json({"apiVersion": "serverware.nativePilotBuildCommand/v1", "command": args.command,
            "output": str(args.out), "artifactBuildComplete": True,
            "releaseAuthority": False, "liveReady": False, "launchPrepared": False}))
        return
    plan = preparation(metadata)
    if args.command == "public-inputs":
        measured = package_public_inputs(args, metadata, plan)
        print(build.canonical_json({"apiVersion": "serverware.nativePilotBuildCommand/v1", "command": args.command,
            "output": str(args.out), "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
            **measured}))
        return
    output = new_output(args.out)
    write_original(output / "preparation.json", plan)
    if args.command == "build":
        assemble(args, metadata, plan, output)
    print(build.canonical_json({"apiVersion": "serverware.nativePilotBuildCommand/v1", "command": args.command,
        "output": str(output), "releaseAuthority": False, "liveReady": False, "launchPrepared": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(build.canonical_json({"ok": False, "error": str(error), "automaticRetryAllowed": False}), file=sys.stderr)
        raise SystemExit(1) from error
