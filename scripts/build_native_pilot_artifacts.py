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

DOCKERFILE = "data-plane/decision-gate-rs/Dockerfile.production"
PROFILES = {
    "cohort": "serverware.nativeShadowProofCohortConfiguration/v6",
    "cohortRoles": ["retrieval", "persistence", "trustedTime", "generationInstall", "bridge",
                    "commitRequest", "ingressAdmission", "terminalAppend", "dispatchBarrier",
                    "activeEffectBarrier", "activeEffectCommit"],
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
    "usr/local/bin/serverware-native-shadow-worker": (0o555, 64 * 1024 * 1024),
    "opt/serverware/native-shadow-custody-runtime.squashfs": (0o444, 256 * 1024 * 1024),
    "usr/share/serverware/native-shadow-custody-runtime.json": (0o444, 4 * 1024 * 1024),
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
            "Protected cohort control/configuration-v6 and original precreation window; eleven distinct actual child assignments",
            "Protected custody-effects-five.json v6, five C9 configurations, service credentials and signed authority histories",
            "Driver bootstrap/configuration/window, actual post-drop measurement, independently signed phase-two scope and constructed admission",
            "Actual gate native startup/lifecycle/receiving configuration, signed policy, assignment, compiler and canary inventory",
            "Exact head-v3/current-v3/cleanup-v1 grants, generation grants, encrypted independently assigned native keys and KMS context pins",
            "Independent trust/revocation/checkpoint/time/verifier/generation-origin authorities and their original transport/key custody",
            "Actual listeners, persistent fs-verity-capable stores, held locks, cgroups, IMA/LSM identities, UID separation and PIDFD support",
            "Control-plane database/OIDC/WebAuthn/protected-authority configuration and operator two-person approvals",
            "Independent Setup hardware/proxy/final issuer artifacts, protected configurations and sealed key delivery",
        ],
        "existingOwners": {
            "nativeCohort": "serverware.native_shadow_proof_cohort_control.ParkedProofCohort.start",
            "ordinaryFive": "serverware.custody_generation_launch.FiveServiceLaunch.start_effects",
            "generationInputs": "serverware.custody_generation_business.BusinessResources.prepare_commitment(five).commitment_inputs()",
            "spoolResources": "serverware.native_shadow_spool_inputs.SpoolInputs.prepare",
            "driver": "serverware.native_shadow_driver_bootstrap.DriverBootstrap.start",
            "outgoingAndContinuation": "serverware.native_shadow_driver_inputs.OperationalInputs.prepare_outgoing",
            "orderedRelease": "serverware.custody_generation_launch.FiveServiceLaunch.release_proof_cohort",
        },
        "boundary": "Preparation is build data only. Actual live owners must measure, admit, sign independently, retain and release under original deadlines; no launch is performed.",
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
