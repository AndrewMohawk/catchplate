#!/usr/bin/env python3
"""Read-only review of the exact rehearsed managed-capable demo candidate.

`review` resolves the four fixed layers against the original private env and
freshly observed edge peer address. It permits only the enumerated transition;
`--phase deployed` instead requires the exact candidate already running. Neither
mode reads app state, mounts files, creates directories or authorizes rollout.
`custody` is a separate metadata-only check after root provisions the directory.
All error receipts are fixed and secret-silent; no engine/env objects are output.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import ipaddress
import json
import os
from pathlib import Path
import signal
import stat

from scripts import operator_demo_deployment_review as legacy
from scripts import prepare_operator_proxy_basic_fixture as archives

OLD_SOURCE, OLD_SHA, OLD_BINARY = legacy.NEW_SOURCE, legacy.NEW_SHA, legacy.NEW_BINARY
NEW_COMMIT = "9222b4c090d77aa983d3c01be34e0a2ba79f8e6c"
NEW_SOURCE = legacy.ARTIFACTS + "source-" + NEW_COMMIT
NEW_SHA = "333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0"
NEW_BINARY = legacy.ARTIFACTS + "sha256-" + NEW_SHA + "/serverware-decision-gate"
SOURCE_MANIFEST_SHA = "b724e252161476dbd5106aadbb71c4229afb36e47c1528e4678e166333f7a3da"
EVIDENCE = Path(legacy.ARTIFACTS).parent / "serverware-operator-workspace-evidence/managed-retained.qBkamJ3p"
JOIN = EVIDENCE / "compiled-source-join.json"
JOIN_SHA = "1f03a59d9cb4a7f39891d7bb0c2eb7719dc608bb90177db7eb5466c5d1adef4c"
DATA_ROOT = Path("/srv/catchplate-fast/homelab_data/serverware-operator-demo")
APP_DATA = DATA_ROOT / "app-data"
PROVIDER_CUSTODY = Path("/srv/catchplate-fast/homelab_data/serverware-operator-demo-google-provider")
LEAVES = (".operator-publication.lock", ".serverware-operator-demo.json",
    "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")
MANAGED = legacy.STACK / "docker-compose.managed-google-candidate.yml"
CURATED = legacy.STACK / "docker-compose.curated-gate.yml"
LAYERS = (legacy.BASE, MANAGED, CURATED, legacy.NOTIFICATIONS)
PINS = {**legacy.PINS,
    MANAGED: "946691442ff1a78f43c8a919fb8e97fcedcb80bfca93c20ae5751c6dd1ca522b",
    CURATED: "e5335f471f60a2cb918d7e2e201c469012655efcba38fed86ceb6608cf71d6b5"}
APP_MANAGED_ENV = {
    "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1",
    "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
    "SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane", "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
    "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite", "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
    "SERVERWARE_RELEASE_CHANNEL": "dev", "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "SERVERWARE_KEY_RELEASE_REQUIRED": "0", "SERVERWARE_DEV_AUTHENTICATOR": "0", "SERVERWARE_DEV_DEMO_SEED": "0"}
FRESH_FLAGS = frozenset(("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED",
    "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR", "SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED"))
APP_ENV_DELTA = "serverware explicit managed development ownership"
APP_CUSTODY_DELTA = "serverware app-only provider custody bind"
GATE_ENV_DELTA = "decision-gate-rs managed public configuration"
GATE_DATA_DELTA = "decision-gate-rs curated data and four original read-only leaves"
APPROVED_DELTAS = legacy.APPROVED_DELTAS | {APP_ENV_DELTA, APP_CUSTODY_DELTA, GATE_ENV_DELTA, GATE_DATA_DELTA}
TRANSITION = (OLD_SOURCE, NEW_SOURCE, OLD_SHA, NEW_SHA, OLD_BINARY, NEW_BINARY)
Refused, require = legacy.Refused, legacy.require


def error_receipt(_error):
    return {"ok": False, "error": "managed candidate comparison refused"}


def provider_path(value):
    value = Path(value)
    require(value == PROVIDER_CUSTODY and value.is_absolute() and ".." not in value.parts,
        "fixed provider custody path")
    return value


def volumes(rows):
    require(isinstance(rows, list), "mount shape")
    result = {row["target"]: row for row in rows}
    require(len(result) == len(rows), "duplicate mount target")
    return result


def bind(source, target, readonly):
    return {"type": "bind", "source": str(source), "target": target,
        "read_only": readonly, "bind": {"create_host_path": False}}


def admitted_bind(value, source, target, readonly):
    """Compose may omit only the false read_only default on a writable bind."""
    require(type(value) is dict and set(value) in (
        {"type", "source", "target", "bind"}, {"type", "source", "target", "read_only", "bind"}), "closed bind fields")
    effective_readonly = value.get("read_only", False)
    require(type(effective_readonly) is bool and effective_readonly is readonly, "exact bind access")
    options = value["bind"]
    require(type(options) is dict and set(options) == {"create_host_path"}
        and options["create_host_path"] is False, "exact bind creation guard")
    require({**value, "read_only": effective_readonly} == bind(source, target, readonly), "exact bind identity")


def candidate_service(name, proposed, provider_custody):
    """Admit new fields independently, before comparison to retained settings."""
    provider_path(provider_custody)
    environment = proposed.get("environment", {})
    require(not any(key.startswith("SERVERWARE_GOOGLE_") or key == "SERVERWARE_OPERATOR_GOOGLE_PROFILE"
        for key in environment), "external Google profile refused")
    mounts = volumes(proposed["volumes"])
    if name == "serverware":
        require(all(environment.get(key) == value for key, value in APP_MANAGED_ENV.items()), "managed app environment")
        admitted_bind(mounts.get("/provider-custody"), provider_custody, "/provider-custody", False)
        require(mounts.get("/data", {}).get("source") == str(APP_DATA), "fixed app data source")
    elif name == "decision-gate-rs":
        require(environment.get("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED") == "1"
            and "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR" not in environment, "managed gate environment")
        admitted_bind(mounts.get("/data"), APP_DATA / "gate-runtime", "/data", True)
        for leaf in LEAVES:
            admitted_bind(mounts.get("/data/" + leaf), APP_DATA / leaf, "/data/" + leaf, True)
    require(all(row["source"] != str(provider_custody) or name == "serverware" and row["target"] == "/provider-custody"
        for row in mounts.values()), "provider custody exposure")


def compare_service(name, proposed, live, image, networks, *, provider_custody=PROVIDER_CUSTODY,
                    digest_file=legacy.file_digest):
    """Closed delta admission, then unchanged historical retained-setting oracle."""
    candidate_service(name, proposed, provider_custody)
    retained = legacy.envmap(live["Config"].get("Env"))
    require(not any(key in FRESH_FLAGS or key.startswith("SERVERWARE_GOOGLE_")
        or key == "SERVERWARE_OPERATOR_GOOGLE_PROFILE" for key in retained), "baseline managed profile already present")
    normalized, changes = deepcopy(proposed), set()
    if name == "serverware":
        for key, value in APP_MANAGED_ENV.items():
            require(key not in retained or retained[key] == value, "retained ownership flag differs")
            if key not in retained:
                del normalized["environment"][key]
        normalized["volumes"] = [row for row in normalized["volumes"] if row["target"] != "/provider-custody"]
        changes.update((APP_ENV_DELTA, APP_CUSTODY_DELTA))
    elif name == "decision-gate-rs":
        del normalized["environment"]["SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED"]
        normalized["volumes"] = [row for row in normalized["volumes"] if row["target"] not in {"/data/" + leaf for leaf in LEAVES}]
        volumes(normalized["volumes"])["/data"]["source"] = str(APP_DATA)
        changes.update((GATE_ENV_DELTA, GATE_DATA_DELTA))
    changes.update(legacy.compare_service(name, normalized, live, image, networks, digest_file=digest_file,
        transition=TRANSITION))
    return changes


def compare_candidate_runtime(name, proposed, live, image, networks, *, provider_custody=PROVIDER_CUSTODY,
                              digest_file=legacy.file_digest):
    """No tolerated configuration changes after root recreates the pair."""
    candidate_service(name, proposed, provider_custody)
    changes = legacy.compare_service(name, proposed, live, image, networks, digest_file=digest_file,
        transition=(NEW_SOURCE, NEW_SOURCE, NEW_SHA, NEW_SHA, NEW_BINARY, NEW_BINARY))
    expected = {"serverware": {legacy.APP_DELTA, legacy.DIGEST_DELTA},
        "decision-gate-rs": {legacy.BINARY_DELTA}}.get(name, set())
    require(changes == expected, "candidate exact configuration")
    return set()


def compare_model(model, observed, images, *, provider_custody=PROVIDER_CUSTODY,
                  digest_file=legacy.file_digest, phase="proposed"):
    require(phase in {"proposed", "deployed"}, "comparison phase")
    legacy.validate_model(model)
    require(set(observed) == legacy.SERVICES, "exact retained services")
    changes = set()
    compare = compare_service if phase == "proposed" else compare_candidate_runtime
    for name in sorted(legacy.SERVICES):
        proposed = model["services"][name]
        changes.update(compare(name, proposed, observed[name], images[proposed["image"]], model["networks"],
            provider_custody=provider_custody, digest_file=digest_file))
    require(changes == (APPROVED_DELTAS if phase == "proposed" else set()), "closed managed transition")
    return {"ok": True, "schema": "serverware.operatorManagedDeploymentReview/v1", "phase": phase,
        "sourceCommit": NEW_COMMIT, "candidateBinarySha256": NEW_SHA, "approvedDifferences": sorted(changes),
        "notificationsRetained": True, "retainedServicesMustNotBeRecreated": ["demo-upstream", "edge"],
        "providerCustodyMetadataVerified": False, "curatedFilesystemVerified": False,
        "runtimeMutationsPerformed": False, "rolloutVerified": False}


def custody_metadata(provider_custody):
    """Metadata-only alias check; never opens SQLite, key or token contents."""
    provider = provider_path(provider_custody)
    require(provider.resolve(strict=True) == provider, "canonical provider directory")
    info = provider.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == info.st_gid == 10001, "private provider ownership")
    require(not list(provider.iterdir()), "empty initial provider custody")
    identity = (info.st_dev, info.st_ino)
    # Lexical disjointness alone does not detect bind aliases. Compare directory
    # identities in the two fixed retained trees, bounded and metadata-only.
    pending, seen, entries = [DATA_ROOT, Path(legacy.CUSTODY)], set(), 0
    while pending:
        directory = pending.pop()
        require(directory.resolve(strict=True) == directory, "retained directory alias")
        current = directory.lstat()
        require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) != identity, "provider aliases retained state")
        key = (current.st_dev, current.st_ino)
        require(key not in seen and len(seen) < 2048, "directory alias or bound")
        seen.add(key)
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                require(entries <= 4096 and not child.is_symlink(), "retained metadata bound")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
    final = provider.lstat()
    require((final.st_dev, final.st_ino, final.st_uid, final.st_gid, final.st_mode, final.st_mtime_ns, final.st_ctime_ns)
        == (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
        and not list(provider.iterdir()), "provider metadata changed")
    return {"ok": True, "schema": "serverware.operatorManagedProviderDirectoryReview/v1", "empty": True,
        "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
        "device": info.st_dev, "inode": info.st_ino, "retainedDirectoryAliasesAbsent": True,
        "privateFileContentsRead": False, "runtimeMutationsPerformed": False, "rolloutVerified": False}


def source_identity(source, source_manifest):
    require(str(source) == NEW_SOURCE, "exact rehearsed source")
    files = archives.source_inventory(source, source_manifest, SOURCE_MANIFEST_SHA, NEW_COMMIT)
    require(len(files) == 4910, "rehearsed file inventory")
    for directory, _, names in os.walk(source):
        require(stat.S_IMODE(Path(directory).stat().st_mode) == 0o555, "immutable source directories")
        require(all(stat.S_IMODE((Path(directory) / name).stat().st_mode) in {0o444, 0o555} for name in names), "immutable source files")
    require(legacy.file_digest(OLD_BINARY) == OLD_SHA and legacy.file_digest(NEW_BINARY) == NEW_SHA, "paired binary bytes")
    join = archives.pinned_json(JOIN, JOIN_SHA)
    require(join == {"binarySha256": NEW_SHA, "binarySourceCommit": "ff6d86b1a0267dcb5915e07684bdc5b216dbde7d",
        "cargoManifestAndLockMatched": True, "completeGitTreeEqualityClaimed": False,
        "exactCompilerInputFilesMatched": 494, "newRustBuildClaimed": False,
        "sourceCommit": NEW_COMMIT, "sourceManifestSha256": SOURCE_MANIFEST_SHA}, "retained compiler input join")


def review(args):
    provider_path(args.provider_custody)
    source_identity(args.source, args.source_manifest)
    fingerprints = {path: legacy.file_digest(path) for path in LAYERS}
    require(fingerprints == PINS, "fixed Compose layers")
    observed = legacy.discover()
    edge_env = legacy.envmap(observed["edge"]["Config"].get("Env"))
    peer = edge_env.get("TRAEFIK_IPV4")
    require(isinstance(peer, str) and str(ipaddress.IPv4Address(peer)) == peer
        and not ipaddress.IPv4Address(peer).is_unspecified and not ipaddress.IPv4Address(peer).is_multicast,
        "current edge peer selection")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TRAEFIK_IPV4": peer,
        "OPERATOR_MANAGED_SOURCE": NEW_SOURCE, "OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR": str(args.provider_custody),
        "OPERATOR_DEMO_NOTIFICATIONS_ENABLED": "1", "OPERATOR_DEMO_NOTIFICATIONS_CUSTODY_DIR": legacy.CUSTODY}
    command = ["docker", "compose", "-p", legacy.PROJECT, "--env-file", legacy.ENVFILE]
    for layer in LAYERS:
        command.extend(("-f", str(layer)))
    model = legacy.command_json([*command, "config", "--format", "json"], environment=environment)
    images = {}
    for proposed in model["services"].values():
        reference = proposed["image"]
        if reference not in images:
            values = legacy.command_json(["docker", "image", "inspect", reference])
            require(isinstance(values, list) and len(values) == 1, "cached image identity")
            images[reference] = values[0]
    result = compare_model(model, observed, images, provider_custody=args.provider_custody, phase=args.phase)
    after = legacy.discover()
    for name in legacy.SERVICES:
        old, new = observed[name], after[name]
        require(all(old[key] == new[key] for key in ("Id", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings"))
            and old["State"]["Pid"] == new["State"]["Pid"] and old["State"]["StartedAt"] == new["State"]["StartedAt"],
            "stable inspection identity")
    require({path: legacy.file_digest(path) for path in LAYERS} == fingerprints, "stable Compose layers")
    source_identity(args.source, args.source_manifest)
    return {**result, "sourceFilesVerified": 4910, "compilerInputFilesMatched": 494,
        "edgePeerFromCurrentInspection": True, "services": [{"service": name, "id": observed[name]["Id"]}
            for name in sorted(legacy.SERVICES)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    model = commands.add_parser("review")
    for name in ("source", "source-manifest", "provider-custody"):
        model.add_argument("--" + name, type=Path, required=True)
    model.add_argument("--phase", choices=("proposed", "deployed"), default="proposed")
    metadata = commands.add_parser("custody")
    metadata.add_argument("--provider-custody", type=Path, required=True)
    args = parser.parse_args()
    def expired(*_):
        raise Refused("review deadline")
    signal.signal(signal.SIGALRM, expired); signal.alarm(180)
    try:
        result = review(args) if args.command == "review" else custody_metadata(args.provider_custody)
        print(json.dumps(result, sort_keys=True))
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps(error_receipt(error), sort_keys=True))
        raise SystemExit(1)
