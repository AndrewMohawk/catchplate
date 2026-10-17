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
import re
import signal
import stat

from scripts import operator_demo_deployment_review as legacy
from scripts import prepare_operator_proxy_basic_fixture as archives

OLD_SOURCE, OLD_SHA, OLD_BINARY = legacy.NEW_SOURCE, legacy.NEW_SHA, legacy.NEW_BINARY
NEW_COMMIT = "9222b4c090d77aa983d3c01be34e0a2ba79f8e6c"
NEW_SOURCE = legacy.ARTIFACTS + "source-" + NEW_COMMIT
NEW_SHA = "333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0"
NEW_BINARY = legacy.ARTIFACTS + "sha256-" + NEW_SHA + "/catchplate-decision-gate"
SOURCE_MANIFEST_SHA = "b724e252161476dbd5106aadbb71c4229afb36e47c1528e4678e166333f7a3da"
EVIDENCE = Path(legacy.ARTIFACTS).parent / "catchplate-operator-workspace-evidence/managed-retained.qBkamJ3p"
JOIN = EVIDENCE / "compiled-source-join.json"
JOIN_SHA = "1f03a59d9cb4a7f39891d7bb0c2eb7719dc608bb90177db7eb5466c5d1adef4c"
DATA_ROOT = Path("/srv/catchplate-fast/homelab_data/catchplate-operator-demo")
APP_DATA = DATA_ROOT / "app-data"
PROVIDER_CUSTODY = Path("/srv/catchplate-fast/homelab_data/catchplate-operator-demo-google-provider")
LEAVES = (".operator-publication.lock", ".catchplate-operator-demo.json",
    "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")
MANAGED = legacy.STACK / "docker-compose.managed-google-candidate.yml"
CURATED = legacy.STACK / "docker-compose.curated-gate.yml"
LAYERS = (legacy.BASE, MANAGED, CURATED, legacy.NOTIFICATIONS)
PINS = {**legacy.PINS,
    MANAGED: "946691442ff1a78f43c8a919fb8e97fcedcb80bfca93c20ae5751c6dd1ca522b",
    CURATED: "e5335f471f60a2cb918d7e2e201c469012655efcba38fed86ceb6608cf71d6b5"}
APP_MANAGED_ENV = {
    "CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1",
    "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
    "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
    "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane", "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
    "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite", "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_RELEASE_CHANNEL": "dev", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "CATCHPLATE_DEV_AUTHENTICATOR": "0", "CATCHPLATE_DEV_DEMO_SEED": "0"}
FRESH_FLAGS = frozenset(("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED",
    "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR", "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED"))
APP_ENV_DELTA = "catchplate explicit managed development ownership"
APP_CUSTODY_DELTA = "catchplate app-only provider custody bind"
GATE_ENV_DELTA = "decision-gate-rs managed public configuration"
GATE_DATA_DELTA = "decision-gate-rs curated data and four original read-only leaves"
APPROVED_DELTAS = legacy.APPROVED_DELTAS | {APP_ENV_DELTA, APP_CUSTODY_DELTA, GATE_ENV_DELTA, GATE_DATA_DELTA}
TRANSITION = (OLD_SOURCE, NEW_SOURCE, OLD_SHA, NEW_SHA, OLD_BINARY, NEW_BINARY)
# Separate opt-in for the rehearsed, already-managed upgrade. The Python
# snapshot reuses the b55f3024 Rust build; the original rich equality receipt
# is admitted below without manufacturing a new build or transformed receipt.
RETAINED_COMMIT = "3724110941888e753bc194459e14170bc2a28916"
RETAINED_SOURCE = legacy.ARTIFACTS + "source-" + RETAINED_COMMIT
RETAINED_MANIFEST_SHA = "c11de979a8b8091940fdf22538e9844acff6bc5accc2b2980f4305afb5fe9228"
RETAINED_SOURCE_FILES = 4952
RETAINED_COMPILER_COMMIT = "b55f3024a0a2e696a462df723dae9a8a1fdded6a"
RETAINED_LAYER = legacy.STACK / "docker-compose.npm-publish-candidate.yml"
RETAINED_CANDIDATE = {
    "binary_sha256": "82a99cf00a7763dd1187f86607ffe2415487e98734f4b7d585f44909150e7b85",
    "layer_sha256": "d2ef222b896243a7e582ea9f84a44a6b160ebf8cca058bd7a45196393451d383",
    "join_path": Path("/srv/catchplate-fast/tmp/catchplate-catalog-timing-validation.qg5M5tPT/compiled-source-join.json"),
    "join_sha256": "3b39eadb5829cb20c07f27f185829775ec9bf34798dca2ff08ee4e1c62f749ef",
    "compiler_input_files": 499,
}
Refused, require = legacy.Refused, legacy.require
TRAEFIK_SERVICE = "traefik_traefik"
TRAEFIK_NETWORK = "traefik-v3-public"


def error_receipt(_error):
    return {"ok": False, "error": "managed candidate comparison refused"}


def selection(transition_mode):
    """Choose only one fixed reviewed pair; never take arbitrary CLI pins."""
    require(transition_mode in {"migration", "retained"}, "managed transition mode")
    selected = {"commit": NEW_COMMIT, "source": NEW_SOURCE, "binary_sha256": NEW_SHA,
        "binary": NEW_BINARY, "source_manifest_sha256": SOURCE_MANIFEST_SHA, "source_files": 4910,
        "join_path": JOIN, "join_sha256": JOIN_SHA, "compiler_source_commit": "ff6d86b1a0267dcb5915e07684bdc5b216dbde7d",
        "compiler_input_files": 494, "new_build": False, "layers": LAYERS, "pins": PINS,
        "transition": TRANSITION, "approved_deltas": APPROVED_DELTAS}
    if transition_mode == "migration":
        return selected
    pins = RETAINED_CANDIDATE
    require(type(pins) is dict and set(pins) == {"binary_sha256", "layer_sha256", "join_path",
        "join_sha256", "compiler_input_files"}, "retained candidate not pinned")
    require(all(type(pins[key]) is str and re.fullmatch(r"[0-9a-f]{64}", pins[key]) is not None
        and pins[key] != "0" * 64 for key in ("binary_sha256", "layer_sha256", "join_sha256"))
        and pins["binary_sha256"] not in {OLD_SHA, NEW_SHA, legacy.OLD_SHA}, "retained candidate digest pins")
    require(isinstance(pins["join_path"], Path) and pins["join_path"].is_absolute()
        and ".." not in pins["join_path"].parts and type(pins["compiler_input_files"]) is int
        and 1 <= pins["compiler_input_files"] <= 4096, "retained compiler receipt pins")
    binary = legacy.ARTIFACTS + "sha256-" + pins["binary_sha256"] + "/catchplate-decision-gate"
    selected.update(commit=RETAINED_COMMIT, source=RETAINED_SOURCE, binary_sha256=pins["binary_sha256"],
        binary=binary, source_manifest_sha256=RETAINED_MANIFEST_SHA, source_files=RETAINED_SOURCE_FILES,
        join_path=pins["join_path"], join_sha256=pins["join_sha256"], compiler_source_commit=RETAINED_COMPILER_COMMIT,
        compiler_input_files=pins["compiler_input_files"], new_build=False,
        layers=(legacy.BASE, RETAINED_LAYER, CURATED, legacy.NOTIFICATIONS),
        pins={**legacy.PINS, RETAINED_LAYER: pins["layer_sha256"], CURATED: PINS[CURATED]},
        transition=(NEW_SOURCE, RETAINED_SOURCE, NEW_SHA, pins["binary_sha256"], NEW_BINARY, binary),
        approved_deltas=legacy.APPROVED_DELTAS)
    return selected


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
    require(not any(key.startswith("CATCHPLATE_GOOGLE_") or key == "CATCHPLATE_OPERATOR_GOOGLE_PROFILE"
        for key in environment), "external Google profile refused")
    mounts = volumes(proposed["volumes"])
    if name == "catchplate":
        require(all(environment.get(key) == value for key, value in APP_MANAGED_ENV.items()), "managed app environment")
        admitted_bind(mounts.get("/provider-custody"), provider_custody, "/provider-custody", False)
        require(mounts.get("/data", {}).get("source") == str(APP_DATA), "fixed app data source")
    elif name == "decision-gate-rs":
        require(environment.get("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED") == "1"
            and "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR" not in environment, "managed gate environment")
        admitted_bind(mounts.get("/data"), APP_DATA / "gate-runtime", "/data", True)
        for leaf in LEAVES:
            admitted_bind(mounts.get("/data/" + leaf), APP_DATA / leaf, "/data/" + leaf, True)
    require(all(row["source"] != str(provider_custody) or name == "catchplate" and row["target"] == "/provider-custody"
        for row in mounts.values()), "provider custody exposure")


def compare_service(name, proposed, live, image, networks, *, provider_custody=PROVIDER_CUSTODY,
                    digest_file=legacy.file_digest, transition_mode="migration"):
    """Closed delta admission, then unchanged historical retained-setting oracle."""
    selected = selection(transition_mode)
    candidate_service(name, proposed, provider_custody)
    if transition_mode == "retained":
        # No managed field is projected away: the unchanged full comparator
        # requires every existing flag, custody bind and curated leaf to match.
        return legacy.compare_service(name, proposed, live, image, networks, digest_file=digest_file,
            transition=selected["transition"])
    retained = legacy.envmap(live["Config"].get("Env"))
    require(not any(key in FRESH_FLAGS or key.startswith("CATCHPLATE_GOOGLE_")
        or key == "CATCHPLATE_OPERATOR_GOOGLE_PROFILE" for key in retained), "baseline managed profile already present")
    normalized, changes = deepcopy(proposed), set()
    if name == "catchplate":
        for key, value in APP_MANAGED_ENV.items():
            require(key not in retained or retained[key] == value, "retained ownership flag differs")
            if key not in retained:
                del normalized["environment"][key]
        normalized["volumes"] = [row for row in normalized["volumes"] if row["target"] != "/provider-custody"]
        changes.update((APP_ENV_DELTA, APP_CUSTODY_DELTA))
    elif name == "decision-gate-rs":
        del normalized["environment"]["CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED"]
        normalized["volumes"] = [row for row in normalized["volumes"] if row["target"] not in {"/data/" + leaf for leaf in LEAVES}]
        volumes(normalized["volumes"])["/data"]["source"] = str(APP_DATA)
        changes.update((GATE_ENV_DELTA, GATE_DATA_DELTA))
    changes.update(legacy.compare_service(name, normalized, live, image, networks, digest_file=digest_file,
        transition=TRANSITION))
    return changes


def compare_candidate_runtime(name, proposed, live, image, networks, *, provider_custody=PROVIDER_CUSTODY,
                              digest_file=legacy.file_digest, transition_mode="migration"):
    """No tolerated configuration changes after root recreates the pair."""
    selected = selection(transition_mode)
    candidate_service(name, proposed, provider_custody)
    changes = legacy.compare_service(name, proposed, live, image, networks, digest_file=digest_file,
        transition=(selected["source"], selected["source"], selected["binary_sha256"], selected["binary_sha256"],
            selected["binary"], selected["binary"]))
    expected = {"catchplate": {legacy.APP_DELTA, legacy.DIGEST_DELTA},
        "decision-gate-rs": {legacy.BINARY_DELTA}}.get(name, set())
    require(changes == expected, "candidate exact configuration")
    return set()


def compare_model(model, observed, images, *, provider_custody=PROVIDER_CUSTODY,
                  digest_file=legacy.file_digest, phase="proposed", transition_mode="migration"):
    selected = selection(transition_mode)
    require(phase in {"proposed", "deployed"}, "comparison phase")
    legacy.validate_model(model)
    require(set(observed) == legacy.SERVICES, "exact retained services")
    changes = set()
    compare = compare_service if phase == "proposed" else compare_candidate_runtime
    for name in sorted(legacy.SERVICES):
        proposed = model["services"][name]
        changes.update(compare(name, proposed, observed[name], images[proposed["image"]], model["networks"],
            provider_custody=provider_custody, digest_file=digest_file, transition_mode=transition_mode))
    require(changes == (selected["approved_deltas"] if phase == "proposed" else set()), "closed managed transition")
    result = {"ok": True, "schema": "catchplate.operatorManagedDeploymentReview/v1", "phase": phase,
        "sourceCommit": selected["commit"], "candidateBinarySha256": selected["binary_sha256"], "approvedDifferences": sorted(changes),
        "notificationsRetained": True, "retainedServicesMustNotBeRecreated": ["demo-upstream", "edge"],
        "providerCustodyMetadataVerified": False, "curatedFilesystemVerified": False,
        "runtimeMutationsPerformed": False, "rolloutVerified": False}
    if transition_mode == "retained":
        result["transitionMode"] = "retained"
    return result


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
    return {"ok": True, "schema": "catchplate.operatorManagedProviderDirectoryReview/v1", "empty": True,
        "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
        "device": info.st_dev, "inode": info.st_ino, "retainedDirectoryAliasesAbsent": True,
        "privateFileContentsRead": False, "runtimeMutationsPerformed": False, "rolloutVerified": False}


def _retained_compiler_join(selected):
    """Exact original receipt contract, not a newly generated compatibility receipt."""
    return {
        "schema": "catchplate.pythonSnapshotCompilerEquality/v1",
        "sourceCommit": selected["commit"],
        "sourceTree": "23e2f96a8c0e9b9fbfbc25b272b1e42ccffe2f1e",
        "sourceManifestSha256": selected["source_manifest_sha256"],
        "archiveSha256": "dd87e896b23be7c1698b1f242986692c22a1e32e889235870656e9a4d1e1ceb5",
        "binaryBuildCommit": selected["compiler_source_commit"],
        "binaryBuildTree": "47359a0e049d1d9a731568e9de05264f93bf9b6f",
        "binarySha256": selected["binary_sha256"],
        "buildReceiptSha256": "b4679c6b62b9e0add258fdc419b560d16be94e945025fc90298e881567e74382",
        "compilerDepfileSha256": "63634621f9bf9c5cd273065f21175b89830de4d74a27daa603c1249f7f1ad880",
        "cargoManifestAndLockMatched": True,
        "compilerInputGitModesMatched": True,
        "completeCrateFilesMatched": 745,
        "completeGitTreeEqualityClaimed": False,
        "exactCompilerInputFilesMatched": selected["compiler_input_files"],
        "newRustBuildClaimed": selected["new_build"],
        "freshRustTestsRun": 0,
        "retainedRustTestCommit": RETAINED_COMPILER_COMMIT,
        "retainedRustTestCount": 116,
        "retainedRustTestReceiptSha256": "fc98d3de725e82c22faa26fb6bd71d3853b2394717cdc977f4f8e73d401fdd88",
        "allowedSourceChanges": [
            "docs/operator-npm-publish.md", "scripts/check_operator_npm_publish.py",
            "scripts/test_operator_catalog_header_replacement.py",
            "scripts/test_operator_catalog_mutation_receipts.py", "scripts/test_operator_catalog_timing.py",
            "scripts/test_operator_npm_publish_breadcrumbs.py", "catchplate/app.py",
            "catchplate/operator_catalog_api.py", "catchplate/operator_catalog_mutations.py",
            "catchplate/operator_catalog_timing.py",
        ],
        "externalCompilerInputs": [
            "schemas/adapters/generic.rest.schema.json", "schemas/adapters/gmail.read.v1.schema.json",
            "schemas/adapters/gmail.v1.schema.json", "schemas/adapters/npm.metadata.v1.schema.json",
            "schemas/adapters/npm.publish.v1.schema.json", "schemas/adapters/npm.registry.schema.json",
            "schemas/adapters/x.v2.schema.json", "schemas/policy-bundle.v1.schema.json",
            "schemas/policy-bundle.v2.schema.json",
        ],
    }


def _validate_retained_compiler_join(join, selected):
    expected = _retained_compiler_join(selected)
    require(type(join) is dict and set(join) == set(expected), "retained compiler equality fields")
    for key, value in expected.items():
        actual = join[key]
        # Python equality alone would admit True == 1 and False == 0.
        require(type(actual) is type(value) and actual == value, "retained compiler equality value")
        if type(value) is list:
            require(all(type(item) is str for item in actual), "retained compiler equality list")


def source_identity(source, source_manifest, *, transition_mode="migration"):
    selected = selection(transition_mode)
    require(str(source) == selected["source"], "exact rehearsed source")
    files = archives.source_inventory(source, source_manifest, selected["source_manifest_sha256"], selected["commit"])
    require(len(files) == selected["source_files"], "rehearsed file inventory")
    for directory, _, names in os.walk(source):
        require(stat.S_IMODE(Path(directory).stat().st_mode) == 0o555, "immutable source directories")
        require(all(stat.S_IMODE((Path(directory) / name).stat().st_mode) in {0o444, 0o555} for name in names), "immutable source files")
    _, _, old_sha, new_sha, old_binary, new_binary = selected["transition"]
    require(legacy.file_digest(old_binary) == old_sha and legacy.file_digest(new_binary) == new_sha, "paired binary bytes")
    join = archives.pinned_json(selected["join_path"], selected["join_sha256"])
    if transition_mode == "retained":
        _validate_retained_compiler_join(join, selected)
        return
    require(join == {"binarySha256": selected["binary_sha256"], "binarySourceCommit": selected["compiler_source_commit"],
        "cargoManifestAndLockMatched": True, "completeGitTreeEqualityClaimed": False,
        "exactCompilerInputFilesMatched": selected["compiler_input_files"], "newRustBuildClaimed": selected["new_build"],
        "sourceCommit": selected["commit"], "sourceManifestSha256": selected["source_manifest_sha256"]}, "retained compiler input join")


def current_traefik_peer(edge):
    """Match the retained /32 to the actual single running Swarm task.

    An edge's saved environment is configuration, not discovery: the task's
    overlay address can change while that edge remains healthy. Refuse stale
    values; do not rewrite the environment, use a VIP, or broaden the allowlist.
    The returned public identity is sampled again after the model comparison.
    """
    values = legacy.command_json(["docker", "service", "inspect", TRAEFIK_SERVICE])
    require(type(values) is list and len(values) == 1, "Traefik service selection")
    service = values[0]
    service_id = service["ID"]
    require(type(service_id) is str and re.fullmatch(r"[a-z0-9]{25}", service_id)
        and service["Spec"]["Name"] == TRAEFIK_SERVICE, "Traefik service identity")
    task_ids = legacy.command(["docker", "service", "ps", "--no-trunc", "--filter",
        "desired-state=running", "--format", "{{.ID}}", service_id]).decode("ascii").splitlines()
    require(len(task_ids) == 1 and re.fullmatch(r"[a-z0-9]{25}", task_ids[0]), "single current Traefik task")
    values = legacy.command_json(["docker", "inspect", "--type", "task", task_ids[0]])
    require(type(values) is list and len(values) == 1, "Traefik task inspection")
    task = values[0]
    require(task["ID"] == task_ids[0] and task["ServiceID"] == service_id
        and task["DesiredState"] == "running" and task["Status"]["State"] == "running",
        "current running Traefik task")
    container_id = task["Status"]["ContainerStatus"]["ContainerID"]
    require(type(container_id) is str and re.fullmatch(r"[0-9a-f]{64}", container_id), "Traefik task container")
    values = legacy.command_json(["docker", "inspect", "--type", "container", container_id])
    require(type(values) is list and len(values) == 1, "Traefik container inspection")
    container = values[0]
    labels, state = container["Config"]["Labels"], container["State"]
    require(container["Id"] == container_id and labels.get("com.docker.swarm.service.id") == service_id
        and labels.get("com.docker.swarm.service.name") == TRAEFIK_SERVICE
        and labels.get("com.docker.swarm.task.id") == task_ids[0]
        and state["Running"] is True and state["Paused"] is False and state["Restarting"] is False
        and state["Dead"] is False and type(state["Pid"]) is int and state["Pid"] > 0,
        "running Traefik container identity")
    network = container["NetworkSettings"]["Networks"][TRAEFIK_NETWORK]
    edge_network = edge["NetworkSettings"]["Networks"][TRAEFIK_NETWORK]
    network_id, peer = network["NetworkID"], network["IPAddress"]
    require(type(network_id) is str and re.fullmatch(r"[a-z0-9]{25}", network_id)
        and edge_network["NetworkID"] == network_id
        and sum(row.get("Target") == network_id for row in service["Spec"]["TaskTemplate"]["Networks"]) == 1,
        "shared current Traefik overlay")
    try:
        address = ipaddress.IPv4Address(peer)
    except (ValueError, TypeError):
        raise Refused("Traefik overlay IPv4") from None
    require(type(peer) is str and str(address) == peer and not address.is_unspecified
        and not address.is_multicast and not address.is_loopback and not address.is_link_local
        and peer != edge_network["IPAddress"], "Traefik overlay IPv4")
    require(legacy.envmap(edge["Config"].get("Env")).get("TRAEFIK_IPV4") == peer,
        "edge allowlist must match current Traefik task")
    return {"serviceId": service_id, "serviceVersion": service["Version"]["Index"],
        "taskId": task_ids[0], "containerId": container_id, "network": network,
        "pid": state["Pid"], "startedAt": state["StartedAt"], "ipv4": peer}


def review(args):
    transition_mode = getattr(args, "transition_mode", "migration")
    selected = selection(transition_mode)
    provider_path(args.provider_custody)
    source_identity(args.source, args.source_manifest, transition_mode=transition_mode)
    fingerprints = {path: legacy.file_digest(path) for path in selected["layers"]}
    require(fingerprints == selected["pins"], "fixed Compose layers")
    observed = legacy.discover()
    traefik = current_traefik_peer(observed["edge"])
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TRAEFIK_IPV4": traefik["ipv4"],
        "OPERATOR_MANAGED_SOURCE": selected["source"], "OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR": str(args.provider_custody),
        "OPERATOR_DEMO_NOTIFICATIONS_ENABLED": "1", "OPERATOR_DEMO_NOTIFICATIONS_CUSTODY_DIR": legacy.CUSTODY}
    command = ["docker", "compose", "-p", legacy.PROJECT, "--env-file", legacy.ENVFILE]
    for layer in selected["layers"]:
        command.extend(("-f", str(layer)))
    model = legacy.command_json([*command, "config", "--format", "json"], environment=environment)
    images = {}
    for proposed in model["services"].values():
        reference = proposed["image"]
        if reference not in images:
            values = legacy.command_json(["docker", "image", "inspect", reference])
            require(isinstance(values, list) and len(values) == 1, "cached image identity")
            images[reference] = values[0]
    result = compare_model(model, observed, images, provider_custody=args.provider_custody, phase=args.phase,
        transition_mode=transition_mode)
    after = legacy.discover()
    for name in legacy.SERVICES:
        old, new = observed[name], after[name]
        require(all(old[key] == new[key] for key in ("Id", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings"))
            and old["State"]["Pid"] == new["State"]["Pid"] and old["State"]["StartedAt"] == new["State"]["StartedAt"],
            "stable inspection identity")
    require(current_traefik_peer(after["edge"]) == traefik, "stable current Traefik task and peer")
    require({path: legacy.file_digest(path) for path in selected["layers"]} == fingerprints, "stable Compose layers")
    source_identity(args.source, args.source_manifest, transition_mode=transition_mode)
    return {**result, "sourceFilesVerified": selected["source_files"], "compilerInputFilesMatched": selected["compiler_input_files"],
        "edgePeerFromCurrentInspection": True, "services": [{"service": name, "id": observed[name]["Id"]}
            for name in sorted(legacy.SERVICES)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    model = commands.add_parser("review")
    for name in ("source", "source-manifest", "provider-custody"):
        model.add_argument("--" + name, type=Path, required=True)
    model.add_argument("--phase", choices=("proposed", "deployed"), default="proposed")
    model.add_argument("--transition-mode", choices=("migration", "retained"), default="migration",
        help="Explicit already-managed upgrade; refuses until its separate fixed candidate receipt is pinned.")
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
