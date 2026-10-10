#!/usr/bin/env python3
"""Read-only comparison for the exact paired operator-demo candidate.

Explicit invocation renders Compose and inspects existing containers/images.
It never starts, stops, recreates, builds, pulls or writes deployment state.
Private environment/image defaults are compared only in memory, never emitted.
Passing is a configuration review, not rollout authorization or runtime proof.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess

PROJECT = "serverware-operator-demo"
STACK = Path("/srv/catchplate-fast/projects/serverware-operator-workspace/docker/serverware-operator-demo")
ENVFILE = "/srv/catchplate-fast/tmp/serverware-browser-handoff.67Dtng/source/docker/serverware-operator-demo/.env"
BASE, NOTIFICATIONS = STACK / "docker-compose.yml", STACK / "docker-compose.notifications.yml"
CANDIDATE = STACK / "docker-compose.destinations-candidate.yml"
PINS = {BASE: "c088fd890afd20fa2f09073913deed2f2542c58715d45a53149b6ca4ec9e5300",
    NOTIFICATIONS: "27d5d13613c9210047614db346ab00cc7b46980b4665d09650272e5e3d53254a"}
ARTIFACTS = "/srv/catchplate-fast/projects/serverware-operator-artifacts/"
OLD_SOURCE = ARTIFACTS + "source-b897d1aa51c70e23afaafc57e989e3f366939548"
NEW_COMMIT = "577badff84b32eea052c53d6df8f6fd5de61d66a"
NEW_SOURCE = ARTIFACTS + "source-" + NEW_COMMIT
OLD_SHA = "e7529b4484228ebdbf2be1ebb471a80a78a3e127673f0bc6dcb4921db92489e2"
NEW_SHA = "2bfe5e384d7e9c655de70704c25350c16336c55a2584fc59f363f12164f297d6"
OLD_BINARY, NEW_BINARY = (ARTIFACTS + "sha256-" + value + "/serverware-decision-gate" for value in (OLD_SHA, NEW_SHA))
BINARY_TARGET = "/usr/local/bin/serverware-decision-gate"
EXPECTED_DIGEST = "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"
CUSTODY = "/srv/catchplate-fast/homelab_data/serverware-operator-demo-notifications"
SERVICES = frozenset(("serverware", "decision-gate-rs", "edge", "demo-upstream"))
NOTIFICATION_ENV = {"SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED": "1",
    "SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR": "/notification-custody",
    "SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON": '{"bindings":[]}'}
APP_DELTA, DIGEST_DELTA, BINARY_DELTA = "serverware /app source", "serverware expected gate digest", "decision-gate-rs executable bind"
APPROVED_DELTAS = frozenset((APP_DELTA, DIGEST_DELTA, BINARY_DELTA))
MODEL_NETWORKS = {
    "sandbox": {"name": PROJECT + "_sandbox", "internal": True,
        "ipam": {"config": [{"subnet": "172.16.249.16/28"}]}},
    "outbound": {"name": PROJECT + "_outbound", "ipam": {"config": [{"subnet": "172.16.249.32/29"}]}},
    "traefik-v3-public": {"name": "traefik-v3-public", "external": True, "ipam": {}},
}
# Compose retains this exact extension from the independently hash-pinned base.
# It is not a license to discard arbitrary top-level keys or changed settings.
BASE_EXTENSION = {"pull_policy": "never", "restart": "unless-stopped", "user": "10001:10001",
    "init": True, "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
    "pids_limit": 128, "networks": ["sandbox"], "dns": ["127.0.0.1"],
    "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700"],
    "logging": {"driver": "local", "options": {"max-size": "2m", "max-file": "2"}}}


class Refused(Exception):
    """Only fixed, non-secret comparison stages may be exposed."""


def require(value, stage):
    if not value:
        raise Refused(stage)


def command(arguments, *, environment=None):
    result = subprocess.run(arguments, capture_output=True, timeout=30, check=False, env=environment)
    require(result.returncode == 0 and len(result.stdout) <= 8 * 1024**2 and len(result.stderr) <= 1024**2,
        "read-only command")
    return result.stdout


def command_json(arguments, *, environment=None):
    return json.loads(command(arguments, environment=environment))


def file_digest(path):
    value = Path(path)
    require(value.is_absolute() and value.resolve() == value and value.is_file()
        and not value.is_symlink() and value.stat().st_size <= 128 * 1024**2, "public artifact path")
    with value.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def envmap(items):
    require(isinstance(items or [], list) and all(isinstance(item, str) for item in items or []), "environment encoding")
    pairs = [item.split("=", 1) for item in items or []]
    require(all(len(pair) == 2 and pair[0] for pair in pairs), "environment encoding")
    value = dict(pairs)
    require(len(value) == len(pairs), "duplicate environment key")
    return value


def duration(value):
    if type(value) is int:
        return value
    require(isinstance(value, str), "duration format")
    units = {"ns": 1, "us": 1000, "ms": 1000000, "s": 1000000000, "m": 60000000000, "h": 3600000000000}
    pieces = re.findall(r"(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)", value)
    require(pieces and "".join(number + unit for number, unit in pieces) == value, "duration format")
    total = sum(Decimal(number) * units[unit] for number, unit in pieces)
    require(total == int(total), "duration precision")
    return int(total)


def hosts(value):
    pairs = []
    if isinstance(value, dict):
        for name, addresses in value.items():
            for address in addresses if isinstance(addresses, list) else [addresses]:
                pairs.append((name, address))
    else:
        require(value is None or isinstance(value, list), "extra hosts format")
        for row in value or []:
            require(isinstance(row, str), "extra hosts format")
            pair = row.split("=", 1) if "=" in row else row.split(":", 1)
            require(len(pair) == 2, "extra hosts format")
            pairs.append(tuple(pair))
    require(all(isinstance(name, str) and name and isinstance(address, str) and address for name, address in pairs)
        and len(set(pairs)) == len(pairs), "extra hosts encoding")
    return sorted(pairs)


def validate_model(model):
    require(set(model) == {"name", "services", "networks", "x-isolated"} and model["name"] == PROJECT
        and set(model["services"]) == SERVICES, "candidate service and network set")
    require(model["x-isolated"] == BASE_EXTENSION, "retained base extension")
    require(model["networks"] == MODEL_NETWORKS, "retained network definitions")


def discover():
    raw = command(["docker", "ps", "--no-trunc", "--filter", "label=com.docker.compose.project=" + PROJECT,
        "--format", "{{.ID}}"])
    identifiers = raw.decode("ascii").splitlines()
    require(len(identifiers) == len(SERVICES) and len(set(identifiers)) == len(identifiers)
        and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in identifiers), "running project container set")
    observed = command_json(["docker", "inspect", *sorted(identifiers)])
    require(isinstance(observed, list) and len(observed) == len(SERVICES), "inspected container set")
    result = {}
    for live in observed:
        labels = live["Config"]["Labels"]
        name = labels.get("com.docker.compose.service")
        require(labels.get("com.docker.compose.project") == PROJECT and name in SERVICES and name not in result
            and live["Id"] in identifiers and labels.get("com.docker.compose.oneoff", "False").lower() == "false",
            "exact project service identity")
        require(live["State"]["Running"] is True and live["State"]["Health"]["Status"] == "healthy"
            and live["RestartCount"] == 0, name + " health")
        result[name] = live
    require(set(result) == SERVICES, "exact project service set")
    return result


def compare_service(name, proposed, live, image, networks, digest_file=file_digest, *, transition=None):
    """Compare effective settings; do not return environments or engine objects."""
    # Existing callers retain the exact historical pair. A separate closed
    # reviewer may supply its independently admitted pair without mutating
    # these module constants or weakening any retained-setting comparison.
    old_source, new_source, old_sha, new_sha, old_binary, new_binary = (
        (OLD_SOURCE, NEW_SOURCE, OLD_SHA, NEW_SHA, OLD_BINARY, NEW_BINARY)
        if transition is None else transition)
    config, host = live["Config"], live["HostConfig"]
    image_config = image["Config"]
    deltas = set()
    require(set(proposed) <= {"image", "pull_policy", "restart", "user", "init", "read_only", "cap_drop", "cap_add",
        "security_opt", "pids_limit", "networks", "dns", "dns_search", "dns_opt", "extra_hosts", "tmpfs", "logging",
        "cpus", "mem_limit", "memswap_limit", "working_dir", "command", "entrypoint", "environment", "volumes",
        "depends_on", "healthcheck", "labels"}, name + " unsupported service setting")
    dependencies = proposed.get("depends_on", {})
    expected_dependency = {"serverware": "demo-upstream", "decision-gate-rs": "serverware"}.get(name)
    require(set(dependencies) == ({expected_dependency} if expected_dependency else set())
        and all(set(value) <= {"condition", "required"} and value.get("condition") == "service_healthy"
            and value.get("required", True) is True for value in dependencies.values()), name + " retained dependencies")
    require(image["Id"] == live["Image"] and proposed.get("pull_policy") == "never" and not proposed.get("build"), name + " image")
    expected_env = envmap(image_config.get("Env")); expected_env.update(proposed.get("environment", {}))
    actual_env = envmap(config.get("Env"))
    if name == "edge":
        require(expected_env.get("NGINX_ENVSUBST_FILTER") == "^TRAEFIK_IPV4$$", "edge filter model")
        expected_env["NGINX_ENVSUBST_FILTER"] = "^TRAEFIK_IPV4$"
    if name == "serverware":
        require(actual_env.get(EXPECTED_DIGEST) == "sha256:" + old_sha
            and expected_env.get(EXPECTED_DIGEST) == "sha256:" + new_sha, "exact paired expected gate digest")
        require({key: value for key, value in actual_env.items() if key.startswith("SERVERWARE_OPERATOR_NOTIFICATIONS_")}
            == NOTIFICATION_ENV, "retained enabled notification configuration")
        expected_env[EXPECTED_DIGEST] = actual_env[EXPECTED_DIGEST]
        deltas.add(DIGEST_DELTA)
    require(actual_env == expected_env, name + " retained environment")
    require(config["User"] == proposed.get("user", image_config.get("User", ""))
        and host["ReadonlyRootfs"] == proposed.get("read_only", False), name + " identity")
    for engine_key, compose_key in (("Cmd", "command"), ("Entrypoint", "entrypoint")):
        selected = proposed.get(compose_key)
        expected = (image_config.get(engine_key) if selected is None else selected) or []
        if selected is not None:
            require(isinstance(expected, list), name + " process shape")
            expected = [item.replace("$$", "$") for item in expected]
        require((config.get(engine_key) or []) == expected, name + " process")
    require(config.get("WorkingDir", "") == proposed.get("working_dir", image_config.get("WorkingDir", "")), name + " working directory")
    require(host["Memory"] == int(proposed["mem_limit"]) and host["NanoCpus"] == round(float(proposed["cpus"]) * 1000000000)
        and host["PidsLimit"] == proposed["pids_limit"]
        and host["MemorySwap"] == int(proposed.get("memswap_limit", 2 * int(proposed["mem_limit"]))), name + " resource bounds")
    require(host["RestartPolicy"]["Name"] == proposed["restart"] and host["RestartPolicy"].get("MaximumRetryCount", 0) == 0
        and bool(host.get("Init")) == proposed.get("init", False), name + " lifecycle")
    require(sorted(host.get("CapDrop") or []) == sorted(proposed.get("cap_drop", []))
        and sorted(host.get("CapAdd") or []) == sorted(proposed.get("cap_add", [])), name + " capabilities")
    normalize_security = lambda values: sorted(value.removesuffix(":true") for value in values or [])
    require(normalize_security(host.get("SecurityOpt")) == normalize_security(proposed.get("security_opt")), name + " security options")
    require(not host.get("Privileged") and not proposed.get("privileged") and not host.get("Devices")
        and not proposed.get("devices") and not proposed.get("network_mode") and not proposed.get("pid")
        and not proposed.get("ipc") and not proposed.get("volumes_from"), name + " namespace boundary")
    require((host.get("Dns") or []) == proposed.get("dns", [])
        and (host.get("DnsSearch") or []) == proposed.get("dns_search", [])
        and (host.get("DnsOptions") or []) == proposed.get("dns_opt", [])
        and hosts(host.get("ExtraHosts")) == hosts(proposed.get("extra_hosts")), name + " DNS and explicit hosts")
    require(not host.get("PortBindings") and not proposed.get("ports")
        and not any(live["NetworkSettings"]["Ports"].values()), name + " host ports")
    expected_tmpfs = dict(item.split(":", 1) for item in proposed.get("tmpfs", []))
    require({key: sorted(value.split(",")) for key, value in (host.get("Tmpfs") or {}).items()}
        == {key: sorted(value.split(",")) for key, value in expected_tmpfs.items()}, name + " tmpfs")
    require(host["LogConfig"]["Type"] == proposed["logging"]["driver"]
        and host["LogConfig"]["Config"] == proposed["logging"]["options"], name + " logging")
    expected_labels = {**(image_config.get("Labels") or {}), **proposed.get("labels", {})}
    require({key: value for key, value in config["Labels"].items() if not key.startswith("com.docker.compose.")}
        == expected_labels, name + " auth and service labels")
    expected_networks = {networks[key]["name"]: value for key, value in proposed["networks"].items()}
    require(set(live["NetworkSettings"]["Networks"]) == set(expected_networks), name + " networks")
    for key, selected in expected_networks.items():
        require(set(selected) <= {"ipv4_address", "ipv6_address", "aliases"}, name + " network settings")
        actual = live["NetworkSettings"]["Networks"][key]
        ipam = actual.get("IPAMConfig") or {}
        # The existing external overlay records its dynamically allocated IP in
        # IPAMConfig too. Only this exact empty Compose attachment leaves address
        # selection to that network; sandbox/outbound selections remain exact.
        external_dynamic = (key == "traefik-v3-public" and selected == {}
            and networks.get("traefik-v3-public") == MODEL_NETWORKS["traefik-v3-public"])
        if not external_dynamic:
            require((ipam.get("IPv4Address") or "") == selected.get("ipv4_address", "")
                and (ipam.get("IPv6Address") or "") == selected.get("ipv6_address", ""), name + " retained static address selection")
        for setting, observed in (("ipv4_address", "IPAddress"), ("ipv6_address", "GlobalIPv6Address")):
            if selected.get(setting):
                require(actual[observed] == selected[setting], name + " network address")
        if selected.get("aliases"):
            require(set(selected["aliases"]) <= set(actual.get("Aliases") or []), name + " network aliases")
    require(set(proposed["healthcheck"]) == {"test", "interval", "timeout", "start_period", "retries"}, name + " healthcheck fields")
    for key, engine_key in (("test", "Test"), ("interval", "Interval"), ("timeout", "Timeout"), ("start_period", "StartPeriod"), ("retries", "Retries")):
        value = proposed["healthcheck"][key]
        if key == "test":
            value = [item.replace("$$", "$") for item in value]
        require(config["Healthcheck"][engine_key] == (duration(value) if key in {"interval", "timeout", "start_period"} else value), name + " healthcheck")
    require(not proposed["healthcheck"].get("disable") and not proposed["healthcheck"].get("start_interval"), name + " healthcheck extras")
    mounts = {item["Destination"]: item for item in live["Mounts"]}
    targets = {item["target"] for item in proposed["volumes"]}
    require(len(mounts) == len(live["Mounts"]) and len(targets) == len(proposed["volumes"])
        and set(mounts) == targets, name + " exact mount targets")
    for volume in proposed["volumes"]:
        actual = mounts[volume["target"]]
        require(set(volume) <= {"type", "source", "target", "read_only", "bind"}
            and set(volume.get("bind", {})) <= {"create_host_path", "propagation"}
            and actual["Type"] == volume["type"] == "bind" and actual["RW"] == (not volume.get("read_only", False))
            and volume.get("bind", {}).get("create_host_path") is False
            and actual.get("Propagation", "rprivate") == volume.get("bind", {}).get("propagation", "rprivate"), name + " mount boundary")
        if name == "serverware" and volume["target"] == "/app":
            require(actual["Source"] == old_source and volume["source"] == new_source and volume.get("read_only") is True, "exact app source change")
            deltas.add(APP_DELTA)
        elif name == "decision-gate-rs" and volume["target"] == BINARY_TARGET:
            require(actual["Source"] == old_binary and volume["source"] == new_binary and volume.get("read_only") is True, "exact gate executable change")
            deltas.add(BINARY_DELTA)
        elif name == "edge" and volume["target"] == "/etc/nginx/templates/nginx.conf.template":
            require(Path(actual["Source"]).name == "nginx.conf.template" and volume["source"] == str(STACK / "config/nginx.conf.template")
                and digest_file(actual["Source"]) == digest_file(volume["source"]), "byte-identical retained edge template")
        else:
            require(actual["Source"] == volume["source"], name + " retained mount source")
        if volume["source"] == CUSTODY:
            require(name == "serverware" and volume["target"] == "/notification-custody" and actual["RW"] is True, "app-only retained notification custody")
    return deltas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-override", type=Path, default=CANDIDATE)
    args = parser.parse_args()
    layer = args.candidate_override
    require(layer.is_absolute() and layer.parent == STACK and layer.name.startswith("docker-compose.")
        and layer.suffix == ".yml" and layer not in PINS, "candidate layer path")
    fingerprints = {path: file_digest(path) for path in (*PINS, layer)}
    require(all(fingerprints[path] == value for path, value in PINS.items()), "retained Compose layer digest")
    require(Path(NEW_SOURCE).is_dir() and Path(NEW_SOURCE).resolve() == Path(NEW_SOURCE), "candidate immutable source")
    require(file_digest(OLD_BINARY) == OLD_SHA and file_digest(NEW_BINARY) == NEW_SHA, "paired executable digests")
    def expired(*_): raise Refused("review deadline")
    signal.signal(signal.SIGALRM, expired); signal.alarm(150)
    environment = os.environ.copy()
    environment.update(OPERATOR_DEMO_NOTIFICATIONS_ENABLED="1", OPERATOR_DEMO_NOTIFICATIONS_CUSTODY_DIR=CUSTODY)
    model = command_json(["docker", "compose", "-p", PROJECT, "--env-file", ENVFILE,
        "-f", str(BASE), "-f", str(layer), "-f", str(NOTIFICATIONS), "config", "--format", "json"], environment=environment)
    validate_model(model)
    observed, images, deltas = discover(), {}, set()
    for name in sorted(SERVICES):
        proposed = model["services"][name]
        reference = proposed["image"]
        if reference not in images:
            inspected = command_json(["docker", "image", "inspect", reference])
            require(isinstance(inspected, list) and len(inspected) == 1, "candidate cached image")
            images[reference] = inspected[0]
        deltas.update(compare_service(name, proposed, observed[name], images[reference], model["networks"]))
    require(deltas == APPROVED_DELTAS, "exact three paired changes")
    retained = discover()
    for name in SERVICES:
        before, after = observed[name], retained[name]
        require(all(before[key] == after[key] for key in ("Id", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings"))
            and before["State"]["Pid"] == after["State"]["Pid"]
            and before["State"]["StartedAt"] == after["State"]["StartedAt"], name + " stable inspection identity")
    require(all(file_digest(path) == value for path, value in fingerprints.items()), "Compose layers unchanged during review")
    signal.alarm(0)
    return {"ok": True, "schema": "serverware.operatorDemoDeploymentReview/v1", "sourceCommit": NEW_COMMIT,
        "candidateBinarySha256": NEW_SHA, "approvedDifferences": sorted(deltas),
        "notificationsRetained": True, "retainedServicesMustNotBeRecreated": ["demo-upstream", "edge"],
        "edgeTemplateBytesEqual": True, "runtimeMutationsPerformed": False, "rolloutVerified": False,
        "services": [{"service": name, "id": observed[name]["Id"], "healthy": True, "restarts": 0}
            for name in sorted(SERVICES)]}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except Refused as error:
        print(json.dumps({"ok": False, "stage": str(error), "error": "candidate comparison refused"}))
        raise SystemExit(1)
    except Exception:
        print('{"ok":false,"error":"candidate comparison refused"}')
        raise SystemExit(1)
