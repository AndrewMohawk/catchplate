#!/usr/bin/env python3
"""Render/preflight the private catalog fixture; never initialize or launch it.

Default is read-only, including an as-yet nonexistent exact job root. --write
may only populate a caller-created, owned, empty0700 NVMe job directory. Runtime
initialization/launch/acceptance/cleanup remain separate reviewed operations.
No Compose inheritance, relay, edge, host ports, outbound or live data mounts.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess


SCRATCH = Path("/srv/catchplate-fast/tmp")
APP_IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"
FIXTURE_IMAGE = "sha256:13fba0146806ccc218afd91dbc2c9087f5d8abdb16fc8c7acbe3c3448e79937d"
GATE_IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
BINARY_SHA256 = "c03ee35ca70ec145b23fea632ab6b73af8203272eabf48f65d16220b56a7b57a"
INITIALIZER_SHA256 = "484e2cc7f0c4eea0439537e7a1035f7d63b389380e91a29b258a10a97b272b97"
ORIGIN = "https://catchplate-demo.example.com"
INSTANCE = "spiffe://operator-demo.catchplate/decision-gate/local"
ROLES = ("admin", "credential-lease", "audit", "grant-consume", "rate-limit-consume", "release-authorization", "management")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def bind(source, target, readonly=True):
    return {"type": "bind", "source": str(source), "target": target,
        "read_only": readonly, "bind": {"create_host_path": False}}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validated_binary_sha256(value: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "expected executable digest must be bare lowercase SHA-256")
    return value


def build(source: Path, binary: Path, initializer: Path, root: Path, subnet: str, *,
          expected_binary_sha256: str = BINARY_SHA256):
    """Pure manifest builder: no filesystem, processes, sockets or writes."""
    expected_binary_sha256 = validated_binary_sha256(expected_binary_sha256)
    require(root.parent == SCRATCH and re.fullmatch(r"catchplate-catalog-private\.[A-Za-z0-9]{6,32}", root.name),
            "new catalog NVMe job root required")
    require(all(path.is_absolute() and ".." not in path.parts for path in (source, binary, initializer)),
            "exact source, executable and initializer paths required")
    network = ipaddress.ip_network(subnet, strict=True)
    require(network.version == 4 and network.prefixlen == 28
            and network.subnet_of(ipaddress.ip_network("172.16.0.0/12")), "private IPv4 /28 required")
    addresses = {name: str(network.network_address + offset) for name, offset in (
        ("demo-upstream", 2), ("catchplate", 3), ("decision-gate-rs", 4))}
    runtime = root / "runtime"
    project = "catchplate-catalog-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    common = {"image": GATE_IMAGE, "pull_policy": "never", "restart": "no", "user": "10001:10001",
        "init": True, "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "pids_limit": 64, "cpus": 0.5, "mem_limit": "256m", "memswap_limit": "256m", "working_dir": "/app", "dns": ["127.0.0.1"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700"],
        "logging": {"driver": "local", "options": {"max-size": "2m", "max-file": "2"}},
        "labels": {"traefik.enable": "false", "com.centurylinklabs.watchtower.enable": "false"}}
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app", "CATCHPLATE_OPERATOR_DEMO": "1",
        "CATCHPLATE_RELEASE_CHANNEL": "dev", "CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": '["https://demo-upstream:8443"]',
        "CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS": json.dumps([addresses["demo-upstream"] + "/32"]),
        # Required HTTPS profile metadata, not a tested/resolved/public endpoint.
        "CATCHPLATE_OPERATOR_DEMO_PROXY_URL": "https://catchplate-proxy.example.com",
        "CATCHPLATE_DATA_PLANE_INSTANCE_ID": INSTANCE}
    services = {name: {**deepcopy(common), "networks": {"fixture": {"ipv4_address": address}}}
        for name, address in addresses.items()}
    app = services["catchplate"]
    app.update(image=APP_IMAGE, cpus=2, mem_limit="1g", memswap_limit="1g", pids_limit=128,
        command=["python", "-B", "-m", "catchplate.operator_demo_runner"],
        depends_on={"demo-upstream": {"condition": "service_healthy"}})
    app["environment"] = {**env, "CATCHPLATE_DATA_DIR": "/data", "CATCHPLATE_PUBLIC_URL": ORIGIN,
        "CATCHPLATE_DIRECT_CA_DOWNLOAD_ENABLED": "1", "CATCHPLATE_ADMIN_USER": "user:operator-demo-operator",
        "CATCHPLATE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "CATCHPLATE_DECISION_GATE_BASE": "http://decision-gate-rs:9091",
        "CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST": "sha256:" + expected_binary_sha256}
    for role in ROLES:
        prefix = "ADMIN" if role == "admin" else "DATA_PLANE_" + role.upper().replace("-", "_")
        app["environment"]["CATCHPLATE_" + prefix + "_TOKEN_FILE"] = "/run/secrets/catchplate/" + role + ".token"
    app["volumes"] = [bind(source, "/app"), bind(runtime / "app-data", "/data", False),
        bind(runtime / "service-secrets", "/run/secrets/catchplate"),
        bind(runtime / "upstream-data/demo-upstream", "/demo-upstream"),
        bind(runtime / ".private-fixture.json", "/private-audit-fixture.json")]
    app["healthcheck"] = health("http://127.0.0.1:3000/healthz", start=30)
    fixture = services["demo-upstream"]
    fixture.update(image=FIXTURE_IMAGE, command=["python", "-B", "scripts/demo_upstream.py"],
        environment={"PYTHONDONTWRITEBYTECODE": "1"},
        volumes=[bind(source, "/app"), bind(runtime / "upstream-data", "/data", False)])
    fixture["healthcheck"] = {"test": ["CMD", "python", "-c",
        "import ssl,urllib.request; c=ssl.create_default_context(cafile='/data/demo-upstream/ca.pem'); "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
        "r=o.open('https://demo-upstream:8443/_test/request-count?method=GET&path=%2Fecho',timeout=2); "
        "raise SystemExit(0 if r.status==200 else 1)"], "interval": "3s", "timeout": "3s", "retries": 10,
        "start_period": "10s"}
    gate = services["decision-gate-rs"]
    gate.update(entrypoint=["/usr/local/bin/catchplate-decision-gate"], command=[], cpus=1,
        mem_limit="512m", memswap_limit="512m", pids_limit=128, depends_on={"catchplate": {"condition": "service_healthy"}})
    gate["environment"] = {**env, "CATCHPLATE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES": "1",
        "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0", "CATCHPLATE_POLICY_BUNDLE": "/data/policy-bundle.json",
        "CATCHPLATE_POLICY_HIGH_WATER_FILE": "/gate-data/policy-high-water.json",
        "CATCHPLATE_POLICY_TRUST_ROOT_ATTESTATION_URL": "http://catchplate:3000/attestation",
        "CATCHPLATE_CONTROL_PLANE_CREDENTIAL_LEASE_URL": "http://catchplate:3000/api/data-plane/credential-leases",
        "CATCHPLATE_CONTROL_PLANE_AUDIT_URL": "http://catchplate:3000/api/data-plane/audit",
        "CATCHPLATE_DATA_PLANE_AUDIT_BATCH_MAX": "16", "CATCHPLATE_DATA_PLANE_AUDIT_QUEUE_MAX": "256",
        "CATCHPLATE_DATA_PLANE_AUDIT_FLUSH_MS": "500", "CATCHPLATE_UPSTREAM_CA_BUNDLE": "/demo-upstream/ca.pem",
        "CATCHPLATE_MITM_CA_CERT": "/data/mitmproxy/mitmproxy-ca-cert.pem",
        "CATCHPLATE_MITM_CA_KEY": "/data/mitmproxy/mitmproxy-ca.pem",
        "CATCHPLATE_PROXY_INGRESS_MODE": "operator-demo-tls-edge", "CATCHPLATE_DECISION_GATE_HOST": "0.0.0.0",
        "CATCHPLATE_DECISION_GATE_PORT": "9090", "CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST": addresses["decision-gate-rs"],
        "CATCHPLATE_DECISION_GATE_MANAGEMENT_PORT": "9091"}
    gate["volumes"] = [bind(binary, "/usr/local/bin/catchplate-decision-gate"), bind(runtime / "app-data", "/data"),
        bind(runtime / "gate-data", "/gate-data", False), bind(runtime / "upstream-data/demo-upstream", "/demo-upstream")]
    for role in ("credential-lease", "audit", "management"):
        target = "/run/secrets/catchplate/" + role + ".token"
        gate["environment"]["CATCHPLATE_DATA_PLANE_" + role.upper().replace("-", "_") + "_TOKEN_FILE"] = target
        gate["volumes"].append(bind(runtime / "service-secrets" / (role + ".token"), target))
    gate["healthcheck"] = health("http://" + addresses["decision-gate-rs"] + ":9091/healthz", start=20)
    services["initialize"] = {**deepcopy(common), "profiles": ["prepare"], "user": "0:0", "network_mode": "none",
        "cap_add": ["CHOWN", "DAC_OVERRIDE"], "cpus": 0.25, "mem_limit": "64m", "memswap_limit": "64m", "pids_limit": 16,
        "working_dir": "/", "command": ["python", "-B", "/initialize.py"],
        "volumes": [bind(initializer, "/initialize.py"), bind(runtime, "/fixture-runtime", False)]}
    config = {"name": project, "services": services,
        "networks": {"fixture": {"internal": True, "ipam": {"config": [{"subnet": subnet}]}}}}
    validate(config, source, binary, initializer, root, expected_binary_sha256=expected_binary_sha256)
    return config


def health(url, *, start):
    return {"test": ["CMD", "python", "-c", "import json,urllib.request; "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('" + url + "',timeout=2); "
        "raise SystemExit(0 if r.status==200 and json.load(r).get('ok') is True else 1)"],
        "interval": "3s", "timeout": "3s", "retries": 20, "start_period": str(start) + "s"}


def validate(config, source, binary, initializer, root, *, expected_binary_sha256: str = BINARY_SHA256):
    expected_binary_sha256 = validated_binary_sha256(expected_binary_sha256)
    require(set(config["services"]) == {"initialize", "catchplate", "demo-upstream", "decision-gate-rs"},
            "unexpected fixture service")
    require(config["services"]["catchplate"]["environment"].get("CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST")
            == "sha256:" + expected_binary_sha256, "expected executable digest binding differs")
    require(set(config["networks"]) == {"fixture"} and config["networks"]["fixture"].get("internal") is True
            and not config["networks"]["fixture"].get("external"), "internal-only network required")
    runtime = root / "runtime"
    for name, service in config["services"].items():
        require(not any(service.get(key) for key in ("ports", "privileged", "devices", "pid", "ipc", "extra_hosts",
                    "volumes_from", "env_file", "extends")), "host exposure or external configuration refused")
        require(service.get("labels", {}).get("traefik.enable") == "false"
                and service.get("pull_policy") == "never" and service.get("read_only") is True
                and service.get("cap_drop") == ["ALL"] and service.get("security_opt") == ["no-new-privileges:true"]
                and service.get("restart") == "no" and service.get("dns") == ["127.0.0.1"], "security guard missing")
        require(0 < service.get("cpus", 0) <= 2 and 1 <= service.get("pids_limit", 0) <= 128
                and service.get("mem_limit") in {"64m", "256m", "512m", "1g"}
                and service.get("memswap_limit") == service.get("mem_limit"), "resource bounds missing")
        if name == "initialize":
            require(service.get("network_mode") == "none" and service.get("profiles") == ["prepare"]
                    and service.get("user") == "0:0" and service.get("cap_add") == ["CHOWN", "DAC_OVERRIDE"],
                    "initializer isolation differs")
        else:
            require(set(service.get("networks", {})) == {"fixture"} and not service.get("network_mode")
                    and service.get("user") == "10001:10001" and not service.get("cap_add"), "runtime isolation differs")
        for volume in service["volumes"]:
            path = Path(volume["source"])
            require(volume.get("type") == "bind" and volume.get("bind", {}).get("create_host_path") is False
                    and (path in {source, binary, initializer, runtime} or runtime in path.parents), "mount scope differs")
            require(volume.get("read_only") or path == runtime or runtime in path.parents, "source or executable writable")
    gate = config["services"]["decision-gate-rs"]
    require(gate["depends_on"] == {"catchplate": {"condition": "service_healthy"}}
            and config["services"]["catchplate"]["command"][-1] == "catchplate.operator_demo_runner",
            "gate must target the real catalog app, not a relay")
    for name, image in (("initialize", GATE_IMAGE), ("decision-gate-rs", GATE_IMAGE),
                       ("catchplate", APP_IMAGE), ("demo-upstream", FIXTURE_IMAGE)):
        require(config["services"][name]["image"] == image, "fixed image differs")
    for key, suffix in (("CATCHPLATE_POLICY_TRUST_ROOT_ATTESTATION_URL", "/attestation"),
                       ("CATCHPLATE_CONTROL_PLANE_CREDENTIAL_LEASE_URL", "/api/data-plane/credential-leases"),
                       ("CATCHPLATE_CONTROL_PLANE_AUDIT_URL", "/api/data-plane/audit")):
        require(gate["environment"][key] == "http://catchplate:3000" + suffix, "control destination differs")
    for name in ("catchplate", "decision-gate-rs"):
        environment = config["services"][name]["environment"]
        require(environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] == '["https://demo-upstream:8443"]'
                and not any(key.startswith("PRIVATE_OPERATOR_") for key in environment), "fixture scope differs")


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout


def overlaps(subnet):
    candidate = ipaddress.ip_network(subnet)
    ids = command(["docker", "network", "ls", "-q"]).split()
    networks = json.loads(command(["docker", "network", "inspect", *ids])) if ids else []
    existing = [item["Subnet"] for network in networks for item in (network.get("IPAM", {}).get("Config") or [])
        if item.get("Subnet")]
    existing += [row["dst"] for row in json.loads(command(["ip", "-json", "route", "show"]))
        if row.get("dst") not in (None, "default")]
    require(not any(candidate.version == ipaddress.ip_network(value).version
        and candidate.overlaps(ipaddress.ip_network(value)) for value in existing), "subnet overlaps existing routes")
    return {"dockerNetworksChecked": len(networks), "candidate": subnet, "conflicts": []}


def fresh_root(root, *, must_exist):
    require(root.resolve() == root and not root.is_symlink(), "symlink root refused")
    if not root.exists():
        require(not must_exist, "write requires caller-created empty root")
        return
    info = root.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
            and not any(root.iterdir()), "root must be owned empty0700 directory")


def prepare(args):
    expected_binary_sha256 = validated_binary_sha256(getattr(args, "expected_binary_sha256", BINARY_SHA256))
    config = build(args.source, args.binary, args.initializer, args.job_root, args.subnet,
                   expected_binary_sha256=expected_binary_sha256)
    fresh_root(args.job_root, must_exist=args.write)
    for path in (args.source, args.binary, args.initializer):
        require(path.resolve() == path and not path.is_symlink(), "exact non-symlink inputs required")
    require(digest(args.binary) == expected_binary_sha256 and digest(args.initializer) == INITIALIZER_SHA256,
            "reviewed executable or committed initializer differs")
    for image in (APP_IMAGE, FIXTURE_IMAGE, GATE_IMAGE):
        command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    require(not command(["docker", "ps", "-a", "-q", "--filter",
        "label=com.docker.compose.project=" + config["name"]]).strip(), "project already exists")
    filesystem = json.loads(command(["findmnt", "--json", "-T", str(SCRATCH), "-o", "TARGET,SOURCE,FSTYPE"]))
    space = os.statvfs(SCRATCH)
    require(space.f_bavail * space.f_frsize >= 2 * 1024**3, "at least2GiB scratch capacity required")
    network = overlaps(args.subnet)
    source_files = command(["git", "-C", str(args.source), "ls-files", "-co", "--exclude-standard", "--",
        "catchplate", "scripts", "schemas"]).splitlines()
    require(0 < len(source_files) <= 4096, "source manifest count exceeds bound")
    hashes = {name: digest(args.source / name) for name in sorted(set(source_files)) if (args.source / name).is_file()}
    manifest = {"schema": "catchplate.privateOperatorCatalogPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source),
        "sourceHead": command(["git", "-C", str(args.source), "rev-parse", "HEAD"]).strip(),
        "sourceStatus": command(["git", "-C", str(args.source), "status", "--short"]).splitlines(),
        "sourceScope": "catchplate, scripts and schemas tracked plus non-ignored files", "sourceSha256": hashes,
        "binary": str(args.binary), "binarySha256": expected_binary_sha256,
        "initializer": str(args.initializer), "initializerSha256": INITIALIZER_SHA256,
        "images": {"app": APP_IMAGE, "fixture": FIXTURE_IMAGE, "gate": GATE_IMAGE},
        "networkPreflight": network, "filesystem": filesystem, "launched": False, "productionReady": False,
        "composeSha256": hashlib.sha256((json.dumps(config, indent=2, sort_keys=True) + "\n").encode()).hexdigest()}
    if args.write:
        fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, value in (("compose.json", config), ("preparation.json", manifest)):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(value, target, indent=2, sort_keys=True)
                target.write("\n")
                target.flush()
                os.fsync(target.fileno())
    return {"preparation": manifest, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "binary", "initializer", "job-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", type=validated_binary_sha256, default=BINARY_SHA256,
        help="Reviewed executable SHA-256 (bare lowercase hex); defaults to the historical fixture pin")
    parser.add_argument("--subnet", default="172.16.249.48/28")
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("Private catalog preparation refused; no exception or subprocess details emitted") from None


if __name__ == "__main__":
    main()
