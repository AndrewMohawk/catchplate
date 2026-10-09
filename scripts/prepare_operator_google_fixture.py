#!/usr/bin/env python3
"""Prepare, never launch, one network-none normal-binary Google acceptance fixture.

The sole public-looking /32 is assigned to loopback inside a new isolated network
namespace. No external interface/default route, host DNS/trust changes, published
port, provider URL override or production guard patch is part of this fixture.
The caller owns one bounded Compose run and MUST tear down every project service
on every exit; expiry of the namespace keeper is not proof of container teardown.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from scripts import prepare_operator_catalog_fixture as base
from scripts.operator_google_fixture import CLIENT_ID, CONTROL_ORIGIN, GOOGLE_IP


BINARY_SHA256 = "9be25b5dbca69befbbbdfab7b1fab9a852f3c6212a73078ea0c05a32375ef3a4"


def build(source, binary, initializer, root):
    """Pure closed manifest, derived from the existing real-app catalog fixture."""
    base.require(root.parent == base.SCRATCH and re.fullmatch(
        r"serverware-google-private\.[A-Za-z0-9]{6,32}", root.name), "fresh Google NVMe root required")
    template_root = root.with_name("serverware-catalog-private." + root.name.split(".", 1)[1])
    config = base.build(source, binary, initializer, template_root, "172.16.249.48/28",
                        expected_binary_sha256=BINARY_SHA256)
    runtime = root / "runtime"
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template_root):
                mount["source"] = str(root / path.relative_to(template_root))
    config["name"] = "serverware-google-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    config.pop("networks")
    services = config["services"]
    services.pop("demo-upstream")
    app, gate = services["serverware"], services["decision-gate-rs"]
    common = deepcopy(app)
    for name, service in (("serverware", app), ("decision-gate-rs", gate)):
        service.pop("networks")
        service.pop("dns")
        service["network_mode"] = "service:network"
        environment = service["environment"]
        environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://gmail.googleapis.com"]'
        environment.pop("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS")
        environment.update(SERVERWARE_OPERATOR_GOOGLE_PROFILE="operator-google-v1",
            SERVERWARE_GOOGLE_OAUTH_CLIENT_ID=CLIENT_ID,
            SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI=CONTROL_ORIGIN + "/api/oauth/callback/google")
        service["volumes"] = [mount for mount in service["volumes"]
                              if mount["target"] != "/demo-upstream"]
        service["volumes"] += [base.bind(runtime / "google-data/ca.pem", "/fixture-google/ca.pem"),
            base.bind(runtime / "fixture-hosts", "/etc/hosts"),
            base.bind(runtime / "fixture-resolv.conf", "/etc/resolv.conf")]
    app["cpus"] = 1
    app["depends_on"] = {"provider": {"condition": "service_healthy"}}
    app["environment"].update(SSL_CERT_FILE="/fixture-google/ca.pem",
        SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE="/run/secrets/serverware/google-client.secret")
    gate["environment"].update(SERVERWARE_UPSTREAM_CA_BUNDLE="/fixture-google/ca.pem",
        SERVERWARE_DECISION_GATE_MANAGEMENT_HOST="127.0.0.1")
    gate["healthcheck"] = base.health("http://127.0.0.1:9091/healthz", start=20)

    # New fixture services inherit the same caps/no-new-privileges/read-only /
    # resource/logging defaults, but no application environment or authority.
    for key in ("networks", "dns", "depends_on", "healthcheck", "environment", "volumes", "command"):
        common.pop(key, None)
    common.update(cpus=0.5, mem_limit="256m", memswap_limit="256m", pids_limit=64,
        environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"},
        network_mode="service:network")
    hosts = [base.bind(runtime / "fixture-hosts", "/etc/hosts"),
             base.bind(runtime / "fixture-resolv.conf", "/etc/resolv.conf")]
    provider = {**deepcopy(common), "command": ["python", "-B", "-m", "scripts.operator_google_fixture"],
        "depends_on": {"network": {"condition": "service_healthy"}},
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "google-data", "/fixture-google"), *hosts],
        "healthcheck": {"test": ["CMD", "python", "-c",
            "import ssl,urllib.request; "
            "c=ssl.create_default_context(cafile='/fixture-google/ca.pem'); "
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
            "r=o.open('https://gmail.googleapis.com/__test__/observations',timeout=2); "
            "raise SystemExit(0 if r.status==200 else 1)"],
            "interval": "3s", "timeout": "3s", "retries": 10, "start_period": "5s"}}
    services["provider"] = provider
    network = {**deepcopy(common), "user": "0:0", "network_mode": "none",
        "cap_add": ["NET_ADMIN", "SETUID", "SETGID"], "cpus": 0.25,
        "command": ["python", "-B", "-m", "scripts.operator_google_fixture_setup", "network"],
        "sysctls": {"net.ipv4.ip_unprivileged_port_start": "0", "net.ipv4.ip_nonlocal_bind": "0"},
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "network-data", "/fixture-network", False), *hosts],
        "healthcheck": {"test": ["CMD", "python", "-c",
            # Docker starts healthchecks as Config.User (root), not the keeper's
            # permanently dropped UID. Use existing SETGID/SETUID, not DAC bypass.
            "import os,stat; os.setgroups([]); os.setgid(10001); os.setuid(10001); "
            "s=os.stat('/fixture-network/ready',follow_symlinks=False); "
            "raise SystemExit(0 if stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o400 "
            "and s.st_uid==s.st_gid==10001 and s.st_nlink==1 and 0<s.st_size<=1024 else 1)"],
            "interval": "2s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    services["network"] = network
    initialize = services["initialize"]
    initialize.update(image=base.APP_IMAGE, working_dir="/app", mem_limit="256m", memswap_limit="256m",
        command=["python", "-B", "-m", "scripts.operator_google_fixture_setup", "initialize"],
        environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
    initialize["volumes"].append(base.bind(source, "/app"))
    services["check"] = {**deepcopy(common), "profiles": ["check"],
        "depends_on": {"decision-gate-rs": {"condition": "service_healthy"}},
        "command": ["python", "-B", "scripts/check_operator_google_refresh.py",
            "--control-base", CONTROL_ORIGIN, "--management-base", "http://127.0.0.1:9091",
            "--proxy-url", "http://127.0.0.1:9090", "--operator-origin", CONTROL_ORIGIN,
            "--expected-binary-sha256", "sha256:" + BINARY_SHA256,
            "--ca-file", "/data/mitmproxy/mitmproxy-ca-cert.pem",
            "--upstream-ca-file", "/fixture-google/ca.pem", "--control-ca-file", "/fixture-google/ca.pem",
            "--admin-token-file", "/run/secrets/serverware/admin.token",
            "--fixture-marker-file", "/private-audit-fixture.json",
            "--google-fixture-marker-file", "/private-google-fixture.json",
            "--run-claim-file", "/data/.operator-catalog-acceptance.claim", "--timeout-seconds", "180"],
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "app-data", "/data", False),
            base.bind(runtime / "service-secrets/admin.token", "/run/secrets/serverware/admin.token"),
            base.bind(runtime / "google-data/ca.pem", "/fixture-google/ca.pem"),
            base.bind(runtime / ".private-fixture.json", "/private-audit-fixture.json"),
            base.bind(runtime / ".private-google-fixture.json", "/private-google-fixture.json"), *hosts]}
    return config


def validate(config, source, binary, initializer, root):
    # This is an intentionally closed fixture, not a generic Compose editor.
    base.require(config == build(source, binary, initializer, root), "Google fixture manifest changed")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root)
    base.fresh_root(args.job_root, must_exist=args.write)
    for path in (args.source, args.binary, args.initializer):
        base.require(path.resolve() == path and not path.is_symlink(), "exact non-symlink inputs required")
    base.require(base.digest(args.binary) == BINARY_SHA256
        and base.digest(args.initializer) == base.INITIALIZER_SHA256, "reviewed executable or initializer differs")
    for image in (base.APP_IMAGE, base.GATE_IMAGE):
        base.command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    base.require(not base.command(["docker", "ps", "-a", "-q", "--filter",
        "label=com.docker.compose.project=" + config["name"]]).strip(), "project already exists")
    filesystem = json.loads(base.command(["findmnt", "--json", "-T", str(base.SCRATCH), "-o", "TARGET,SOURCE,FSTYPE"]))
    space = os.statvfs(base.SCRATCH)
    base.require(space.f_bavail * space.f_frsize >= 2 * 1024**3, "at least2GiB scratch capacity required")
    names = base.command(["git", "-C", str(args.source), "ls-files", "-co", "--exclude-standard", "--",
        "serverware", "scripts", "schemas"]).splitlines()
    base.require(0 < len(names) <= 4096, "source manifest exceeds bound")
    hashes = {name: base.digest(args.source / name) for name in sorted(set(names)) if (args.source / name).is_file()}
    manifest = {"schema": "serverware.privateOperatorGooglePreparation/v1", "project": config["name"],
        "source": str(args.source), "sourceHead": base.command(["git", "-C", str(args.source), "rev-parse", "HEAD"]).strip(),
        "sourceSha256": hashes, "jobRoot": str(args.job_root), "binary": str(args.binary),
        "binarySha256": BINARY_SHA256, "initializer": str(args.initializer),
        "initializerSha256": base.INITIALIZER_SHA256, "filesystem": filesystem,
        "network": {"mode": "none", "interfaces": ["lo"], "fixtureOnlyAddress": GOOGLE_IP,
            "externalProviderContact": False, "hostPorts": [], "defaultRoute": False},
        "images": {"app": base.APP_IMAGE, "gate": base.GATE_IMAGE}, "launched": False,
        "productionReady": False, "teardownRequired": "all project containers, including keeper, on every exit",
        "composeSha256": hashlib.sha256((json.dumps(config, indent=2, sort_keys=True) + "\n").encode()).hexdigest()}
    if args.write:
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, value in (("compose.json", config), ("preparation.json", manifest)):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
    return {"preparation": manifest, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "binary", "initializer", "job-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("Private Google fixture preparation refused; no raw errors emitted") from None


if __name__ == "__main__":
    main()
