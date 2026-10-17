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
import stat
import subprocess

from scripts import prepare_operator_catalog_fixture as base
from scripts.operator_google_fixture import CLIENT_ID, CONTROL_ORIGIN, GOOGLE_IP


BINARY_SHA256 = "eba8cc0df0fcde6645e4b2b2c7d8d14e04bdad90e4587ee73fe2dc522108432d"
REFRESH_PROFILE = "google-refresh"
GMAIL_JOB_PROFILE = "gmail-job"
GMAIL_JOB_CHECKER_SECONDS = 180
GMAIL_JOB_OUTER_CHECKER_SECONDS = 210
GMAIL_JOB_LIFETIME_SECONDS = 300
GMAIL_JOB_KEEPER_MARGIN_SECONDS = 15
GMAIL_CLIENT_DEPENDENCIES = Path("/srv/catchplate-fast/projects/catchplate-operator-workspace-evidence/requests-dependencies.6BgfNK0L")
GMAIL_CLIENT_MANIFEST_SHA256 = "d932320e6f32eeca7f496abea639c1a80cf5afd0ba3642011e2a41cee3a70059"


def selected_binary_sha256(profile, expected_binary_sha256):
    """Two closed fixtures; the legacy refresh executable cannot be overridden."""
    base.require(profile in (REFRESH_PROFILE, GMAIL_JOB_PROFILE), "unknown Google fixture profile")
    if profile == REFRESH_PROFILE:
        base.require(expected_binary_sha256 is None or expected_binary_sha256 == BINARY_SHA256,
                     "legacy Google refresh executable is fixed")
        return BINARY_SHA256
    return base.validated_binary_sha256(expected_binary_sha256)


def selected_client_dependencies(profile, directory, manifest_sha256):
    if profile == REFRESH_PROFILE:
        base.require(directory is None and manifest_sha256 is None,
                     "legacy Google refresh has no client dependency overlay")
        return None
    base.require(directory == GMAIL_CLIENT_DEPENDENCIES
        and manifest_sha256 == GMAIL_CLIENT_MANIFEST_SHA256, "reviewed Gmail client dependency pin required")
    return GMAIL_CLIENT_DEPENDENCIES


def verify_client_dependencies(directory):
    """Hash the one reviewed, closed pure-Python payload; never import it."""
    base.require(directory == GMAIL_CLIENT_DEPENDENCIES and directory.resolve() == directory,
                 "exact Gmail dependency artifact required")
    root_info = directory.lstat()
    base.require(stat.S_ISDIR(root_info.st_mode) and stat.S_IMODE(root_info.st_mode) == 0o555,
                 "Gmail dependency root is not frozen")
    inventory, pending, examined, total_bytes = {}, [directory], 0, 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            examined += 1
            base.require(examined <= 2048, "Gmail dependency inventory exceeds bound")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                base.require(stat.S_IMODE(info.st_mode) == 0o555, "dependency directory is not frozen")
                pending.append(path)
            else:
                base.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
                    and info.st_nlink == 1 and info.st_size <= 8 * 1024**2, "dependency file is not frozen regular data")
                total_bytes += info.st_size
                base.require(total_bytes <= 8 * 1024**2, "Gmail dependency bytes exceed bound")
                inventory[path.relative_to(directory).as_posix()] = (info.st_size, base.digest(path))
    base.require(inventory.pop("manifest.json", None) ==
        ((directory / "manifest.json").stat().st_size, GMAIL_CLIENT_MANIFEST_SHA256),
        "Gmail dependency manifest differs")
    manifest = json.loads((directory / "manifest.json").read_text())
    base.require(manifest.get("schema") == "catchplate.syntheticRequestsDependencies/v1"
        and manifest.get("moduleSubdirectory") == "site-packages", "Gmail dependency schema differs")
    rows = manifest.get("files")
    base.require(isinstance(rows, list) and len(rows) == 143, "Gmail dependency inventory differs")
    expected = {row["path"]: (row["size"], row["sha256"]) for row in rows}
    base.require(len(expected) == len(rows) and inventory == expected
        and sum(size for size, _ in inventory.values()) <= 8 * 1024**2,
        "Gmail dependency payload differs")


def build(source, binary, initializer, root, *, profile=REFRESH_PROFILE, expected_binary_sha256=None,
          client_dependencies=None, client_dependencies_manifest_sha256=None):
    """Pure closed manifest, derived from the existing real-app catalog fixture."""
    binary_sha256 = selected_binary_sha256(profile, expected_binary_sha256)
    dependencies = selected_client_dependencies(profile, client_dependencies, client_dependencies_manifest_sha256)
    base.require(root.parent == base.SCRATCH and re.fullmatch(
        r"catchplate-google-private\.[A-Za-z0-9]{6,32}", root.name), "fresh Google NVMe root required")
    template_root = root.with_name("catchplate-catalog-private." + root.name.split(".", 1)[1])
    config = base.build(source, binary, initializer, template_root, "172.16.249.48/28",
                        expected_binary_sha256=binary_sha256)
    runtime = root / "runtime"
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template_root):
                mount["source"] = str(root / path.relative_to(template_root))
    config["name"] = "catchplate-google-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    config.pop("networks")
    services = config["services"]
    services.pop("demo-upstream")
    app, gate = services["catchplate"], services["decision-gate-rs"]
    common = deepcopy(app)
    for name, service in (("catchplate", app), ("decision-gate-rs", gate)):
        service.pop("networks")
        service.pop("dns")
        service["network_mode"] = "service:network"
        environment = service["environment"]
        environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = '["https://gmail.googleapis.com"]'
        environment.pop("CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS")
        environment.update(CATCHPLATE_OPERATOR_GOOGLE_PROFILE="operator-google-v1",
            CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID=CLIENT_ID,
            CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI=CONTROL_ORIGIN + "/api/oauth/callback/google")
        service["volumes"] = [mount for mount in service["volumes"]
                              if mount["target"] != "/demo-upstream"]
        service["volumes"] += [base.bind(runtime / "google-data/ca.pem", "/fixture-google/ca.pem"),
            base.bind(runtime / "fixture-hosts", "/etc/hosts"),
            base.bind(runtime / "fixture-resolv.conf", "/etc/resolv.conf")]
    app["cpus"] = 1
    app["depends_on"] = {"provider": {"condition": "service_healthy"}}
    app["environment"].update(SSL_CERT_FILE="/fixture-google/ca.pem",
        CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE="/run/secrets/catchplate/google-client.secret")
    gate["environment"].update(CATCHPLATE_UPSTREAM_CA_BUNDLE="/fixture-google/ca.pem",
        CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST="127.0.0.1")
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
            "--expected-binary-sha256", "sha256:" + binary_sha256,
            "--ca-file", "/data/mitmproxy/mitmproxy-ca-cert.pem",
            "--upstream-ca-file", "/fixture-google/ca.pem", "--control-ca-file", "/fixture-google/ca.pem",
            "--admin-token-file", "/run/secrets/catchplate/admin.token",
            "--fixture-marker-file", "/private-audit-fixture.json",
            "--google-fixture-marker-file", "/private-google-fixture.json",
            "--run-claim-file", "/data/.operator-catalog-acceptance.claim", "--timeout-seconds", "180"],
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "app-data", "/data", False),
            base.bind(runtime / "service-secrets/admin.token", "/run/secrets/catchplate/admin.token"),
            base.bind(runtime / "google-data/ca.pem", "/fixture-google/ca.pem"),
            base.bind(runtime / ".private-fixture.json", "/private-audit-fixture.json"),
            base.bind(runtime / ".private-google-fixture.json", "/private-google-fixture.json"), *hosts]}
    if profile == GMAIL_JOB_PROFILE:
        # Closed opt-in: no arbitrary module, command, endpoint or budget input.
        provider["command"] = ["python", "-B", "-m", "scripts.operator_gmail_job_fixture",
                               "--lifetime-seconds", str(GMAIL_JOB_LIFETIME_SECONDS)]
        services["check"]["command"][2] = "scripts/check_operator_gmail_job.py"
        services["check"]["command"][-1] = str(GMAIL_JOB_CHECKER_SECONDS)
        services["check"]["volumes"].append(base.bind(dependencies, "/client-dependencies"))
        services["check"]["environment"]["PYTHONPATH"] = "/app:/client-dependencies/site-packages"
    return config


def validate(config, source, binary, initializer, root, *, profile=REFRESH_PROFILE, expected_binary_sha256=None,
             client_dependencies=None, client_dependencies_manifest_sha256=None):
    # This is an intentionally closed fixture, not a generic Compose editor.
    base.require(config == build(source, binary, initializer, root, profile=profile,
        expected_binary_sha256=expected_binary_sha256, client_dependencies=client_dependencies,
        client_dependencies_manifest_sha256=client_dependencies_manifest_sha256), "Google fixture manifest changed")


def prepare(args):
    profile = getattr(args, "profile", REFRESH_PROFILE)
    binary_sha256 = selected_binary_sha256(profile, getattr(args, "expected_binary_sha256", None))
    dependencies = selected_client_dependencies(profile, getattr(args, "client_dependencies", None),
        getattr(args, "client_dependencies_manifest_sha256", None))
    config = build(args.source, args.binary, args.initializer, args.job_root,
        profile=profile, expected_binary_sha256=binary_sha256, client_dependencies=dependencies,
        client_dependencies_manifest_sha256=getattr(args, "client_dependencies_manifest_sha256", None))
    base.fresh_root(args.job_root, must_exist=args.write)
    for path in (args.source, args.binary, args.initializer):
        base.require(path.resolve() == path and not path.is_symlink(), "exact non-symlink inputs required")
    base.require(base.digest(args.binary) == binary_sha256
        and base.digest(args.initializer) == base.INITIALIZER_SHA256, "reviewed executable or initializer differs")
    if dependencies is not None:
        verify_client_dependencies(dependencies)
    for image in (base.APP_IMAGE, base.GATE_IMAGE):
        base.command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    base.require(not base.command(["docker", "ps", "-a", "-q", "--filter",
        "label=com.docker.compose.project=" + config["name"]]).strip(), "project already exists")
    filesystem = json.loads(base.command(["findmnt", "--json", "-T", str(base.SCRATCH), "-o", "TARGET,SOURCE,FSTYPE"]))
    space = os.statvfs(base.SCRATCH)
    base.require(space.f_bavail * space.f_frsize >= 2 * 1024**3, "at least2GiB scratch capacity required")
    names = base.command(["git", "-C", str(args.source), "ls-files", "-co", "--exclude-standard", "--",
        "catchplate", "scripts", "schemas"]).splitlines()
    base.require(0 < len(names) <= 4096, "source manifest exceeds bound")
    hashes = {name: base.digest(args.source / name) for name in sorted(set(names)) if (args.source / name).is_file()}
    manifest = {"schema": "catchplate.privateOperatorGooglePreparation/v1", "project": config["name"],
        "source": str(args.source), "sourceHead": base.command(["git", "-C", str(args.source), "rev-parse", "HEAD"]).strip(),
        "sourceSha256": hashes, "jobRoot": str(args.job_root), "binary": str(args.binary),
        "binarySha256": binary_sha256, "initializer": str(args.initializer),
        "initializerSha256": base.INITIALIZER_SHA256, "filesystem": filesystem,
        "network": {"mode": "none", "interfaces": ["lo"], "fixtureOnlyAddress": GOOGLE_IP,
            "externalProviderContact": False, "hostPorts": [], "defaultRoute": False},
        "images": {"app": base.APP_IMAGE, "gate": base.GATE_IMAGE}, "launched": False,
        "productionReady": False, "teardownRequired": "all project containers, including keeper, on every exit",
        "composeSha256": hashlib.sha256((json.dumps(config, indent=2, sort_keys=True) + "\n").encode()).hexdigest()}
    if profile == GMAIL_JOB_PROFILE:
        # A 90s real expiry fits the 180s checker; its outer 210s budget plus
        # 15s margin must still fit the ORIGINAL 300s keeper before launch.
        # The caller must observe this eligibility, never extend either timer.
        manifest["fixtureProfile"] = GMAIL_JOB_PROFILE
        manifest["clientDependencies"] = {"root": str(dependencies),
            "manifestSha256": GMAIL_CLIENT_MANIFEST_SHA256, "moduleSubdirectory": "site-packages",
            "mount": "/client-dependencies", "readOnly": True, "scope": "checker-only"}
        manifest["budgets"] = {"checkerTimeoutSeconds": GMAIL_JOB_CHECKER_SECONDS,
            "checkerOuterBudgetSeconds": GMAIL_JOB_OUTER_CHECKER_SECONDS,
            "keeperLifetimeSeconds": GMAIL_JOB_LIFETIME_SECONDS,
            "providerLifetimeSeconds": GMAIL_JOB_LIFETIME_SECONDS,
            "keeperMarginSeconds": GMAIL_JOB_KEEPER_MARGIN_SECONDS,
            "maximumPrecheckElapsedSeconds": GMAIL_JOB_LIFETIME_SECONDS
                - GMAIL_JOB_OUTER_CHECKER_SECONDS - GMAIL_JOB_KEEPER_MARGIN_SECONDS}
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
    parser.add_argument("--profile", choices=(REFRESH_PROFILE, GMAIL_JOB_PROFILE), default=REFRESH_PROFILE)
    parser.add_argument("--expected-binary-sha256", help="Required bare reviewed SHA-256 for gmail-job only")
    parser.add_argument("--client-dependencies", type=Path, help="Exact reviewed gmail-job checker dependency artifact")
    parser.add_argument("--client-dependencies-manifest-sha256", help="Exact reviewed dependency manifest SHA-256")
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit("Private Google fixture preparation refused; no raw errors emitted") from None


if __name__ == "__main__":
    main()
