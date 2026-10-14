"""Pure recipe for browser-created resources and genuine proxy/revoke effects.

No seeded catalog rows, provider accounts, image pulls, build or runtime launch.
The baseline initializer, upstream and TLS relay remain unchanged.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re

from scripts import prepare_operator_proxy_basic_fixture as basic
from scripts import operator_guided_fixture_network as network
from scripts import operator_guided_hosted_profile as hosted

base = basic.base
CONTROL_ORIGIN = "https://" + network.CONTROL_HOST
PROXY_URL = "https://" + network.PROXY_HOST
CHECKER = "/app/scripts/check_operator_guided.py"
BROWSER_DRIVER = "scripts/check_operator_guided_browser.cjs"
CHECKER_SECONDS, CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 180, 190, 75
KEEPER_SECONDS, EDGE_SECONDS = network.KEEPER_SECONDS, network.EDGE_SECONDS
RUNTIME_SERVICES = {"network", "provider", "serverware", "decision-gate-rs", "edge", "check"}
LEAVES = (".operator-publication.lock", ".serverware-operator-demo.json",
    "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")


def build(source, binary, initializer, root, *, expected_binary_sha256,
          hosted_profile=None, hosted_provision=None):
    base.require((hosted_profile is None) == (hosted_provision is None),
        "guided hosted profile and provision must be paired")
    if hosted_profile is not None:
        hosted_profile = hosted.validate(hosted_profile)
        base.require(isinstance(hosted_provision, Path) and hosted_provision.is_absolute()
            and ".." not in hosted_provision.parts, "exact hosted provision path required")
    curl_sha256 = basic.CURL_SHA256 if hosted_profile is None else hosted_profile["curl"]["sha256"]
    base.require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-guided-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh guided NVMe fixture root required")
    template = root.with_name("serverware-proxy-basic-private." + root.name.split(".", 1)[1])
    config = basic.build(source, binary, initializer, template, "172.16.249.48/28",
        expected_binary_sha256=expected_binary_sha256)
    config["name"] = "serverware-guided-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    config.pop("networks")
    services, runtime = config["services"], root / "runtime"
    for service in services.values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
        service.setdefault("entrypoint", [])
        service.pop("networks", None); service.pop("dns", None)
    hosts = [base.bind(runtime / "upstream-data/guided-network/hosts", "/etc/hosts"),
        base.bind(runtime / "upstream-data/guided-network/resolv.conf", "/etc/resolv.conf")]
    provider = services["provider"] = services.pop("demo-upstream")
    provider["command"] = ["python", "-B", "scripts/demo_upstream.py"]
    provider["depends_on"] = {"network": {"condition": "service_healthy"}}
    common = deepcopy(provider)
    for key in ("command", "environment", "volumes", "healthcheck", "depends_on"):
        common.pop(key, None)
    common.update(image=base.APP_IMAGE, environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"},
        cpus=0.25, mem_limit="128m", memswap_limit="128m", pids_limit=16)
    helper = ["python", "-B", "-m", "scripts.operator_guided_fixture_network"]
    services["network-files"] = {**deepcopy(common), "profiles": ["network-files"], "network_mode": "none",
        "command": helper + ["files"], "volumes": [base.bind(source, "/app"),
            base.bind(runtime / "upstream-data", "/upstream-data", False)]}
    services["network"] = {**deepcopy(common), "network_mode": "none", "command": helper + ["network"],
        "sysctls": {"net.ipv4.ip_unprivileged_port_start": "0", "net.ipv4.ip_nonlocal_bind": "0"},
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "upstream-data/guided-network", "/fixture-network", False), *hosts],
        "healthcheck": {"test": ["CMD", "python", "-c", "import os,stat; s=os.stat('/fixture-network/ready',follow_symlinks=False); "
            "raise SystemExit(0 if stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o400 "
            "and s.st_uid==s.st_gid==10001 and s.st_nlink==1 and 0<s.st_size<=1024 else 1)"],
            "interval": "2s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    app, gate = services["serverware"], services["decision-gate-rs"]
    app["depends_on"] = {"provider": {"condition": "service_healthy"}}
    app["environment"].update(SERVERWARE_PUBLIC_URL=CONTROL_ORIGIN, SERVERWARE_DECISION_GATE_BASE="http://127.0.0.1:9091",
        SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED="1")
    for service in (app, gate):
        service["environment"].update(SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS='["127.0.0.2/32"]',
            SERVERWARE_OPERATOR_DEMO_PROXY_URL=PROXY_URL)
    gate["environment"].update(SERVERWARE_DECISION_GATE_HOST="127.0.0.1", SERVERWARE_DECISION_GATE_MANAGEMENT_HOST="127.0.0.1")
    gate["healthcheck"] = base.health("http://127.0.0.1:9091/healthz", start=20)
    gate["volumes"] = [mount for mount in gate["volumes"] if mount["target"] != "/data"] + [
        base.bind(runtime / "app-data/gate-runtime", "/data"),
        *(base.bind(runtime / "app-data" / leaf, "/data/" + leaf) for leaf in LEAVES)]
    services["basic-pki"]["command"] = ["-m", "scripts.operator_guided_fixture_network", "pki"]
    services["edge"]["command"] = ["-m", "scripts.operator_guided_fixture_network", "edge"]
    check = services["check"]
    check.update(stdin_open=True, tty=False, environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
    # Attach carries one-time private form/response frames. Docker must not
    # retain them, even when the checker exits or cleanup is uncertain.
    check["logging"] = {"driver": "none", "options": {}}
    check["volumes"] = [mount for mount in check["volumes"] if mount["target"] != "/client-dependencies"]
    check["command"] = [CHECKER, "--control-base", "http://127.0.0.1:3000", "--management-base", "http://127.0.0.1:9091",
        "--proxy-url", PROXY_URL, "--operator-origin", CONTROL_ORIGIN,
        "--expected-binary-sha256", "sha256:" + expected_binary_sha256,
        "--ca-file", "/client-trust/inner-ca.pem", "--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--upstream-ca-file", "/client-trust/upstream-ca.pem", "--admin-token-file", "/client-secrets/admin.token",
        "--fixture-marker-file", "/private-fixture.json", "--run-claim-file", "/client-work/.operator-catalog-acceptance.claim",
        "--curl-binary", "/usr/bin/curl", "--expected-curl-sha256", curl_sha256, "--timeout-seconds", "180"]
    if hosted_profile is not None:
        for service in services.values():
            if service["image"] in {base.APP_IMAGE, base.FIXTURE_IMAGE}:
                service["image"] = hosted_profile["app"]["id"]
        check["image"] = hosted.CLIENT_IMAGE
        check["entrypoint"] = [hosted.PYTHON, "-B"]
        check["command"] += ["--profile", hosted.PROFILE, "--hosted-provision", hosted.PROVISION_MOUNT]
        check["volumes"].append(base.bind(hosted_provision, hosted.PROVISION_MOUNT))
    for name in RUNTIME_SERVICES - {"network"}:
        services[name]["network_mode"] = "service:network"
        services[name]["volumes"] += deepcopy(hosts)
    base.require(set(config) == {"name", "services"} and set(services) == RUNTIME_SERVICES | {
        "initialize", "network-files", "basic-pki"}, "guided service roster differs")
    for service in services.values():
        base.require(len(service["volumes"]) == len({mount["target"] for mount in service["volumes"]}), "duplicate guided mount")
    return config


def validate(config, *args, **kwargs):
    base.require(config == build(*args, **kwargs), "guided fixture recipe differs")
