#!/usr/bin/env python3
"""One bounded real catalog -> signed policy -> cached Rust -> synthetic provider check.

Reuses the guided fixture lifecycle, empty-store initializer, images and curl.
An explicit MCP profile runs only two OpenAI calls through the official stdio
client and existing Requests helper, using already-installed SDK packages.
No compilation, download, public DNS, real provider, live deployment or retry.
Run only from a frozen source export with the exact existing normal Rust binary.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_common_apps_fixture as fixture
from scripts import prepare_operator_guided_fixture as recipe
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, OperatorCatalogCheck, claim_fixture
from scripts.check_operator_demo import Endpoint, SHA256, require, token_file
from scripts.check_operator_guided import CURL_SHA256, run_curl
from scripts.check_operator_ordinary_client import OrdinaryClientCheck, START, RELEASE
from scripts.run_operator_guided_fixture import GuidedRun, admitted_image_entrypoint
from scripts.run_operator_npm_example_fixture import environment
from scripts.run_operator_x_examples_fixture import failure_site, PYTHON_IMAGE

SCRIPT = "scripts/test_common_apps_connected.py"
ORIGINS = sorted("https://" + host for host in fixture.PROVIDERS)
MCP_PACKAGES = "/usr/local/lib/python3.12/site-packages"
MCP_PINS = {"mcp": "2.3.0", "requests": "2.34.2", "urllib3": "2.8.0", "certifi": "2026.7.22",
    "charset-normalizer": "3.5.2", "idna": "3.20"}


class CommonAppsCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        fixture.assert_isolated()
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": "127.0.0.1"}))
        self.credential, self.phase, self.last = fixture.TOKEN, "preflight", None
        require(args.control_base == "http://127.0.0.1:3000" and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == recipe.PROXY_URL and args.operator_origin == recipe.CONTROL_ORIGIN,
            "exact isolated endpoints required")
        if args.mcp_smoke:
            from importlib.metadata import version
            require(sys.version_info[:3] == (3, 12, 14)
                and all(version(name) == expected for name, expected in MCP_PINS.items()), "cached MCP runtime differs")
        else:
            require(args.expected_curl_sha256 == CURL_SHA256 and args.curl_binary == Path("/usr/bin/curl")
                and hashlib.sha256(args.curl_binary.read_bytes()).hexdigest() == CURL_SHA256, "cached curl differs")
        self.provider = Endpoint(ORIGINS[0], address="127.0.0.1")
        self.provider.address = fixture.isolated.FIXTURE_IP

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("allowed_upstreams") == ORIGINS and all(isinstance(value.get(key), list) for key in COLLECTIONS)
            and SHA256.fullmatch(value.get("policy", {}).get("policy_hash", "")), "fixture catalog differs")
        self.snapshot = value
        return value

    def provider_observations(self):
        status, value = self.json_request(self.provider, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and set(value) == {"total", "attempts"}, "fixture counter unavailable")
        return value

    def dispatch(self, name, body, *, case, count, allowed=False, path=None):
        spec = fixture.SPECS[name]
        target = "https://" + spec["host"] + (path or spec["path"])
        data = fixture.encoded(body)
        payload_path = self.args.run_claim_file.parent / ("common-" + case + ".json")
        descriptor = os.open(payload_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        argv = [str(self.args.curl_binary), "-q", "--config", "-", "--silent", "--show-error", "--proxy-basic",
            "--proxy", self.args.proxy_url, "--noproxy", "", "--proxy-cacert", str(self.args.proxy_ca_file),
            "--cacert", str(self.args.ca_file), "--proto", "=https", "--proto-redir", "=https", "--http1.1",
            "--connect-timeout", "3", "--max-time", "8", "--retry", "0", "--max-filesize", "65536",
            "--raw", "--include", "--suppress-connect-headers", "--request", "POST", "--data-binary", "@" + str(payload_path),
            "--header", spec["header"] + ": " + spec["placeholder"], "--header", "Content-Type: application/json",
            "--header", "Accept: application/json", "--header", "Accept-Encoding: identity", "--header", "Connection: close",
            "--header", "User-Agent: serverware-common-apps-fixture/1"]
        if name == "anthropic":
            argv += ["--header", "anthropic-version: 2023-06-01"]
        argv += ["--write-out", "\nserverware-common-apps:%{http_connect}:%{http_code}\n", target]
        private = ('proxy-user = "' + self.application["id"] + ":" + self.client_token + '"\n').encode()
        code, output, error = run_curl(argv, private, min(12, self.timeout()))
        self.clean(output); self.clean(error)
        wire, separator, tail = output.rpartition(b"\nserverware-common-apps:")
        match = re.fullmatch(rb"([0-9]{3}):([0-9]{3})\n", tail) if separator else None
        observed = self.provider_observations()
        self.last = {"case": case, "curlExit": code, "connectStatus": int(match[1]) if match else None,
            "httpStatus": int(match[2]) if match else None, "providerArrivals": observed["total"], "stderrPresent": bool(error)}
        try:
            document = json.loads(wire.partition(b"\r\n\r\n")[2])
            error_code = document.get("error") or document.get("payload", {}).get("error")
            if isinstance(error_code, str) and re.fullmatch(r"[a-z_]{1,80}", error_code):
                self.last["errorCode"] = error_code
        except (ValueError, AttributeError):
            pass
        require(code == 0 and not error and match is not None and observed["total"] == count,
            "proxy transport or arrival count differs")
        if allowed:
            expected = fixture.encoded({"synthetic": True, "provider": name, "result": "fixed fixture response"})
            require(tail == b"200:200\n" and wire.partition(b"\r\n\r\n")[2] == expected
                and observed["attempts"][-1]["accepted"] is True, "synthetic allowed response differs")
        else:
            require(int(match[2]) == 403 or (int(match[1]) == 403 and int(match[2]) == 0),
                "out-of-scope request was not denied")
        return dict(self.last)

    def mcp_configurations(self, rule):
        """The same downloaded-client fields, with one intentionally wrong local scope.

        Both files retain the single real application login and access-rule ID.
        The negative changes only local model selection, never proxy authority.
        """
        config = {key: deepcopy(rule[key]) for key in ("upstream_url", "methods", "response_mode",
            "credential_input", "app_preset", "app_operation", "scope", "query_keys")}
        config.update(application_id=self.application["id"], access_rule_id=rule["id"],
            proxy_url=self.args.proxy_url, proxy_authentication="basic_and_bearer_v1",
            proxy_username=self.application["id"], proxy_password=self.client_token,
            token_expires_at_epoch_ms=self.application["token_expires_at_epoch_ms"],
            request_headers={"Authorization": rule["placeholder"]}, request_query={},
            ca_file=str(self.args.ca_file), proxy_ca_file=str(self.args.proxy_ca_file),
            client_recipe={"automatic_retries": 0})
        paths = {}
        for alias in ("approved", "wrongscope"):
            value = deepcopy(config)
            if alias == "wrongscope":
                value["scope"]["model"] = "not-the-approved-model"
            path = self.args.run_claim_file.parent / ("mcp-" + alias + ".json")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(fixture.encoded(value))
            paths[alias] = path
        return paths

    def dispatch_mcp(self, rule):
        import anyio
        from mcp import Client, StdioServerParameters

        paths = self.mcp_configurations(rule)
        parameters = StdioServerParameters(command="/usr/local/bin/python", args=["-I", "-B",
            "/app/examples/mcp/server.py", *[item for alias, path in paths.items()
                for item in ("--config", alias + "=" + str(path), "--allow-actions", alias)]],
            cwd="/app", env={"PYTHONDONTWRITEBYTECODE": "1"})

        async def invoke():
            checks = []
            with anyio.fail_after(min(120, self.deadline - time.monotonic())):
                async with Client(parameters, read_timeout_seconds=50, cache=None) as client:
                    tools = await client.list_tools()
                    require({tool.name for tool in tools.tools} == {
                        "list_operations", "read_operation", "perform_action"}, "MCP tools differ")
                    catalog = await client.call_tool("list_operations", {})
                    self.clean(catalog.model_dump_json().encode())
                    require({item["id"] for item in catalog.structured_content["operations"]} == set(paths)
                        and self.provider_observations()["total"] == 0, "MCP discovery sent traffic")
                    for alias, status, http_status in (("approved", "ok", 200), ("wrongscope", "provider_error", 403)):
                        self.phase = "mcp-" + alias
                        result = await client.call_tool("perform_action", {"operation_id": alias,
                            "arguments": {"prompt": "Hi", "output_tokens": 16}, "confirmed": True})
                        self.clean(result.model_dump_json().encode())
                        value, observed = result.structured_content, self.provider_observations()
                        self.last = {"case": self.phase, "mcpStatus": value.get("status"),
                            "httpStatus": value.get("http_status"), "providerArrivals": observed["total"]}
                        require(value.get("status") == status and value.get("http_status") == http_status
                            and result.is_error is (status != "ok")
                            and value.get("automatic_retry") is False and observed["total"] == 1,
                            "MCP request outcome or arrival count differs")
                        if alias == "approved":
                            require(value.get("response") == {"synthetic": True, "provider": "openai",
                                "result": "fixed fixture response"} and value.get("untrusted_response") is True
                                and observed["attempts"][0]["accepted"] is True, "MCP provider response differs")
                        checks.append(dict(self.last))
            return checks

        return anyio.run(invoke)

    def run(self):
        self.admin_token = token_file(self.args.admin_token_file)
        self.health()
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] for key in COLLECTIONS)
            and self.provider_observations() == {"total": 0, "attempts": []}, "fixture must be fresh")
        self.application, self.client_token, _ = self.mutate("/applications", {"name": self.run_id,
            "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        rules, mcp_rule = {}, None
        specs = {"openai": fixture.SPECS["openai"]} if self.args.mcp_smoke else fixture.SPECS
        for name, spec in specs.items():
            self.phase = "create-" + name
            credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-" + name,
                "auth_type": "header" if name == "anthropic" else "bearer", "header_name": spec["header"],
                "secret": self.credential, "app_preset": name}, collection="credentials", result_key="credential",
                event="operator_catalog.credential.created", creates=True)
            scope = {"channel_id": fixture.CHANNEL} if name == "discord" else {"model": fixture.MODEL, "max_output_tokens": 16}
            rule, _, _ = self.mutate("/access-rules/common-app", {"name": self.run_id + "-" + name,
                "application_id": self.application["id"], "credential_id": credential["id"], "app_preset": name,
                "operation": spec["operation"], "scope": scope}, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
            rules[name] = rule["route_id"]
            if self.args.mcp_smoke:
                mcp_rule = rule
        self.wait_catalog_loaded("common_apps_loaded")
        checks, arrivals = [], 0
        if self.args.mcp_smoke:
            checks = self.dispatch_mcp(mcp_rule)
        for name, spec in (() if self.args.mcp_smoke else specs.items()):
            self.phase = "dispatch-" + name
            arrivals += 1
            checks.append(self.dispatch(name, spec["body"], case=name + "-allowed", count=arrivals, allowed=True))
            if name in {"openai", "anthropic"}:
                for variant in ("model", "stream", "tokens"):
                    body = deepcopy(spec["body"])
                    key = ("max_output_tokens" if name == "openai" else "max_tokens") if variant == "tokens" else variant
                    body[key] = {"model": "not-the-approved-model", "stream": True, "tokens": 17}[variant]
                    checks.append(self.dispatch(name, body, case=name + "-wrong-" + variant, count=arrivals))
            else:
                path = spec["path"].replace(fixture.CHANNEL, "987654321098765432")
                checks.append(self.dispatch(name, spec["body"], case="discord-wrong-channel", count=arrivals, path=path))
        self.phase = "audit"
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        rows = self.audit()
        attempts = [row for row in rows if row["event_type"] in {START, RELEASE}]
        require(Counter(row["event_type"] for row in attempts) == Counter({START: len(specs), RELEASE: len(specs)}), "release audit differs")
        for route in rules.values():
            selected = [row for row in attempts if row["event"].get("route_id") == route]
            require(Counter(row["event_type"] for row in selected) == Counter({START: 1, RELEASE: 1})
                and all(row["event"].get("policy_hash") == self.policy_hash for row in selected), "signed policy audit binding differs")
        observed = self.provider_observations()
        require(observed["total"] == len(specs) and all(row["accepted"] for row in observed["attempts"]), "provider assertions differ")
        return {"schema": "serverware.commonAppsConnectedCheck/v1", "ok": True, "syntheticOnly": True,
            "realProviderVerified": False, "stockSdkVerified": False, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "policyHash": self.policy_hash, "catalogRevision": self.catalog()["revision"], "checks": checks,
            "provider": observed, "auditCounts": dict(Counter(row["event_type"] for row in attempts)),
            "mcpSdkVerified": self.args.mcp_smoke, "requestsHelperVerified": self.args.mcp_smoke}


def check(args):
    signal.alarm(180)
    instance = None
    try:
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        instance = CommonAppsCheck(args)
        result = instance.run()
    except Exception as error:
        result = {"ok": False, "phase": instance.phase if instance else "preflight", "exceptionType": type(error).__name__,
            "failureSite": failure_site(error, Path(__file__).resolve().parents[1]), "observation": instance.last if instance else None}
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["ok"] else 1


def run(args):
    source, root = args.source, args.job_root
    require(Path(__file__).resolve() == source / SCRIPT and re.fullmatch(r"[0-9a-f]{40}", args.commit), "frozen source required")
    require(source.is_dir() and not source.stat().st_mode & 0o222, "source export must be nonwritable")
    require(root.is_dir() and not list(root.iterdir()) and root.stat().st_mode & 0o777 == 0o700
        and args.evidence.is_dir() and not list(args.evidence.iterdir()), "fresh private roots required")
    require(recipe.base.digest(args.binary) == args.expected_binary_sha256, "normal binary pin differs")
    args.initializer = source / "scripts/private_operator_audit/initialize.py"
    require(recipe.base.digest(args.initializer) == recipe.base.INITIALIZER_SHA256, "initializer pin differs")
    runner = GuidedRun(args)
    begun = time.monotonic()
    runner.deadline = begun + 300
    success, clean, armed, phase, failure = False, False, False, "prepare", None
    try:
        config = recipe.build(source, args.binary, args.initializer, root, expected_binary_sha256=args.expected_binary_sha256)
        services = config["services"]
        helper = ["python", "-B", "-m", "scripts.operator_common_apps_fixture"]
        services["network-files"]["command"] = helper + ["setup"]
        services["network"].update(user="0:0", init=False, cap_add=["NET_ADMIN", "SETUID", "SETGID"], command=helper + ["network"])
        services["network"]["healthcheck"]["test"][3] = "import os; os.setgroups([]); os.setgid(10001); os.setuid(10001); " + services["network"]["healthcheck"]["test"][3]
        services["provider"]["image"] = recipe.base.APP_IMAGE
        services["provider"]["command"] = helper + ["provider"]
        services["provider"]["healthcheck"]["test"][3] = ("import ssl,urllib.request; c=ssl.create_default_context(cafile='/data/demo-upstream/ca.pem'); "
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
            "r=o.open('https://api.openai.com/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)")
        services["edge"]["command"] = ["-m", "scripts.operator_common_apps_fixture", "edge"]
        for name in ("serverware", "decision-gate-rs"):
            services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(ORIGINS)
            services[name]["environment"].pop("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", None)
        services["check"]["command"][0:1] = ["/app/" + SCRIPT, "check"]
        if args.mcp_sdk_packages is not None:
            packages = args.mcp_sdk_packages
            require(packages.is_absolute() and packages.resolve() == packages and packages.is_dir()
                and packages.parts[-3:] == ("lib", "python3.12", "site-packages")
                and packages.is_relative_to(recipe.base.SCRATCH)
                and (packages / "mcp-2.3.0.dist-info/METADATA").is_file(), "prepared MCP package directory required")
            services["provider"]["command"].append("--mcp-smoke")
            services["check"].update(image=PYTHON_IMAGE, entrypoint=["/usr/local/bin/python", "-I", "-B"])
            services["check"]["command"].append("--mcp-smoke")
            services["check"]["volumes"].append(recipe.base.bind(packages, MCP_PACKAGES))
        runner.project, runner.services = config["name"], services
        require(not runner.container_rows("preexisting") and runner.no_project_networks("preexisting-networks"), "project already exists")
        images, runner.image_environments = {}, {}
        for index, image in enumerate(sorted({service["image"] for service in services.values()})):
            value = json.loads(runner.command("image-" + str(index), ["docker", "image", "inspect", "--format",
                '{"id":{{json .Id}},"environment":{{json .Config.Env}},"entrypoint":{{json (index .Config "Entrypoint")}}}', image], 10))
            require(admitted_image_entrypoint(image, value["entrypoint"]), "image entrypoint differs")
            images[image], runner.image_environments[image] = value["id"], environment(value["environment"])
        runner.save("run.claim.json", {"sourceCommit": args.commit, "source": str(source), "binarySha256": args.expected_binary_sha256,
            "checkerSha256": recipe.base.digest(source / SCRIPT), "images": images, "jobRoot": str(root), "syntheticOnly": True,
            "mcpSdkPackages": str(args.mcp_sdk_packages) if args.mcp_sdk_packages else None})
        (root / "runtime").mkdir(mode=0o700)
        compose_file = root / "compose.json"
        with compose_file.open("x") as stream:
            json.dump(config, stream, sort_keys=True, indent=2)
        compose = ["docker", "compose", "-f", str(compose_file), "-p", runner.project]
        armed = True
        for phase, profile in (("initialize", "prepare"), ("network-files", "network-files")):
            runner.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], 30)
        phase, keeper = "network", time.monotonic()
        runner.command("network", compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
        phase = "app-and-gate"
        runner.start_app_then_gate(compose)
        phase = "pki-edge"
        runner.command("basic-pki", compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
        runner.command("edge", compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
        runner.command("create-check", compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build", "--pull", "never", "--no-deps", "check"], 10)
        phase = "inspect"
        identities = runner.inspect_runtime(config, images, keeper_anchor=keeper)
        runner.deadline = runner.admit_checker_window(identities["edge"], keeper_anchor=keeper, work_anchor=begun)
        phase = "check"
        raw = runner.command("connected-check", ["docker", "start", "--attach", identities["check"]], 190)
        result = json.loads(raw)
        runner.save("result.json", result)
        require(result.get("ok") is True, "connected check failed")
        phase, success = "complete", True
    except BaseException as error:
        failure = {"exceptionType": type(error).__name__, "sourceSite": failure_site(error, source)}
    finally:
        runner.deadline = time.monotonic() + 60
        if armed:
            try:
                rows = runner.container_rows("cleanup-before")
                for row in rows:
                    name = row["Config"]["Labels"]["com.docker.compose.service"]
                    if name in {"provider", "serverware", "decision-gate-rs"}:
                        runner.command("retained-" + name + "-logs", ["docker", "logs", "--tail", "60", row["Id"]], 3)
                ids = [row["Id"] for row in rows]
                if ids:
                    runner.command("cleanup-stop", ["docker", "stop", "--time", "5", *ids], 20)
                    runner.command("cleanup-remove", ["docker", "rm", *ids], 10)
                clean = not runner.container_rows("cleanup-after") and runner.no_project_networks("cleanup-networks")
            except Exception:
                clean = False
        terminal = {"success": success, "cleanup": clean, "phase": phase, "failure": failure,
            "sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
            "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True, "realProviderVerified": False}
        runner.save("terminal.json", terminal)
        print(json.dumps(terminal, sort_keys=True), flush=True)
    return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    host = modes.add_parser("run")
    for name in ("source", "binary", "job-root", "evidence"):
        host.add_argument("--" + name, type=Path, required=True)
    for name in ("commit", "expected-binary-sha256"):
        host.add_argument("--" + name, required=True)
    host.add_argument("--mcp-sdk-packages", type=Path,
        help="Opt into only two MCP OpenAI calls, using an existing Python 3.12 site-packages tree")
    client = modes.add_parser("check")
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-curl-sha256"):
        client.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "curl-binary"):
        client.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        client.add_argument("--" + name, type=Path)
    client.add_argument("--timeout-seconds", type=int, default=180)
    client.add_argument("--mcp-smoke", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if args.mode == "run":
        for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
            os.environ.pop(name, None)
        os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
        return run(args)
    return check(args)


if __name__ == "__main__":
    raise SystemExit(main())
