#!/usr/bin/env python3
"""One-shot, private standalone baseline. No providers, host ports or live state.

Start deliberately returns with an empty instance for separately approved browser
inspection. This is installer integration, not successful provider dispatch.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parents[1]
CLI = SOURCE / "scripts/serverware_standalone.py"
IMAGE = "sha256:28b5ed4743d4ff6b98950799214550994466f68210c4377fb26be22434b89408"
REVISION = "133b967f0542d961385c5a9b2971028f53158453"
PROBE_IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"
CONSOLE, PROXY = "console.install.serverware.example", "proxy.install.serverware.example"
SUBNETS = {"control": "172.16.249.64/28", "outbound": "172.16.249.80/28"}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def write(path, value, mode=0o600):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run(args, *, data=None, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    require(len(result.stdout) <= 4 * 1024**2 and len(result.stderr) <= 4 * 1024**2, "bounded command output exceeded")
    return result


def docker(*args):
    value = run(["docker", *args])
    require(value.returncode == 0, "Docker readback failed")
    return value.stdout


def probe():
    """Actual TLS/HTTP from the instance outbound network; input never logged."""
    params = json.loads(sys.stdin.buffer.read(65537))
    context = ssl.create_default_context(cadata=params["certificate"])
    context.set_alpn_protocols(["http/1.1"])
    authorization = "Basic " + base64.b64encode(("admin:" + params["password"]).encode()).decode()

    def request(path, authenticated=True, payload=None):
        with socket.create_connection((params["edge_ip"], 8443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=CONSOLE) as connection:
                data = b"" if payload is None else json.dumps(payload).encode()
                headers = [("GET" if payload is None else "POST") + " " + path + " HTTP/1.1", "Host: " + CONSOLE,
                    "Connection: close", "Accept-Encoding: identity"]
                if authenticated:
                    headers.append("Authorization: " + authorization)
                if payload is not None:
                    headers.extend(["Origin: https://" + CONSOLE, "Content-Type: application/json", "Content-Length: " + str(len(data))])
                connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(connection)
                response.begin()
                body = response.read(2 * 1024**2 + 1)
                require(len(body) <= 2 * 1024**2, "HTTP response bound exceeded")
                return response.status, body

    def catalog_read():
        status, body = request("/api/operator-demo/catalog")
        require(status == 200, "authenticated catalog unavailable")
        return json.loads(body)

    def projection(catalog):
        return {**{name: catalog[name] for name in ("revision", "credentials", "applications", "access_rules")},
            "policy": {name: catalog["policy"][name] for name in ("policy_hash", "sequence", "activation", "loaded_policy_hash")}}

    mode = params.get("mode", "empty")
    if mode in {"create", "read"}:
        catalog = catalog_read()
        if mode == "create":
            require(all(catalog[name] == [] for name in ("credentials", "applications", "access_rules")), "create requires empty catalog")
            journal = Path("/private/actions.jsonl")
            descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                def record(value):
                    stream.write(json.dumps(value, sort_keys=True) + "\n"); stream.flush(); os.fsync(stream.fileno())

                def create(route, payload, result_key, collection):
                    before = catalog_read()
                    record({"stage": "before_send", "route": route, "revision": before["revision"], "policyHash": before["policy"]["policy_hash"]})
                    payload.update(expected_revision=before["revision"], expected_policy_hash=before["policy"]["policy_hash"])
                    status, body = request("/api/operator-demo" + route, payload=payload)
                    require(status == 201, "synthetic catalog creation refused")
                    result = json.loads(body)
                    resource = result[result_key]
                    record({"stage": "acknowledged", "route": route, "id": resource["id"], "revision": result["revision"]})
                    if "client_token" in result:
                        write(Path("/private/client-token.json"), {"application_id": resource["id"], "client_token": result["client_token"]})
                    after = catalog_read()
                    require(result["revision"] == before["revision"] + 1 == after["revision"]
                        and any(row["id"] == resource["id"] for row in after[collection]), "acknowledged resource missing in fresh read")
                    return resource

                credential = create("/credentials", {"name": "Installer synthetic OpenAI key", "auth_type": "bearer",
                    "header_name": "Authorization", "secret": "synthetic-installer-" + secrets.token_urlsafe(32), "app_preset": "openai"}, "credential", "credentials")
                application = create("/applications", {"name": "Installer synthetic client", "token_lifetime_seconds": 3600,
                    "proxy_authentication": "basic_and_bearer_v1"}, "application", "applications")
                create("/access-rules/common-app", {"name": "Installer bounded response", "application_id": application["id"],
                    "credential_id": credential["id"], "app_preset": "openai", "operation": "responses_text_v1",
                    "scope": {"model": "fixture-model", "max_output_tokens": 16}}, "access_rule", "access_rules")
                record({"stage": "all_three_acknowledged"})
        deadline = time.monotonic() + 20
        while True:
            catalog = catalog_read()
            policy = catalog["policy"]
            if policy["activation"] == "active" and policy["policy_hash"] == policy["loaded_policy_hash"]:
                break
            require(time.monotonic() < deadline, "saved policy did not activate")
            time.sleep(0.25)
        status, ca = request("/ca.pem")
        require(status == 200 and b"PRIVATE KEY" not in ca, "public CA unavailable")
        status, raw = request("/api/audit?limit=500")
        require(status == 200, "audit readback unavailable")
        events = json.loads(raw)
        require(isinstance(events, list) and all(row["event_type"] not in {
            "data_plane.credential.release_started", "data_plane.upstream.request_started", "data_plane.response.released"} for row in events),
            "unexpected provider dispatch audit")
        print(json.dumps({"catalog": projection(catalog), "proxyCaDigest": digest(ca), "providerReleaseAuditRows": 0}))
        return
    require(mode == "empty", "unknown bounded probe mode")

    require(request("/api/operator-demo/catalog", False)[0] == 401, "console did not require Basic authentication")
    status, body = request("/api/operator-demo/catalog")
    require(status == 200, "authenticated catalog unavailable")
    catalog = json.loads(body)
    require(catalog.get("schema") == "serverware.operatorCatalog/v1"
        and catalog.get("allowed_upstreams") == ["https://api.openai.com"], "fresh catalog profile differs")
    require(all(catalog.get(name) == [] for name in ("credentials", "applications", "access_rules")), "fresh installation was not empty")
    policy = catalog["policy"]
    require(policy["activation"] == "active" and policy["policy_hash"] == policy["loaded_policy_hash"], "initial deny-all policy not loaded")
    status, ca = request("/ca.pem")
    require(status == 200 and b"BEGIN CERTIFICATE" in ca and b"PRIVATE KEY" not in ca, "public proxy CA download differs")
    with socket.create_connection((params["edge_ip"], 8443), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=PROXY) as connection:
            connection.sendall(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(connection)
            response.begin()
            require(response.status == 403, "unauthenticated proxy CONNECT not denied")
    print(json.dumps({"consoleUnauthenticated": 401, "consoleAuthenticated": 200,
        "proxyUnauthenticated": 403, "emptyCatalog": True, "policyHash": policy["policy_hash"],
        "catalogRevision": catalog["revision"], "proxyCaDigest": digest(ca), "providerRequests": 0}))


class Baseline:
    def __init__(self, job, image=IMAGE):
        self.job = job
        self.image = image
        self.phase = "preflight"
        self.started = time.monotonic()
        self.number = 0

    def cli(self, operation, *arguments, expected=0, timeout=150):
        self.phase = operation
        self.number += 1
        result = run([sys.executable, "-B", str(CLI), operation, *map(str, arguments), "--json"], timeout=timeout)
        prefix = self.job / f"cli-{self.number:02d}-{operation}"
        write(prefix.with_suffix(".stdout"), result.stdout)
        write(prefix.with_suffix(".stderr"), result.stderr)
        require(result.returncode == expected, "installer CLI " + operation + " returned unexpected status")
        return json.loads(result.stdout) if result.returncode == 0 else None

    def inspect(self, project):
        identifiers = docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project).decode().split()
        require(len(identifiers) == 3, "expected exactly three installation services")
        rows = json.loads(docker("inspect", *identifiers))
        result = {}
        for row in rows:
            labels = row["Config"]["Labels"]
            role = labels["com.docker.compose.service"]
            require(role in {"serverware", "decision-gate-rs", "edge"} and role not in result, "unexpected service role")
            require(not row["HostConfig"].get("PortBindings"), "test installation published a host port")
            result[role] = {"id": row["Id"], "image": row["Image"], "startedAt": row["State"]["StartedAt"],
                "networks": {key: value["IPAddress"] for key, value in row["NetworkSettings"]["Networks"].items()}}
        return result

    def start(self):
        require(os.geteuid() == 0 and {name for _, name in socket.if_nameindex()} == {"lo"}, "use the approved network-none root tool container")
        require(self.job.is_absolute() and self.job.resolve() == self.job and stat.S_IMODE(self.job.stat().st_mode) == 0o700,
            "job must be an exact private directory")
        require(not list(self.job.iterdir()), "start refuses a previously used job")
        host_files = ["scripts/serverware_standalone.py", *["scripts/operator_install/" + name + ".py"
            for name in ("bootstrap", "lifecycle", "config", "process", "state", "compose", "tls")]]
        host_hashes = {name: digest((SOURCE / name).read_bytes()) for name in host_files}
        write(self.job / "start.claim.json", {"schema": "serverware.standaloneBaselineClaim/v1",
            "imageRevision": REVISION, "hostInstallerFiles": host_hashes})
        (self.job / "tmp").mkdir(mode=0o700)
        os.environ["TMPDIR"] = str(self.job / "tmp")
        # Recheck only selected address ranges, without mutating any network.
        identifiers = docker("network", "ls", "--quiet").decode().split()
        require(len(identifiers) <= 512, "network inventory exceeds bounded preflight")
        for offset in range(0, len(identifiers), 50):
            for row in json.loads(docker("network", "inspect", *identifiers[offset:offset + 50])):
                for entry in row.get("IPAM", {}).get("Config") or []:
                    if entry.get("Subnet"):
                        selected = ipaddress.ip_network(entry["Subnet"], strict=False)
                        require(selected.version != 4 or not any(selected.overlaps(ipaddress.ip_network(value)) for value in SUBNETS.values()), "selected installation subnet already allocated")
        self.phase = "certificate"
        certificate, key = self.job / "outer.crt", self.job / "outer.key"
        generated = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=" + CONSOLE,
            "-addext", "subjectAltName=DNS:" + CONSOLE + ",DNS:" + PROXY])
        require(generated.returncode == 0, "synthetic TLS generation failed")
        key.chmod(0o600)
        password = secrets.token_urlsafe(32)
        write(self.job / "console.password", password.encode())
        project = "serverware-install-" + secrets.token_hex(5)
        state = self.job / "state"
        configuration = {"schema": "serverware.standaloneInstall/v1", "project_name": project, "state_dir": str(state),
            "console_origin": "https://" + CONSOLE, "proxy_origin": "https://" + PROXY,
            "allowed_upstreams": ["https://api.openai.com"], "tls_certificate": str(certificate), "tls_private_key": str(key),
            "paired_image": self.image, "publish_address": None, "network_subnets": SUBNETS}
        write(self.job / "config.json", configuration)
        initialized = self.cli("init", "--config", self.job / "config.json", "--admin-password-file", self.job / "console.password")
        require(initialized["status"] == "initialized", "initializer status differs")
        manifest_before = (state / "manifest.json").read_bytes()
        manifest = json.loads(manifest_before)
        require(manifest["artifact"]["sourceRevision"] == REVISION and manifest["config"]["paired_image"] == self.image, "paired image provenance differs")
        self.cli("init", "--config", self.job / "config.json", "--admin-password-file", self.job / "console.password", expected=1)
        require((state / "manifest.json").read_bytes() == manifest_before, "repeat init changed retained manifest")
        ready = self.cli("start", "--state-dir", state, "--timeout", "120")
        require(ready["status"] == "ready", "startup did not reach paired readiness")
        services = self.inspect(project)
        outbound = project + "_outbound"
        edge_ip = services["edge"]["networks"][outbound]
        self.phase = "empty-instance-probe"
        result = run(["docker", "run", "--rm", "--pull", "never", "--network", outbound, "--read-only", "--user", "10001:10001",
            "--cpus", "1", "--memory", "128m", "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--label", "io.serverware.acceptance=" + manifest["instance_id"], "--mount", "type=bind,src=" + str(SOURCE) + ",dst=" + str(SOURCE) + ",readonly",
            "--entrypoint", "python", "-i", PROBE_IMAGE, "-B", str(Path(__file__).resolve()), "--probe"],
            data=json.dumps({"edge_ip": edge_ip, "certificate": certificate.read_text(), "password": password}).encode(), timeout=40)
        write(self.job / "probe.stderr", result.stderr)
        require(result.returncode == 0, "empty-instance authenticated probe failed")
        observed = json.loads(result.stdout)
        require(observed["proxyCaDigest"] == digest((state / "app-data/mitmproxy/mitmproxy-ca-cert.pem").read_bytes()), "downloaded CA differs from retained proxy CA")
        write(self.job / "empty-probe.json", observed)
        public = self.job / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        write(public / "outer.crt", certificate.read_bytes(), mode=0o644)
        receipt = {"schema": "serverware.standaloneBaselineReady/v1", "sourceRevision": REVISION, "pairedImage": self.image,
            "hostInstallerFiles": host_hashes,
            "project": project, "instanceId": manifest["instance_id"], "stateDir": str(state), "services": services,
            "edgeIp": edge_ip, "consoleHost": CONSOLE, "proxyHost": PROXY, "seconds": round(time.monotonic() - self.started, 3),
            "emptyProbe": observed, "hostPorts": False, "providerAcceptance": False, "awaitingBrowser": True}
        write(public / "ready.json", receipt, mode=0o644)
        print(json.dumps(receipt, sort_keys=True))

    def verify(self):
        require(os.geteuid() == 0 and {name for _, name in socket.if_nameindex()} == {"lo"}, "use the approved root tool container")
        ready = json.loads((self.job / "public/ready.json").read_bytes())
        state, project = self.job / "state", ready["project"]
        manifest = json.loads((state / "manifest.json").read_bytes())
        require(manifest["instance_id"] == ready["instanceId"] and manifest["config"]["paired_image"] == self.image
            and self.inspect(project) == ready["services"], "ready installation identity changed")
        write(self.job / "verify.claim.json", {"oneShot": True, "instanceId": ready["instanceId"], "writes": 3})
        os.environ["TMPDIR"] = str(self.job / "tmp")
        self.number = 10
        private = self.job / "verification-private"
        private.mkdir(mode=0o700); os.chown(private, 10001, 10001)
        certificate = self.job / "outer.crt"
        probe_number = 0

        def call_probe(mode):
            nonlocal probe_number
            probe_number += 1
            self.phase = "verify-probe-" + mode
            services = self.inspect(project)
            result = run(["docker", "run", "--rm", "--pull", "never", "--network", project + "_outbound", "--read-only", "--user", "10001:10001",
                "--cpus", "1", "--memory", "128m", "--pids-limit", "32", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--label", "io.serverware.acceptance=" + ready["instanceId"],
                "--mount", "type=bind,src=" + str(SOURCE) + ",dst=" + str(SOURCE) + ",readonly",
                "--mount", "type=bind,src=" + str(private) + ",dst=/private",
                "--entrypoint", "python", "-i", PROBE_IMAGE, "-B", str(Path(__file__).resolve()), "--probe"],
                data=json.dumps({"mode": mode, "edge_ip": services["edge"]["networks"][project + "_outbound"],
                    "certificate": certificate.read_text(), "password": (self.job / "console.password").read_text()}).encode(), timeout=70)
            write(self.job / f"verify-probe-{probe_number}.stderr", result.stderr)
            require(result.returncode == 0, "bounded verification probe failed; inspect private action journal without replay")
            value = json.loads(result.stdout)
            write(self.job / f"verify-probe-{probe_number}.json", value)
            return value

        before_ids = self.inspect(project)
        started = time.monotonic()
        require(self.cli("start", "--state-dir", state)["status"] == "ready", "idempotent start failed")
        idempotent_seconds = round(time.monotonic() - started, 3)
        require(self.inspect(project) == before_ids, "already-ready start restarted a service")
        created = call_probe("create")
        require(created["catalog"]["revision"] == 4 and all(len(created["catalog"][name]) == 1
            for name in ("credentials", "applications", "access_rules")), "expected exactly three saved resources")
        protected = [str(path.relative_to(state)) for path in (state / "service-secrets").iterdir()]
        protected += ["app-data/mitmproxy/mitmproxy-ca-cert.pem", "app-data/mitmproxy/mitmproxy-ca.pem",
            "app-data/policy-signing-ed25519.pem", "app-data/policy-signing-ed25519.pub.pem", "app-data/response-signing-ed25519.pem"]
        hashes = {name: digest((state / name).read_bytes()) for name in protected}
        token_hash = digest((private / "client-token.json").read_bytes())
        require(self.cli("stop", "--state-dir", state)["status"] == "stopped", "stop failed")
        require(self.cli("status", "--state-dir", state)["status"] == "not_ready", "stopped status differs")
        started = time.monotonic()
        require(self.cli("start", "--state-dir", state)["status"] == "ready", "retained restart failed")
        restart_seconds = round(time.monotonic() - started, 3)
        require({name: row["id"] for name, row in self.inspect(project).items()} == {name: row["id"] for name, row in before_ids.items()}, "restart replaced container identities")
        require(call_probe("read") == created, "restart changed saved resources, policy or public CA")
        pair_before = self.inspect(project)
        certificate, key = self.job / "replacement.crt", self.job / "replacement.key"
        generated = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=" + CONSOLE,
            "-addext", "subjectAltName=DNS:" + CONSOLE + ",DNS:" + PROXY])
        require(generated.returncode == 0, "replacement test certificate generation failed")
        key.chmod(0o600)
        replacement = self.cli("replace-tls", "--state-dir", state, "--certificate", certificate, "--private-key", key)
        require(replacement["status"] == "ready" and replacement["tls"]["verified_hostnames"] == 2, "replacement dual-host TLS proof differs")
        after_tls = self.inspect(project)
        require(all(after_tls[name] == pair_before[name] for name in ("serverware", "decision-gate-rs")), "TLS replacement restarted the app or gate")
        require(after_tls["edge"]["id"] == pair_before["edge"]["id"] and after_tls["edge"]["startedAt"] != pair_before["edge"]["startedAt"], "TLS replacement did not restart only the original edge")
        require(call_probe("read") == created, "TLS replacement changed catalog, policy or public CA")
        require({name: digest((state / name).read_bytes()) for name in protected} == hashes
            and digest((private / "client-token.json").read_bytes()) == token_hash, "retained CA, signing keys or credentials changed")
        require(self.cli("stop", "--state-dir", state)["status"] == "stopped", "final stop failed")
        # Remove only this verified, stopped project's exact resources. Keep all files.
        for row in self.inspect(project).values():
            actual = json.loads(docker("inspect", row["id"]))[0]
            require(not actual["State"]["Running"] and actual["Config"]["Labels"]["io.serverware.installation"] == ready["instanceId"], "cleanup ownership/state differs")
            docker("rm", row["id"])
        networks = docker("network", "ls", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project).decode().split()
        require(len(networks) == 2, "cleanup network count differs")
        for identifier in networks:
            row = json.loads(docker("network", "inspect", identifier))[0]
            require(row["Labels"]["io.serverware.installation"] == ready["instanceId"] and not row["Containers"], "cleanup network ownership differs")
            docker("network", "rm", identifier)
        require(not docker("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project).strip()
            and not docker("network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project).strip(), "owned resources remain")
        receipt = {"schema": "serverware.standaloneBaselineVerified/v1", "project": project, "instanceId": ready["instanceId"],
            "syntheticWrites": 3, "catalogRevision": 4, "policyHash": created["catalog"]["policy"]["policy_hash"],
            "idempotentStartSeconds": idempotent_seconds, "restartSeconds": restart_seconds,
            "dualSniTlsReplacement": True, "retainedKeysAndCaUnchanged": True, "ownedRemaining": 0,
            "providerAcceptance": False, "hostPorts": False, "seconds": round(time.monotonic() - self.started, 3)}
        write(self.job / "public/verified.json", receipt, mode=0o644)
        print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    os.umask(0o077)
    if args.probe:
        probe()
        return
    require(args.job is not None, "private job path required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "exact immutable image required")
    baseline = Baseline(args.job, args.image)
    try:
        baseline.verify() if args.verify else baseline.start()
    except Exception as error:
        failure = {"ok": False, "phase": baseline.phase, "errorType": type(error).__name__,
            "seconds": round(time.monotonic() - baseline.started, 3), "automaticRetry": False}
        if args.job.is_dir() and not (args.job / "failure.json").exists():
            write(args.job / "failure.json", failure)
        print(json.dumps(failure, sort_keys=True))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
