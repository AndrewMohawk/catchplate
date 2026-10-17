#!/usr/bin/env python3
"""Fixed entrypoint for the Python-backed OCI verification lanes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import multiprocessing
import os
import runpy
import secrets
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path("/opt/catchplate/src")
RESULT_PREFIX = "CATCHPLATE_OCI_LANE_RESULT="
MAX_WATCHDOG_RESPONSE_BYTES = 4 * 1024 * 1024
SHA256_PREFIX = "sha256:"
FIXED_SCRIPTS = {
    "approval-review": ("scripts/test_approval_review.py", ()),
    "clean-room": ("scripts/test_agent_trust_clean_room.py", ()),
    "credential-constraints": ("scripts/test_credential_constraints.py", ()),
    "credential-constraints-proxy": (
        "scripts/test_credential_constraints.py",
        ("--proxy-transport-only",),
    ),
    "internal-service-auth": ("scripts/test_internal_service_auth.py", ()),
    "jit-transaction-sqlite-full": (
        "scripts/test_jit_transaction_state.py",
        ("--sqlite-only",),
    ),
    "onboarding-evidence": ("scripts/test_onboarding_evidence.py", ()),
    "portal-browser-oauth": ("scripts/test_portal_browser_oauth.py", ()),
    "webauthn-attestation": ("scripts/test_webauthn_attestation.py", ()),
}
PYTHON_PROBE_ROLES = {
    "browser-python-compatibility",
    "host-python-compatibility",
    "proxy-python-compatibility",
}
ALL_ROLES = frozenset(
    {
        *FIXED_SCRIPTS,
        *PYTHON_PROBE_ROLES,
        "chromium-compatibility",
    }
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _spawn_probe(queue: Any) -> None:
    queue.put("spawn-ok")


def _prepare_work_directories() -> None:
    work_fd = os.open(
        "/work",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW,
    )
    try:
        for name in ("home", "tmp"):
            try:
                os.mkdir(name, mode=0o700, dir_fd=work_fd)
            except FileExistsError:
                pass
            metadata = os.stat(name, dir_fd=work_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 65532
                or metadata.st_gid != 65532
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise RuntimeError(f"/work/{name} is not the fixed private directory")
    finally:
        os.close(work_fd)


def _python_probes() -> dict[str, Any]:
    addresses = sorted(
        {
            item[4][0]
            for item in socket.getaddrinfo(
                "localhost",
                9,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        }
    )
    if not addresses or any(
        address not in {"127.0.0.1", "::1"} for address in addresses
    ):
        raise RuntimeError("bounded DNS/NSS probe escaped localhost")

    with tempfile.TemporaryDirectory(dir="/work/tmp") as directory:
        database = Path(directory) / "probe.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE probe(value TEXT NOT NULL)")
            connection.execute("INSERT INTO probe(value) VALUES ('sqlite-ok')")
            value = connection.execute("SELECT value FROM probe").fetchone()
            connection.commit()
        finally:
            connection.close()
        if value != ("sqlite-ok",):
            raise RuntimeError("SQLite compatibility probe failed")

    context = multiprocessing.get_context("spawn")
    queue = context.Queue(maxsize=1)
    process = context.Process(target=_spawn_probe, args=(queue,))
    process.start()
    process.join(10)
    if process.exitcode != 0 or queue.get(timeout=1) != "spawn-ok":
        raise RuntimeError("multiprocessing spawn probe failed")

    provider_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    provider_context.minimum_version = ssl.TLSVersion.TLSv1_2
    provider_context.maximum_version = ssl.TLSVersion.TLSv1_3
    provider_context.load_default_certs()
    providers = sorted(
        {
            cipher.get("protocol", "")
            for cipher in provider_context.get_ciphers()
        }
    )
    if not providers:
        raise RuntimeError("OpenSSL provider probe returned no ciphers")
    return {
        "dnsNss": addresses,
        "multiprocessing": "spawn-ok",
        "opensslProtocols": providers,
        "sqlite": "memory-and-file-ok",
    }


def _chromium_probe() -> dict[str, Any]:
    profile = Path("/work/chromium-profile")
    profile.mkdir(mode=0o700)
    command = [
        "/opt/catchplate/chromium/chrome",
        "--headless=new",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-dev-shm-usage",
        "--disable-features=OptimizationHints,MediaRouter",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-sandbox",
        "--remote-debugging-pipe",
        f"--user-data-dir={profile}",
        "data:text/html,<title>catchplate-compatibility</title>",
    ]
    completed = subprocess.run(
        command,
        cwd="/work",
        env={
            "HOME": "/work/home",
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": "/work/tmp",
            "TZ": "UTC",
            "XDG_RUNTIME_DIR": "/run/catchplate-runtime",
        },
        input=(
            b'{"id":1,"method":"Browser.getVersion"}\x00'
            b'{"id":2,"method":"Browser.close"}\x00'
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Chromium no-network startup probe failed")
    return {
        "argvSha256": _sha256(_canonical_json(command)),
        "stderrSha256": _sha256(completed.stderr),
        "stdoutSha256": _sha256(completed.stdout),
    }


def _required_dynamic(name: str, *, token: bool = False) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"required dynamic environment is missing: {name}")
    if token and (
        len(value) != 64
        or any(item not in "0123456789abcdef" for item in value)
    ):
        raise RuntimeError(f"dynamic token is invalid: {name}")
    if not token and (
        not value.startswith(SHA256_PREFIX)
        or len(value) != len(SHA256_PREFIX) + 64
        or any(item not in "0123456789abcdef" for item in value[7:])
    ):
        raise RuntimeError(f"dynamic digest is invalid: {name}")
    return value


def _watchdog_npm_response(frame: dict[str, Any]) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    endpoint = os.environ.get("CATCHPLATE_WATCHDOG_ENDPOINT")
    if not endpoint:
        raise RuntimeError("watchdog endpoint is missing")
    expected_spki = _required_dynamic(
        "CATCHPLATE_WATCHDOG_TLS_SPKI_SHA256"
    )
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "watchdog.catchplate.internal"
        or parsed.port not in {None, 443}
        or parsed.path != "/v1/npm-publish-one-use"
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("watchdog endpoint escaped its fixed HTTPS origin")
    body = _canonical_json(frame)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        context=context,
        timeout=35,
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise RuntimeError("watchdog TLS socket is unavailable")
        certificate = connection.sock.getpeercert(binary_form=True)
        public_key = x509.load_der_x509_certificate(certificate).public_key()
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if _sha256(spki) != expected_spki:
            raise RuntimeError("watchdog TLS SPKI does not match its lane pin")
        connection.request(
            "POST",
            parsed.path,
            body=body,
            headers={
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_WATCHDOG_RESPONSE_BYTES + 1)
    finally:
        connection.close()
    if response.status != 200 or len(raw) > MAX_WATCHDOG_RESPONSE_BYTES:
        raise RuntimeError("watchdog rejected the bounded npm operation")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("watchdog npm response is not ASCII JSON") from exc
    if _canonical_json(value) != raw:
        raise RuntimeError("watchdog npm response is not canonical JSON")
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "apiVersion",
            "attempt",
            "companionResult",
            "reported428",
            "requestSha256",
            "responseSha256",
        }
        or value.get("apiVersion")
        != "catchplate.npmOneUsePortalResponse/v1"
        or value.get("attempt") != frame["attempt"]
        or value.get("requestSha256") != _sha256(body)
        or value.get("reported428") is not (frame["attempt"] == 1)
        or not isinstance(value.get("companionResult"), dict)
    ):
        raise RuntimeError("watchdog npm response binding is invalid")
    response_payload = dict(value)
    response_sha256 = response_payload.pop("responseSha256")
    if response_sha256 != _sha256(_canonical_json(response_payload)):
        raise RuntimeError("watchdog npm response digest is invalid")
    companion = value["companionResult"]
    companion_payload = dict(companion)
    companion_sha256 = companion_payload.pop("resultSha256", None)
    if (
        set(companion)
        != {
            "apiVersion",
            "argvSha256",
            "attempt",
            "environmentSha256",
            "exitCode",
            "leaseId",
            "manifestSha256",
            "operationInputSha256",
            "promotionReceiptSha256",
            "requestNonce",
            "resultSha256",
            "stderrBytes",
            "stderrSha256",
            "stdoutBytes",
            "stdoutSha256",
        }
        or companion.get("apiVersion") != "catchplate.npmOneUseResult/v2"
        or companion.get("attempt") != frame["attempt"]
        or companion.get("leaseId") != frame["leaseId"]
        or companion.get("manifestSha256") != frame["manifestSha256"]
        or companion.get("operationInputSha256")
        != frame["operationInputSha256"]
        or companion.get("promotionReceiptSha256")
        != frame["promotionReceiptSha256"]
        or companion.get("requestNonce") != frame["requestNonce"]
        or companion_sha256 != _sha256(_canonical_json(companion_payload))
    ):
        raise RuntimeError("npm companion result is not request-bound")
    return value


class _PortalNpmCompanionClient:
    def __init__(self) -> None:
        self._attempt = 0
        self._responses: list[dict[str, Any]] = []
        self._contract = {
            "nodeBinarySha256": _required_dynamic(
                "CATCHPLATE_NPM_NODE_SHA256"
            ),
            "nodeExecutable": Path("/opt/catchplate/node/bin/node"),
            "npmEntrypoint": Path("/opt/catchplate/npm/bin/npm-cli.js"),
            "npmEntrypointSha256": _required_dynamic(
                "CATCHPLATE_NPM_ENTRYPOINT_SHA256"
            ),
            "npmExecutable": Path("/opt/catchplate/npm/bin/npm-cli.js"),
            "npmExecutableSha256": _required_dynamic(
                "CATCHPLATE_NPM_ENTRYPOINT_SHA256"
            ),
            "npmPackageManifest": Path("/opt/catchplate/npm/package.json"),
            "npmPackageSha256": _required_dynamic(
                "CATCHPLATE_NPM_PACKAGE_SHA256"
            ),
            "npmVersion": "11.8.0",
        }

    def contract(self) -> dict[str, Any]:
        return dict(self._contract)

    def assert_contract(self, value: dict[str, Any]) -> None:
        if value != self._contract:
            raise RuntimeError("npm companion identity changed during the lane")

    def validate_command(
        self,
        command: list[str],
        *,
        contract: dict[str, Any],
    ) -> bool:
        return (
            contract == self._contract
            and bool(command)
            and command[0] == str(self._contract["npmExecutable"])
        )

    def run_publish(
        self,
        command: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> dict[str, Any]:
        self._attempt += 1
        if (
            self._attempt not in {1, 2}
            or len(command) != 14
            or command[1] != "publish"
            or not command[2].startswith(str(cwd) + "/")
            or command[6:]
            != [
                "--strict-ssl=true",
                "--fetch-retries=0",
                "--ignore-scripts=true",
                "--tag=latest",
                "--access=public",
                "--json",
                "--loglevel=error",
                "--progress=false",
            ]
            or environment
            != {
                "CI": "true",
                "HOME": str(cwd / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "NO_PROXY": "",
                "PATH": "/opt/catchplate/node/bin:/usr/bin:/bin",
                "TMPDIR": str(cwd / "tmp"),
                "no_proxy": "",
                "npm_config_audit": "false",
                "npm_config_cache": str(cwd / "cache"),
                "npm_config_fund": "false",
                "npm_config_globalconfig": str(cwd / "empty.npmrc"),
                "npm_config_tmp": str(cwd / "tmp"),
                "npm_config_update_notifier": "false",
                "npm_config_userconfig": str(cwd / "empty.npmrc"),
            }
        ):
            raise RuntimeError("portal selected a non-fixed npm operation")
        registry_argument = command[3]
        proxy_argument = command[4]
        ca_argument = command[5]
        if (
            not registry_argument.startswith("--registry=https://127.0.0.1:")
            or not registry_argument.endswith("/")
            or not proxy_argument.startswith("--https-proxy=http://127.0.0.1:")
            or not ca_argument.startswith("--cafile=")
        ):
            raise RuntimeError("portal npm fixture endpoints are invalid")
        registry_port = int(
            registry_argument.removeprefix(
                "--registry=https://127.0.0.1:"
            ).removesuffix("/")
        )
        proxy_port = int(
            proxy_argument.removeprefix("--https-proxy=http://127.0.0.1:")
        )
        tarball = Path(command[2]).read_bytes()
        ca_pem = Path(ca_argument.removeprefix("--cafile=")).read_text(
            encoding="ascii"
        )
        operation = {
            "apiVersion": "catchplate.npmOperationInput/v1",
            "caPem": ca_pem,
            "operation": "npm.publish.fixture",
            "packageTarballBase64": base64.b64encode(tarball).decode("ascii"),
            "packageTarballSha256": _sha256(tarball),
            "proxyPort": proxy_port,
            "registryPort": registry_port,
        }
        frame = {
            "apiVersion": "catchplate.npmOneUseRequest/v2",
            "attempt": self._attempt,
            "caPem": ca_pem,
            "lane": "portal-browser-oauth",
            "laneOneUseNonce": _required_dynamic(
                "CATCHPLATE_ONE_USE_NONCE", token=True
            ),
            "laneSequence": 10,
            "leaseId": _required_dynamic("CATCHPLATE_LEASE_ID", token=True),
            "manifestSha256": _required_dynamic(
                "CATCHPLATE_MANIFEST_SHA256"
            ),
            "operation": "npm.publish.fixture",
            "operationInputSha256": _sha256(_canonical_json(operation)),
            "packageTarballBase64": operation["packageTarballBase64"],
            "packageTarballSha256": operation["packageTarballSha256"],
            "promotionReceiptSha256": _required_dynamic(
                "CATCHPLATE_PROMOTION_RECEIPT_SHA256"
            ),
            "proxyPort": proxy_port,
            "registryPort": registry_port,
            "requestNonce": secrets.token_hex(32),
            "sequence": self._attempt,
        }
        response = _watchdog_npm_response(frame)
        companion = response["companionResult"]
        self._responses.append(
            {
                "attempt": self._attempt,
                "companionImageId": _required_dynamic(
                    "CATCHPLATE_NPM_COMPANION_IMAGE_ID"
                ),
                "companionResultSha256": companion["resultSha256"],
                "portalResponseSha256": response["responseSha256"],
                "requestSha256": response["requestSha256"],
            }
        )
        return {
            "exitCode": companion["exitCode"],
            "outputSha256": _sha256(
                _canonical_json(
                    {
                        "stderrSha256": companion["stderrSha256"],
                        "stdoutSha256": companion["stdoutSha256"],
                    }
                )
            ),
            "reported428": response["reported428"],
        }

    def observations(self) -> dict[str, Any]:
        if self._attempt != 2 or len(self._responses) != 2:
            raise RuntimeError("portal did not use exactly two npm companions")
        payload = {
            "apiVersion": "catchplate.portalNpmCompanionEvidence/v1",
            "companionImageId": _required_dynamic(
                "CATCHPLATE_NPM_COMPANION_IMAGE_ID"
            ),
            "invocationCount": 2,
            "responses": self._responses,
        }
        return {
            **payload,
            "evidenceSha256": _sha256(_canonical_json(payload)),
        }


def _run_fixed_script(role: str) -> None:
    relative, arguments = FIXED_SCRIPTS[role]
    script = ROOT / relative
    if role == "portal-browser-oauth":
        client = _PortalNpmCompanionClient()
        namespace = runpy.run_path(
            str(script),
            init_globals={"_CATCHPLATE_NPM_COMPANION_CLIENT": client},
            run_name="_catchplate_portal_browser_lane",
        )
        sys.argv = [str(script), *arguments]
        namespace["main"]()
        client.observations()
        return
    sys.argv = [str(script), *arguments]
    runpy.run_path(str(script), run_name="__main__")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--role", required=True, choices=sorted(ALL_ROLES))
    args = parser.parse_args()
    if sys.argv[1:] != ["--role", args.role]:
        parser.error("the OCI lane entrypoint accepts only one fixed role")
    if Path.cwd() != Path("/work"):
        parser.error("the OCI lane must start in /work")
    return args


def main() -> None:
    args = _parse_args()
    _prepare_work_directories()
    if args.role in PYTHON_PROBE_ROLES:
        payload = {
            "apiVersion": "catchplate.ociCapabilityProbeResult/v1",
            "probes": _python_probes(),
            "role": args.role,
        }
        result = {**payload, "resultSha256": _sha256(_canonical_json(payload))}
        print(RESULT_PREFIX + _canonical_json(result).decode("ascii"), flush=True)
        return
    if args.role == "chromium-compatibility":
        payload = {
            "apiVersion": "catchplate.ociCapabilityProbeResult/v1",
            "probes": _chromium_probe(),
            "role": args.role,
        }
        result = {**payload, "resultSha256": _sha256(_canonical_json(payload))}
        print(RESULT_PREFIX + _canonical_json(result).decode("ascii"), flush=True)
        return
    _run_fixed_script(args.role)


if __name__ == "__main__":
    main()
