#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import ctypes
import datetime as dt
import email.utils
import gzip
import hashlib
import http.cookies
import io
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unicodedata
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, parse_qsl, quote, urlsplit
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.oauth_provider_simulator import OAuthProviderSimulator  # noqa: E402


ADMIN_TOKEN = "browser-oauth-admin-token"
CREDENTIAL_LEASE_TOKEN = "browser-oauth-credential-lease-token"
AUDIT_TOKEN = "browser-oauth-audit-ingest-token"
GRANT_CONSUME_TOKEN = "browser-oauth-grant-consume-token"
RATE_LIMIT_CONSUME_TOKEN = "browser-oauth-rate-limit-consume-token"
RELEASE_AUTHORIZATION_TOKEN = "browser-oauth-release-authorization-token"
MANAGEMENT_TOKEN = "browser-oauth-management-token"
GOOGLE_NAME = "Browser Gmail OAuth"
X_NAME = "Browser X OAuth"
X_JIT_ROUTE_ID = "browser.x.post.one-per-day.jit"
NPM_JIT_ROUTE_ID = "browser.npm.common-writes.jit"
NPM_CONTENTION_ROUTE_ID = "browser.npm.publish.concurrent-one-use.jit"
NPM_CREDENTIAL_ID = "cred-demo-bearer"
NPM_PACKAGE_NAME = "@scope/serverware-browser"
NPM_PACKAGE_PATH = "@scope%2fserverware-browser"
NPM_PACKAGE_VERSION = "1.2.3"
NPM_CONTENTION_PACKAGE_NAME = "@scope/serverware-contention"
NPM_CONTENTION_PACKAGE_PATH = "@scope%2fserverware-contention"
NPM_CONTENTION_PACKAGE_VERSION = "9.8.7"
NPM_REMAINING_VERSION = "1.2.2"
NPM_REVISION = "42-deadbeef"
NPM_TOKEN_KEY = "token-key-browser-001"
NPM_FIXTURE_BEARER = "demo-token-from-vault"
GOOGLE_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
]
X_SCOPES = ["tweet.read", "tweet.write", "users.read", "offline.access"]
OAUTH_COOKIE_PREFIX = "__Host-serverware-oauth-"
OAUTH_STATE_TTL_SECONDS = 600
OAUTH_COOKIE_CLOCK_SKEW_SECONDS = 2
EXPECTED_NPM_VERSION = "11.8.0"
if "_SERVERWARE_NPM_COMPANION_CLIENT" not in globals():
    _SERVERWARE_NPM_COMPANION_CLIENT: Any | None = None
DEFAULT_TIMEOUT_MS = 20_000
JOURNEY_TIMEOUT_SECONDS = 10 * 60
CLEANUP_TIMEOUT_SECONDS = 90
MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CALLBACK_STREAM_BYTES = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_GATE_LOG_BYTES = 8 * 1024 * 1024
MAX_BROWSER_OBSERVATIONS = 20_000
MAX_ENROLLMENT_PACKET_BYTES = 1024 * 1024
HOST_ENROLLMENT_IDENTITY_VERSION = "serverware.agentTrustHostIdentity/v1"
HOST_ENROLLMENT_TOOLING_VERSION = "serverware.agentEnrollmentTooling/v1"
HOST_ENROLLMENT_EXPECTED_MODULES = {
    "serverware_agent_trust",
    "serverware_agent_trust.attestation",
    "serverware_agent_trust.enrollment",
    "serverware_agent_trust.http",
}
HOST_ENROLLMENT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
CONSOLIDATED_BUILD_VERSION = "serverware.consolidatedTestArtifacts/v2"
SAME_JOURNEY_CALLBACK_VERSION = "serverware.browserEnrollmentHostCallback/v1"
SAME_JOURNEY_RESULT_VERSION = "serverware.agentTrustSameJourneyResult/v1"
SAME_JOURNEY_NOT_ESTABLISHED = {
    "build-provenance",
    "hardware-attestation",
    "image-provenance",
    "independent-execution",
    "key-independence",
    "server-provenance",
    "source-provenance",
    "tee-custody",
}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HTTP_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_JOURNEY_DEADLINE: float | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _journey_timeout_seconds(*, label: str, cap: float) -> float:
    _require(cap > 0, f"{label} timeout cap must be positive")
    if _JOURNEY_DEADLINE is None:
        return cap
    remaining = _JOURNEY_DEADLINE - time.monotonic()
    _require(remaining > 0, f"browser journey deadline expired before {label}")
    return min(cap, remaining)


def _journey_timeout_ms(*, label: str, cap_ms: int = DEFAULT_TIMEOUT_MS) -> int:
    seconds = _journey_timeout_seconds(label=label, cap=cap_ms / 1000)
    return max(1, int(seconds * 1000))


def _run_with_hard_timeout(
    action: Callable[[], Any],
    *,
    label: str,
    timeout_seconds: float,
) -> Any:
    _require(
        hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread(),
        f"{label} requires main-thread POSIX interval timers",
    )
    _require(timeout_seconds > 0, f"{label} timeout must be positive")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    effective_timeout = min(
        timeout_seconds,
        previous_delay if previous_delay > 0 else timeout_seconds,
    )

    def expire(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"{label} exceeded {effective_timeout:.3f} seconds")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, effective_timeout)
    try:
        return action()
    finally:
        elapsed = time.monotonic() - started
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay > 0:
            remaining = previous_delay - elapsed
            if remaining > 0:
                signal.setitimer(
                    signal.ITIMER_REAL,
                    remaining,
                    previous_interval,
                )


def _enable_child_subreaper() -> None:
    _require(
        sys.platform.startswith("linux"),
        "the browser proof requires Linux child-subreaper process ownership",
    )
    libc = ctypes.CDLL(None, use_errno=True)
    pr_set_child_subreaper = 36
    result = libc.prctl(pr_set_child_subreaper, 1, 0, 0, 0)
    if result != 0:
        error_number = ctypes.get_errno()
        raise AssertionError(
            f"could not establish browser child-subreaper ownership: errno={error_number}"
        )


def _append_bounded(
    target: list[Any],
    value: Any,
    *,
    label: str,
    maximum: int = MAX_BROWSER_OBSERVATIONS,
) -> None:
    _require(len(target) < maximum, f"{label} exceeded its evidence-item bound")
    target.append(value)


def _read_bounded_file(path: Path, *, label: str, maximum: int) -> bytes:
    metadata = path.stat()
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and 0 < metadata.st_size <= maximum,
        f"{label} is not a bounded regular file",
    )
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    _require(
        len(raw) == metadata.st_size and len(raw) <= maximum,
        f"{label} changed or exceeded its byte bound while being read",
    )
    return raw


def _process_group_alive(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise AssertionError(
            f"cannot inspect task-owned process group {process_group_id}"
        ) from exc
    return True


def _stop_process_group(
    process: subprocess.Popen[bytes],
    *,
    label: str,
) -> None:
    process_group_id = process.pid
    if _process_group_alive(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if _process_group_alive(process_group_id):
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if _process_group_alive(process_group_id):
                try:
                    os.killpg(process_group_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    if _process_group_alive(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while _process_group_alive(process_group_id) and time.monotonic() < deadline:
            time.sleep(0.05)
    if process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    _require(
        process.poll() is not None,
        f"{label} process leader {process.pid} was not reaped",
    )
    _require(
        not _process_group_alive(process_group_id),
        f"{label} left task-owned descendants in process group {process_group_id}",
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _descendant_pids(root_pid: int) -> set[int]:
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    _require(
        completed.returncode == 0
        and not completed.stderr
        and len(completed.stdout) <= 1024 * 1024,
        "could not capture the browser harness process tree",
    )
    children: dict[int, set[int]] = {}
    for line in completed.stdout.decode("ascii").splitlines():
        fields = line.split()
        _require(
            len(fields) == 2 and all(field.isdigit() for field in fields),
            "process-tree output was malformed",
        )
        pid, parent_pid = (int(field) for field in fields)
        children.setdefault(parent_pid, set()).add(pid)
    descendants: set[int] = set()
    pending = list(children.get(root_pid, set()))
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children.get(pid, set()))
    return {pid for pid in descendants if _pid_alive(pid)}


def _wait_for_pids_to_exit(
    pids: set[int],
    *,
    label: str,
    timeout_seconds: float = 10,
) -> None:
    remaining = {pid for pid in pids if _pid_alive(pid)}
    deadline = time.monotonic() + timeout_seconds
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = {pid for pid in remaining if _pid_alive(pid)}
    _require(
        not remaining,
        f"{label} left task-owned child PIDs alive: {sorted(remaining)}",
    )


def _terminate_task_pids(pids: set[int], *, label: str) -> None:
    remaining = {pid for pid in pids if pid != os.getpid() and _pid_alive(pid)}
    for signal_value, timeout_seconds in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 5.0)):
        for pid in remaining:
            try:
                os.kill(pid, signal_value)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + timeout_seconds
        while remaining and time.monotonic() < deadline:
            for pid in tuple(remaining):
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    waited = 0
                if waited == pid or not _pid_alive(pid):
                    remaining.discard(pid)
            if remaining:
                time.sleep(0.05)
        if not remaining:
            break
    _require(
        not remaining,
        f"{label} could not terminate and reap task-owned PIDs: {sorted(remaining)}",
    )


def _terminate_all_task_descendants(
    baseline_child_pids: set[int],
    observed_child_pids: set[int],
    *,
    label: str,
) -> None:
    deadline = time.monotonic() + 20
    stable_empty_scans = 0
    while time.monotonic() < deadline:
        current = _descendant_pids(os.getpid()) - baseline_child_pids
        observed_child_pids.update(current)
        live = {pid for pid in current if _pid_alive(pid)}
        if live:
            stable_empty_scans = 0
            _terminate_task_pids(live, label=label)
            continue
        stable_empty_scans += 1
        if stable_empty_scans >= 3:
            return
        time.sleep(0.05)
    remaining = _descendant_pids(os.getpid()) - baseline_child_pids
    _require(
        not remaining,
        f"{label} left adopted task-owned descendants alive: {sorted(remaining)}",
    )


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str],
    label: str,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
) -> tuple[int, bytes, bytes]:
    bounded_timeout = _journey_timeout_seconds(
        label=label,
        cap=timeout_seconds,
    )
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    _require(
        process.stdout is not None and process.stderr is not None,
        f"{label} output pipes are unavailable",
    )
    stdout_output = bytearray()
    stderr_output = bytearray()
    streams = {
        process.stdout.fileno(): (
            "stdout",
            process.stdout,
            stdout_output,
            stdout_limit,
        ),
        process.stderr.fileno(): (
            "stderr",
            process.stderr,
            stderr_output,
            stderr_limit,
        ),
    }
    deadline = time.monotonic() + bounded_timeout
    try:
        while streams:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, f"{label} exceeded its time bound")
            ready, _, _ = select.select(
                [item[1] for item in streams.values()],
                [],
                [],
                min(0.25, remaining),
            )
            if not ready:
                continue
            for stream in ready:
                descriptor = stream.fileno()
                name, _, output, limit = streams[descriptor]
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, limit + 1 - len(output)),
                )
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                output.extend(chunk)
                _require(
                    len(output) <= limit,
                    f"{label} {name} exceeded {limit} bytes",
                )
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        returncode = int(process.returncode)
        stdout = bytes(stdout_output)
        stderr = bytes(stderr_output)
    except BaseException:
        _stop_process_group(process, label=label)
        raise
    finally:
        for _, stream, _, _ in list(streams.values()):
            stream.close()
    _stop_process_group(process, label=label)
    return returncode, stdout, stderr


def _cleanup_actions(
    actions: list[tuple[str, Callable[[], None]]],
) -> list[BaseException]:
    errors: list[BaseException] = []
    cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    for label, action in actions:
        remaining = cleanup_deadline - time.monotonic()
        if remaining <= 0:
            errors.append(
                TimeoutError(
                    f"{label} cleanup was not attempted after the absolute cleanup deadline"
                )
            )
            continue
        try:
            _run_with_hard_timeout(
                action,
                label=f"{label} cleanup",
                timeout_seconds=min(15, remaining),
            )
        except BaseException as exc:
            errors.append(AssertionError(f"{label} cleanup failed: {exc!r}"))
    return errors


def _raise_cleanup_errors(
    primary_error: BaseException | None,
    cleanup_errors: list[BaseException],
    *,
    label: str,
) -> None:
    if not cleanup_errors:
        return
    errors = (
        [primary_error, *cleanup_errors]
        if primary_error is not None
        else cleanup_errors
    )
    raise BaseExceptionGroup(label, errors)


def _reserve_https_socket() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.set_inheritable(False)
    return listener


def _reserve_loopback_port() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _required_sha256(value: str, *, label: str) -> str:
    _require(
        SHA256_RE.fullmatch(value) is not None,
        f"{label} must be sha256:<64 lower-case hex characters>",
    )
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            _require(key not in value, f"{label} contains duplicate key {key!r}")
            value[key] = item
        return value

    def reject_constant(value: str) -> Any:
        raise AssertionError(f"{label} contains non-standard constant {value!r}")

    def reject_float(value: str) -> Any:
        raise AssertionError(f"{label} contains forbidden floating-point value {value!r}")

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=reject_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{label} is not strict ASCII JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{label} root must be an object")
    return value


def _read_pinned_regular_file(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
    max_bytes: int = HOST_ENROLLMENT_MAX_TOTAL_BYTES,
) -> bytes:
    expected_sha256 = _required_sha256(expected_sha256, label=f"{label} digest")
    _require(hasattr(os, "O_NOFOLLOW"), f"{label} requires O_NOFOLLOW support")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssertionError(
            f"{label} cannot be opened as a non-symlink file: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
        _require(
            0 <= before.st_size <= max_bytes,
            f"{label} exceeds {max_bytes} bytes",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            _require(total <= max_bytes, f"{label} exceeds {max_bytes} bytes")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        _require(
            before_identity == after_identity,
            f"{label} changed while it was measured",
        )
        raw = b"".join(chunks)
        _require(
            "sha256:" + hashlib.sha256(raw).hexdigest() == expected_sha256,
            f"{label} differs from its caller-supplied digest pin",
        )
        return raw
    finally:
        os.close(descriptor)


def _resolve_manifest_path(value: str, *, label: str) -> Path:
    path = Path(value)
    candidate = path if path.is_absolute() else ROOT / path
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise AssertionError(f"{label} is unavailable: {candidate}") from exc


def _resolve_new_output_path(value: Path | None, *, label: str) -> Path | None:
    if value is None:
        return None
    path = Path(os.path.abspath(value))
    _require(path.parent.is_dir(), f"{label} parent is unavailable: {path.parent}")
    _require(not path.exists(), f"{label} already exists: {path}")
    return path


def _load_same_journey_contract(
    args: argparse.Namespace,
    *,
    decision_gate_binary: Path,
    response_proof_fixture: Path,
) -> dict[str, Any]:
    _require(
        args.same_journey_artifact_manifest is not None,
        "SERVERWARE_BROWSER_PREBUILT_BUILD_MANIFEST or "
        "--same-journey-artifact-manifest is required",
    )
    artifact_manifest_path = args.same_journey_artifact_manifest.resolve(strict=True)
    manifest_file_sha256 = _sha256_path(artifact_manifest_path)
    manifest_raw = _read_pinned_regular_file(
        artifact_manifest_path,
        manifest_file_sha256,
        label="same-journey consolidated build manifest",
        max_bytes=32 * 1024 * 1024,
    )
    manifest = _strict_json_object(
        manifest_raw,
        label="same-journey consolidated build manifest",
    )
    _require(
        set(manifest)
        == {
            "apiVersion",
            "artifacts",
            "assurance",
            "config",
            "manifestSha256",
            "source",
        }
        and manifest.get("apiVersion") == CONSOLIDATED_BUILD_VERSION,
        "same-journey consolidated build manifest schema changed",
    )
    manifest_payload = dict(manifest)
    embedded_manifest_sha256 = manifest_payload.pop("manifestSha256", None)
    _require(
        embedded_manifest_sha256
        == "sha256:"
        + hashlib.sha256(_canonical_json_bytes(manifest_payload)).hexdigest(),
        "same-journey consolidated build manifest self-digest is invalid",
    )
    build_manifest_sha256 = (
        "sha256:" + hashlib.sha256(_canonical_json_bytes(manifest)).hexdigest()
    )
    artifacts = manifest.get("artifacts")
    config = manifest.get("config")
    source = manifest.get("source")
    _require(
        isinstance(artifacts, dict)
        and isinstance(config, dict)
        and isinstance(source, dict)
        and isinstance(manifest.get("assurance"), dict)
        and (manifest["assurance"]).get("localArtifactConsistencyEstablished")
        is True
        and (manifest["assurance"]).get("buildProvenanceEstablished") is False
        and (manifest["assurance"]).get("sourceProvenanceEstablished") is False,
        "same-journey build manifest assurance is not local-only",
    )
    for value, label in (
        (args.same_journey_host_python, "prepared host interpreter"),
        (args.same_journey_callback_script, "prepared same-journey verifier"),
        (args.same_journey_host_identity, "prepared host identity"),
    ):
        _require(
            value is not None,
            f"{label} must be supplied by the consolidated test preparation",
        )

    def artifact_file(
        value: Any,
        *,
        label: str,
        expected_path: Path | None = None,
        max_bytes: int = HOST_ENROLLMENT_MAX_TOTAL_BYTES,
    ) -> tuple[Path, str, bytes]:
        _require(isinstance(value, dict), f"{label} identity is missing")
        path = _resolve_manifest_path(str(value.get("path") or ""), label=label)
        digest = _required_sha256(
            str(value.get("sha256") or ""),
            label=f"{label} digest",
        )
        if expected_path is not None:
            _require(path == expected_path, f"{label} path changed after preparation")
        raw = _read_pinned_regular_file(
            path,
            digest,
            label=label,
            max_bytes=max_bytes,
        )
        _require(
            value.get("size") == len(raw),
            f"{label} size changed after preparation",
        )
        return path, digest, raw

    decision_gate_entry = artifacts.get("decisionGate")
    _, decision_gate_sha256, _ = artifact_file(
        decision_gate_entry,
        label="consolidated decision-gate binary",
        expected_path=decision_gate_binary,
        max_bytes=256 * 1024 * 1024,
    )
    response_fixture_entry = artifacts.get("responseProofFixture")
    _, response_fixture_sha256, _ = artifact_file(
        response_fixture_entry,
        label="consolidated response-proof fixture",
        expected_path=response_proof_fixture,
        max_bytes=256 * 1024 * 1024,
    )
    _require(
        isinstance(response_fixture_entry, dict)
        and response_fixture_entry.get("independentlySourced") is False,
        "response-proof fixture incorrectly claims independent provenance",
    )

    host_identity_artifact = artifacts.get("hostIdentity")
    _require(
        isinstance(host_identity_artifact, dict)
        and isinstance(host_identity_artifact.get("document"), dict),
        "consolidated host identity is missing",
    )
    host_identity_path, host_identity_file_sha256, identity_raw = artifact_file(
        host_identity_artifact.get("file"),
        label="consolidated host identity file",
        max_bytes=1024 * 1024,
    )
    if args.same_journey_host_identity is not None:
        _require(
            args.same_journey_host_identity.resolve(strict=True) == host_identity_path,
            "caller host identity path differs from the consolidated build",
        )
    identity = _strict_json_object(identity_raw, label="same-journey host identity")
    _require(
        identity == host_identity_artifact["document"]
        and identity.get("apiVersion") == HOST_ENROLLMENT_IDENTITY_VERSION,
        "host identity file differs from the consolidated build document",
    )
    identity_payload = dict(identity)
    identity_sha256 = identity_payload.pop("identitySha256", None)
    _require(
        isinstance(identity_sha256, str)
        and identity_sha256
        == "sha256:" + hashlib.sha256(_canonical_json_bytes(identity_payload)).hexdigest(),
        "same-journey host identity self-digest is invalid",
    )
    interpreter = identity.get("interpreter")
    entrypoint = identity.get("entrypoint")
    modules = identity.get("modules")
    _require(
        isinstance(interpreter, dict)
        and isinstance(entrypoint, dict)
        and isinstance(modules, dict)
        and set(modules) == HOST_ENROLLMENT_EXPECTED_MODULES,
        "same-journey host identity has an incomplete executable or module closure",
    )
    host_python = _resolve_manifest_path(
        str(interpreter.get("path") or ""),
        label="host identity interpreter",
    )
    host_python_sha256 = _required_sha256(
        str(interpreter.get("sha256") or ""),
        label="host identity interpreter digest",
    )
    host_entrypoint = _resolve_manifest_path(
        str(entrypoint.get("path") or ""),
        label="host identity enrollment entrypoint",
    )
    host_entrypoint_sha256 = _required_sha256(
        str(entrypoint.get("sha256") or ""),
        label="host identity enrollment entrypoint digest",
    )
    _read_pinned_regular_file(
        host_python,
        host_python_sha256,
        label="same-journey host interpreter",
    )
    _read_pinned_regular_file(
        host_entrypoint,
        host_entrypoint_sha256,
        label="same-journey enrollment entrypoint",
    )
    if args.same_journey_host_python is not None:
        _require(
            args.same_journey_host_python.resolve(strict=True) == host_python,
            "caller host interpreter differs from the consolidated identity",
        )
    if args.same_journey_host_entrypoint is not None:
        _require(
            args.same_journey_host_entrypoint.resolve(strict=True) == host_entrypoint,
            "caller enrollment entrypoint differs from the consolidated identity",
        )

    callback_script, callback_script_sha256, _ = artifact_file(
        artifacts.get("sameJourneyVerifier"),
        label="consolidated same-journey verifier",
        max_bytes=1024 * 1024,
    )
    if args.same_journey_callback_script is not None:
        _require(
            args.same_journey_callback_script.resolve(strict=True) == callback_script,
            "caller callback script differs from the consolidated build",
        )

    chromium = artifacts.get("chromium")
    _require(
        isinstance(chromium, dict),
        "consolidated Chromium identity is missing",
    )
    chromium_path, chromium_sha256, _ = artifact_file(
        chromium.get("executable"),
        label="consolidated Playwright Chromium",
        max_bytes=512 * 1024 * 1024,
    )
    browser_environment = artifacts.get("browserEnvironment")
    _require(
        isinstance(browser_environment, dict)
        and isinstance(config.get("browserVenv"), str)
        and browser_environment.get("path") == config["browserVenv"],
        "consolidated browser environment identity is missing",
    )
    browser_venv = Path(os.path.abspath(config["browserVenv"]))
    browser_python = browser_venv / "bin" / "python"
    _require(
        browser_python.is_file(),
        "prepared browser interpreter is unavailable",
    )
    source_sha256 = _required_sha256(
        str(source.get("closureSha256") or ""),
        label="consolidated source closure digest",
    )
    if args.frozen_source_tree_sha256 is not None:
        _require(
            args.frozen_source_tree_sha256 == source_sha256,
            "caller source digest differs from the consolidated source closure",
        )
    source_root = _resolve_manifest_path(
        str(source.get("root") or ""),
        label="consolidated source root",
    )
    portal_script = Path(__file__).resolve(strict=True)
    try:
        portal_relative = portal_script.relative_to(source_root).as_posix()
    except ValueError as exc:
        raise AssertionError(
            "browser portal script is outside the consolidated source closure"
        ) from exc
    source_files = {
        item.get("path"): item
        for item in (source.get("files") or [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    portal_source_entry = source_files.get(portal_relative)
    _require(
        isinstance(portal_source_entry, dict),
        "browser portal script is absent from the consolidated source closure",
    )
    portal_script_sha256 = _required_sha256(
        str(portal_source_entry.get("sha256") or ""),
        label="browser portal script source digest",
    )
    _read_pinned_regular_file(
        portal_script,
        portal_script_sha256,
        label="browser portal script",
        max_bytes=256 * 1024 * 1024,
    )

    for supplied, expected, label in (
        (
            args.same_journey_host_python_sha256,
            host_python_sha256,
            "caller host interpreter digest",
        ),
        (
            args.same_journey_host_entrypoint_sha256,
            host_entrypoint_sha256,
            "caller enrollment entrypoint digest",
        ),
        (
            args.same_journey_callback_script_sha256,
            callback_script_sha256,
            "caller callback script digest",
        ),
        (
            args.same_journey_host_identity_sha256,
            host_identity_file_sha256,
            "caller host identity file digest",
        ),
        (
            args.same_journey_artifact_manifest_sha256,
            manifest_file_sha256,
            "caller build-manifest file digest",
        ),
    ):
        if supplied is not None:
            _require(supplied == expected, f"{label} differs from preparation")

    return {
        "artifactManifest": artifact_manifest_path,
        "artifactManifestDocument": manifest,
        "artifactManifestFileSha256": manifest_file_sha256,
        "buildManifestSha256": build_manifest_sha256,
        "browserPython": browser_python,
        "callbackScript": callback_script,
        "callbackScriptSha256": callback_script_sha256,
        "chromiumExecutable": chromium_path,
        "chromiumExecutableSha256": chromium_sha256,
        "decisionGateSha256": decision_gate_sha256,
        "frozenSourceTreeSha256": source_sha256,
        "hostEntrypoint": host_entrypoint,
        "hostEntrypointSha256": host_entrypoint_sha256,
        "hostIdentity": host_identity_path,
        "hostIdentityDocument": identity,
        "hostIdentityFileSha256": host_identity_file_sha256,
        "hostPython": host_python,
        "hostPythonSha256": host_python_sha256,
        "portalScript": portal_script,
        "portalScriptSha256": portal_script_sha256,
        "responseProofFixtureSha256": response_fixture_sha256,
        "resultOut": _resolve_new_output_path(
            args.same_journey_result_out,
            label="same-journey callback result output",
        ),
        "secureInstructionsOut": _resolve_new_output_path(
            args.same_journey_secure_instructions_out,
            label="same-journey authenticated instructions output",
        ),
    }


def _publish_private_file(path: Path, raw: bytes) -> None:
    absolute = Path(os.path.abspath(path))
    _require(
        absolute.is_absolute()
        and all(part not in {"", ".", ".."} for part in absolute.parts[1:]),
        f"private output path is invalid: {path}",
    )

    def open_parent() -> int:
        current = os.open(
            "/",
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            for component in absolute.parts[1:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                metadata = os.fstat(child)
                mode = stat.S_IMODE(metadata.st_mode)
                sticky_root = (
                    metadata.st_uid == 0
                    and bool(mode & stat.S_ISVTX)
                )
                if not (
                    stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_uid in {0, os.getuid()}
                    and (not mode & 0o022 or sticky_root)
                ):
                    os.close(child)
                    raise AssertionError(
                        f"private output ancestor is unsafe: {absolute}"
                    )
                os.close(current)
                current = child
            return current
        except BaseException:
            os.close(current)
            raise

    parent = open_parent()
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        parent_identity = os.fstat(parent)
        descriptor = os.open(
            absolute.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        _require(
            stat.S_ISREG(created.st_mode)
            and created.st_nlink == 1
            and created.st_uid == os.getuid()
            and stat.S_IMODE(created.st_mode) == 0o600,
            f"private output leaf is unsafe: {absolute}",
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, f"could not publish {path}")
            view = view[written:]
        os.fsync(descriptor)
        final_leaf = os.fstat(descriptor)
        _require(
            stat.S_ISREG(final_leaf.st_mode)
            and final_leaf.st_nlink == 1
            and final_leaf.st_uid == os.getuid()
            and stat.S_IMODE(final_leaf.st_mode) == 0o600
            and final_leaf.st_size == len(raw),
            f"private output metadata changed: {absolute}",
        )
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent)

        current_parent = open_parent()
        try:
            current_parent_identity = os.fstat(current_parent)
            current_leaf = os.stat(
                absolute.name,
                dir_fd=current_parent,
                follow_symlinks=False,
            )
            identity = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
            )
            leaf_identity = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
            _require(
                identity(current_parent_identity) == identity(parent_identity)
                and leaf_identity(current_leaf)
                == leaf_identity(final_leaf),
                f"private output path changed during publication: {absolute}",
            )
        finally:
            os.close(current_parent)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        try:
            current = os.stat(
                absolute.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            current = None
        if current is not None:
            _require(
                created_identity is not None
                and stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino) == created_identity,
                f"private output leaf was replaced: {absolute}",
            )
            os.unlink(absolute.name, dir_fd=parent)
            os.fsync(parent)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _process_started_at(pid: int, *, label: str) -> str:
    result = subprocess.run(
        ["ps", "-ww", "-p", str(pid), "-o", "lstart="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    _require(
        result.returncode == 0 and not result.stderr,
        f"could not capture the live {label} start identity",
    )
    try:
        value = result.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise AssertionError(f"{label} start identity is not UTF-8") from exc
    _require(
        bool(value) and "\x00" not in value and "\n" not in value,
        f"{label} start identity is malformed",
    )
    return value


def _write_local_fixture_attestation_documents(
    data_dir: Path,
    *,
    decision_gate_digest: str,
    response_proof_fixture_digest: str,
    contract: dict[str, Any],
) -> dict[str, Any]:
    binding = {
        "callbackScriptSha256": contract["callbackScriptSha256"],
        "callerSuppliedFrozenSourceTreeSha256": contract["frozenSourceTreeSha256"],
        "consolidatedBuildManifestFileSha256": contract[
            "artifactManifestFileSha256"
        ],
        "consolidatedBuildManifestSha256": contract["buildManifestSha256"],
        "decisionGateBinarySha256": decision_gate_digest,
        "hostIdentityFileSha256": contract["hostIdentityFileSha256"],
        "hostIdentitySha256": contract["hostIdentityDocument"]["identitySha256"],
        "responseProofFixtureSha256": response_proof_fixture_digest,
    }
    limitations = {
        "fixtureProvenanceOnly": True,
        "buildProvenanceEstablished": False,
        "buildReproductionProven": False,
        "hardwareAttestationEstablished": False,
        "hardwareAttestationProven": False,
        "imageProvenanceEstablished": False,
        "imageProvenanceProven": False,
        "independentSourceAuthorizationProven": False,
        "serverProvenanceProven": False,
        "sourceProvenanceEstablished": False,
        "sourceTreeMeasuredByThisJourney": False,
        "teeCustodyEstablished": False,
        "teeCustodyProven": False,
    }
    provenance_payload = {
        "apiVersion": "serverware.localFixtureReleaseProvenance/v1",
        "assurance": {
            "classification": "local-fixture-metadata-only",
            "factOrigin": "caller-supplied-and-locally-measured",
            **limitations,
        },
        "binding": binding,
        "provenance": {
            "data_plane": {
                "binary_digest": decision_gate_digest,
                "digestOrigin": "exact-prebuilt-file-and-consolidated-manifest",
            },
            "source_tree": {
                "digest": contract["frozenSourceTreeSha256"],
                "digestOrigin": "caller-supplied-frozen-pin",
                "independentlyAuthorized": False,
                "measuredByThisJourney": False,
            },
        },
        "signature": None,
        "warning": (
            "Local fixture provenance supplies enrollment pins only. It is not "
            "independent source authorization, build reproduction, image provenance, "
            "server provenance, hardware attestation, or TEE custody."
        ),
    }
    provenance_document = {
        **provenance_payload,
        "provenance_digest": (
            "sha256:" + hashlib.sha256(_canonical_json_bytes(provenance_payload)).hexdigest()
        ),
    }
    image_payload = {
        "apiVersion": "serverware.localFixtureImageSignatures/v1",
        "assurance": {
            "classification": "unsigned-local-fixture-binding",
            **limitations,
        },
        "binding": {
            **binding,
            "releaseProvenanceDigest": provenance_document["provenance_digest"],
        },
        "signatures": [],
        "signatureProvider": "none-local-fixture",
        "warning": (
            "This unsigned local fixture is digest-bound metadata, not an image "
            "signature or independent image provenance proof."
        ),
    }
    image_document = {
        **image_payload,
        "image_signature_bundle_digest": (
            "sha256:" + hashlib.sha256(_canonical_json_bytes(image_payload)).hexdigest()
        ),
    }
    provenance_path = data_dir / "release-provenance.json"
    image_signatures_path = data_dir / "image-signatures.json"
    _publish_private_file(
        provenance_path,
        _canonical_json_bytes(provenance_document) + b"\n",
    )
    _publish_private_file(
        image_signatures_path,
        _canonical_json_bytes(image_document) + b"\n",
    )
    return {
        "assurance": limitations,
        "binding": binding,
        "imageSignaturesDigest": image_document["image_signature_bundle_digest"],
        "imageSignaturesPath": image_signatures_path,
        "provenanceDigest": provenance_document["provenance_digest"],
        "provenancePath": provenance_path,
        "sourceTreeDigest": contract["frozenSourceTreeSha256"],
    }


def _write_mitm_ca(work_dir: Path) -> tuple[Path, Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Serverware browser Rust gate CA")]
    )
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = work_dir / "decision-gate-mitm-ca.pem"
    key_path = work_dir / "decision-gate-mitm-ca-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    return cert_path, key_path


def _configure_environment(
    data_dir: Path,
    public_url: str,
    simulator: OAuthProviderSimulator,
    data_plane_digest: str,
) -> None:
    public_host = urlsplit(public_url).hostname
    _require(
        public_host == "localhost",
        "browser journey must use the exact localhost origin",
    )
    service_tokens = {
        CREDENTIAL_LEASE_TOKEN,
        AUDIT_TOKEN,
        GRANT_CONSUME_TOKEN,
        RATE_LIMIT_CONSUME_TOKEN,
        RELEASE_AUTHORIZATION_TOKEN,
        MANAGEMENT_TOKEN,
    }
    _require(len(service_tokens) == 6, "data-plane service tokens must be distinct")
    values = {
        "SERVERWARE_DATA_DIR": str(data_dir),
        "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PUBLIC_URL": public_url,
        "SERVERWARE_WEB_TLS_CERT_FILE": str(simulator.server_cert_path),
        "SERVERWARE_WEB_TLS_KEY_FILE": str(simulator.server_key_path),
        "SERVERWARE_ADMIN_TOKEN": ADMIN_TOKEN,
        "SERVERWARE_ADMIN_USER": "user:demo",
        "SERVERWARE_ADMIN_ROLES": (
            "admin,approver,auditor,policy_author,policy_publisher,credential_owner,"
            "attestation_operator,attestation_reviewer"
        ),
        "SERVERWARE_DEV_AUTHENTICATOR": "1",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_OIDC_ENABLED": "0",
        "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED": "0",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS": "credential.oauth.activate",
        "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "0",
        "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": "0",
        "SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED": "1",
        "SERVERWARE_POLICY_CANARY_REQUIRED": "0",
        "SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS": "0",
        "SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS": "0",
        "SERVERWARE_POLICY_CANARY_MAX_DENIALS": "0",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": simulator.GOOGLE_CLIENT_ID,
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET": simulator.GOOGLE_CLIENT_SECRET,
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/google",
        "SERVERWARE_X_OAUTH_CLIENT_ID": simulator.X_CLIENT_ID,
        "SERVERWARE_X_OAUTH_CLIENT_SECRET": simulator.X_CLIENT_SECRET,
        "SERVERWARE_X_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/x",
        "SERVERWARE_WEBAUTHN_RP_ID": public_host,
        "SERVERWARE_WEBAUTHN_ORIGIN": public_url,
        "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
            "spiffe://test.serverware/decision-gate/browser-oauth"
        ),
        "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": CREDENTIAL_LEASE_TOKEN,
        "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": AUDIT_TOKEN,
        "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": GRANT_CONSUME_TOKEN,
        "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": RATE_LIMIT_CONSUME_TOKEN,
        "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": (
            RELEASE_AUTHORIZATION_TOKEN
        ),
        "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": MANAGEMENT_TOKEN,
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
        "SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS": "30",
        "SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS": "30",
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": data_plane_digest,
        "SERVERWARE_RELEASE_PROVENANCE": str(
            data_dir / "release-provenance.json"
        ),
        "SERVERWARE_IMAGE_SIGNATURES": str(data_dir / "image-signatures.json"),
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "SERVERWARE_AUDIT_ANCHOR_URL": "",
        "SERVERWARE_DECISION_GATE_BASE": "",
        "SSL_CERT_FILE": str(simulator.ca_cert_path),
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }
    for name in (
        "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
        "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_ID",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_REDIRECT_URI",
    ):
        os.environ.pop(name, None)
    os.environ.update(values)


class _DecisionGateProcess:
    def __init__(
        self,
        *,
        binary: Path,
        response_proof_fixture: Path,
        data_dir: Path,
        portal_url: str,
        simulator: OAuthProviderSimulator,
    ) -> None:
        self.binary = binary
        self.response_proof_fixture = response_proof_fixture
        self.data_dir = data_dir
        self.portal_url = portal_url
        self.simulator = simulator
        self.proxy_port = _reserve_loopback_port()
        self.management_port = _reserve_loopback_port()
        self.ca_cert_path, self.ca_key_path = _write_mitm_ca(
            data_dir / "browser-rust-gate"
        )
        attestation_ca_path = data_dir / "mitmproxy" / "mitmproxy-ca-cert.pem"
        attestation_ca_path.parent.mkdir(parents=True, exist_ok=True)
        attestation_ca_path.write_bytes(self.ca_cert_path.read_bytes())
        attestation_ca_path.chmod(0o644)
        self.log_path = data_dir / "browser-rust-gate.log"
        self._log_handle: Any = None
        self._process: subprocess.Popen[bytes] | None = None
        self._log_monitor_stop = threading.Event()
        self._log_monitor_error: BaseException | None = None
        self._log_monitor_thread: threading.Thread | None = None

    @property
    def health_url(self) -> str:
        return f"http://127.0.0.1:{self.management_port}/healthz"

    @property
    def attestation_url(self) -> str:
        return f"http://127.0.0.1:{self.management_port}/attestation"

    @property
    def pid(self) -> int:
        _require(
            self._process is not None and self._process.poll() is None,
            "decision gate is not live",
        )
        return self._process.pid

    def started_at(self) -> str:
        return _process_started_at(self.pid, label="decision-gate")

    def attestation(self, nonce: str) -> dict[str, Any]:
        request = Request(
            self.attestation_url + "?nonce=" + quote(nonce, safe=""),
            headers={"Cache-Control": "no-store"},
        )
        with urlopen(request, timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
            _require(
                response.status == 200
                and len(raw) <= 1024 * 1024
                and response.headers.get_content_type() == "application/json",
                "decision-gate management attestation response is invalid",
            )
        return _strict_json_object(raw, label="decision-gate management attestation")

    def start(self) -> None:
        _require(self.binary.is_file(), f"decision gate binary is missing: {self.binary}")
        _require(
            os.access(self.binary, os.X_OK),
            f"decision gate binary is not executable: {self.binary}",
        )
        _require(
            self.response_proof_fixture.is_file(),
            f"response proof fixture is missing: {self.response_proof_fixture}",
        )
        _require(
            os.access(self.response_proof_fixture, os.X_OK),
            f"response proof fixture is not executable: {self.response_proof_fixture}",
        )
        env = os.environ.copy()
        env.update(
            {
                "SERVERWARE_POLICY_BUNDLE": str(self.data_dir / "policy-bundle.json"),
                "SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL": (
                    f"{self.portal_url}/attestation"
                ),
                "SERVERWARE_CONTROL_PLANE_CA_BUNDLE": str(
                    self.simulator.ca_cert_path
                ),
                "SERVERWARE_CONTROL_PLANE_CREDENTIAL_LEASE_URL": (
                    f"{self.portal_url}/api/data-plane/credential-leases"
                ),
                "SERVERWARE_CONTROL_PLANE_AUDIT_URL": (
                    f"{self.portal_url}/api/data-plane/audit"
                ),
                "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL": (
                    f"{self.portal_url}/api/data-plane/release-authorizations"
                ),
                "SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES": "1",
                "SERVERWARE_RELEASE_CHANNEL": "dev",
                "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
                "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": (
                    CREDENTIAL_LEASE_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": AUDIT_TOKEN,
                "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": GRANT_CONSUME_TOKEN,
                "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": (
                    RATE_LIMIT_CONSUME_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": (
                    RELEASE_AUTHORIZATION_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": MANAGEMENT_TOKEN,
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
                    "spiffe://test.serverware/decision-gate/browser-oauth"
                ),
                "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND": str(
                    self.response_proof_fixture
                ),
                "SERVERWARE_MITM_CA_CERT": str(self.ca_cert_path),
                "SERVERWARE_MITM_CA_KEY": str(self.ca_key_path),
                "SERVERWARE_UPSTREAM_CA_BUNDLE": str(self.simulator.ca_cert_path),
                "SERVERWARE_POLICY_POLL_SECONDS": "0.05",
                "SERVERWARE_CREDENTIAL_LEASE_POLL_SECONDS": "0.05",
                "SERVERWARE_DECISION_GATE_HOST": "127.0.0.1",
                "SERVERWARE_DECISION_GATE_PORT": str(self.proxy_port),
                "SERVERWARE_DECISION_GATE_MANAGEMENT_HOST": "127.0.0.1",
                "SERVERWARE_DECISION_GATE_MANAGEMENT_PORT": str(
                    self.management_port
                ),
                "SSL_CERT_FILE": str(self.simulator.ca_cert_path),
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
            }
        )
        self._log_handle = self.log_path.open("wb")
        self._process = subprocess.Popen(
            [str(self.binary)],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._log_monitor_thread = threading.Thread(
            target=self._monitor_log,
            name="serverware-browser-gate-log-monitor",
            daemon=True,
        )
        self._log_monitor_thread.start()

    def _monitor_log(self) -> None:
        while not self._log_monitor_stop.wait(0.1):
            try:
                if (
                    self.log_path.exists()
                    and self.log_path.stat().st_size > MAX_GATE_LOG_BYTES
                ):
                    self._log_monitor_error = AssertionError(
                        "decision-gate log exceeded its byte bound"
                    )
                    process = self._process
                    if process is not None and process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    return
            except BaseException as exc:
                self._log_monitor_error = exc
                return

    def _failure_detail(self) -> str:
        if self._log_handle is not None:
            self._log_handle.flush()
        if not self.log_path.exists():
            return ""
        _require(
            self.log_path.stat().st_size <= MAX_GATE_LOG_BYTES,
            "decision-gate log exceeded its byte bound",
        )
        with self.log_path.open("rb") as handle:
            handle.seek(max(0, self.log_path.stat().st_size - 4000))
            return handle.read(4000).decode("utf-8", errors="replace")

    def wait_ready(
        self,
        *,
        policy_hash: str,
        binary_digest: str,
        require_hot_generation: bool = False,
        timeout_seconds: float = 30,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + _journey_timeout_seconds(
            label="decision gate readiness",
            cap=timeout_seconds,
        )
        last: Any = None
        while time.monotonic() < deadline:
            if self._log_monitor_error is not None:
                raise AssertionError("decision-gate log monitor failed") from (
                    self._log_monitor_error
                )
            if self.log_path.exists():
                _require(
                    self.log_path.stat().st_size <= MAX_GATE_LOG_BYTES,
                    "decision-gate log exceeded its byte bound",
                )
            if self._process is None:
                raise AssertionError("decision gate was not started")
            if self._process.poll() is not None:
                raise AssertionError(
                    "decision gate exited before readiness: " + self._failure_detail()
                )
            try:
                request = Request(self.health_url, headers={"Cache-Control": "no-store"})
                with urlopen(request, timeout=2) as response:
                    last = json.loads(response.read(1024 * 1024))
            except Exception as exc:
                last = {"health_error": str(exc)}
                time.sleep(0.1)
                continue
            release = last.get("release_authorization") or {}
            audit = last.get("audit") or {}
            base_ready = (
                last.get("ok") is True
                and last.get("policy_hash") == policy_hash
                and last.get("data_plane_binary_digest") == binary_digest
                and last.get("policy_trust_root_source") == "attested-control-plane"
                and last.get("jit_grant_store") == "atomic_release_authorization"
                and last.get("shared_rate_limit_store") is True
                and release.get("enabled") is True
                and release.get("mode") == "reserve_dispatch_complete"
                and last.get("connect_preflight") is True
                and last.get("connect_mitm_interceptor") is True
                and audit.get("enabled") is True
                and audit.get("dropped") == 0
                and audit.get("required_failed") == 0
                and (last.get("policy_reload") or {}).get("failed") == 0
            )
            generation_ready = (
                last.get("credential_generations_ready") is True
                and (
                    not require_hot_generation
                    or (
                        int(last.get("credential_generation_hot_scopes") or 0) >= 1
                        and int(last.get("credential_generations") or 0) >= 1
                    )
                )
            )
            if base_ready and generation_ready:
                return last
            time.sleep(0.1)
        raise AssertionError(
            f"decision gate did not reach exact readiness: {last!r}; "
            f"log={self._failure_detail()}"
        )

    def close(self) -> None:
        process = self._process
        try:
            if process is not None:
                _stop_process_group(process, label="decision gate")
                self._process = None
        finally:
            self._log_monitor_stop.set()
            if self._log_monitor_thread is not None:
                self._log_monitor_thread.join(timeout=2)
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None
            _require(
                self._log_monitor_thread is None
                or not self._log_monitor_thread.is_alive(),
                "decision-gate log monitor did not stop",
            )
            if self._log_monitor_error is not None:
                raise AssertionError("decision-gate log cap was violated") from (
                    self._log_monitor_error
                )
            if self.log_path.exists():
                _require(
                    self.log_path.stat().st_size <= MAX_GATE_LOG_BYTES,
                    "decision-gate log exceeded its byte bound",
                )


def _certificate_spki_sha256(cert_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _certificate_spki_sha256_hex(cert_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def _closed_response_header_array(
    headers_array: list[dict[str, Any]],
    *,
    body: bytes,
    label: str,
) -> list[dict[str, str]]:
    _require(
        isinstance(headers_array, list)
        and 1 <= len(headers_array) <= 128,
        f"{label} omitted its ordered response header array",
    )
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for index, item in enumerate(headers_array):
        _require(isinstance(item, dict), f"{label} header {index} is not an object")
        _require(
            set(item) == {"name", "value"},
            f"{label} header {index} has an open schema",
        )
        name = item.get("name")
        value = item.get("value")
        _require(
            isinstance(name, str)
            and HTTP_FIELD_NAME_RE.fullmatch(name) is not None
            and isinstance(value, str)
            and all(ord(character) <= 255 for character in value)
            and "\r" not in value
            and "\n" not in value
            and "\x00" not in value,
            f"{label} header {index} is malformed",
        )
        normalized_name = name.lower()
        total_bytes += len(name.encode("ascii")) + len(value.encode("latin-1"))
        _require(
            total_bytes <= 64 * 1024,
            f"{label} response headers exceeded 64 KiB",
        )
        _require(
            normalized_name not in seen,
            f"{label} duplicated normalized header {normalized_name!r}",
        )
        seen.add(normalized_name)
        normalized.append({"name": normalized_name, "value": value})
    values = {item["name"]: item["value"] for item in normalized}
    _require(
        {
            "cache-control",
            "content-length",
            "content-type",
            "x-content-type-options",
            "x-serverware-enrollment-packet-sha256",
        }
        <= set(values),
        f"{label} omitted an authority-bearing response header",
    )
    _require(
        "transfer-encoding" not in values
        and "content-encoding" not in values
        and "content-range" not in values,
        f"{label} used encoded, ranged, or transfer-framed content",
    )
    content_length = values.get("content-length")
    _require(
        content_length is not None
        and content_length.isdigit()
        and content_length == str(len(body)),
        f"{label} Content-Length did not bind the exact body length",
    )
    return normalized


def _playwright_response_tls_evidence(
    page: Any,
    response: Any,
    *,
    expected_leaf_spki_sha256: str,
    origin: str,
) -> dict[str, Any]:
    security_details: dict[str, Any] | None = None
    server_address: dict[str, Any] | None = None
    try:
        details = response.security_details()
        if isinstance(details, dict):
            security_details = {
                "issuer": (
                    details.get("issuer")
                    if isinstance(details.get("issuer"), str)
                    else None
                ),
                "protocol": (
                    details.get("protocol")
                    if isinstance(details.get("protocol"), str)
                    else None
                ),
                "subjectName": (
                    details.get("subjectName")
                    if isinstance(details.get("subjectName"), str)
                    else None
                ),
                "validFrom": (
                    details.get("validFrom")
                    if type(details.get("validFrom")) is int
                    else None
                ),
                "validTo": (
                    details.get("validTo")
                    if type(details.get("validTo")) is int
                    else None
                ),
            }
    except Exception:
        security_details = None
    try:
        address = response.server_addr()
        if isinstance(address, dict):
            server_address = {
                "ipAddress": (
                    address.get("ipAddress")
                    if isinstance(address.get("ipAddress"), str)
                    else None
                ),
                "port": (
                    address.get("port")
                    if type(address.get("port")) is int
                    else None
                ),
            }
    except Exception:
        server_address = None

    certificate_sha256: str | None = None
    leaf_spki_sha256: str | None = None
    cdp_error: str | None = None
    cdp_session: Any = None
    try:
        cdp_session = page.context.new_cdp_session(page)
        result = cdp_session.send("Network.getCertificate", {"origin": origin})
        certificates = result.get("tableNames") if isinstance(result, dict) else None
        _require(
            isinstance(certificates, list)
            and bool(certificates)
            and all(isinstance(item, str) and item for item in certificates),
            "CDP did not return a closed certificate chain",
        )
        leaf_der = base64.b64decode(certificates[0], validate=True)
        certificate = x509.load_der_x509_certificate(leaf_der)
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_sha256 = "sha256:" + hashlib.sha256(leaf_der).hexdigest()
        leaf_spki_sha256 = "sha256:" + hashlib.sha256(spki).hexdigest()
        _require(
            leaf_spki_sha256 == expected_leaf_spki_sha256,
            "CDP response certificate differs from the pinned portal certificate",
        )
    except Exception as exc:
        cdp_error = f"{type(exc).__name__}: {exc}"
        certificate_sha256 = None
        leaf_spki_sha256 = None
    finally:
        if cdp_session is not None:
            try:
                cdp_session.detach()
            except Exception:
                pass
    response_specific_tls_proven = False
    if leaf_spki_sha256 is not None:
        cdp_error = (
            "Network.getCertificate is origin-scoped rather than response-scoped; "
            "the origin certificate and Playwright response metadata are not treated "
            "as proof of the exact enrollment response connection"
        )
    return {
        "apiVersion": "serverware.browserResponseTlsEvidence/v1",
        "originCertificateAvailable": leaf_spki_sha256 is not None,
        "responseSpecificTlsProven": response_specific_tls_proven,
        "certificateSha256": certificate_sha256,
        "leafSpkiSha256": leaf_spki_sha256,
        "expectedLeafSpkiSha256": expected_leaf_spki_sha256,
        "securityDetails": security_details,
        "serverAddress": server_address,
        "cdpUnavailableReason": cdp_error,
        "verifierContractBindsResponseSpecificTls": False,
    }


def _assert_host_callback_origin_resolution(public_url: str) -> None:
    parsed = urlsplit(public_url)
    _require(
        parsed.scheme == "https"
        and parsed.hostname == "localhost"
        and parsed.port is not None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment,
        "same-journey journey requires https://localhost:<port>",
    )
    try:
        addresses = {
            str(item[4][0])
            for item in socket.getaddrinfo(
                parsed.hostname,
                parsed.port,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as exc:
        raise AssertionError(
            "localhost must resolve for both Chromium and the host verifier"
        ) from exc
    _require(
        bool(addresses)
        and all(ipaddress.ip_address(value).is_loopback for value in addresses),
        f"same-journey hostname must resolve only to loopback: {addresses}",
    )


def _run_same_journey_callback(
    *,
    contract: dict[str, Any],
    fixture_facts: dict[str, Any],
    gate: _DecisionGateProcess,
    public_url: str,
    portal_ca_path: Path,
    portal_leaf_cert_path: Path,
    packet_path: Path,
    packet_bytes: bytes,
    packet: dict[str, Any],
    response_header_sha256: str,
    response_header_values: list[str],
    response_headers_array: list[dict[str, str]],
    response_tls_evidence: dict[str, Any],
    response_status: int,
    response_url: str,
    policy_sha256: str,
    decision_gate_digest: str,
    callback_dir: Path,
) -> dict[str, Any]:
    packet_sha256 = "sha256:" + hashlib.sha256(packet_bytes).hexdigest()
    _require(
        packet_sha256 == response_header_sha256,
        "same-journey callback packet and response digest header differ",
    )
    tooling = packet.get("tooling")
    pinning = packet.get("pinning")
    handoff = packet.get("agentHandoff")
    _require(
        isinstance(tooling, dict)
        and tooling.get("apiVersion") == HOST_ENROLLMENT_TOOLING_VERSION
        and isinstance(pinning, dict)
        and isinstance(handoff, dict),
        "same-journey enrollment packet lacks its closed tooling or pinning contract",
    )
    principal = packet.get("principalId")
    nonce = packet.get("nonce")
    authenticated_instructions = handoff.get("authenticatedInstructions")
    _require(
        isinstance(principal, str)
        and principal == "agent:demo"
        and isinstance(nonce, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce) is not None
        and isinstance(authenticated_instructions, str)
        and bool(authenticated_instructions),
        "same-journey enrollment identity or authenticated instructions are invalid",
    )
    _require(
        pinning.get("dataPlaneBinaryDigest") == decision_gate_digest
        and pinning.get("policyHash") == policy_sha256
        and pinning.get("sourceTreeDigest") == contract["frozenSourceTreeSha256"]
        and pinning.get("provenanceDigest") == fixture_facts["provenanceDigest"]
        and pinning.get("imageSignaturesDigest")
        == fixture_facts["imageSignaturesDigest"],
        "same-journey enrollment packet differs from its frozen local fixture pins",
    )
    for field in (
        "responseSigningKeyId",
        "runtimeManifestDigest",
        "sourceTreeDigest",
    ):
        _required_sha256(str(pinning.get(field) or ""), label=f"packet pin {field}")

    gate_challenge = (
        base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    )
    gate_attestation = gate.attestation(gate_challenge)
    gate_signer_boot_sha256 = str(
        gate_attestation.get("response_proof_signer_boot_digest") or ""
    )
    gate_server_instance_id = str(gate_attestation.get("server_instance_id") or "")
    _require(
        gate_attestation.get("nonce") == gate_challenge
        and gate_attestation.get("data_plane_binary_digest") == decision_gate_digest
        and gate_attestation.get("policy_bundle_digest") == policy_sha256
        and gate_attestation.get("policy_trust_root_source")
        == "attested-control-plane"
        and gate_attestation.get("source_tree_digest")
        == contract["frozenSourceTreeSha256"]
        and gate_attestation.get("provenance_digest")
        == fixture_facts["provenanceDigest"]
        and gate_attestation.get("image_signatures_digest")
        == fixture_facts["imageSignaturesDigest"]
        and gate_attestation.get("tee_platform") == "none-dev"
        and gate_attestation.get("quote") is None
        and gate_attestation.get("response_proof_signer_hardware_proof") is False
        and bool(gate_server_instance_id),
        "live Rust management attestation escaped its frozen local fixture identity",
    )
    _required_sha256(
        gate_signer_boot_sha256,
        label="Rust response-proof signer boot digest",
    )

    callback_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    callback_dir.chmod(0o700)
    callback_home = callback_dir / "home"
    callback_home.mkdir(mode=0o700)
    challenge_path = callback_dir / "browser-challenge"
    challenge = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
    _require(
        re.fullmatch(rb"[A-Za-z0-9_-]{43,128}", challenge) is not None,
        "same-journey browser challenge is malformed",
    )
    _publish_private_file(challenge_path, challenge)
    challenge_sha256 = "sha256:" + hashlib.sha256(challenge).hexdigest()
    instructions_path = contract["secureInstructionsOut"] or (
        callback_dir / "authenticated-instructions.txt"
    )
    result_path = contract["resultOut"] or (
        callback_dir / "same-journey-result.json"
    )
    _require(
        instructions_path != result_path,
        "same-journey instructions and result outputs must be distinct",
    )
    portal_ca_sha256 = _sha256_path(portal_ca_path)
    leaf_spki_sha256 = _certificate_spki_sha256_hex(portal_leaf_cert_path)
    _require(
        response_header_values == [response_header_sha256],
        "browser did not observe exactly one enrollment digest response header",
    )
    _require(
        [item for item in response_headers_array if item["name"]
         == "x-serverware-enrollment-packet-sha256"]
        == [
            {
                "name": "x-serverware-enrollment-packet-sha256",
                "value": response_header_sha256,
            }
        ],
        "browser response header array did not contain one exact packet digest",
    )
    response_headers_array_sha256 = (
        "sha256:"
        + hashlib.sha256(_canonical_json_bytes(response_headers_array)).hexdigest()
    )
    _require(
        set(response_tls_evidence)
        == {
            "apiVersion",
            "cdpUnavailableReason",
            "certificateSha256",
            "expectedLeafSpkiSha256",
            "leafSpkiSha256",
            "originCertificateAvailable",
            "responseSpecificTlsProven",
            "securityDetails",
            "serverAddress",
            "verifierContractBindsResponseSpecificTls",
        }
        and response_tls_evidence["apiVersion"]
        == "serverware.browserResponseTlsEvidence/v1"
        and response_tls_evidence["expectedLeafSpkiSha256"] == leaf_spki_sha256
        and response_tls_evidence["verifierContractBindsResponseSpecificTls"] is False,
        "browser response TLS evidence has an open or inconsistent schema",
    )
    _require(
        response_status == 200
        and response_url == public_url + "/api/agents/enrollment",
        "browser enrollment response status or URL differs from the exact HTTPS endpoint",
    )
    response_record = {
        "apiVersion": "serverware.browserEnrollmentResponse/v2",
        "bodyLength": len(packet_bytes),
        "bodySha256": packet_sha256,
        "framing": {
            "contentEncoding": None,
            "contentLength": len(packet_bytes),
            "transferEncoding": None,
        },
        "headersArray": response_headers_array,
        "nonce": nonce,
        "portalBootInstanceBound": False,
        "principal": principal,
        "responseSpecificTls": response_tls_evidence,
        "status": response_status,
        "url": response_url,
    }
    _require(
        set(response_record)
        == {
            "apiVersion",
            "bodyLength",
            "bodySha256",
            "framing",
            "headersArray",
            "nonce",
            "portalBootInstanceBound",
            "principal",
            "responseSpecificTls",
            "status",
            "url",
        }
        and set(response_record["framing"])
        == {"contentEncoding", "contentLength", "transferEncoding"},
        "browser enrollment response record schema is not closed",
    )
    response_record_path = callback_dir / "browser-response-record.json"
    response_record_raw = _canonical_json_bytes(response_record) + b"\n"
    _publish_private_file(response_record_path, response_record_raw)
    response_record_sha256 = (
        "sha256:" + hashlib.sha256(response_record_raw).hexdigest()
    )
    browser_pid = os.getpid()
    browser_started_at = _process_started_at(
        browser_pid,
        label="browser Python driver",
    )
    gate_started_at = gate.started_at()

    command = [
        str(contract["hostPython"]),
        str(contract["callbackScript"]),
        "verify-callback",
        "--identity",
        str(contract["hostIdentity"]),
        "--build-manifest",
        str(contract["artifactManifest"]),
        "--callback-version",
        SAME_JOURNEY_CALLBACK_VERSION,
        "--packet",
        str(packet_path),
        "--playwright-download-sha256",
        packet_sha256,
        "--response-header-sha256",
        response_header_sha256,
        "--response-record",
        str(response_record_path),
        "--response-record-sha256",
        response_record_sha256,
        "--principal",
        principal,
        "--nonce",
        nonce,
        "--https-origin",
        public_url,
        "--ca-bundle",
        str(portal_ca_path),
        "--ca-bundle-sha256",
        portal_ca_sha256,
        "--leaf-spki-sha256",
        leaf_spki_sha256,
        "--browser-challenge",
        str(challenge_path),
        "--browser-challenge-sha256",
        challenge_sha256,
        "--browser-pid",
        str(browser_pid),
        "--browser-python",
        str(contract["browserPython"]),
        "--portal-pid",
        str(browser_pid),
        "--portal-started-at",
        browser_started_at,
        "--portal-script",
        str(contract["portalScript"]),
        "--portal-script-sha256",
        contract["portalScriptSha256"],
        "--gate-pid",
        str(gate.pid),
        "--gate-started-at",
        gate_started_at,
        "--gate-binary",
        str(gate.binary),
        "--gate-binary-sha256",
        decision_gate_digest,
        "--gate-attestation-url",
        gate.attestation_url,
        "--gate-server-instance-id",
        gate_server_instance_id,
        "--gate-signer-boot-sha256",
        gate_signer_boot_sha256,
        "--host-python",
        str(contract["hostPython"]),
        "--response-proof-fixture",
        str(gate.response_proof_fixture),
        "--policy-sha256",
        policy_sha256,
        "--response-signing-key-id",
        str(pinning["responseSigningKeyId"]),
        "--runtime-manifest-sha256",
        str(pinning["runtimeManifestDigest"]),
        "--source-tree-sha256",
        str(pinning["sourceTreeDigest"]),
        "--quote-provider",
        "dev-signed-quote",
        "--fact-origin",
        "host-supplied",
        "--secure-instructions-out",
        str(instructions_path),
        "--result-out",
        str(result_path),
    ]
    environment = {
        "HOME": str(callback_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "SSL_CERT_FILE": str(portal_ca_path),
        "TZ": "UTC",
        "SERVERWARE_BROWSER_SAME_JOURNEY_CALLBACK": "1",
        "SERVERWARE_BROWSER_ATTESTATION_SOURCE": "live-host-supplied",
        "SERVERWARE_BROWSER_ENROLLMENT_FIXTURE": "0",
        "SERVERWARE_BROWSER_GATE_STATE": "running",
        "SERVERWARE_BROWSER_PORTAL_STATE": "running",
        "SERVERWARE_BROWSER_BUILD_MANIFEST": str(
            contract["artifactManifest"].absolute()
        ),
        "SERVERWARE_BROWSER_PREBUILT_BUILD_MANIFEST": str(
            contract["artifactManifest"].absolute()
        ),
        "SERVERWARE_BROWSER_PREBUILT_HOST_IDENTITY": str(
            contract["hostIdentity"].absolute()
        ),
        "SERVERWARE_BROWSER_SAME_JOURNEY_PYTHON": str(
            contract["hostPython"].absolute()
        ),
        "SERVERWARE_BROWSER_SAME_JOURNEY_VERIFIER": str(
            contract["callbackScript"].absolute()
        ),
        "SERVERWARE_BROWSER_PID": str(browser_pid),
        "SERVERWARE_BROWSER_PORTAL_PID": str(browser_pid),
        "SERVERWARE_BROWSER_PACKET_PATH": str(packet_path.absolute()),
        "SERVERWARE_BROWSER_RESPONSE_RECORD_PATH": str(
            response_record_path.absolute()
        ),
        "SERVERWARE_BROWSER_RESPONSE_RECORD_SHA256": response_record_sha256,
        "SERVERWARE_BROWSER_CHALLENGE_PATH": str(challenge_path.absolute()),
        "SERVERWARE_BROWSER_HTTPS_ORIGIN": public_url,
        "SERVERWARE_BROWSER_PLAYWRIGHT_DOWNLOAD_SHA256": packet_sha256,
        "SERVERWARE_BROWSER_RESPONSE_HEADER_SHA256": response_header_sha256,
        "SERVERWARE_BROWSER_ENROLLMENT_PRINCIPAL": principal,
        "SERVERWARE_BROWSER_ENROLLMENT_NONCE": nonce,
        "SERVERWARE_BROWSER_GATE_PID": str(gate.pid),
        "SERVERWARE_BROWSER_GATE_BINARY_SHA256": decision_gate_digest,
        "SERVERWARE_BROWSER_RESPONSE_SIGNING_KEY_ID": str(
            pinning["responseSigningKeyId"]
        ),
        "ALL_PROXY": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "NO_PROXY": "",
        "all_proxy": "",
        "http_proxy": "",
        "https_proxy": "",
        "no_proxy": "",
    }
    try:
        returncode, callback_stdout, callback_stderr = _run_bounded_process(
            command,
            environment=environment,
            label="same-journey host verifier",
            timeout_seconds=120,
            stdout_limit=MAX_CALLBACK_STREAM_BYTES,
            stderr_limit=MAX_CALLBACK_STREAM_BYTES,
        )
    except FileNotFoundError as exc:
        raise AssertionError(
            "same-journey host verifier did not complete synchronously"
        ) from exc
    _require(
        returncode == 0
        and not callback_stderr
        and 0 < len(callback_stdout) <= MAX_CALLBACK_STREAM_BYTES,
        "same-journey host verifier failed: "
        + callback_stderr.decode("utf-8", errors="replace"),
    )
    callback_output = _strict_json_object(
        callback_stdout,
        label="same-journey callback stdout",
    )
    _require(
        set(callback_output) == {"ok", "result"}
        and callback_stdout == _canonical_json_bytes(callback_output) + b"\n",
        "same-journey callback wrapper was not exact canonical JSON",
    )
    result = callback_output.get("result")
    _require(
        callback_output.get("ok") is True
        and isinstance(result, dict)
        and set(result)
        == {
            "apiVersion",
            "assurance",
            "browserBinding",
            "frozenLocalBuild",
            "hostInstalledIdentity",
            "instructions",
            "live",
            "ok",
        }
        and result.get("apiVersion") == SAME_JOURNEY_RESULT_VERSION
        and result.get("ok") is True,
        "same-journey callback did not return its closed success result",
    )

    expected_instruction_bytes = authenticated_instructions.encode("utf-8")
    expected_instruction_sha256 = (
        "sha256:" + hashlib.sha256(expected_instruction_bytes).hexdigest()
    )
    normalized_instruction = unicodedata.normalize("NFC", authenticated_instructions)

    def assert_no_instruction_text(value: Any, *, path: str = "result") -> None:
        if isinstance(value, str):
            normalized_value = unicodedata.normalize("NFC", value)
            _require(
                normalized_instruction not in normalized_value,
                f"same-journey callback disclosed authenticated instructions at {path}",
            )
            return
        if isinstance(value, dict):
            for key, item in value.items():
                assert_no_instruction_text(item, path=f"{path}.{key}")
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                assert_no_instruction_text(item, path=f"{path}[{index}]")

    assert_no_instruction_text(result)
    instruction_bytes = _read_pinned_regular_file(
        instructions_path,
        expected_instruction_sha256,
        label="same-journey authenticated instructions",
        max_bytes=1024 * 1024,
    )
    _require(
        instruction_bytes == expected_instruction_bytes,
        "same-journey callback output is not byte-for-byte authenticated instructions",
    )
    result_file_sha256 = (
        "sha256:"
        + hashlib.sha256(_canonical_json_bytes(result) + b"\n").hexdigest()
    )
    result_file = _read_pinned_regular_file(
        result_path,
        result_file_sha256,
        label="same-journey callback result",
        max_bytes=1024 * 1024,
    )
    _require(
        result_file == _canonical_json_bytes(result) + b"\n",
        "same-journey callback result file differs from callback stdout",
    )

    assurance = result.get("assurance")
    instructions = result.get("instructions")
    live = result.get("live")
    browser_binding = result.get("browserBinding")
    frozen_build = result.get("frozenLocalBuild")
    live_processes = (
        (live.get("processes") or {}) if isinstance(live, dict) else {}
    )
    live_process_before = live_processes.get("before") or {}
    live_gate = (live.get("gate") or {}) if isinstance(live, dict) else {}
    live_portal = (live.get("portal") or {}) if isinstance(live, dict) else {}
    live_tls = (live.get("tls") or {}) if isinstance(live, dict) else {}
    _require(
        isinstance(assurance, dict)
        and set(assurance)
        == {
            "buildProvenanceEstablished",
            "classification",
            "hardwareAttestationEstablished",
            "imageProvenanceEstablished",
            "independentExecutionEstablished",
            "keyIndependenceEstablished",
            "localArtifactConsistencyEstablished",
            "localFixtureProvenance",
            "notEstablished",
            "serverProvenanceEstablished",
            "sourceProvenanceEstablished",
            "teeCustodyEstablished",
        }
        and assurance.get("classification")
        == "host-installed-live-same-journey-consistency"
        and assurance.get("buildProvenanceEstablished") is False
        and assurance.get("hardwareAttestationEstablished") is False
        and assurance.get("imageProvenanceEstablished") is False
        and assurance.get("independentExecutionEstablished") is False
        and assurance.get("keyIndependenceEstablished") is False
        and assurance.get("localArtifactConsistencyEstablished") is True
        and assurance.get("localFixtureProvenance")
        == "caller-supplied-local-build-artifact"
        and assurance.get("serverProvenanceEstablished") is False
        and assurance.get("sourceProvenanceEstablished") is False
        and assurance.get("teeCustodyEstablished") is False
        and set(assurance.get("notEstablished") or ())
        == SAME_JOURNEY_NOT_ESTABLISHED
        and isinstance(instructions, dict)
        and set(instructions)
        == {
            "command",
            "secureOutputPath",
            "sha256",
            "size",
            "stderrEmpty",
            "stdoutExact",
            "textIncludedInResult",
        }
        and instructions.get("sha256") == expected_instruction_sha256
        and instructions.get("size") == len(expected_instruction_bytes)
        and instructions.get("stdoutExact") is True
        and instructions.get("stderrEmpty") is True
        and instructions.get("textIncludedInResult") is False
        and instructions.get("command")
        == "serverware-enrollment --verify-packet --emit-verified-instructions"
        and instructions.get("secureOutputPath") == str(instructions_path.absolute())
        and isinstance(browser_binding, dict)
        and set(browser_binding)
        == {
            "callbackVersion",
            "challengeSha256",
            "httpsOrigin",
            "nonce",
            "playwrightDownloadSha256",
            "principal",
            "responseHeaderSha256",
            "responseRecordSha256",
            "synchronousBrowserAncestor",
        }
        and browser_binding.get("callbackVersion") == SAME_JOURNEY_CALLBACK_VERSION
        and browser_binding.get("challengeSha256") == challenge_sha256
        and browser_binding.get("httpsOrigin") == public_url
        and browser_binding.get("playwrightDownloadSha256") == packet_sha256
        and browser_binding.get("responseHeaderSha256") == response_header_sha256
        and browser_binding.get("responseRecordSha256") == response_record_sha256
        and browser_binding.get("principal") == principal
        and browser_binding.get("nonce") == nonce
        and browser_binding.get("synchronousBrowserAncestor") is True
        and isinstance(frozen_build, dict)
        and set(frozen_build)
        == {
            "buildManifestSha256",
            "independentlyAuthorized",
            "sourceClosureSha256",
            "sourceProvenanceEstablished",
        }
        and isinstance(live, dict)
        and set(live) == {"gate", "portal", "processes", "tls"}
        and set(live_gate) == {"pre", "post"}
        and set(live_gate.get("pre") or {})
        == {
            "binarySha256",
            "policySha256",
            "serverInstanceId",
            "signerBootSha256",
            "sourceClosureSha256",
        }
        and live_gate.get("pre") == live_gate.get("post")
        and set(live_portal) == {"pre", "post"}
        and set(live_portal.get("pre") or {})
        == {
            "factOrigin",
            "quoteProvider",
            "quoteSha256",
            "responseSigningKeyId",
            "runtimeManifestSha256",
            "tlsLeafSpkiSha256",
        }
        and set(live_portal.get("post") or {})
        == set(live_portal.get("pre") or {})
        and set(live_processes) == {"before", "after"}
        and set(live_process_before)
        == {
            "browserPid",
            "browserPython",
            "gateBinary",
            "gateBinarySha256",
            "gateListener",
            "gatePid",
            "gateStartedAt",
            "portalListener",
            "portalPid",
            "portalScript",
            "portalScriptSha256",
            "portalStartedAt",
        }
        and set(live_process_before.get("gateListener") or {})
        == {"listenerOwnershipChecked", "listenerPort"}
        and set(live_process_before.get("portalListener") or {})
        == {"listenerOwnershipChecked", "listenerPort"}
        and live_process_before == live_processes.get("after")
        and live_process_before.get("browserPid") == browser_pid
        and live_process_before.get("browserPython")
        == str(contract["browserPython"])
        and live_process_before.get("portalPid") == browser_pid
        and live_process_before.get("portalStartedAt") == browser_started_at
        and live_process_before.get("portalScript")
        == str(contract["portalScript"])
        and live_process_before.get("portalScriptSha256")
        == contract["portalScriptSha256"]
        and live_process_before.get("gatePid") == gate.pid
        and live_process_before.get("gateStartedAt") == gate_started_at
        and live_process_before.get("gateBinary") == str(gate.binary)
        and live_process_before.get("gateBinarySha256") == decision_gate_digest
        and live_process_before.get("gateListener")
        == {
            "listenerOwnershipChecked": True,
            "listenerPort": gate.management_port,
        }
        and live_process_before.get("portalListener")
        == {
            "listenerOwnershipChecked": True,
            "listenerPort": urlsplit(public_url).port or 443,
        }
        and set(live_tls)
        == {"caBundleSha256", "leafSpkiSha256", "postLeafSpkiSha256"}
        and live_tls.get("caBundleSha256") == portal_ca_sha256
        and live_tls.get("leafSpkiSha256") == leaf_spki_sha256
        and live_tls.get("postLeafSpkiSha256")
        == leaf_spki_sha256,
        "same-journey callback result omitted an exact live, process, TLS, or "
        "authenticated-instructions binding",
    )
    portal_pre = (live.get("portal") or {}).get("pre") or {}
    portal_post = (live.get("portal") or {}).get("post") or {}
    gate_pre = (live.get("gate") or {}).get("pre") or {}
    _require(
        gate_pre.get("binarySha256") == decision_gate_digest
        and gate_pre.get("policySha256") == policy_sha256
        and gate_pre.get("serverInstanceId") == gate_server_instance_id
        and gate_pre.get("signerBootSha256") == gate_signer_boot_sha256
        and gate_pre.get("sourceClosureSha256")
        == str(pinning["sourceTreeDigest"]),
        "same-journey gate identity was not bound to independently captured values",
    )
    _require(
        portal_pre.get("quoteProvider") == "dev-signed-quote"
        and portal_pre.get("factOrigin") == "host-supplied"
        and portal_pre.get("responseSigningKeyId")
        == str(pinning["responseSigningKeyId"])
        and portal_pre.get("runtimeManifestSha256")
        == str(pinning["runtimeManifestDigest"])
        and portal_pre.get("tlsLeafSpkiSha256") == leaf_spki_sha256
        and SHA256_RE.fullmatch(str(portal_pre.get("quoteSha256") or ""))
        is not None
        and {
            key: value for key, value in portal_pre.items() if key != "quoteSha256"
        }
        == {
            key: value for key, value in portal_post.items() if key != "quoteSha256"
        },
        "same-journey portal identity changed or claimed non-development authority",
    )
    _require(
        result.get("hostInstalledIdentity") == contract["hostIdentityDocument"],
        "same-journey callback used a different prebuilt host identity",
    )
    _require(
        isinstance(frozen_build, dict)
        and frozen_build.get("buildManifestSha256")
        == contract["buildManifestSha256"]
        and frozen_build.get("sourceClosureSha256")
        == contract["frozenSourceTreeSha256"]
        and frozen_build.get("independentlyAuthorized") is False
        and frozen_build.get("sourceProvenanceEstablished") is False,
        "same-journey result escaped its frozen local-build assurance boundary",
    )
    _require(
        _process_started_at(browser_pid, label="browser Python driver")
        == browser_started_at
        and gate.started_at() == gate_started_at,
        "same-journey Python driver or decision-gate start identity changed",
    )

    for path, expected, label in (
        (
            contract["callbackScript"],
            contract["callbackScriptSha256"],
            "same-journey callback script",
        ),
        (
            contract["hostPython"],
            contract["hostPythonSha256"],
            "same-journey host interpreter",
        ),
        (
            contract["hostEntrypoint"],
            contract["hostEntrypointSha256"],
            "same-journey enrollment entrypoint",
        ),
        (
            contract["hostIdentity"],
            contract["hostIdentityFileSha256"],
            "same-journey host identity",
        ),
        (
            contract["artifactManifest"],
            contract["artifactManifestFileSha256"],
            "same-journey consolidated artifact manifest",
        ),
    ):
        _read_pinned_regular_file(path, expected, label=label)

    return {
        "apiVersion": SAME_JOURNEY_RESULT_VERSION,
        "assurance": {
            "classification": "local-fixture-same-journey-consistency-only",
            "buildReproductionProven": False,
            "hardwareAttestationProven": False,
            "imageProvenanceProven": False,
            "independentExecutionProven": False,
            "keyIndependenceProven": False,
            "serverProvenanceProven": False,
            "sourceProvenanceProven": False,
            "teeCustodyProven": False,
        },
        "buildManifestFileSha256": contract["artifactManifestFileSha256"],
        "buildManifestSha256": contract["buildManifestSha256"],
        "callbackResult": result,
        "callbackScriptSha256": contract["callbackScriptSha256"],
        "hostIdentityFileSha256": contract["hostIdentityFileSha256"],
        "hostIdentitySha256": contract["hostIdentityDocument"]["identitySha256"],
        "hostInterpreterSha256": contract["hostPythonSha256"],
        "hostEntrypointSha256": contract["hostEntrypointSha256"],
        "authenticatedInstructionsSha256": expected_instruction_sha256,
        "authenticatedInstructionsSize": len(expected_instruction_bytes),
        "exactAuthenticatedInstructionsOutput": True,
        "gateRemainedLive": True,
        "gatePid": gate.pid,
        "gateStartedAt": gate_started_at,
        "browserPythonPid": browser_pid,
        "browserPythonStartedAt": browser_started_at,
        "portalRemainedLive": True,
        "rawPlaywrightPacketSha256": packet_sha256,
        "responseHeaderSha256": response_header_sha256,
        "responseHeadersArraySha256": response_headers_array_sha256,
        "completeResponseRecordSha256": response_record_sha256,
        "completeOrderedResponseHeadersValidatedByBrowser": True,
        "completeResponseRecordPassedToCallbackVerifier": True,
        "completeOrderedResponseHeadersBoundByCallbackVerifier": False,
        "portalBootInstanceBoundByCallbackVerifier": False,
        "hostInstalledCliExecutionIndependentlyObserved": False,
        "pinnedVerifierProducedExactAuthenticatedInstructions": True,
        "responseSpecificTls": response_tls_evidence,
        "responseRecordSha256": response_record_sha256,
    }


def _assert_simulator_contract(
    simulator: OAuthProviderSimulator,
    public_url: str,
) -> None:
    public_host = urlsplit(public_url).hostname
    _require(
        public_host == "localhost" and simulator.redirect_base_url == public_url,
        "simulator did not retain the configured HTTPS callback origin",
    )
    certificate = x509.load_pem_x509_certificate(
        simulator.server_cert_path.read_bytes()
    )
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    dns_names = set(san.get_values_for_type(x509.DNSName))
    ip_addresses = {str(value) for value in san.get_values_for_type(x509.IPAddress)}
    _require(public_host in dns_names, "simulator certificate lacks public-host SAN")
    _require("localhost" in dns_names, "simulator certificate lost its localhost SAN")
    _require(
        "127.0.0.1" in ip_addresses, "simulator certificate lost its loopback IP SAN"
    )


def _assert_redirect_validation(work_dir: Path) -> None:
    default = OAuthProviderSimulator(work_dir / "default-contract")
    _require(
        default.redirect_base_url == "https://serverware.test",
        "simulator default redirect origin changed",
    )
    invalid_origins = (
        "http://serverware.test",
        "https://serverware.test/path",
        "https://serverware.test?query=1",
        "https://user@serverware.test",
        "https://serverware.test#fragment",
        "https://serverware.test:70000",
        " https://serverware.test",
        "https://serverware.test.",
    )
    for index, origin in enumerate(invalid_origins):
        try:
            OAuthProviderSimulator(
                work_dir / f"invalid-{index}", redirect_base_url=origin
            )
        except ValueError:
            continue
        raise AssertionError(
            f"simulator accepted an unsafe redirect origin: {origin!r}"
        )


def _npm_publish_document_for(
    package_name: str,
    package_version: str,
    tarball: bytes,
) -> dict[str, Any]:
    integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball).digest()
    ).decode("ascii")
    return {
        "_id": package_name,
        "name": package_name,
        "dist-tags": {"latest": package_version},
        "versions": {
            package_version: {
                "name": package_name,
                "version": package_version,
                "dist": {"integrity": integrity},
            }
        },
        "_attachments": {
            f"{package_name.rsplit('/', 1)[-1]}-{package_version}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }


def _npm_unpublish_document() -> dict[str, Any]:
    return {
        "_id": NPM_PACKAGE_NAME,
        "_rev": NPM_REVISION,
        "name": NPM_PACKAGE_NAME,
        "dist-tags": {"latest": NPM_REMAINING_VERSION},
        "versions": {
            NPM_REMAINING_VERSION: {
                "name": NPM_PACKAGE_NAME,
                "version": NPM_REMAINING_VERSION,
            }
        },
    }


def _npm_metadata_document() -> dict[str, Any]:
    return {
        "_id": NPM_PACKAGE_NAME,
        "_rev": NPM_REVISION,
        "name": NPM_PACKAGE_NAME,
        "dist-tags": {"latest": NPM_PACKAGE_VERSION},
        "versions": {
            NPM_PACKAGE_VERSION: {
                "name": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "deprecated": "Use the supported replacement package",
            }
        },
    }


def _npm_publish_document() -> dict[str, Any]:
    return _npm_publish_document_for(
        NPM_PACKAGE_NAME,
        NPM_PACKAGE_VERSION,
        b"serverware-browser-npm-fixture-v1",
    )


def _npm_contention_publish_document() -> dict[str, Any]:
    return _npm_publish_document_for(
        NPM_CONTENTION_PACKAGE_NAME,
        NPM_CONTENTION_PACKAGE_VERSION,
        b"serverware-browser-npm-contention-v1",
    )


class _NpmRegistryFixture:
    def __init__(self, simulator: OAuthProviderSimulator) -> None:
        self._lock = threading.Lock()
        self.ca_cert_path = simulator.ca_cert_path
        self.server_cert_path = simulator.server_cert_path
        self.server_key_path = simulator.server_key_path
        self._events: list[dict[str, Any]] = []
        self._cli_publish_tarball: bytes | None = None
        self._contention_armed = False
        self._contention_arrivals = 0
        self._contention_arrived = threading.Event()
        self._contention_release = threading.Event()
        self._counts = {
            "npm.publish": 0,
            "npm.unpublish": 0,
            "npm.distTagWrite": 0,
            "npm.tokenWrite": 0,
            "npm.metadataWrite": 0,
            "npm.tokenCreate": 0,
            "rejected": 0,
        }
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(
                    _journey_timeout_seconds(
                        label="npm fixture request headers",
                        cap=5,
                    )
                )

            def do_GET(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_POST(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_PUT(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_DELETE(self) -> None:  # noqa: N802
                fixture._handle(self)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.block_on_close = False
        self._server.timeout = 0.5
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(simulator.server_cert_path),
            keyfile=str(simulator.server_key_path),
        )
        self._server.socket = context.wrap_socket(
            self._server.socket,
            server_side=True,
        )
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="serverware-browser-npm-registry",
            daemon=True,
        )
        self._started = False

    @staticmethod
    def _strict_body(handler: BaseHTTPRequestHandler) -> bytes:
        handler.connection.settimeout(
            _journey_timeout_seconds(label="npm fixture request body", cap=5)
        )
        transfer_encoding = handler.headers.get("Transfer-Encoding")
        if transfer_encoding:
            raise ValueError("transfer_encoding_denied")
        raw_length = handler.headers.get("Content-Length")
        if raw_length is None:
            return b""
        if not raw_length.isdigit():
            raise ValueError("content_length_invalid")
        length = int(raw_length)
        if length > 16 * 1024 * 1024:
            raise ValueError("body_too_large")
        body = handler.rfile.read(length)
        if len(body) != length:
            raise ValueError("body_truncated")
        return body

    @staticmethod
    def _json_body(body: bytes) -> Any:
        if not body:
            return None
        return json.loads(body.decode("utf-8"))

    @staticmethod
    def _response_for(
        operation: str,
        *,
        package_name: str = NPM_PACKAGE_NAME,
        package_version: str = NPM_PACKAGE_VERSION,
    ) -> dict[str, Any]:
        if operation == "npm.publish":
            return {
                "package": package_name,
                "version": package_version,
                "published": True,
            }
        if operation == "npm.unpublish":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "revision": NPM_REVISION,
                "unpublished": True,
            }
        if operation == "npm.distTagWrite":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "tag": "latest",
                "dist_tag_written": True,
            }
        if operation == "npm.tokenWrite":
            return {"ok": True, "token_revoked": True}
        if operation == "npm.metadataWrite":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "metadata_updated": True,
            }
        raise ValueError("unsupported_fixture_operation")

    def register_cli_publish_tarball(self, tarball: bytes) -> None:
        _require(bool(tarball), "npm CLI fixture tarball must not be empty")
        with self._lock:
            _require(
                self._cli_publish_tarball is None,
                "npm CLI fixture tarball was registered more than once",
            )
            self._cli_publish_tarball = bytes(tarball)

    def arm_contention_latch(self) -> None:
        with self._lock:
            _require(
                not self._contention_armed,
                "npm contention latch was already armed",
            )
            self._contention_armed = True
            self._contention_arrivals = 0
            self._contention_arrived.clear()
            self._contention_release.clear()

    def wait_for_contention_winner(self, *, timeout_seconds: float) -> None:
        _require(
            self._contention_arrived.wait(timeout=timeout_seconds),
            "npm contention winner did not reach the upstream fixture",
        )

    def contention_latch_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "armed": self._contention_armed,
                "arrivals": self._contention_arrivals,
                "winnerHeld": (
                    self._contention_armed
                    and self._contention_arrivals == 1
                    and not self._contention_release.is_set()
                ),
                "released": self._contention_release.is_set(),
            }

    def release_contention_winner(self) -> None:
        self._contention_release.set()

    def finish_contention_latch(self) -> dict[str, Any]:
        self._contention_release.set()
        with self._lock:
            state = {
                "armed": self._contention_armed,
                "arrivals": self._contention_arrivals,
                "released": True,
            }
            self._contention_armed = False
        return state

    def _is_cli_publish_document(self, body: Any) -> bool:
        with self._lock:
            tarball = self._cli_publish_tarball
        if tarball is None or not isinstance(body, dict):
            return False
        if (
            body.get("_id") != NPM_PACKAGE_NAME
            or body.get("name") != NPM_PACKAGE_NAME
            or body.get("dist-tags") != {"latest": NPM_PACKAGE_VERSION}
        ):
            return False
        versions = body.get("versions")
        if not isinstance(versions, dict) or set(versions) != {NPM_PACKAGE_VERSION}:
            return False
        version = versions.get(NPM_PACKAGE_VERSION)
        if (
            not isinstance(version, dict)
            or version.get("name") != NPM_PACKAGE_NAME
            or version.get("version") != NPM_PACKAGE_VERSION
        ):
            return False
        attachments = body.get("_attachments")
        attachment_name = f"{NPM_PACKAGE_NAME}-{NPM_PACKAGE_VERSION}.tgz"
        if not isinstance(attachments, dict) or set(attachments) != {
            attachment_name
        }:
            return False
        attachment = attachments.get(attachment_name)
        if not isinstance(attachment, dict):
            return False
        try:
            decoded = base64.b64decode(
                attachment.get("data", ""),
                validate=True,
            )
        except (TypeError, ValueError):
            return False
        expected_integrity = "sha512-" + base64.b64encode(
            hashlib.sha512(tarball).digest()
        ).decode("ascii")
        expected_shasum = hashlib.sha1(tarball).hexdigest()
        dist = version.get("dist")
        tarball_url = (
            urlsplit(dist.get("tarball"))
            if isinstance(dist, dict) and isinstance(dist.get("tarball"), str)
            else None
        )
        return (
            decoded == tarball
            and attachment.get("content_type") == "application/octet-stream"
            and attachment.get("length") == len(tarball)
            and isinstance(dist, dict)
            and dist.get("integrity") == expected_integrity
            and dist.get("shasum") == expected_shasum
            and tarball_url is not None
            and tarball_url.scheme == "http"
            and tarball_url.hostname == "127.0.0.1"
            and tarball_url.port == self.port
            and not tarball_url.username
            and tarball_url.password is None
            and not tarball_url.query
            and not tarball_url.fragment
            and tarball_url.path.endswith(
                f"/serverware-browser-{NPM_PACKAGE_VERSION}.tgz"
            )
        )

    def _classify(
        self,
        method: str,
        path: str,
        body: Any,
    ) -> tuple[str, str]:
        package_path = f"/{NPM_PACKAGE_PATH}"
        if method == "PUT" and path == package_path:
            if body == _npm_publish_document():
                return "npm.publish", "deterministic-direct-wire"
            if self._is_cli_publish_document(body):
                return "npm.publish", "installed-npm-cli"
            if body == _npm_metadata_document():
                return "npm.metadataWrite", "deterministic-direct-wire"
        if (
            method == "PUT"
            and path == f"/{NPM_CONTENTION_PACKAGE_PATH}"
            and body == _npm_contention_publish_document()
        ):
            return "npm.publish", "concurrent-direct-wire"
        if (
            method == "PUT"
            and path == f"{package_path}/-rev/{NPM_REVISION}"
            and body == _npm_unpublish_document()
        ):
            return "npm.unpublish", "deterministic-direct-wire"
        if (
            method == "PUT"
            and path
            == f"/-/package/{NPM_PACKAGE_PATH}/dist-tags/latest"
            and body == NPM_PACKAGE_VERSION
        ):
            return "npm.distTagWrite", "deterministic-direct-wire"
        if (
            method == "DELETE"
            and path == f"/-/npm/v1/tokens/token/{NPM_TOKEN_KEY}"
            and body is None
        ):
            return "npm.tokenWrite", "deterministic-direct-wire"
        if method == "POST" and path == "/-/npm/v1/tokens":
            return "npm.tokenCreate", "deterministic-direct-wire"
        raise ValueError("fixture_request_unclassified")

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        payload: dict[str, Any],
    ) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)
        handler.close_connection = True

    def _append_event_locked(self, event: dict[str, Any]) -> None:
        _require(
            len(self._events) < MAX_BROWSER_OBSERVATIONS,
            "npm registry observations exceeded their item bound",
        )
        self._events.append(event)

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        method = handler.command.upper()
        path = urlsplit(handler.path).path
        operation: str | None = None
        client_kind: str | None = None
        body_sha256: str | None = None
        npm_session_headers = list(handler.headers.get_all("npm-session") or [])
        try:
            if npm_session_headers:
                raise ValueError("npm_session_reached_upstream")
            body_bytes = self._strict_body(handler)
            body_sha256 = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
            body = self._json_body(body_bytes)
            authorization = handler.headers.get("Authorization")
            if authorization != f"Bearer {NPM_FIXTURE_BEARER}":
                raise PermissionError("credential_injection_missing")
            operation, client_kind = self._classify(method, path, body)
            if client_kind == "concurrent-direct-wire":
                with self._lock:
                    if not self._contention_armed:
                        raise ValueError("contention_latch_not_armed")
                    self._contention_arrivals += 1
                    contention_arrival = self._contention_arrivals
                    self._contention_arrived.set()
                if contention_arrival != 1:
                    raise ValueError("second_contention_request_reached_upstream")
                _require(
                    self._contention_release.wait(
                        timeout=_journey_timeout_seconds(
                            label="npm contention upstream hold",
                            cap=20,
                        )
                    ),
                    "npm contention winner was not released within its bound",
                )
            if operation == "npm.tokenCreate":
                with self._lock:
                    self._counts[operation] += 1
                    self._append_event_locked(
                        {
                            "operation": operation,
                            "method": method,
                            "path": path,
                            "bodySha256": body_sha256,
                            "clientKind": client_kind,
                            "authorizationPresent": True,
                            "authorizationScheme": "Bearer",
                            "npmSessionHeaders": npm_session_headers,
                            "unexpected": True,
                        }
                    )
                self._send_json(
                    handler,
                    500,
                    {"error": "token_creation_must_not_reach_registry"},
                )
                return
            package_name = (
                body.get("name")
                if isinstance(body, dict) and isinstance(body.get("name"), str)
                else NPM_PACKAGE_NAME
            )
            package_version = (
                (body.get("dist-tags") or {}).get("latest")
                if isinstance(body, dict)
                and isinstance(body.get("dist-tags"), dict)
                and isinstance((body.get("dist-tags") or {}).get("latest"), str)
                else NPM_PACKAGE_VERSION
            )
            response = self._response_for(
                operation,
                package_name=package_name,
                package_version=package_version,
            )
            with self._lock:
                self._counts[operation] += 1
                self._append_event_locked(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "packageName": package_name,
                        "clientKind": client_kind,
                        "authorizationPresent": True,
                        "authorizationScheme": "Bearer",
                        "npmSessionHeaders": npm_session_headers,
                    }
                )
            self._send_json(handler, 200, response)
        except PermissionError as exc:
            with self._lock:
                self._counts["rejected"] += 1
                self._append_event_locked(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "authorizationPresent": False,
                        "npmSessionHeaders": npm_session_headers,
                        "reason": str(exc),
                    }
                )
            self._send_json(handler, 401, {"error": "registry_credential_required"})
        except Exception as exc:
            with self._lock:
                self._counts["rejected"] += 1
                self._append_event_locked(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "npmSessionHeaders": npm_session_headers,
                        "reason": str(exc),
                    }
                )
            self._send_json(handler, 400, {"error": "registry_fixture_rejected"})

    def start(self) -> None:
        self._thread.start()
        self._started = True

    def observations(self) -> dict[str, Any]:
        with self._lock:
            _require(
                len(self._events) <= MAX_BROWSER_OBSERVATIONS,
                "npm registry observations exceeded their item bound",
            )
            return json.loads(
                json.dumps(
                    {"counts": self._counts, "events": self._events},
                    sort_keys=True,
                )
            )

    def close(self) -> None:
        self._contention_release.set()
        if not self._started:
            self._server.server_close()
            return
        shutdown_thread = threading.Thread(
            target=self._server.shutdown,
            name="serverware-browser-npm-registry-shutdown",
            daemon=True,
        )
        shutdown_thread.start()
        shutdown_thread.join(timeout=5)
        self._server.server_close()
        self._thread.join(timeout=5)
        _require(
            not shutdown_thread.is_alive() and not self._thread.is_alive(),
            "npm registry fixture did not stop within its cleanup bound",
        )
        self._started = False


class _UvicornThread:
    def __init__(
        self, app: Any, listener: socket.socket, simulator: OAuthProviderSimulator
    ) -> None:
        try:
            import uvicorn
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "uvicorn is unavailable; run this script with the repository requirements.lock"
            ) from exc
        self._listener = listener
        self._error: BaseException | None = None
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=int(listener.getsockname()[1]),
                ssl_certfile=str(simulator.server_cert_path),
                ssl_keyfile=str(simulator.server_key_path),
                log_level="warning",
                access_log=False,
                proxy_headers=False,
                server_header=False,
                lifespan="on",
            )
        )
        self._thread = threading.Thread(
            target=self._run,
            name="serverware-browser-oauth-portal",
            daemon=True,
        )

    def _run(self) -> None:
        try:
            self._server.run(sockets=[self._listener])
        except BaseException as exc:  # pragma: no cover - surfaced to the caller
            self._error = exc

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + _journey_timeout_seconds(
            label="HTTPS portal startup",
            cap=20,
        )
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if self._error is not None:
                raise RuntimeError(
                    "HTTPS portal failed during startup"
                ) from self._error
            if not self._thread.is_alive():
                raise RuntimeError("HTTPS portal stopped before startup completed")
            time.sleep(0.05)
        raise TimeoutError("HTTPS portal did not become ready")

    def close(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=8)
        if self._thread.is_alive():
            self._server.force_exit = True
            self._thread.join(timeout=3)
        if self._thread.is_alive():
            raise RuntimeError("HTTPS portal did not stop")
        if self._error is not None:
            raise RuntimeError("HTTPS portal failed") from self._error


def _api_result(
    page: Any,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timeout_ms = _journey_timeout_ms(label=f"{method} {path} browser API probe")
    return page.evaluate(
        """
        async ({path, method, payload, timeoutMs, maxBytes}) => {
          const token = document.querySelector('#admin-token')?.value || '';
          return window.__serverwareBoundedFetch(path, {
            method,
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: method === 'GET' ? undefined : JSON.stringify(payload || {}),
            credentials: 'same-origin',
            cache: 'no-store'
          }, timeoutMs, maxBytes);
        }
        """,
        {
            "path": path,
            "method": method,
            "payload": payload or {},
            "timeoutMs": timeout_ms,
            "maxBytes": MAX_API_RESPONSE_BYTES,
        },
    )


def _api_json(page: Any, path: str) -> Any:
    result = _api_result(page, path)
    if result["status"] != 200:
        raise AssertionError(
            f"GET {path} returned HTTP {result['status']}: {result['text'][:500]}"
        )
    return json.loads(result["text"])


def _api_post_json(page: Any, path: str, payload: dict[str, Any] | None = None) -> Any:
    result = _api_result(page, path, method="POST", payload=payload)
    if result["status"] != 200:
        raise AssertionError(
            f"POST {path} returned HTTP {result['status']}: {result['text'][:500]}"
        )
    return json.loads(result["text"])


def _wait_for_api(
    page: Any,
    path: str,
    predicate: Callable[[Any], bool],
    *,
    timeout_seconds: float = 20,
) -> Any:
    deadline = time.monotonic() + _journey_timeout_seconds(
        label=f"GET {path} expected state",
        cap=timeout_seconds,
    )
    last: Any = None
    while time.monotonic() < deadline:
        last = _api_json(page, path)
        if predicate(last):
            return last
        time.sleep(0.1)
    raise AssertionError(f"GET {path} did not reach the expected state: {last!r}")


def _credential_by_name(bootstrap: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item for item in bootstrap.get("credentials", []) if item.get("name") == name
    ]
    _require(len(matches) == 1, f"expected exactly one credential named {name!r}")
    return matches[0]


def _assert_public_credential(
    credential: dict[str, Any],
    *,
    provider: str,
    subject: str,
    account: str,
    scopes: list[str],
) -> None:
    metadata = credential.get("metadata") or {}
    _require(
        credential.get("kind") == "oauth2", f"{provider} credential kind is not oauth2"
    )
    _require(
        metadata.get("oauth") is True, f"{provider} credential is not managed OAuth"
    )
    _require(
        metadata.get("provider_id") == provider,
        f"{provider} credential provider mismatch",
    )
    _require(
        metadata.get("provider_subject") == subject,
        f"{provider} credential subject was not callback-verified",
    )
    _require(
        metadata.get("provider_account") == account,
        f"{provider} credential account was not callback-verified",
    )
    _require(
        metadata.get("provider_identity_verified") is True,
        f"{provider} credential identity is not marked verified",
    )
    _require(
        set(metadata.get("scopes") or []) == set(scopes),
        f"{provider} credential granted scopes mismatch",
    )
    forbidden_keys = {
        "secret",
        "encrypted_secret",
        "ciphertext",
        "access_token",
        "refresh_token",
        "client_secret",
        "code_verifier",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            overlap = forbidden_keys.intersection(value)
            _require(
                not overlap,
                f"public credential exposed secret-bearing keys: {sorted(overlap)}",
            )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(credential)


def _wait_for_portal(
    page: Any, public_url: str, *, expected_url: str | None = None
) -> None:
    expected = expected_url or (public_url + "/")
    page.wait_for_url(
        re.compile(rf"^{re.escape(expected)}(?:\?.*)?$"),
        timeout=_journey_timeout_ms(label="portal URL wait"),
    )
    page.locator("#oauth-form").wait_for(
        state="visible",
        timeout=_journey_timeout_ms(label="portal form wait"),
    )
    page.wait_for_function(
        """
        () => document.querySelector('#operator-auth-status')?.textContent === 'Token session'
          && document.querySelectorAll('#oauth-provider option').length === 2
        """,
        timeout=_journey_timeout_ms(label="portal session wait"),
    )


def _assert_refresh_preserves_live_oauth_form(page: Any) -> None:
    original = page.evaluate(
        """
        () => ({
          provider: document.querySelector('#oauth-provider')?.value || '',
          name: document.querySelector('#oauth-credential-name')?.value || '',
          scopes: document.querySelector('#oauth-scopes')?.value || '',
          metadata: document.querySelector('#oauth-metadata')?.value || '{}'
        })
        """
    )
    page.evaluate(
        """
        () => {
          const originalFetch = window.fetch.bind(window);
          let release;
          const barrier = new Promise((resolve) => { release = resolve; });
          window.__oauthRefreshRaceStarted = false;
          window.__oauthRefreshRaceDone = false;
          window.__oauthRefreshRaceRelease = release;
          window.fetch = (input, init) => {
            const raw = typeof input === 'string' ? input : input.url;
            const url = new URL(raw, window.location.href);
            if (!window.__oauthRefreshRaceStarted && url.pathname === '/api/bootstrap') {
              window.__oauthRefreshRaceStarted = true;
              return barrier.then(() => {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 20000);
                return originalFetch(input, {...(init || {}), signal: controller.signal})
                  .finally(() => clearTimeout(timer));
              });
            }
            return originalFetch(input, init);
          };
          window.__oauthRefreshRacePromise = (async () => {
            if (refreshInFlight) await refreshInFlight;
            await refresh();
          })().finally(() => {
            window.fetch = originalFetch;
            window.__oauthRefreshRaceDone = true;
          });
        }
        """
    )
    try:
        page.wait_for_function(
            "() => window.__oauthRefreshRaceStarted === true",
            timeout=_journey_timeout_ms(label="refresh race start wait"),
        )
        page.locator("#oauth-provider").select_option("x")
        page.locator("#oauth-credential-name").fill("Refresh race probe")
        page.locator("#oauth-scopes").fill("\n".join(X_SCOPES))
        page.locator("#oauth-metadata").fill('{"probe":"refresh-race"}')
        page.evaluate("window.__oauthRefreshRaceRelease()")
        page.wait_for_function(
            "() => window.__oauthRefreshRaceDone === true",
            timeout=_journey_timeout_ms(label="refresh race completion wait"),
        )
        submitted = page.evaluate(
            """
            () => {
              const form = new FormData(document.querySelector('#oauth-form'));
              return {provider: form.get('provider'), scopes: form.get('scopes')};
            }
            """
        )
        _require(
            submitted == {"provider": "x", "scopes": "\n".join(X_SCOPES)},
            f"in-flight refresh replaced live OAuth form values: {submitted}",
        )
    finally:
        page.evaluate("window.__oauthRefreshRaceRelease?.()")
        page.wait_for_function(
            "() => window.__oauthRefreshRaceDone === true",
            timeout=_journey_timeout_ms(label="refresh race cleanup wait"),
        )
        page.locator("#oauth-provider").select_option(original["provider"])
        page.locator("#oauth-credential-name").fill(original["name"])
        page.locator("#oauth-scopes").fill(original["scopes"])
        page.locator("#oauth-metadata").fill(original["metadata"])


def _assert_no_oauth_cookies(context: Any) -> None:
    cookies = context.cookies()
    residue = [
        item["name"] for item in cookies if item["name"].startswith(OAUTH_COOKIE_PREFIX)
    ]
    _require(
        not residue, f"OAuth state cookies survived callback consumption: {residue}"
    )


def _assert_oauth_state_cookie(
    context: Any,
    *,
    state: str,
    response_headers_array: list[dict[str, str]],
) -> None:
    cookies = [
        item
        for item in context.cookies()
        if item["name"].startswith(OAUTH_COOKIE_PREFIX)
    ]
    expected_name = OAUTH_COOKIE_PREFIX + state
    normalized_headers = [
        {
            "name": str(item.get("name") or "").lower(),
            "value": str(item.get("value") or ""),
        }
        for item in response_headers_array
    ]
    set_cookie_values = [
        item["value"]
        for item in normalized_headers
        if item["name"] == "set-cookie"
        and item["value"].startswith(expected_name + "=")
    ]
    date_values = [
        item["value"] for item in normalized_headers if item["name"] == "date"
    ]
    _require(
        len(set_cookie_values) == 1 and len(date_values) == 1,
        "OAuth start response did not expose one exact state cookie and Date header",
    )
    raw_set_cookie = set_cookie_values[0]
    parsed_cookie = http.cookies.SimpleCookie()
    parsed_cookie.load(raw_set_cookie)
    _require(
        set(parsed_cookie) == {expected_name},
        "OAuth state Set-Cookie metadata parsed to an unexpected cookie set",
    )
    morsel = parsed_cookie[expected_name]
    attribute_names = {
        segment.split("=", 1)[0].strip().lower()
        for segment in raw_set_cookie.split(";")[1:]
        if segment.strip()
    }
    _require(
        attribute_names
        == {"path", "max-age", "secure", "httponly", "samesite"}
        and morsel["path"] == "/"
        and morsel["domain"] == ""
        and morsel["expires"] == ""
        and morsel["secure"] is True
        and morsel["httponly"] is True
        and morsel["samesite"].lower() == "lax"
        and re.fullmatch(r"[0-9]+", morsel["max-age"]) is not None,
        f"OAuth state Set-Cookie escaped its exact __Host metadata: {raw_set_cookie!r}",
    )
    max_age = int(morsel["max-age"])
    _require(
        OAUTH_STATE_TTL_SECONDS - OAUTH_COOKIE_CLOCK_SKEW_SECONDS
        <= max_age
        <= OAUTH_STATE_TTL_SECONDS,
        f"OAuth state Max-Age was not the exact configured TTL: {max_age}",
    )
    response_date = email.utils.parsedate_to_datetime(date_values[0])
    _require(
        response_date is not None
        and response_date.tzinfo is not None
        and response_date.timestamp() > 0,
        "OAuth state response Date was malformed",
    )
    expected_browser_expiry = response_date.timestamp() + max_age
    browser_cookie = cookies[0] if len(cookies) == 1 else {}
    _require(
        len(cookies) == 1
        and browser_cookie.get("name") == expected_name
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", str(browser_cookie.get("value") or ""))
        is not None
        and browser_cookie.get("value") == morsel.value
        and browser_cookie.get("secure") is True
        and browser_cookie.get("httpOnly") is True
        and browser_cookie.get("sameSite") == "Lax"
        and browser_cookie.get("domain") == "localhost"
        and browser_cookie.get("path") == "/"
        and abs(
            float(browser_cookie.get("expires") or 0)
            - expected_browser_expiry
        )
        <= OAUTH_COOKIE_CLOCK_SKEW_SECONDS,
        f"OAuth state cookie did not preserve its exact bounded __Host contract: {cookies}",
    )


def _assert_no_horizontal_overflow(page: Any, *, label: str) -> None:
    dimensions = page.evaluate(
        """
        () => ({
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth
        })
        """
    )
    maximum = max(dimensions["documentWidth"], dimensions["bodyWidth"])
    _require(
        maximum <= dimensions["viewportWidth"] + 1,
        f"{label} portal overflows horizontally: {dimensions}",
    )


def _assert_control_within_viewport(page: Any, locator: Any, *, label: str) -> None:
    box = locator.bounding_box()
    viewport = page.viewport_size
    _require(box is not None and viewport is not None, f"{label} has no rendered bounds")
    _require(
        box["x"] >= -1
        and box["y"] >= -1
        and box["x"] + box["width"] <= viewport["width"] + 1,
        f"{label} is outside the viewport: box={box}, viewport={viewport}",
    )


def _approval_diagnostics(page: Any, approval_id: str) -> dict[str, Any]:
    return page.evaluate(
        """
        (id) => ({
          url: window.location.href,
          stateReview: state.approvalReview,
          stateApproval: (state.approvals || []).find((item) => item.id === id) || null,
          status: document.querySelector('#operator-status')?.textContent || '',
          reviewText: document.querySelector('#approval-review')?.textContent || '',
          actionsText: document.querySelector('#approval-review-actions')?.textContent || '',
          actionsHidden: document.querySelector('#approval-review-actions')?.hidden,
          activeElement: document.activeElement?.id || ''
        })
        """,
        approval_id,
    )


def _install_dev_webauthn_shim(context: Any) -> None:
    context.add_init_script(
        r"""
        (() => {
          const toBase64Url = (value) => {
            const bytes = new Uint8Array(value);
            let raw = '';
            for (const byte of bytes) raw += String.fromCharCode(byte);
            return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
          };
          const fromBase64Url = (value) => {
            const padded = value + '='.repeat((4 - value.length % 4) % 4);
            const raw = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            return Uint8Array.from(raw, (char) => char.charCodeAt(0)).buffer;
          };
          const boundedFetch = async (
            input,
            init = {},
            timeoutMs = 20000,
            maxBytes = 2097152
          ) => {
            if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) {
              throw new Error('bounded fetch timeout is invalid');
            }
            if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 2097152) {
              throw new Error('bounded fetch response limit is invalid');
            }
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);
            let reader = null;
            try {
              const response = await fetch(input, {...init, signal: controller.signal});
              const declaredLength = response.headers.get('content-length');
              if (
                declaredLength !== null
                && (!/^(0|[1-9][0-9]*)$/.test(declaredLength)
                  || Number(declaredLength) > maxBytes)
              ) {
                throw new Error('bounded fetch Content-Length is invalid');
              }
              if (!response.body) {
                return {status: response.status, ok: response.ok, text: ''};
              }
              reader = response.body.getReader();
              const chunks = [];
              let length = 0;
              while (true) {
                const item = await reader.read();
                if (item.done) break;
                length += item.value.byteLength;
                if (length > maxBytes) {
                  await reader.cancel('response exceeded byte limit');
                  throw new Error('bounded fetch response exceeded byte limit');
                }
                chunks.push(item.value);
              }
              if (declaredLength !== null && Number(declaredLength) !== length) {
                throw new Error('bounded fetch body length differs from Content-Length');
              }
              const body = new Uint8Array(length);
              let offset = 0;
              for (const chunk of chunks) {
                body.set(chunk, offset);
                offset += chunk.byteLength;
              }
              const text = new TextDecoder('utf-8', {fatal: true}).decode(body);
              return {status: response.status, ok: response.ok, text};
            } finally {
              clearTimeout(timer);
              if (reader) {
                try {
                  reader.releaseLock();
                } catch (_) {}
              }
            }
          };
          Object.defineProperty(window, '__serverwareBoundedFetch', {
            configurable: false,
            writable: false,
            value: boundedFetch
          });
          if (!window.PublicKeyCredential) {
            Object.defineProperty(window, 'PublicKeyCredential', {
              configurable: true,
              value: function PublicKeyCredential() {}
            });
          }
          const credentials = navigator.credentials;
          if (!credentials) return;
          const nativeGet = typeof credentials.get === 'function'
            ? credentials.get.bind(credentials)
            : null;
          Object.defineProperty(credentials, 'get', {
            configurable: true,
            value: async (options = {}) => {
              if (!options.publicKey) {
                if (nativeGet) return nativeGet(options);
                throw new Error('Credential request did not include publicKey options');
              }
              const publicKey = options.publicKey;
              const isBuffer = (value) => value instanceof ArrayBuffer
                || ArrayBuffer.isView(value);
              if (
                window.location.protocol !== 'https:'
                || window.location.hostname !== 'localhost'
                || publicKey.rpId !== 'localhost'
                || publicKey.userVerification !== 'required'
                || !isBuffer(publicKey.challenge)
                || new Uint8Array(publicKey.challenge).byteLength < 16
                || new Uint8Array(publicKey.challenge).byteLength > 1024
                || !Array.isArray(publicKey.allowCredentials)
                || publicKey.allowCredentials.length !== 1
                || publicKey.allowCredentials[0]?.type !== 'public-key'
                || !isBuffer(publicKey.allowCredentials[0]?.id)
                || options.mediation !== undefined
              ) {
                throw new Error('Dev WebAuthn request escaped its exact localhost UV contract');
              }
              const allowedTransports = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid']);
              if (
                publicKey.allowCredentials[0].transports !== undefined
                && (
                  !Array.isArray(publicKey.allowCredentials[0].transports)
                  || publicKey.allowCredentials[0].transports.some(
                    (item) => !allowedTransports.has(item)
                  )
                )
              ) {
                throw new Error('Dev WebAuthn request included an invalid transport');
              }
              const challenge = toBase64Url(publicKey.challenge);
              const token = document.querySelector('#admin-token')?.value || '';
              const response = await boundedFetch('/api/dev/webauthn/assertion', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Serverware-Admin-Token': token,
                  'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({challenge}),
                credentials: 'same-origin',
                cache: 'no-store'
              }, 20000, 1048576);
              if (!response.ok) {
                throw new Error(`Dev WebAuthn assertion failed with ${response.status}: ${response.text.slice(0, 300)}`);
              }
              const assertion = JSON.parse(response.text);
              if (
                !assertion
                || assertion.type !== 'public-key'
                || typeof assertion.id !== 'string'
                || assertion.id.length < 1
                || typeof assertion.rawId !== 'string'
                || !assertion.response
                || typeof assertion.response.clientDataJSON !== 'string'
                || typeof assertion.response.authenticatorData !== 'string'
                || typeof assertion.response.signature !== 'string'
                || !Object.prototype.hasOwnProperty.call(assertion.response, 'userHandle')
              ) {
                throw new Error('Dev WebAuthn assertion schema is invalid');
              }
              const rawId = fromBase64Url(assertion.rawId);
              const allowedId = new Uint8Array(publicKey.allowCredentials[0].id);
              const returnedId = new Uint8Array(rawId);
              if (
                toBase64Url(rawId) !== assertion.rawId
                || assertion.id !== assertion.rawId
                || allowedId.byteLength !== returnedId.byteLength
                || allowedId.some((byte, index) => returnedId[index] !== byte)
              ) {
                throw new Error('Dev WebAuthn credential identity is not canonical');
              }
              const clientDataBytes = new Uint8Array(
                fromBase64Url(assertion.response.clientDataJSON)
              );
              const clientData = JSON.parse(
                new TextDecoder('utf-8', {fatal: true}).decode(clientDataBytes)
              );
              if (
                clientData.type !== 'webauthn.get'
                || clientData.challenge !== challenge
                || clientData.origin !== window.location.origin
                || clientData.crossOrigin === true
              ) {
                throw new Error('Dev WebAuthn client data escaped the exact browser origin');
              }
              const authenticatorData = new Uint8Array(
                fromBase64Url(assertion.response.authenticatorData)
              );
              const expectedRpIdHash = new Uint8Array(
                await crypto.subtle.digest('SHA-256', new TextEncoder().encode('localhost'))
              );
              if (
                authenticatorData.byteLength < 37
                || expectedRpIdHash.some((byte, index) => authenticatorData[index] !== byte)
                || (authenticatorData[32] & 0x05) !== 0x05
              ) {
                throw new Error('Dev WebAuthn authenticator data lacks localhost UP/UV binding');
              }
              return {
                id: assertion.id,
                rawId,
                type: assertion.type,
                response: Object.fromEntries(
                  Object.entries(assertion.response || {}).map(
                    ([key, value]) => [key, fromBase64Url(value)]
                  )
                ),
                getClientExtensionResults: () => ({})
              };
            }
          });
          window.__serverwareDevWebAuthnShim = true;
        })();
        """
    )


def _assert_single_approval_decision(
    page: Any,
    browser_observations: list[dict[str, Any]],
    approval_id: str,
    decision: str,
    *,
    reason: str | None = None,
    expected_request_count: int = 1,
    expected_denied_count: int = 0,
) -> dict[str, Any]:
    expected_status = "approved" if decision == "approve" else "denied"
    endpoint = f"/api/approvals/{approval_id}/{decision}"
    decision_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and endpoint in item.get("url", "")
    ]
    decision_responses = [
        item
        for item in browser_observations
        if item.get("type") == "response" and endpoint in item.get("url", "")
    ]
    approvals = _api_json(page, "/api/approvals")
    matches = [item for item in approvals if item.get("id") == approval_id]
    from serverware import db

    audit_events = [
        item
        for item in db.list_audit_events(limit=500)
        if item.get("event_type") == f"approval.{expected_status}"
        and (item.get("event") or {}).get("approval_request_id") == approval_id
    ]
    diagnostics = {
        "decisionRequests": decision_requests,
        "decisionResponses": decision_responses,
        "approvalRecords": matches,
        "auditEvents": audit_events,
        "review": _approval_diagnostics(page, approval_id),
    }
    _require(
        len(decision_requests) == expected_request_count,
        f"{decision} issued an unexpected number of decision requests: {diagnostics}",
    )
    _require(
        sum(item.get("status") == 200 for item in decision_responses) == 1
        and sum(item.get("status") == 403 for item in decision_responses)
        == expected_denied_count,
        f"{decision} response statuses did not preserve fail-closed review: {diagnostics}",
    )
    _require(
        len(matches) == 1 and matches[0].get("status") == expected_status,
        f"{decision} from review did not persist exactly one {expected_status} status: {diagnostics}",
    )
    _require(
        len(audit_events) == 1,
        f"{decision} from review did not append exactly one audit decision: {diagnostics}",
    )
    if reason is not None:
        _require(
            matches[0].get("decision_note") == reason
            and (audit_events[0].get("event") or {}).get("note") == reason,
            f"review denial did not preserve its exact reason: {diagnostics}",
        )
    return matches[0]


def _assert_stripe_uses_manual_credential_flow(
    page: Any, browser_observations: list[dict[str, Any]]
) -> None:
    oauth_requests_before = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    oauth_state_before = page.evaluate(
        """
        () => ({
          provider: document.querySelector('#oauth-provider')?.value || '',
          draft: sessionStorage.getItem('serverware.oauthDraft'),
          setupSessionId: state.oauthSetupSessionId
        })
        """
    )
    credential_form_before = {
        "name": page.locator("#credential-name").input_value(),
        "kind": page.locator("#credential-kind").input_value(),
        "metadata": page.locator("#credential-metadata").input_value(),
    }

    page.locator("#setup-template").select_option("stripe_payment_intent_jit")
    page.locator("#setup-principal").select_option("agent:demo")
    # The setup action records a durable run against an active route before it opens
    # the credential form. Reuse a seeded route only for this UI-path assertion.
    page.locator("#setup-route-id").fill("demo.echo")
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'stripe_payment_intent_jit'
          && document.querySelector('#setup-connect-button')?.textContent === 'Add credential'
        """,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )

    setup_credential = page.locator("#setup-credential")
    unrelated_bearer = setup_credential.locator(
        "option[value='cred-demo-bearer']"
    )
    _require(
        unrelated_bearer.count() == 1 and unrelated_bearer.is_disabled(),
        "Stripe setup did not reject the unrelated seeded bearer credential",
    )
    _require(
        setup_credential.input_value() == "",
        "Stripe setup silently selected an unrelated bearer credential",
    )
    _require(
        page.locator("#oauth-provider option[value='stripe']").count() == 0,
        "Stripe was incorrectly exposed as an OAuth provider",
    )
    add_credential = page.get_by_role("button", name="Add credential", exact=True)
    _require(add_credential.is_enabled(), "Stripe manual credential action is disabled")
    add_credential.click()
    page.wait_for_function(
        """
        () => {
          try {
            const metadata = JSON.parse(document.querySelector('#credential-metadata')?.value || '{}');
            return document.querySelector('#credential-kind')?.value === 'bearer'
              && metadata.provider === 'stripe'
              && new URL(window.location.href).searchParams.has('setup');
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    _require(
        page.locator("#credential-name").input_value()
        == (
            "Tokenized PaymentIntent create, five per UTC calendar day, resetting at "
            "00:00 UTC + hardware JIT credential"
        ),
        "Stripe manual credential name was not prefilled",
    )
    _require(
        json.loads(page.locator("#credential-metadata").input_value())
        == {"provider": "stripe"},
        "Stripe provider metadata was not prefilled",
    )
    _require(
        page.evaluate("document.activeElement?.id") == "credential-name",
        "Stripe setup did not focus the manual static credential form",
    )

    stripe_state = page.evaluate(
        """
        () => ({
          sessionId: state.setupSession?.id || null,
          revision: state.setupSession?.revision ?? null,
          oauthSetupSessionId: state.oauthSetupSessionId,
          oauthProvider: document.querySelector('#oauth-provider')?.value || '',
          oauthDraft: sessionStorage.getItem('serverware.oauthDraft')
        })
        """
    )
    _require(stripe_state["sessionId"], "Stripe setup did not create its temporary run")
    _require(
        stripe_state["oauthSetupSessionId"] == oauth_state_before["setupSessionId"],
        "Stripe manual setup was incorrectly attached to OAuth state",
    )
    _require(
        stripe_state["oauthProvider"] == oauth_state_before["provider"]
        and stripe_state["oauthDraft"] == oauth_state_before["draft"],
        "Stripe manual setup changed the selected OAuth provider or draft",
    )
    oauth_requests_after = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    _require(
        oauth_requests_after == oauth_requests_before,
        "Stripe manual setup started an OAuth request",
    )

    cancelled = page.evaluate(
        """
        async ({sessionId, revision, timeoutMs, maxBytes}) => {
          const token = document.querySelector('#admin-token')?.value || '';
          return window.__serverwareBoundedFetch(`/api/setup/sessions/${encodeURIComponent(sessionId)}/cancel`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            credentials: 'same-origin',
            body: JSON.stringify({
              expectedRevision: revision,
              reason: 'Browser Stripe manual credential flow assertion complete'
            })
          }, timeoutMs, maxBytes);
        }
        """,
        {
            "sessionId": stripe_state["sessionId"],
            "revision": stripe_state["revision"],
            "timeoutMs": _journey_timeout_ms(label="Stripe setup cancellation"),
            "maxBytes": MAX_API_RESPONSE_BYTES,
        },
    )
    _require(
        200 <= cancelled["status"] < 300,
        f"temporary Stripe setup run could not be cancelled: {cancelled}",
    )
    page.locator("#setup-session").select_option("")
    page.wait_for_function(
        """
        () => !new URL(window.location.href).searchParams.has('setup')
          && state.setupSession === null
        """,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    page.locator("#setup-template").select_option("gmail_recent")
    page.locator("#credential-name").fill(credential_form_before["name"])
    page.locator("#credential-kind").select_option(credential_form_before["kind"])
    page.locator("#credential-metadata").fill(credential_form_before["metadata"])
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'gmail_recent'
          && document.querySelector('#setup-connect-button')?.textContent === 'Connect credential'
        """,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )


def _connect_oauth(
    page: Any,
    context: Any,
    reviewer_page: Any,
    public_url: str,
    *,
    provider: str,
    name: str,
    scopes: list[str],
    account: str,
) -> dict[str, Any]:
    page.locator("#oauth-provider").select_option(provider)
    page.locator("#oauth-credential-name").fill(name)
    page.locator("#oauth-scopes").fill("\n".join(scopes))
    page.locator("#oauth-metadata").fill(
        json.dumps({"evidence": "deterministic-browser-oauth"}, separators=(",", ":"))
    )
    _require(
        page.locator("#oauth-submit").is_enabled(),
        f"{provider} OAuth submit is disabled",
    )
    with page.expect_response(
        lambda response: (
            response.request.method == "POST"
            and urlsplit(response.url).hostname == "localhost"
            and urlsplit(response.url).path == "/api/oauth/start"
        ),
        timeout=_journey_timeout_ms(label=f"{provider} OAuth start response"),
    ) as oauth_start_response_info:
        with page.expect_request(
            lambda request: (
                urlsplit(request.url).hostname == "localhost"
                and request.url != public_url
                and len(parse_qs(urlsplit(request.url).query).get("state", [])) == 1
            ),
            timeout=_journey_timeout_ms(label=f"{provider} OAuth authorization request"),
        ) as authorization_request_info:
            page.locator("#oauth-submit").click(no_wait_after=True)
    oauth_start_response = oauth_start_response_info.value
    _require(
        oauth_start_response.status == 200,
        f"{provider} OAuth start response was not successful",
    )
    oauth_start_headers_array = oauth_start_response.headers_array
    authorization_request = authorization_request_info.value
    authorization_state = parse_qs(
        urlsplit(authorization_request.url).query,
        strict_parsing=True,
    )["state"][0]
    _require(
        re.fullmatch(r"[A-Za-z0-9_-]{43,128}", authorization_state) is not None,
        f"{provider} OAuth authorization request state was malformed",
    )
    _assert_oauth_state_cookie(
        context,
        state=authorization_state,
        response_headers_array=oauth_start_headers_array,
    )
    try:
        page.get_by_role(
            "heading", name="OAuth account verified", exact=True
        ).wait_for(
            state="visible",
            timeout=_journey_timeout_ms(label="OAuth provider redirect wait"),
        )
    except Exception as exc:
        diagnostic = page.evaluate(
            """
            () => ({
              url: window.location.href,
              heading: document.querySelector('h1,h2')?.textContent || '',
              body: (document.body?.innerText || '').slice(0, 1000)
            })
            """
        )
        raise AssertionError(
            f"{provider} OAuth callback did not stage exact-account activation: {diagnostic}"
        ) from exc
    page.wait_for_url(
        re.compile(rf"^{re.escape(public_url)}/(?:\?.*)?$"),
        timeout=_journey_timeout_ms(label="OAuth callback URL wait"),
    )
    _require(
        page.locator("#admin-token").input_value() == "",
        "manual admin token unexpectedly survived the OAuth navigation",
    )
    page.locator("#admin-token").fill(ADMIN_TOKEN)
    page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(page, public_url)
    page.wait_for_function(
        """
        ({name, account}) => (state.pendingOAuthCredentials || []).some(
          (item) => item.name === name
            && item.requester_id === 'user:operator'
            && item.status === 'pending'
            && item.review?.provider_account === account
        )
        """,
        arg={"name": name, "account": account},
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    pending = page.evaluate(
        """
        ({name, account}) => (state.pendingOAuthCredentials || []).find(
          (item) => item.name === name && item.review?.provider_account === account
        )
        """,
        {"name": name, "account": account},
    )
    _require(
        pending.get("requester_id") == "user:operator",
        f"{provider} pending activation was not bound to the requester: {pending}",
    )
    pending_item = page.locator(
        "#pending-oauth-credentials .pending-oauth-item"
    ).filter(has_text=account)
    pending_item.get_by_role(
        "button", name="Request approval and activate", exact=True
    ).click()
    page.wait_for_function(
        """
        () => {
          try {
            const mutation = JSON.parse(
              sessionStorage.getItem('serverware.pendingMutation') || 'null'
            );
            return mutation?.kind === 'oauth-activate'
              && typeof mutation?.approvalId === 'string';
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    pending_mutation = page.evaluate(
        "() => JSON.parse(sessionStorage.getItem('serverware.pendingMutation'))"
    )
    approval_id = pending_mutation["approvalId"]
    _require(
        pending_mutation.get("path") == f"/api/oauth/pending/{pending['id']}/activate",
        f"{provider} retry mutation is not bound to the pending credential",
    )
    self_approval = page.evaluate(
        """
        async ({id, token, timeoutMs, maxBytes}) => {
          const response = await window.__serverwareBoundedFetch(`/api/control-plane/approvals/${id}/approve`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({note: 'requester self-approval must fail'}),
            credentials: 'same-origin',
            cache: 'no-store'
          }, timeoutMs, maxBytes);
          return {status: response.status, body: JSON.parse(response.text)};
        }
        """,
        {
            "id": approval_id,
            "token": ADMIN_TOKEN,
            "timeoutMs": _journey_timeout_ms(
                label=f"OAuth requester self-approval {approval_id}"
            ),
            "maxBytes": MAX_API_RESPONSE_BYTES,
        },
    )
    _require(
        self_approval.get("status") == 403
        and "requester cannot approve" in str(self_approval.get("body")),
        f"{provider} requester self-approval did not fail closed: {self_approval}",
    )

    reviewer_page.goto(public_url + "/", wait_until="domcontentloaded")
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(reviewer_page, public_url)
    reviewer_page.wait_for_function(
        """
        (id) => (state.controlPlaneApprovals || []).some(
          (item) => item.id === id
            && item.status === 'pending'
            && item.action === 'credential.oauth.activate'
            && item.requester_id === 'user:operator'
        )
        """,
        arg=approval_id,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    reviewer_activation = reviewer_page.evaluate(
        """
        async ({pendingId, setupSessionId, setupRevision, token, timeoutMs, maxBytes}) => {
          const response = await window.__serverwareBoundedFetch(`/api/oauth/pending/${pendingId}/activate`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
              setupSessionId,
              setupRevision
            }),
            credentials: 'same-origin',
            cache: 'no-store'
          }, timeoutMs, maxBytes);
          return {status: response.status, body: JSON.parse(response.text)};
        }
        """,
        {
            "pendingId": pending["id"],
            "setupSessionId": pending_mutation.get("body", {}).get("setupSessionId"),
            "setupRevision": pending_mutation.get("body", {}).get("setupRevision"),
            "token": ADMIN_TOKEN,
            "timeoutMs": _journey_timeout_ms(
                label=f"OAuth reviewer direct activation {pending['id']}"
            ),
            "maxBytes": MAX_API_RESPONSE_BYTES,
        },
    )
    _require(
        reviewer_activation.get("status") == 403
        and "only the OAuth requester" in str(reviewer_activation.get("body")),
        f"{provider} reviewer directly activated requester grant: {reviewer_activation}",
    )
    approval_row = reviewer_page.locator("#control-plane-approvals tr").filter(
        has_text=pending["id"]
    )
    approval_text = approval_row.inner_text()
    for marker in (
        "credential.oauth.activate",
        "user:operator",
        account,
        str(pending["review"]["provider_subject"]),
    ):
        _require(
            marker in approval_text,
            f"{provider} exact-account approval omitted {marker!r}",
        )
    approval_row.get_by_role("button", name="Approve", exact=True).click()
    reviewer_page.wait_for_function(
        """
        (id) => (state.controlPlaneApprovals || []).some(
          (item) => item.id === id
            && item.status === 'approved'
            && item.approved_by === 'user:demo'
        )
        """,
        arg=approval_id,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )

    page.get_by_role("button", name="Continue approved request", exact=True).click()
    page.wait_for_function(
        """
        ({name, account}) => [...document.querySelectorAll('#credentials tr')].some(
          (row) => row.textContent.includes(name)
            && row.textContent.includes(account)
            && row.textContent.includes('verified identity')
        )
        """,
        arg={"name": name, "account": account},
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    page.wait_for_function(
        """
        (id) => !(state.pendingOAuthCredentials || []).some((item) => item.id === id)
          && sessionStorage.getItem('serverware.pendingMutation') === null
        """,
        arg=pending["id"],
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    _assert_no_oauth_cookies(context)
    bootstrap = _api_json(page, "/api/bootstrap")
    credential = _credential_by_name(bootstrap, name)
    credential["browserApprovalId"] = approval_id
    return credential


def _preview_stage_activate_policy(
    page: Any,
    *,
    template: str,
    route_id: str,
    credential_id: str,
    custom_route: dict[str, Any] | None = None,
) -> dict[str, Any]:
    active_before = _api_json(page, "/api/policy")
    _require(
        active_before.get("ready") is True, "demo seed did not install an active policy"
    )
    old_hash = active_before.get("policy_hash")
    page.wait_for_function(
        "() => !refreshInFlight",
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    page.evaluate(
        "(activePolicy) => { state.activePolicy = activePolicy; }",
        active_before,
    )

    page.locator("#policy-template").select_option(template)
    page.locator("#policy-route-id").fill(route_id)
    page.locator("#policy-principal").select_option("agent:demo")
    page.locator("#policy-credential").select_option(credential_id)
    if custom_route is not None:
        _require(template == "custom_json", "custom route requires custom_json template")
        page.locator("#policy-custom-route").fill(
            json.dumps(custom_route, indent=2, sort_keys=True)
        )
    page.locator("#policy-route-form button[type='submit']").click()
    try:
        page.wait_for_function(
            """
            (routeId) => state.policyCandidate?.routeId === routeId
              && state.policyCandidate?.report?.dryRun?.passed === true
              && document.querySelector('#policy-candidate-summary')?.textContent.includes(
                '2/2 dry-run checks passed'
              )
            """,
            arg=route_id,
            timeout=_journey_timeout_ms(label="Playwright wait"),
        )
    except Exception as exc:
        diagnostics = page.evaluate(
            """
            () => ({
              status: document.querySelector('#operator-status')?.textContent || '',
              authStatus: document.querySelector('#operator-auth-status')?.textContent || '',
              candidateSummary: document.querySelector('#policy-candidate-summary')?.textContent || '',
              candidateOutput: document.querySelector('#policy-candidate-output')?.value || '',
              tokenLength: document.querySelector('#admin-token')?.value?.length || 0
            })
            """
        )
        raise AssertionError(
            f"{route_id} candidate preview did not complete: {diagnostics}"
        ) from exc
    preview = json.loads(page.locator("#policy-candidate-output").input_value())
    report = preview.get("candidate") or {}
    checks = (report.get("dryRun") or {}).get("results") or []
    _require(report.get("ok") is True, f"{route_id} candidate preview failed")
    _require(
        (report.get("dryRun") or {}).get("passed") is True
        and len(checks) == 2
        and all(item.get("passed") is True for item in checks),
        f"{route_id} candidate did not pass both allow/deny dry runs",
    )

    page.locator("#policy-stage-button").wait_for(
        state="visible",
        timeout=_journey_timeout_ms(label="policy stage action wait"),
    )
    _require(
        page.locator("#policy-stage-button").is_enabled(),
        "validated candidate cannot be staged",
    )
    page.locator("#policy-stage-button").click()
    try:
        page.wait_for_function(
            """
            () => {
              try {
                return JSON.parse(document.querySelector('#policy-canary-status')?.value || '{}')
                  .canary?.status === 'running';
              } catch (_) {
                return false;
              }
            }
            """,
            timeout=_journey_timeout_ms(label="Playwright wait"),
        )
    except Exception as exc:
        diagnostics = page.evaluate(
            """
            () => ({
              status: document.querySelector('#operator-status')?.textContent || '',
              canaryStatus: document.querySelector('#policy-canary-status')?.value || '',
              candidateOutput: document.querySelector('#policy-candidate-output')?.value || ''
            })
            """
        )
        raise AssertionError(
            f"{route_id} candidate staging did not complete: {diagnostics}"
        ) from exc
    _require(
        page.locator("#policy-activate-button").is_enabled(),
        "running canary cannot be activated",
    )
    page.locator("#policy-activate-button").click()
    active_after = _wait_for_api(
        page,
        "/api/policy",
        lambda payload: payload.get("ready") is True
        and payload.get("policy_hash") != old_hash,
    )
    page.wait_for_function(
        "(policyHash) => state.activePolicy?.policy_hash === policyHash",
        arg=active_after["policy_hash"],
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    route = next(
        (
            item
            for item in active_after["bundle"].get("routes", [])
            if item.get("id") == route_id
        ),
        None,
    )
    _require(route is not None, f"activated policy omits route {route_id}")
    _require(
        route.get("credentialRef") == credential_id,
        f"{route_id} credential assignment mismatch",
    )
    _require(
        route.get("principals") == ["agent:demo"],
        f"{route_id} principal assignment mismatch",
    )
    return active_after


def _assert_policy_evidence(
    policy: dict[str, Any],
    google_id: str,
    x_id: str,
    simulator: OAuthProviderSimulator,
    npm_registry: _NpmRegistryFixture,
    gate: _DecisionGateProcess,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    from serverware.policy_bundle import provider_request_profile

    bundle = policy["bundle"]
    defaults = bundle.get("defaults") or {}
    _require(
        defaults
        == {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "activated policy is not fail closed",
    )
    credentials = {item["id"]: item for item in bundle.get("credentials", [])}
    google = credentials.get(google_id) or {}
    x_credential = credentials.get(x_id) or {}
    _require(google.get("provider") == "google", "policy lost Google provider binding")
    _require(
        google.get("providerSubject") == "google-subject-001",
        "policy lost callback-verified Google subject",
    )
    _require(
        set(google.get("scopes") or []) == set(GOOGLE_SCOPES),
        "policy lost Google scopes",
    )
    _require(x_credential.get("provider") == "x", "policy lost X provider binding")
    _require(
        x_credential.get("providerSubject") == "x-subject-001",
        "policy lost callback-verified X subject",
    )
    _require(
        set(x_credential.get("scopes") or []) == set(X_SCOPES), "policy lost X scopes"
    )

    routes = {item["id"]: item for item in bundle.get("routes", [])}
    gmail = routes["browser.gmail.last-30-days"]
    x_search = routes["browser.x.search.seven-days"]
    x_post = routes[X_JIT_ROUTE_ID]
    npm_writes = routes[NPM_JIT_ROUTE_ID]
    npm_contention = routes[NPM_CONTENTION_ROUTE_ID]
    production_npm = routes["demo.npm.publish.jit"]
    expected_request_profiles = {
        "browser.gmail.last-30-days": provider_request_profile("gmail.v1"),
        "browser.x.search.seven-days": provider_request_profile(
            "x.v2",
            "recentSearchOnly",
        ),
        X_JIT_ROUTE_ID: provider_request_profile("x.v2", "controlledWrite"),
        NPM_JIT_ROUTE_ID: provider_request_profile("npm.registry"),
        NPM_CONTENTION_ROUTE_ID: provider_request_profile("npm.registry"),
    }
    for route_id, expected_request in expected_request_profiles.items():
        activated_request = (
            routes[route_id].get("adapter", {}).get("config", {}).get("request")
        )
        _require(
            activated_request == expected_request
            and set(activated_request)
            == {
                "allowedHeaders",
                "discardHeaders",
                "allowedQueryKeys",
                "allowedMediaTypes",
                "maxBodyBytes",
            }
            and not (
                set(activated_request["allowedHeaders"])
                & set(activated_request["discardHeaders"])
            ),
            f"{route_id} activated with a noncanonical or open request profile",
        )
    for npm_route in (npm_writes, npm_contention):
        npm_request = npm_route["adapter"]["config"]["request"]
        _require(
            "npm-session" not in npm_request["allowedHeaders"]
            and npm_request["discardHeaders"] == ["npm-session"],
            f"{npm_route['id']} did not discard npm-session before canonicalization",
        )
    _require(gmail["match"]["methods"] == ["GET"], "Gmail route is not read-only")
    _require(
        gmail["match"].get("host") == "127.0.0.1"
        and gmail["match"].get("port") == urlsplit(simulator.base_url).port,
        "Gmail route is not bound to the local HTTPS provider simulator",
    )
    _require(gmail["adapter"]["type"] == "gmail.v1", "Gmail route adapter mismatch")
    _require(
        gmail["adapter"]["config"].get("maxAgeDays") == 30
        and gmail["adapter"]["config"]["response"].get("validateInternalDate") is True,
        "Gmail route does not enforce and validate the 30-day boundary",
    )
    _require(x_search["match"]["methods"] == ["GET"], "X search route is not read-only")
    _require(
        x_search["match"].get("host") == "127.0.0.1"
        and x_search["match"].get("port") == urlsplit(simulator.base_url).port,
        "X search route is not bound to the local HTTPS provider simulator",
    )
    _require(
        x_search["adapter"]["config"].get("blockWrites") is True,
        "X search route does not block writes",
    )
    _require(
        x_search["adapter"]["config"].get("appIds") == [simulator.X_CLIENT_ID],
        "X route is not bound to the verified OAuth app",
    )
    _require(
        any(
            item.get("type") == "responseDateWindow" and item.get("maxAgeDays") == 7
            for item in x_search.get("constraints", [])
        ),
        "X route does not validate the seven-day response boundary",
    )
    _require(x_post["match"]["methods"] == ["POST"], "X posting route is not write-only")
    _require(
        x_post["match"].get("host") == "127.0.0.1"
        and x_post["match"].get("port") == urlsplit(simulator.base_url).port,
        "X posting route is not bound to the local simulator authority",
    )
    _require(
        x_post["adapter"]["config"].get("appIds") == [simulator.X_CLIENT_ID],
        "X posting route is not bound to the verified OAuth app",
    )
    daily_limits = [
        item
        for item in x_post.get("constraints", [])
        if item.get("type") == "rateLimit"
    ]
    _require(
        len(daily_limits) == 1
        and daily_limits[0].get("max") == 1
        and daily_limits[0].get("calendarWindow") == "utcDay"
        and daily_limits[0].get("store") == "shared"
        and (daily_limits[0].get("key") or {}).get("scope") == ["route", "operation"]
        and (daily_limits[0].get("key") or {}).get("operationFields")
        == ["providerAccount"],
        "X posting route lost its provider-account UTC calendar quota",
    )
    jit = x_post.get("jit") or {}
    authn = (jit.get("approvers") or {}).get("authn") or {}
    _require(
        jit.get("required") is True
        and jit.get("mode") == "perOperation"
        and jit.get("maxUses") == 1
        and jit.get("consumeOn") == "forwardStart"
        and (jit.get("approvers") or {}).get("users") == ["user:demo"]
        and authn.get("webauthnRequired") is True
        and authn.get("userVerification") == "required"
        and authn.get("allowedAuthenticatorClasses") == ["dev"]
        and authn.get("requireHardwareAttestation") is False,
        "X posting route lost its one-use reviewer WebAuthn JIT binding",
    )
    npm_operations = {
        "npm.publish",
        "npm.unpublish",
        "npm.distTagWrite",
        "npm.tokenWrite",
        "npm.metadataWrite",
    }
    npm_operation_policy = next(
        (
            item
            for item in npm_writes.get("constraints", [])
            if item.get("type") == "operationPolicy"
        ),
        {},
    )
    npm_jit = npm_writes.get("jit") or {}
    npm_authn = (npm_jit.get("approvers") or {}).get("authn") or {}
    _require(
        npm_writes.get("credentialRef") == NPM_CREDENTIAL_ID
        and npm_writes.get("match", {}).get("host") == "127.0.0.1"
        and npm_writes.get("match", {}).get("port") == npm_registry.port
        and npm_writes.get("match", {}).get("resolvedCidrs")
        == ["127.0.0.1/32"]
        and set(npm_writes.get("match", {}).get("methods") or [])
        == {"PUT", "POST", "DELETE"}
        and set(npm_writes.get("adapter", {}).get("config", {}).get("operations") or [])
        == {"publish", "unpublish", "distTagWrite", "tokenWrite", "metadataWrite"}
        and set(npm_operation_policy.get("allowedOperations") or [])
        == npm_operations
        and "npm.tokenCreate"
        not in set(npm_operation_policy.get("allowedOperations") or []),
        "npm route lost its exact local authority or closed five-operation allowlist",
    )
    _require(
        npm_jit.get("required") is True
        and npm_jit.get("mode") == "perOperation"
        and npm_jit.get("maxUses") == 1
        and npm_jit.get("consumeOn") == "forwardStart"
        and npm_jit.get("binding", {}).get("type") == "operationDigest"
        and "operation" in set(npm_jit.get("binding", {}).get("fields") or [])
        and (npm_jit.get("approvers") or {}).get("users") == ["user:demo"]
        and npm_authn.get("webauthnRequired") is True
        and npm_authn.get("userVerification") == "required"
        and npm_authn.get("allowedAuthenticatorClasses") == ["dev"]
        and npm_authn.get("requireHardwareAttestation") is False,
        "development npm route lost immutable operation-bound one-use dev WebAuthn JIT",
    )
    contention_limits = [
        item
        for item in npm_contention.get("constraints", [])
        if item.get("type") == "rateLimit"
    ]
    contention_jit = npm_contention.get("jit") or {}
    _require(
        npm_contention.get("credentialRef") == NPM_CREDENTIAL_ID
        and npm_contention.get("match", {}).get("host") == "127.0.0.1"
        and npm_contention.get("match", {}).get("port") == npm_registry.port
        and npm_contention.get("match", {}).get("methods") == ["PUT"]
        and npm_contention.get("match", {}).get("paths")
        == [f"/{NPM_CONTENTION_PACKAGE_PATH}"]
        and npm_contention.get("adapter", {}).get("config", {}).get("operations")
        == ["publish"]
        and len(contention_limits) == 1
        and contention_limits[0].get("max") == 1
        and contention_limits[0].get("windowSeconds") == 3600
        and contention_limits[0].get("store") == "shared"
        and contention_jit.get("required") is True
        and contention_jit.get("maxUses") == 1
        and contention_jit.get("consumeOn") == "forwardStart",
        "npm contention route lost its exact package, one-use grant, or shared quota",
    )
    contention_authn = (
        (contention_jit.get("approvers") or {}).get("authn") or {}
    )
    production_authn = (
        ((production_npm.get("jit") or {}).get("approvers") or {}).get("authn")
        or {}
    )
    _require(
        contention_authn
        == {
            "webauthnRequired": True,
            "userVerification": "required",
            "allowedAuthenticatorClasses": ["dev"],
            "requireHardwareAttestation": False,
        },
        "npm contention compatibility route is not explicitly development-only",
    )
    _require(
        production_authn.get("webauthnRequired") is True
        and production_authn.get("userVerification") == "required"
        and set(production_authn.get("allowedAuthenticatorClasses") or [])
        == {"yubikey", "hardware"}
        and production_authn.get("requireHardwareAttestation") is True,
        "canonical production npm template lost its separate hardware-only contract",
    )
    from serverware import db
    from serverware.webauthn import credential_trust_status

    development_credentials = [
        item
        for item in db.list_webauthn_credentials("user:demo")
        if item.get("revoked_at") is None
        and item.get("authenticator_class") == "dev"
    ]
    _require(
        len(development_credentials) == 1,
        "production hardware rejection did not have one exact development credential",
    )
    production_route_id = "demo.npm.publish.jit"
    stored_npm_credential = db.get_credential(NPM_CREDENTIAL_ID)
    _require(
        isinstance(stored_npm_credential, dict),
        "production hardware rejection lost the persisted npm credential",
    )
    credential_version = int(stored_npm_credential["credential_version"])
    development_credential = development_credentials[0]
    development_credential_trust = credential_trust_status(
        development_credential
    )
    _require(
        development_credential.get("user_id") == "user:demo"
        and development_credential.get("authenticator_class") == "dev"
        and development_credential_trust["effective_authenticator_class"] == "dev"
        and type(development_credential_trust["currently_trusted"]) is bool
        and "dev"
        not in set(production_authn["allowedAuthenticatorClasses"]),
        "persisted development credential did not independently fail the production policy",
    )
    body = _canonical_json_bytes(_npm_publish_document())
    production_request = (
        f"PUT /npm/{NPM_PACKAGE_PATH} HTTP/1.1\r\n"
        "Host: demo-upstream:8443\r\n"
        "Content-Type: application/json\r\n"
        "npm-session: 0123456789abcdef\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    production_before_428 = _jit_state_snapshot(
        production_route_id,
        NPM_CREDENTIAL_ID,
    )
    registry_before_428 = npm_registry.observations()
    production_first = _send_connect_tls_request(
        gate,
        authority_host="demo-upstream",
        authority_port=8443,
        request_bytes=production_request,
    )
    production_decision = production_first["json"] or {}
    production_approval_id = production_decision.get("approval_id")
    production_after_428 = _jit_state_snapshot(
        production_route_id,
        NPM_CREDENTIAL_ID,
    )
    production_approval_rows = [
        item
        for item in production_after_428["approvals"]
        if item["id"] == production_approval_id
    ]
    _require(
        production_first["status"] == 428
        and production_decision.get("action") == "jit_required"
        and production_decision.get("allowed") is False
        and production_decision.get("route_id") == production_route_id
        and production_decision.get("principal_id") == "agent:demo"
        and production_decision.get("policy_hash") == policy["policy_hash"]
        and production_decision.get("approval_status") == "pending"
        and production_decision.get("approval_created") is True
        and isinstance(production_approval_id, str)
        and production_decision.get("approval_url")
        == f"/approvals/{production_approval_id}"
        and len(production_after_428["approvals"])
        == len(production_before_428["approvals"]) + 1
        and len(production_approval_rows) == 1
        and production_approval_rows[0]["status"] == "pending"
        and production_approval_rows[0]["credential_id"] == NPM_CREDENTIAL_ID
        and production_approval_rows[0]["credential_version"]
        == credential_version
        and production_approval_rows[0]["policy_hash"] == policy["policy_hash"]
        and production_after_428["credential"]
        == production_before_428["credential"]
        and production_after_428["reviewReceipts"]
        == production_before_428["reviewReceipts"]
        and production_after_428["grants"] == production_before_428["grants"]
        and production_after_428["attempts"]
        == production_before_428["attempts"]
        and production_after_428["credentialIssuances"]
        == production_before_428["credentialIssuances"]
        and production_after_428["quotaReservations"]
        == production_before_428["quotaReservations"]
        and production_after_428["grantConsumptions"]
        == production_before_428["grantConsumptions"]
        and production_after_428["rateLimitCounters"]
        == production_before_428["rateLimitCounters"]
        and production_after_428["releaseEvents"]
        == production_before_428["releaseEvents"]
        and npm_registry.observations() == registry_before_428,
        "production request did not create one side-effect-free persisted Rust 428",
    )
    review = _api_json(
        reviewer_page,
        f"/api/approvals/{production_approval_id}/review",
    )
    review_receipt = review.get("review_receipt") or {}
    review_receipt_id = review_receipt.get("id")
    _require(
        review.get("route_id") == production_route_id
        and review.get("status") == "pending"
        and review.get("credential_ref") == NPM_CREDENTIAL_ID
        and review.get("credential_version") == credential_version
        and review.get("policy_hash") == policy["policy_hash"]
        and (review.get("normalized_operation_fields") or {}).get("operation")
        == "npm.publish"
        and (review.get("normalized_operation_fields") or {}).get("packageName")
        == NPM_PACKAGE_NAME
        and (
            review.get("normalized_operation_fields") or {}
        ).get("packageVersion")
        == NPM_PACKAGE_VERSION
        and isinstance(review_receipt_id, str),
        "production hardware rejection did not traverse the persisted review API",
    )
    state_before_rejection = _jit_state_snapshot(
        production_route_id,
        NPM_CREDENTIAL_ID,
    )
    registry_before_rejection = npm_registry.observations()
    dev_credential_before = db.get_webauthn_credential_by_record_id(
        development_credentials[0]["id"]
    )
    with db.connect() as conn:
        challenges_before_rejection = int(
            conn.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0]
        )
        audit_before_rejection = int(
            conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        )
    options_endpoint = (
        f"/api/approvals/{production_approval_id}/webauthn/options"
    )
    option_requests_before = sum(
        item.get("type") == "request"
        and item.get("method") == "POST"
        and options_endpoint in item.get("url", "")
        for item in browser_observations
    )
    rejected_options = _api_result(
        reviewer_page,
        options_endpoint,
        method="POST",
        payload={"reviewReceiptId": review_receipt_id},
    )
    option_requests_after = sum(
        item.get("type") == "request"
        and item.get("method") == "POST"
        and options_endpoint in item.get("url", "")
        for item in browser_observations
    )
    _require(
        rejected_options["status"] == 403
        and json.loads(rejected_options["text"])
        == {"detail": "no currently eligible WebAuthn credential is available"}
        and option_requests_after == option_requests_before + 1
        and "publicKey" not in rejected_options["text"]
        and "challenge" not in rejected_options["text"],
        "production hardware-only options API did not reject the development credential",
    )
    _require(
        _jit_state_snapshot(production_route_id, NPM_CREDENTIAL_ID)
        == state_before_rejection
        and npm_registry.observations() == registry_before_rejection
        and db.get_webauthn_credential_by_record_id(
            development_credentials[0]["id"]
        )
        == dev_credential_before
        and db.get_active_approval_review_receipt(
            review_receipt_id,
            approval_request_id=production_approval_id,
            reviewer_id="user:demo",
        )
        is not None,
        "production hardware rejection occurred after a JIT, quota, release, or upstream effect",
    )
    with db.connect() as conn:
        challenges_after_rejection = int(
            conn.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0]
        )
        audit_after_rejection = int(
            conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        )
    _require(
        challenges_after_rejection == challenges_before_rejection
        and audit_after_rejection == audit_before_rejection,
        "production hardware rejection created a challenge or audit side effect",
    )
    return {
        "routeId": production_route_id,
        "approvalId": production_approval_id,
        "reviewReceiptId": review_receipt_id,
        "optionsStatus": rejected_options["status"],
        "persistedApprovalApiPathExercised": True,
        "persistedApprovalCreatedThroughRustRoute": True,
        "developmentCredentialRejected": True,
        "rejectionCauseCrossBoundFromStoredCredentialAndPolicy": True,
        "typedHttpRejectionProven": False,
        "challengeCreated": False,
        "jitOrUpstreamEffect": False,
        "physicalHardwareAuthenticatorProven": False,
        "assuranceBoundary": (
            "The real production route, persisted review API, and options API are "
            "exercised. Stored credential trust facts independently prove that the only "
            "development credential is ineligible, and no challenge or release effect "
            "occurs. The options endpoint currently surfaces that WebAuthnError only as "
            "HTTP 500, so a typed client-visible hardware-policy rejection is not claimed."
        ),
    }


def _settle_screenshot_focus(page: Any) -> None:
    page.evaluate(
        """() => {
          const active = document.activeElement;
          if (active instanceof HTMLElement) active.blur();
          const skipLink = document.querySelector('.skip-link');
          if (skipLink instanceof HTMLElement) skipLink.style.visibility = 'hidden';
        }"""
    )
    page.wait_for_timeout(50)


def _capture_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -16)")
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_mobile_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -8)")
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_element_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    target = page.locator(selector)
    target.scroll_into_view_if_needed()
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    target.screenshot(path=str(destination), type="png")


def _jit_state_snapshot(route_id: str, credential_id: str) -> dict[str, Any]:
    from serverware import db

    def rows(conn: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        return [dict(item) for item in conn.execute(sql, params).fetchall()]

    with db.connect() as conn:
        credential_row = conn.execute(
            """
            SELECT credential_version, secret_updated_at, lifecycle_status
            FROM credentials
            WHERE id = ?
            """,
            (credential_id,),
        ).fetchone()
        _require(credential_row is not None, "callback credential disappeared")
        approvals = rows(
            conn,
            """
            SELECT id, status, principal_id, credential_id, credential_version,
                   policy_hash, request_digest, operation_digest, approved_by,
                   approval_challenge_id
            FROM approval_requests
            WHERE route_id = ?
            ORDER BY requested_at, id
            """,
            (route_id,),
        )
        receipts = rows(
            conn,
            """
            SELECT receipt.id, receipt.approval_request_id, receipt.reviewer_id,
                   receipt.review_digest, receipt.used_at
            FROM approval_review_receipts AS receipt
            INNER JOIN approval_requests AS approval
              ON approval.id = receipt.approval_request_id
            WHERE approval.route_id = ?
            ORDER BY receipt.created_at, receipt.id
            """,
            (route_id,),
        )
        grants = rows(
            conn,
            """
            SELECT id, approval_request_id, state, uses_remaining,
                   reserved_attempt_id, consumed_at
            FROM approval_grants
            WHERE route_id = ?
            ORDER BY created_at, id
            """,
            (route_id,),
        )
        attempts = rows(
            conn,
            """
            SELECT attempt_id, flow_id, state, credential_version, policy_hash,
                   request_digest, operation_digest, grant_id,
                   approval_request_id, completion_outcome
            FROM release_authorization_attempts
            WHERE route_id = ?
            ORDER BY created_at, attempt_id
            """,
            (route_id,),
        )
        issuances = rows(
            conn,
            """
            SELECT issuance.attempt_id, issuance.binding_digest,
                   issuance.request_binding_sha256,
                   attempt.approval_request_id, attempt.grant_id
            FROM release_authorization_credential_issuances AS issuance
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = issuance.attempt_id
            WHERE attempt.route_id = ?
            ORDER BY issuance.created_at, issuance.attempt_id
            """,
            (route_id,),
        )
        quotas = rows(
            conn,
            """
            SELECT quota.attempt_id, quota.constraint_id, quota.window_kind,
                   quota.max_count, quota.count_after, quota.reservation_state,
                   attempt.approval_request_id, attempt.grant_id
            FROM release_authorization_quota_reservations AS quota
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = quota.attempt_id
            WHERE attempt.route_id = ?
            ORDER BY quota.created_at, quota.attempt_id, quota.counter_key
            """,
            (route_id,),
        )
        consumptions = rows(
            conn,
            """
            SELECT id, grant_id, approval_request_id, attempt_id, outcome,
                   uses_remaining_before, uses_remaining_after
            FROM approval_grant_consumptions
            WHERE route_id = ?
            ORDER BY created_at, id
            """,
            (route_id,),
        )
        counters = rows(
            conn,
            """
            SELECT counter_key, constraint_id, window_kind, max_count, count
            FROM rate_limit_counters
            WHERE route_id = ?
            ORDER BY counter_key
            """,
            (route_id,),
        )
        release_events = rows(
            conn,
            """
            SELECT event.id, event.attempt_id, event.event_type,
                   attempt.approval_request_id, attempt.grant_id
            FROM release_authorization_events AS event
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = event.attempt_id
            WHERE attempt.route_id = ?
            ORDER BY event.created_at, event.id
            """,
            (route_id,),
        )
    return {
        "credential": dict(credential_row),
        "approvals": approvals,
        "reviewReceipts": receipts,
        "grants": grants,
        "attempts": attempts,
        "credentialIssuances": issuances,
        "quotaReservations": quotas,
        "grantConsumptions": consumptions,
        "rateLimitCounters": counters,
        "releaseEvents": release_events,
        "releaseEventCount": len(release_events),
    }


def _simulator_resource_state(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    observations = simulator.observations()
    google_counts = observations["counts"]["google"]
    x_counts = observations["counts"]["x"]
    return {
        "googleResourceRequests": int(
            google_counts.get("resource_requests") or 0
        ),
        "googleResourceRejections": int(
            google_counts.get("resource_rejections") or 0
        ),
        "gmailLists": int(
            google_counts.get("resource_gmail.messages.list") or 0
        ),
        "gmailMetadataGets": int(
            google_counts.get("resource_gmail.message.get") or 0
        ),
        "googleRefreshRequests": int(
            google_counts.get("refresh_exchanges") or 0
        ),
        "xResourceRequests": int(x_counts.get("resource_requests") or 0),
        "xResourceRejections": int(x_counts.get("resource_rejections") or 0),
        "tweetCreates": int(x_counts.get("resource_x.tweet.create") or 0),
        "recentSearches": int(x_counts.get("resource_x.search.recent") or 0),
        "xRefreshRequests": int(x_counts.get("refresh_exchanges") or 0),
        "resourceEvents": [
            {
                "type": item.get("type"),
                "provider": item.get("provider"),
                "operation": item.get("operation"),
                "reason": item.get("reason"),
            }
            for item in observations["events"]
            if str(item.get("type") or "").startswith("resource_")
        ],
    }


def _parse_http_response(raw: bytes) -> dict[str, Any]:
    _require(len(raw) <= 2 * 1024 * 1024, "gate response exceeded test bound")
    head, separator, body = raw.partition(b"\r\n\r\n")
    _require(bool(separator), f"gate response omitted header terminator: {raw[:500]!r}")
    lines = head.split(b"\r\n")
    _require(bool(lines), "gate response omitted a status line")
    status_parts = lines[0].split(b" ", 2)
    _require(
        len(status_parts) >= 2 and status_parts[1].isdigit(),
        f"gate response status line was malformed: {lines[0]!r}",
    )
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        _require(bool(separator), f"gate response header was malformed: {line!r}")
        normalized_name = name.decode("ascii").lower()
        _require(
            normalized_name not in headers,
            f"gate response duplicated header {normalized_name!r}",
        )
        headers[normalized_name] = value.decode("latin-1").strip()
    content_length = headers.get("content-length")
    if content_length is not None:
        _require(content_length.isdigit(), "gate response Content-Length was invalid")
        _require(
            len(body) == int(content_length),
            "gate response body length did not match Content-Length",
        )
    payload = json.loads(body) if body else None
    return {
        "status": int(status_parts[1]),
        "headers": headers,
        "body": body,
        "json": payload,
    }


class _PreparedConnectTlsClient:
    def __init__(
        self,
        gate: _DecisionGateProcess,
        *,
        authority_host: str,
        authority_port: int,
    ) -> None:
        authority = f"{authority_host}:{authority_port}"
        connect_request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "X-Serverware-Agent: demo-agent\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii")
        connect_timeout = _journey_timeout_seconds(
            label="gate CONNECT establishment",
            cap=10,
        )
        sock = socket.create_connection(
            ("127.0.0.1", gate.proxy_port),
            timeout=connect_timeout,
        )
        self._tls: ssl.SSLSocket | None = None
        self._sent = False
        self.authority = authority
        self.local_address = sock.getsockname()
        try:
            connect_deadline = time.monotonic() + connect_timeout
            sock.sendall(connect_request)
            connect_response = b""
            while b"\r\n\r\n" not in connect_response:
                remaining = connect_deadline - time.monotonic()
                _require(remaining > 0, "gate CONNECT response exceeded its deadline")
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                _require(bool(chunk), "gate closed before CONNECT response completed")
                connect_response += chunk
                _require(
                    len(connect_response) <= 64 * 1024,
                    "CONNECT response headers exceeded test bound",
                )
            connect_head, separator, connect_remainder = connect_response.partition(
                b"\r\n\r\n"
            )
            _require(bool(separator), "CONNECT response omitted its header terminator")
            _require(not connect_remainder, "gate sent bytes before the TLS handshake")
            _require(
                connect_head.startswith(b"HTTP/1.1 200 "),
                f"gate CONNECT preflight failed: {connect_head[:1000]!r}",
            )
            context = ssl.create_default_context(cafile=str(gate.ca_cert_path))
            tls = context.wrap_socket(sock, server_hostname=authority_host)
            tls.settimeout(
                _journey_timeout_seconds(label="gate TLS handshake", cap=10)
            )
            peer_certificate = tls.getpeercert(binary_form=True)
            _require(
                isinstance(peer_certificate, bytes) and bool(peer_certificate),
                "gate TLS interception omitted its peer certificate",
            )
            self.peer_certificate_sha256 = (
                "sha256:" + hashlib.sha256(peer_certificate).hexdigest()
            )
            self.tls_version = tls.version()
            self._tls = tls
        except BaseException:
            sock.close()
            raise

    def send(
        self,
        request_bytes: bytes,
        *,
        include_raw_response: bool = False,
    ) -> dict[str, Any]:
        _require(type(request_bytes) is bytes, "proxy request must be immutable bytes")
        _require(self._tls is not None, "prepared proxy client is closed")
        _require(not self._sent, "prepared proxy client may send only once")
        self._sent = True
        sent_request_sha256 = "sha256:" + hashlib.sha256(request_bytes).hexdigest()
        sent_request_length = len(request_bytes)
        tls = self._tls
        tls.sendall(request_bytes)
        response = b""
        response_deadline = time.monotonic() + _journey_timeout_seconds(
            label="gate HTTP response",
            cap=30,
        )
        while True:
            try:
                remaining = response_deadline - time.monotonic()
                _require(
                    remaining > 0,
                    "gate response exceeded its absolute receive deadline",
                )
                tls.settimeout(remaining)
                chunk = tls.recv(64 * 1024)
            except ssl.SSLEOFError:
                break
            if not chunk:
                break
            response += chunk
            _require(
                len(response) <= 2 * 1024 * 1024,
                "gate response exceeded test bound",
            )
        parsed = _parse_http_response(response)
        parsed["sentRequestSha256"] = sent_request_sha256
        parsed["sentRequestLength"] = sent_request_length
        parsed["sentRequestObjectId"] = id(request_bytes)
        if include_raw_response:
            parsed["_rawResponseBytes"] = response
        return parsed

    def close(self) -> None:
        tls = self._tls
        self._tls = None
        if tls is not None:
            tls.close()


def _send_connect_tls_request(
    gate: _DecisionGateProcess,
    *,
    authority_host: str,
    authority_port: int,
    request_bytes: bytes,
) -> dict[str, Any]:
    client = _PreparedConnectTlsClient(
        gate,
        authority_host=authority_host,
        authority_port=authority_port,
    )
    try:
        return client.send(request_bytes)
    finally:
        client.close()


def _send_two_connect_tls_requests_concurrently(
    gate: _DecisionGateProcess,
    *,
    registry: _NpmRegistryFixture,
    authority_host: str,
    authority_port: int,
    request_bytes: bytes,
) -> dict[str, Any]:
    _require(type(request_bytes) is bytes, "proxy request must be immutable bytes")
    clients: list[_PreparedConnectTlsClient] = []
    try:
        for _ in range(2):
            clients.append(
                _PreparedConnectTlsClient(
                    gate,
                    authority_host=authority_host,
                    authority_port=authority_port,
                )
            )
    except BaseException:
        for client in clients:
            client.close()
        raise
    _require(
        clients[0].local_address != clients[1].local_address,
        "concurrent contention clients did not use distinct TCP connections",
    )
    release = threading.Barrier(3, timeout=10)
    result_lock = threading.Lock()
    results: list[dict[str, Any] | None] = [None, None]
    errors: list[BaseException | None] = [None, None]

    def send(index: int) -> None:
        try:
            release.wait()
            result = clients[index].send(request_bytes)
            with result_lock:
                results[index] = result
        except BaseException as exc:
            with result_lock:
                errors[index] = exc
            release.abort()
        finally:
            clients[index].close()

    threads = [
        threading.Thread(
            target=send,
            args=(index,),
            name=f"serverware-one-use-contention-{index + 1}",
            daemon=True,
        )
        for index in range(2)
    ]
    started_threads: list[threading.Thread] = []
    coordinator_error: BaseException | None = None
    held_state: dict[str, Any] | None = None
    latch_final_state: dict[str, Any] | None = None
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        release.wait()
        registry.wait_for_contention_winner(
            timeout_seconds=_journey_timeout_seconds(
                label="npm contention upstream arrival",
                cap=10,
            )
        )
        loser_deadline = time.monotonic() + _journey_timeout_seconds(
            label="npm contention loser response",
            cap=10,
        )
        while time.monotonic() < loser_deadline:
            with result_lock:
                completed_results = [
                    item for item in results if item is not None
                ]
                current_errors = [
                    item for item in errors if item is not None
                ]
            if current_errors:
                raise current_errors[0]
            if completed_results:
                _require(
                    len(completed_results) == 1
                    and completed_results[0]["status"] == 428,
                    "npm contention winner completed before the loser failed closed",
                )
                held_state = registry.contention_latch_state()
                _require(
                    held_state
                    == {
                        "armed": True,
                        "arrivals": 1,
                        "winnerHeld": True,
                        "released": False,
                    },
                    "npm contention fixture did not hold exactly one upstream winner",
                )
                break
            time.sleep(0.01)
        _require(
            held_state is not None,
            "npm contention loser did not return 428 while the winner was held upstream",
        )
        registry.release_contention_winner()
    except BaseException as exc:
        coordinator_error = exc
        release.abort()
        for client in clients:
            client.close()
    finally:
        registry.release_contention_winner()
        deadline = time.monotonic() + 20
        for thread in started_threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for client in clients:
            client.close()
        latch_final_state = registry.finish_contention_latch()
    _require(
        all(not thread.is_alive() for thread in started_threads),
        "concurrent contention clients did not terminate within the bound",
    )
    if any(error is not None for error in errors):
        raise AssertionError(
            "concurrent contention client failed before producing a bounded response: "
            + "; ".join(
                f"client {index + 1}: {error!r}"
                for index, error in enumerate(errors)
                if error is not None
            )
        )
    if coordinator_error is not None:
        raise coordinator_error
    _require(
        all(result is not None for result in results),
        "concurrent contention omitted a client result",
    )
    return {
        "responses": [result for result in results if result is not None],
        "clients": [
            {
                "localAddress": list(client.local_address),
                "authority": client.authority,
                "peerCertificateSha256": client.peer_certificate_sha256,
                "tlsVersion": client.tls_version,
            }
            for client in clients
        ],
        "latch": {
            "winnerHeldWhileLoserReturned428": held_state is not None,
            "heldState": held_state,
            "finalState": latch_final_state,
            "secondUpstreamRequestObserved": (
                (latch_final_state or {}).get("arrivals") != 1
            ),
        },
    }


def _assert_storage_and_disk_do_not_leak_tokens(
    page: Any,
    context: Any,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    api_documents: list[Any],
    browser_observations: list[dict[str, Any]],
) -> None:
    storage = page.evaluate(
        """
        () => ({
          session: Object.fromEntries(Object.entries(sessionStorage)),
          local: Object.fromEntries(Object.entries(localStorage)),
          html: document.documentElement.outerHTML
        })
        """
    )
    observable = {
        "storage": storage,
        "cookies": context.cookies(),
        "api": api_documents,
        "browser": browser_observations,
    }
    simulator.assert_no_token_values(
        json.dumps(observable, sort_keys=True, default=str)
    )
    for path in data_dir.rglob("*"):
        if not path.is_file():
            continue
        size = path.stat().st_size
        _require(
            size <= MAX_EVIDENCE_FILE_BYTES,
            f"unexpected oversized evidence file: {path}",
        )
        simulator.assert_no_token_values(path.read_bytes())


def _assert_provider_observations(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    observations = simulator.observations()
    for provider in ("google", "x"):
        counts = observations["counts"][provider]
        for key in (
            "authorization_requests",
            "authorization_codes_issued",
            "token_requests",
            "authorization_code_exchanges",
            "token_responses",
            "identity_requests",
        ):
            _require(
                counts.get(key) == 1, f"{provider} {key} count was {counts.get(key)!r}"
            )
        for key in (
            "authorization_denials",
            "token_rejections",
            "identity_rejections",
            "revocation_rejections",
        ):
            _require(not counts.get(key), f"{provider} recorded unexpected {key}")
    _require(
        observations["active"]["authorizationCodes"] == 0,
        "simulator retained an unconsumed authorization code",
    )
    _require(
        observations["counts"]["google"].get("resource_requests") == 3
        and observations["counts"]["google"].get(
            "resource_gmail.messages.list"
        )
        == 1
        and observations["counts"]["google"].get(
            "resource_gmail.message.get"
        )
        == 2
        and not observations["counts"]["google"].get("resource_rejections")
        and not observations["counts"]["google"].get("refresh_exchanges"),
        "simulator did not accept one callback-token Gmail list with two "
        "metadata hydration requests and no refresh",
    )
    _require(
        observations["counts"]["x"].get("resource_requests") == 2
        and observations["counts"]["x"].get("resource_x.search.recent") == 1
        and observations["counts"]["x"].get("resource_x.tweet.create") == 1
        and not observations["counts"]["x"].get("resource_rejections")
        and not observations["counts"]["x"].get("refresh_exchanges"),
        "simulator did not accept one callback-token X search and one post "
        "without refresh",
    )
    rejected = [
        event for event in observations["events"] if "rejected" in event.get("type", "")
    ]
    _require(
        not rejected, f"simulator recorded rejected or replayed operations: {rejected}"
    )
    return observations


def _x_jit_route(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    return {
        "match": {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": simulator_port,
            "resolvedCidrs": ["127.0.0.0/8"],
            "methods": ["POST"],
            "paths": ["/2/tweets"],
        },
        "adapter": {
            "type": "x.v2",
            "config": {
                "mode": "controlledWrite",
                "blockWrites": False,
                "appIds": [simulator.X_CLIENT_ID],
                "request": {
                    "allowedHeaders": [
                        "accept",
                        "accept-encoding",
                        "content-type",
                        "user-agent",
                    ],
                    "discardHeaders": [],
                    "allowedQueryKeys": [],
                    "allowedMediaTypes": ["application/json"],
                    "maxBodyBytes": 65536,
                },
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 65536,
                    "allowedFields": ["data.id", "data.text"],
                    "allowedHeaders": [],
                    "error": {
                        "mode": "json",
                        "maxBodyBytes": 65536,
                        "allowedFields": [
                            "title",
                            "detail",
                            "type",
                            "status",
                            "errors.title",
                            "errors.detail",
                            "errors.type",
                            "errors.value",
                        ],
                        "allowedHeaders": ["retry-after"],
                        "onInvalid": "block",
                    },
                },
            },
        },
        "constraints": [
            {
                "id": "browser-x-only-tweet-create",
                "type": "operationPolicy",
                "allowedOperations": ["tweets.write"],
            },
            {
                "id": "browser-x-one-post-per-day",
                "type": "rateLimit",
                "max": 1,
                "calendarWindow": "utcDay",
                "store": "shared",
                "key": {
                    "scope": ["route", "operation"],
                    "operationFields": ["providerAccount"],
                },
            },
            {
                "id": "browser-x-plain-text-body",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["text", "reply_settings"],
                "requiredFields": ["text"],
                "deniedFields": ["media", "poll", "direct_message_deep_link"],
                "fields": {
                    "text": {"type": "string", "minLength": 1, "maxLength": 280},
                    "reply_settings": {
                        "type": "string",
                        "enum": ["following", "mentionedUsers"],
                    },
                },
            },
        ],
        "jit": {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 120,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "operationDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                    "operation",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:demo"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["dev"],
                    "requireHardwareAttestation": False,
                },
            },
        },
    }


def _npm_jit_route(registry: _NpmRegistryFixture) -> dict[str, Any]:
    return {
        "match": {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": registry.port,
            "resolvedCidrs": ["127.0.0.1/32"],
            "methods": ["PUT", "POST", "DELETE"],
            "paths": [
                "/{package}",
                "/{package}/-rev/{revision}",
                "/-/package/{package}/dist-tags/{tag}",
                "/-/npm/v1/tokens",
                "/-/npm/v1/tokens/token/{token}",
            ],
        },
        "adapter": {
            "type": "npm.registry",
            "config": {
                "request": {
                    "allowedHeaders": [
                        "accept",
                        "accept-encoding",
                        "content-type",
                        "npm-auth-type",
                        "npm-command",
                        "npm-in-ci",
                        "npm-otp",
                        "npm-scope",
                        "user-agent",
                    ],
                    "discardHeaders": ["npm-session"],
                    "allowedQueryKeys": [],
                    "allowedMediaTypes": ["application/json"],
                    "maxBodyBytes": 16_777_216,
                },
                "operations": [
                    "publish",
                    "unpublish",
                    "distTagWrite",
                    "tokenWrite",
                    "metadataWrite",
                ],
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 65_536,
                    "allowedFields": [
                        "ok",
                        "package",
                        "version",
                        "published",
                        "revision",
                        "unpublished",
                        "tag",
                        "dist_tag_written",
                        "token_revoked",
                        "metadata_updated",
                    ],
                    "allowedHeaders": [],
                    "error": {
                        "mode": "json",
                        "maxBodyBytes": 65_536,
                        "allowedFields": ["error", "reason", "code"],
                        "allowedHeaders": [],
                        "onInvalid": "block",
                    },
                },
            },
        },
        "constraints": [
            {
                "id": "browser-npm-five-write-classes",
                "type": "operationPolicy",
                "allowedOperations": [
                    "npm.publish",
                    "npm.unpublish",
                    "npm.distTagWrite",
                    "npm.tokenWrite",
                    "npm.metadataWrite",
                ],
            },
            {
                "id": "browser-npm-publish-identity",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["npm.publish"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "package-name",
                        "operationField": "packageName",
                        "responseField": "package",
                        "comparison": "exactString",
                    },
                    {
                        "id": "package-version",
                        "operationField": "packageVersion",
                        "responseField": "version",
                        "comparison": "exactString",
                    },
                ],
            },
            {
                "id": "browser-npm-publish-success",
                "type": "responseJson",
                "phase": "response",
                "operations": ["npm.publish"],
                "required": True,
                "fields": {
                    "published": {
                        "required": True,
                        "type": "boolean",
                        "equals": True,
                    }
                },
            },
        ],
        "jit": {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 300,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "operationDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                    "operation",
                    "packageName",
                    "packageVersion",
                    "tarballIntegrity",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:demo"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["dev"],
                    "requireHardwareAttestation": False,
                },
            },
        },
    }


def _npm_contention_route(registry: _NpmRegistryFixture) -> dict[str, Any]:
    return {
        "match": {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": registry.port,
            "resolvedCidrs": ["127.0.0.1/32"],
            "methods": ["PUT"],
            "paths": [f"/{NPM_CONTENTION_PACKAGE_PATH}"],
        },
        "adapter": {
            "type": "npm.registry",
            "config": {
                "request": {
                    "allowedHeaders": [
                        "accept",
                        "accept-encoding",
                        "content-type",
                        "npm-auth-type",
                        "npm-command",
                        "npm-in-ci",
                        "npm-otp",
                        "npm-scope",
                        "user-agent",
                    ],
                    "discardHeaders": ["npm-session"],
                    "allowedQueryKeys": [],
                    "allowedMediaTypes": ["application/json"],
                    "maxBodyBytes": 16_777_216,
                },
                "operations": ["publish"],
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 65_536,
                    "allowedFields": [
                        "package",
                        "version",
                        "published",
                    ],
                    "allowedHeaders": [],
                    "error": {
                        "mode": "json",
                        "maxBodyBytes": 65_536,
                        "allowedFields": ["error", "reason", "code"],
                        "allowedHeaders": [],
                        "onInvalid": "block",
                    },
                },
            },
        },
        "constraints": [
            {
                "id": "browser-npm-contention-publish-only",
                "type": "operationPolicy",
                "allowedOperations": ["npm.publish"],
            },
            {
                "id": "browser-npm-contention-single-shared-mutation",
                "type": "rateLimit",
                "max": 1,
                "windowSeconds": 3600,
                "store": "shared",
                "key": {
                    "scope": ["principal", "credential", "route", "operation"],
                },
            },
            {
                "id": "browser-npm-contention-response-identity",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["npm.publish"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "package-name",
                        "operationField": "packageName",
                        "responseField": "package",
                        "comparison": "exactString",
                    },
                    {
                        "id": "package-version",
                        "operationField": "packageVersion",
                        "responseField": "version",
                        "comparison": "exactString",
                    },
                ],
            },
            {
                "id": "browser-npm-contention-response-success",
                "type": "responseJson",
                "phase": "response",
                "operations": ["npm.publish"],
                "required": True,
                "fields": {
                    "published": {
                        "required": True,
                        "type": "boolean",
                        "equals": True,
                    }
                },
            },
        ],
        "jit": {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 300,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "operationDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                    "operation",
                    "packageName",
                    "packageVersion",
                    "tarballIntegrity",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:demo"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["dev"],
                    "requireHardwareAttestation": False,
                },
            },
        },
    }


def _npm_request_bytes(
    registry: _NpmRegistryFixture,
    operation: str,
) -> tuple[bytes, dict[str, Any]]:
    if operation == "npm.publish":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}"
        command = "publish"
        body_value: Any = _npm_publish_document()
    elif operation == "npm.unpublish":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}/-rev/{NPM_REVISION}"
        command = "unpublish"
        body_value = _npm_unpublish_document()
    elif operation == "npm.distTagWrite":
        method = "PUT"
        path = f"/-/package/{NPM_PACKAGE_PATH}/dist-tags/latest"
        command = "dist-tag"
        body_value = NPM_PACKAGE_VERSION
    elif operation == "npm.tokenWrite":
        method = "DELETE"
        path = f"/-/npm/v1/tokens/token/{NPM_TOKEN_KEY}"
        command = "token-revoke"
        body_value = None
    elif operation == "npm.metadataWrite":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}"
        command = "deprecate"
        body_value = _npm_metadata_document()
    elif operation == "npm.tokenCreate":
        method = "POST"
        path = "/-/npm/v1/tokens"
        command = "token-create"
        body_value = {
            "name": "serverware-browser-token",
            "readonly": False,
            "cidr_whitelist": [],
        }
    else:
        raise AssertionError(f"unsupported npm browser operation: {operation}")

    body = (
        b""
        if body_value is None
        else json.dumps(body_value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{registry.port}\r\n"
        "Accept: application/json\r\n"
        f"Npm-Command: {command}\r\n"
        f"User-Agent: serverware-browser-rust-{command}\r\n"
    )
    if body_value is not None:
        headers += (
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
        )
    headers += "Connection: close\r\n\r\n"
    expected_response = (
        {}
        if operation == "npm.tokenCreate"
        else _NpmRegistryFixture._response_for(operation)
    )
    return headers.encode("ascii") + body, expected_response


def _npm_contention_request_bytes(
    registry: _NpmRegistryFixture,
) -> tuple[bytes, dict[str, Any]]:
    body = json.dumps(
        _npm_contention_publish_document(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = (
        f"PUT /{NPM_CONTENTION_PACKAGE_PATH} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{registry.port}\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: serverware-browser-rust-contention\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    return request, _NpmRegistryFixture._response_for(
        "npm.publish",
        package_name=NPM_CONTENTION_PACKAGE_NAME,
        package_version=NPM_CONTENTION_PACKAGE_VERSION,
    )


def _localized_read_route(
    page: Any,
    *,
    template_id: str,
    simulator: OAuthProviderSimulator,
) -> dict[str, Any]:
    localized = page.evaluate(
        """
        (templateId) => {
          const template = policyTemplates[templateId];
          if (!template) return null;
          return JSON.parse(JSON.stringify({
            match: template.match,
            adapter: template.adapter,
            constraints: template.constraints || []
          }));
        }
        """,
        template_id,
    )
    _require(
        isinstance(localized, dict),
        f"portal omitted canonical policy template {template_id}",
    )
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    localized["match"]["host"] = "127.0.0.1"
    localized["match"]["port"] = simulator_port
    localized["match"]["resolvedCidrs"] = ["127.0.0.1/32"]
    if localized["adapter"].get("type") == "x.v2":
        localized["adapter"]["config"]["appIds"] = [simulator.X_CLIENT_ID]
    return localized


def _exercise_rust_reads(
    *,
    gate: _DecisionGateProcess,
    simulator: OAuthProviderSimulator,
) -> dict[str, Any]:
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    before = _simulator_resource_state(simulator)

    gmail_request = (
        "GET /gmail/v1/users/me/messages?maxResults=2 HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-gmail\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    gmail = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=gmail_request,
    )
    gmail_payload = gmail["json"]
    gmail_messages = (
        gmail_payload.get("messages") if isinstance(gmail_payload, dict) else None
    )
    now_ms = int(time.time() * 1000)
    _require(
        gmail["status"] == 200
        and isinstance(gmail_messages, list)
        and len(gmail_messages) == 2
        and all(
            isinstance(item, dict)
            and set(item).issubset(
                {"id", "threadId", "internalDate", "serverwareAgeProof"}
            )
            and isinstance(item.get("id"), str)
            and isinstance(item.get("threadId"), str)
            and str(item.get("internalDate") or "").isdigit()
            and item.get("serverwareAgeProof") == "validated"
            and 0 <= now_ms - int(item["internalDate"]) <= 30 * 86_400_000
            for item in gmail_messages
        )
        and "resultSizeEstimate" not in gmail_payload,
        f"Rust Gmail route did not hydrate, validate, and project recent messages: {gmail}",
    )

    x_request = (
        "GET /2/tweets/search/recent"
        "?max_results=10&query=serverware&tweet.fields=created_at HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-x-search\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    x_search = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=x_request,
    )
    x_payload = x_search["json"]
    x_items = x_payload.get("data") if isinstance(x_payload, dict) else None
    _require(
        x_search["status"] == 200
        and isinstance(x_items, list)
        and len(x_items) == 1
        and set(x_payload).issubset({"data", "meta"})
        and set(x_items[0]).issubset({"id", "text", "created_at"})
        and x_items[0].get("id") == "x-search-result-1"
        and isinstance(x_items[0].get("created_at"), str)
        and (x_payload.get("meta") or {}).get("result_count") == 1,
        f"Rust X route did not validate and project the recent search: {x_search}",
    )

    after = _simulator_resource_state(simulator)
    _require(
        after["googleResourceRequests"] == before["googleResourceRequests"] + 3
        and after["gmailLists"] == before["gmailLists"] + 1
        and after["gmailMetadataGets"] == before["gmailMetadataGets"] + 2
        and after["googleResourceRejections"]
        == before["googleResourceRejections"]
        and after["googleRefreshRequests"] == before["googleRefreshRequests"]
        and after["xResourceRequests"] == before["xResourceRequests"] + 1
        and after["recentSearches"] == before["recentSearches"] + 1
        and after["xResourceRejections"] == before["xResourceRejections"]
        and after["xRefreshRequests"] == before["xRefreshRequests"],
        f"callback-created read credentials did not reach the exact provider "
        f"operations without refresh or rejection: {before} -> {after}",
    )
    return {
        "gmail": {
            "status": gmail["status"],
            "requestBytesSha256": gmail["sentRequestSha256"],
            "messages": [item["id"] for item in gmail_messages],
            "metadataHydrations": 2,
        },
        "xSearch": {
            "status": x_search["status"],
            "requestBytesSha256": x_search["sentRequestSha256"],
            "resultIds": [item["id"] for item in x_items],
        },
    }


def _exercise_rust_jit(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    simulator: OAuthProviderSimulator,
    policy_hash: str,
    credential_id: str,
    credential_version: int,
    binary_digest: str,
    screenshots_dir: Path | None,
) -> dict[str, Any]:
    from serverware import db

    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    body = json.dumps(
        {"text": "Browser callback credential Rust JIT proof"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    immutable_request = (
        "POST /2/tweets HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: serverware-browser-rust-jit\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    request_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    before = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)

    gate_health = gate.wait_ready(
        policy_hash=policy_hash,
        binary_digest=binary_digest,
    )
    read_routes = _exercise_rust_reads(gate=gate, simulator=simulator)
    provider_before = _simulator_resource_state(simulator)
    first_send_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    first = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    decision = first["json"]
    _require(first["status"] == 428 and isinstance(decision, dict), f"first gate request was not a JSON 428: {first}")
    approval_id = decision.get("approval_id")
    approval_url = decision.get("approval_url")
    _require(
        decision.get("action") == "jit_required"
        and decision.get("allowed") is False
        and (decision.get("payload") or {}).get("error") == "jit_grant_unavailable"
        and isinstance(approval_id, str)
        and approval_url == f"/approvals/{approval_id}"
        and decision.get("approval_status") == "pending"
        and decision.get("approval_created") is True
        and decision.get("route_id") == X_JIT_ROUTE_ID
        and decision.get("principal_id") == "agent:demo"
        and decision.get("policy_hash") == policy_hash
        and str(decision.get("request_digest") or "").startswith("sha256:")
        and str(decision.get("operation_digest") or "").startswith("sha256:")
        and (decision.get("jit") or {}).get("grant_store")
        == "atomic_release_authorization",
        f"Rust 428 lost its exact JIT binding: {decision}",
    )
    after_428 = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        len(after_428["approvals"]) == len(before["approvals"]) + 1
        and after_428["approvals"][-1]["id"] == approval_id
        and after_428["approvals"][-1]["status"] == "pending"
        and after_428["approvals"][-1]["principal_id"] == "agent:demo"
        and after_428["approvals"][-1]["credential_id"] == credential_id
        and after_428["approvals"][-1]["credential_version"]
        == credential_version
        and after_428["approvals"][-1]["policy_hash"] == policy_hash
        and after_428["approvals"][-1]["request_digest"]
        == decision.get("request_digest")
        and after_428["approvals"][-1]["operation_digest"]
        == decision.get("operation_digest")
        and after_428["credential"] == before["credential"]
        and after_428["reviewReceipts"] == before["reviewReceipts"]
        and after_428["grants"] == before["grants"]
        and after_428["attempts"] == before["attempts"]
        and after_428["credentialIssuances"] == before["credentialIssuances"]
        and after_428["quotaReservations"] == before["quotaReservations"]
        and after_428["grantConsumptions"] == before["grantConsumptions"]
        and after_428["rateLimitCounters"] == before["rateLimitCounters"]
        and _simulator_resource_state(simulator) == provider_before,
        f"initial 428 caused secret, release, quota, or upstream side effects: {before} -> {after_428}",
    )
    hot_health = gate.wait_ready(
        policy_hash=policy_hash,
        binary_digest=binary_digest,
        require_hot_generation=True,
    )

    denied_review = _api_result(
        operator_page, f"/api/approvals/{approval_id}/review"
    )
    denied_approve = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/approve",
        method="POST",
        payload={"reviewReceiptId": "00000000-0000-4000-8000-000000000000"},
    )
    _require(
        denied_review["status"] == 403 and denied_approve["status"] == 403,
        f"unlisted operator was not denied review and approval: {denied_review}, {denied_approve}",
    )
    _require(
        _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id) == after_428,
        "operator denial mutated JIT authority state",
    )

    exact_approval_url = public_url + approval_url
    response = reviewer_page.goto(exact_approval_url, wait_until="domcontentloaded")
    _require(
        response is not None and response.status == 200,
        "reviewer approval URL did not return the portal",
    )
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(reviewer_page, public_url, expected_url=exact_approval_url)
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.review_receipt?.id",
        arg=approval_id,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    review = reviewer_page.evaluate("() => state.approvalReview")
    receipt_id = (review.get("review_receipt") or {}).get("id")
    _require(
        review.get("id") == approval_id
        and review.get("status") == "pending"
        and review.get("route_id") == X_JIT_ROUTE_ID
        and review.get("principal_id") == "agent:demo"
        and review.get("credential_ref") == credential_id
        and review.get("credential_version") == credential_version
        and review.get("policy_hash") == policy_hash
        and (review.get("retry_semantics") or {}).get("request_digest")
        == decision.get("request_digest")
        and (review.get("retry_semantics") or {}).get("operation_digest")
        == decision.get("operation_digest")
        and review.get("body_hash")
        == "sha256:" + hashlib.sha256(body).hexdigest()
        and isinstance(receipt_id, str),
        f"review document did not match the Rust 428: {review}",
    )
    active_receipt = db.get_active_approval_review_receipt(
        receipt_id,
        approval_request_id=approval_id,
        reviewer_id="user:demo",
    )
    _require(
        active_receipt is not None
        and active_receipt["review_digest"] == review.get("review_digest"),
        "reviewer did not receive the exact active review receipt",
    )
    if screenshots_dir is not None:
        _capture_element_screenshot(
            reviewer_page,
            ".approval-review-context",
            screenshots_dir / "operator-portal-approval.png",
        )
    approval_button = reviewer_page.locator("#approval-review-actions").get_by_role(
        "button", name="Approve", exact=True
    )
    approval_button.click()
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.status === 'approved'",
        arg=approval_id,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    approved = _assert_single_approval_decision(
        reviewer_page,
        browser_observations,
        approval_id,
        "approve",
        expected_request_count=2,
        expected_denied_count=1,
    )
    stored_approval = db.get_approval_request(approval_id)
    authn = (stored_approval or {}).get("approval_authn") or {}
    credential_record_id = authn.get("credential_record_id")
    approval_credential = (
        db.get_webauthn_credential_by_record_id(credential_record_id)
        if isinstance(credential_record_id, str)
        else None
    )
    _require(
        approved.get("approved_by") == "user:demo"
        and authn.get("method") == "webauthn"
        and authn.get("user_id") == "user:demo"
        and isinstance(approval_credential, dict)
        and approval_credential.get("user_id") == "user:demo"
        and authn.get("credential_id") == approval_credential.get("credential_id")
        and authn.get("authenticator_class")
        == approval_credential.get("authenticator_class")
        and authn.get("effective_authenticator_class") == "dev"
        and authn.get("attestation_trusted")
        is bool(approval_credential.get("attestation_trusted"))
        and authn.get("user_verified") is True
        and authn.get("authenticator_class") == "dev"
        and authn.get("review_receipt_id") == receipt_id
        and db.get_active_approval_review_receipt(
            receipt_id,
            approval_request_id=approval_id,
            reviewer_id="user:demo",
        )
        is None,
        f"review receipt or WebAuthn authority was not consumed exactly once: {stored_approval}",
    )
    options_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and f"/api/approvals/{approval_id}/webauthn/options" in item.get("url", "")
    ]
    assertion_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    ]
    _require(
        len(options_requests) == 1 and len(assertion_requests) == 1,
        "reviewer did not perform exactly one options and WebAuthn assertion request",
    )

    approved_state = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        len(approved_state["grants"]) == 1
        and approved_state["grants"][0]["state"] == "active"
        and approved_state["grants"][0]["uses_remaining"] == 1
        and approved_state["attempts"] == before["attempts"],
        f"approval did not create exactly one unused grant: {approved_state}",
    )
    retry_send_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    retry = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    _require(
        first["sentRequestSha256"]
        == retry["sentRequestSha256"]
        == first_send_digest
        == retry_send_digest
        == request_digest
        and first["sentRequestLength"]
        == retry["sentRequestLength"]
        == len(immutable_request)
        and retry["status"] == 201
        and (retry["json"] or {}).get("data", {}).get("text")
        == "Browser callback credential Rust JIT proof",
        f"approved byte-identical retry did not reach the simulator: {retry}",
    )
    after_success = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    provider_success = _simulator_resource_state(simulator)
    _require(
        len(after_success["attempts"]) == 1
        and after_success["attempts"][0]["state"] == "committed"
        and after_success["attempts"][0]["completion_outcome"] == "forwarded"
        and after_success["attempts"][0]["approval_request_id"] == approval_id
        and after_success["attempts"][0]["request_digest"]
        == decision.get("request_digest")
        and after_success["attempts"][0]["operation_digest"]
        == decision.get("operation_digest")
        and len(after_success["credentialIssuances"]) == 1
        and len(after_success["quotaReservations"]) == 1
        and after_success["quotaReservations"][0]["window_kind"] == "utcDay"
        and after_success["quotaReservations"][0]["count_after"] == 1
        and after_success["quotaReservations"][0]["reservation_state"] == "committed"
        and len(after_success["grantConsumptions"]) == 1
        and after_success["grantConsumptions"][0]["uses_remaining_before"] == 1
        and after_success["grantConsumptions"][0]["uses_remaining_after"] == 0
        and after_success["grants"][0]["state"] == "consumed"
        and after_success["grants"][0]["uses_remaining"] == 0
        and after_success["credential"] == before["credential"]
        and provider_success["xResourceRequests"]
        == provider_before["xResourceRequests"] + 1
        and provider_success["tweetCreates"] == provider_before["tweetCreates"] + 1
        and provider_success["xRefreshRequests"] == provider_before["xRefreshRequests"],
        f"approved retry lost callback-token or atomic lifecycle evidence: {after_success}, {provider_success}",
    )

    third = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    third_decision = third["json"]
    after_third = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        third["status"] == 428
        and third_decision.get("action") == "jit_required"
        and third_decision.get("approval_created") is True
        and third_decision.get("approval_id") != approval_id
        and len(after_third["approvals"]) == len(after_success["approvals"]) + 1
        and after_third["attempts"] == after_success["attempts"]
        and after_third["credentialIssuances"] == after_success["credentialIssuances"]
        and after_third["quotaReservations"] == after_success["quotaReservations"]
        and after_third["grantConsumptions"] == after_success["grantConsumptions"]
        and after_third["rateLimitCounters"] == after_success["rateLimitCounters"]
        and _simulator_resource_state(simulator) == provider_success,
        f"one-use retry did not create a fresh side-effect-free 428: {third}, {after_third}",
    )

    unknown_request = (
        "GET /2/users/me HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-unknown-route\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    unknown_before = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    provider_unknown_before = _simulator_resource_state(simulator)
    unknown = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=unknown_request,
    )
    _require(
        unknown["status"] == 403
        and (unknown["json"] or {}).get("payload", {}).get("error")
        == "unknown_route_denied"
        and _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id) == unknown_before
        and _simulator_resource_state(simulator) == provider_unknown_before,
        f"same-authority unknown route did not fail before secret/JIT/upstream effects: {unknown}",
    )
    return {
        "approvalId": approval_id,
        "freshApprovalId": third_decision["approval_id"],
        "requestBytesSha256": request_digest,
        "requestBytesLength": len(immutable_request),
        "requestDigest": decision["request_digest"],
        "operationDigest": decision["operation_digest"],
        "credentialVersion": credential_version,
        "readRoutes": read_routes,
        "retryStatus": retry["status"],
        "unknownRouteStatus": unknown["status"],
        "gateHealth": gate_health,
        "hotGateHealth": hot_health,
    }


def _approve_npm_jit_request(
    *,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    route_id: str,
    operation: str,
    decision: dict[str, Any],
    state_after_428: dict[str, Any],
    credential_version: int,
    expected_body_sha256: str | None,
    expected_package_name: str | None,
    expected_package_version: str | None,
) -> dict[str, Any]:
    from serverware import db
    from serverware.webauthn import credential_trust_status

    approval_id = decision["approval_id"]
    denied_review = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/review",
    )
    denied_approve = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/approve",
        method="POST",
        payload={"reviewReceiptId": "00000000-0000-4000-8000-000000000000"},
    )
    _require(
        denied_review["status"] == 403 and denied_approve["status"] == 403,
        f"{operation} requester was not denied review and approval",
    )
    _require(
        _jit_state_snapshot(route_id, NPM_CREDENTIAL_ID) == state_after_428,
        f"{operation} requester denials mutated JIT state",
    )

    assertion_requests_before = sum(
        1
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    )
    exact_approval_url = public_url + decision["approval_url"]
    response = reviewer_page.goto(exact_approval_url, wait_until="domcontentloaded")
    _require(
        response is not None and response.status == 200,
        f"{operation} reviewer deep link did not return the portal",
    )
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(
        reviewer_page,
        public_url,
        expected_url=exact_approval_url,
    )
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.review_receipt?.id",
        arg=approval_id,
        timeout=_journey_timeout_ms(label="Playwright wait"),
    )
    review = reviewer_page.evaluate("() => state.approvalReview")
    receipt_id = (review.get("review_receipt") or {}).get("id")
    operation_fields = review.get("normalized_operation_fields") or {}
    review_body_sha256 = review.get("body_hash")
    _require(
        review.get("id") == approval_id
        and review.get("status") == "pending"
        and review.get("route_id") == route_id
        and review.get("principal_id") == "agent:demo"
        and review.get("credential_ref") == NPM_CREDENTIAL_ID
        and review.get("credential_version") == credential_version
        and review.get("policy_hash") == decision["policy_hash"]
        and isinstance(review_body_sha256, str)
        and review_body_sha256.startswith("sha256:")
        and (
            expected_body_sha256 is None
            or review_body_sha256 == expected_body_sha256
        )
        and (review.get("retry_semantics") or {}).get("request_digest")
        == decision["request_digest"]
        and (review.get("retry_semantics") or {}).get("operation_digest")
        == decision["operation_digest"]
        and (review.get("retry_semantics") or {}).get("agent_action")
        == "retry-identical-request-through-proxy"
        and (review.get("retry_semantics") or {}).get(
            "agent_receives_secret_or_token"
        )
        is False
        and operation_fields.get("operation") == operation
        and isinstance(receipt_id, str),
        f"{operation} browser review did not expose its exact safe operation binding: {review}",
    )
    if expected_package_name is not None:
        _require(
            operation_fields.get("packageName") == expected_package_name,
            f"{operation} review lost its package binding: {operation_fields}",
        )
    if expected_package_version is not None:
        _require(
            operation_fields.get("packageVersion") == expected_package_version,
            f"{operation} review lost its package version binding: {operation_fields}",
        )
    if operation == "npm.publish":
        _require(
            str(operation_fields.get("tarballIntegrity") or "").startswith(
                "sha512-"
            ),
            f"{operation} review lost its derived tarball integrity binding",
        )
    active_receipt = db.get_active_approval_review_receipt(
        receipt_id,
        approval_request_id=approval_id,
        reviewer_id="user:demo",
    )
    _require(
        active_receipt is not None
        and active_receipt["review_digest"] == review.get("review_digest"),
        f"{operation} reviewer did not receive the active exact-review receipt",
    )

    reviewer_page.locator("#approval-review-actions").get_by_role(
        "button",
        name="Approve",
        exact=True,
    ).click()
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.status === 'approved'",
        arg=approval_id,
        timeout=_journey_timeout_ms(label="npm approval completion wait"),
    )
    approved = _assert_single_approval_decision(
        reviewer_page,
        browser_observations,
        approval_id,
        "approve",
        expected_request_count=2,
        expected_denied_count=1,
    )
    stored_approval = db.get_approval_request(approval_id)
    authn = (stored_approval or {}).get("approval_authn") or {}
    credential_record_id = authn.get("credential_record_id")
    approval_credential = (
        db.get_webauthn_credential_by_record_id(credential_record_id)
        if isinstance(credential_record_id, str)
        else None
    )
    approval_credential_trust = (
        credential_trust_status(approval_credential)
        if isinstance(approval_credential, dict)
        else None
    )
    assertion_requests_after = sum(
        1
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    )
    operation_options_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and f"/api/approvals/{approval_id}/webauthn/options"
        in item.get("url", "")
    ]
    _require(
        approved.get("approved_by") == "user:demo"
        and authn.get("method") == "webauthn"
        and authn.get("user_id") == "user:demo"
        and isinstance(credential_record_id, str)
        and isinstance(approval_credential, dict)
        and approval_credential.get("id") == credential_record_id
        and approval_credential.get("user_id") == "user:demo"
        and isinstance(approval_credential_trust, dict)
        and isinstance(approval_credential.get("credential_id"), str)
        and authn.get("credential_id") == approval_credential.get("credential_id")
        and authn.get("authenticator_class")
        == approval_credential.get("authenticator_class")
        and type(approval_credential.get("attestation_trusted")) is bool
        and authn.get("attestation_trusted")
        is approval_credential_trust.get("currently_trusted")
        and authn.get("effective_authenticator_class")
        == approval_credential_trust.get("effective_authenticator_class")
        and authn.get("user_verified") is True
        and authn.get("review_receipt_id") == receipt_id
        and len(operation_options_requests) == 1
        and assertion_requests_after == assertion_requests_before + 1
        and db.get_active_approval_review_receipt(
            receipt_id,
            approval_request_id=approval_id,
            reviewer_id="user:demo",
        )
        is None,
        f"{operation} did not consume one browser WebAuthn review authority",
    )
    return {
        "approvalId": approval_id,
        "reviewReceiptId": receipt_id,
        "reviewBodySha256": review_body_sha256,
        "operationFields": operation_fields,
        "webauthnCredentialRecordId": credential_record_id,
        "webauthnCredentialId": approval_credential["credential_id"],
        "authenticatorClass": approval_credential_trust[
            "effective_authenticator_class"
        ],
        "attestationTrusted": approval_credential_trust["currently_trusted"],
        "hardwareAttestationProven": (
            approval_credential_trust["currently_trusted"] is True
            and approval_credential_trust["effective_authenticator_class"]
            in {"yubikey", "hardware"}
        ),
    }


def _exercise_one_npm_jit_operation(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
    operation: str,
) -> dict[str, Any]:
    immutable_request, expected_response = _npm_request_bytes(registry, operation)
    request_bytes_sha256 = (
        "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    )
    _, _, body = immutable_request.partition(b"\r\n\r\n")
    body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
    before = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_before = registry.observations()

    first = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    decision = first["json"]
    _require(
        first["status"] == 428
        and isinstance(decision, dict)
        and decision.get("action") == "jit_required"
        and decision.get("allowed") is False
        and (decision.get("payload") or {}).get("error")
        == "jit_grant_unavailable"
        and decision.get("route_id") == NPM_JIT_ROUTE_ID
        and decision.get("principal_id") == "agent:demo"
        and decision.get("policy_hash") == policy_hash
        and isinstance(decision.get("approval_id"), str)
        and decision.get("approval_url")
        == f"/approvals/{decision.get('approval_id')}"
        and decision.get("approval_status") == "pending"
        and decision.get("approval_created") is True
        and str(decision.get("request_digest") or "").startswith("sha256:")
        and str(decision.get("operation_digest") or "").startswith("sha256:")
        and (decision.get("jit") or {}).get("grant_store")
        == "atomic_release_authorization",
        f"{operation} initial Rust request did not create an exact JIT 428: {first}",
    )
    approval_id = decision["approval_id"]
    after_428 = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    approval_rows = [
        item for item in after_428["approvals"] if item["id"] == approval_id
    ]
    _require(
        len(after_428["approvals"]) == len(before["approvals"]) + 1
        and len(approval_rows) == 1
        and approval_rows[0]["status"] == "pending"
        and approval_rows[0]["principal_id"] == "agent:demo"
        and approval_rows[0]["credential_id"] == NPM_CREDENTIAL_ID
        and approval_rows[0]["credential_version"] == credential_version
        and approval_rows[0]["policy_hash"] == policy_hash
        and approval_rows[0]["request_digest"] == decision["request_digest"]
        and approval_rows[0]["operation_digest"] == decision["operation_digest"]
        and after_428["credential"] == before["credential"]
        and after_428["reviewReceipts"] == before["reviewReceipts"]
        and after_428["grants"] == before["grants"]
        and after_428["attempts"] == before["attempts"]
        and after_428["credentialIssuances"] == before["credentialIssuances"]
        and after_428["quotaReservations"] == before["quotaReservations"]
        and after_428["grantConsumptions"] == before["grantConsumptions"]
        and after_428["rateLimitCounters"] == before["rateLimitCounters"]
        and after_428["releaseEventCount"] == before["releaseEventCount"]
        and registry.observations() == registry_before,
        f"{operation} initial 428 caused credential, release, or upstream effects",
    )

    _approve_npm_jit_request(
        operator_page=operator_page,
        reviewer_page=reviewer_page,
        browser_observations=browser_observations,
        public_url=public_url,
        route_id=NPM_JIT_ROUTE_ID,
        operation=operation,
        decision=decision,
        state_after_428=after_428,
        credential_version=credential_version,
        expected_body_sha256=body_sha256,
        expected_package_name=(
            None if operation == "npm.tokenWrite" else NPM_PACKAGE_NAME
        ),
        expected_package_version=(
            NPM_PACKAGE_VERSION if operation == "npm.publish" else None
        ),
    )

    approved_state = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    grants = [
        item
        for item in approved_state["grants"]
        if item["approval_request_id"] == approval_id
    ]
    _require(
        len(grants) == 1
        and grants[0]["state"] == "active"
        and grants[0]["uses_remaining"] == 1
        and approved_state["attempts"] == before["attempts"],
        f"{operation} approval did not create exactly one unused grant",
    )

    retry = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    _require(
        first["sentRequestSha256"]
        == retry["sentRequestSha256"]
        == request_bytes_sha256
        and first["sentRequestLength"]
        == retry["sentRequestLength"]
        == len(immutable_request)
        and retry["status"] == 200
        and retry["json"] == expected_response,
        f"{operation} approved byte-identical retry failed: {retry}",
    )
    after_success = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_success = registry.observations()
    attempts = [
        item
        for item in after_success["attempts"]
        if item["approval_request_id"] == approval_id
    ]
    consumptions = [
        item
        for item in after_success["grantConsumptions"]
        if item["approval_request_id"] == approval_id
    ]
    success_grants = [
        item
        for item in after_success["grants"]
        if item["approval_request_id"] == approval_id
    ]
    issuance_attempt_ids = {
        item["attempt_id"] for item in after_success["credentialIssuances"]
    }
    operation_events = [
        item
        for item in registry_success["events"]
        if item.get("operation") == operation
    ]
    _require(
        len(after_success["attempts"]) == len(before["attempts"]) + 1
        and len(attempts) == 1
        and attempts[0]["state"] == "committed"
        and attempts[0]["completion_outcome"] == "forwarded"
        and attempts[0]["request_digest"] == decision["request_digest"]
        and attempts[0]["operation_digest"] == decision["operation_digest"]
        and attempts[0]["attempt_id"] in issuance_attempt_ids
        and len(after_success["credentialIssuances"])
        == len(before["credentialIssuances"]) + 1
        and after_success["quotaReservations"] == before["quotaReservations"]
        and len(after_success["grantConsumptions"])
        == len(before["grantConsumptions"]) + 1
        and len(consumptions) == 1
        and consumptions[0]["uses_remaining_before"] == 1
        and consumptions[0]["uses_remaining_after"] == 0
        and len(success_grants) == 1
        and success_grants[0]["state"] == "consumed"
        and success_grants[0]["uses_remaining"] == 0
        and after_success["credential"] == before["credential"]
        and after_success["releaseEventCount"] > before["releaseEventCount"]
        and registry_success["counts"][operation]
        == registry_before["counts"][operation] + 1
        and registry_success["counts"]["rejected"]
        == registry_before["counts"]["rejected"]
        and len(operation_events) == 1
        and operation_events[0]["bodySha256"] == body_sha256
        and operation_events[0]["authorizationPresent"] is True
        and operation_events[0]["authorizationScheme"] == "Bearer"
        and operation_events[0]["npmSessionHeaders"] == [],
        f"{operation} approved retry lost atomic release or upstream evidence",
    )

    third = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    third_decision = third["json"]
    after_third = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    _require(
        third["status"] == 428
        and isinstance(third_decision, dict)
        and third_decision.get("action") == "jit_required"
        and third_decision.get("approval_created") is True
        and third_decision.get("approval_id") != approval_id
        and len(after_third["approvals"]) == len(after_success["approvals"]) + 1
        and after_third["attempts"] == after_success["attempts"]
        and after_third["credentialIssuances"]
        == after_success["credentialIssuances"]
        and after_third["quotaReservations"] == after_success["quotaReservations"]
        and after_third["grantConsumptions"]
        == after_success["grantConsumptions"]
        and after_third["rateLimitCounters"]
        == after_success["rateLimitCounters"]
        and registry.observations() == registry_success,
        f"{operation} one-use grant did not produce a fresh side-effect-free 428",
    )
    return {
        "operation": operation,
        "approvalId": approval_id,
        "freshApprovalId": third_decision["approval_id"],
        "requestBytesSha256": request_bytes_sha256,
        "requestBytesLength": len(immutable_request),
        "requestDigest": decision["request_digest"],
        "operationDigest": decision["operation_digest"],
        "retryStatus": retry["status"],
    }


def _exercise_npm_one_use_contention(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
) -> dict[str, Any]:
    immutable_request, expected_response = _npm_contention_request_bytes(registry)
    request_bytes_sha256 = (
        "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    )
    _, _, body = immutable_request.partition(b"\r\n\r\n")
    body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
    before = _jit_state_snapshot(
        NPM_CONTENTION_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    registry_before = registry.observations()
    _require(
        not before["approvals"]
        and not before["grants"]
        and not before["attempts"]
        and not before["credentialIssuances"]
        and not before["quotaReservations"]
        and not before["grantConsumptions"]
        and not before["rateLimitCounters"]
        and not before["releaseEvents"],
        "npm contention route did not begin with isolated authority state",
    )

    first = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    decision = first["json"]
    _require(
        first["status"] == 428
        and isinstance(decision, dict)
        and decision.get("action") == "jit_required"
        and decision.get("allowed") is False
        and (decision.get("payload") or {}).get("error")
        == "jit_grant_unavailable"
        and decision.get("route_id") == NPM_CONTENTION_ROUTE_ID
        and decision.get("principal_id") == "agent:demo"
        and decision.get("policy_hash") == policy_hash
        and decision.get("approval_created") is True
        and decision.get("approval_status") == "pending"
        and isinstance(decision.get("approval_id"), str)
        and decision.get("approval_url")
        == f"/approvals/{decision.get('approval_id')}",
        f"npm contention preflight did not create one exact pending JIT approval: {first}",
    )
    approval_id = decision["approval_id"]
    after_428 = _jit_state_snapshot(
        NPM_CONTENTION_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    _require(
        len(after_428["approvals"]) == 1
        and after_428["approvals"][0]["id"] == approval_id
        and after_428["approvals"][0]["status"] == "pending"
        and after_428["approvals"][0]["request_digest"]
        == decision["request_digest"]
        and after_428["approvals"][0]["operation_digest"]
        == decision["operation_digest"]
        and after_428["credential"] == before["credential"]
        and after_428["reviewReceipts"] == before["reviewReceipts"]
        and after_428["grants"] == before["grants"]
        and after_428["attempts"] == before["attempts"]
        and after_428["credentialIssuances"] == before["credentialIssuances"]
        and after_428["quotaReservations"] == before["quotaReservations"]
        and after_428["grantConsumptions"] == before["grantConsumptions"]
        and after_428["rateLimitCounters"] == before["rateLimitCounters"]
        and after_428["releaseEvents"] == before["releaseEvents"]
        and registry.observations() == registry_before,
        "npm contention preflight created release, quota, credential, or registry side effects",
    )
    _approve_npm_jit_request(
        operator_page=operator_page,
        reviewer_page=reviewer_page,
        browser_observations=browser_observations,
        public_url=public_url,
        route_id=NPM_CONTENTION_ROUTE_ID,
        operation="npm.publish",
        decision=decision,
        state_after_428=after_428,
        credential_version=credential_version,
        expected_body_sha256=body_sha256,
        expected_package_name=NPM_CONTENTION_PACKAGE_NAME,
        expected_package_version=NPM_CONTENTION_PACKAGE_VERSION,
    )
    approved_state = _jit_state_snapshot(
        NPM_CONTENTION_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    _require(
        len(approved_state["approvals"]) == 1
        and len(approved_state["grants"]) == 1
        and approved_state["grants"][0]["approval_request_id"] == approval_id
        and approved_state["grants"][0]["state"] == "active"
        and approved_state["grants"][0]["uses_remaining"] == 1
        and not approved_state["attempts"]
        and not approved_state["credentialIssuances"]
        and not approved_state["quotaReservations"]
        and not approved_state["grantConsumptions"]
        and not approved_state["rateLimitCounters"]
        and not approved_state["releaseEvents"]
        and registry.observations() == registry_before,
        "npm contention did not begin with exactly one preexisting unused grant",
    )

    registry.arm_contention_latch()
    try:
        contention = _send_two_connect_tls_requests_concurrently(
            gate,
            registry=registry,
            authority_host="127.0.0.1",
            authority_port=registry.port,
            request_bytes=immutable_request,
        )
    except BaseException:
        if registry.contention_latch_state()["armed"]:
            registry.finish_contention_latch()
        raise
    responses = contention["responses"]
    successes = [item for item in responses if item["status"] == 200]
    losers = [item for item in responses if item["status"] == 428]
    _require(
        len(successes) == 1
        and len(losers) == 1
        and successes[0]["json"] == expected_response
        and all(
            item["sentRequestSha256"] == request_bytes_sha256
            and item["sentRequestLength"] == len(immutable_request)
            and item["sentRequestObjectId"] == id(immutable_request)
            for item in responses
        )
        and contention["clients"][0]["localAddress"]
        != contention["clients"][1]["localAddress"],
        f"npm contention did not use two distinct clients with byte-identical requests: {contention}",
    )
    _require(
        contention["latch"]["winnerHeldWhileLoserReturned428"] is True
        and contention["latch"]["secondUpstreamRequestObserved"] is False
        and contention["latch"]["finalState"]
        == {"armed": True, "arrivals": 1, "released": True},
        f"npm contention was not deterministically overlapped at upstream: {contention['latch']}",
    )
    loser_decision = losers[0]["json"]
    _require(
        isinstance(loser_decision, dict)
        and loser_decision.get("action") == "jit_required"
        and loser_decision.get("allowed") is False
        and (loser_decision.get("payload") or {}).get("error")
        == "jit_grant_unavailable"
        and loser_decision.get("route_id") == NPM_CONTENTION_ROUTE_ID
        and loser_decision.get("request_digest") == decision["request_digest"]
        and loser_decision.get("operation_digest") == decision["operation_digest"]
        and loser_decision.get("approval_status") == "pending"
        and loser_decision.get("approval_created") is True
        and isinstance(loser_decision.get("approval_id"), str)
        and loser_decision.get("approval_id") != approval_id,
        f"npm contention loser did not fail closed on the exhausted grant: {losers[0]}",
    )
    loser_approval_id = loser_decision["approval_id"]

    after_contention = _jit_state_snapshot(
        NPM_CONTENTION_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    registry_after = registry.observations()
    attempts = [
        item
        for item in after_contention["attempts"]
        if item["approval_request_id"] == approval_id
    ]
    _require(len(attempts) == 1, "npm contention did not create one winning attempt")
    attempt = attempts[0]
    attempt_id = attempt["attempt_id"]
    issuances = [
        item
        for item in after_contention["credentialIssuances"]
        if item["attempt_id"] == attempt_id
    ]
    quotas = [
        item
        for item in after_contention["quotaReservations"]
        if item["attempt_id"] == attempt_id
    ]
    consumptions = [
        item
        for item in after_contention["grantConsumptions"]
        if item["attempt_id"] == attempt_id
    ]
    release_events = [
        item
        for item in after_contention["releaseEvents"]
        if item["attempt_id"] == attempt_id
    ]
    registry_mutations = [
        item
        for item in registry_after["events"]
        if item.get("clientKind") == "concurrent-direct-wire"
        and item.get("operation") == "npm.publish"
        and item.get("packageName") == NPM_CONTENTION_PACKAGE_NAME
    ]
    _require(
        len(after_contention["approvals"]) == 2
        and any(
            item["id"] == loser_approval_id and item["status"] == "pending"
            for item in after_contention["approvals"]
        )
        and len(after_contention["grants"]) == 1
        and after_contention["grants"][0]["approval_request_id"] == approval_id
        and after_contention["grants"][0]["state"] == "consumed"
        and after_contention["grants"][0]["uses_remaining"] == 0
        and len(after_contention["attempts"]) == 1
        and attempt["state"] == "committed"
        and attempt["completion_outcome"] == "forwarded"
        and attempt["request_digest"] == decision["request_digest"]
        and attempt["operation_digest"] == decision["operation_digest"]
        and len(after_contention["credentialIssuances"]) == 1
        and len(issuances) == 1
        and issuances[0]["approval_request_id"] == approval_id
        and issuances[0]["grant_id"] == after_contention["grants"][0]["id"]
        and len(after_contention["quotaReservations"]) == 1
        and len(quotas) == 1
        and quotas[0]["approval_request_id"] == approval_id
        and quotas[0]["grant_id"] == after_contention["grants"][0]["id"]
        and quotas[0]["max_count"] == 1
        and quotas[0]["count_after"] == 1
        and quotas[0]["reservation_state"] == "committed"
        and len(after_contention["grantConsumptions"]) == 1
        and len(consumptions) == 1
        and consumptions[0]["approval_request_id"] == approval_id
        and consumptions[0]["grant_id"] == after_contention["grants"][0]["id"]
        and consumptions[0]["uses_remaining_before"] == 1
        and consumptions[0]["uses_remaining_after"] == 0
        and len(after_contention["rateLimitCounters"]) == 1
        and after_contention["rateLimitCounters"][0]["max_count"] == 1
        and after_contention["rateLimitCounters"][0]["count"] == 1
        and len(release_events) == len(after_contention["releaseEvents"])
        and {
            item["event_type"] for item in release_events
        }
        == {
            "release_authorization.reserved",
            "release_authorization.dispatching",
            "release_authorization.committed",
        }
        and all(
            item["approval_request_id"] == approval_id
            and item["grant_id"] == after_contention["grants"][0]["id"]
            for item in release_events
        )
        and after_contention["credential"] == approved_state["credential"]
        and registry_after["counts"]["npm.publish"]
        == registry_before["counts"]["npm.publish"] + 1
        and registry_after["counts"]["rejected"]
        == registry_before["counts"]["rejected"]
        and len(registry_mutations) == 1
        and registry_mutations[0]["bodySha256"] == body_sha256
        and registry_mutations[0]["authorizationPresent"] is True
        and registry_mutations[0]["authorizationScheme"] == "Bearer"
        and registry_mutations[0]["npmSessionHeaders"] == [],
        "npm contention did not isolate issuance, grant, quota, dispatch, and registry mutation to one winner",
    )

    sequential_before = after_contention
    sequential_registry_before = registry_after
    sequential = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    sequential_decision = sequential["json"]
    sequential_after = _jit_state_snapshot(
        NPM_CONTENTION_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    _require(
        sequential["status"] == 428
        and isinstance(sequential_decision, dict)
        and sequential_decision.get("action") == "jit_required"
        and (sequential_decision.get("payload") or {}).get("error")
        == "jit_grant_unavailable"
        and sequential_decision.get("approval_id") == loser_approval_id
        and sequential_decision.get("approval_created") is False
        and sequential["sentRequestSha256"] == request_bytes_sha256
        and sequential_after == sequential_before
        and registry.observations() == sequential_registry_before,
        "post-contention sequential reuse was not separately denied without side effects",
    )
    return {
        "routeId": NPM_CONTENTION_ROUTE_ID,
        "approvalId": approval_id,
        "loserApprovalId": loser_approval_id,
        "requestBytesSha256": request_bytes_sha256,
        "requestBytesLength": len(immutable_request),
        "requestDigest": decision["request_digest"],
        "operationDigest": decision["operation_digest"],
        "clientConnections": contention["clients"],
        "concurrentStatuses": sorted(item["status"] for item in responses),
        "successfulForwards": 1,
        "registryMutations": 1,
        "credentialIssuances": 1,
        "grantConsumptions": 1,
        "quotaReservations": 1,
        "loserDispatches": 0,
        "winnerHeldUpstreamWhileLoserReturned428": True,
        "secondUpstreamRequestObserved": False,
        "sequentialReuse": {
            "status": sequential["status"],
            "approvalCreated": False,
            "sideEffectFree": True,
        },
        "scope": {
            "pythonReleaseAuthorityProcesses": 1,
            "rustGateProcesses": 1,
            "tcpConnections": 2,
            "metadataStore": "sqlite",
            "sharedStoreContentionProven": False,
            "distributedStoreContentionProven": False,
        },
    }


def _write_deterministic_npm_cli_tarball(work_dir: Path) -> tuple[Path, bytes]:
    package_json = json.dumps(
        {
            "name": NPM_PACKAGE_NAME,
            "version": NPM_PACKAGE_VERSION,
            "description": "Serverware installed npm compatibility fixture",
            "license": "UNLICENSED",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer,
        mode="w",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        directory = tarfile.TarInfo("package")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.uid = 0
        directory.gid = 0
        directory.uname = ""
        directory.gname = ""
        directory.mtime = 0
        archive.addfile(directory)

        manifest = tarfile.TarInfo("package/package.json")
        manifest.size = len(package_json)
        manifest.mode = 0o644
        manifest.uid = 0
        manifest.gid = 0
        manifest.uname = ""
        manifest.gname = ""
        manifest.mtime = 0
        archive.addfile(manifest, io.BytesIO(package_json))
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=gzip_buffer,
        mtime=0,
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    tarball = gzip_buffer.getvalue()
    path = work_dir / "serverware-installed-npm-fixture.tgz"
    path.write_bytes(tarball)
    path.chmod(0o600)
    return path, tarball


def _installed_npm_contract() -> dict[str, Any]:
    if _SERVERWARE_NPM_COMPANION_CLIENT is not None:
        return _SERVERWARE_NPM_COMPANION_CLIENT.contract()
    npm_command = shutil.which("npm")
    node_command = shutil.which("node")
    _require(npm_command is not None, "installed npm executable is unavailable")
    _require(node_command is not None, "installed Node.js executable is unavailable")
    npm_executable = Path(npm_command)
    node_executable = Path(node_command)
    _require(
        npm_executable.is_absolute() and node_executable.is_absolute(),
        "npm compatibility lane requires absolute npm and Node.js executables",
    )
    npm_entrypoint = npm_executable.resolve(strict=True)
    node_binary = node_executable.resolve(strict=True)
    _require(
        npm_entrypoint.name == "npm-cli.js",
        f"installed npm entrypoint is unsupported: {npm_entrypoint}",
    )
    npm_root = npm_entrypoint.parent.parent
    package_path = npm_root / "package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    version = package.get("version")
    _require(
        package.get("name") == "npm"
        and version == EXPECTED_NPM_VERSION,
        f"installed npm must be exactly {EXPECTED_NPM_VERSION}; found {version!r}",
    )
    return {
        "npmExecutable": npm_executable,
        "npmEntrypoint": npm_entrypoint,
        "npmRoot": npm_root,
        "npmPackageManifest": package_path,
        "npmVersion": version,
        "nodeExecutable": node_binary,
        "npmExecutableSha256": _sha256_path(npm_executable),
        "npmEntrypointSha256": _sha256_path(npm_entrypoint),
        "npmPackageSha256": _sha256_path(package_path),
        "nodeBinarySha256": _sha256_path(node_binary),
    }


def _parse_raw_http_request(raw: bytes, *, label: str) -> dict[str, Any]:
    _require(
        0 < len(raw) <= 16 * 1024 * 1024 + 64 * 1024,
        f"{label} exceeded its total byte bound",
    )
    head, separator, body = raw.partition(b"\r\n\r\n")
    _require(bool(separator), f"{label} omitted its header terminator")
    lines = head.split(b"\r\n")
    request_fields = lines[0].split(b" ")
    _require(
        len(request_fields) == 3
        and request_fields[0]
        and request_fields[1].startswith(b"/")
        and request_fields[2] == b"HTTP/1.1",
        f"{label} request line was not exact origin-form HTTP/1.1",
    )
    ordered_headers: list[dict[str, str]] = []
    normalized_headers: dict[str, str] = {}
    for index, line in enumerate(lines[1:]):
        name, delimiter, value = line.partition(b":")
        _require(
            bool(delimiter)
            and HTTP_FIELD_NAME_RE.fullmatch(name.decode("ascii")) is not None
            and b"\r" not in value
            and b"\n" not in value
            and b"\x00" not in value,
            f"{label} physical header {index} was malformed",
        )
        normalized_name = name.decode("ascii").lower()
        normalized_value = value.decode("latin-1").strip(" \t")
        _require(
            normalized_name not in normalized_headers,
            f"{label} duplicated physical header {normalized_name!r}",
        )
        normalized_headers[normalized_name] = normalized_value
        ordered_headers.append(
            {
                "name": name.decode("ascii"),
                "value": normalized_value,
            }
        )
    _require(
        "transfer-encoding" not in normalized_headers
        and "content-encoding" not in normalized_headers,
        f"{label} used unsupported transfer or content coding",
    )
    content_length = normalized_headers.get("content-length")
    expected_body_length = int(content_length) if content_length is not None else 0
    _require(
        content_length is None
        or (
            re.fullmatch(r"(?:0|[1-9][0-9]*)", content_length) is not None
            and expected_body_length <= 16 * 1024 * 1024
        ),
        f"{label} Content-Length was invalid",
    )
    _require(
        len(body) == expected_body_length,
        f"{label} body did not match its exact Content-Length",
    )
    return {
        "method": request_fields[0].decode("ascii"),
        "target": request_fields[1].decode("ascii"),
        "httpVersion": "HTTP/1.1",
        "orderedPhysicalHeaders": ordered_headers,
        "headers": normalized_headers,
        "body": body,
        "rawSha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "rawLength": len(raw),
    }


def _read_raw_http_request(
    stream: ssl.SSLSocket,
    *,
    label: str,
) -> bytes:
    deadline = time.monotonic() + _journey_timeout_seconds(label=label, cap=15)
    buffered = bytearray()
    header_end = -1
    expected_total: int | None = None
    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0, f"{label} exceeded its receive deadline")
        stream.settimeout(remaining)
        chunk = stream.recv(64 * 1024)
        _require(bool(chunk), f"{label} closed before the request completed")
        buffered.extend(chunk)
        _require(
            len(buffered) <= 16 * 1024 * 1024 + 64 * 1024,
            f"{label} exceeded its total byte bound",
        )
        if header_end < 0:
            header_end = buffered.find(b"\r\n\r\n")
            if header_end >= 0:
                head = bytes(buffered[:header_end])
                lengths = []
                expect_continue = False
                for line in head.split(b"\r\n")[1:]:
                    name, delimiter, value = line.partition(b":")
                    _require(bool(delimiter), f"{label} contained a malformed header")
                    normalized_name = name.decode("ascii").lower()
                    normalized_value = value.decode("latin-1").strip(" \t")
                    if normalized_name == "content-length":
                        lengths.append(normalized_value)
                    if normalized_name == "expect":
                        expect_continue = normalized_value.lower() == "100-continue"
                _require(
                    len(lengths) <= 1
                    and (
                        not lengths
                        or re.fullmatch(r"(?:0|[1-9][0-9]*)", lengths[0]) is not None
                    ),
                    f"{label} Content-Length was duplicated or invalid",
                )
                body_length = int(lengths[0]) if lengths else 0
                _require(
                    body_length <= 16 * 1024 * 1024,
                    f"{label} body exceeded 16 MiB",
                )
                expected_total = header_end + 4 + body_length
                if expect_continue and len(buffered) < expected_total:
                    stream.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        if expected_total is not None and len(buffered) >= expected_total:
            _require(
                len(buffered) == expected_total,
                f"{label} included pipelined bytes after its bounded request",
            )
            raw = bytes(buffered)
            _parse_raw_http_request(raw, label=label)
            return raw


class _NpmCliProxyBridge:
    def __init__(
        self,
        *,
        gate: _DecisionGateProcess,
        registry: _NpmRegistryFixture,
        expected_requests: int,
    ) -> None:
        self._gate = gate
        self._registry = registry
        self._expected_requests = expected_requests
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.5)
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._condition = threading.Condition()
        self._captures: list[bytes] = []
        self._responses: list[dict[str, Any]] = []
        self._error: BaseException | None = None
        self._active_socket: socket.socket | ssl.SSLSocket | None = None
        self._thread = threading.Thread(
            target=self._serve,
            name="serverware-npm-cli-public-proxy-bridge",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    @staticmethod
    def _read_connect_request(connection: socket.socket) -> bytes:
        deadline = time.monotonic() + _journey_timeout_seconds(
            label="npm public CLI CONNECT",
            cap=10,
        )
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "npm public CLI CONNECT exceeded its deadline")
            connection.settimeout(remaining)
            chunk = connection.recv(4096)
            _require(bool(chunk), "npm public CLI closed before CONNECT completed")
            raw.extend(chunk)
            _require(
                len(raw) <= 64 * 1024,
                "npm public CLI CONNECT headers exceeded 64 KiB",
            )
        head, delimiter, remainder = bytes(raw).partition(b"\r\n\r\n")
        _require(
            bool(delimiter) and not remainder,
            "npm public CLI sent bytes before CONNECT authorization",
        )
        return head

    def _handle(self, connection: socket.socket) -> None:
        connect_head = self._read_connect_request(connection)
        connect_lines = connect_head.split(b"\r\n")
        expected_authority = f"127.0.0.1:{self._registry.port}".encode("ascii")
        _require(
            connect_lines[0] == b"CONNECT " + expected_authority + b" HTTP/1.1",
            "npm public CLI CONNECT escaped the exact registry authority",
        )
        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(
            certfile=str(self._registry.server_cert_path),
            keyfile=str(self._registry.server_key_path),
        )
        tls = tls_context.wrap_socket(connection, server_side=True)
        self._active_socket = tls
        raw_request = _read_raw_http_request(
            tls,
            label="npm public CLI raw HTTPS request",
        )
        parsed_request = _parse_raw_http_request(
            raw_request,
            label="npm public CLI raw HTTPS request",
        )
        _require(
            parsed_request["headers"].get("host")
            == f"127.0.0.1:{self._registry.port}",
            "npm public CLI raw request escaped the exact registry Host",
        )
        client = _PreparedConnectTlsClient(
            self._gate,
            authority_host="127.0.0.1",
            authority_port=self._registry.port,
        )
        try:
            result = client.send(raw_request, include_raw_response=True)
            raw_response = result.pop("_rawResponseBytes")
        finally:
            client.close()
        _require(
            isinstance(raw_response, bytes) and bool(raw_response),
            "Rust gate omitted the npm public CLI response bytes",
        )
        tls.sendall(raw_response)
        with self._condition:
            self._captures.append(raw_request)
            self._responses.append(
                {
                    "status": result["status"],
                    "responseSha256": (
                        "sha256:" + hashlib.sha256(raw_response).hexdigest()
                    ),
                }
            )
            self._condition.notify_all()

    def _serve(self) -> None:
        try:
            while (
                not self._stop.is_set()
                and len(self._captures) < self._expected_requests
            ):
                try:
                    connection, _ = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self._active_socket = connection
                try:
                    self._handle(connection)
                finally:
                    try:
                        connection.close()
                    finally:
                        self._active_socket = None
        except BaseException as exc:
            with self._condition:
                self._error = exc
                self._condition.notify_all()

    def capture(self, index: int) -> bytes:
        deadline = time.monotonic() + _journey_timeout_seconds(
            label=f"npm public CLI capture {index + 1}",
            cap=15,
        )
        with self._condition:
            while len(self._captures) <= index and self._error is None:
                remaining = deadline - time.monotonic()
                _require(
                    remaining > 0,
                    f"npm public CLI capture {index + 1} was not observed",
                )
                self._condition.wait(timeout=remaining)
            if self._error is not None:
                raise AssertionError("npm public CLI proxy bridge failed") from self._error
            return bytes(self._captures[index])

    def observations(self) -> dict[str, Any]:
        with self._condition:
            return {
                "capturedRequests": len(self._captures),
                "rawRequestSha256": [
                    "sha256:" + hashlib.sha256(item).hexdigest()
                    for item in self._captures
                ],
                "responses": list(self._responses),
                "requestBytesMutated": False,
                "connectIdentityAddedByBridge": True,
            }

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        active = self._active_socket
        if active is not None:
            try:
                active.close()
            except OSError:
                pass
        if self._thread.ident is not None:
            self._thread.join(timeout=10)
            _require(
                not self._thread.is_alive(),
                "npm public CLI proxy bridge did not stop within its bound",
            )
        if self._error is not None:
            raise AssertionError("npm public CLI proxy bridge failed") from self._error


def _stable_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _run_installed_npm_publish(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    if _SERVERWARE_NPM_COMPANION_CLIENT is not None:
        return _SERVERWARE_NPM_COMPANION_CLIENT.run_publish(
            command,
            cwd=cwd,
            environment=environment,
        )
    returncode, stdout, stderr = _run_bounded_process(
        command,
        cwd=cwd,
        environment=environment,
        label="installed npm publish",
        timeout_seconds=30,
        stdout_limit=128 * 1024,
        stderr_limit=128 * 1024,
    )
    output_bytes = stdout + b"\n" + stderr
    for secret in (
        NPM_FIXTURE_BEARER,
        ADMIN_TOKEN,
        CREDENTIAL_LEASE_TOKEN,
        AUDIT_TOKEN,
        GRANT_CONSUME_TOKEN,
        RATE_LIMIT_CONSUME_TOKEN,
        RELEASE_AUTHORIZATION_TOKEN,
        MANAGEMENT_TOKEN,
    ):
        _require(
            secret.encode("utf-8") not in output_bytes,
            "installed npm output exposed Serverware credential material",
        )
    output_text = output_bytes.decode("utf-8", errors="replace")
    return {
        "exitCode": returncode,
        "outputSha256": "sha256:" + hashlib.sha256(output_bytes).hexdigest(),
        "reported428": re.search(
            r"(?i)(?:\bE428\b|\b428\b[^\r\n]*precondition required\b)",
            output_text,
        )
        is not None,
    }


def _assert_installed_npm_contract_unchanged(contract: dict[str, Any]) -> None:
    if _SERVERWARE_NPM_COMPANION_CLIENT is not None:
        _SERVERWARE_NPM_COMPANION_CLIENT.assert_contract(contract)
        return
    artifacts = {
        "npm executable": (
            contract["npmExecutable"],
            contract["npmExecutableSha256"],
        ),
        "npm entrypoint": (
            contract["npmEntrypoint"],
            contract["npmEntrypointSha256"],
        ),
        "npm package manifest": (
            contract["npmPackageManifest"],
            contract["npmPackageSha256"],
        ),
        "Node.js binary": (
            contract["nodeExecutable"],
            contract["nodeBinarySha256"],
        ),
    }
    _require(
        Path(contract["npmExecutable"]).resolve(strict=True)
        == Path(contract["npmEntrypoint"]),
        "installed npm launcher target changed after evidence capture",
    )
    for label, (path, expected_digest) in artifacts.items():
        _require(
            _sha256_path(Path(path)) == expected_digest,
            f"installed {label} changed after evidence capture",
        )


def _approval_decision_from_store(approval: dict[str, Any]) -> dict[str, Any]:
    approval_id = approval.get("id")
    _require(isinstance(approval_id, str), "stored npm approval omitted its ID")
    return {
        "approval_id": approval_id,
        "approval_url": f"/approvals/{approval_id}",
        "policy_hash": approval.get("policy_hash"),
        "request_digest": approval.get("request_digest"),
        "operation_digest": approval.get("operation_digest"),
    }


def _assert_canonical_excludes_npm_session(
    canonical: dict[str, Any],
) -> dict[str, Any]:
    closed = json.loads(json.dumps(canonical))
    request = closed.get("request")
    _require(isinstance(request, dict), "npm approval canonical request is invalid")
    headers = request.get("headers")
    _require(isinstance(headers, dict), "npm approval canonical headers are invalid")
    _require(
        "npm-session" not in headers
        and all(str(name).lower() != "npm-session" for name in headers),
        "discarded npm-session remained in the canonical request",
    )
    return closed


def _derive_npm_v2_canonical_from_raw_wire(
    raw_request: bytes,
    *,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from serverware.policy_bundle import provider_request_profile

    parsed = _parse_raw_http_request(
        raw_request,
        label="independent npm public CLI wire proof",
    )
    profile = provider_request_profile("npm.registry")
    allowed_headers = set(profile.get("allowedHeaders") or [])
    _require(
        profile.get("discardHeaders") == ["npm-session"]
        and profile.get("allowedQueryKeys") == []
        and profile.get("allowedMediaTypes") == ["application/json"]
        and profile.get("maxBodyBytes") == 16 * 1024 * 1024
        and allowed_headers
        == {
            "accept",
            "accept-encoding",
            "content-type",
            "npm-auth-type",
            "npm-command",
            "npm-in-ci",
            "npm-otp",
            "npm-scope",
            "user-agent",
        },
        "persisted npm request profile differs from the independent v2 proof contract",
    )
    headers = dict(parsed["headers"])
    npm_session = headers.pop("npm-session", None)
    _require(
        isinstance(npm_session, str)
        and re.fullmatch(r"[0-9a-f]{16}", npm_session) is not None,
        "captured npm public CLI request omitted its exact discardable npm-session",
    )
    _require(
        not {
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-serverware-agent",
        }.intersection(headers)
        and not any(name.startswith("x-serverware-") for name in headers),
        "captured npm public CLI request carried agent-supplied credential material",
    )

    target = urlsplit(parsed["target"])
    _require(
        parsed["method"] == "PUT"
        and target.scheme == ""
        and target.netloc == ""
        and target.fragment == ""
        and target.path == f"/{NPM_PACKAGE_PATH}",
        "captured npm public CLI request escaped the exact fixture publish target",
    )
    query = sorted(
        [
            [name, value]
            for name, value in parse_qsl(
                target.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        ]
    )
    _require(not query, "captured npm public CLI publish supplied an unexpected query")

    nominated = {
        name.strip().lower()
        for name in headers.get("connection", "").split(",")
        if name.strip()
    }
    _require(
        not nominated.intersection(headers),
        "captured npm public CLI Connection header nominated a supplied header",
    )
    non_forwardable = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "authorization",
        "cookie",
        "content-length",
        "host",
    }
    forwarded_headers = {
        name: value
        for name, value in headers.items()
        if name not in non_forwardable
        and name not in nominated
        and not name.startswith("x-serverware-")
    }
    unexpected_forwarded = set(forwarded_headers) - allowed_headers
    _require(
        not unexpected_forwarded,
        "captured npm public CLI request contained non-profile forwarding headers: "
        + ", ".join(sorted(unexpected_forwarded)),
    )
    authority = f"127.0.0.1:{registry.port}"
    _require(
        headers.get("host") == authority,
        "captured npm public CLI Host did not match the CONNECT registry authority",
    )
    forwarded_headers["host"] = authority
    body = parsed["body"]
    if body:
        forwarded_headers["content-length"] = str(len(body))
    forwarded_headers = dict(sorted(forwarded_headers.items()))

    document = _strict_json_object(
        body,
        label="captured npm public CLI publish body",
    )
    versions = document.get("versions")
    dist_tags = document.get("dist-tags")
    attachments = document.get("_attachments")
    _require(
        document.get("name") == NPM_PACKAGE_NAME
        and isinstance(versions, dict)
        and set(versions) == {NPM_PACKAGE_VERSION}
        and isinstance(dist_tags, dict)
        and dist_tags.get("latest") == NPM_PACKAGE_VERSION
        and isinstance(attachments, dict)
        and len(attachments) == 1,
        "captured npm public CLI publish document escaped its package binding",
    )
    version_document = versions[NPM_PACKAGE_VERSION]
    _require(
        isinstance(version_document, dict)
        and version_document.get("version") == NPM_PACKAGE_VERSION,
        "captured npm public CLI version document escaped its version binding",
    )
    attachment_name, attachment = next(iter(attachments.items()))
    _require(
        isinstance(attachment_name, str)
        and isinstance(attachment, dict)
        and isinstance(attachment.get("data"), str),
        "captured npm public CLI attachment was malformed",
    )
    try:
        tarball = base64.b64decode(attachment["data"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AssertionError(
            "captured npm public CLI attachment was not canonical base64"
        ) from exc
    _require(
        bool(tarball)
        and base64.b64encode(tarball).decode("ascii") == attachment["data"]
        and (
            "length" not in attachment
            or (
                type(attachment["length"]) is int
                and attachment["length"] == len(tarball)
            )
        ),
        "captured npm public CLI attachment bytes or length were not canonical",
    )
    integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball).digest()
    ).decode("ascii")
    declared_integrities = []
    if "tarball_integrity" in document:
        declared_integrities.append(document["tarball_integrity"])
    version_dist = version_document.get("dist")
    if isinstance(version_dist, dict) and "integrity" in version_dist:
        declared_integrities.append(version_dist["integrity"])
    if "_integrity" in version_document:
        declared_integrities.append(version_document["_integrity"])
    _require(
        all(value == integrity for value in declared_integrities),
        "captured npm public CLI publish declared a contradictory tarball integrity",
    )
    operation = {
        "operation": "npm.publish",
        "packageName": NPM_PACKAGE_NAME,
        "packageVersion": NPM_PACKAGE_VERSION,
        "tarballIntegrity": integrity,
        "attachmentName": attachment_name,
        "attachmentBytes": str(len(tarball)),
    }
    canonical = {
        "v": 2,
        "principal": "agent:demo",
        "client_ip": "127.0.0.1",
        "route_id": NPM_JIT_ROUTE_ID,
        "credential_ref": NPM_CREDENTIAL_ID,
        "credential_version": str(credential_version),
        "policy_hash": policy_hash,
        "request": {
            "method": parsed["method"],
            "scheme": "https",
            "authority": authority,
            "path": target.path or "/",
            "query": query,
            "headers": forwarded_headers,
            "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "discard_headers": ["npm-session"],
        },
        "operation": operation,
    }
    evidence = {
        "rawWireSha256": parsed["rawSha256"],
        "rawWireBytes": parsed["rawLength"],
        "physicalHeaderCount": len(parsed["orderedPhysicalHeaders"]),
        "npmSession": npm_session,
        "npmSessionValueDisclosed": False,
        "canonicalRequestSha256": _stable_json_sha256(canonical),
        "canonicalOperationSha256": _canonical_operation_sha256(canonical),
    }
    return canonical, evidence


def _canonical_operation_sha256(canonical: dict[str, Any]) -> str:
    return _stable_json_sha256(
        {
            "principal": canonical["principal"],
            "route_id": canonical["route_id"],
            "credential_ref": canonical["credential_ref"],
            "credential_version": canonical["credential_version"],
            "policy_hash": canonical["policy_hash"],
            "request": canonical["request"],
            "operation": canonical["operation"],
        }
    )


def _reset_owned_child_directory(root: Path, directory: Path) -> None:
    _require(
        directory.parent == root
        and directory.name not in {"", ".", ".."}
        and "/" not in directory.name
        and "\x00" not in directory.name,
        "npm reset directory escaped its owned root",
    )
    root_fd = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW,
    )

    def clear(current: int) -> None:
        entries = sorted(
            (entry.name for entry in os.scandir(current)),
            key=lambda value: value.encode("utf-8"),
        )
        for name in entries:
            _require(
                name not in {"", ".", ".."}
                and "/" not in name
                and "\x00" not in name,
                "npm reset directory contains an unsafe name",
            )
            metadata = os.stat(name, dir_fd=current, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    opened = os.fstat(child)
                    _require(
                        (opened.st_dev, opened.st_ino)
                        == (metadata.st_dev, metadata.st_ino),
                        "npm reset directory changed while opening",
                    )
                    clear(child)
                finally:
                    os.close(child)
                current_metadata = os.stat(
                    name,
                    dir_fd=current,
                    follow_symlinks=False,
                )
                _require(
                    stat.S_ISDIR(current_metadata.st_mode)
                    and (current_metadata.st_dev, current_metadata.st_ino)
                    == (metadata.st_dev, metadata.st_ino),
                    "npm reset directory was replaced",
                )
                os.rmdir(name, dir_fd=current)
            else:
                os.unlink(name, dir_fd=current)

    child_fd = -1
    try:
        metadata = os.stat(
            directory.name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and not stat.S_IMODE(metadata.st_mode) & 0o022,
            "npm reset target is not an owned private directory",
        )
        child_fd = os.open(
            directory.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        opened = os.fstat(child_fd)
        _require(
            (opened.st_dev, opened.st_ino)
            == (metadata.st_dev, metadata.st_ino),
            "npm reset target changed while opening",
        )
        clear(child_fd)
        os.close(child_fd)
        child_fd = -1
        current = os.stat(
            directory.name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _require(
            stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino)
            == (metadata.st_dev, metadata.st_ino),
            "npm reset target was replaced before recreation",
        )
        os.rmdir(directory.name, dir_fd=root_fd)
        os.mkdir(directory.name, mode=0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(root_fd)


def _exercise_installed_npm_cli_with_bridge(
    *,
    gate: _DecisionGateProcess,
    bridge: _NpmCliProxyBridge,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
    work_dir: Path,
) -> dict[str, Any]:
    from serverware import db

    contract = _installed_npm_contract()
    cli_dir = work_dir / "installed-npm-cli"
    cli_dir.mkdir(mode=0o700, parents=True)
    home_dir = cli_dir / "home"
    cache_dir = cli_dir / "cache"
    tmp_dir = cli_dir / "tmp"
    for directory in (home_dir, cache_dir, tmp_dir):
        directory.mkdir(mode=0o700)
    empty_config = cli_dir / "empty.npmrc"
    empty_config.write_text("", encoding="ascii")
    empty_config.chmod(0o600)
    tarball_path, tarball = _write_deterministic_npm_cli_tarball(cli_dir)
    registry.register_cli_publish_tarball(tarball)

    before = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_before = registry.observations()
    child_environment = {
        "PATH": os.pathsep.join(
            [
                str(Path(contract["nodeExecutable"]).parent),
                "/usr/bin",
                "/bin",
            ]
        ),
        "HOME": str(home_dir),
        "TMPDIR": str(tmp_dir),
        "LANG": "C",
        "LC_ALL": "C",
        "CI": "true",
        "NO_PROXY": "",
        "no_proxy": "",
        "npm_config_userconfig": str(empty_config),
        "npm_config_globalconfig": str(empty_config),
        "npm_config_cache": str(cache_dir),
        "npm_config_tmp": str(tmp_dir),
        "npm_config_update_notifier": "false",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
    }
    _require(
        set(child_environment)
        == {
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "CI",
            "NO_PROXY",
            "no_proxy",
            "npm_config_userconfig",
            "npm_config_globalconfig",
            "npm_config_cache",
            "npm_config_tmp",
            "npm_config_update_notifier",
            "npm_config_audit",
            "npm_config_fund",
        }
        and child_environment["NO_PROXY"] == ""
        and child_environment["no_proxy"] == ""
        and not any(
            marker in name.lower()
            for name in child_environment
            for marker in ("token", "password", "_auth")
        ),
        "installed npm environment was not the exact credential-free sandbox",
    )
    command = [
        str(contract["npmExecutable"]),
        "publish",
        str(tarball_path),
        f"--registry=https://127.0.0.1:{registry.port}/",
        f"--https-proxy=http://127.0.0.1:{bridge.port}",
        f"--cafile={registry.ca_cert_path}",
        "--strict-ssl=true",
        "--fetch-retries=0",
        "--ignore-scripts=true",
        "--tag=latest",
        "--access=public",
        "--json",
        "--loglevel=error",
        "--progress=false",
    ]
    command_is_bound = (
        _SERVERWARE_NPM_COMPANION_CLIENT.validate_command(
            command,
            contract=contract,
        )
        if _SERVERWARE_NPM_COMPANION_CLIENT is not None
        else (
            Path(command[0]) == contract["npmExecutable"]
            and Path(command[0]).resolve(strict=True)
            == contract["npmEntrypoint"]
        )
    )
    _require(
        Path(command[0]).is_absolute()
        and command_is_bound
        and all(
            secret not in argument
            for argument in command
            for secret in (
                NPM_FIXTURE_BEARER,
                ADMIN_TOKEN,
                CREDENTIAL_LEASE_TOKEN,
                AUDIT_TOKEN,
                GRANT_CONSUME_TOKEN,
                RATE_LIMIT_CONSUME_TOKEN,
                RELEASE_AUTHORIZATION_TOKEN,
                MANAGEMENT_TOKEN,
            )
        ),
        "installed npm command was not absolute and credential-free",
    )
    command_sha256 = _stable_json_sha256(command)
    environment_sha256 = _stable_json_sha256(child_environment)
    empty_config_sha256 = _sha256_path(empty_config)
    package_tarball_sha256 = (
        "sha256:" + hashlib.sha256(tarball).hexdigest()
    )

    def assert_cli_inputs_unchanged() -> None:
        _assert_installed_npm_contract_unchanged(contract)
        _require(
            _sha256_path(empty_config) == empty_config_sha256
            and _sha256_path(tarball_path) == package_tarball_sha256,
            "installed npm bounded inputs changed between capture and execution",
        )

    assert_cli_inputs_unchanged()
    first_process = _run_installed_npm_publish(
        command,
        cwd=cli_dir,
        environment=child_environment,
    )
    first_raw_request = bridge.capture(0)
    first_derived_canonical, first_wire_evidence = (
        _derive_npm_v2_canonical_from_raw_wire(
            first_raw_request,
            registry=registry,
            policy_hash=policy_hash,
            credential_version=credential_version,
        )
    )
    after_first = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    first_new_approvals = [
        item
        for item in after_first["approvals"]
        if item["id"] not in {prior["id"] for prior in before["approvals"]}
    ]
    _require(
        first_process["exitCode"] != 0
        and first_process["reported428"] is True
        and len(first_new_approvals) == 1
        and first_new_approvals[0]["status"] == "pending"
        and first_new_approvals[0]["principal_id"] == "agent:demo"
        and first_new_approvals[0]["credential_id"] == NPM_CREDENTIAL_ID
        and first_new_approvals[0]["credential_version"] == credential_version
        and first_new_approvals[0]["policy_hash"] == policy_hash
        and after_first["credential"] == before["credential"]
        and after_first["reviewReceipts"] == before["reviewReceipts"]
        and after_first["grants"] == before["grants"]
        and after_first["attempts"] == before["attempts"]
        and after_first["credentialIssuances"] == before["credentialIssuances"]
        and after_first["quotaReservations"] == before["quotaReservations"]
        and after_first["grantConsumptions"] == before["grantConsumptions"]
        and after_first["rateLimitCounters"] == before["rateLimitCounters"]
        and after_first["releaseEvents"] == before["releaseEvents"]
        and registry.observations() == registry_before,
        "first ordinary npm publish did not exit on one side-effect-free Rust 428",
    )
    first_approval_row = first_new_approvals[0]
    approval_id = first_approval_row["id"]
    first_approval = db.get_approval_request(approval_id)
    _require(
        isinstance(first_approval, dict)
        and isinstance(first_approval.get("canonical_request"), dict),
        "first installed npm approval omitted its authoritative canonical request",
    )
    first_canonical = first_approval["canonical_request"]
    first_canonical = _assert_canonical_excludes_npm_session(first_canonical)
    first_raw_wire_sha256 = first_wire_evidence["rawWireSha256"]
    first_canonical_sha256 = first_wire_evidence["canonicalRequestSha256"]
    first_operation_sha256 = first_wire_evidence["canonicalOperationSha256"]
    first_body_sha256 = (
        (first_derived_canonical.get("request") or {}).get("body_sha256")
    )
    _require(
        first_derived_canonical == first_canonical
        and first_approval_row["request_digest"] == first_canonical_sha256
        and first_approval_row["operation_digest"] == first_operation_sha256
        and (first_canonical.get("request") or {}).get("method") == "PUT"
        and (first_canonical.get("request") or {}).get("authority")
        == f"127.0.0.1:{registry.port}"
        and (first_canonical.get("request") or {}).get("path")
        == f"/{NPM_PACKAGE_PATH}"
        and isinstance(first_body_sha256, str)
        and first_body_sha256.startswith("sha256:"),
        "first installed npm approval escaped the exact fixture publish request",
    )
    approval = _approve_npm_jit_request(
        operator_page=operator_page,
        reviewer_page=reviewer_page,
        browser_observations=browser_observations,
        public_url=public_url,
        route_id=NPM_JIT_ROUTE_ID,
        operation="npm.publish",
        decision=_approval_decision_from_store(first_approval),
        state_after_428=after_first,
        credential_version=credential_version,
        expected_body_sha256=first_body_sha256,
        expected_package_name=NPM_PACKAGE_NAME,
        expected_package_version=NPM_PACKAGE_VERSION,
    )
    approved_state = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    cli_grants = [
        item
        for item in approved_state["grants"]
        if item["approval_request_id"] == approval_id
    ]
    _require(
        len(cli_grants) == 1
        and cli_grants[0]["state"] == "active"
        and cli_grants[0]["uses_remaining"] == 1
        and approved_state["attempts"] == before["attempts"]
        and approved_state["credentialIssuances"] == before["credentialIssuances"]
        and approved_state["grantConsumptions"] == before["grantConsumptions"]
        and registry.observations() == registry_before,
        "installed npm approval did not create exactly one unused grant",
    )

    for directory in (home_dir, cache_dir, tmp_dir):
        _reset_owned_child_directory(cli_dir, directory)
    assert_cli_inputs_unchanged()
    second_process = _run_installed_npm_publish(
        command,
        cwd=cli_dir,
        environment=child_environment,
    )
    second_raw_request = bridge.capture(1)
    second_derived_canonical, second_wire_evidence = (
        _derive_npm_v2_canonical_from_raw_wire(
            second_raw_request,
            registry=registry,
            policy_hash=policy_hash,
            credential_version=credential_version,
        )
    )
    assert_cli_inputs_unchanged()
    after_second = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_after_second = registry.observations()
    second_new_approvals = [
        item
        for item in after_second["approvals"]
        if item["id"] not in {prior["id"] for prior in approved_state["approvals"]}
    ]
    prior_attempt_ids = {
        item["attempt_id"] for item in approved_state["attempts"]
    }
    new_attempts = [
        item
        for item in after_second["attempts"]
        if item["attempt_id"] not in prior_attempt_ids
    ]
    _require(
        len(new_attempts) == 1,
        "successful installed npm retry did not create one release attempt",
    )
    successful_attempt = new_attempts[0]
    successful_attempt_id = successful_attempt["attempt_id"]
    new_issuances = [
        item
        for item in after_second["credentialIssuances"]
        if item["attempt_id"] == successful_attempt_id
    ]
    new_consumptions = [
        item
        for item in after_second["grantConsumptions"]
        if item["attempt_id"] == successful_attempt_id
    ]
    successful_grants = [
        item
        for item in after_second["grants"]
        if item["approval_request_id"] == approval_id
    ]
    cli_registry_mutations = [
        item
        for item in registry_after_second["events"]
        if item.get("clientKind") == "installed-npm-cli"
        and item.get("operation") == "npm.publish"
    ]
    final_approval = db.get_approval_request(approval_id)
    final_canonical = (
        _assert_canonical_excludes_npm_session(
            final_approval.get("canonical_request")
            if isinstance(final_approval, dict)
            else {}
        )
    )
    second_raw_wire_sha256 = second_wire_evidence["rawWireSha256"]
    second_canonical_sha256 = second_wire_evidence["canonicalRequestSha256"]
    second_operation_sha256 = second_wire_evidence["canonicalOperationSha256"]
    for label, digest in (
        ("first request", first_approval_row["request_digest"]),
        ("second request", successful_attempt["request_digest"]),
        ("first operation", first_approval_row["operation_digest"]),
        ("second operation", successful_attempt["operation_digest"]),
        ("first canonical", first_canonical_sha256),
        ("second canonical", second_canonical_sha256),
        ("first raw wire", first_raw_wire_sha256),
        ("second raw wire", second_raw_wire_sha256),
    ):
        _require(
            SHA256_RE.fullmatch(str(digest)) is not None,
            f"{label} digest was not canonical lowercase sha256",
        )
    _require(
        second_process["exitCode"] == 0
        and second_process["reported428"] is False
        and not second_new_approvals
        and len(after_second["approvals"]) == len(approved_state["approvals"])
        and after_second["credential"] == approved_state["credential"]
        and after_second["reviewReceipts"] == approved_state["reviewReceipts"]
        and len(successful_grants) == 1
        and successful_grants[0]["state"] == "consumed"
        and successful_grants[0]["uses_remaining"] == 0
        and successful_grants[0]["id"] == cli_grants[0]["id"]
        and len(after_second["attempts"])
        == len(approved_state["attempts"]) + 1
        and successful_attempt["state"] == "committed"
        and successful_attempt["completion_outcome"] == "forwarded"
        and successful_attempt["approval_request_id"] == approval_id
        and successful_attempt["request_digest"]
        == first_approval_row["request_digest"]
        and successful_attempt["operation_digest"]
        == first_approval_row["operation_digest"]
        and first_approval_row["request_digest"] == first_canonical_sha256
        and successful_attempt["request_digest"] == second_canonical_sha256
        and first_approval_row["operation_digest"] == first_operation_sha256
        and successful_attempt["operation_digest"] == second_operation_sha256
        and first_approval.get("request_digest")
        == first_approval_row["request_digest"]
        and first_approval.get("operation_digest")
        == first_approval_row["operation_digest"]
        and len(after_second["credentialIssuances"])
        == len(approved_state["credentialIssuances"]) + 1
        and len(new_issuances) == 1
        and new_issuances[0]["approval_request_id"] == approval_id
        and new_issuances[0]["grant_id"] == successful_grants[0]["id"]
        and SHA256_RE.fullmatch(new_issuances[0]["binding_digest"]) is not None
        and SHA256_RE.fullmatch(new_issuances[0]["request_binding_sha256"])
        is not None
        and after_second["quotaReservations"]
        == approved_state["quotaReservations"]
        and len(after_second["grantConsumptions"])
        == len(approved_state["grantConsumptions"]) + 1
        and len(new_consumptions) == 1
        and new_consumptions[0]["approval_request_id"] == approval_id
        and new_consumptions[0]["grant_id"] == successful_grants[0]["id"]
        and new_consumptions[0]["uses_remaining_before"] == 1
        and new_consumptions[0]["uses_remaining_after"] == 0
        and after_second["rateLimitCounters"]
        == approved_state["rateLimitCounters"]
        and after_second["releaseEventCount"]
        == approved_state["releaseEventCount"] + 3
        and registry_after_second["counts"]["npm.publish"]
        == registry_before["counts"]["npm.publish"] + 1
        and registry_after_second["counts"]["rejected"]
        == registry_before["counts"]["rejected"]
        and len(cli_registry_mutations) == 1
        and cli_registry_mutations[0]["npmSessionHeaders"] == []
        and cli_registry_mutations[0]["authorizationPresent"] is True
        and cli_registry_mutations[0]["authorizationScheme"] == "Bearer"
        and first_wire_evidence["npmSession"]
        != second_wire_evidence["npmSession"]
        and first_raw_wire_sha256 != second_raw_wire_sha256
        and first_derived_canonical == first_canonical
        and second_derived_canonical == final_canonical
        and second_derived_canonical == first_derived_canonical
        and second_canonical_sha256 == first_canonical_sha256
        and approval["reviewBodySha256"] == first_body_sha256,
        "approved second installed npm process did not produce one canonical release",
    )
    bridge_observations = bridge.observations()
    _require(
        bridge_observations["capturedRequests"] == 2
        and bridge_observations["rawRequestSha256"]
        == [first_raw_wire_sha256, second_raw_wire_sha256]
        and [
            item.get("status") for item in bridge_observations["responses"]
        ]
        == [428, 200]
        and bridge_observations["requestBytesMutated"] is False
        and bridge_observations["connectIdentityAddedByBridge"] is True,
        "public npm CLI bridge did not retain the exact bounded wire observations",
    )
    companion_execution = (
        _SERVERWARE_NPM_COMPANION_CLIENT.observations()
        if _SERVERWARE_NPM_COMPANION_CLIENT is not None
        else None
    )
    return {
        "mode": (
            "two-watchdog-attested-npm-companions"
            if companion_execution is not None
            else "two-public-npm-cli-publish-processes-through-bounded-identity-bridge"
        ),
        "fixtureOnly": True,
        "fixtureCompatibilityProven": True,
        "localFixtureCompatibilityProven": True,
        "firstRequestSideEffectFree428Proven": True,
        "liveNpmRegistryProven": False,
        "npmExecutable": str(contract["npmExecutable"]),
        "npmEntrypoint": str(contract["npmEntrypoint"]),
        "npmPackageManifest": str(contract["npmPackageManifest"]),
        "npmVersion": contract["npmVersion"],
        "nodeExecutable": str(contract["nodeExecutable"]),
        "npmExecutableSha256": contract["npmExecutableSha256"],
        "npmEntrypointSha256": contract["npmEntrypointSha256"],
        "npmPackageSha256": contract["npmPackageSha256"],
        "nodeBinarySha256": contract["nodeBinarySha256"],
        "emptyNpmConfigSha256": empty_config_sha256,
        "packageTarballSha256": package_tarball_sha256,
        "packageTarball": str(tarball_path),
        "command": command,
        "publicCliArgv": command,
        "commandSha256": command_sha256,
        "environmentSha256": environment_sha256,
        "environmentKeys": sorted(child_environment),
        "isolatedHome": str(home_dir),
        "isolatedNpmConfig": str(empty_config),
        "noProxyBypassDisabled": True,
        "approvalId": approval_id,
        "firstRequestDigest": first_approval_row["request_digest"],
        "secondRequestDigest": successful_attempt["request_digest"],
        "firstOperationDigest": first_approval_row["operation_digest"],
        "secondOperationDigest": successful_attempt["operation_digest"],
        "requestDigestsIdentical": True,
        "operationDigestsIdentical": True,
        "canonicalRequestReused": True,
        "firstCanonicalRequestSha256": first_canonical_sha256,
        "secondCanonicalRequestSha256": second_canonical_sha256,
        "firstRawWireRequestSha256": first_raw_wire_sha256,
        "secondRawWireRequestSha256": second_raw_wire_sha256,
        "rawWireRequestDigestsDiffer": True,
        "canonicalRequestDigestsIdentical": True,
        "canonicalRequestExcludesNpmSession": True,
        "clientNpmSessionsDistinct": True,
        "clientNpmSessionValuesDisclosed": False,
        "upstreamNpmSessionHeaders": [],
        "bodySha256": approval["reviewBodySha256"],
        "firstExitCode": first_process["exitCode"],
        "secondExitCode": second_process["exitCode"],
        "firstOutputSha256": first_process["outputSha256"],
        "secondOutputSha256": second_process["outputSha256"],
        "firstHttpStatus": 428,
        "secondHttpStatus": 200,
        "registryMutations": 1,
        "credentialIssuances": 1,
        "credentialIssuanceBindingDigest": new_issuances[0]["binding_digest"],
        "credentialIssuanceRequestBindingSha256": new_issuances[0][
            "request_binding_sha256"
        ],
        "grantConsumptions": 1,
        "approvedGrantUsesRemaining": 0,
        "approvalCount": 1,
        "newApprovalOnRetry": False,
        "agentSuppliedRegistryCredential": False,
        "rustConnectProxy": True,
        "npmCompanionExecution": companion_execution,
        "sameAbsoluteCommandAndEnvironment": True,
        "sameSanitizedFilesystemBaseline": True,
        "artifactDigestsStableAcrossInvocations": True,
        "rawWireCapturedBeforeRust": True,
        "rawWireDerivedWithoutStoredCanonicalInput": True,
        "requestBytesForwardedUnmodified": True,
        "bridgeObservations": bridge_observations,
        "identitySupport": (
            "bounded local CONNECT bridge adds only the required principal header "
            "on its independent bridge-to-Rust CONNECT request"
        ),
        "assuranceBoundary": (
            "Local npm 11.8.0 fixture compatibility is proven only by two public CLI "
            "process invocations against the deterministic HTTPS fixture through one "
            "bounded identity bridge and one Rust gate. The bridge terminates local "
            "fixture TLS to capture exact physical request bytes, forwards those bytes "
            "unchanged, and adds identity only to its separate CONNECT request. No public "
            "npm registry, arbitrary npm version, independent bridge implementation, or "
            "production network behavior is claimed."
        ),
    }


def _exercise_installed_npm_cli(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
    work_dir: Path,
) -> dict[str, Any]:
    bridge = _NpmCliProxyBridge(
        gate=gate,
        registry=registry,
        expected_requests=2,
    )
    primary_error: BaseException | None = None
    try:
        bridge.start()
        return _exercise_installed_npm_cli_with_bridge(
            gate=gate,
            bridge=bridge,
            operator_page=operator_page,
            reviewer_page=reviewer_page,
            browser_observations=browser_observations,
            public_url=public_url,
            registry=registry,
            policy_hash=policy_hash,
            credential_version=credential_version,
            work_dir=work_dir,
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors = _cleanup_actions(
            [("npm public CLI proxy bridge", bridge.close)]
        )
        _raise_cleanup_errors(
            primary_error,
            cleanup_errors,
            label="npm public CLI journey and bridge cleanup failed",
        )


def _exercise_rust_npm(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
    work_dir: Path,
) -> dict[str, Any]:
    operations = [
        "npm.publish",
        "npm.unpublish",
        "npm.distTagWrite",
        "npm.tokenWrite",
        "npm.metadataWrite",
    ]
    journeys = [
        _exercise_one_npm_jit_operation(
            gate=gate,
            operator_page=operator_page,
            reviewer_page=reviewer_page,
            browser_observations=browser_observations,
            public_url=public_url,
            registry=registry,
            policy_hash=policy_hash,
            credential_version=credential_version,
            operation=operation,
        )
        for operation in operations
    ]
    _require(
        len({item["requestBytesSha256"] for item in journeys}) == len(operations)
        and len({item["requestDigest"] for item in journeys}) == len(operations)
        and len({item["operationDigest"] for item in journeys}) == len(operations),
        "npm operation journeys did not retain distinct immutable request bindings",
    )

    before_token_create = _jit_state_snapshot(
        NPM_JIT_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    registry_before_token_create = registry.observations()
    token_create_request, _ = _npm_request_bytes(registry, "npm.tokenCreate")
    token_create = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=token_create_request,
    )
    token_create_payload = token_create["json"] or {}
    _require(
        token_create["status"] == 403
        and token_create_payload.get("action") == "deny"
        and (token_create_payload.get("payload") or {}).get("error")
        == "npm_token_creation_denied"
        and _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
        == before_token_create
        and registry.observations() == registry_before_token_create,
        f"npm token creation did not fail before JIT, credential release, or upstream: {token_create}",
    )

    direct_registry = registry.observations()
    _require(
        all(direct_registry["counts"][operation] == 1 for operation in operations)
        and direct_registry["counts"]["npm.tokenCreate"] == 0
        and direct_registry["counts"]["rejected"] == 0
        and len(direct_registry["events"]) == len(operations),
        f"npm registry did not observe exactly the five approved write classes: {direct_registry}",
    )
    contention = _exercise_npm_one_use_contention(
        gate=gate,
        operator_page=operator_page,
        reviewer_page=reviewer_page,
        browser_observations=browser_observations,
        public_url=public_url,
        registry=registry,
        policy_hash=policy_hash,
        credential_version=credential_version,
    )
    cli_compatibility = _exercise_installed_npm_cli(
        gate=gate,
        operator_page=operator_page,
        reviewer_page=reviewer_page,
        browser_observations=browser_observations,
        public_url=public_url,
        registry=registry,
        policy_hash=policy_hash,
        credential_version=credential_version,
        work_dir=work_dir,
    )
    final_registry = registry.observations()
    _require(
        final_registry["counts"]["npm.publish"] == 3
        and all(
            final_registry["counts"][operation] == 1
            for operation in operations
            if operation != "npm.publish"
        )
        and final_registry["counts"]["npm.tokenCreate"] == 0
        and final_registry["counts"]["rejected"] == 0
        and len(final_registry["events"]) == len(operations) + 2
        and all(
            item.get("npmSessionHeaders") == []
            for item in final_registry["events"]
        ),
        "npm registry did not retain five direct-wire classes plus exactly one "
        f"contention winner and one installed-CLI mutation: {final_registry}",
    )
    return {
        "routeId": NPM_JIT_ROUTE_ID,
        "credentialId": NPM_CREDENTIAL_ID,
        "credentialVersion": credential_version,
        "writeClasses": journeys,
        "concurrentOneUseContention": contention,
        "installedNpmCli": cli_compatibility,
        "tokenCreation": {
            "status": token_create["status"],
            "error": "npm_token_creation_denied",
            "requestBytesSha256": token_create["sentRequestSha256"],
            "preSideEffectDenied": True,
        },
        "directWireRegistryCounts": direct_registry["counts"],
        "registryCounts": final_registry["counts"],
    }


class _OwnedPlaywrightSession:
    def __init__(
        self,
        factory: Callable[[], Any],
        *,
        baseline_child_pids: set[int],
        observed_child_pids: set[int],
    ) -> None:
        self._factory = factory
        self._baseline_child_pids = baseline_child_pids
        self._observed_child_pids = observed_child_pids
        self._manager: Any = None

    def __enter__(self) -> Any:
        primary_error: BaseException | None = None
        try:
            self._manager = self._factory()
            playwright = _run_with_hard_timeout(
                self._manager.start,
                label="Playwright driver startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="Playwright driver startup",
                    cap=30,
                ),
            )
            self._observed_child_pids.update(
                _descendant_pids(os.getpid()) - self._baseline_child_pids
            )
            return playwright
        except BaseException as exc:
            primary_error = exc
            cleanup_errors: list[BaseException] = []
            if self._manager is not None:
                cleanup_errors.extend(
                    _cleanup_actions(
                        [("Playwright startup manager", self._manager.stop)]
                    )
                )
            try:
                _run_with_hard_timeout(
                    lambda: _terminate_all_task_descendants(
                        self._baseline_child_pids,
                        self._observed_child_pids,
                        label="failed Playwright startup cleanup",
                    ),
                    label="failed Playwright startup descendant cleanup",
                    timeout_seconds=25,
                )
            except BaseException as cleanup_exc:
                cleanup_errors.append(cleanup_exc)
            _raise_cleanup_errors(
                primary_error,
                cleanup_errors,
                label="Playwright startup and cleanup failed",
            )
            raise

    def __exit__(
        self,
        _exception_type: Any,
        exception: BaseException | None,
        _traceback: Any,
    ) -> bool:
        cleanup_errors: list[BaseException] = []
        if self._manager is not None:
            cleanup_errors.extend(
                _cleanup_actions([("Playwright driver", self._manager.stop)])
            )
        try:
            _run_with_hard_timeout(
                lambda: _terminate_all_task_descendants(
                    self._baseline_child_pids,
                    self._observed_child_pids,
                    label="Playwright and Chromium descendant cleanup",
                ),
                label="Playwright and Chromium descendant cleanup",
                timeout_seconds=25,
            )
        except BaseException as cleanup_exc:
            cleanup_errors.append(cleanup_exc)
        _raise_cleanup_errors(
            exception,
            cleanup_errors,
            label="Playwright session and cleanup failed",
        )
        return False


def _cleanup_browser_journey_resources(
    *,
    gate: _DecisionGateProcess | None,
    page: Any,
    reviewer_page: Any,
    context: Any,
    reviewer_context: Any,
    browser: Any,
    baseline_child_pids: set[int],
    observed_child_pids: set[int],
) -> list[BaseException]:
    errors: list[BaseException] = []
    try:
        for _ in range(2):
            observed_child_pids.update(
                _descendant_pids(os.getpid()) - baseline_child_pids
            )
            time.sleep(0.05)
    except BaseException as exc:
        errors.append(exc)
    actions: list[tuple[str, Callable[[], None]]] = []
    if gate is not None:
        actions.append(("decision gate", gate.close))
    if reviewer_page is not None:
        actions.append(("reviewer page", reviewer_page.close))
    if page is not None:
        actions.append(("operator page", page.close))
    if reviewer_context is not None:
        actions.append(("reviewer browser context", reviewer_context.close))
    if context is not None:
        actions.append(("operator browser context", context.close))
    if browser is not None:
        actions.append(("Chromium browser", browser.close))
    errors.extend(_cleanup_actions(actions))
    try:
        observed_child_pids.update(
            _descendant_pids(os.getpid()) - baseline_child_pids
        )
    except BaseException as exc:
        errors.append(exc)
    for label, resource, check in (
        (
            "reviewer page",
            reviewer_page,
            lambda value: value.is_closed(),
        ),
        (
            "operator page",
            page,
            lambda value: value.is_closed(),
        ),
        (
            "Chromium browser",
            browser,
            lambda value: not value.is_connected(),
        ),
    ):
        if resource is None:
            continue
        try:
            closed = _run_with_hard_timeout(
                lambda: check(resource),
                label=f"{label} post-cleanup state check",
                timeout_seconds=2,
            )
            _require(closed, f"{label} remained live after cleanup")
        except BaseException as exc:
            errors.append(exc)
    return errors


def _run_browser_journey(
    public_url: str,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    npm_registry: _NpmRegistryFixture,
    screenshots_dir: Path | None,
    decision_gate_binary: Path,
    decision_gate_digest: str,
    response_proof_fixture: Path,
    same_journey_contract: dict[str, Any],
    fixture_facts: dict[str, Any],
) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Playwright is unavailable; install playwright==1.61.0 and its Chromium browser"
        ) from exc

    browser_observations: list[dict[str, Any]] = []
    console_errors: list[str] = []
    page_errors: list[str] = []
    api_documents: list[Any] = []
    gate: _DecisionGateProcess | None = None
    _enable_child_subreaper()
    baseline_child_pids = _descendant_pids(os.getpid())
    task_owned_browser_child_pids: set[int] = set()
    journey_result: dict[str, Any] | None = None
    with _OwnedPlaywrightSession(
        sync_playwright,
        baseline_child_pids=baseline_child_pids,
        observed_child_pids=task_owned_browser_child_pids,
    ) as playwright:
        browser: Any = None
        context: Any = None
        reviewer_context: Any = None
        page: Any = None
        reviewer_page: Any = None
        try:
            expected_chromium = same_journey_contract["chromiumExecutable"]
            configured_chromium = Path(playwright.chromium.executable_path)
            actual_chromium = configured_chromium.resolve(strict=True)
            _require(
                actual_chromium == expected_chromium
                and not configured_chromium.is_symlink()
                and _sha256_path(actual_chromium)
                == same_journey_contract["chromiumExecutableSha256"],
                "Playwright Chromium differs from the frozen consolidated artifact",
            )
            browser = _run_with_hard_timeout(
                lambda: playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--ignore-certificate-errors-spki-list={_certificate_spki_sha256(simulator.server_cert_path)}",
                        "--no-proxy-server",
                        "--disable-background-networking",
                    ],
                ),
                label="Chromium browser startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="Chromium browser startup",
                    cap=30,
                ),
            )
            context = _run_with_hard_timeout(
                lambda: browser.new_context(
                    viewport={"width": 1440, "height": 1100},
                    locale="en-US",
                    timezone_id="UTC",
                    reduced_motion="reduce",
                    extra_http_headers={"X-Test-Actor": "operator"},
                ),
                label="operator browser context startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="operator browser context startup",
                    cap=15,
                ),
            )
            reviewer_context = _run_with_hard_timeout(
                lambda: browser.new_context(
                    viewport={"width": 1440, "height": 1100},
                    locale="en-US",
                    timezone_id="UTC",
                    reduced_motion="reduce",
                    extra_http_headers={"X-Test-Actor": "reviewer"},
                ),
                label="reviewer browser context startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="reviewer browser context startup",
                    cap=15,
                ),
            )
            _run_with_hard_timeout(
                lambda: _install_dev_webauthn_shim(context),
                label="operator WebAuthn shim startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="operator WebAuthn shim startup",
                    cap=15,
                ),
            )
            _run_with_hard_timeout(
                lambda: _install_dev_webauthn_shim(reviewer_context),
                label="reviewer WebAuthn shim startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="reviewer WebAuthn shim startup",
                    cap=15,
                ),
            )
            page = _run_with_hard_timeout(
                context.new_page,
                label="operator page startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="operator page startup",
                    cap=15,
                ),
            )
            reviewer_page = _run_with_hard_timeout(
                reviewer_context.new_page,
                label="reviewer page startup",
                timeout_seconds=_journey_timeout_seconds(
                    label="reviewer page startup",
                    cap=15,
                ),
            )
            page.set_default_timeout(
                _journey_timeout_ms(label="operator page setup")
            )
            reviewer_page.set_default_timeout(
                _journey_timeout_ms(label="reviewer page setup")
            )

            def record_request(request: Any) -> None:
                _append_bounded(
                    browser_observations,
                    {"type": "request", "method": request.method, "url": request.url},
                    label="browser observations",
                )

            def record_response(response: Any) -> None:
                _append_bounded(
                    browser_observations,
                    {"type": "response", "status": response.status, "url": response.url},
                    label="browser observations",
                )

            def record_console(message: Any) -> None:
                if message.type == "error":
                    _append_bounded(
                        console_errors,
                        message.text[:4096],
                        label="browser console errors",
                        maximum=1000,
                    )

            def record_page_error(error: Any) -> None:
                _append_bounded(
                    page_errors,
                    str(error)[:4096],
                    label="browser page errors",
                    maximum=1000,
                )

            page.on("request", record_request)
            page.on("response", record_response)
            reviewer_page.on("request", record_request)
            reviewer_page.on("response", record_response)
            page.on("console", record_console)
            page.on("pageerror", record_page_error)
            reviewer_page.on("console", record_console)
            reviewer_page.on("pageerror", record_page_error)
            task_owned_browser_child_pids = (
                _descendant_pids(os.getpid()) - baseline_child_pids
            )
            _require(
                bool(task_owned_browser_child_pids),
                "Playwright did not expose any task-owned browser child process",
            )
        except BaseException as exc:
            cleanup_errors = _cleanup_browser_journey_resources(
                gate=gate,
                page=page,
                reviewer_page=reviewer_page,
                context=context,
                reviewer_context=reviewer_context,
                browser=browser,
                baseline_child_pids=baseline_child_pids,
                observed_child_pids=task_owned_browser_child_pids,
            )
            _raise_cleanup_errors(
                exc,
                cleanup_errors,
                label="browser allocation and cleanup failed",
            )
            raise

        try:
            response = page.goto(public_url + "/", wait_until="domcontentloaded")
            _require(
                response is not None and response.status == 200,
                "portal did not return HTTP 200",
            )
            response_headers = response.headers
            expected_headers = {
                "cache-control": "no-store",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            }
            for name, expected in expected_headers.items():
                _require(
                    response_headers.get(name) == expected,
                    f"portal security header {name} was not {expected!r}",
                )
            _require(
                "frame-ancestors 'none'" in response_headers.get(
                    "content-security-policy", ""
                ),
                "portal CSP does not deny framing",
            )
            _require(
                response_headers.get("strict-transport-security", "").startswith(
                    "max-age=31536000"
                ),
                "HTTPS portal response omitted HSTS",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            token_storage = page.evaluate(
                "() => JSON.stringify({session: {...sessionStorage}, local: {...localStorage}})"
            )
            _require(
                ADMIN_TOKEN not in token_storage,
                "manually entered operator token was written to Web Storage",
            )
            page.reload(wait_until="domcontentloaded")
            _require(
                page.locator("#admin-token").input_value() == "",
                "manually entered operator token survived a portal reload",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            _assert_no_horizontal_overflow(page, label="desktop initial")

            page.once("dialog", lambda dialog: dialog.accept())
            page.get_by_role("button", name="Seed demo", exact=True).click()
            _wait_for_api(
                page,
                "/api/policy",
                lambda payload: payload.get("ready") is True,
            )
            _wait_for_api(
                page,
                "/api/bootstrap",
                lambda payload: any(
                    item.get("id") == "agent:demo"
                    for item in payload.get("policyPrincipals", [])
                ),
            )
            page.wait_for_function(
                """
                () => [...document.querySelectorAll('#policy-principal option')].some(
                  (item) => item.value === 'agent:demo'
                )
                """,
                timeout=_journey_timeout_ms(label="Playwright wait"),
            )
            _assert_refresh_preserves_live_oauth_form(page)
            seed_status = page.locator("#operator-status").inner_text()
            if "failed:" in seed_status.lower():
                bounded_bootstrap = _api_result(
                    page,
                    "/api/bootstrap",
                )
                raise AssertionError(
                    "demo seed failed: "
                    f"{seed_status}; bounded bootstrap={bounded_bootstrap}"
                )
            _assert_stripe_uses_manual_credential_flow(page, browser_observations)
            if screenshots_dir is not None:
                _capture_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-desktop.png",
                )
                _capture_mobile_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-mobile.png",
                )
                page.set_viewport_size({"width": 1440, "height": 1100})

            reviewer_page.goto(public_url + "/", wait_until="domcontentloaded")
            reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
            reviewer_page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(reviewer_page, public_url)
            _require(
                reviewer_page.evaluate("state.currentUserId") == "user:demo",
                "review browser did not receive the distinct reviewer identity",
            )
            dev_credential = _api_post_json(
                reviewer_page, "/api/dev/webauthn/credential"
            )
            _require(
                dev_credential.get("user_id") == "user:demo"
                and dev_credential.get("attestation_trusted") is True
                and dev_credential.get("authenticator_class") == "dev",
                f"dev authenticator registration was not trusted: {dev_credential}",
            )
            _require(
                reviewer_page.evaluate(
                    "window.__serverwareDevWebAuthnShim === true"
                ),
                "browser WebAuthn shim was not installed",
            )

            page.locator("#setup-template").select_option("gmail_recent")
            page.wait_for_function(
                """
                () => {
                  const text = document.querySelector('#setup-template-summary')?.textContent || '';
                  return text.includes('Gmail messages from last 30 days')
                    && text.includes('gmail.googleapis.com')
                    && text.includes('Response age: at most 30 days')
                    && text.includes('Unknown host, path, method, or validation result is denied');
                }
                """,
                timeout=_journey_timeout_ms(label="Playwright wait"),
            )
            page.locator("#setup-principal").select_option("agent:demo")
            page.locator("#setup-route-id").fill("browser.gmail.last-30-days")
            page.locator("#setup-connect-button").click()
            page.wait_for_function(
                """
                () => state.oauthSetupSessionId
                  && state.setupSession?.id === state.oauthSetupSessionId
                  && state.setupSession?.routeId === 'browser.gmail.last-30-days'
                  && state.setupSession?.routePolicyDigest === null
                  && document.activeElement?.id === 'oauth-provider'
                """,
                timeout=_journey_timeout_ms(label="Playwright wait"),
            )
            google_credential = _connect_oauth(
                page,
                context,
                reviewer_page,
                public_url,
                provider="google",
                name=GOOGLE_NAME,
                scopes=GOOGLE_SCOPES,
                account="operator@example.test",
            )
            _assert_public_credential(
                google_credential,
                provider="google",
                subject="google-subject-001",
                account="operator@example.test",
                scopes=GOOGLE_SCOPES,
            )
            setup_after_google = page.evaluate("() => state.setupSession")
            _require(
                setup_after_google.get("routeId") == "browser.gmail.last-30-days"
                and setup_after_google.get("credentialId") == google_credential["id"]
                and setup_after_google.get("phase") == "credential_activated",
                f"fresh Setup OAuth flow did not bind its credential: {setup_after_google}",
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".oauth-connect-section",
                    screenshots_dir / "operator-portal-oauth.png",
                )

            gmail_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id="browser.gmail.last-30-days",
                credential_id=google_credential["id"],
                custom_route=_localized_read_route(
                    page,
                    template_id="gmail_recent",
                    simulator=simulator,
                ),
            )
            api_documents.append(gmail_policy)

            x_credential = _connect_oauth(
                page,
                context,
                reviewer_page,
                public_url,
                provider="x",
                name=X_NAME,
                scopes=X_SCOPES,
                account="@operator_x",
            )
            _assert_public_credential(
                x_credential,
                provider="x",
                subject="x-subject-001",
                account="@operator_x",
                scopes=X_SCOPES,
            )
            _require(
                (x_credential.get("metadata") or {}).get("x_app_id")
                == simulator.X_CLIENT_ID,
                "X credential is not bound to the OAuth client app",
            )

            x_read_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id="browser.x.search.seven-days",
                credential_id=x_credential["id"],
                custom_route=_localized_read_route(
                    page,
                    template_id="x_read_recent",
                    simulator=simulator,
                ),
            )
            api_documents.append(x_read_policy)
            x_write_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id=X_JIT_ROUTE_ID,
                credential_id=x_credential["id"],
                custom_route=_x_jit_route(simulator),
            )
            api_documents.append(x_write_policy)
            npm_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id=NPM_JIT_ROUTE_ID,
                credential_id=NPM_CREDENTIAL_ID,
                custom_route=_npm_jit_route(npm_registry),
            )
            api_documents.append(npm_policy)
            final_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id=NPM_CONTENTION_ROUTE_ID,
                credential_id=NPM_CREDENTIAL_ID,
                custom_route=_npm_contention_route(npm_registry),
            )
            final_bootstrap = _api_json(page, "/api/bootstrap")
            final_policy_api = _api_json(page, "/api/policy")
            api_documents.extend([final_bootstrap, final_policy_api])
            from serverware import db

            stored_x_credential = db.get_credential(x_credential["id"])
            stored_npm_credential = db.get_credential(NPM_CREDENTIAL_ID)
            _require(
                stored_x_credential is not None,
                "callback-created X credential disappeared before Rust startup",
            )
            _require(
                stored_npm_credential is not None,
                "seeded npm credential disappeared before Rust startup",
            )
            x_credential_version = int(
                stored_x_credential["credential_version"]
            )
            npm_credential_version = int(
                stored_npm_credential["credential_version"]
            )
            gate = _DecisionGateProcess(
                binary=decision_gate_binary,
                response_proof_fixture=response_proof_fixture,
                data_dir=data_dir,
                portal_url=public_url,
                simulator=simulator,
            )
            gate.start()
            production_hardware_policy = _assert_policy_evidence(
                final_policy,
                google_credential["id"],
                x_credential["id"],
                simulator,
                npm_registry,
                gate,
                reviewer_page,
                browser_observations,
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".policy-authoring-section",
                    screenshots_dir / "operator-portal-policy.png",
                )

            rust_jit = _exercise_rust_jit(
                gate=gate,
                operator_page=page,
                reviewer_page=reviewer_page,
                browser_observations=browser_observations,
                public_url=public_url,
                simulator=simulator,
                policy_hash=final_policy_api["policy_hash"],
                credential_id=x_credential["id"],
                credential_version=x_credential_version,
                binary_digest=decision_gate_digest,
                screenshots_dir=screenshots_dir,
            )
            api_documents.append(rust_jit)
            rust_npm = _exercise_rust_npm(
                gate=gate,
                operator_page=page,
                reviewer_page=reviewer_page,
                browser_observations=browser_observations,
                public_url=public_url,
                registry=npm_registry,
                policy_hash=final_policy_api["policy_hash"],
                credential_version=npm_credential_version,
                work_dir=data_dir.parent / "client-runtime",
            )
            api_documents.append(rust_npm)
            page.locator("#enrollment-principal").select_option("agent:demo")
            with page.expect_response(
                lambda item: item.request.method == "POST"
                and item.url.endswith("/api/agents/enrollment"),
                timeout=_journey_timeout_ms(label="Playwright wait"),
            ) as enrollment_response_info:
                page.locator("#agent-enrollment-form button[type='submit']").click()
            enrollment_response = enrollment_response_info.value
            enrollment_headers_before_body = enrollment_response.headers_array
            enrollment_content_lengths = [
                item.get("value")
                for item in enrollment_headers_before_body
                if str(item.get("name") or "").lower() == "content-length"
            ]
            _require(
                len(enrollment_content_lengths) == 1
                and str(enrollment_content_lengths[0]).isdigit()
                and 0 < int(enrollment_content_lengths[0])
                <= MAX_ENROLLMENT_PACKET_BYTES,
                "enrollment response was not size-bounded before body materialization",
            )
            enrollment_response_bytes = enrollment_response.body()
            enrollment_response_headers_array = _closed_response_header_array(
                enrollment_headers_before_body,
                body=enrollment_response_bytes,
                label="browser enrollment response",
            )
            enrollment_response_header_values = [
                item["value"]
                for item in enrollment_response_headers_array
                if item["name"]
                == "x-serverware-enrollment-packet-sha256"
            ]
            enrollment_response_header_map = {
                item["name"]: item["value"]
                for item in enrollment_response_headers_array
            }
            enrollment_response_sha256 = enrollment_response_header_map.get(
                "x-serverware-enrollment-packet-sha256"
            )
            observed_enrollment_response_sha256 = (
                "sha256:"
                + hashlib.sha256(enrollment_response_bytes).hexdigest()
            )
            expected_portal_leaf_spki_sha256 = _certificate_spki_sha256_hex(
                simulator.server_cert_path
            )
            enrollment_response_tls = _playwright_response_tls_evidence(
                page,
                enrollment_response,
                expected_leaf_spki_sha256=expected_portal_leaf_spki_sha256,
                origin=public_url,
            )
            _require(
                enrollment_response.status == 200
                and enrollment_response.url
                == public_url + "/api/agents/enrollment"
                and {
                    item.strip()
                    for item in enrollment_response_header_map.get(
                        "cache-control", ""
                    ).split(",")
                    if item.strip()
                }
                == {"no-store"}
                and {
                    item.strip()
                    for item in enrollment_response_header_map.get(
                        "x-content-type-options", ""
                    ).split(",")
                    if item.strip()
                }
                == {"nosniff"}
                and enrollment_response_header_map.get("content-type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
                == "application/json"
                and enrollment_response_sha256
                == observed_enrollment_response_sha256
                and enrollment_response_header_values
                == [observed_enrollment_response_sha256],
                "enrollment API response did not authenticate its exact canonical "
                f"bytes: status={enrollment_response.status}, "
                f"headers={enrollment_response_headers_array}, "
                f"observedSha256={observed_enrollment_response_sha256}",
            )
            try:
                page.wait_for_function(
                    """
                    ({policyHash, routeId, credentialId}) => {
                      const packet = state.enrollmentPacket;
                      return packet?.apiVersion === 'serverware.agentEnrollment/v1'
                        && packet?.principalId === 'agent:demo'
                        && packet?.pinning?.policyHash === policyHash
                        && (packet?.allowedRoutes || []).some(
                          (item) => item.id === routeId
                            && item.credentialRef === credentialId
                        );
                    }
                    """,
                    arg={
                        "policyHash": final_policy_api["policy_hash"],
                        "routeId": "browser.gmail.last-30-days",
                        "credentialId": google_credential["id"],
                    },
                    timeout=_journey_timeout_ms(label="Playwright wait"),
                )
            except Exception as exc:
                diagnostics = page.evaluate(
                    """
                    () => ({
                      status: document.querySelector('#operator-status')?.textContent || '',
                      packet: state.enrollmentPacket,
                      principal: document.querySelector('#enrollment-principal')?.value || '',
                      output: (document.querySelector('#enrollment-output')?.value || '').slice(0, 2000)
                    })
                    """
                )
                raise AssertionError(
                    f"browser enrollment packet did not bind the Gmail assignment: {diagnostics}"
                ) from exc
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    "section:has(#agent-enrollment-form)",
                    screenshots_dir / "operator-portal-enrollment.png",
                )
            with page.expect_download(
                timeout=_journey_timeout_ms(label="enrollment download wait")
            ) as download_info:
                page.get_by_role("button", name="Download", exact=True).click()
            download = download_info.value
            packet_path = Path(download.path())
            packet_bytes = _read_bounded_file(
                packet_path,
                label="downloaded enrollment packet",
                maximum=MAX_ENROLLMENT_PACKET_BYTES,
            )
            enrollment_packet = json.loads(packet_bytes)
            state_packet = page.evaluate("() => state.enrollmentPacket")
            state_packet_text = page.evaluate("() => state.enrollmentPacketText")
            state_packet_sha256 = page.evaluate(
                "() => state.enrollmentPacketFileSha256"
            )
            _require(
                packet_bytes == enrollment_response_bytes
                and state_packet_text.encode("utf-8") == enrollment_response_bytes
                and state_packet_sha256 == enrollment_response_sha256
                and enrollment_packet == state_packet,
                "downloaded enrollment packet differs from the authenticated API response bytes",
            )
            _require(
                download.suggested_filename
                == "serverware-enrollment-agent-demo.json",
                "downloaded enrollment packet filename is not principal-bound",
            )
            unknown_route_canaries = [
                item
                for item in (enrollment_packet.get("canaries", {}).get("deny") or [])
                if item.get("expectedError") == "unknown_route_denied"
            ]
            _require(
                len(unknown_route_canaries) == 1
                and unknown_route_canaries[0].get("expectedStatus") == 403,
                "enrollment packet does not bind one fail-closed unknown-route canary",
            )
            enrollment_packet_sha256 = enrollment_response_sha256
            api_documents.append(enrollment_packet)
            same_journey = _run_same_journey_callback(
                contract=same_journey_contract,
                fixture_facts=fixture_facts,
                gate=gate,
                public_url=public_url,
                portal_ca_path=simulator.ca_cert_path,
                portal_leaf_cert_path=simulator.server_cert_path,
                packet_path=packet_path,
                packet_bytes=packet_bytes,
                packet=enrollment_packet,
                response_header_sha256=enrollment_response_sha256,
                response_header_values=enrollment_response_header_values,
                response_headers_array=enrollment_response_headers_array,
                response_tls_evidence=enrollment_response_tls,
                response_status=enrollment_response.status,
                response_url=enrollment_response.url,
                policy_sha256=final_policy_api["policy_hash"],
                decision_gate_digest=decision_gate_digest,
                callback_dir=data_dir.parent / "same-journey-callback",
            )
            api_documents.append(same_journey)
            _require(
                not final_bootstrap.get("pendingOAuthCredentials"),
                "browser journey left a pending OAuth credential",
            )
            _require(
                not final_bootstrap.get("oauthIssuanceUncertainties"),
                "browser journey left uncertain provider issuance",
            )
            _assert_no_oauth_cookies(context)
            state_path = data_dir / "oauth-states.json"
            if state_path.exists():
                state_document = json.loads(state_path.read_text(encoding="utf-8"))
                _require(
                    state_document.get("states") == {},
                    "consumed OAuth state remains on disk",
                )

            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="mobile final")
            page.set_viewport_size({"width": 1440, "height": 1100})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="desktop final")

            _require(not page_errors, f"browser page errors occurred: {page_errors}")
            expected_activation_challenges = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 428
                and re.search(
                    r"/api/oauth/pending/[^/]+/activate$",
                    str(item.get("url") or ""),
                )
            ]
            _require(
                len(expected_activation_challenges) == 2,
                "browser journey did not observe exactly one two-person activation "
                "challenge for each OAuth credential",
            )
            expected_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and (
                    re.search(
                        r"/api/control-plane/approvals/[^/]+/approve$",
                        str(item.get("url") or ""),
                    )
                    or re.search(
                        r"/api/oauth/pending/[^/]+/activate$",
                        str(item.get("url") or ""),
                    )
                )
            ]
            _require(
                len(expected_separation_denials) == 4,
                "browser journey did not observe requester self-approval and reviewer "
                "direct-activation denials for both OAuth credentials",
            )
            jit_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and re.search(
                    rf"/api/approvals/{re.escape(rust_jit['approvalId'])}/(?:review|approve)$",
                    str(item.get("url") or ""),
                )
            ]
            _require(
                len(jit_separation_denials) == 2,
                "browser journey did not observe operator review and approval denials",
            )
            npm_approval_ids = {
                item["approvalId"] for item in rust_npm["writeClasses"]
            }
            npm_approval_ids.add(
                rust_npm["concurrentOneUseContention"]["approvalId"]
            )
            npm_approval_ids.add(rust_npm["installedNpmCli"]["approvalId"])
            npm_jit_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and any(
                    re.search(
                        rf"/api/approvals/{re.escape(approval_id)}/(?:review|approve)$",
                        str(item.get("url") or ""),
                    )
                    for approval_id in npm_approval_ids
                )
            ]
            _require(
                len(npm_jit_separation_denials) == 2 * len(npm_approval_ids),
                "browser journey did not observe requester review and approval denials "
                "for every npm write class",
            )
            expected_console_428 = (
                "Failed to load resource: the server responded with a status of 428 "
                "(Precondition Required)"
            )
            expected_console_403 = (
                "Failed to load resource: the server responded with a status of 403 "
                "(Forbidden)"
            )
            expected_console_500 = (
                "Failed to load resource: the server responded with a status of 500 "
                "(Internal Server Error)"
            )
            unexpected_console_errors = [
                message
                for message in console_errors
                if message
                not in {
                    expected_console_428,
                    expected_console_403,
                    expected_console_500,
                }
            ]
            _require(
                console_errors.count(expected_console_428) == 2
                and console_errors.count(expected_console_403)
                == (
                    len(expected_separation_denials)
                    + len(jit_separation_denials)
                    + len(npm_jit_separation_denials)
                )
                and console_errors.count(expected_console_500) == 1
                and not unexpected_console_errors,
                f"browser console errors occurred: {console_errors}",
            )
            _assert_storage_and_disk_do_not_leak_tokens(
                page,
                context,
                data_dir,
                simulator,
                api_documents,
                browser_observations,
            )
            _assert_storage_and_disk_do_not_leak_tokens(
                reviewer_page,
                reviewer_context,
                data_dir,
                simulator,
                api_documents,
                browser_observations,
            )
            observations = _assert_provider_observations(simulator)
            journey_remaining_seconds = _journey_timeout_seconds(
                label="browser journey completion",
                cap=JOURNEY_TIMEOUT_SECONDS,
            )
            journey_result = {
                "ok": True,
                "portalUrl": public_url,
                "credentials": {
                    "google": google_credential["id"],
                    "x": x_credential["id"],
                },
                "oauthActivationApprovals": {
                    "google": google_credential["browserApprovalId"],
                    "x": x_credential["browserApprovalId"],
                    "approvedBy": "user:demo",
                    "requestedBy": "user:operator",
                },
                "enrollment": {
                    "filename": download.suggested_filename,
                    "packetSha256": enrollment_packet_sha256,
                    "principalId": enrollment_packet["principalId"],
                    "policyHash": enrollment_packet["pinning"]["policyHash"],
                    "gmailRoute": "browser.gmail.last-30-days",
                    "unknownRouteCanary": unknown_route_canaries[0],
                    "orderedResponseHeaders": enrollment_response_headers_array,
                    "responseSpecificTls": enrollment_response_tls,
                    "sameJourney": same_journey,
                },
                "rustJit": rust_jit,
                "rustNpm": rust_npm,
                "productionHardwarePolicy": production_hardware_policy,
                "policyHash": final_policy_api["policy_hash"],
                "routes": [
                    "browser.gmail.last-30-days",
                    "browser.x.search.seven-days",
                    X_JIT_ROUTE_ID,
                    NPM_JIT_ROUTE_ID,
                    NPM_CONTENTION_ROUTE_ID,
                ],
                "providerCounts": observations["counts"],
                "testAssurance": {
                    "productionProof": False,
                    "identity": "header-selected-distinct-test-subjects",
                    "webauthn": "server-generated-development-authenticator",
                    "attestation": (
                        "signed-development-consistency; no TEE workload custody"
                    ),
                    "jitOrigin": "measured-host-rust-connect-tls",
                    "dataPlaneBinaryDigest": decision_gate_digest,
                    "byteIdenticalRetry": True,
                    "oneUseGrantSequentialRuntimeAsserted": True,
                    "oneUseGrantSequentialReuseAsserted": True,
                    "oneUseGrantConcurrentContentionAsserted": True,
                    "oneUseContentionScope": (
                        "one-python-release-authority-one-rust-gate-"
                        "two-tcp-connections-sqlite"
                    ),
                    "sharedOrDistributedStoreContentionProven": False,
                    "installedNpmCliFixtureCompatibilityProven": True,
                    "installedNpmCliFirstRequestSideEffectFree428Proven": True,
                    "installedNpmCliApprovedRetryProven": True,
                    "installedNpmSessionDiscardProven": True,
                    "unmodifiedNpmCliProven": False,
                    "liveNpmRegistryProven": False,
                    "developmentAuthenticatorUsedForCompatibilityRoutes": True,
                    "productionHardwareOnlyTemplateAsserted": True,
                    "productionHardwareOnlyPersistedApiPathExercised": (
                        production_hardware_policy[
                            "persistedApprovalApiPathExercised"
                        ]
                    ),
                    "productionHardwareOnlyDevCredentialRejectedPreJit": (
                        production_hardware_policy["jitOrUpstreamEffect"] is False
                    ),
                    "productionHardwareOnlyDevCredentialRejectedBeforeAssertion": (
                        production_hardware_policy["challengeCreated"] is False
                    ),
                    "physicalHardwareAuthenticatorProven": False,
                    "oauthActivationChallenges": len(
                        expected_activation_challenges
                    ),
                    "oauthSeparationDenials": len(expected_separation_denials),
                    "jitSeparationDenials": len(jit_separation_denials),
                    "npmJitSeparationDenials": len(
                        npm_jit_separation_denials
                    ),
                    "npmWriteClassesThroughRust": len(
                        rust_npm["writeClasses"]
                    ),
                    "npmTokenCreationDeniedPreSideEffect": True,
                    "downloadedPacketExactBytesVerified": True,
                    "enrollmentResponseDigestHeaderVerified": True,
                    "enrollmentCompleteOrderedHeadersValidated": True,
                    "enrollmentCompleteOrderedHeadersBoundByCallback": False,
                    "responseSpecificBrowserTlsProven": enrollment_response_tls[
                        "responseSpecificTlsProven"
                    ],
                    "responseSpecificTlsBoundByCallback": False,
                    "portalBootInstanceBound": False,
                    "sameJourneyHostInstalledCliVerified": False,
                    "sameJourneyHostInstalledCliExecutionIndependentlyObserved": (
                        same_journey[
                            "hostInstalledCliExecutionIndependentlyObserved"
                        ]
                    ),
                    "sameJourneyPinnedVerifierProducedExactInstructions": (
                        same_journey[
                            "pinnedVerifierProducedExactAuthenticatedInstructions"
                        ]
                    ),
                    "sameJourneyGateRemainedLive": True,
                    "sameJourneyPortalRemainedLive": True,
                    "sourceProvenanceProven": False,
                    "buildReproductionProven": False,
                    "imageProvenanceProven": False,
                    "hardwareAttestationProven": False,
                    "teeCustodyProven": False,
                    "unknownRouteRuntimeAsserted": True,
                    "absoluteJourneyDeadlineSeconds": JOURNEY_TIMEOUT_SECONDS,
                    "journeyDeadlineMet": True,
                    "journeyRemainingSecondsAtResult": int(
                        journey_remaining_seconds
                    ),
                },
                "screenshots": str(screenshots_dir)
                if screenshots_dir is not None
                else None,
            }
        finally:
            primary_error = sys.exc_info()[1]
            cleanup_errors = _cleanup_browser_journey_resources(
                gate=gate,
                page=page,
                reviewer_page=reviewer_page,
                context=context,
                reviewer_context=reviewer_context,
                browser=browser,
                baseline_child_pids=baseline_child_pids,
                observed_child_pids=task_owned_browser_child_pids,
            )
            _raise_cleanup_errors(
                primary_error,
                cleanup_errors,
                label="browser journey and cleanup failed",
            )
    _require(
        not (_descendant_pids(os.getpid()) - baseline_child_pids),
        "Playwright session returned with task-owned descendants still alive",
    )
    _require(journey_result is not None, "browser journey omitted its closed result")
    journey_result["testAssurance"]["taskOwnedBrowserChildrenExited"] = True
    journey_result["testAssurance"][
        "taskOwnedBrowserProcessOwnership"
    ] = "linux-child-subreaper"
    journey_result["testAssurance"]["taskOwnedBrowserChildCount"] = len(
        task_owned_browser_child_pids
    )
    return journey_result


def main() -> None:
    global _JOURNEY_DEADLINE

    parser = argparse.ArgumentParser(
        description="Drive the real HTTPS Serverware portal through deterministic Google and X OAuth",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--screenshots-dir",
        type=Path,
        help="refresh the canonical portal, approval, OAuth, and policy screenshots",
    )
    parser.add_argument(
        "--decision-gate-binary",
        type=Path,
        default=ROOT
        / "data-plane"
        / "decision-gate-rs"
        / "target"
        / "debug"
        / "serverware-decision-gate",
    )
    parser.add_argument(
        "--response-proof-fixture",
        type=Path,
        default=ROOT
        / "data-plane"
        / "decision-gate-rs"
        / "target"
        / "debug"
        / "serverware-response-proof-fixture",
    )
    parser.add_argument(
        "--same-journey-host-python",
        type=Path,
        default=(
            Path(value)
            if (value := os.getenv("SERVERWARE_BROWSER_SAME_JOURNEY_PYTHON"))
            else None
        ),
        help="exact prebuilt host-venv interpreter used for the synchronous callback",
    )
    parser.add_argument(
        "--same-journey-host-python-sha256",
        help="caller-pinned digest of the prebuilt host-venv interpreter",
    )
    parser.add_argument(
        "--same-journey-host-entrypoint",
        type=Path,
        help="exact prebuilt serverware-enrollment entrypoint recorded in the host identity",
    )
    parser.add_argument(
        "--same-journey-host-entrypoint-sha256",
        help="caller-pinned digest of the prebuilt enrollment entrypoint",
    )
    parser.add_argument(
        "--same-journey-callback-script",
        type=Path,
        default=(
            Path(value)
            if (value := os.getenv("SERVERWARE_BROWSER_SAME_JOURNEY_VERIFIER"))
            else None
        ),
        help="exact verify_agent_trust_same_journey.py callback script",
    )
    parser.add_argument(
        "--same-journey-callback-script-sha256",
        help="caller-pinned digest of the callback script",
    )
    parser.add_argument(
        "--same-journey-host-identity",
        type=Path,
        default=(
            Path(value)
            if (value := os.getenv("SERVERWARE_BROWSER_PREBUILT_HOST_IDENTITY"))
            else None
        ),
        help="checksum-closed identity recorded by the prebuilt host interpreter",
    )
    parser.add_argument(
        "--same-journey-host-identity-sha256",
        help="caller-pinned digest of the exact host identity file",
    )
    parser.add_argument(
        "--same-journey-artifact-manifest",
        type=Path,
        default=(
            Path(value)
            if (value := os.getenv("SERVERWARE_BROWSER_PREBUILT_BUILD_MANIFEST"))
            else None
        ),
        help="frozen consolidated build-artifact manifest",
    )
    parser.add_argument(
        "--same-journey-artifact-manifest-sha256",
        help="caller-pinned digest of the consolidated artifact manifest",
    )
    parser.add_argument(
        "--frozen-source-tree-sha256",
        help=(
            "caller-supplied frozen source-tree digest; this journey records but "
            "does not independently authorize or reproduce it"
        ),
    )
    parser.add_argument(
        "--same-journey-secure-instructions-out",
        type=Path,
        default=(
            Path(value)
            if (
                value := os.getenv(
                    "SERVERWARE_BROWSER_SECURE_INSTRUCTIONS_OUT"
                )
            )
            else None
        ),
        help="persist the exact authenticated instructions outside the journey tempdir",
    )
    parser.add_argument(
        "--same-journey-result-out",
        type=Path,
        default=(
            Path(value)
            if (
                value := os.getenv(
                    "SERVERWARE_BROWSER_SAME_JOURNEY_RESULT_OUT"
                )
            )
            else None
        ),
        help="persist the verified same-journey result outside the journey tempdir",
    )
    args = parser.parse_args()
    _JOURNEY_DEADLINE = time.monotonic() + JOURNEY_TIMEOUT_SECONDS
    if hasattr(signal, "setitimer"):
        def expire_journey(_signum: int, _frame: Any) -> None:
            raise TimeoutError("browser journey exceeded its absolute deadline")

        signal.signal(signal.SIGALRM, expire_journey)
        signal.setitimer(signal.ITIMER_REAL, JOURNEY_TIMEOUT_SECONDS)
    screenshots_dir = args.screenshots_dir.resolve() if args.screenshots_dir else None
    decision_gate_binary = args.decision_gate_binary.resolve()
    response_proof_fixture = args.response_proof_fixture.resolve()
    _require(
        decision_gate_binary.is_file(),
        f"build the host decision gate before this journey: {decision_gate_binary}",
    )
    _require(
        response_proof_fixture.is_file(),
        f"build the response proof fixture before this journey: {response_proof_fixture}",
    )
    decision_gate_digest = _sha256_path(decision_gate_binary)
    response_proof_fixture_digest = _sha256_path(response_proof_fixture)
    same_journey_contract = _load_same_journey_contract(
        args,
        decision_gate_binary=decision_gate_binary,
        response_proof_fixture=response_proof_fixture,
    )
    _require(
        decision_gate_digest == same_journey_contract["decisionGateSha256"]
        and response_proof_fixture_digest
        == same_journey_contract["responseProofFixtureSha256"],
        "live Rust artifacts differ from the consolidated build manifest",
    )
    _require(
        Path(os.path.abspath(sys.executable))
        == same_journey_contract["browserPython"],
        "portal browser harness is not using the prepared browser interpreter",
    )
    if screenshots_dir is not None:
        screenshots_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="serverware-oauth-contract-"
    ) as raw_contract_tmp:
        _assert_redirect_validation(Path(raw_contract_tmp))
    with tempfile.TemporaryDirectory(prefix="serverware-browser-oauth-") as raw_tmp:
        tmp = Path(raw_tmp)
        listener = _reserve_https_socket()
        portal_port = int(listener.getsockname()[1])
        public_url = f"https://localhost:{portal_port}"
        simulator: OAuthProviderSimulator | None = None
        npm_registry: _NpmRegistryFixture | None = None
        portal: _UvicornThread | None = None
        original_providers: Any = None
        original_request_bytes: Any = None
        original_reconciler: Any = None
        oauth_module: Any = None
        app_module: Any = None
        fixture_facts: dict[str, Any] | None = None
        result: dict[str, Any] | None = None
        try:
            _assert_host_callback_origin_resolution(public_url)
            simulator = OAuthProviderSimulator(
                tmp / "provider",
                redirect_base_url=public_url,
                authorization_token_ttl_seconds=300,
            )
            simulator.start()
            _assert_simulator_contract(simulator, public_url)
            npm_registry = _NpmRegistryFixture(simulator)
            npm_registry.start()
            data_dir = tmp / "serverware"
            _configure_environment(
                data_dir,
                public_url,
                simulator,
                decision_gate_digest,
            )
            fixture_facts = _write_local_fixture_attestation_documents(
                data_dir,
                decision_gate_digest=decision_gate_digest,
                response_proof_fixture_digest=response_proof_fixture_digest,
                contract=same_journey_contract,
            )

            from serverware import app as app_module
            from serverware import oauth as oauth_module
            from fastapi import HTTPException, Request
            from serverware.auth import AdminIdentity, require_admin

            identities = {
                "operator": AdminIdentity(
                    "user:operator",
                    frozenset(
                        {
                            "admin",
                            "approver",
                            "auditor",
                            "policy_author",
                            "policy_publisher",
                            "credential_owner",
                            "attestation_operator",
                            "attestation_reviewer",
                        }
                    ),
                    "browser-test-actor",
                ),
                "reviewer": AdminIdentity(
                    "user:demo",
                    frozenset({"admin", "approver", "auditor", "credential_owner"}),
                    "browser-test-actor",
                ),
            }

            def test_require_admin(request: Request) -> AdminIdentity:
                identity = identities.get(request.headers.get("X-Test-Actor", ""))
                if identity is None:
                    raise HTTPException(
                        status_code=401, detail="recognized browser actor required"
                    )
                return identity

            test_require_admin.__annotations__["request"] = Request
            app_module.app.dependency_overrides[require_admin] = test_require_admin

            original_providers = oauth_module._providers
            configured = original_providers()
            google_provider = replace(
                configured["google"],
                **simulator.provider_urls("google"),
            )
            x_provider = replace(configured["x"], **simulator.provider_urls("x"))
            oauth_module._providers = lambda: {
                "google": google_provider,
                "x": x_provider,
                "twitter": x_provider,
            }

            original_request_bytes = oauth_module.request_bytes

            def trusted_provider_request(request: Any, **kwargs: Any) -> Any:
                kwargs["context"] = simulator.client_ssl_context
                return original_request_bytes(request, **kwargs)

            oauth_module.request_bytes = trusted_provider_request
            original_reconciler = app_module._start_oauth_revocation_reconciler
            app_module._start_oauth_revocation_reconciler = lambda: None

            portal = _UvicornThread(app_module.app, listener, simulator)
            portal.start()
            result = _run_browser_journey(
                public_url,
                data_dir,
                simulator,
                npm_registry,
                screenshots_dir,
                decision_gate_binary,
                decision_gate_digest,
                response_proof_fixture,
                same_journey_contract,
                fixture_facts,
            )
        finally:
            primary_error = sys.exc_info()[1]
            cleanup_actions: list[tuple[str, Callable[[], None]]] = []
            if portal is not None:
                cleanup_actions.append(("HTTPS portal", portal.close))
            cleanup_actions.append(("HTTPS listener", listener.close))
            if oauth_module is not None:
                if original_providers is not None:
                    cleanup_actions.append(
                        (
                            "OAuth provider patch",
                            lambda: setattr(
                                oauth_module,
                                "_providers",
                                original_providers,
                            ),
                        )
                    )
                if original_request_bytes is not None:
                    cleanup_actions.append(
                        (
                            "OAuth request patch",
                            lambda: setattr(
                                oauth_module,
                                "request_bytes",
                                original_request_bytes,
                            ),
                        )
                    )
            if app_module is not None and original_reconciler is not None:
                cleanup_actions.append(
                    (
                        "OAuth reconciler patch",
                        lambda: setattr(
                            app_module,
                            "_start_oauth_revocation_reconciler",
                            original_reconciler,
                        ),
                    )
                )
            if app_module is not None:
                cleanup_actions.append(
                    (
                        "FastAPI dependency overrides",
                        app_module.app.dependency_overrides.clear,
                    )
                )
            if npm_registry is not None:
                cleanup_actions.append(("npm registry fixture", npm_registry.close))
            if simulator is not None:
                cleanup_actions.append(("OAuth simulator", simulator.close))
            cleanup_errors = _cleanup_actions(cleanup_actions)
            _raise_cleanup_errors(
                primary_error,
                cleanup_errors,
                label="browser harness and cleanup failed",
            )
        _require(result is not None, "browser journey completed without a result")
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
