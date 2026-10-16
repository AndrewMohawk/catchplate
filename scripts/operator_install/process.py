"""Bounded local commands with no raw subprocess-error or input disclosure."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

from .config import InstallError, parse_json


def _failure(stdout=b"", stderr=b"", *, timed_out=False) -> InstallError:
    """Retain only bounded command output, never its arguments, input or env."""
    message = "A required local command timed out" if timed_out else "A required local command failed"
    try:
        descriptor, path = tempfile.mkstemp(prefix="serverware-standalone-command-", suffix=".log")
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            for heading, value in ((b"stdout (bounded tail)\n", stdout), (b"\nstderr (bounded tail)\n", stderr)):
                output.write(heading)
                output.write((value if type(value) is bytes else b"")[-262144:])
        error = InstallError(message + "; private diagnostics were retained. Existing state was not reset.")
        error.diagnostic_path = path
        return error
    except OSError:
        return InstallError(message + "; private diagnostics could not be retained. Existing state was not reset.")


def run(args: list[str], *, input: bytes | None = None, timeout: int = 30) -> bytes:
    try:
        completed = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8"})
    except subprocess.TimeoutExpired as error:
        raise _failure(error.stdout, error.stderr, timed_out=True) from None
    except OSError:
        raise _failure(stderr=b"The required executable could not be started.\n") from None
    if completed.returncode != 0 or len(completed.stdout) > 4 * 1024 * 1024:
        raise _failure(completed.stdout, completed.stderr)
    return completed.stdout


def require_host() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise InstallError("Standalone lifecycle commands require root on Linux to preserve private state ownership.")
    if any(os.environ.get(key) for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")):
        raise InstallError("Use the local rootful Docker daemon without remote Docker environment overrides.")
    host = parse_json(run(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], timeout=10))
    if host != "unix:///var/run/docker.sock":
        raise InstallError("Standalone bind mounts require the local rootful Docker socket.")
    security = parse_json(run(["docker", "info", "--format", "{{json .SecurityOptions}}"], timeout=10))
    if type(security) is not list or any(type(item) is not str or "rootless" in item for item in security):
        raise InstallError("Standalone bind mounts require rootful Docker with UID 10001 ownership.")
    run(["docker", "compose", "version", "--short"], timeout=10)
