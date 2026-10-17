"""Explicit start/status/stop of one pinned, independently owned installation."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
import time

from . import process, state
from .config import InstallError, check_path, parse_json, read_file

SERVICES = ("catchplate", "decision-gate-rs", "edge")
LABEL = "io.catchplate.installation"


def _identifiers(raw: bytes) -> list[str]:
    try:
        values = raw.decode("ascii").split()
        if len(values) > 32 or any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in values):
            raise ValueError()
        return values
    except (UnicodeError, ValueError):
        raise InstallError("Docker returned an unexpected resource inventory; no resources were adopted.") from None


def resources(project: str, instance_id: str | None) -> None:
    """Refuse project-name collisions, including resources not in this manifest."""
    selector = "label=com.docker.compose.project=" + project
    queries = (("container", ["docker", "ps", "--all", "--quiet", "--no-trunc", "--filter", selector], ".Config.Labels"),
        ("network", ["docker", "network", "ls", "--quiet", "--no-trunc", "--filter", selector], ".Labels"))
    for kind, command, path in queries:
        for identifier in _identifiers(process.run(command, timeout=10)):
            if instance_id is None:
                raise InstallError("The selected Docker project already owns resources; choose a new project name.")
            labels = parse_json(process.run(["docker", kind, "inspect", "--format", "{{json " + path + "}}", identifier], timeout=10))
            if type(labels) is not dict or labels.get(LABEL) != instance_id or labels.get("com.docker.compose.project") != project:
                raise InstallError("A Docker resource has different installation ownership; nothing was started or stopped.")
            role = labels.get("com.docker.compose.service" if kind == "container" else "com.docker.compose.network")
            if role not in (SERVICES if kind == "container" else ("control", "outbound")):
                raise InstallError("The Docker project contains an unexpected resource role; no resources were adopted.")
    if process.run(["docker", "volume", "ls", "--quiet", "--filter", selector], timeout=10).strip():
        raise InstallError("This project has unexpected Docker volumes; existing resources were not adopted.")


def _compose(manifest: dict, *args: str, timeout=30) -> bytes:
    config = manifest["config"]
    path = Path(config["state_dir"]) / "compose.json"
    if state.digest(read_file(path, maximum=4 * 1024 * 1024, private=True)) != manifest["files"]["compose.json"]:
        raise InstallError("The installed Compose model changed; lifecycle action was refused.")
    return process.run(["docker", "compose", "--project-name", config["project_name"],
        "--file", str(path), *args], timeout=timeout)


def _service_status(manifest, service) -> dict:
    identifiers = _identifiers(_compose(manifest, "ps", "--all", "--quiet", service))
    if not identifiers:
        return {"state": "absent", "health": "unavailable"}
    if len(identifiers) != 1:
        raise InstallError("An installation service has unexpected replicas; no service was replaced.")
    image = parse_json(process.run(["docker", "inspect", "--format", "{{json .Image}}", identifiers[0]], timeout=10))
    if image != manifest["config"]["edge_image" if service == "edge" else "paired_image"]:
        raise InstallError("A running service uses a different image; no container was replaced automatically.")
    value = parse_json(process.run(["docker", "inspect", "--format", "{{json .State}}", identifiers[0]], timeout=10))
    if type(value) is not dict or value.get("Status") not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}:
        raise InstallError("Docker service state is unavailable.")
    health = value.get("Health", {}).get("Status", "unavailable")
    if health not in {"starting", "healthy", "unhealthy", "unavailable"}:
        health = "unavailable"
    return {"state": value["Status"], "health": health}


def _tls_recovery_pending(state_dir: Path) -> bool:
    try:
        (state_dir / "tls-replacement.json").lstat()
    except FileNotFoundError:
        return False
    return True


def _pending_activation(state_dir: Path) -> None:
    if _tls_recovery_pending(state_dir):
        raise InstallError("A TLS replacement needs recovery; ordinary startup is blocked and retained state is preserved.")
    database = state_dir / "app-data/catchplate.sqlite3"
    check_path(database, missing_leaf=True)
    if not database.exists():
        if next((state_dir / "app-data").iterdir(), None) is not None:
            raise InstallError("Application state is incomplete; inspect it before startup, without resetting it.")
        return
    try:
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            for table in ("operator_google_setups", "operator_upstream_setups"):
                exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                if exists and connection.execute("SELECT 1 FROM " + table + " WHERE status='pending' LIMIT 1").fetchone():
                    raise InstallError("A prepared provider or destination change requires explicit deployment activation; retained state is preserved.")
            connection.rollback()
    except sqlite3.Error:
        raise InstallError("Pending configuration could not be checked safely; no lifecycle action was taken.") from None


def _publication_ready(manifest) -> bool:
    from .compose import PUBLICATION_FILES
    root = Path(manifest["config"]["state_dir"]) / "app-data"
    for name in PUBLICATION_FILES:
        path = root / name
        try:
            check_path(path)
            info = path.stat()
            if not path.is_file() or info.st_nlink != 1 or info.st_uid != 10001:
                return False
            if name != ".operator-publication.lock" and not 1 <= info.st_size <= 16 * 1024 * 1024:
                return False
        except (InstallError, FileNotFoundError):
            return False
    return True


def _service_failed(service: str, status: str) -> InstallError:
    if service not in SERVICES or status not in {"exited", "dead", "removing", "restarting"}:
        return InstallError("An installation service failed before readiness; inspect status and Docker service logs. State was preserved.")
    return InstallError(f"{service} is {status} before readiness; inspect status and this service's Docker logs. State was preserved; no later service was started.")


def _wait_healthy(manifest, service, deadline) -> None:
    while time.monotonic() < deadline:
        status = _service_status(manifest, service)
        if status == {"state": "running", "health": "healthy"}:
            if service != "catchplate" or _publication_ready(manifest):
                return
        if status["state"] in {"exited", "dead", "removing", "restarting"}:
            raise _service_failed(service, status["state"])
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise InstallError("Readiness timed out; no later service was started. Inspect status before retrying; state was preserved.")


def _pair_status(manifest) -> dict:
    value = parse_json(_compose(manifest, "exec", "-T", "catchplate", "python", "-B", "-m",
        "scripts.operator_install.runtime", "pair-status", timeout=10))
    if (type(value) is not dict or set(value) != {"ready", "policy_hash", "loaded_policy_hash"}
            or type(value["ready"]) is not bool
            or any(item is not None and (type(item) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", item))
                for item in (value["policy_hash"], value["loaded_policy_hash"]))):
        raise InstallError("The paired readiness response was not recognized.")
    return value


def start(state_dir: Path, timeout=120) -> dict:
    if type(timeout) is not int or not 5 <= timeout <= 600:
        raise InstallError("Readiness timeout must be between five and 600 seconds.")
    process.require_host()
    with state.instance_lock(state_dir):
        manifest = state.load_manifest(state_dir)
        resources(manifest["config"]["project_name"], manifest["instance_id"])
        _pending_activation(state_dir)
        deadline = time.monotonic() + timeout
        for service in SERVICES:
            current = _service_status(manifest, service)
            if current["state"] == "restarting":
                raise _service_failed(service, "restarting")
            if current["state"] not in {"running", "restarting"}:
                if time.monotonic() >= deadline:
                    raise InstallError("Readiness timed out before the next service; no later service was started.")
                _compose(manifest, "up", "--detach", "--no-deps", "--no-build", "--pull", "never", service,
                    timeout=max(1, min(30, int(deadline - time.monotonic()))))
            _wait_healthy(manifest, service, deadline)
            if service == "decision-gate-rs":
                while time.monotonic() < deadline:
                    pair = _pair_status(manifest)
                    if pair["ready"]:
                        break
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
                else:
                    raise InstallError("App and proxy policy are not aligned; the edge was not started. State was preserved.")
        return state.result(manifest, "start", "ready", services={name: _service_status(manifest, name) for name in SERVICES})


def stop(state_dir: Path) -> dict:
    process.require_host()
    with state.instance_lock(state_dir):
        # TLS recovery must not prevent a safe stop; Compose itself is still pinned.
        manifest = state.load_manifest(state_dir, verify_files=False)
        resources(manifest["config"]["project_name"], manifest["instance_id"])
        _compose(manifest, "stop", "--timeout", "30", "edge", "decision-gate-rs", "catchplate", timeout=100)
        services = {name: _service_status(manifest, name) for name in SERVICES}
        if any(value["state"] not in {"absent", "created", "exited", "dead"} for value in services.values()):
            raise InstallError("Not every service is confirmed stopped; inspect status before backing up retained state.")
        return state.result(manifest, "stop", "stopped", services=services)


def status(state_dir: Path) -> dict:
    process.require_host()
    with state.instance_lock(state_dir, shared=True):
        manifest = state.load_manifest(state_dir)
        resources(manifest["config"]["project_name"], manifest["instance_id"])
        services = {name: _service_status(manifest, name) for name in SERVICES}
        maintenance = _tls_recovery_pending(state_dir)
        ready = not maintenance and all(value == {"state": "running", "health": "healthy"} for value in services.values())
        # A GET-only pair observation cannot initialize schemas or start services.
        if ready:
            ready = _pair_status(manifest)["ready"]
        return state.result(manifest, "status", "maintenance_required" if maintenance else "ready" if ready else "not_ready",
            services=services)


def edge_running(manifest) -> bool:
    resources(manifest["config"]["project_name"], manifest["instance_id"])
    current = _service_status(manifest, "edge")["state"]
    if current == "running":
        return True
    if current in {"absent", "created", "exited"}:
        return False
    raise InstallError("The edge is changing state; inspect it before replacing TLS. No restart was attempted.")


def edge_reload(state_dir: Path, manifest, timeout=60) -> dict:
    """Caller owns instance_lock; never start a stopped edge or touch the pair."""
    if not edge_running(manifest):
        return {"reloaded": False}
    _compose(manifest, "restart", "--timeout", "15", "edge", timeout=30)
    _wait_healthy(manifest, "edge", time.monotonic() + timeout)
    return {"reloaded": True}
