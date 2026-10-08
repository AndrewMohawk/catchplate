"""Explicit, process-local activation for the isolated synthetic test deployment.

This is not an authority profile. The normal runner never activates it and
production images/channels refuse it. Persistent data must belong to a sandbox
from its first creation; existing application or pilot databases are not adopted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import threading

_check_lock = threading.Lock()

SCHEMA = "serverware.developmentSandbox/v1"
MARKER = ".serverware-development-sandbox.json"
_pid: int | None = None
_identity: tuple[int, int] | None = None
_configuration: tuple[tuple[str, str], ...] | None = None
_directory: Path | None = None
_directory_identity: tuple[int, ...] | None = None
_marker_identity: tuple[int, ...] | None = None
_STARTUP_PID = "SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID"
_MARKER_BYTES = (json.dumps({"schema": SCHEMA, "syntheticOnly": True}, sort_keys=True) + "\n").encode("ascii")
_EXPECTED = {
    "SERVERWARE_DEVELOPMENT_SANDBOX": "1", "SERVERWARE_RELEASE_CHANNEL": "dev",
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
    "SERVERWARE_METADATA_STORE_BACKEND": "sqlite", "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
    "SERVERWARE_GRANT_STORE_BACKEND": "sqlite", "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
}
_FIXED_PATHS = {
    "SERVERWARE_CA_INSTALL_SESSIONS": "ca-install-sessions.json",
    "SERVERWARE_KEY_RELEASE_STATE": "key-release-state.json",
    "SERVERWARE_TEE_QUOTE_SIGNING_KEY": "dev-tee-quote-ed25519.pem",
    "SERVERWARE_RESPONSE_SIGNING_KEY": "response-signing-ed25519.pem",
    "SERVERWARE_POLICY_BUNDLE": "policy-bundle.json",
    "SERVERWARE_POLICY_CANARY_STATE": "policy-canary-state.json",
    "SERVERWARE_POLICY_CANARY_BUNDLE": "policy-canary-bundle.json",
    "SERVERWARE_POLICY_SIGNING_KEY": "policy-signing-ed25519.pem",  # gitleaks:allow (filename only)
    "SERVERWARE_POLICY_SIGNING_PUBLIC_KEY": "policy-signing-ed25519.pub.pem",
    "SERVERWARE_RBAC_BINDINGS": "rbac-bindings.json",
    "SERVERWARE_RELEASE_PROVENANCE": "release-provenance.json",
    "SERVERWARE_IMAGE_SIGNATURES": "image-signatures.json",
    "SERVERWARE_DECISION_GATE_CA_CERT": "decision-gate-ca-cert.pem",
    "SERVERWARE_DECISION_GATE_CA_KEY": "decision-gate-ca-key.pem",
    "SERVERWARE_OAUTH_STATE_PATH": "oauth-states.json",
    "SERVERWARE_WEBAUTHN_TRUST_ROOTS": "webauthn-trust-roots.pem",
    "SERVERWARE_WEBAUTHN_TRUST_BUNDLE": "webauthn-trust-bundle.json",
    "SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE": "webauthn-trust-bundle-state.json",
    "SERVERWARE_WEBAUTHN_TRUST_SIGNING_KEY": "webauthn-trust-signing-ed25519.pem",
    "SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY": "webauthn-trust-signing-ed25519.pub.pem",
}
_TOKEN_FILES = {"SERVERWARE_" + name + "_FILE" for name in (
    "ADMIN_TOKEN", "DATA_PLANE_CREDENTIAL_LEASE_TOKEN", "DATA_PLANE_AUDIT_TOKEN",
    "DATA_PLANE_GRANT_CONSUME_TOKEN", "DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
    "DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN", "DATA_PLANE_MANAGEMENT_TOKEN", "AUDIT_ANCHOR_TOKEN",
)}


def _environment() -> tuple[tuple[str, str], ...]:
    return tuple(sorted((name, value) for name, value in os.environ.items()
                        if name.startswith("SERVERWARE_") and name != _STARTUP_PID))


def _validate_environment() -> Path:
    # Inspect raw selections BEFORE config imports can open credential files.
    if os.getenv("SERVERWARE_PRODUCTION_IMAGE") == "1" or any(
            os.getenv(name) != value for name, value in _EXPECTED.items()):
        raise RuntimeError("sandbox requires explicit non-production local-key SQLite configuration")
    directory = Path(os.getenv("SERVERWARE_DATA_DIR", ""))
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        raise RuntimeError("sandbox requires a dedicated absolute data directory")
    forbidden = ("SERVERWARE_AUTHORITY_", "SERVERWARE_POLICY_AUTHORITY_", "SERVERWARE_NITRO_",
        "SERVERWARE_AWS_", "SERVERWARE_CONTROL_PLANE_CUSTODY_", "SERVERWARE_CONTROL_PLANE_ENROLLMENT_",
        "SERVERWARE_GOOGLE_", "SERVERWARE_X_OAUTH_", "SERVERWARE_TWITTER_OAUTH_", "SERVERWARE_OIDC_",
        "SERVERWARE_WEBAUTHN_RECOVERY_", "SERVERWARE_SETUP_ENROLLMENT_", "SERVERWARE_SETUP_HARDWARE_",
        "SERVERWARE_SETUP_FINAL_")
    disabled = {"SERVERWARE_OIDC_ENABLED", "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED",
                "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED", "SERVERWARE_WEBAUTHN_RECOVERY_ENABLED"}
    for name, value in _environment():
        if not value or name in disabled and value == "0":
            continue
        if name in _FIXED_PATHS:
            if Path(value) != directory / _FIXED_PATHS[name]:
                raise RuntimeError("sandbox state and signing paths must use dedicated data defaults")
            continue
        if name in _TOKEN_FILES:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts or not path.is_relative_to("/run"):
                raise RuntimeError("sandbox service token files must be explicit private /run files")
            continue
        if (name.startswith(forbidden) or name.endswith(("_FD", "_DSN", "_COMMAND", "_FILE", "_PATH"))
                or "_FD_" in name or "_COMMAND_" in name
                or name in {"SERVERWARE_MASTER_KEY", "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
                            "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", "SERVERWARE_SCHEMA_DIR"}):
            raise RuntimeError("sandbox cannot inherit provider, external key or measured authority configuration")
    if os.getenv("SERVERWARE_TEE_QUOTE_PROVIDER", "dev-signed-quote") != "dev-signed-quote" or os.getenv(
            "SERVERWARE_TEE_PLATFORM", "none-dev") != "none-dev":
        raise RuntimeError("sandbox requires the explicitly local development quote profile")
    return directory


def _file_identity(info) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink


def _open_directory(path: Path, *, create: bool = False) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("sandbox data directory must be private and owned by its runtime user")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_marker(directory: int) -> tuple[int, ...]:
    descriptor = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_size != len(_MARKER_BYTES) or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                or os.read(descriptor, len(_MARKER_BYTES) + 1) != _MARKER_BYTES):
            raise RuntimeError("sandbox marker does not identify private synthetic test data")
        return _file_identity(info)
    finally:
        os.close(descriptor)


def active() -> bool:
    if _pid is None:
        return False
    if (_pid != os.getpid() or _identity != (os.geteuid(), os.getegid())
            or _configuration != _environment()
            or os.getenv(_STARTUP_PID) not in {None, str(_pid)}):
        raise RuntimeError("development sandbox process configuration changed")
    descriptor = _open_directory(_directory)
    try:
        if (_file_identity(os.fstat(descriptor))[:4] != _directory_identity
                or _read_marker(descriptor) != _marker_identity):
            raise RuntimeError("development sandbox data identity changed")
    finally:
        os.close(descriptor)
    return True


def activate() -> None:
    global _pid, _identity, _configuration, _directory, _directory_identity, _marker_identity
    if _pid is not None:
        if active():
            return
    directory = _validate_environment()
    from serverware import config
    if (config.PRODUCTION_IMAGE or config.RELEASE_CHANNEL != "dev" or config.DATA_DIR != directory
            or config.METADATA_STORE_BACKEND != "sqlite" or config.AUDIT_STORE_BACKEND != "sqlite"
            or config.GRANT_STORE_BACKEND != "sqlite" or config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED
            or config.KEY_RELEASE_REQUIRED):
        raise RuntimeError("sandbox requires explicit non-production local-key SQLite configuration")
    for name, filename in _FIXED_PATHS.items():
        attribute = name.removeprefix("SERVERWARE_")
        if not attribute.endswith("_PATH"):
            attribute += "_PATH"
        if getattr(config, attribute) != directory / filename:
            raise RuntimeError("sandbox imported configuration differs from its dedicated data defaults")
    descriptor = _open_directory(directory, create=True)
    try:
        try:
            marker_identity = _read_marker(descriptor)
        except FileNotFoundError:
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise RuntimeError("sandbox refuses existing unmarked application data")
            marker = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=descriptor)
            try:
                if os.write(marker, _MARKER_BYTES) != len(_MARKER_BYTES):
                    raise RuntimeError("sandbox marker write was incomplete")
                os.fsync(marker)
            finally:
                os.close(marker)
            os.fsync(descriptor)
            marker_identity = _read_marker(descriptor)
        _directory_identity = _file_identity(os.fstat(descriptor))[:4]
        _marker_identity = marker_identity
    finally:
        os.close(descriptor)
    _directory = directory
    _identity = os.geteuid(), os.getegid()
    _configuration = _environment()
    _pid = os.getpid()


def request_allowed(method: str, path: str) -> bool:
    """OAuth/OIDC callbacks can mutate on GET; they are never sandbox flows."""
    if path.startswith(("/api/auth/oidc/", "/api/oauth/callback/")):
        return False
    return method.upper() in {"GET", "HEAD", "OPTIONS"} or mutation_allowed(path)


def bootstrap() -> None:
    """Install the fixed synthetic policy and demo data, never pilot authority."""
    if not active():
        raise RuntimeError("sandbox bootstrap requires the dedicated runner")
    from serverware import config, policy_bundle, development_sandbox_store

    signed = policy_bundle.sign_policy_bundle(policy_bundle.demo_policy_bundle())
    development_sandbox_store.commission_policy(signed)
    raw = policy_bundle.canonical_json(signed).encode("utf-8")
    destination = config.POLICY_BUNDLE_PATH
    if destination.parent != config.DATA_DIR:
        raise RuntimeError("sandbox policy must remain in its dedicated data directory")
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != raw:
            raise RuntimeError("sandbox policy changed; refusing silent replacement")
    else:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(descriptor, raw) != len(raw):
                raise RuntimeError("sandbox policy write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    from serverware import app, db
    if db.get_credential("cred-demo-bearer") is None:
        app.seed_demo(_=None)


def status() -> dict:
    if not active():
        raise RuntimeError("development sandbox is not active")
    return {"schema": SCHEMA, "mode": "synthetic-development", "syntheticOnly": True,
        "productionReady": False, "hardwareVerified": False, "persistent": True,
        "allowedUpstreams": ["demo-upstream"], "commissioningRequired": False}


def mutation_allowed(path: str) -> bool:
    """No real provider, enrollment, authority or arbitrary secret mutations."""
    return path in {"/api/sandbox/check", "/api/demo/seed",
        "/api/data-plane/credential-leases", "/api/data-plane/audit"}


def run_proxy_check() -> dict:
    if not active():
        raise RuntimeError("sandbox proxy check requires the dedicated runner")
    if not _check_lock.acquire(blocking=False):
        return {"ok": False, "error": "A sandbox check is already running."}
    try:
        from scripts.check_development_sandbox import run_checks
        from serverware.config import EXPECTED_DATA_PLANE_BINARY_DIGEST
        return run_checks(expected_binary_sha256=EXPECTED_DATA_PLANE_BINARY_DIGEST)
    finally:
        _check_lock.release()


def decorate_portal(document: str) -> str:
    if not active():
        return document
    # Render a purpose-built console; never run the hidden production setup UI
    # or its background polling in the explicit synthetic profile.
    from serverware.sandbox_portal import render
    return render()
