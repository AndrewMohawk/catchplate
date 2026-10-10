"""Explicit local operator demo; never production or native custody authority."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from serverware.development_sandbox import (
    _FIXED_PATHS, _TOKEN_FILES, _environment, _file_identity, _open_directory,
)

SCHEMA = "serverware.operatorDemo/v1"
MARKER = ".serverware-operator-demo.json"
MARKER_BYTES = b'{"schema": "serverware.operatorDemo/v1", "syntheticOnly": false}\n'
_pid = None
_configuration = None
_directory = None
_identity = None
_marker_identity = None
_upstreams = ()
_fixture_cidrs = ()
_proxy_url = None


def origin(value: str, *, target: bool = False) -> tuple[str, str]:
    """Canonical HTTPS origins and literal paths, with no wildcard or URL credentials."""
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("invalid HTTPS destination")
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    try:
        port = parsed.port or 443
    except ValueError:
        raise ValueError("invalid HTTPS destination") from None
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or host != host.lower()
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
            or ".." in host or host.endswith((".localhost", ".local", ".internal", ".invalid", ".test"))
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))):
        raise ValueError("invalid HTTPS destination")
    if host == "demo-upstream" and port == 8443:
        canonical = "https://demo-upstream:8443"
    else:
        if "." not in host or port != 443:
            raise ValueError("public HTTPS origins require port 443")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("literal IP destinations are unavailable")
        canonical = "https://" + host
    path = parsed.path or "/"
    if not target and path != "/":
        raise ValueError("upstream allowlist must contain origins only")
    if (not path.startswith("/") or any(c in path for c in "%*{}\\")
            or any(segment in {".", ".."} for segment in path.split("/"))):
        raise ValueError("destination requires an exact literal path")
    accepted = {canonical + path} if target else {canonical, canonical + "/"}
    if port == 443:
        accepted.add(canonical + ":443" + (path if target else ""))
        if not target:
            accepted.add(canonical + ":443/")
    if value not in accepted:
        raise ValueError("destination must use canonical HTTPS spelling")
    return canonical, path


def _marker(fd: int):
    handle = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(MARKER_BYTES)
                or os.read(handle, len(MARKER_BYTES) + 1) != MARKER_BYTES):
            raise RuntimeError("operator demo marker refused")
        return _file_identity(info)
    finally:
        os.close(handle)


def active() -> bool:
    if _pid is None:
        return False
    if (_pid != os.getpid() or _configuration != _environment()
            or os.getenv("SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID") not in {None, str(_pid)}):
        raise RuntimeError("operator demo process configuration changed")
    fd = _open_directory(_directory)
    try:
        if _file_identity(os.fstat(fd))[:4] != _identity or _marker(fd) != _marker_identity:
            raise RuntimeError("operator demo private data identity changed")
    finally:
        os.close(fd)
    return True


def activate() -> None:
    global _pid, _configuration, _directory, _identity, _marker_identity, _upstreams, _fixture_cidrs, _proxy_url
    if _pid is not None:
        active()
        return
    expected = {
        "SERVERWARE_OPERATOR_DEMO": "1", "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite", "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite", "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    }
    if (any(os.getenv(k) != v for k, v in expected.items())
            or os.getenv("SERVERWARE_PRODUCTION_IMAGE") == "1"
            or os.getenv("SERVERWARE_DEVELOPMENT_SANDBOX", "0") != "0"):
        raise RuntimeError("operator demo requires separate explicit non-production configuration")
    directory = Path(os.getenv("SERVERWARE_DATA_DIR", ""))
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        raise RuntimeError("operator demo requires a dedicated absolute data directory")
    from serverware import operator_catalog_oauth_profile as google_profile
    google_selected = google_profile.selected()
    forbidden = ("SERVERWARE_AUTHORITY_", "SERVERWARE_POLICY_AUTHORITY_", "SERVERWARE_NATIVE_",
        "SERVERWARE_NITRO_", "SERVERWARE_AWS_", "SERVERWARE_CONTROL_PLANE_CUSTODY_",
        "SERVERWARE_CONTROL_PLANE_ENROLLMENT_", "SERVERWARE_WORKLOAD_IDENTITY_",
        "SERVERWARE_GOOGLE_", "SERVERWARE_X_OAUTH_", "SERVERWARE_TWITTER_OAUTH_", "SERVERWARE_OIDC_",
        "SERVERWARE_WEBAUTHN_RECOVERY_", "SERVERWARE_SETUP_")
    disabled = {"SERVERWARE_OIDC_ENABLED", "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED",
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED", "SERVERWARE_WEBAUTHN_RECOVERY_ENABLED"}
    for name, value in _environment():
        if not value or name in disabled and value == "0":
            continue
        if google_selected and name in google_profile.GOOGLE_CONFIGURATION_KEYS:
            continue  # Strict preflight runs before config reads the secret file.
        if name in _FIXED_PATHS:
            if Path(value) != directory / _FIXED_PATHS[name]:
                raise RuntimeError("operator demo state paths must remain in its private directory")
            continue
        if name in _TOKEN_FILES:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts or not path.is_relative_to("/run"):
                raise RuntimeError("operator demo service token files must be private /run files")
            continue
        if (name.startswith(forbidden) or name.endswith(("_FD", "_DSN", "_COMMAND", "_FILE", "_PATH"))
                or "_FD_" in name or "_COMMAND_" in name
                or name in {"SERVERWARE_MASTER_KEY", "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
                            "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", "SERVERWARE_SCHEMA_DIR"}):
            raise RuntimeError("operator demo refuses provider, external key or native authority configuration")
    raw = json.loads(os.environ.get("SERVERWARE_OPERATOR_DEMO_UPSTREAMS", "null"))
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise RuntimeError("operator demo requires 1-16 explicitly allowed HTTPS origins")
    upstreams = tuple(origin(item)[0] for item in raw)
    if len(set(upstreams)) != len(upstreams):
        raise RuntimeError("operator demo upstream origins must be unique")
    fixture = json.loads(os.getenv("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", "[]"))
    if not isinstance(fixture, list) or len(fixture) > 1:
        raise RuntimeError("operator demo fixture requires at most one pinned host CIDR")
    if bool(fixture) != ("https://demo-upstream:8443" in upstreams):
        raise RuntimeError("operator demo fixture requires its explicit pinned host CIDR")
    for item in fixture:
        network = ipaddress.ip_network(item, strict=True)
        address = network.network_address
        private = tuple(ipaddress.ip_network(cidr) for cidr in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"))
        if (str(network) != item or network.prefixlen != network.max_prefixlen
                or not any(address.version == candidate.version and address in candidate for candidate in private)):
            raise RuntimeError("operator demo fixture CIDR must pin one private or loopback host")
    proxy = os.environ.get("SERVERWARE_OPERATOR_DEMO_PROXY_URL", "")
    proxy_origin, _ = origin(proxy)
    from serverware import config
    if google_selected:
        google_profile.validate_imported_configuration(config)
    if (config.PRODUCTION_IMAGE or config.RELEASE_CHANNEL != "dev" or config.DATA_DIR != directory
            or config.METADATA_STORE_BACKEND != "sqlite" or config.AUDIT_STORE_BACKEND != "sqlite"
            or config.GRANT_STORE_BACKEND != "sqlite" or config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED
            or config.KEY_RELEASE_REQUIRED):
        raise RuntimeError("operator demo imported configuration differs")
    for name, filename in _FIXED_PATHS.items():
        attribute = name.removeprefix("SERVERWARE_")
        if not attribute.endswith("_PATH"):
            attribute += "_PATH"
        if getattr(config, attribute) != directory / filename:
            raise RuntimeError("operator demo imported state paths differ")
    if config.TEE_QUOTE_PROVIDER != "dev-signed-quote" or config.TEE_PLATFORM != "none-dev":
        raise RuntimeError("operator demo requires local development quote profile")
    fd = _open_directory(directory, create=True)
    try:
        try:
            identity = _marker(fd)
        except FileNotFoundError:
            with os.scandir(fd) as entries:
                if next(entries, None) is not None:
                    raise RuntimeError("operator demo refuses existing unmarked data")
            marker = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                if os.write(marker, MARKER_BYTES) != len(MARKER_BYTES):
                    raise RuntimeError("operator demo marker write incomplete")
                os.fsync(marker)
            finally:
                os.close(marker)
            os.fsync(fd)
            identity = _marker(fd)
        _identity = _file_identity(os.fstat(fd))[:4]
        _marker_identity = identity
    finally:
        os.close(fd)
    _directory, _upstreams, _fixture_cidrs, _proxy_url = directory, upstreams, tuple(fixture), proxy_origin
    _configuration, _pid = _environment(), os.getpid()


def settings() -> dict:
    if not active():
        raise RuntimeError("operator demo is not active")
    return {"allowed_upstreams": list(_upstreams), "fixture_cidrs": list(_fixture_cidrs), "proxy_url": _proxy_url}


def request_allowed(method: str, path: str) -> bool:
    from serverware import operator_catalog_oauth_profile as google_profile
    if path == "/api/operator-demo/oauth/google/setup":
        return method.upper() in {"GET", "POST"}
    if google_profile.selected():
        if path == "/api/oauth/callback/google":
            google_profile.require_profile()
            return method.upper() == "GET"
        if path == "/api/operator-demo/oauth/google/start":
            google_profile.require_profile()
            return method.upper() == "POST"
        if path == "/api/operator-demo/oauth/google/reauthorization-storage":
            google_profile.require_profile()
            return method.upper() in {"GET", "POST"}
    if path.startswith(("/api/auth/oidc/", "/api/oauth/callback/")):
        return False
    mutations = {
        "/api/operator-demo/connections", "/api/operator-demo/connections/revoke",
        "/api/operator-demo/credentials", "/api/operator-demo/credentials/revoke",
        "/api/operator-demo/credentials/replace-key", "/api/operator-demo/credentials/github-token",
        "/api/operator-demo/applications", "/api/operator-demo/applications/revoke",
        "/api/operator-demo/applications/proxy-authentication",
        "/api/operator-demo/applications/rotate-token", "/api/operator-demo/access-rules",
        "/api/operator-demo/access-rules/revoke", "/api/operator-demo/access-rules/gmail-read",
        "/api/operator-demo/access-rules/github",
        "/api/operator-demo/oauth/google/disconnect", "/api/operator-demo/oauth/google/reauthorize",
        "/api/operator-demo/oauth/google/setup/cancel",
        "/api/operator-demo/notifications/settings", "/api/operator-demo/notifications/test",
        "/api/data-plane/credential-leases", "/api/data-plane/audit"}
    if path in mutations:
        return method.upper() == "POST"
    return method.upper() in {"GET", "HEAD", "OPTIONS"}


def bootstrap() -> None:
    from serverware import operator_demo_store
    operator_demo_store.initialize()
