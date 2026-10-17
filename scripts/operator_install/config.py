"""Small, nonsecret standalone configuration, independent of app imports."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

SCHEMA = "catchplate.standaloneInstall/v1"
EDGE_IMAGE = "nginx@sha256:1ed1b0e1d7652937d6cbdaf4018c7b6fc009a7dd6c3047351e2eddda745de43f"


class InstallError(Exception):
    """A fixed, public diagnostic; never wrap raw command or secret input text."""


def absolute_path(value) -> Path:
    if (type(value) is not str or not value or len(value) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise InstallError("Paths must be explicit absolute filesystem paths.")
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or str(path) != value or ".." in path.parts:
        raise InstallError("Paths must be canonical absolute paths, without parent traversal.")
    return path


def check_path(path: Path, *, missing_leaf=False) -> None:
    """Reject symlinks at every existing component, including the selected leaf."""
    path = absolute_path(str(path))
    current = Path("/")
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing_leaf and index == len(path.parts) - 2:
                return
            raise InstallError("A required parent directory or input file does not exist.") from None
        if stat.S_ISLNK(info.st_mode):
            raise InstallError("Installation paths must not contain symbolic links.")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise InstallError("An installation path parent is not a directory.")


def read_file(path: Path, *, maximum=65536, private=False) -> bytes:
    check_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) not in {0o400, 0o600}):
            raise InstallError("Input must be a bounded regular file with safe permissions.")
        value = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if len(value) != before.st_size or (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (
                after.st_mtime_ns, after.st_ctime_ns, after.st_size):
            raise InstallError("Input changed while being read; no operation was accepted.")
        return value
    finally:
        os.close(descriptor)


def parse_json(value: bytes):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError()
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise InstallError("Configuration must be valid JSON without duplicate keys.") from None


def origin(value) -> str:
    if type(value) is not str or len(value) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise InstallError("Origins must be exact HTTPS DNS origins on port 443.")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname or "", parsed.port or 443
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or port != 443
                or "." not in host or host != host.lower() or len(host) > 253
                or host.endswith((".localhost", ".local", ".internal", ".invalid", ".test"))
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                    for part in host.split("."))):
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError()
        canonical = "https://" + host
        if value not in {canonical, canonical + "/", canonical + ":443", canonical + ":443/"}:
            raise ValueError()
        return canonical
    except ValueError:
        raise InstallError("Origins must be exact HTTPS DNS origins on port 443.") from None


def validate(value: dict) -> dict:
    required = {"schema", "project_name", "state_dir", "console_origin", "proxy_origin",
        "allowed_upstreams", "tls_certificate", "tls_private_key"}
    defaults = {"admin_username": "admin", "paired_image": "catchplate-standalone:local",
        "edge_image": EDGE_IMAGE, "publish_address": None, "network_subnets": None}
    if type(value) is not dict or not required <= set(value) or set(value) - required - set(defaults):
        raise InstallError("Configuration contains missing or unsupported fields.")
    result = {**defaults, **value}
    if result["schema"] != SCHEMA:
        raise InstallError("Unsupported standalone configuration schema.")
    if not isinstance(result["project_name"], str) or not re.fullmatch(r"catchplate-[a-z0-9][a-z0-9_-]{0,47}", result["project_name"]):
        raise InstallError("Project name must start with catchplate- and use lowercase letters, digits, hyphens or underscores.")
    if result["project_name"] == "catchplate-operator-demo":
        raise InstallError("The retained operator deployment project is not a fresh standalone installation.")
    if type(result["admin_username"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", result["admin_username"]):
        raise InstallError("Console username must use letters, digits, dots, hyphens or underscores.")
    for field in ("state_dir", "tls_certificate", "tls_private_key"):
        absolute_path(result[field])
    if "$" in result["state_dir"]:
        raise InstallError("The state path cannot contain dollar signs because Compose interpolates them.")
    for field in ("console_origin", "proxy_origin"):
        result[field] = origin(result[field])
    if result["console_origin"] == result["proxy_origin"]:
        raise InstallError("Console and proxy must use different HTTPS hostnames.")
    raw = result["allowed_upstreams"]
    if type(raw) is not list or not 1 <= len(raw) <= 32:
        raise InstallError("Configure between one and 32 explicit HTTPS destination origins.")
    result["allowed_upstreams"] = [origin(item) for item in raw]
    if len(set(result["allowed_upstreams"])) != len(raw):
        raise InstallError("Destination origins must be unique.")
    for field in ("paired_image", "edge_image"):
        if type(result[field]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}", result[field]):
            raise InstallError("Image selections must be explicit local Docker references.")
    address = result["publish_address"]
    if address is not None:
        try:
            if type(address) is not str or not address.endswith(":443"):
                raise ValueError()
            host = address[:-4]
            parsed = ipaddress.ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
            canonical = f"[{parsed}]:443" if parsed.version == 6 else f"{parsed}:443"
            if canonical != address:
                raise ValueError()
        except ValueError:
            raise InstallError("publish_address must be null or an explicit IP address on port 443.") from None
    subnets = result["network_subnets"]
    if subnets is not None:
        try:
            if type(subnets) is not dict or set(subnets) != {"control", "outbound"}:
                raise ValueError()
            networks = [ipaddress.ip_network(subnets[name], strict=True) for name in ("control", "outbound")]
            private = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
            if any(network.version != 4 or not 16 <= network.prefixlen <= 28
                    or not any(network.subnet_of(parent) for parent in private) for network in networks) or networks[0].overlaps(networks[1]):
                raise ValueError()
            if any(str(network) != subnets[name] for name, network in zip(("control", "outbound"), networks)):
                raise ValueError()
        except (ValueError, TypeError):
            raise InstallError("network_subnets requires two distinct, nonoverlapping private IPv4 CIDRs (/16 to /28) named control and outbound.") from None
    return result


def load_config(path: Path) -> dict:
    return validate(parse_json(read_file(absolute_path(os.path.abspath(path)))))
