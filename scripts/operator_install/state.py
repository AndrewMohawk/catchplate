"""Private, no-clobber installer state and one instance-wide operation lock."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .config import InstallError, absolute_path, check_path, parse_json, read_file, validate

SCHEMA = "serverware.standaloneInstallation/v1"
TOKEN_FILES = ("admin.token", "credential-lease.token", "audit.token", "grant-consume.token",
    "rate-limit-consume.token", "release-authorization.token", "management.token")
PINNED_FILES = {"compose.json", "edge/nginx.conf", "edge-secrets/tls.crt", "edge-secrets/tls.key",
    "edge-secrets/htpasswd", "edge-secrets/operator-admin-header.conf",
    *("service-secrets/" + name for name in TOKEN_FILES)}
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _directory(path: Path, *, owner=0) -> None:
    check_path(path)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise InstallError("Installation directories must retain their private owner and mode 0700.")


@contextmanager
def instance_lock(state_dir: Path, *, initialize=False, shared=False):
    state_dir = absolute_path(str(state_dir))
    if initialize:
        check_path(state_dir, missing_leaf=True)
        try:
            state_dir.mkdir(mode=0o700)
        except FileExistsError:
            _directory(state_dir)
            if next(state_dir.iterdir(), None) is not None:
                raise InstallError("Initialization refuses existing nonempty state; nothing was replaced.")
        os.chmod(state_dir, 0o700)
        os.chown(state_dir, 0, 0)
    _directory(state_dir)
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDONLY if shared else os.O_RDWR)
    if initialize:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(state_dir / ".install.lock", flags, 0o600)
    except FileExistsError:
        raise InstallError("Initialization refuses existing installer state; nothing was replaced.") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError("The installation lock does not have its expected private identity.")
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("Another installation operation is running; wait and inspect status before retrying.") from None
        if initialize and {entry.name for entry in state_dir.iterdir()} != {".install.lock"}:
            raise InstallError("Initialization refuses changed or nonempty state; nothing was replaced.")
        yield
    finally:
        os.close(descriptor)


def write_file(path: Path, data: bytes, *, owner=0, mode=0o600, exclusive=True) -> None:
    """No-clobber creation, or explicit same-directory atomic replacement."""
    check_path(path.parent)
    destination = path if exclusive else path.with_name("." + path.name + "." + uuid.uuid4().hex)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner, owner)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not exclusive:
        # The caller holds the private instance lock; never follow a changed leaf.
        check_path(path)
        if not path.is_file() or path.stat().st_nlink != 1:
            raise InstallError("An installed file changed identity; replacement was refused.")
        os.replace(destination, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def artifact(value) -> dict:
    fields = {"schema", "sourceRevision", "sourceTreeDigest", "compilerInputsDigest", "dataPlaneBinaryDigest"}
    if (type(value) is not dict or set(value) != fields or value["schema"] != "serverware.standaloneArtifact/v1"
            or type(value["sourceRevision"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", value["sourceRevision"])
            or any(type(value[field]) is not str or not _SHA.fullmatch(value[field]) for field in fields - {"schema", "sourceRevision"})):
        raise InstallError("Paired image artifact metadata is missing or malformed; rebuild the selected image explicitly.")
    return value


def write_manifest(state_dir: Path, manifest: dict, *, exclusive=False) -> None:
    write_file(state_dir / "manifest.json", encoded(manifest), exclusive=exclusive)


def load_manifest(state_dir: Path, *, verify_files=True) -> dict:
    state_dir = absolute_path(str(state_dir))
    _directory(state_dir)
    value = parse_json(read_file(state_dir / "manifest.json", maximum=131072, private=True))
    if (state_dir / "manifest.json").stat().st_uid != 0:
        raise InstallError("Installation manifest ownership changed; existing state was not adopted.")
    if type(value) is not dict or set(value) != {"schema", "config", "instance_id", "images", "artifact", "files"} or value["schema"] != SCHEMA:
        raise InstallError("Installation manifest is missing or malformed; existing state was not adopted.")
    config = validate(value["config"])
    if config != value["config"] or config["state_dir"] != str(state_dir):
        raise InstallError("Installation manifest does not match this state directory.")
    try:
        if str(uuid.UUID(value["instance_id"])) != value["instance_id"]:
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise InstallError("Installation identity is malformed.") from None
    artifact(value["artifact"])
    if (type(value["images"]) is not dict or set(value["images"]) != {"paired", "edge"}
            or any(not _SHA.fullmatch(config[key + "_image"]) for key in ("paired", "edge"))
            or type(value["files"]) is not dict or set(value["files"]) != PINNED_FILES
            or any(type(pin) is not str or not _SHA.fullmatch(pin) for pin in value["files"].values())):
        raise InstallError("Installation artifact pins are malformed.")
    for key in ("paired", "edge"):
        info = value["images"][key]
        if type(info) is not dict or info.get("id") != config[key + "_image"]:
            raise InstallError("Installation image identity is inconsistent.")
    if verify_files:
        for name, expected in value["files"].items():
            data = read_file(state_dir / name, maximum=4 * 1024 * 1024, private=True)
            info = (state_dir / name).stat()
            if info.st_uid != (0 if name == "compose.json" else 10001) or digest(data) != expected:
                raise InstallError("An installed artifact differs from its recorded pin; state was not reset or adopted.")
    return value


def result(manifest, operation, status, **extra) -> dict:
    config = manifest["config"]
    return {"schema": "serverware.standaloneResult/v1", "operation": operation, "status": status,
        **{key: config[key] for key in ("state_dir", "project_name", "console_origin", "proxy_origin")}, **extra}
