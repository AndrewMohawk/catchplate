"""Opt-in, policy-only view for the operator gate; never a new authority store.

The original publication EX owner covers both copies. The gate mounts this
directory, not the atomically replaced policy file. Its lock, marker and CA are
separate read-only binds of the ORIGINAL files; the placeholders here carry no
authority or key material and deliberately fail admission without those binds.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile

from catchplate import operator_publication

FLAG = "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED"
DIRECTORY = "gate-runtime"
POLICY = "policy-bundle.json"
GOOGLE_CONFIGURATION = "operator-google-configuration.json"
X_CONFIGURATION = "operator-x-configuration.json"
_LEAVES = (operator_publication.LOCK_NAME, ".catchplate-operator-demo.json")
_CA_LEAVES = ("mitmproxy-ca-cert.pem", "mitmproxy-ca.pem")
_TEMPORARY = re.compile(r"\.operator-policy-[0-9a-f]{32}\Z")
_pinned = None


def _require(condition: bool) -> None:
    if not condition:
        raise RuntimeError("operator gate publication refused")


def enabled() -> bool:
    value = os.getenv(FLAG)
    _require(value in {None, "", "0", "1"})
    if value != "1":
        return False
    from catchplate import config, operator_demo
    _require(operator_demo.active() and config.RELEASE_CHANNEL == "dev"
        and not config.PRODUCTION_IMAGE)
    return True


def _directory_identity(info) -> tuple[int, ...]:
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def _regular(info, mode: int, *, empty: bool = False) -> None:
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1
        and (not empty or info.st_size == 0))


def _placeholder(directory_fd: int, name: str) -> None:
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0, dir_fd=directory_fd)
    except FileExistsError:
        pass
    else:
        try:
            _regular(os.fstat(descriptor), 0, empty=True)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _regular(os.stat(name, dir_fd=directory_fd, follow_symlinks=False), 0, empty=True)


def _open_child(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd)
    try:
        _directory_identity(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def _export_directory(data: Path, *, managed_google: bool, managed_x: bool = False):
    global _pinned
    from catchplate.development_sandbox import _open_directory
    operator_publication.assert_held()
    with operator_publication.closing_fd(_open_directory(data)) as parent:
        if _pinned is not None:
            _require(_pinned == (os.getpid(), data,
                _directory_identity(os.stat(DIRECTORY, dir_fd=parent, follow_symlinks=False))))
        with operator_publication.closing_fd(_open_child(parent, DIRECTORY)) as descriptor:
            identity = _directory_identity(os.fstat(descriptor))
            _pinned = (os.getpid(), data, identity)

            def check():
                operator_publication.assert_held()
                _require(_directory_identity(os.fstat(descriptor)) == identity
                    and _directory_identity(os.stat(DIRECTORY, dir_fd=parent,
                        follow_symlinks=False)) == identity)

            check()
            # Refuse unexpected contents before creating any mountpoints. Stale
            # owned writer temporaries are recoverable after a process crash.
            stale = []
            for name in os.listdir(descriptor):
                if (name in {POLICY, "mitmproxy", *_LEAVES}
                        or managed_google and name == GOOGLE_CONFIGURATION
                        or managed_x and name == X_CONFIGURATION):
                    continue
                _require(_TEMPORARY.fullmatch(name) is not None)
                _regular(os.stat(name, dir_fd=descriptor, follow_symlinks=False), 0o600)
                stale.append(name)
            for name in _LEAVES:
                _placeholder(descriptor, name)
            with operator_publication.closing_fd(_open_child(descriptor, "mitmproxy")) as ca:
                _require(set(os.listdir(ca)).issubset(_CA_LEAVES))
                for name in _CA_LEAVES:
                    _placeholder(ca, name)
                os.fsync(ca)
            for name in stale:
                os.unlink(name, dir_fd=descriptor)
            os.fsync(descriptor)
            check()
            yield descriptor
            check()


def _replace_publication(path: Path, raw: bytes, *, directory_fd: int | None = None) -> None:
    """One durable writer; legacy canonical paths retain their existing behavior."""
    filename = path.name
    _require(filename == POLICY or directory_fd is not None
        and filename in {GOOGLE_CONFIGURATION, X_CONFIGURATION})
    if directory_fd is None:
        if path.is_symlink():
            raise RuntimeError("operator demo policy file cannot be a symlink")
        if path.exists() and path.read_bytes() == raw:
            return
        descriptor, temporary = tempfile.mkstemp(prefix=".operator-policy-", dir=path.parent)
        destination, replace_options = path, {}
    else:
        try:
            existing = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        else:
            with operator_publication.closing_fd(existing):
                before = os.fstat(existing)
                _regular(before, 0o600)
                same = before.st_size == len(raw) and os.pread(existing, len(raw) + 1, 0) == raw
                current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
                _regular(current, 0o600)
                _require((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino))
                if same:
                    # Also finish durability after an earlier post-replace fsync failure.
                    os.fsync(existing)
                    os.fsync(directory_fd)
                    return
        temporary = ".operator-policy-" + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        destination = filename
        replace_options = {"src_dir_fd": directory_fd, "dst_dir_fd": directory_fd}
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination, **replace_options)
        if directory_fd is None:
            with operator_publication.closing_fd(os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)) as parent:
                os.fsync(parent)
        else:
            os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def materialize(raw: bytes, *, google_configuration: bytes | None = None,
        x_configuration: bytes | None = None) -> None:
    """Publish DB-supplied signed bytes under the ORIGINAL EX owner; never sign.

Postcommit failures propagate to existing pending-activation handling. Startup
repairs both copies independently; a current canonical file is not an early exit.
"""
    from catchplate import config
    operator_publication.assert_held()
    selected = enabled()
    _require(type(raw) is bytes and bool(raw)
        and config.POLICY_BUNDLE_PATH == config.DATA_DIR / POLICY)
    if google_configuration is not None:
        _require(selected and type(google_configuration) is bytes and 0 < len(google_configuration) <= 32768)
    if x_configuration is not None:
        _require(selected and type(x_configuration) is bytes and 0 < len(x_configuration) <= 32768)
    if not selected:
        _replace_publication(config.POLICY_BUNDLE_PATH, raw)
        return
    with _export_directory(config.DATA_DIR, managed_google=google_configuration is not None,
            managed_x=x_configuration is not None) as directory_fd:
        _replace_publication(config.POLICY_BUNDLE_PATH, raw)
        _replace_publication(config.DATA_DIR / DIRECTORY / POLICY, raw, directory_fd=directory_fd)
        if google_configuration is not None:
            _replace_publication(config.DATA_DIR / DIRECTORY / GOOGLE_CONFIGURATION,
                google_configuration, directory_fd=directory_fd)
        if x_configuration is not None:
            _replace_publication(config.DATA_DIR / DIRECTORY / X_CONFIGURATION,
                x_configuration, directory_fd=directory_fd)
