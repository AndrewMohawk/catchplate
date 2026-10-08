"""Operator-only publication ownership shared with the Rust audit sender.

Order is local RLock -> flock(EX) -> SQLite -> durable policy materialization.
Readers, nonce reservations and the audit receiver must not enter this guard.
The offline provisioning acknowledgment is NOT proof that old services stopped.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time

LOCK_NAME = ".operator-publication.lock"
ACQUISITION_SECONDS = 5.0
LOCAL_LOCK = threading.RLock()
_state = threading.local()
_pinned = None


class PublicationError(RuntimeError):
    """Fixed, non-secret publication admission failure."""


def _file_identity(info) -> tuple[int, ...]:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 0):
        raise PublicationError("operator publication lock identity refused")
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size


def _directory_identity(info) -> tuple[int, ...]:
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PublicationError("operator publication directory identity refused")
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def _directory() -> Path:
    from serverware import config, operator_demo
    if not operator_demo.active() or config.POLICY_BUNDLE_PATH != config.DATA_DIR / "policy-bundle.json":
        raise PublicationError("operator publication profile unavailable")
    return config.POLICY_BUNDLE_PATH.parent


@dataclass(frozen=True)
class _Pinned:
    pid: int
    directory: Path
    directory_fd: int
    directory_identity: tuple[int, ...]
    file_fd: int  # Retain the inode for the entire process lifetime.
    file_identity: tuple[int, ...]

    def check(self) -> None:
        from serverware.development_sandbox import _open_directory
        if self.pid != os.getpid() or _directory() != self.directory:
            raise PublicationError("operator publication process identity changed")
        with closing_fd(_open_directory(self.directory)) as current:
            if (_directory_identity(os.fstat(current)) != self.directory_identity
                    or _directory_identity(os.fstat(self.directory_fd)) != self.directory_identity
                    or _file_identity(os.fstat(self.file_fd)) != self.file_identity
                    or _file_identity(os.stat(LOCK_NAME, dir_fd=current, follow_symlinks=False))
                    != self.file_identity):
                raise PublicationError("operator publication lock identity changed")


@contextmanager
def closing_fd(descriptor: int):
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _database_identity(directory_fd: int):
    from serverware import config
    info = os.stat(config.DB_PATH.name, dir_fd=directory_fd, follow_symlinks=False)
    if (config.DB_PATH.parent != config.DATA_DIR or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise PublicationError("operator publication database identity refused")
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink


@contextmanager
def _read_database(directory_fd: int):
    """No db.connect(): no schema, journal-mode change or authority writes."""
    from serverware import config
    identity = _database_identity(directory_fd)
    with closing(sqlite3.connect(config.DB_PATH.as_uri() + "?mode=ro", uri=True, timeout=0)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        yield conn
        if _database_identity(directory_fd) != identity:
            raise PublicationError("operator publication database identity changed")


def _fresh(directory_fd: int) -> bool:
    from serverware import config
    try:
        os.stat(config.POLICY_BUNDLE_PATH.name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        return False
    try:
        _database_identity(directory_fd)
    except FileNotFoundError:
        return True
    with _read_database(directory_fd) as conn:
        return not any(row[0].lower().startswith(("operator_demo_", "operator_catalog_"))
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))


def _create(directory_fd: int) -> None:
    # Never repair, truncate or chmod an existing object, including a bad one.
    try:
        descriptor = os.open(LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
            dir_fd=directory_fd)
    except FileExistsError:
        return
    with closing_fd(descriptor):
        _file_identity(os.fstat(descriptor))
        os.fsync(descriptor)
    os.fsync(directory_fd)


def _pin(*, startup: bool) -> _Pinned:
    global _pinned
    if _pinned is not None:
        _pinned.check()
        return _pinned
    if not startup:
        raise PublicationError("operator publication startup required")
    from serverware.development_sandbox import _open_directory
    directory = _directory()
    directory_fd = _open_directory(directory)
    file_fd = None
    try:
        directory_identity = _directory_identity(os.fstat(directory_fd))
        try:
            file_fd = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directory_fd)
        except FileNotFoundError:
            if not _fresh(directory_fd):
                raise PublicationError("existing operator store requires offline publication-lock provisioning") from None
            _create(directory_fd)
            file_fd = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directory_fd)
        candidate = _Pinned(os.getpid(), directory, directory_fd, directory_identity,
            file_fd, _file_identity(os.fstat(file_fd)))
        candidate.check()
        _pinned = candidate
        return candidate
    except BaseException:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
        raise


def assert_held() -> None:
    """Transaction-level publishers assert ownership; they never wait for it."""
    if getattr(_state, "depth", 0) < 1 or _pinned is None:
        raise PublicationError("operator publication ownership required")
    _pinned.check()


@contextmanager
def exclusive(*, startup: bool = False):
    if getattr(_state, "depth", 0):
        assert_held()
        _state.depth += 1
        try:
            yield
            assert_held()
        finally:
            _state.depth -= 1
        return
    deadline = time.monotonic() + ACQUISITION_SECONDS
    if not LOCAL_LOCK.acquire(timeout=max(0.0, deadline - time.monotonic())):
        raise PublicationError("operator publication ownership timed out")
    descriptor = None
    acquired = False
    try:
        pin = _pin(startup=startup)
        descriptor = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=pin.directory_fd)
        if _file_identity(os.fstat(descriptor)) != pin.file_identity:
            raise PublicationError("operator publication lock identity changed")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublicationError("operator publication ownership timed out")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                time.sleep(min(0.01, remaining))
        pin.check()
        _state.depth, _state.deadline = 1, deadline
        yield
        pin.check()
    finally:
        _state.depth = 0
        _state.deadline = None
        try:
            if descriptor is not None:
                try:
                    if acquired:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
        finally:
            LOCAL_LOCK.release()


def provision_existing_stopped(*, acknowledged: bool = False) -> None:
    """Offline only: validate retained authority, then add only the lock inode.

The caller must stop ALL old/new control-plane and gate processes. Neither this
flag nor an absent lock can establish that prerequisite from inside a container.
"""
    if acknowledged is not True or _pinned is not None:
        raise PublicationError("offline stopped-service acknowledgment required")
    from serverware import operator_catalog_policy, operator_catalog_schema
    from serverware.development_sandbox import _open_directory
    with closing_fd(_open_directory(_directory())) as directory_fd:
        identity = _directory_identity(os.fstat(directory_fd))
        with _read_database(directory_fd) as conn:
            operator_catalog_policy._retained(conn)
            if operator_catalog_schema.active(conn):
                catalog = operator_catalog_schema.read_catalog(conn)
                operator_catalog_schema.validate_bindings(conn, catalog)
                operator_catalog_policy.verify_retained_policy(conn, catalog)
        if (_directory_identity(os.fstat(directory_fd)) != identity
                or _directory() != Path(os.environ["SERVERWARE_DATA_DIR"])):
            raise PublicationError("operator publication directory identity changed")
        _create(directory_fd)
        with closing_fd(os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directory_fd)) as descriptor:
            if _file_identity(os.fstat(descriptor)) != _file_identity(
                    os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)):
                raise PublicationError("operator publication lock identity changed")
        _directory()  # Revalidate the active marked directory after provisioning.


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Offline operator publication-lock provisioning; stop all app/gate services first.")
    parser.add_argument("--provision-existing-stopped", action="store_true", required=True,
        help="acknowledge all operator app/gate services have been stopped; this helper cannot verify that")
    args = parser.parse_args()
    # Require a retained marker BEFORE activate(), which may mark fresh data.
    from serverware import operator_demo
    from serverware.development_sandbox import _open_directory
    directory = Path(os.environ.get("SERVERWARE_DATA_DIR", ""))
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        raise PublicationError("existing operator directory required")
    with closing_fd(_open_directory(directory)) as descriptor:
        operator_demo._marker(descriptor)
    operator_demo.activate()
    provision_existing_stopped(acknowledged=args.provision_existing_stopped)
    print("Publication lock provisioned; retained authority was not rewritten. Stopped services were acknowledged, not verified.")


if __name__ == "__main__":
    main()
