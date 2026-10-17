"""Local synthetic state, never measured policy or PostgreSQL authority.

Only the dedicated development runner can activate this store. Its policy is
one immutable, genuinely signed demo bundle; nonce transactions use a separate
persistent SQLite file. Nothing here creates production authority receipts.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
import stat


_NAME = "development-sandbox.sqlite3"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_NONCES = 100_000
_RETENTION_MS = 24 * 60 * 60 * 1000
_MAX_EPOCH_MS = (1 << 63) - _RETENTION_MS - 1


class DevelopmentSandboxStoreError(ValueError):
    pass


def _require_active() -> Path:
    from catchplate.development_sandbox import active
    if not active():
        raise DevelopmentSandboxStoreError("synthetic development sandbox is not active")
    from catchplate.config import DATA_DIR
    return DATA_DIR / _NAME


@contextmanager
def _connect(*, initialize: bool = False):
    path = _require_active()
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    if initialize:
        flags |= os.O_CREAT
    descriptor = os.open(path, flags, 0o600)
    try:
        identity = os.fstat(descriptor)
        if (not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.geteuid()
                or stat.S_IMODE(identity.st_mode) != 0o600 or identity.st_nlink != 1):
            raise DevelopmentSandboxStoreError("sandbox store must be an owner-only regular file")
        connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                     timeout=10, isolation_level=None)
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise DevelopmentSandboxStoreError("sandbox store changed while opening")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            if initialize:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS sandbox_policy (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        policy_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        rollback_epoch INTEGER NOT NULL CHECK (rollback_epoch >= 1),
                        policy_hash TEXT NOT NULL,
                        signed_bundle_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS sandbox_credential_nonces (
                        recipient_key_id TEXT NOT NULL,
                        nonce_sha256 TEXT NOT NULL,
                        expires_at_epoch_ms INTEGER NOT NULL,
                        PRIMARY KEY (recipient_key_id, nonce_sha256)
                    );
                    CREATE INDEX IF NOT EXISTS sandbox_nonce_expiry
                        ON sandbox_credential_nonces(expires_at_epoch_ms);
                """)
            yield connection
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
    finally:
        os.close(descriptor)


def _public_policy(row) -> dict | None:
    if row is None:
        return None
    return {name: row[name] for name in (
        "policy_id", "sequence", "rollback_epoch", "policy_hash", "updated_at"
    )}


def commission_policy(signed_bundle: dict) -> dict:
    """Install exact synthetic semantics once; same signed input is idempotent.

    A different policy, signature, key, sequence or epoch requires a separately
    selected empty sandbox. This is local fixture admission, not genesis.
    """
    _require_active()
    from catchplate import policy_bundle as bundles
    from catchplate.demo_seed_policy import require_demo_semantics

    require_demo_semantics(signed_bundle)
    snapshot = bundles.compile_policy_bundle(
        signed_bundle, verify_signature=True, validate_schema=True
    )
    policy_id, sequence, rollback_epoch, policy_hash = bundles._policy_snapshot_authority(snapshot)
    canonical = bundles.canonical_json(signed_bundle)
    if len(canonical.encode("utf-8")) > bundles.MAX_POLICY_BUNDLE_BYTES:
        raise DevelopmentSandboxStoreError("sandbox policy exceeds the policy size bound")
    with _connect(initialize=True) as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute("SELECT * FROM sandbox_policy WHERE singleton=1").fetchone()
        if existing is not None:
            if existing["signed_bundle_json"] != canonical:
                raise DevelopmentSandboxStoreError("sandbox policy differs from its immutable commissioned fixture")
            result = _public_policy(existing)
        else:
            connection.execute(
                "INSERT INTO sandbox_policy VALUES (1, ?, ?, ?, ?, ?, ?)",
                (policy_id, sequence, rollback_epoch, policy_hash, canonical,
                 datetime.now(timezone.utc).isoformat()),
            )
            result = _public_policy(connection.execute(
                "SELECT * FROM sandbox_policy WHERE singleton=1"
            ).fetchone())
        connection.commit()
    return result


def get_policy_high_water() -> dict | None:
    _require_active()
    try:
        with _connect() as connection:
            return _public_policy(connection.execute(
                "SELECT * FROM sandbox_policy WHERE singleton=1"
            ).fetchone())
    except FileNotFoundError:
        return None


def get_policy_publication(policy_hash: str) -> dict | None:
    _require_active()
    if not isinstance(policy_hash, str) or _SHA256.fullmatch(policy_hash) is None:
        raise DevelopmentSandboxStoreError("sandbox publication hash is invalid")
    state = get_policy_high_water()
    if state is None or state["policy_hash"] != policy_hash:
        return None
    # Compatibility for the real policy reader, not a production receipt.
    return {**state, "scope": "active", "status": "committed",
            "previous_policy_hash": None, "created_at": state["updated_at"],
            "committed_at": state["updated_at"]}


def verify_policy_high_water(*, policy_id: str, sequence: int,
                             rollback_epoch: int, policy_hash: str,
                             _connection=None, _allow_pending: bool = False) -> dict:
    _require_active()
    if _connection is not None or _allow_pending:
        raise DevelopmentSandboxStoreError("sandbox does not support policy authority transactions")
    if (type(sequence) is not int or type(rollback_epoch) is not int
            or sequence < 1 or rollback_epoch < 1):
        raise DevelopmentSandboxStoreError("sandbox policy counters are invalid")
    state = get_policy_high_water()
    expected = dict(policy_id=policy_id, sequence=sequence,
                    rollback_epoch=rollback_epoch, policy_hash=policy_hash)
    if state is None or any(state[name] != value for name, value in expected.items()):
        raise DevelopmentSandboxStoreError("signed policy is not the exact sandbox fixture")
    return state


def _nonce_values(recipient_key_id: str, nonce_sha256: str, now_epoch_ms: int) -> None:
    _require_active()
    if any(not isinstance(value, str) or _SHA256.fullmatch(value) is None
           for value in (recipient_key_id, nonce_sha256)):
        raise DevelopmentSandboxStoreError("sandbox nonce identifiers must be SHA-256 digests")
    if type(now_epoch_ms) is not int or not 0 <= now_epoch_ms <= _MAX_EPOCH_MS:
        raise DevelopmentSandboxStoreError("sandbox nonce time is invalid")


def reserve_credential_lease_nonce(recipient_key_id: str, nonce_sha256: str,
                                 *, now_epoch_ms: int) -> str | None:
    _nonce_values(recipient_key_id, nonce_sha256, now_epoch_ms)
    from catchplate.config import CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES
    maximum = min(CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES, _MAX_NONCES)
    if maximum < 1:
        raise DevelopmentSandboxStoreError("sandbox nonce capacity is invalid")
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM sandbox_credential_nonces WHERE expires_at_epoch_ms<=?",
                           (now_epoch_ms,))
        if connection.execute(
            "SELECT 1 FROM sandbox_credential_nonces WHERE recipient_key_id=? AND nonce_sha256=?",
            (recipient_key_id, nonce_sha256),
        ).fetchone() is not None:
            result = "replay"
        elif connection.execute("SELECT COUNT(*) FROM sandbox_credential_nonces").fetchone()[0] >= maximum:
            result = "capacity"
        else:
            connection.execute("INSERT INTO sandbox_credential_nonces VALUES (?, ?, ?)",
                               (recipient_key_id, nonce_sha256, now_epoch_ms + _RETENTION_MS))
            result = None
        connection.commit()
    return result


def credential_lease_nonce_reserved(recipient_key_id: str, nonce_sha256: str,
                                   *, now_epoch_ms: int) -> bool:
    _nonce_values(recipient_key_id, nonce_sha256, now_epoch_ms)
    with _connect() as connection:
        return connection.execute(
            "SELECT 1 FROM sandbox_credential_nonces WHERE recipient_key_id=? AND nonce_sha256=? "
            "AND expires_at_epoch_ms>?", (recipient_key_id, nonce_sha256, now_epoch_ms),
        ).fetchone() is not None
