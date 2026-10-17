"""Internal foundation for operator-owned Google application-secret custody.

This is not provider setup, activation, rotation, or a new settings authority.
The caller must first admit the complete operator-development ownership profile;
the explicit admission below records that internal decision, not HTTP authority.
Writers borrow the existing publication lock and SQLite transaction. The caller
must join custody changes to its setup operation and durable audit before commit.

Reads neither initialize storage nor import config/crypto, select a version,
create a key, or adopt another owner. The file reader reads only an existing key;
the caller owns WAL-aware database opening and the existing read transaction.
These primitives alone do not implement the future cold-start consumer.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from catchplate import operator_catalog_oauth_profile as google
from catchplate.operator_demo import MARKER, MARKER_BYTES, origin

SCHEMA = "catchplate.operatorProviderCustody/v1"
AAD_SCHEMA = "catchplate.operatorProviderCustodyAAD/v1"
TABLE = "operator_provider_custody"
META = TABLE + "_meta"
MAX_VERSIONS = 16
MAX_SECRET_BYTES = 4096
MAX_PROFILE_BYTES = 4096
_ERROR = "operator provider custody refused"
_META_SQL = f"""CREATE TABLE {META} (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL,
    owner_id TEXT NOT NULL) WITHOUT ROWID"""
_TABLE_SQL = f"""CREATE TABLE {TABLE} (
    config_version INTEGER PRIMARY KEY CHECK(config_version BETWEEN 1 AND {MAX_VERSIONS}),
    profile_json TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL) WITHOUT ROWID"""
_DEFINITIONS = ((META, "table", META, _META_SQL), (TABLE, "table", TABLE, _TABLE_SQL)) + tuple(
    (name + suffix, "trigger", name, f"CREATE TRIGGER {name + suffix} BEFORE {operation} ON {name} "
     + (f"WHEN EXISTS (SELECT 1 FROM {name} WHERE {key}=NEW.{key}) " if operation == "INSERT" else "")
     + "BEGIN SELECT RAISE(ABORT,'operator provider custody is retained'); END")
    for name, key in ((META, "singleton"), (TABLE, "config_version"))
    for suffix, operation in (("_insert_guard", "INSERT"), ("_immutable", "UPDATE"), ("_retained", "DELETE"))
)


class CustodyError(RuntimeError):
    """Fixed non-secret failure, including malformed or missing retained material."""


class CustodyAbsent(CustodyError):
    """Dedicated schema is wholly absent; not permission to initialize it."""


def _require(condition: bool) -> None:
    if not condition:
        raise CustodyError(_ERROR)


def _uuid(value: str) -> bool:
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


@dataclass(frozen=True)
class DevelopmentOwner:
    owner_id: str
    uid: int
    pid: int


def admit_development_owner(owner_id: str, *, operator_development: bool,
        release_channel: str, production_image: bool, native_or_enrolled: bool) -> DevelopmentOwner:
    """Internal assertion only; caller must derive every flag from admitted state."""
    _require(_uuid(owner_id) and operator_development is True and release_channel == "dev"
        and production_image is False and native_or_enrolled is False)
    return DevelopmentOwner(owner_id, os.geteuid(), os.getpid())


def _owner(owner: DevelopmentOwner) -> None:
    _require(type(owner) is DevelopmentOwner and _uuid(owner.owner_id)
        and type(owner.uid) is int and owner.uid == os.geteuid()
        and type(owner.pid) is int and owner.pid == os.getpid())


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _profile(value: dict) -> str:
    try:
        _require(type(value) is dict)
        client_id, redirect_uri = value.get("client_id"), value.get("redirect_uri")
        _require(type(client_id) is str and google._CLIENT_ID.fullmatch(client_id) is not None
            and type(redirect_uri) is str and redirect_uri.endswith(google.CALLBACK_PATH))
        console = redirect_uri[:-len(google.CALLBACK_PATH)]
        canonical_origin, _ = origin(console)
        _require(console == canonical_origin and console != "https://demo-upstream:8443"
            and value == google._record(client_id, redirect_uri))
        result = _canonical(value)
        _require(len(result.encode("utf-8")) <= MAX_PROFILE_BYTES)
        return result
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise CustodyError(_ERROR) from None


@dataclass(frozen=True)
class Binding:
    owner_id: str
    config_version: int
    profile_json: str


def bind_google(owner: DevelopmentOwner, *, config_version: int, public_profile: dict) -> Binding:
    _owner(owner)
    _require(type(config_version) is int and 1 <= config_version <= MAX_VERSIONS)
    return Binding(owner.owner_id, config_version, _profile(public_profile))


def _binding(owner: DevelopmentOwner, binding: Binding) -> None:
    _owner(owner)
    try:
        _require(type(binding) is Binding and binding.owner_id == owner.owner_id
            and type(binding.config_version) is int and 1 <= binding.config_version <= MAX_VERSIONS
            and type(binding.profile_json) is str
            and len(binding.profile_json.encode("utf-8")) <= MAX_PROFILE_BYTES)
        _require(_profile(json.loads(binding.profile_json)) == binding.profile_json)
    except (ValueError, TypeError, RecursionError):
        raise CustodyError(_ERROR) from None


def _aad(binding: Binding) -> bytes:
    return _canonical({"schema": AAD_SCHEMA, "owner_id": binding.owner_id,
        "config_version": binding.config_version,
        "public_profile": json.loads(binding.profile_json)}).encode("utf-8")


def _key(key: bytes) -> None:
    _require(type(key) is bytes and len(key) == 32)


def _secret(secret: str) -> bytes:
    try:
        _require(type(secret) is str and secret == secret.strip()
            and not any(char in secret for char in ("\x00", "\r", "\n")))
        encoded = secret.encode("utf-8")
        _require(1 <= len(encoded) <= MAX_SECRET_BYTES)
        return encoded
    except (ValueError, TypeError, UnicodeError):
        raise CustodyError(_ERROR) from None


@dataclass(frozen=True)
class PrivateEnvelope:
    binding: Binding
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)


@dataclass(frozen=True)
class SecretMaterial:
    binding: Binding
    secret: str = field(repr=False)

    def public_view(self) -> dict:
        return _public_view(self.binding)


def _public_view(binding: Binding) -> dict:
    return {"schema": SCHEMA, "owner_id": binding.owner_id,
        "config_version": binding.config_version,
        "public_profile": json.loads(binding.profile_json), "secret_present": True}


def seal(owner: DevelopmentOwner, binding: Binding, *, key: bytes, secret: str) -> PrivateEnvelope:
    _binding(owner, binding)
    _key(key)
    plaintext = _secret(secret)
    nonce = os.urandom(12)
    return PrivateEnvelope(binding, nonce, AESGCM(key).encrypt(nonce, plaintext, _aad(binding)))


def open_secret(owner: DevelopmentOwner, envelope: PrivateEnvelope, *, key: bytes) -> SecretMaterial:
    _require(type(envelope) is PrivateEnvelope)
    _binding(owner, envelope.binding)
    _key(key)
    _require(type(envelope.nonce) is bytes and len(envelope.nonce) == 12
        and type(envelope.ciphertext) is bytes and 17 <= len(envelope.ciphertext) <= MAX_SECRET_BYTES + 16)
    try:
        secret = AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, _aad(envelope.binding)).decode("utf-8")
        _secret(secret)
        return SecretMaterial(envelope.binding, secret)
    except (InvalidTag, ValueError, UnicodeError):
        raise CustodyError(_ERROR) from None


def _transaction(conn: sqlite3.Connection, owner: DevelopmentOwner, *, writing: bool = False) -> None:
    _owner(owner)
    try:
        _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None
    if writing:
        # Lazy writer-only import. Read paths never reach config-backed guards.
        from catchplate.operator_publication import assert_held
        try:
            assert_held()
        except RuntimeError:
            raise CustodyError(_ERROR) from None


def _objects(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT substr(name,1,129),type,substr(tbl_name,1,129),substr(sql,1,8193),"
        "length(name),length(tbl_name),length(sql) FROM sqlite_master "
        "WHERE lower(name) GLOB 'operator_provider_custody*' OR lower(tbl_name) IN (?,?) LIMIT 10", (TABLE, META)).fetchall()
    _require(all(type(row[4]) is int and row[4] <= 128 and type(row[5]) is int and row[5] <= 128
        and type(row[6]) is int and row[6] <= 8192 for row in rows))
    return {row[0]: tuple(row[:4]) for row in rows}


def _schema(conn: sqlite3.Connection, owner: DevelopmentOwner) -> None:
    objects = _objects(conn)
    if not objects:
        raise CustodyAbsent("operator provider custody absent")
    _require(set(objects) == {item[0] for item in _DEFINITIONS})
    for name, kind, table, sql in _DEFINITIONS:
        actual = objects[name]
        _require(actual[1:3] == (kind, table) and type(actual[3]) is str
            and " ".join(actual[3].split()) == " ".join(sql.split()))
    marker = conn.execute(f"SELECT singleton,substr(schema,1,128),substr(owner_id,1,37),"
        f"length(schema),length(owner_id) FROM {META} LIMIT 2").fetchall()
    _require(len(marker) == 1
        and tuple(marker[0]) == (1, SCHEMA, owner.owner_id, len(SCHEMA), 36))


def _records(conn: sqlite3.Connection, owner: DevelopmentOwner) -> list[PrivateEnvelope]:
    _schema(conn, owner)
    # Bound allocations before fetching retained blobs. Limits include one extra
    # row so overflow cannot be hidden by truncating the result set.
    sizes = conn.execute(f"SELECT typeof(config_version),typeof(profile_json),length(CAST(profile_json AS BLOB)),"
        f"typeof(nonce),length(nonce),typeof(ciphertext),length(ciphertext) FROM {TABLE} "
        "ORDER BY config_version LIMIT ?", (MAX_VERSIONS + 1,)).fetchall()
    _require(len(sizes) <= MAX_VERSIONS and all(tuple(row[:2]) == ("integer", "text")
        and type(row[2]) is int and 1 <= row[2] <= MAX_PROFILE_BYTES
        and row[3] == "blob" and row[4] == 12 and row[5] == "blob"
        and type(row[6]) is int and 17 <= row[6] <= MAX_SECRET_BYTES + 16 for row in sizes))
    rows = conn.execute(f"SELECT config_version,profile_json,nonce,ciphertext FROM {TABLE} "
        "ORDER BY config_version LIMIT ?", (MAX_VERSIONS + 1,)).fetchall()
    _require(len(rows) <= MAX_VERSIONS)
    result = []
    for version, profile, nonce, ciphertext in rows:
        binding = Binding(owner.owner_id, version, profile)
        _binding(owner, binding)
        _require(type(nonce) is bytes and len(nonce) == 12 and type(ciphertext) is bytes
            and 17 <= len(ciphertext) <= MAX_SECRET_BYTES + 16)
        result.append(PrivateEnvelope(binding, nonce, ciphertext))
    return result


def install_empty_store(conn: sqlite3.Connection, owner: DevelopmentOwner) -> None:
    """Explicit caller-authorized DDL only; never called by a reader or retried.

    Caller must prove first-configuration/schema admission and append its audit
    in this same transaction. Absence alone does not establish that authority.
    """
    _transaction(conn, owner, writing=True)
    try:
        _require(not _objects(conn))
        for _, _, _, sql in _DEFINITIONS:
            conn.execute(sql)
        conn.execute(f"INSERT INTO {META} VALUES(1,?,?)", (SCHEMA, owner.owner_id))
        _require(not _records(conn, owner))
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def insert_secret(conn: sqlite3.Connection, owner: DevelopmentOwner, binding: Binding,
        *, key: bytes, secret: str) -> None:
    """Append one exact caller-selected version; never commit, rotate or activate."""
    _transaction(conn, owner, writing=True)
    _binding(owner, binding)
    try:
        records = _records(conn, owner)
        _require(len(records) < MAX_VERSIONS
            and all(item.binding.config_version != binding.config_version for item in records))
        envelope = seal(owner, binding, key=key, secret=secret)
        conn.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?)", (binding.config_version,
            binding.profile_json, envelope.nonce, envelope.ciphertext))
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def _matching_envelope(conn: sqlite3.Connection, owner: DevelopmentOwner,
        binding: Binding) -> PrivateEnvelope:
    _transaction(conn, owner)
    _binding(owner, binding)
    try:
        records = _records(conn, owner)
        matches = [item for item in records if item.binding == binding]
        _require(len(matches) == 1)
        return matches[0]
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def inspect_public_binding(conn: sqlite3.Connection, owner: DevelopmentOwner,
        binding: Binding) -> dict:
    """Inspect one exact binding in the caller's snapshot without reading a key.

    Validates the complete retained schema, owner, public profiles, and bounded
    envelope structure; never initializes storage, decrypts, or selects latest.
    ``secret_present`` means structurally present only: this inspection does not
    authenticate ciphertext or prove decryptability, activation, or readiness.
    """
    return _public_view(_matching_envelope(conn, owner, binding).binding)


def read_secret(conn: sqlite3.Connection, owner: DevelopmentOwner, binding: Binding,
        *, key: bytes) -> SecretMaterial:
    """Read exact retained binding in the caller's snapshot; no latest fallback."""
    return open_secret(owner, _matching_envelope(conn, owner, binding), key=key)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _directory(path: Path, owner: DevelopmentOwner):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner.uid and stat.S_IMODE(info.st_mode) == 0o700)
        yield descriptor
    finally:
        os.close(descriptor)


def _read_file(directory: int, name: str, owner: DevelopmentOwner, *, size: int, modes: set[int]):
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == owner.uid
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in modes and before.st_size == size)
        payload = os.pread(descriptor, size + 1, 0)
        identity = _identity(before)
        _require(len(payload) == size and _identity(os.fstat(descriptor)) == identity
            and _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity)
        return payload, identity
    finally:
        os.close(descriptor)


def read_existing_master_key(data_directory: str | Path, owner: DevelopmentOwner) -> bytes:
    """Read fixed master.key from an existing admitted private directory, never create.

    Caller must revalidate ownership at activation. This snapshot does not pin
    key identity for a process lifetime and does not open a database.
    """
    _owner(owner)
    try:
        path = Path(data_directory)
        _require(path.is_absolute() and path != Path("/") and ".." not in path.parts
            and str(path) == str(data_directory) and not any(ord(char) < 33 for char in str(path)))
        with _directory(path, owner) as directory:
            before = _identity(os.fstat(directory))
            marker, marker_identity = _read_file(directory, MARKER, owner, size=len(MARKER_BYTES), modes={0o600})
            _require(marker == MARKER_BYTES)
            key, key_identity = _read_file(directory, "master.key", owner, size=32, modes={0o400, 0o600})
            with _directory(path, owner) as current:
                _require(_identity(os.fstat(current)) == before and _identity(os.fstat(directory)) == before
                    and _identity(os.stat(MARKER, dir_fd=current, follow_symlinks=False)) == marker_identity
                    and _identity(os.stat("master.key", dir_fd=current, follow_symlinks=False)) == key_identity)
            return key
    except (OSError, ValueError, TypeError):
        raise CustodyError(_ERROR) from None
