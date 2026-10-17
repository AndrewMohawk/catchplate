"""Explicit-key, provider-disjoint X application-secret custody.

This is not configured/activated OAuth, key ownership proof, or native custody.
The caller must independently admit the real development owner, select an
existing app-only key, and join writes to its durable lifecycle and audit. Store
writers borrow an actual SQLite transaction and publication EX ownership; they
never commit or initialize implicitly. Readers select an exact retained binding,
not a latest version. The caller joins the entire roster to its setup history.
No key files, settings, fallback readers, or network actions exist here.
Google's closed binding, AAD and retained store are intentionally unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import sqlite3
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from catchplate.operator_provider_custody import DevelopmentOwner
from catchplate import operator_x_oauth_profile as profile

SCHEMA = "catchplate.operatorXProviderCustody/v1"
AAD_SCHEMA = "catchplate.operatorXProviderCustodyAAD/v1"
TABLE = "operator_x_provider_custody"
META = TABLE + "_meta"
MAX_VERSIONS = 16
MAX_SECRET_BYTES = profile.MAX_SECRET_BYTES
MAX_PROFILE_BYTES = profile.MAX_PROFILE_BYTES
_ERROR = "operator X provider custody refused"
_META_SQL = f"""CREATE TABLE {META} (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL,
    owner_id TEXT NOT NULL) WITHOUT ROWID"""
_TABLE_SQL = f"""CREATE TABLE {TABLE} (
    config_version INTEGER PRIMARY KEY CHECK(config_version BETWEEN 1 AND {MAX_VERSIONS}),
    profile_json TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL) WITHOUT ROWID"""
_DEFINITIONS = ((META, "table", META, _META_SQL), (TABLE, "table", TABLE, _TABLE_SQL)) + tuple(
    (name + suffix, "trigger", name, f"CREATE TRIGGER {name + suffix} BEFORE {operation} ON {name} "
     + (f"WHEN EXISTS (SELECT 1 FROM {name} WHERE {key}=NEW.{key}) " if operation == "INSERT" else "")
     + "BEGIN SELECT RAISE(ABORT,'operator X provider custody is retained'); END")
    for name, key in ((META, "singleton"), (TABLE, "config_version"))
    for suffix, operation in (("_insert_guard", "INSERT"), ("_immutable", "UPDATE"), ("_retained", "DELETE"))
)


class CustodyError(RuntimeError):
    """Fixed failure, with no secret or caller-controlled diagnostics."""


class CustodyAbsent(CustodyError):
    """The complete dedicated namespace is absent; not permission to initialize."""


def _require(condition):
    if not condition:
        raise CustodyError(_ERROR)


def _owner(owner):
    try:
        _require(type(owner) is DevelopmentOwner and type(owner.owner_id) is str
            and str(uuid.UUID(owner.owner_id)) == owner.owner_id
            and type(owner.uid) is int and owner.uid == os.geteuid()
            and type(owner.pid) is int and owner.pid == os.getpid())
    except (ValueError, AttributeError, TypeError):
        raise CustodyError(_ERROR) from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class XBinding:
    owner_id: str
    config_version: int
    profile_json: str


def bind_x(owner: DevelopmentOwner, *, config_version: int, public_profile: dict) -> XBinding:
    _owner(owner)
    _require(type(config_version) is int and 1 <= config_version <= MAX_VERSIONS)
    try:
        value = profile.public_record(profile.parse_profile(public_profile))
        raw = _canonical(value)
        _require(len(raw.encode("ascii")) <= MAX_PROFILE_BYTES)
        return XBinding(owner.owner_id, config_version, raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CustodyError(_ERROR) from None


def _binding(owner, binding):
    _owner(owner)
    try:
        _require(type(binding) is XBinding and binding.owner_id == owner.owner_id
            and type(binding.profile_json) is str and len(binding.profile_json) <= MAX_PROFILE_BYTES)
        expected = bind_x(owner, config_version=binding.config_version,
            public_profile=json.loads(binding.profile_json))
        _require(binding == expected)
    except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError):
        raise CustodyError(_ERROR) from None


def _aad(binding):
    return _canonical({"schema": AAD_SCHEMA, "owner_id": binding.owner_id,
        "config_version": binding.config_version,
        "public_profile": json.loads(binding.profile_json)}).encode("ascii")


def _key(key):
    _require(type(key) is bytes and len(key) == 32)


@dataclass(frozen=True)
class XPrivateEnvelope:
    binding: XBinding
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)


@dataclass(frozen=True)
class XSecretMaterial:
    binding: XBinding
    secret: str = field(repr=False)

    def public_view(self) -> dict:
        return _public_view(self.binding)


def _public_view(binding: XBinding) -> dict:
    return {"schema": SCHEMA, "owner_id": binding.owner_id,
        "config_version": binding.config_version,
        "public_profile": json.loads(binding.profile_json), "secret_present": True}


def seal_x(owner: DevelopmentOwner, binding: XBinding, *, key: bytes, secret: str) -> XPrivateEnvelope:
    _binding(owner, binding)
    _key(key)
    try:
        plaintext = profile.validate_client_secret(secret).encode("utf-8")
        nonce = os.urandom(12)
        return XPrivateEnvelope(binding, nonce, AESGCM(key).encrypt(nonce, plaintext, _aad(binding)))
    except (ValueError, TypeError, UnicodeError, OSError):
        raise CustodyError(_ERROR) from None


def open_x(owner: DevelopmentOwner, envelope: XPrivateEnvelope, *, key: bytes) -> XSecretMaterial:
    _require(type(envelope) is XPrivateEnvelope)
    _binding(owner, envelope.binding)
    _key(key)
    _require(type(envelope.nonce) is bytes and len(envelope.nonce) == 12
        and type(envelope.ciphertext) is bytes and 17 <= len(envelope.ciphertext) <= MAX_SECRET_BYTES + 16)
    try:
        raw = AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, _aad(envelope.binding))
        secret = profile.validate_client_secret(raw.decode("utf-8"))
        return XSecretMaterial(envelope.binding, secret)
    except (InvalidTag, ValueError, TypeError, UnicodeError):
        raise CustodyError(_ERROR) from None


def _transaction(conn: sqlite3.Connection, owner: DevelopmentOwner, *, writing=False) -> None:
    _owner(owner)
    try:
        _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction
            and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
        if writing:
            # Lazy writer-only import; read-only consumers never need config.
            from catchplate.operator_publication import assert_held
            assert_held()
            _require(conn.execute("PRAGMA query_only").fetchone()[0] == 0)
    except (sqlite3.Error, RuntimeError):
        raise CustodyError(_ERROR) from None


def _objects(conn: sqlite3.Connection) -> dict:
    prefix = TABLE + "*"
    # Refuse temp shadowing instead of silently inspecting or writing a different
    # object. The connected owner separately proves the actual main DB identity.
    if any(row[1] == "temp" for row in conn.execute("PRAGMA database_list")):
        _require(conn.execute("SELECT 1 FROM sqlite_temp_master WHERE lower(name) GLOB ? "
            "OR lower(tbl_name) GLOB ? LIMIT 1", (prefix, prefix)).fetchone() is None)
    rows = conn.execute("SELECT substr(name,1,129),type,substr(tbl_name,1,129),substr(sql,1,8193),"
        "length(name),length(tbl_name),length(sql) FROM main.sqlite_master "
        "WHERE lower(name) GLOB ? OR lower(tbl_name) GLOB ? LIMIT ?",
        (prefix, prefix, len(_DEFINITIONS) + 1)).fetchall()
    _require(len(rows) <= len(_DEFINITIONS) and all(type(row[4]) is int and row[4] <= 128
        and type(row[5]) is int and row[5] <= 128 and type(row[6]) is int and row[6] <= 8192 for row in rows))
    return {row[0]: tuple(row[:4]) for row in rows}


def _schema(conn: sqlite3.Connection, owner: DevelopmentOwner) -> None:
    objects = _objects(conn)
    if not objects:
        raise CustodyAbsent("operator X provider custody absent")
    _require(set(objects) == {item[0] for item in _DEFINITIONS})
    for name, kind, table, sql in _DEFINITIONS:
        actual = objects[name]
        _require(actual[1:3] == (kind, table) and type(actual[3]) is str
            and " ".join(actual[3].split()) == " ".join(sql.split()))
    marker = conn.execute(f"SELECT singleton,substr(schema,1,128),substr(owner_id,1,37),"
        f"length(schema),length(owner_id) FROM main.{META} LIMIT 2").fetchall()
    _require(len(marker) == 1
        and tuple(marker[0]) == (1, SCHEMA, owner.owner_id, len(SCHEMA), 36))


def _records(conn: sqlite3.Connection, owner: DevelopmentOwner) -> list[XPrivateEnvelope]:
    _schema(conn, owner)
    # First bound every retained value before fetching any profile or ciphertext.
    sizes = conn.execute(f"SELECT typeof(config_version),typeof(profile_json),length(CAST(profile_json AS BLOB)),"
        f"typeof(nonce),length(nonce),typeof(ciphertext),length(ciphertext) FROM main.{TABLE} "
        "ORDER BY config_version LIMIT ?", (MAX_VERSIONS + 1,)).fetchall()
    _require(len(sizes) <= MAX_VERSIONS and all(tuple(row[:2]) == ("integer", "text")
        and type(row[2]) is int and 1 <= row[2] <= MAX_PROFILE_BYTES
        and row[3] == "blob" and row[4] == 12 and row[5] == "blob"
        and type(row[6]) is int and 17 <= row[6] <= MAX_SECRET_BYTES + 16 for row in sizes))
    rows = conn.execute(f"SELECT config_version,profile_json,nonce,ciphertext FROM main.{TABLE} "
        "ORDER BY config_version LIMIT ?", (MAX_VERSIONS + 1,)).fetchall()
    _require(len(rows) == len(sizes) and len(rows) <= MAX_VERSIONS)
    result = []
    for version, public_profile, nonce, ciphertext in rows:
        exact = XBinding(owner.owner_id, version, public_profile)
        _binding(owner, exact)
        _require(type(nonce) is bytes and len(nonce) == 12 and type(ciphertext) is bytes
            and 17 <= len(ciphertext) <= MAX_SECRET_BYTES + 16)
        result.append(XPrivateEnvelope(exact, nonce, ciphertext))
    return result


def install_empty_store(conn: sqlite3.Connection, owner: DevelopmentOwner) -> None:
    """Explicit first-configuration DDL; caller owns absence proof/audit/commit."""
    _transaction(conn, owner, writing=True)
    try:
        _require(not _objects(conn))
        for _, _, _, sql in _DEFINITIONS:
            conn.execute(sql)
        conn.execute(f"INSERT INTO main.{META} VALUES(1,?,?)", (SCHEMA, owner.owner_id))
        _require(not _records(conn, owner))
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def insert_secret(conn: sqlite3.Connection, owner: DevelopmentOwner, binding: XBinding,
        *, key: bytes, secret: str) -> None:
    """Append the exact selected version; never initialize, replace or commit."""
    _transaction(conn, owner, writing=True)
    _binding(owner, binding)
    try:
        records = _records(conn, owner)
        _require(len(records) < MAX_VERSIONS
            and all(item.binding.config_version != binding.config_version for item in records))
        envelope = seal_x(owner, binding, key=key, secret=secret)
        conn.execute(f"INSERT INTO main.{TABLE} VALUES(?,?,?,?)", (binding.config_version,
            binding.profile_json, envelope.nonce, envelope.ciphertext))
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def _matching_envelope(conn: sqlite3.Connection, owner: DevelopmentOwner,
        binding: XBinding) -> XPrivateEnvelope:
    _transaction(conn, owner)
    _binding(owner, binding)
    try:
        matches = [item for item in _records(conn, owner) if item.binding == binding]
        _require(len(matches) == 1)
        return matches[0]
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def inspect_public_binding(conn: sqlite3.Connection, owner: DevelopmentOwner, binding: XBinding) -> dict:
    """Inspect exact binding; present means structural, not decryptable or active."""
    return _public_view(_matching_envelope(conn, owner, binding).binding)


def inspect_public_roster(conn: sqlite3.Connection, owner: DevelopmentOwner) -> tuple[dict, ...]:
    """Return every validated public binding in ascending configuration version.

    Wholly absent storage raises CustodyAbsent; an installed empty store returns
    (). No key or decryption is used. The caller must compare this complete
    structural roster to its selected setup/history, not infer activation from it.
    """
    _transaction(conn, owner)
    try:
        return tuple(_public_view(item.binding) for item in _records(conn, owner))
    except sqlite3.Error:
        raise CustodyError(_ERROR) from None


def read_secret(conn: sqlite3.Connection, owner: DevelopmentOwner, binding: XBinding,
        *, key: bytes) -> XSecretMaterial:
    """Decrypt this exact binding in the existing snapshot; never select latest."""
    return open_x(owner, _matching_envelope(conn, owner, binding), key=key)
