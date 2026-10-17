"""Offline, one-way ordinary policy migration; never a serving compatibility mode.

The caller owns a stopped source, a fresh private staging target, its publication
lock and the target SQLite transaction. Failure leaves staging unpublishable;
the caller must not start it or replay migration over partially written files.
Historical signed bytes are verified and archived, not renamed in place.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LEGACY_POLICY = "serverware-operator-demo"
CURRENT_POLICY = "catchplate-operator-demo"
LINEAGE = "catchplate.rebrandPolicyLineage/v1"
MAX_BUNDLE = 16 * 1024 * 1024
KEY_FILES = ("policy-signing-ed25519.pem", "policy-signing-ed25519.pub.pem", "response-signing-ed25519.pem")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


class PolicyMigrationError(ValueError):
    """Closed refusal; no keys, tokens, policy values or raw exceptions exposed."""


def _need(value):
    if not value:
        raise PolicyMigrationError("ordinary policy rebrand refused")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: _need(False))


def _directory(path):
    _need(isinstance(path, Path))
    _need(path.is_absolute() and path.resolve() == path and path.is_dir()
        and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0)


def _read(path, limit):
    _need(path.parent.resolve() == path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        _need(len(raw) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return raw
    finally:
        os.close(fd)


def _write(path, raw, *, replace=False):
    _need(path.parent.resolve() == path.parent)
    if not replace:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    else:
        fd, temporary = tempfile.mkstemp(prefix=".rebrand-policy-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _protocol_only(before, after, path=()):
    """Allow only generated protocol labels; never arbitrary string replacement."""
    _need(type(before) is type(after))
    if isinstance(before, dict):
        _need(before.keys() == after.keys())
        for key in before:
            _protocol_only(before[key], after[key], (*path, key))
    elif isinstance(before, list):
        _need(len(before) == len(after))
        for index, (old, new) in enumerate(zip(before, after)):
            _protocol_only(old, new, (*path, index))
    elif before != after:
        _need(type(before) is str)
        if path == ("metadata", "id"):
            _need((before, after) == (LEGACY_POLICY, CURRENT_POLICY))
        elif path[-1:] in {("schema",), ("apiVersion",)}:
            _need(re.fullmatch(r"catchplate\.[A-Za-z][A-Za-z0-9]*/v[1-9][0-9]*", after) is not None
                and before == "serverware" + after[len("catchplate"):])
        elif path == ("routes", 0, "match", "paths", 0):
            _need((before, after) == ("/__serverware_operator_demo_unconfigured__", "/__catchplate_operator_demo_unconfigured__"))
        elif len(path) == 4 and path[0] == "routes" and path[2:] == ("credentialHeader", "expectedValue"):
            from catchplate import operator_common_apps
            known = {item["placeholder"] for item in operator_common_apps.presets()}
            known.update({"token catchplate-github-placeholder-v1", "Bearer catchplate-npm-placeholder-v1",
                "Bearer catchplate-x-placeholder-v1", "Bearer catchplate-x-post-placeholder-v1",
                "Bearer catchplate-alchemy-placeholder-v1"})
            _need(after in known and before == after.replace("catchplate-", "serverware-", 1))
        else:
            _need(False)


def _identity(catalog):
    fields = {"id", "ordinal", "name", "status", "version", "application_id", "credential_id", "route_id",
        "provider_subject", "principal_id", "token_sha256", "token_version", "token_expires_at_epoch_ms", "client_renewal"}
    return {collection: [{key: row[key] for key in fields if key in row} for row in catalog[collection]]
        for collection in ("credentials", "applications", "access_rules")}


def prepare_policy_migration(source_conn, target_conn, source_data: Path, target_data: Path,
        source_gate_data: Path, target_gate_data: Path) -> dict:
    """Stage a linked N+1 policy/high-water; caller commits, publishes and starts.

Source SQLite must be read-only. Target holds an existing transaction containing
the imported catalog and the unchanged legacy operator_demo_policy singleton.
No legacy protocol is accepted by the normal compiler or serving gate.
"""
    try:
        return _prepare(source_conn, target_conn, source_data, target_data, source_gate_data, target_gate_data)
    except PolicyMigrationError:
        raise
    except Exception:
        raise PolicyMigrationError("ordinary policy rebrand refused") from None


def _prepare(source_conn, target_conn, source_data, target_data, source_gate_data, target_gate_data):
    from catchplate import config, operator_catalog_schema as catalog, operator_catalog_policy as policy
    from catchplate import operator_publication, policy_bundle
    operator_publication.assert_held()
    for path in (source_data, target_data, source_gate_data, target_gate_data):
        _directory(path)
    roots = (source_data, target_data, source_gate_data, target_gate_data)
    _need(all(not left.is_relative_to(right) for left in roots for right in roots if left is not right)
        and len(set(roots)) == 4
        and source_conn is not target_conn and source_conn.execute("PRAGMA query_only").fetchone()[0] == 1
        and target_conn.in_transaction and config.DATA_DIR == target_data
        and policy_bundle.POLICY_SIGNING_KEY_PATH == target_data / KEY_FILES[0]
        and policy_bundle.POLICY_SIGNING_PUBLIC_KEY_PATH == target_data / KEY_FILES[1])
    for conn, path in ((source_conn, source_data / "serverware.sqlite3"), (target_conn, target_data / "catchplate.sqlite3")):
        main = [row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"]
        _need(main == [str(path)] and path.resolve() == path)
    rows = source_conn.execute("SELECT * FROM operator_demo_policy").fetchall()
    target_rows = target_conn.execute("SELECT * FROM operator_demo_policy").fetchall()
    _need(len(rows) == len(target_rows) == 1 and dict(rows[0]) == dict(target_rows[0]))
    retained = dict(rows[0]); old_bytes = retained["signed_bundle_json"].encode()
    _need(0 < len(old_bytes) <= MAX_BUNDLE and retained["singleton"] == 1)
    old = _json(old_bytes); meta = old["metadata"]
    sequence = retained["sequence"]
    _need(type(sequence) is int and 1 <= sequence < 9_007_199_254_740_991
        and old["apiVersion"] == "serverware.policy/v1" and meta["id"] == LEGACY_POLICY
        and type(meta["sequence"]) is int and meta["sequence"] == sequence
        and type(meta["rollbackEpoch"]) is int and meta["rollbackEpoch"] == 1
        and _SHA.fullmatch(retained["initial_hash"]) is not None)
    key_bytes = {name: _read(source_data / name, 8192) for name in KEY_FILES}
    _need(all(_read(target_data / name, 8192) == raw for name, raw in key_bytes.items()))
    private = serialization.load_pem_private_key(key_bytes[KEY_FILES[0]], password=None)
    public = serialization.load_pem_public_key(key_bytes[KEY_FILES[1]])
    response = serialization.load_pem_private_key(key_bytes[KEY_FILES[2]], password=None)
    _need(isinstance(private, Ed25519PrivateKey) and isinstance(public, Ed25519PublicKey)
        and isinstance(response, Ed25519PrivateKey))
    public_bytes = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _need(private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public_bytes
        and meta["signingKeyId"] == _digest(public_bytes))
    unsigned = deepcopy(old); signature = unsigned["metadata"].pop("signature")
    _need(type(signature) is str and re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", signature) is not None)
    encoded_signature = signature.split(":", 1)[1]
    signature_bytes = base64.urlsafe_b64decode(encoded_signature + "==")
    _need(base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=") == encoded_signature)
    public.verify(signature_bytes, _canonical(unsigned))
    old_hash = _digest(_canonical(unsigned))
    _need(retained["policy_hash"] == old_hash and _read(source_data / "policy-bundle.json", MAX_BUNDLE) == old_bytes)
    old_water_bytes = _read(source_gate_data / "policy-high-water.json", 4096)
    old_water = _json(old_water_bytes)
    expected_water = {"api_version": "serverware.policyHighWater/v1", "policy_id": LEGACY_POLICY,
        "sequence": sequence, "rollback_epoch": 1, "policy_hash": old_hash}
    _need(_canonical(old_water) == _canonical(expected_water))
    before_catalog, after_catalog = catalog.read_catalog(source_conn), catalog.read_catalog(target_conn)
    _need(_canonical(_identity(before_catalog)) == _canonical(_identity(after_catalog))
        and before_catalog["revision"] == after_catalog["revision"])
    catalog.validate_bindings(target_conn, after_catalog)
    current = policy.render(after_catalog, sequence, retained["initial_hash"])
    old_unsigned = policy.unsigned(old)
    _protocol_only(old_unsigned, current)
    current["metadata"]["sequence"] = sequence + 1
    current["metadata"]["signingKeyId"] = meta["signingKeyId"]
    current["metadata"]["signature"] = "ed25519:" + base64.urlsafe_b64encode(private.sign(_canonical(current))).decode().rstrip("=")
    compiled = policy_bundle.compile_policy_bundle(current, verify_signature=True, validate_schema=True)
    new_bytes = _canonical(current)
    new_water = {"api_version": "catchplate.policyHighWater/v1", "policy_id": CURRENT_POLICY,
        "sequence": sequence + 1, "rollback_epoch": 1, "policy_hash": compiled.hash}
    archive = target_data / "rebrand-originals"
    _need(not os.path.lexists(archive))
    target_water = target_gate_data / "policy-high-water.json"
    if os.path.lexists(target_water):
        _need(_read(target_water, 4096) == old_water_bytes)
    target_policy = target_data / "policy-bundle.json"
    if os.path.lexists(target_policy):
        _read(target_policy, MAX_BUNDLE)  # Refuse links, special files and oversized stale exports.
    receipt = {"schema": LINEAGE, "source": expected_water, "target": new_water,
        "oldBundleSha256": _digest(old_bytes), "oldHighWaterSha256": _digest(old_water_bytes),
        "newBundleSha256": _digest(new_bytes), "signingKeyId": meta["signingKeyId"],
        "responseKeySha256": _digest(key_bytes[KEY_FILES[2]]),
        "catalogIdentitySha256": _digest(_canonical(_identity(after_catalog))), "catalogRevision": after_catalog["revision"]}
    receipt["signature"] = "ed25519:" + base64.urlsafe_b64encode(private.sign(LINEAGE.encode() + b"\0" + _canonical(receipt))).decode().rstrip("=")
    archive.mkdir(mode=0o700)
    _write(archive / "policy-bundle.json", old_bytes)
    _write(archive / "policy-high-water.json", old_water_bytes)
    _write(archive / "lineage.json", _canonical(receipt))
    changed = target_conn.execute("UPDATE operator_demo_policy SET sequence=?,policy_hash=?,signed_bundle_json=? WHERE singleton=1 AND sequence=? AND policy_hash=?",
        (sequence + 1, compiled.hash, new_bytes.decode(), sequence, old_hash)).rowcount
    _need(changed == 1)
    _write(target_policy, new_bytes, replace=True)
    _write(target_water, _canonical(new_water) + b"\n", replace=True)
    return receipt
