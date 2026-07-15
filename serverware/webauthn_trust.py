from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware.config import (
    SCHEMA_DIR,
    WEBAUTHN_TRUST_BUNDLE_PATH,
    WEBAUTHN_TRUST_BUNDLE_STATE_PATH,
    WEBAUTHN_TRUST_ROOTS_PATH,
    WEBAUTHN_TRUST_SIGNING_KEY_PATH,
    WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH,
    ensure_data_dirs,
)


class WebAuthnTrustError(ValueError):
    pass


@contextmanager
def trust_bundle_lock(*, exclusive: bool):
    lock_path = WEBAUTHN_TRUST_BUNDLE_PATH.with_name(
        WEBAUTHN_TRUST_BUNDLE_PATH.name + ".lock"
    )
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def trust_read_locked(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with trust_bundle_lock(exclusive=False):
            return function(*args, **kwargs)

    return wrapped


@dataclass(frozen=True)
class TrustRoot:
    id: str
    cert: x509.Certificate
    authenticator_class: str | None
    aaguids: frozenset[str]
    certificate_sha256: str
    bundle_digest: str | None
    bundle_sequence: int | None
    bundle_rollback_epoch: int | None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_pem_certificates(raw: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    marker = b"-----END CERTIFICATE-----"
    for chunk in raw.split(marker):
        if b"-----BEGIN CERTIFICATE-----" not in chunk:
            continue
        certs.append(x509.load_pem_x509_certificate(chunk + marker + b"\n"))
    return certs


def load_certificate(raw: bytes) -> x509.Certificate:
    if b"-----BEGIN CERTIFICATE-----" in raw:
        certs = _load_pem_certificates(raw)
        if len(certs) != 1:
            raise WebAuthnTrustError("trust root entry must contain exactly one certificate")
        return certs[0]
    return x509.load_der_x509_certificate(raw)


def cert_digest(cert: x509.Certificate) -> str:
    return sha256_prefixed(cert.public_bytes(serialization.Encoding.DER))


def _public_key_hash(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def _write_public_key(public_key: Ed25519PublicKey) -> None:
    WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH, 0o644)


def _load_private_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if WEBAUTHN_TRUST_SIGNING_KEY_PATH.exists():
        key = serialization.load_pem_private_key(WEBAUTHN_TRUST_SIGNING_KEY_PATH.read_bytes(), password=None)
        _write_public_key(key.public_key())
        return key
    key = Ed25519PrivateKey.generate()
    WEBAUTHN_TRUST_SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEBAUTHN_TRUST_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(WEBAUTHN_TRUST_SIGNING_KEY_PATH, 0o600)
    _write_public_key(key.public_key())
    return key


def trust_public_key() -> Ed25519PublicKey:
    if WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH.exists():
        public = serialization.load_pem_public_key(WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH.read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise WebAuthnTrustError("WebAuthn trust public key must be Ed25519")
        return public
    return _load_private_key().public_key()


def trust_public_key_hash() -> str:
    return _public_key_hash(trust_public_key())


def signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(bundle)
    metadata = unsigned.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
    return unsigned


def trust_bundle_digest(bundle: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_json(signature_payload(bundle)).encode("utf-8"))


def sign_trust_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(raw)
    signed.setdefault("metadata", {})
    signed["metadata"]["signingKeyId"] = trust_public_key_hash()
    signed["metadata"].pop("signature", None)
    signature = _load_private_key().sign(canonical_json(signature_payload(signed)).encode("utf-8"))
    signed["metadata"]["signature"] = "ed25519:" + b64e(signature)
    return signed


def _load_schema() -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / "webauthn-trust-bundle.v1.schema.json").read_text(encoding="utf-8"))


def validate_trust_bundle_schema(bundle: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator, ValidationError
    except Exception as exc:
        raise WebAuthnTrustError("jsonschema package is required for WebAuthn trust validation") from exc
    try:
        Draft202012Validator(_load_schema()).validate(bundle)
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise WebAuthnTrustError(f"WebAuthn trust bundle schema validation failed{location}: {exc.message}") from exc


def verify_trust_bundle_signature(bundle: dict[str, Any]) -> None:
    signature_value = (bundle.get("metadata") or {}).get("signature")
    if not isinstance(signature_value, str) or not signature_value.startswith("ed25519:"):
        raise WebAuthnTrustError("WebAuthn trust bundle must include metadata.signature using ed25519")
    expected_key = (bundle.get("metadata") or {}).get("signingKeyId")
    actual_key = trust_public_key_hash()
    if expected_key != actual_key:
        raise WebAuthnTrustError("WebAuthn trust bundle signing key mismatch")
    try:
        trust_public_key().verify(
            b64d(signature_value.split(":", 1)[1]),
            canonical_json(signature_payload(bundle)).encode("utf-8"),
        )
    except InvalidSignature as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle signature verification failed") from exc


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_time_window(bundle: dict[str, Any]) -> None:
    metadata = bundle.get("metadata") or {}
    now = datetime.now(timezone.utc)
    valid_from = _parse_time(metadata.get("validFrom"))
    valid_until = _parse_time(metadata.get("validUntil"))
    if valid_from and now < valid_from:
        raise WebAuthnTrustError("WebAuthn trust bundle is not valid yet")
    if valid_until and now > valid_until:
        raise WebAuthnTrustError("WebAuthn trust bundle is expired")


def _state() -> dict[str, Any]:
    if not WEBAUTHN_TRUST_BUNDLE_STATE_PATH.exists():
        return {"version": 1}
    try:
        return json.loads(WEBAUTHN_TRUST_BUNDLE_STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebAuthnTrustError(f"WebAuthn trust state is corrupt: {exc}") from exc


def _write_state(state: dict[str, Any]) -> None:
    ensure_data_dirs()
    _durable_replace(
        WEBAUTHN_TRUST_BUNDLE_STATE_PATH,
        (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )


def _durable_replace(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _enforce_rollback(bundle: dict[str, Any], digest: str) -> None:
    metadata = bundle.get("metadata") or {}
    sequence = int(metadata.get("sequence", 0))
    rollback_epoch = int(metadata.get("rollbackEpoch", 0))
    state = _state()
    last_sequence = int(state.get("sequence", 0) or 0)
    last_epoch = int(state.get("rollback_epoch", 0) or 0)
    if rollback_epoch < last_epoch:
        raise WebAuthnTrustError("WebAuthn trust bundle rollback epoch is stale")
    if rollback_epoch == last_epoch and sequence < last_sequence:
        raise WebAuthnTrustError("WebAuthn trust bundle sequence is stale")
    if (
        state.get("bundle_digest")
        and rollback_epoch == last_epoch
        and sequence == last_sequence
        and digest != state.get("bundle_digest")
    ):
        raise WebAuthnTrustError(
            "WebAuthn trust bundle content changed without advancing sequence"
        )
    if (
        sequence != last_sequence
        or rollback_epoch != last_epoch
        or digest != state.get("bundle_digest")
    ):
        _write_state(
            {
                "version": 1,
                "bundle_digest": digest,
                "sequence": sequence,
                "rollback_epoch": rollback_epoch,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def verify_trust_bundle(bundle: dict[str, Any], *, update_state: bool = True) -> dict[str, Any]:
    validate_trust_bundle_schema(bundle)
    verify_trust_bundle_signature(bundle)
    _validate_time_window(bundle)
    digest = trust_bundle_digest(bundle)
    if update_state:
        _enforce_rollback(bundle, digest)
    metadata = bundle.get("metadata") or {}
    return {
        "digest": digest,
        "sequence": int(metadata.get("sequence", 0)),
        "rollback_epoch": int(metadata.get("rollbackEpoch", 0)),
        "signing_key_id": metadata.get("signingKeyId"),
    }


def _trust_root_from_bundle_item(item: dict[str, Any], bundle_info: dict[str, Any]) -> TrustRoot:
    cert = load_certificate(item["certificatePem"].encode("utf-8"))
    digest = cert_digest(cert)
    if item.get("certificateSha256") and item["certificateSha256"] != digest:
        raise WebAuthnTrustError(f"WebAuthn trust root {item.get('id')} certificate digest mismatch")
    return TrustRoot(
        id=item["id"],
        cert=cert,
        authenticator_class=item.get("authenticatorClass"),
        aaguids=frozenset(item.get("aaguids") or []),
        certificate_sha256=digest,
        bundle_digest=bundle_info["digest"],
        bundle_sequence=bundle_info["sequence"],
        bundle_rollback_epoch=bundle_info["rollback_epoch"],
    )


def _legacy_roots_from_path(path: Path) -> list[TrustRoot]:
    if not path.exists():
        return []
    files: list[Path]
    if path.is_dir():
        files = sorted(
            item
            for item in path.iterdir()
            if item.is_file() and item.suffix.lower() in {".pem", ".crt", ".cer"}
        )
    else:
        files = [path]
    roots: list[TrustRoot] = []
    for item in files:
        raw = item.read_bytes()
        certs = _load_pem_certificates(raw) if b"-----BEGIN CERTIFICATE-----" in raw else [load_certificate(raw)]
        for index, cert in enumerate(certs):
            roots.append(
                TrustRoot(
                    id=f"legacy:{item.name}:{index}",
                    cert=cert,
                    authenticator_class=None,
                    aaguids=frozenset(),
                    certificate_sha256=cert_digest(cert),
                    bundle_digest=None,
                    bundle_sequence=None,
                    bundle_rollback_epoch=None,
                )
            )
    return roots


def load_trust_roots() -> list[TrustRoot]:
    if WEBAUTHN_TRUST_BUNDLE_PATH.exists():
        bundle = json.loads(WEBAUTHN_TRUST_BUNDLE_PATH.read_text(encoding="utf-8"))
        return trust_roots_from_bundle(bundle)
    return _legacy_roots_from_path(WEBAUTHN_TRUST_ROOTS_PATH)


def trust_roots_from_bundle(
    bundle: dict[str, Any], *, update_state: bool = True
) -> list[TrustRoot]:
    bundle_info = verify_trust_bundle(bundle, update_state=update_state)
    return [
        _trust_root_from_bundle_item(item, bundle_info)
        for item in bundle.get("roots") or []
    ]


def write_trust_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    roots = trust_roots_from_bundle(bundle)
    info = verify_trust_bundle(bundle, update_state=False)
    _durable_replace(
        WEBAUTHN_TRUST_BUNDLE_PATH,
        (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    return {
        "ok": True,
        **info,
        "root_count": len(roots),
        "root_certificate_sha256": sorted(root.certificate_sha256 for root in roots),
    }


def reconcile_trust_publications(
    *, expected_publication_id: str | None = None
) -> dict[str, Any]:
    from serverware import db

    publication = db.get_pending_webauthn_trust_publication()
    if publication is None:
        return {"ok": True, "reconciled": False}
    if (
        expected_publication_id is not None
        and publication["id"] != expected_publication_id
    ):
        raise WebAuthnTrustError("a different WebAuthn trust publication is pending")
    try:
        with trust_bundle_lock(exclusive=True):
            bundle = publication["bundle"]
            info = verify_trust_bundle(bundle, update_state=False)
            if (
                info["digest"] != publication["bundle_digest"]
                or info["sequence"] != publication["sequence"]
                or info["rollback_epoch"] != publication["rollback_epoch"]
                or info["signing_key_id"] != publication["signing_key_id"]
            ):
                raise WebAuthnTrustError(
                    "pending WebAuthn trust publication does not match its journal"
                )
            for record_id in publication["withdrawn_credential_ids"]:
                credential = db.get_webauthn_credential_by_record_id(
                    record_id, include_revoked=True
                )
                if credential is None or credential.get("revoked_at") is None:
                    raise WebAuthnTrustError(
                        "pending WebAuthn trust publication has an active withdrawn credential"
                    )
            disk_digest = None
            if WEBAUTHN_TRUST_BUNDLE_PATH.exists():
                try:
                    disk_bundle = json.loads(
                        WEBAUTHN_TRUST_BUNDLE_PATH.read_text(encoding="utf-8")
                    )
                    disk_digest = verify_trust_bundle(
                        disk_bundle, update_state=False
                    )["digest"]
                except (OSError, json.JSONDecodeError, WebAuthnTrustError) as exc:
                    raise WebAuthnTrustError(
                        "installed WebAuthn trust bundle is not recoverable"
                    ) from exc
            if disk_digest not in {
                publication["previous_bundle_digest"],
                publication["bundle_digest"],
            }:
                raise WebAuthnTrustError(
                    "installed WebAuthn trust bundle does not match publication history"
                )
            result = write_trust_bundle(bundle)
            completed = db.complete_webauthn_trust_publication(publication["id"])
            return {
                **result,
                "reconciled": True,
                "publication_id": completed["id"],
            }
    except Exception as exc:
        try:
            db.record_webauthn_trust_publication_error(
                publication["id"], f"{type(exc).__name__}: {exc}"
            )
        except Exception:
            pass
        raise


def status() -> dict[str, Any]:
    result: dict[str, Any] = {
        "bundle_path": str(WEBAUTHN_TRUST_BUNDLE_PATH),
        "legacy_roots_path": str(WEBAUTHN_TRUST_ROOTS_PATH),
        "signing_key_id": trust_public_key_hash(),
        "state": _state(),
    }
    if WEBAUTHN_TRUST_BUNDLE_PATH.exists():
        bundle = json.loads(WEBAUTHN_TRUST_BUNDLE_PATH.read_text(encoding="utf-8"))
        info = verify_trust_bundle(bundle)
        result["mode"] = "signed-bundle"
        result["bundle"] = info
        result["roots"] = [
            {
                "id": root.id,
                "authenticator_class": root.authenticator_class,
                "aaguids": sorted(root.aaguids),
                "certificate_sha256": root.certificate_sha256,
                "bundle_digest": root.bundle_digest,
            }
            for root in load_trust_roots()
        ]
    else:
        roots = _legacy_roots_from_path(WEBAUTHN_TRUST_ROOTS_PATH)
        result["mode"] = "legacy-pem"
        result["roots"] = [
            {"id": root.id, "certificate_sha256": root.certificate_sha256}
            for root in roots
        ]
    return result
