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
from cryptography.exceptions import UnsupportedAlgorithm
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
from serverware.webauthn_trust_core import (
    MAX_INSTALLATION_BYTES,
    MAX_PUBLIC_KEY_BYTES,
    MAX_SCHEMA_BYTES,
    MAX_STATE_BYTES,
    TrustVerificationContext,
    VerifiedBundle,
    WebAuthnTrustError,
    plan_rollback,
    verify_bundle,
)


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
        if not isinstance(key, Ed25519PrivateKey):
            raise WebAuthnTrustError("WebAuthn trust signing key must be Ed25519")
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
    # Reading/verifying trust never creates or repairs a signer. Explicit local
    # signing below remains the separate development/provisioning operation.
    try:
        raw = _read_bounded(WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH, MAX_PUBLIC_KEY_BYTES)
        public = serialization.load_pem_public_key(raw)
    except (OSError, ValueError, UnsupportedAlgorithm) as exc:
        raise WebAuthnTrustError("WebAuthn trust public key is unavailable or invalid") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise WebAuthnTrustError("WebAuthn trust public key must be Ed25519")
    return public


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
    private_key = _load_private_key()
    signed = copy.deepcopy(raw)
    signed.setdefault("metadata", {})
    signed["metadata"]["signingKeyId"] = _public_key_hash(private_key.public_key())
    signed["metadata"].pop("signature", None)
    signature = private_key.sign(canonical_json(signature_payload(signed)).encode("utf-8"))
    signed["metadata"]["signature"] = "ed25519:" + b64e(signature)
    return signed


def _read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise WebAuthnTrustError("WebAuthn trust artifact exceeds its byte bound")
    return raw


def _capture_verification_context() -> TrustVerificationContext:
    public = trust_public_key()
    try:
        schema = _read_bounded(SCHEMA_DIR / "webauthn-trust-bundle.v1.schema.json", MAX_SCHEMA_BYTES)
    except OSError as exc:
        raise WebAuthnTrustError("WebAuthn trust schema is unavailable") from exc
    return TrustVerificationContext(
        public_key_der=public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        schema_bytes=schema,
        verified_at=datetime.now(timezone.utc),
    )


def _verify_bundle(
    bundle: dict[str, Any], context: TrustVerificationContext | None = None
) -> VerifiedBundle:
    # These bytes are reconstructed from the already-decoded API object. They
    # must never be labelled the original HTTP request or installed file bytes.
    try:
        raw = canonical_json(bundle).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle is not encodable JSON") from exc
    return verify_bundle(raw, context if context is not None else _capture_verification_context())


def _state_bytes() -> bytes | None:
    try:
        return _read_bounded(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, MAX_STATE_BYTES)
    except FileNotFoundError:
        return None


def _state() -> dict[str, Any]:
    raw = _state_bytes()
    if raw is None:
        return {"version": 1}
    try:
        state = json.loads(raw.decode("utf-8"))
        if not isinstance(state, dict):
            raise ValueError("state must be an object")
        return state
    except (ValueError, UnicodeError) as exc:
        raise WebAuthnTrustError(f"WebAuthn trust state is corrupt: {exc}") from exc


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


def verify_trust_bundle(bundle: dict[str, Any], *, update_state: bool = True) -> dict[str, Any]:
    context = _capture_verification_context()
    verified = _verify_bundle(bundle, context)
    if update_state:
        state = plan_rollback(verified, _state_bytes(), context)
        if state is not None:
            _durable_replace(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, state, mode=0o600)
    return verified.info_dict()


def _verified_roots(verified: VerifiedBundle) -> list[TrustRoot]:
    return [TrustRoot(
        id=root.id, cert=x509.load_der_x509_certificate(root.certificate_der),
        authenticator_class=root.authenticator_class, aaguids=root.aaguids,
        certificate_sha256=root.certificate_sha256, bundle_digest=verified.bundle_digest,
        bundle_sequence=verified.sequence, bundle_rollback_epoch=verified.rollback_epoch,
    ) for root in verified.roots]


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
        context = _capture_verification_context()
        verified = verify_bundle(_read_bounded(WEBAUTHN_TRUST_BUNDLE_PATH, MAX_INSTALLATION_BYTES), context)
        state = plan_rollback(verified, _state_bytes(), context)
        if state is not None:
            _durable_replace(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, state, mode=0o600)
        return _verified_roots(verified)
    return _legacy_roots_from_path(WEBAUTHN_TRUST_ROOTS_PATH)


def trust_roots_from_bundle(
    bundle: dict[str, Any], *, update_state: bool = True
) -> list[TrustRoot]:
    context = _capture_verification_context()
    verified = _verify_bundle(bundle, context)
    if update_state:
        state = plan_rollback(verified, _state_bytes(), context)
        if state is not None:
            _durable_replace(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, state, mode=0o600)
    return _verified_roots(verified)


def write_trust_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    with trust_bundle_lock(exclusive=True):
        context = _capture_verification_context()
        return _install_verified_bundle(_verify_bundle(bundle, context), context)


def _install_verified_bundle(
    verified: VerifiedBundle, context: TrustVerificationContext
) -> dict[str, Any]:
    """Install under the caller's exclusive lock; return unsigned local facts."""
    result, _, _ = _install_verified_bundle_with_readback(verified, context)
    return result


def _install_verified_bundle_with_readback(
    verified: VerifiedBundle, context: TrustVerificationContext
) -> tuple[dict[str, Any], bytes, bytes]:
    """Install under the caller's exclusive lock and retain exact readback bytes.

    Validation precedes both writes. State-first ordering retains the existing
    fail-closed recovery boundary: a failed bundle replacement may leave state
    ahead. The same pending publication can retry that exact generation; later
    generations retain the existing monotonicity rules and need their own
    authorization. Neither two-file atomicity nor independent rollback
    authority is claimed.

    The result and bytes are ordinary local observations, not installation
    authorization or evidence of an independently admitted committed stage.
    """
    previous_state = _state_bytes()
    next_state = plan_rollback(verified, previous_state, context)
    expected_state = next_state if next_state is not None else previous_state
    if expected_state is None:
        raise WebAuthnTrustError("WebAuthn installation has no rollback state")
    # Re-persist even unchanged bytes: a preceding attempt may have renamed the
    # state but failed its directory fsync. The state directory can differ from
    # the bundle directory, so syncing only the latter cannot repair that gap.
    _durable_replace(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, expected_state, mode=0o600)
    _durable_replace(WEBAUTHN_TRUST_BUNDLE_PATH, verified.installation_bytes, mode=0o600)
    installed_bytes = _read_bounded(WEBAUTHN_TRUST_BUNDLE_PATH, MAX_INSTALLATION_BYTES)
    installed_state = _state_bytes()
    if installed_bytes != verified.installation_bytes or installed_state != expected_state:
        raise WebAuthnTrustError("WebAuthn trust installation readback changed")
    result = {
        "ok": True,
        **verified.info_dict(),
        "root_count": len(verified.roots),
        "root_certificate_sha256": sorted(root.certificate_sha256 for root in verified.roots),
        "local_installation": {
            "schema": "serverware.webauthnLocalInstallationObservation/v1",
            "bundleDigest": verified.bundle_digest,
            "bundleFileDigest": sha256_prefixed(installed_bytes),
            "stateFileDigest": sha256_prefixed(expected_state),
            "bundlePath": str(WEBAUTHN_TRUST_BUNDLE_PATH),
            "statePath": str(WEBAUTHN_TRUST_BUNDLE_STATE_PATH),
            "verifiedAt": verified.verified_at.isoformat(),
        },
    }
    return result, installed_bytes, installed_state


def reconcile_trust_publications(
    *, expected_publication_id: str | None = None
) -> dict[str, Any]:
    from serverware import db

    publication = None
    try:
        with trust_bundle_lock(exclusive=True):
            # Re-read the journal under the same lock that protects installation;
            # a pre-lock observation can have completed while waiting for it.
            publication = db.get_pending_webauthn_trust_publication()
            if publication is None:
                return {"ok": True, "reconciled": False}
            if expected_publication_id is not None and publication["id"] != expected_publication_id:
                raise WebAuthnTrustError("a different WebAuthn trust publication is pending")
            context = _capture_verification_context()
            bundle = publication["bundle"]
            verified = _verify_bundle(bundle, context)
            info = verified.info_dict()
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
                    disk = verify_bundle(
                        _read_bounded(WEBAUTHN_TRUST_BUNDLE_PATH, MAX_INSTALLATION_BYTES), context
                    )
                    disk_digest = disk.bundle_digest
                except (OSError, WebAuthnTrustError) as exc:
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
            # Already holding the exclusive lock: do not nest flock acquisition.
            # The local observation is not the missing signed installation
            # receipt; ID-only legacy completion remains an authority blocker.
            result = _install_verified_bundle(verified, context)
            completed = db.complete_webauthn_trust_publication(publication["id"])
            return {
                **result,
                "reconciled": True,
                "publication_id": completed["id"],
            }
    except Exception as exc:
        if publication is not None:
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
        "state": _state(),
    }
    if WEBAUTHN_TRUST_BUNDLE_PATH.exists():
        context = _capture_verification_context()
        verified = verify_bundle(_read_bounded(WEBAUTHN_TRUST_BUNDLE_PATH, MAX_INSTALLATION_BYTES), context)
        state = plan_rollback(verified, _state_bytes(), context)
        if state is not None:
            _durable_replace(WEBAUTHN_TRUST_BUNDLE_STATE_PATH, state, mode=0o600)
            result["state"] = json.loads(state)
        result["mode"] = "signed-bundle"
        result["signing_key_id"] = verified.signing_key_id
        result["bundle"] = verified.info_dict()
        result["roots"] = [
            {
                "id": root.id,
                "authenticator_class": root.authenticator_class,
                "aaguids": sorted(root.aaguids),
                "certificate_sha256": root.certificate_sha256,
                "bundle_digest": root.bundle_digest,
            }
            for root in _verified_roots(verified)
        ]
    else:
        roots = _legacy_roots_from_path(WEBAUTHN_TRUST_ROOTS_PATH)
        result["mode"] = "legacy-pem"
        result["signing_key_id"] = trust_public_key_hash()
        result["roots"] = [
            {"id": root.id, "certificate_sha256": root.certificate_sha256}
            for root in roots
        ]
    return result
