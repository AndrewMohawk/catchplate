"""Explicit-input WebAuthn trust-bundle verification and rollback planning.

No database, filesystem, configuration, signer provisioning or clock is used.
The supplied public key, measured schema and verification instant are trusted
integration inputs, not fields selected by the candidate bundle. Results are
immutable local computations, NOT stage authority, installation evidence,
signed receipts, or permission to complete an authority transition.

This profile newly bounds legacy direct writes by the existing 2 MiB journal
envelope and registration trust-snapshot limits: 256 roots, 64 KiB DER per root,
1024 AAGUIDs per root and 2 MiB total DER/descriptor material. Raw JSON may be
larger than its canonical envelope, including our own pretty installation
format. The fixed, pinned schema has bounded nesting and nonempty, long-form
root/AAGUID entries; four times the canonical ceiling generously covers its
indent=2 expansion. These byte bounds are not whole-process memory/RSS bounds.
Duplicate JSON keys, nonfinite values, noninteger counters, malformed times,
and malformed persisted checkpoints are denied rather than coerced.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


TRUST_BUNDLE_SCHEMA_SHA256 = (
    "68752c1d4af1dfc994f8b3238e33f393da8a5c1c4368f5b1c6e5767856c0d975"
)
MAX_CANONICAL_BYTES = 2 * 1024 * 1024
MAX_INSTALLATION_BYTES = 4 * MAX_CANONICAL_BYTES
MAX_INPUT_BYTES = MAX_INSTALLATION_BYTES
MAX_STATE_BYTES = 64 * 1024
MAX_SCHEMA_BYTES = 64 * 1024
MAX_PUBLIC_KEY_BYTES = 4096
MAX_TRUST_ROOTS = 256
MAX_ROOT_CERTIFICATE_BYTES = 64 * 1024
MAX_ROOT_AAGUIDS = 1024
MAX_TRUST_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_COUNTER = 2**63 - 1


class WebAuthnTrustError(ValueError):
    pass


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_bytes(value: bytes, label: str, maximum: int) -> None:
    if type(value) is not bytes or not 1 <= len(value) <= maximum:
        raise WebAuthnTrustError(f"WebAuthn trust {label} is invalid or oversized")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebAuthnTrustError("WebAuthn trust JSON contains duplicate keys")
        result[key] = value
    return result


def _nonfinite(_: str) -> Any:
    raise WebAuthnTrustError("WebAuthn trust JSON contains a nonfinite value")


def _json_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    _bounded_bytes(raw, label, maximum)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object,
            parse_constant=_nonfinite,
        )
    except WebAuthnTrustError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise WebAuthnTrustError(f"WebAuthn trust {label} is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be a JSON object")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WebAuthnTrustError("WebAuthn trust value is not canonical JSON") from exc


def _pretty(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
        allow_nan=False) + "\n").encode("ascii")


def _positive_counter(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_COUNTER:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be a positive bounded integer")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise WebAuthnTrustError(f"WebAuthn trust {label} digest is invalid")
    return value


def _time(value: Any, label: str) -> datetime:
    if type(value) is not str or not value:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be an aware timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError("naive timestamp")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be an aware timestamp") from exc


def _scalar_strings(value: Any) -> None:
    # Called only after validation against the closed, bounded-depth schema.
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise WebAuthnTrustError("WebAuthn trust bundle contains invalid Unicode") from exc
    elif type(value) is dict:
        for key, item in value.items():
            _scalar_strings(key)
            _scalar_strings(item)
    elif type(value) is list:
        for item in value:
            _scalar_strings(item)


def _public_key(raw: bytes) -> Ed25519PublicKey:
    _bounded_bytes(raw, "public key", MAX_PUBLIC_KEY_BYTES)
    try:
        key = serialization.load_der_public_key(raw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise WebAuthnTrustError("WebAuthn trust public key is not valid DER") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise WebAuthnTrustError("WebAuthn trust public key must be Ed25519")
    if key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo) != raw:
        raise WebAuthnTrustError("WebAuthn trust public key DER is not canonical SPKI")
    return key


@dataclass(frozen=True, slots=True)
class TrustVerificationContext:
    public_key_der: bytes
    schema_bytes: bytes
    verified_at: datetime

    def __post_init__(self) -> None:
        _public_key(self.public_key_der)
        _bounded_bytes(self.schema_bytes, "schema", MAX_SCHEMA_BYTES)
        if hashlib.sha256(self.schema_bytes).hexdigest() != TRUST_BUNDLE_SCHEMA_SHA256:
            raise WebAuthnTrustError("WebAuthn trust schema does not match the measured source schema")
        if (type(self.verified_at) is not datetime
            or self.verified_at.utcoffset() != timedelta(0)):
            raise WebAuthnTrustError("WebAuthn trust verification time must be explicit aware UTC")
        object.__setattr__(self, "verified_at", self.verified_at.replace(tzinfo=timezone.utc))


@dataclass(frozen=True, slots=True)
class VerifiedTrustRoot:
    id: str
    certificate_der: bytes
    certificate_sha256: str
    authenticator_class: str
    aaguids: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.id) is not str or not self.id:
            raise WebAuthnTrustError("WebAuthn trust root ID is invalid")
        _scalar_strings(self.id)
        _bounded_bytes(self.certificate_der, "root certificate", MAX_ROOT_CERTIFICATE_BYTES)
        _digest(self.certificate_sha256, "root certificate")
        if (type(self.authenticator_class) is not str
            or self.authenticator_class not in {"yubikey", "hardware", "platform"}):
            raise WebAuthnTrustError("WebAuthn trust root class is invalid")
        if type(self.aaguids) is not frozenset or len(self.aaguids) > MAX_ROOT_AAGUIDS:
            raise WebAuthnTrustError("WebAuthn trust root AAGUID set is invalid or oversized")
        if any(type(value) is not str or re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value) is None for value in self.aaguids):
            raise WebAuthnTrustError("WebAuthn trust root AAGUID is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    input_bytes: bytes
    input_digest: str
    canonical_envelope_bytes: bytes
    canonical_envelope_digest: str
    signature_payload_bytes: bytes
    bundle_digest: str
    installation_bytes: bytes
    installation_digest: str
    sequence: int
    rollback_epoch: int
    signing_key_id: str
    roots: tuple[VerifiedTrustRoot, ...]
    verified_at: datetime

    def __post_init__(self) -> None:
        # Immutability/type checks do not manufacture verification provenance.
        # plan_rollback separately rejoins every field to actual verification.
        for value, label, maximum in (
            (self.input_bytes, "input bytes", MAX_INPUT_BYTES),
            (self.canonical_envelope_bytes, "canonical envelope bytes", MAX_CANONICAL_BYTES),
            (self.signature_payload_bytes, "signature payload bytes", MAX_CANONICAL_BYTES),
            (self.installation_bytes, "installation bytes", MAX_INSTALLATION_BYTES),
        ):
            _bounded_bytes(value, label, maximum)
        for value, label in (
            (self.input_digest, "input"),
            (self.canonical_envelope_digest, "canonical envelope"),
            (self.bundle_digest, "bundle"),
            (self.installation_digest, "installation"),
            (self.signing_key_id, "signing key"),
        ):
            _digest(value, label)
        _positive_counter(self.sequence, "sequence")
        _positive_counter(self.rollback_epoch, "rollback epoch")
        if (type(self.roots) is not tuple or len(self.roots) > MAX_TRUST_ROOTS
            or any(type(root) is not VerifiedTrustRoot for root in self.roots)):
            raise WebAuthnTrustError("WebAuthn trust result roots are invalid or oversized")
        if (type(self.verified_at) is not datetime
            or self.verified_at.utcoffset() != timedelta(0)):
            raise WebAuthnTrustError("WebAuthn trust verification time must be explicit aware UTC")

    def info_dict(self) -> dict[str, Any]:
        return {"digest": self.bundle_digest, "sequence": self.sequence,
            "rollback_epoch": self.rollback_epoch, "signing_key_id": self.signing_key_id}

    def bundle_dict(self) -> dict[str, Any]:
        # A new JSON graph, never a mutable alias into the retained result.
        return _json_object(self.canonical_envelope_bytes, "bundle", MAX_CANONICAL_BYTES)


def _certificate(raw: bytes) -> x509.Certificate:
    try:
        if b"-----BEGIN CERTIFICATE-----" not in raw:
            return x509.load_der_x509_certificate(raw)
        marker = b"-----END CERTIFICATE-----"
        certificates = [x509.load_pem_x509_certificate(chunk + marker + b"\n")
            for chunk in raw.split(marker) if b"-----BEGIN CERTIFICATE-----" in chunk]
        if len(certificates) != 1:
            raise WebAuthnTrustError("trust root entry must contain exactly one certificate")
        return certificates[0]
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, WebAuthnTrustError):
            raise
        raise WebAuthnTrustError("WebAuthn trust root certificate is invalid") from exc


def verify_bundle(bundle_bytes: bytes, context: TrustVerificationContext) -> VerifiedBundle:
    """Verify a signed bundle completely, without changing any external state.

    Root validity/CA policy is not added here: the legacy bundle path loads
    certificates and checks their declared digests; attestation verification
    separately checks certificate times and chain policy. A parsed root alone
    does not establish hardware class or bundle provenance.
    """
    if type(context) is not TrustVerificationContext:
        raise WebAuthnTrustError("WebAuthn trust verification context is invalid")
    # Validate even a manually reconstructed context before using its bytes.
    context = TrustVerificationContext(context.public_key_der, context.schema_bytes,
        context.verified_at)
    bundle = _json_object(bundle_bytes, "bundle", MAX_INPUT_BYTES)
    canonical_envelope = _canonical(bundle)
    if len(canonical_envelope) > MAX_CANONICAL_BYTES:
        raise WebAuthnTrustError("WebAuthn trust canonical bundle exceeds 2 MiB")
    try:
        from jsonschema import Draft202012Validator, ValidationError
    except ImportError as exc:
        raise WebAuthnTrustError("jsonschema package is required for WebAuthn trust validation") from exc
    # The byte pin precedes parsing and schema use. The source schema contains
    # no references; callers cannot substitute a remote or permissive schema.
    schema = _json_object(context.schema_bytes, "schema", MAX_SCHEMA_BYTES)
    try:
        Draft202012Validator(schema).validate(bundle)
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise WebAuthnTrustError(
            f"WebAuthn trust bundle schema validation failed{location}: {exc.message}"
        ) from exc
    _scalar_strings(bundle)
    metadata = bundle["metadata"]
    sequence = _positive_counter(metadata["sequence"], "sequence")
    rollback_epoch = _positive_counter(metadata["rollbackEpoch"], "rollback epoch")
    signing_key_id = sha256_prefixed(context.public_key_der)
    if metadata["signingKeyId"] != signing_key_id:
        raise WebAuthnTrustError("WebAuthn trust bundle signing key mismatch")
    unsigned = {**bundle, "metadata": {key: value for key, value in metadata.items()
        if key != "signature"}}
    signature_payload = _canonical(unsigned)
    bundle_digest = sha256_prefixed(signature_payload)
    signature_text = metadata["signature"].split(":", 1)[1]
    try:
        signature = base64.b64decode(signature_text + "=" * (-len(signature_text) % 4),
            altchars=b"-_", validate=True)
        if len(signature) != 64:
            raise ValueError("wrong Ed25519 signature length")
    except (ValueError, binascii.Error) as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle signature encoding is invalid") from exc
    try:
        _public_key(context.public_key_der).verify(signature, signature_payload)
    except InvalidSignature as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle signature verification failed") from exc
    valid_from = _time(metadata["validFrom"], "validFrom")
    valid_until = (_time(metadata["validUntil"], "validUntil")
        if "validUntil" in metadata else None)
    if context.verified_at < valid_from:
        raise WebAuthnTrustError("WebAuthn trust bundle is not valid yet")
    if valid_until is not None and context.verified_at > valid_until:
        raise WebAuthnTrustError("WebAuthn trust bundle is expired")
    if len(bundle["roots"]) > MAX_TRUST_ROOTS:
        raise WebAuthnTrustError("WebAuthn trust root count exceeds the verification profile")
    roots: list[VerifiedTrustRoot] = []
    total_snapshot_bytes = 0
    for item in bundle["roots"]:
        aaguids = frozenset(item.get("aaguids", []))
        if len(aaguids) > MAX_ROOT_AAGUIDS:
            raise WebAuthnTrustError("WebAuthn trust root AAGUID set is oversized")
        certificate = _certificate(item["certificatePem"].encode("utf-8"))
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        if len(certificate_der) > MAX_ROOT_CERTIFICATE_BYTES:
            raise WebAuthnTrustError("WebAuthn trust root certificate is oversized")
        certificate_sha256 = sha256_prefixed(certificate_der)
        if ("certificateSha256" in item
            and item["certificateSha256"] != certificate_sha256):
            raise WebAuthnTrustError(f"WebAuthn trust root {item['id']} certificate digest mismatch")
        # Keep AAGUID spelling/case and root class exactly as signed. Include
        # ID as well as the attestation snapshot fields in the retention cost.
        total_snapshot_bytes += len(certificate_der) + len(_canonical({
            "id": item["id"], "certificateSha256": certificate_sha256,
            "authenticatorClass": item["authenticatorClass"],
            "aaguids": sorted(aaguids), "bundleDigest": bundle_digest,
            "bundleSequence": sequence, "bundleRollbackEpoch": rollback_epoch,
        }))
        if total_snapshot_bytes > MAX_TRUST_SNAPSHOT_BYTES:
            raise WebAuthnTrustError("WebAuthn trust root snapshot is oversized")
        roots.append(VerifiedTrustRoot(item["id"], certificate_der,
            certificate_sha256, item["authenticatorClass"], aaguids))
    installation_bytes = _pretty(bundle)
    if len(installation_bytes) > MAX_INSTALLATION_BYTES:
        raise WebAuthnTrustError("WebAuthn trust installation bytes exceed the verification profile")
    return VerifiedBundle(
        input_bytes=bundle_bytes, input_digest=sha256_prefixed(bundle_bytes),
        canonical_envelope_bytes=canonical_envelope,
        canonical_envelope_digest=sha256_prefixed(canonical_envelope),
        signature_payload_bytes=signature_payload,
        bundle_digest=bundle_digest,
        installation_bytes=installation_bytes,
        installation_digest=sha256_prefixed(installation_bytes),
        sequence=sequence, rollback_epoch=rollback_epoch,
        signing_key_id=signing_key_id, roots=tuple(roots), verified_at=context.verified_at,
    )


def _same_exact(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, (VerifiedBundle, VerifiedTrustRoot)):
        return all(_same_exact(getattr(actual, field.name), getattr(expected, field.name))
            for field in fields(expected))
    if type(expected) is tuple:
        return len(actual) == len(expected) and all(
            _same_exact(left, right) for left, right in zip(actual, expected))
    return actual == expected


def plan_rollback(bundle: VerifiedBundle, state_bytes: bytes | None,
    context: TrustVerificationContext) -> bytes | None:
    """Return exact next checkpoint bytes, or None for an identical checkpoint.

    The caller owns locking, checkpoint provenance, rechecking and durable
    persistence. A missing state is the legacy bootstrap state, not proof of
    rollback safety. The result does not claim installation happened. Even
    frozen dataclasses are not authority tokens: reverify retained input and
    compare every result field/type before deriving a checkpoint from it.
    """
    if type(bundle) is not VerifiedBundle:
        raise WebAuthnTrustError("WebAuthn trust verified bundle is invalid")
    expected = verify_bundle(bundle.input_bytes, context)
    if not _same_exact(bundle, expected):
        raise WebAuthnTrustError("WebAuthn trust verified bundle does not match retained input")
    bundle = expected
    state = {"version": 1} if state_bytes is None else _json_object(
        state_bytes, "rollback state", MAX_STATE_BYTES)
    if type(state.get("version")) is not int or state["version"] != 1:
        raise WebAuthnTrustError("WebAuthn trust rollback state version is invalid")
    last_sequence = 0
    last_epoch = 0
    last_digest = None
    if set(state) != {"version"}:
        if set(state) != {"version", "bundle_digest", "sequence", "rollback_epoch", "updated_at"}:
            raise WebAuthnTrustError("WebAuthn trust rollback state fields are invalid")
        last_sequence = _positive_counter(state["sequence"], "rollback state sequence")
        last_epoch = _positive_counter(state["rollback_epoch"], "rollback state epoch")
        last_digest = _digest(state["bundle_digest"], "rollback state bundle")
        _time(state["updated_at"], "rollback state updated_at")
    if bundle.rollback_epoch < last_epoch:
        raise WebAuthnTrustError("WebAuthn trust bundle rollback epoch is stale")
    if bundle.rollback_epoch == last_epoch and bundle.sequence < last_sequence:
        raise WebAuthnTrustError("WebAuthn trust bundle sequence is stale")
    if (last_digest is not None and bundle.rollback_epoch == last_epoch
        and bundle.sequence == last_sequence and bundle.bundle_digest != last_digest):
        raise WebAuthnTrustError("WebAuthn trust bundle content changed without advancing sequence")
    if (bundle.sequence == last_sequence and bundle.rollback_epoch == last_epoch
        and bundle.bundle_digest == last_digest):
        return None
    next_state = _pretty({
        "version": 1, "bundle_digest": bundle.bundle_digest,
        "sequence": bundle.sequence, "rollback_epoch": bundle.rollback_epoch,
        "updated_at": bundle.verified_at.isoformat(),
    })
    if len(next_state) > MAX_STATE_BYTES:
        raise WebAuthnTrustError("WebAuthn trust rollback state is oversized")
    return next_state
