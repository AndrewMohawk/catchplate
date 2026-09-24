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
from dataclasses import InitVar, dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES as MAX_WORK_INPUT_BYTES, MAX_JSON_NODES,
    QueryReadValidationLimits, QueryReadWorkError, _ValidationWork,
)


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


def _require_work(work) -> None:
    if work is None:
        return
    if (type(work) is not _ValidationWork or type(work.limits) is not QueryReadValidationLimits
            or any(type(value) is not int or not 1 <= value <= maximum for value, maximum in (
                (work.limits.max_hashes, MAX_HASHES), (work.limits.max_input_bytes, MAX_WORK_INPUT_BYTES),
                (work.limits.max_json_nodes, MAX_JSON_NODES)))
            or any(type(value) is not int or not 0 <= value <= maximum for value, maximum in (
                (work.hash_work, work.limits.max_hashes), (work.input_bytes, work.limits.max_input_bytes),
                (work.json_nodes, work.limits.max_json_nodes)))):
        raise QueryReadWorkError("WebAuthn trust work is not the original valid shared meter")


def _native(work, call):
    """Guard bounded native calls, without inventing their internal H/B/N cost.

    JSON/schema/X509/Ed25519 parsing, verification and native allocations remain
    a separate boundary, not a CPU/RSS/deadline guarantee. Visible input/output
    walks and buffers are charged at their real call sites. Failure refunds no
    prior work and cannot hide changed counters or a replacement allowance.
    """
    _require_work(work)
    before = None if work is None else (work.limits, work.limits.max_hashes,
        work.limits.max_input_bytes, work.limits.max_json_nodes,
        work.hash_work, work.input_bytes, work.json_nodes)
    try:
        return call()
    finally:
        if work is not None:
            _require_work(work)
            if (work.limits is not before[0]
                    or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes,
                        work.hash_work, work.input_bytes, work.json_nodes) != before[1:]):
                raise QueryReadWorkError("WebAuthn trust native operation changed the shared work meter")


def sha256_prefixed(value: bytes, *, _work=None) -> str:
    _require_work(_work)
    if _work is not None:
        _work.charge(hashes=1, input_bytes=len(value))
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


def _json_object(raw: bytes, label: str, maximum: int, *, _work=None) -> dict[str, Any]:
    _require_work(_work)
    _bounded_bytes(raw, label, maximum)
    if _work is not None:
        _work.charge(input_bytes=len(raw))
    try:
        text = raw.decode("utf-8")
        value = _native(_work, lambda: json.loads(
            text, object_pairs_hook=_object,
            parse_constant=_nonfinite,
        ))
    except WebAuthnTrustError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise WebAuthnTrustError(f"WebAuthn trust {label} is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be a JSON object")
    if _work is not None:
        # Actual returned graph traversal; decoder internals are separate.
        _work.prepare_scan(value)
    return value


def _canonical(value: Any, *, _work=None) -> bytes:
    _require_work(_work)
    size = None if _work is None else _work.prepare_encoding(value)[0]
    try:
        encoded = _native(_work, lambda: json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii"))
        if size is not None and len(encoded) != size:
            raise QueryReadWorkError("WebAuthn trust canonical encoding changed after measurement")
        return encoded
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WebAuthnTrustError("WebAuthn trust value is not canonical JSON") from exc


def _pretty_extra(value: Any, depth: int = 0) -> int:
    # Canonical strings/scalars have identical spelling. Only container
    # indentation/newlines and dict colon spaces differ from compact JSON.
    if type(value) not in (dict, list) or not value:
        return 0
    count = len(value)
    extra = count + 1 + 2 * depth + 2 * (depth + 1) * count
    if type(value) is dict:
        return extra + count + sum(_pretty_extra(child, depth + 1) for child in value.values())
    return extra + sum(_pretty_extra(child, depth + 1) for child in value)


def _pretty(value: Any, *, _work=None) -> bytes:
    _require_work(_work)
    size = None
    if _work is not None:
        compact, _ = _work.prepare_encoding(value)
        _work.prepare_scan(value)
        extra = _pretty_extra(value) + 1
        size = compact + extra
        if size > MAX_INSTALLATION_BYTES:
            raise WebAuthnTrustError("WebAuthn trust installation encoding is oversized")
        _work.charge(input_bytes=extra)
    encoded = _native(_work, lambda: (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
        allow_nan=False) + "\n").encode("ascii"))
    if size is not None and len(encoded) != size:
        raise QueryReadWorkError("WebAuthn trust installation encoding changed after measurement")
    return encoded


def _positive_counter(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_COUNTER:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be a positive bounded integer")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise WebAuthnTrustError(f"WebAuthn trust {label} digest is invalid")
    return value


def _time(value: Any, label: str, *, _work=None) -> datetime:
    _require_work(_work)
    if type(value) is not str or not value:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be an aware timestamp")
    if _work is not None:
        _work.prepare_scan(value)
        _work.prepare_copy(value)
        _work.charge(input_bytes=5 * value.count("Z"))
    try:
        replaced = value.replace("Z", "+00:00")
        result = _native(_work, lambda: datetime.fromisoformat(replaced))
        if result.utcoffset() is None:
            raise ValueError("naive timestamp")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise WebAuthnTrustError(f"WebAuthn trust {label} must be an aware timestamp") from exc


def _scalar_strings(value: Any, *, _work=None) -> None:
    # Called only after validation against the closed, bounded-depth schema.
    if _work is not None:
        _work.charge(json_nodes=1)
    if type(value) is str:
        try:
            if _work is not None:
                _work.prepare_utf8(value)
            value.encode("utf-8")
        except UnicodeError as exc:
            raise WebAuthnTrustError("WebAuthn trust bundle contains invalid Unicode") from exc
    elif type(value) is dict:
        for key, item in value.items():
            _scalar_strings(key, _work=_work)
            _scalar_strings(item, _work=_work)
    elif type(value) is list:
        for item in value:
            _scalar_strings(item, _work=_work)


def _public_key(raw: bytes, *, _work=None) -> Ed25519PublicKey:
    _require_work(_work)
    _bounded_bytes(raw, "public key", MAX_PUBLIC_KEY_BYTES)
    if _work is not None:
        _work.charge(input_bytes=len(raw))
    try:
        key = _native(_work, lambda: serialization.load_der_public_key(raw))
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise WebAuthnTrustError("WebAuthn trust public key is not valid DER") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise WebAuthnTrustError("WebAuthn trust public key must be Ed25519")
    encoded = _native(_work, lambda: key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    if _work is not None:
        _work.charge(input_bytes=len(encoded) + len(raw))
    if encoded != raw:
        raise WebAuthnTrustError("WebAuthn trust public key DER is not canonical SPKI")
    return key


@dataclass(frozen=True, slots=True)
class TrustVerificationContext:
    public_key_der: bytes
    schema_bytes: bytes
    verified_at: datetime
    _work: InitVar[_ValidationWork | None] = None

    def __post_init__(self, _work) -> None:
        _require_work(_work)
        public_key_der, schema_bytes, verified_at = self.public_key_der, self.schema_bytes, self.verified_at
        _public_key(public_key_der, _work=_work)
        _bounded_bytes(schema_bytes, "schema", MAX_SCHEMA_BYTES)
        if _work is not None:
            _work.charge(hashes=1, input_bytes=len(schema_bytes))
        if hashlib.sha256(schema_bytes).hexdigest() != TRUST_BUNDLE_SCHEMA_SHA256:
            raise WebAuthnTrustError("WebAuthn trust schema does not match the measured source schema")
        if (type(verified_at) is not datetime
            or verified_at.utcoffset() != timedelta(0)):
            raise WebAuthnTrustError("WebAuthn trust verification time must be explicit aware UTC")
        object.__setattr__(self, "public_key_der", public_key_der)
        object.__setattr__(self, "schema_bytes", schema_bytes)
        object.__setattr__(self, "verified_at", verified_at.replace(tzinfo=timezone.utc))


@dataclass(frozen=True, slots=True)
class VerifiedTrustRoot:
    id: str
    certificate_der: bytes
    certificate_sha256: str
    authenticator_class: str
    aaguids: frozenset[str]
    _work: InitVar[_ValidationWork | None] = None

    def __post_init__(self, _work) -> None:
        _require_work(_work)
        if type(self.id) is not str or not self.id:
            raise WebAuthnTrustError("WebAuthn trust root ID is invalid")
        _scalar_strings(self.id, _work=_work)
        _bounded_bytes(self.certificate_der, "root certificate", MAX_ROOT_CERTIFICATE_BYTES)
        _digest(self.certificate_sha256, "root certificate")
        if (type(self.authenticator_class) is not str
            or self.authenticator_class not in {"yubikey", "hardware", "platform"}):
            raise WebAuthnTrustError("WebAuthn trust root class is invalid")
        if type(self.aaguids) is not frozenset or len(self.aaguids) > MAX_ROOT_AAGUIDS:
            raise WebAuthnTrustError("WebAuthn trust root AAGUID set is invalid or oversized")
        if _work is not None:
            for value in self.aaguids:
                _work.prepare_scan(value)
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

    def bundle_dict(self, *, _work=None) -> dict[str, Any]:
        # A new JSON graph, never a mutable alias into the retained result.
        return _json_object(self.canonical_envelope_bytes, "bundle", MAX_CANONICAL_BYTES, _work=_work)


def _certificate(raw: bytes, *, _work=None) -> x509.Certificate:
    _require_work(_work)
    if _work is not None:
        _work.charge(input_bytes=len(raw))
    try:
        if b"-----BEGIN CERTIFICATE-----" not in raw:
            return _native(_work, lambda: x509.load_der_x509_certificate(raw))
        marker = b"-----END CERTIFICATE-----"
        if _work is not None:
            _work.charge(input_bytes=2 * len(raw))
        chunks = raw.split(marker)
        certificates = []
        for chunk in chunks:
            if _work is not None:
                _work.charge(input_bytes=len(chunk), json_nodes=1)
            if b"-----BEGIN CERTIFICATE-----" in chunk:
                if _work is not None:
                    _work.charge(input_bytes=2 * (len(chunk) + len(marker)) + 1)
                pem = chunk + marker + b"\n"
                certificates.append(_native(_work, lambda: x509.load_pem_x509_certificate(pem)))
        if len(certificates) != 1:
            raise WebAuthnTrustError("trust root entry must contain exactly one certificate")
        return certificates[0]
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, WebAuthnTrustError):
            raise
        raise WebAuthnTrustError("WebAuthn trust root certificate is invalid") from exc


def _schema_types():
    from jsonschema import Draft202012Validator, ValidationError
    return Draft202012Validator, ValidationError


def verify_bundle(bundle_bytes: bytes, context: TrustVerificationContext, *, _work=None) -> VerifiedBundle:
    """Verify a signed bundle completely, without changing any external state.

    Root validity/CA policy is not added here: the legacy bundle path loads
    certificates and checks their declared digests; attestation verification
    separately checks certificate times and chain policy. A parsed root alone
    does not establish hardware class or bundle provenance.

    The optional private route uses the existing invocation meter. Native
    decoder/schema/certificate/signature internals remain separately bounded
    calls, never fictional H/B/N charges or replacement work allowances.
    """
    _require_work(_work)
    if _work is not None:
        _bounded_bytes(bundle_bytes, "bundle", MAX_INPUT_BYTES)
    if type(context) is not TrustVerificationContext:
        raise WebAuthnTrustError("WebAuthn trust verification context is invalid")
    # Validate even a manually reconstructed context before using its bytes.
    context = TrustVerificationContext(context.public_key_der, context.schema_bytes,
        context.verified_at, _work=_work)
    bundle = _json_object(bundle_bytes, "bundle", MAX_INPUT_BYTES, _work=_work)
    canonical_envelope = _canonical(bundle, _work=_work)
    if len(canonical_envelope) > MAX_CANONICAL_BYTES:
        raise WebAuthnTrustError("WebAuthn trust canonical bundle exceeds 2 MiB")
    try:
        Draft202012Validator, ValidationError = _native(_work, _schema_types)
    except ImportError as exc:
        raise WebAuthnTrustError("jsonschema package is required for WebAuthn trust validation") from exc
    # The byte pin precedes parsing and schema use. The source schema contains
    # no references; callers cannot substitute a remote or permissive schema.
    schema = _json_object(context.schema_bytes, "schema", MAX_SCHEMA_BYTES, _work=_work)
    try:
        _native(_work, lambda: Draft202012Validator(schema).validate(bundle))
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise WebAuthnTrustError(
            f"WebAuthn trust bundle schema validation failed{location}: {exc.message}"
        ) from exc
    _scalar_strings(bundle, _work=_work)
    metadata = bundle["metadata"]
    sequence = _positive_counter(metadata["sequence"], "sequence")
    rollback_epoch = _positive_counter(metadata["rollbackEpoch"], "rollback epoch")
    signing_key_id = sha256_prefixed(context.public_key_der, _work=_work)
    if _work is not None:
        _work.prepare_comparison(metadata["signingKeyId"], signing_key_id)
    if metadata["signingKeyId"] != signing_key_id:
        raise WebAuthnTrustError("WebAuthn trust bundle signing key mismatch")
    if _work is not None:
        _work.prepare_copy(bundle)
        _work.prepare_copy(metadata)
    unsigned = {**bundle, "metadata": {key: value for key, value in metadata.items()
        if key != "signature"}}
    signature_payload = _canonical(unsigned, _work=_work)
    bundle_digest = sha256_prefixed(signature_payload, _work=_work)
    if _work is not None:
        _work.prepare_copy(metadata["signature"])
    signature_text = metadata["signature"].split(":", 1)[1]
    try:
        padding = -len(signature_text) % 4
        if _work is not None:
            # Actual text/padding buffer and bounded decode output reservation.
            _work.charge(input_bytes=len(signature_text) + padding +
                (len(signature_text) + padding) * 3 // 4)
        encoded_signature = signature_text + "=" * padding
        signature = _native(_work, lambda: base64.b64decode(encoded_signature,
            altchars=b"-_", validate=True))
        if len(signature) != 64:
            raise ValueError("wrong Ed25519 signature length")
    except (ValueError, binascii.Error) as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle signature encoding is invalid") from exc
    try:
        public_key = _public_key(context.public_key_der, _work=_work)
        _native(_work, lambda: public_key.verify(signature, signature_payload))
    except InvalidSignature as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle signature verification failed") from exc
    valid_from = _time(metadata["validFrom"], "validFrom", _work=_work)
    valid_until = (_time(metadata["validUntil"], "validUntil", _work=_work)
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
        if _work is not None:
            _work.prepare_copy(item.get("aaguids", []))
        aaguids = frozenset(item.get("aaguids", []))
        if len(aaguids) > MAX_ROOT_AAGUIDS:
            raise WebAuthnTrustError("WebAuthn trust root AAGUID set is oversized")
        if _work is not None:
            _work.prepare_utf8(item["certificatePem"])
        certificate = _certificate(item["certificatePem"].encode("utf-8"), _work=_work)
        certificate_der = _native(_work, lambda: certificate.public_bytes(serialization.Encoding.DER))
        if len(certificate_der) > MAX_ROOT_CERTIFICATE_BYTES:
            raise WebAuthnTrustError("WebAuthn trust root certificate is oversized")
        certificate_sha256 = sha256_prefixed(certificate_der, _work=_work)
        if _work is not None and "certificateSha256" in item:
            _work.prepare_comparison(item["certificateSha256"], certificate_sha256)
        if ("certificateSha256" in item
            and item["certificateSha256"] != certificate_sha256):
            raise WebAuthnTrustError(f"WebAuthn trust root {item['id']} certificate digest mismatch")
        # Keep AAGUID spelling/case and root class exactly as signed. Include
        # ID as well as the attestation snapshot fields in the retention cost.
        if _work is not None:
            _work.prepare_copy(item.get("aaguids", []))
        descriptor = {
            "id": item["id"], "certificateSha256": certificate_sha256,
            "authenticatorClass": item["authenticatorClass"],
            "aaguids": sorted(aaguids), "bundleDigest": bundle_digest,
            "bundleSequence": sequence, "bundleRollbackEpoch": rollback_epoch,
        }
        total_snapshot_bytes += len(certificate_der) + len(_canonical(descriptor, _work=_work))
        if total_snapshot_bytes > MAX_TRUST_SNAPSHOT_BYTES:
            raise WebAuthnTrustError("WebAuthn trust root snapshot is oversized")
        roots.append(VerifiedTrustRoot(item["id"], certificate_der,
            certificate_sha256, item["authenticatorClass"], aaguids, _work=_work))
    installation_bytes = _pretty(bundle, _work=_work)
    if len(installation_bytes) > MAX_INSTALLATION_BYTES:
        raise WebAuthnTrustError("WebAuthn trust installation bytes exceed the verification profile")
    if _work is not None:
        # The actual final tuple retains these bounded DER/descriptor roots;
        # charge their already calculated source material, not Python RSS.
        _work.charge(input_bytes=total_snapshot_bytes, json_nodes=len(roots) + 1)
    return VerifiedBundle(
        input_bytes=bundle_bytes, input_digest=sha256_prefixed(bundle_bytes, _work=_work),
        canonical_envelope_bytes=canonical_envelope,
        canonical_envelope_digest=sha256_prefixed(canonical_envelope, _work=_work),
        signature_payload_bytes=signature_payload,
        bundle_digest=bundle_digest,
        installation_bytes=installation_bytes,
        installation_digest=sha256_prefixed(installation_bytes, _work=_work),
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
