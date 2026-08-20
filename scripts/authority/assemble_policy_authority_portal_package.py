#!/usr/bin/env python3
"""Assemble a portal package from already-signed authority records.

This local trusted-host helper never signs evidence and never accepts private
key material. Production records still require external signers and server-side
verification against the current durable authority state.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_INPUT_BYTES = 8 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
HARDWARE_ATTESTATION_TYPES = frozenset(
    {"aws-nitro-enclave", "amd-sev-snp", "intel-tdx"}
)
FORBIDDEN_KEY_NAMES = frozenset(
    {
        "privatekey",
        "privatekeybase64",
        "privatekeybase64url",
        "privatekeybytes",
        "privatekeypem",
        "secretkey",
        "signingseed",
        "seedphrase",
        "mnemonic",
        "recoveryphrase",
        "clientsecret",
        "sharedsecret",
        "accesstoken",
        "refreshtoken",
        "bearertoken",
        "password",
    }
)
SIGNED_RECORD_FIELDS = {
    "artifact": (
        "artifact_envelope_digest",
        "artifact_payload_digest",
        "artifact_envelope_json",
        "artifact_payload_json",
    ),
    "assignment": (
        "assignment_envelope_digest",
        "assignment_payload_digest",
        "assignment_envelope_json",
        "assignment_payload_json",
    ),
    "load receipt": (
        "load_receipt_envelope_digest",
        "load_receipt_payload_digest",
        "load_receipt_envelope_json",
        "load_receipt_payload_json",
    ),
}
SIGNATURE_FIELDS = (
    "signature_algorithm",
    "signing_key_id",
    "signature",
    "signature_digest",
)
RUNTIME_HANDOFF_FIELDS = frozenset(
    {
        "apiVersion",
        "receiptId",
        "receiptRevision",
        "receipt",
        "receiptSha256",
        "receiptPayloadSha256",
        "roleAuthorizationId",
        "roleAuthorizationRevision",
        "roleAuthorization",
        "roleAuthorizationSha256",
        "roleAuthorizationPayloadSha256",
        "evidence",
        "chainSha256",
    }
)
RUNTIME_EVIDENCE_FIELDS = frozenset(
    {
        "apiVersion",
        "evidenceId",
        "evidenceRevision",
        "evidenceType",
        "evidenceSha256",
        "evidence",
    }
)
ACTIVATION_FIELDS = frozenset(
    {"prepare", "recordInclusions", "finalize", "abort"}
)
ACTIVATION_OPERATIONS = {
    "prepare": "policy.activation.prepare",
    "finalize": "policy.activation.finalize",
    "abort": "policy.activation.abort",
}


class AssemblyError(ValueError):
    pass


class VerificationTrust:
    def __init__(self, value: dict[str, Any]) -> None:
        if set(value) != {"apiVersion", "keys"} or value.get(
            "apiVersion"
        ) != "serverware.policyAuthorityAssemblerVerificationTrust/v1":
            raise AssemblyError("verification trust artifact is not closed")
        keys = value.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 64:
            raise AssemblyError("verification trust key set is not bounded")
        self._keys: dict[str, tuple[Ed25519PublicKey, frozenset[str]]] = {}
        for index, record in enumerate(keys):
            if not isinstance(record, dict) or set(record) != {
                "signingKeyId",
                "signingKeySpkiSha256",
                "publicKeyFile",
                "allowedSignatureDomains",
            }:
                raise AssemblyError(f"verification trust key {index} is not closed")
            key_id = _digest(record["signingKeyId"], "verification key ID")
            spki_pin = _digest(
                record["signingKeySpkiSha256"], "verification key SPKI"
            )
            domains = record["allowedSignatureDomains"]
            if (
                key_id != spki_pin
                or key_id in self._keys
                or not isinstance(domains, list)
                or not 1 <= len(domains) <= 32
                or len(set(domains)) != len(domains)
            ):
                raise AssemblyError("verification trust key identity is invalid")
            allowed = frozenset(
                _text(domain, "signature domain", 256) for domain in domains
            )
            path = Path(_text(record["publicKeyFile"], "public key path", 4096))
            encoded = _read_pinned_public_file(path, "verification public key", 16 * 1024)
            if b"PRIVATE KEY" in encoded.upper():
                raise AssemblyError("verification trust contains private key material")
            try:
                key = (
                    serialization.load_pem_public_key(encoded)
                    if encoded.lstrip().startswith(b"-----BEGIN")
                    else serialization.load_der_public_key(encoded)
                )
            except (TypeError, ValueError) as exc:
                raise AssemblyError("verification public key cannot be decoded") from exc
            if not isinstance(key, Ed25519PublicKey):
                raise AssemblyError("verification public key is not Ed25519")
            spki = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if "sha256:" + hashlib.sha256(spki).hexdigest() != spki_pin:
                raise AssemblyError("verification public key differs from its pin")
            self._keys[key_id] = (key, allowed)

    def verify_envelope(self, envelope: Any, label: str) -> dict[str, Any]:
        fields = {
            "apiVersion", "kind", "canonicalProfile", "signatureDomain",
            "payload", "payloadSha256", "signatureAlgorithm", "signingKeyId",
            "signingKeySpkiSha256", "signature",
        }
        if (
            not isinstance(envelope, dict)
            or set(envelope) != fields
            or envelope.get("canonicalProfile")
                != "serverware.canonicalJson/ascii-integer-v1"
            or envelope.get("signatureAlgorithm") != "Ed25519"
            or not isinstance(envelope.get("payload"), dict)
            or envelope.get("apiVersion") != envelope.get("signatureDomain")
        ):
            raise AssemblyError(f"{label} is not an exact signed envelope")
        domain = _text(envelope["signatureDomain"], f"{label} domain", 256)
        key_id = _digest(envelope["signingKeyId"], f"{label} key ID")
        if envelope.get("signingKeySpkiSha256") != key_id:
            raise AssemblyError(f"{label} signer identity is inconsistent")
        trusted = self._keys.get(key_id)
        if trusted is None or domain not in trusted[1]:
            raise AssemblyError(f"{label} signer/domain is not pinned")
        payload_bytes = _canonical_bytes(envelope["payload"])
        payload_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
        if envelope.get("payloadSha256") != payload_digest:
            raise AssemblyError(f"{label} payload digest changed")
        signature_text = _text(envelope["signature"], f"{label} signature", 4096)
        try:
            signature = base64.urlsafe_b64decode(
                signature_text + "=" * (-len(signature_text) % 4)
            )
        except (ValueError, TypeError) as exc:
            raise AssemblyError(f"{label} signature is not base64url") from exc
        if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(
            b"="
        ).decode("ascii") != signature_text:
            raise AssemblyError(f"{label} signature encoding is not canonical")
        message = b"\0".join(
            (
                b"serverware.signedEnvelope/v1",
                domain.encode("ascii"),
                b"serverware.canonicalJson/ascii-integer-v1",
                payload_bytes,
            )
        )
        try:
            trusted[0].verify(signature, message)
        except InvalidSignature as exc:
            raise AssemblyError(f"{label} signature is invalid") from exc
        return envelope


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AssemblyError("input is not canonical-profile JSON") from exc


def _read_pinned_public_file(path: Path, label: str, maximum: int) -> bytes:
    if not path.is_absolute():
        raise AssemblyError(f"{label} path must be absolute")
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise AssemblyError(f"cannot read {label}: {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not 2 <= len(payload) <= maximum
    ):
        raise AssemblyError(f"{label} is not a bounded immutable root-owned file")
    return payload


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise AssemblyError(f"cannot read {label}: {path}") from exc
    if not 2 <= len(payload) <= MAX_INPUT_BYTES:
        raise AssemblyError(f"{label} exceeds the fixed input bound")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssemblyError(f"{label} is not JSON") from exc
    if not isinstance(value, dict):
        raise AssemblyError(f"{label} must be a JSON object")
    _reject_private_material(value, label)
    _canonical_bytes(value)
    return value


def _load_verification_trust(
    path: Path, expected_digest: str
) -> VerificationTrust:
    expected_digest = _digest(
        expected_digest, "verification trust artifact digest"
    )
    payload = _read_pinned_public_file(
        path, "verification trust artifact", MAX_INPUT_BYTES
    )
    if "sha256:" + hashlib.sha256(payload).hexdigest() != expected_digest:
        raise AssemblyError("verification trust artifact differs from its pin")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssemblyError("verification trust artifact is not JSON") from exc
    if not isinstance(value, dict) or _canonical_bytes(value) != payload:
        raise AssemblyError("verification trust artifact is not canonical JSON")
    _reject_private_material(value, "verification trust artifact")
    return VerificationTrust(value)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _reject_private_material(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, member in value.items():
            if not isinstance(key, str):
                raise AssemblyError(f"{path} contains a non-string key")
            normalized = _normalized_key(key)
            if any(
                marker in normalized
                for marker in FORBIDDEN_KEY_NAMES
            ):
                raise AssemblyError(f"{path}.{key} contains forbidden key material")
            _reject_private_material(member, f"{path}.{key}")
    elif isinstance(value, list):
        for index, member in enumerate(value):
            _reject_private_material(member, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_INPUT_BYTES:
            raise AssemblyError(f"{path} string exceeds the fixed bound")
        stripped = value.strip()
        lowered = stripped.lower()
        if (
            "-----begin private key-----" in lowered
            or "-----begin encrypted private key-----" in lowered
            or "-----begin rsa private key-----" in lowered
            or re.match(
                r"^(?:bearer|basic|token)\s+[A-Za-z0-9._~+/-]+=*$",
                stripped,
                re.I,
            )
            or re.fullmatch(
                r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                stripped,
            )
            or re.search(
                r"^[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@",
                stripped,
                re.I,
            )
        ):
            raise AssemblyError(f"{path} contains private or token material")
        if stripped[:1] in {"{", "["} and len(stripped) <= 1024 * 1024:
            try:
                embedded = json.loads(stripped)
            except json.JSONDecodeError:
                embedded = None
            if isinstance(embedded, (dict, list)):
                _reject_private_material(embedded, f"{path}<embedded-json>")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise AssemblyError(f"{label} must be a canonical SHA-256 digest")
    return value


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise AssemblyError(f"{label} is invalid")
    return value


def _signed_record(
    value: dict[str, Any], label: str, trust: VerificationTrust
) -> None:
    envelope_fields = SIGNED_RECORD_FIELDS[label]
    for field in envelope_fields:
        if field not in value:
            raise AssemblyError(f"{label} omits {field}")
    for field in envelope_fields[:2]:
        _digest(value[field], f"{label}.{field}")
    if value.get("signature_algorithm") != "Ed25519":
        raise AssemblyError(f"{label} is not an Ed25519-signed record")
    for field in SIGNATURE_FIELDS[1:]:
        if field not in value:
            raise AssemblyError(f"{label} omits {field}")
    _digest(value["signing_key_id"], f"{label}.signing_key_id")
    _digest(value["signature_digest"], f"{label}.signature_digest")
    _text(value["signature"], f"{label}.signature", 4096)
    decoded_values: dict[str, Any] = {}
    for field in envelope_fields[2:]:
        raw = _text(value[field], f"{label}.{field}", MAX_INPUT_BYTES)
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AssemblyError(f"{label}.{field} is not JSON") from exc
        if _canonical_bytes(decoded).decode("ascii") != raw:
            raise AssemblyError(f"{label}.{field} is not canonical JSON")
        decoded_values[field] = decoded
    envelope = trust.verify_envelope(
        decoded_values[envelope_fields[2]], f"{label} envelope"
    )
    if (
        envelope["payload"] != decoded_values[envelope_fields[3]]
        or "sha256:"
            + hashlib.sha256(_canonical_bytes(envelope)).hexdigest()
            != value[envelope_fields[0]]
        or envelope["payloadSha256"] != value[envelope_fields[1]]
        or envelope["signingKeyId"] != value["signing_key_id"]
        or envelope["signature"] != value["signature"]
    ):
        raise AssemblyError(f"{label} row diverges from its verified envelope")


def _runtime_handoff(
    record: dict[str, Any], trust: VerificationTrust
) -> tuple[dict[str, Any], str]:
    required_record_fields = {
        "canary_id",
        "instance_id",
        "boot_id",
        "candidate_id",
        "runtime_attestation_json",
        "actor_id",
    }
    if set(record) != required_record_fields:
        raise AssemblyError("runtime-attestation record fields are not exact")
    raw = _text(
        record["runtime_attestation_json"],
        "runtime attestation JSON",
        MAX_INPUT_BYTES,
    )
    try:
        handoff = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AssemblyError("runtime attestation handoff is not JSON") from exc
    if (
        not isinstance(handoff, dict)
        or set(handoff) != RUNTIME_HANDOFF_FIELDS
        or handoff.get("apiVersion")
        != "serverware.policyShadowRuntimeAttestationHandoff/v2"
    ):
        raise AssemblyError("runtime attestation handoff is not closed")
    if _canonical_bytes(handoff).decode("ascii") != raw:
        raise AssemblyError("runtime attestation handoff is not canonical JSON")
    for label, envelope in (
        ("runtime attestation receipt", handoff.get("receipt")),
        ("runtime role authorization", handoff.get("roleAuthorization")),
    ):
        trust.verify_envelope(envelope, label)
    evidence = handoff.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != RUNTIME_EVIDENCE_FIELDS
        or evidence.get("apiVersion")
        != "serverware.policyShadowRuntimeAttestationEvidence/v1"
        or evidence.get("evidenceType") not in HARDWARE_ATTESTATION_TYPES
    ):
        raise AssemblyError(
            "runtime handoff requires supplied signed hardware attestation evidence"
        )
    _digest(evidence.get("evidenceSha256"), "runtime evidence digest")
    return handoff, "sha256:" + hashlib.sha256(raw.encode("ascii")).hexdigest()


def _activation(
    value: dict[str, Any],
    *,
    purpose: str,
    trust: VerificationTrust,
) -> dict[str, Any]:
    fields = set(value)
    if not fields.issubset(ACTIVATION_FIELDS):
        raise AssemblyError("activation record set is not closed")
    if purpose in {"handoff", "decision-gate-activation"} and fields:
        raise AssemblyError(
            "handoff assembly must not predict later activation evidence"
        )
    if purpose == "authority-finalization" and (
        fields != {"prepare", "recordInclusions", "finalize"}
        or not isinstance(value.get("recordInclusions"), list)
        or not value["recordInclusions"]
    ):
        raise AssemblyError(
            "activation assembly requires prepare, audit inclusion, and finalize records"
        )
    if purpose == "abort" and fields != {"abort"}:
        raise AssemblyError(
            "abort assembly requires only its durable prepared abort record"
        )
    result: dict[str, Any] = {}
    for field, operation in ACTIVATION_OPERATIONS.items():
        if field not in value:
            continue
        step = value[field]
        if (
            not isinstance(step, dict)
            or set(step) != {"operation", "arguments"}
            or step.get("operation") != operation
            or not isinstance(step.get("arguments"), dict)
        ):
            raise AssemblyError(f"activation {field} record is not closed")
        if field == "prepare":
            arguments = step["arguments"]
            for record_field in (
                "activationRevisions",
                "canaryRevisions",
            ):
                records = arguments.get(record_field)
                if not isinstance(records, list) or not records:
                    raise AssemblyError(
                        f"activation prepare omits signed {record_field} records"
                    )
                for index, record in enumerate(records):
                    if (
                        not isinstance(record, dict)
                        or record.get("signature_algorithm") != "Ed25519"
                        or not record.get("signature")
                    ):
                        raise AssemblyError(
                            f"activation {record_field}[{index}] is not signed"
                        )
                    _digest(
                        record.get("signing_key_id"),
                        f"activation {record_field}[{index}] signer",
                    )
                    _digest(
                        record.get("signature_digest"),
                        f"activation {record_field}[{index}] signature digest",
                    )
                    envelope_text = record.get("state_envelope_json")
                    if not isinstance(envelope_text, str):
                        raise AssemblyError(
                            f"activation {record_field}[{index}] omits its envelope"
                        )
                    try:
                        envelope = json.loads(envelope_text)
                    except json.JSONDecodeError as exc:
                        raise AssemblyError(
                            f"activation {record_field}[{index}] envelope is invalid"
                        ) from exc
                    trust.verify_envelope(
                        envelope, f"activation {record_field}[{index}]"
                    )
            publication = arguments.get("publicationReceipt")
            if (
                not isinstance(publication, dict)
                or publication.get("signature_algorithm") != "Ed25519"
                or not publication.get("signature")
            ):
                raise AssemblyError(
                    "activation publication receipt is not a signed record"
                )
            _digest(
                publication.get("signing_key_id"),
                "activation publication receipt signer",
            )
            _digest(
                publication.get("signature_digest"),
                "activation publication receipt signature digest",
            )
            try:
                publication_envelope = json.loads(
                    publication["publication_receipt_envelope_json"]
                )
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise AssemblyError(
                    "activation publication receipt omits its envelope"
                ) from exc
            trust.verify_envelope(
                publication_envelope, "activation publication receipt"
            )
        result[field] = step
    if "recordInclusions" in value:
        inclusions = value["recordInclusions"]
        if not isinstance(inclusions, list) or len(inclusions) > 64:
            raise AssemblyError("activation inclusion records exceed the fixed bound")
        for item in inclusions:
            if (
                not isinstance(item, dict)
                or set(item) != {"operation", "arguments"}
                or item.get("operation")
                != "policy.activation.record-inclusion"
                or not isinstance(item.get("arguments"), dict)
            ):
                raise AssemblyError("activation inclusion record is not closed")
        result["recordInclusions"] = inclusions
    return result


def assemble(
    artifact: dict[str, Any],
    assignment: dict[str, Any],
    load_receipt: dict[str, Any],
    runtime_attestation: dict[str, Any],
    activation: dict[str, Any],
    *,
    purpose: str,
    trust: VerificationTrust,
) -> dict[str, Any]:
    _signed_record(artifact, "artifact", trust)
    _signed_record(assignment, "assignment", trust)
    _signed_record(load_receipt, "load receipt", trust)
    _, runtime_handoff_digest = _runtime_handoff(runtime_attestation, trust)
    candidate_id = _text(artifact.get("candidate_id"), "candidate ID")
    canary_id = _text(assignment.get("canary_id"), "canary ID")
    instance_id = _text(load_receipt.get("instance_id"), "instance ID")
    boot_id = _digest(load_receipt.get("boot_id"), "boot ID")
    artifact_digest = _digest(
        artifact.get("artifact_envelope_digest"), "artifact envelope digest"
    )
    assignment_digest = _digest(
        assignment.get("assignment_envelope_digest"),
        "assignment envelope digest",
    )
    load_digest = _digest(
        load_receipt.get("load_receipt_envelope_digest"),
        "load-receipt envelope digest",
    )
    predecessor = _digest(
        artifact.get("predecessor_policy_hash"), "predecessor policy hash"
    )
    exact = (
        (assignment.get("artifact_envelope_digest"), artifact_digest),
        (load_receipt.get("artifact_envelope_digest"), artifact_digest),
        (load_receipt.get("assignment_envelope_digest"), assignment_digest),
        (load_receipt.get("canary_id"), canary_id),
        (runtime_attestation.get("candidate_id"), candidate_id),
        (runtime_attestation.get("canary_id"), canary_id),
        (runtime_attestation.get("instance_id"), instance_id),
        (runtime_attestation.get("boot_id"), boot_id),
    )
    if any(actual != expected for actual, expected in exact):
        raise AssemblyError("signed records do not form one exact handoff chain")
    package = {
        "apiVersion": "serverware.policyAuthorityPortalPackage/v1",
        "handoff": {
            "candidateId": candidate_id,
            "artifactEnvelopeDigest": artifact_digest,
            "canaryId": canary_id,
            "assignmentEnvelopeDigest": assignment_digest,
            "loadReceiptEnvelopeDigest": load_digest,
            "instanceId": instance_id,
            "bootId": boot_id,
            "runtimeAttestationHandoffDigest": runtime_handoff_digest,
            "predecessorPolicyHash": predecessor,
        },
        "activation": _activation(activation, purpose=purpose, trust=trust),
    }
    _reject_private_material(package, "portal package")
    _canonical_bytes(package)
    return package


def _write_output(path: Path, payload: bytes) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--assignment", required=True, type=Path)
    parser.add_argument("--load-receipt", required=True, type=Path)
    parser.add_argument("--runtime-attestation", required=True, type=Path)
    parser.add_argument(
        "--purpose",
        choices=(
            "handoff",
            "decision-gate-activation",
            "authority-finalization",
            "abort",
        ),
        required=True,
    )
    parser.add_argument("--verification-trust", required=True, type=Path)
    parser.add_argument("--verification-trust-sha256", required=True)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        trust = _load_verification_trust(
            args.verification_trust,
            args.verification_trust_sha256,
        )
        if args.purpose in {"handoff", "decision-gate-activation"}:
            if args.activation is not None:
                raise AssemblyError(
                    "--activation is forbidden before authority finalization"
                )
            activation = {}
        else:
            if args.activation is None:
                raise AssemblyError(
                    "--activation is required for activation or abort assembly"
                )
            activation = _load_object(args.activation, "activation")
        package = assemble(
            _load_object(args.artifact, "artifact"),
            _load_object(args.assignment, "assignment"),
            _load_object(args.load_receipt, "load receipt"),
            _load_object(args.runtime_attestation, "runtime attestation"),
            activation,
            purpose=args.purpose,
            trust=trust,
        )
        payload = _canonical_bytes(package) + b"\n"
        if args.output is None:
            sys.stdout.buffer.write(payload)
        else:
            _write_output(args.output, payload)
    except AssemblyError as exc:
        print(f"assembly refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
