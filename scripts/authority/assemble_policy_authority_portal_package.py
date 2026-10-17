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
        ) != "catchplate.policyAuthorityAssemblerVerificationTrust/v1":
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
                != "catchplate.canonicalJson/ascii-integer-v1"
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
                b"catchplate.signedEnvelope/v1",
                domain.encode("ascii"),
                b"catchplate.canonicalJson/ascii-integer-v1",
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


def _load_intake_record(path: Path, expected_kind: str) -> dict[str, Any]:
    value = _load_object(path, expected_kind)
    if "kind" not in value and "record" not in value:
        return value
    if (set(value) != {"kind", "record"} or value["kind"] != expected_kind
        or not isinstance(value["record"], dict)):
        raise AssemblyError(f"{expected_kind} intake wrapper must contain only its matching kind and record")
    # Keep the original record and embedded signed JSON strings unchanged.
    return value["record"]


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
        != "catchplate.policyShadowRuntimeAttestationHandoff/v2"
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
        != "catchplate.policyShadowRuntimeAttestationEvidence/v1"
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
    signed_bundle: dict[str, Any] | None = None,
    policy_public_key: Path | None = None,
    policy_public_key_sha256: str | None = None,
    draft_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    carrier_inputs = (signed_bundle, policy_public_key, policy_public_key_sha256)
    if any(value is not None for value in carrier_inputs) and (
        any(value is None for value in carrier_inputs) or purpose != "handoff"
    ):
        raise AssemblyError("signed-bundle carrier requires handoff purpose and all public-key inputs")
    if draft_request is not None and signed_bundle is None:
        raise AssemblyError("a draft request requires an already-signed handoff carrier")
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
        "apiVersion": "catchplate.policyAuthorityPortalPackage/v1",
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
    if signed_bundle is not None:
        carrier = _bundle_carrier(
            package, signed_bundle, artifact, assignment,
            public_key_path=policy_public_key,
            public_key_sha256=policy_public_key_sha256,
        )
        if draft_request is not None:
            _match_draft_request(draft_request, carrier)
        return carrier
    return package


def _match_draft_request(request: dict[str, Any], carrier: dict[str, Any]) -> None:
    """Join an unsigned operator request to verified output; never approve it."""
    fields = {"apiVersion", "unsignedPolicyBundle", "predecessorPolicyHash",
        "previewDraftHash", "selection", "dryRun", "approved", "signed"}
    if (not isinstance(request, dict) or set(request) != fields
        or request["apiVersion"] != "catchplate.policyAuthorityDraftRequest/v1"
        or request["approved"] is not False or request["signed"] is not False):
        raise AssemblyError("draft request is not the closed unsigned v1 request")
    _reject_private_material(request, "draft request")
    if len(_canonical_bytes(request)) > MAX_INPUT_BYTES:
        raise AssemblyError("draft request exceeds the fixed input bound")
    draft = request["unsignedPolicyBundle"]
    if (not isinstance(draft, dict)
        or not isinstance(draft.get("apiVersion"), str)
        or draft.get("apiVersion") not in {"catchplate.policy/v1", "catchplate.policy/v2"}
        or not isinstance(draft.get("metadata"), dict)
        or {"signature", "signingKeyId"} & set(draft["metadata"])):
        raise AssemblyError("draft request must contain an unsigned PolicyBundle")
    returned = json.loads(_canonical_bytes(carrier["signedPolicyBundle"]))
    returned["metadata"].pop("signature", None)
    returned["metadata"].pop("signingKeyId", None)
    if _canonical_bytes(returned) != _canonical_bytes(draft):
        raise AssemblyError("signed bundle differs from the requested unsigned draft")
    # Reuse the actual policy framing, including the explicit v2 profile.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from catchplate.policy_bundle import PolicyBundleError, policy_signature_bytes
    try:
        draft_hash = "sha256:" + hashlib.sha256(policy_signature_bytes(draft)).hexdigest()
    except (PolicyBundleError, TypeError, ValueError) as exc:
        raise AssemblyError("draft signature framing is invalid") from exc
    if _digest(request["previewDraftHash"], "preview draft hash") != draft_hash:
        raise AssemblyError("preview hash differs from the requested draft")
    if (_digest(request["predecessorPolicyHash"], "draft predecessor")
        != carrier["portalPackage"]["handoff"]["predecessorPolicyHash"]):
        raise AssemblyError("signed artifact predecessor differs from the draft request")
    selection = request["selection"]
    if not isinstance(selection, dict) or set(selection) != {"templateId", "routeId", "principalId", "credentialId"}:
        raise AssemblyError("draft selection is not closed")
    for name, value in selection.items():
        _text(value, "draft " + name, 1024)
    selected = {}
    for group, name in (("routes", "routeId"), ("principals", "principalId"), ("credentials", "credentialId")):
        rows = draft.get(group)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise AssemblyError("draft policy declarations are invalid")
        matches = [row for row in rows if row.get("id") == selection[name]]
        if len(matches) != 1:
            raise AssemblyError("draft selection does not identify one policy declaration")
        selected[group] = matches[0]
    route = selected["routes"]
    if (route.get("credentialRef") != selection["credentialId"]
        or not isinstance(route.get("principals"), list)
        or selection["principalId"] not in route["principals"]):
        raise AssemblyError("draft selection differs from its route binding")
    cases = request["dryRun"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
        raise AssemblyError("draft request must retain its bounded preview cases")
    case_fields = {"name", "principalId", "scheme", "host", "port", "method", "path", "expect", "expectedRouteId"}
    for case in cases:
        if (not isinstance(case, dict) or not {"principalId", "host", "method", "path"} <= set(case) <= case_fields
            or not isinstance(case.get("expect", "allow"), str)
            or case.get("expect", "allow") not in {"allow", "deny"}
            or type(case.get("port", 443)) is not int or not 1 <= case.get("port", 443) <= 65535):
            raise AssemblyError("draft preview case is invalid")
        for name in ("principalId", "host", "method", "path"):
            _text(case[name], "draft preview " + name, MAX_INPUT_BYTES)
        for name in ("name", "expectedRouteId"):
            if case.get(name) is not None:
                _text(case[name], "draft preview " + name, MAX_INPUT_BYTES)
        if "scheme" in case:
            _text(case["scheme"], "draft preview scheme", 32)


def _bundle_carrier(package, bundle, artifact, assignment, *, public_key_path, public_key_sha256):
    # Only the explicitly selected public key is used. In particular, do not
    # call policy_public_key(): its compatibility fallback can create a key.
    pin = _digest(public_key_sha256, "policy public-key SPKI digest")
    encoded = _read_pinned_public_file(public_key_path, "policy public key", 16 * 1024)
    if b"PRIVATE KEY" in encoded.upper():
        raise AssemblyError("policy public key contains private key material")
    try:
        key = (serialization.load_pem_public_key(encoded)
            if encoded.lstrip().startswith(b"-----BEGIN")
            else serialization.load_der_public_key(encoded))
    except (TypeError, ValueError) as exc:
        raise AssemblyError("policy public key cannot be decoded") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AssemblyError("policy public key is not Ed25519")
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if "sha256:" + hashlib.sha256(spki).hexdigest() != pin:
        raise AssemblyError("policy public key differs from its independent SPKI pin")
    metadata = bundle.get("metadata")
    if (bundle.get("apiVersion") not in {"catchplate.policy/v1", "catchplate.policy/v2"}
        or not isinstance(metadata, dict) or metadata.get("signingKeyId") != pin
        or not isinstance(metadata.get("signature"), str)
        or re.fullmatch(r"ed25519:[A-Za-z0-9_-]{86}", metadata["signature"]) is None):
        raise AssemblyError("candidate bundle signature identity is invalid")
    signature_text = metadata["signature"][8:]
    signature = base64.urlsafe_b64decode(signature_text + "==")
    if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != signature_text:
        raise AssemblyError("candidate bundle signature encoding is not canonical")
    # Reuse the actual v1/v2 signature framing, not a second JSON codec.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from catchplate.policy_bundle import PolicyBundleError, policy_signature_bytes
    try:
        message = policy_signature_bytes(bundle)
        key.verify(signature, message)
    except (InvalidSignature, PolicyBundleError, TypeError, ValueError) as exc:
        raise AssemblyError("candidate bundle signature is invalid") from exc
    bundle_digest = "sha256:" + hashlib.sha256(_canonical_bytes(bundle)).hexdigest()
    policy_digest = "sha256:" + hashlib.sha256(message).hexdigest()
    # assemble() has verified these literal envelopes. Join signed payloads,
    # not merely the caller-supplied outer SQL-record projections.
    artifact_envelope = json.loads(artifact["artifact_envelope_json"])
    assignment_envelope = json.loads(assignment["assignment_envelope_json"])
    artifact_payload = artifact_envelope["payload"]
    artifact_record = artifact_payload.get("record")
    assignment_payload = assignment_envelope["payload"]
    identity = assignment_payload.get("policyIdentity")
    if (artifact_envelope["signatureDomain"] != "catchplate.policyCandidateArtifact/v2"
        or artifact_envelope["kind"] != "PolicyCandidateArtifact"
        or set(artifact_payload) != {"issuedAtEpochNs", "expiresAtEpochNs", "record"}
        or not isinstance(artifact_record, dict)
        or assignment_envelope["signatureDomain"] != "catchplate.policyShadowAssignment/v1"
        or assignment_envelope["kind"] != "PolicyShadowAssignment"
        or not isinstance(identity, dict)
        or artifact_record.get("policy_bundle_digest") != bundle_digest
        or artifact.get("policy_bundle_digest") != bundle_digest
        or assignment.get("policy_bundle_digest") != bundle_digest
        or identity.get("policyBundleSha256") != bundle_digest
        or artifact_record.get("policy_hash") != policy_digest
        or artifact.get("policy_hash") != policy_digest
        or identity.get("candidatePolicySha256") != policy_digest
        or artifact_record.get("candidate_id") != package["handoff"]["candidateId"]
        or artifact_record.get("predecessor_policy_hash") != package["handoff"]["predecessorPolicyHash"]
        or assignment_payload.get("canaryId") != package["handoff"]["canaryId"]
        or identity.get("predecessorPolicySha256") != package["handoff"]["predecessorPolicyHash"]):
        raise AssemblyError("signed bundle differs from authenticated artifact or assignment")
    carrier = {"apiVersion": "catchplate.policyAuthorityPortalCarrier/v1",
        "signedPolicyBundle": bundle, "portalPackage": package}
    if len(_canonical_bytes(carrier)) + 1 > MAX_INPUT_BYTES:
        raise AssemblyError("portal carrier exceeds the fixed import bound")
    return carrier


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
    parser.add_argument("--signed-bundle", type=Path,
        help="optional already-signed bundle; emits a v1 carrier for handoff only")
    parser.add_argument("--policy-public-key", type=Path,
        help="independently trusted root-owned Ed25519 PUBLIC key (PEM or DER)")
    parser.add_argument("--policy-public-key-sha256",
        help="independently selected sha256: digest of public-key DER SPKI")
    parser.add_argument("--draft-request", type=Path,
        help="optional portal unsigned request; verify the signed carrier matches it (not approval)")
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
            _load_intake_record(args.artifact, "artifact"),
            _load_intake_record(args.assignment, "assignment"),
            _load_object(args.load_receipt, "load receipt"),
            _load_object(args.runtime_attestation, "runtime attestation"),
            activation,
            purpose=args.purpose,
            trust=trust,
            signed_bundle=(_load_object(args.signed_bundle, "signed policy bundle")
                if args.signed_bundle is not None else None),
            policy_public_key=args.policy_public_key,
            policy_public_key_sha256=args.policy_public_key_sha256,
            draft_request=(_load_object(args.draft_request, "unsigned draft request")
                if args.draft_request is not None else None),
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
