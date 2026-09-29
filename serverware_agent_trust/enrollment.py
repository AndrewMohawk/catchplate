#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from . import (  # noqa: E402
    ENROLLMENT_CLI_COMMAND,
    __version__,
    validate_enrollment_tooling,
)
from .attestation import (  # noqa: E402
    enrollment_install_session,
    spki_hash_from_public_key_pem,
    verify_enrollment_measurements,
    verify_enrollment_packet_signature,
    verify_quote,
    verify_runtime_digest,
)
from .http import request_bytes  # noqa: E402
from .workload_transport import validate_workload_transport  # noqa: E402
from .receipts import (  # noqa: E402
    ENROLLMENT_CHECKS,
    ENROLLMENT_RECEIPT_API_VERSION,
    Ed25519TrustRoot,
    SetupAssignment,
    VerifiedAgentEgressEvidence,
    canonical_base64url,
    canonical_json_bytes,
    sha256_digest,
    validate_attestation_evidence_binding,
    verify_agent_egress_evidence,
)


MAX_ENROLLMENT_PACKET_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_BYTES = 8 * 1024 * 1024
MAX_SIGNING_KEY_BYTES = 64 * 1024
MAX_EGRESS_EVIDENCE_BYTES = 128 * 1024


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"JSON contains non-standard constant {value!r}")


def _reject_json_float(value: str) -> object:
    raise ValueError(f"JSON contains unsupported floating-point value {value!r}")


def parse_json_object(
    raw: bytes,
    *,
    label: str,
    max_bytes: int,
    allow_floats: bool = False,
) -> dict[str, object]:
    if len(raw) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    try:
        load_options = {
            "object_pairs_hook": _reject_duplicate_keys,
            "parse_constant": _reject_json_constant,
        }
        if not allow_floats:
            load_options["parse_float"] = _reject_json_float
        value = json.loads(raw.decode("utf-8"), **load_options)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def read_file_snapshot(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    require_private_permissions: bool = False,
    require_current_owner: bool = False,
    require_nofollow: bool = False,
) -> bytes:
    if require_nofollow and not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} cannot be opened without following symlinks on this platform")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is not a readable non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if require_private_permissions and metadata.st_mode & 0o077:
            raise ValueError(f"{label} must not be accessible by group or other users")
        if require_current_owner and hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ValueError(f"{label} must be owned by the current process user")
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds {max_bytes} bytes")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_enrollment_packet_snapshot(path: Path) -> tuple[bytes, dict[str, object]]:
    raw = read_file_snapshot(
        path,
        label="enrollment packet",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )
    return raw, parse_json_object(
        raw,
        label="enrollment packet",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )


def load_enrollment_packet(path: Path) -> dict[str, object]:
    return load_enrollment_packet_snapshot(path)[1]


def load_setup_receipt_signing_key(
    path: Path,
    *,
    password_env: str | None,
) -> Ed25519PrivateKey:
    raw = read_file_snapshot(
        path,
        label="setup receipt signing key",
        max_bytes=MAX_SIGNING_KEY_BYTES,
        require_private_permissions=True,
        require_current_owner=True,
        require_nofollow=True,
    )
    password: bytes | None = None
    if password_env is not None:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", password_env) is None:
            raise ValueError("setup receipt signing key password environment variable name is invalid")
        password_value = os.getenv(password_env)
        if not password_value:
            raise ValueError(
                f"setup receipt signing key password environment variable {password_env!r} is unset or empty"
            )
        password = password_value.encode("utf-8")
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as exc:
        raise ValueError("setup receipt signing key is not a valid PEM private key for the supplied password") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("setup receipt signing key must be an Ed25519 private key")
    return key


def load_trusted_ed25519_public_key(path: Path, *, provider: str) -> Ed25519TrustRoot:
    raw = read_file_snapshot(
        path,
        label="egress evidence trusted public key",
        max_bytes=MAX_SIGNING_KEY_BYTES,
        require_nofollow=True,
    )
    if b"PRIVATE KEY" in raw:
        raise ValueError("egress evidence trust file must contain public key material only")
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("egress evidence trust file is not a valid Ed25519 public key") from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("egress evidence trust file must contain an Ed25519 public key")
    return Ed25519TrustRoot(
        provider,
        key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def canonical_uuid(value: str, *, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return value


def enrollment_nonce(packet: dict[str, object]) -> str:
    nonce = packet.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce):
        raise ValueError("enrollment packet is missing a valid nonce")
    return nonce


def verify_packet(packet: dict[str, object], attestation: dict[str, object], nonce: str) -> dict[str, object]:
    if not isinstance(packet, dict):
        raise ValueError("enrollment packet must be a JSON object")
    if (
        packet.get("apiVersion") != "serverware.agentEnrollment/v1"
        or packet.get("kind") != "AgentEnrollment"
    ):
        raise ValueError("enrollment packet schema is unsupported")
    if "verificationReceipt" in packet:
        raise ValueError("enrollment packet already contains an untrusted verificationReceipt")
    if packet.get("nonce") != nonce or attestation.get("nonce") != nonce:
        raise ValueError("enrollment packet or attestation nonce mismatch")
    now_ms = int(time.time() * 1000)
    issued_at = packet.get("issuedAtEpochMs")
    expires_at = packet.get("expiresAtEpochMs")
    if type(issued_at) is not int or type(expires_at) is not int or not issued_at <= now_ms < expires_at:
        raise ValueError("enrollment packet is not currently valid")
    if expires_at - issued_at > 900_000:
        raise ValueError("enrollment packet lifetime exceeds 900 seconds")
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict):
        raise ValueError("enrollment packet is missing pinning")
    expected_pins = {
        "policyHash": "policy_bundle_digest",
        "policySigningKeyId": "policy_signing_key_id",
        "policySequence": "policy_sequence",
        "policyHighWaterDigest": "policy_high_water_digest",
        "caIntermediateSpkiSha256": "ca_intermediate_spki_sha256",
        "dataPlaneBinaryDigest": "data_plane_binary_digest",
        "runtimeManifestDigest": "runtime_manifest_digest",
        "responseSigningKeyId": "response_signing_key_id",
        "provenanceDigest": "provenance_digest",
        "imageSignaturesDigest": "image_signatures_digest",
        "sourceTreeDigest": "source_tree_digest",
        "rollbackEpoch": "rollback_epoch",
        "releaseChannel": "release_channel",
    }
    for packet_field, attestation_field in expected_pins.items():
        if pinning.get(packet_field) != attestation.get(attestation_field):
            raise ValueError(f"enrollment pin {packet_field} does not match live attestation")

    authenticity = packet.get("authenticity")
    if not isinstance(authenticity, dict):
        raise ValueError("enrollment packet is missing authenticity")
    statement = authenticity.get("statement")
    signature = authenticity.get("signature")
    if not isinstance(statement, dict) or not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("enrollment authenticity statement is invalid")
    unsigned_packet = dict(packet)
    unsigned_packet.pop("authenticity", None)
    packet_sha256 = digest(canonical_json(unsigned_packet).encode("utf-8"))
    if statement.get("packetSha256") != packet_sha256:
        raise ValueError("enrollment packet digest mismatch")
    statement_sha256 = digest(canonical_json(statement).encode("utf-8"))
    if authenticity.get("statementSha256") != statement_sha256:
        raise ValueError("enrollment statement digest mismatch")
    public_key_pem = attestation.get("response_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation is missing the response signing public key")
    response_key_id = spki_hash_from_public_key_pem(public_key_pem)
    if response_key_id != pinning.get("responseSigningKeyId"):
        raise ValueError("enrollment response signing key does not match its pin")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(statement).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("enrollment packet signature verification failed") from exc
    validate_workload_transport(packet)
    validate_enrollment_tooling(packet)
    return {
        "apiVersion": "serverware.agentEnrollmentVerification/v1",
        "kind": "AgentEnrollmentVerification",
        "verifiedAtEpochMs": now_ms,
        "nonce": nonce,
        "packetSha256": packet_sha256,
        "statementSha256": statement_sha256,
        "attestationQuoteSha256": digest(canonical_json(attestation.get("quote")).encode("utf-8")),
        "policyHash": pinning["policyHash"],
        "runtimeManifestDigest": pinning["runtimeManifestDigest"],
        "responseSigningKeyId": response_key_id,
        "checks": [
            "packet-schema",
            "tooling-contract",
            "tooling-version",
            "attestation-nonce",
            "attestation-quote",
            "runtime-manifest",
            "measurement-pins",
            "packet-expiry",
            "packet-signature",
        ],
    }


def verify_attestation_for_packet(
    packet: dict[str, object],
    attestation: dict[str, object],
    nonce: str,
    tee_verify_command: str | None,
    expected_tee_verifier_identity_sha256: str | None = None,
) -> dict[str, object]:
    if attestation.get("nonce") != nonce:
        raise ValueError("live attestation nonce does not match enrollment packet")
    verify_runtime_digest(attestation)
    verified_quote = verify_quote(
        attestation,
        tee_verify_command,
        expected_tee_verifier_identity_sha256,
    )
    quote = attestation.get("quote")
    claims = verified_quote.get("claims")
    if not isinstance(claims, dict) or claims.get("nonce") != nonce:
        raise ValueError("attestation quote nonce does not match enrollment packet")
    receipt = verify_packet(packet, attestation, nonce)
    receipt.update(
        {
            "quoteProvider": verified_quote.get("provider"),
            "attestationQuoteSha256": digest(canonical_json(quote).encode("utf-8")),
            "verifiedClaimsSha256": digest(canonical_json(claims).encode("utf-8")),
            "quoteVerifierIdentitySha256": verified_quote.get("evidence_identity_sha256"),
            "quoteSelfRooted": verified_quote.get("self_rooted"),
            "quoteDebug": verified_quote.get("debug"),
            "attestationAssurance": verified_quote.get("assurance"),
        }
    )
    return receipt


def request_attestation(base: str, nonce: str) -> dict[str, object]:
    query = urllib.parse.urlencode({"nonce": nonce})
    request = urllib.request.Request(f"{base.rstrip('/')}/attestation?{query}")
    response = request_bytes(request, timeout=10, max_bytes=MAX_ATTESTATION_BYTES)
    return parse_json_object(
        response.body,
        label="live attestation",
        max_bytes=MAX_ATTESTATION_BYTES,
        allow_floats=True,
    )


def verify_downloaded_packet(
    packet_path: Path,
    *,
    base: str,
    tee_verify_command: str | None,
    expected_packet_sha256: str,
    expected_principal: str,
    expected_nonce: str,
    expected_tee_verifier_identity_sha256: str | None = None,
) -> dict[str, object]:
    raw_packet, packet = load_enrollment_packet_snapshot(packet_path)
    actual_packet_sha256 = digest(raw_packet)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_packet_sha256) is None:
        raise ValueError("expected enrollment packet SHA-256 is malformed")
    if actual_packet_sha256 != expected_packet_sha256:
        raise ValueError("downloaded enrollment packet SHA-256 does not match the expected file")
    if packet.get("principalId") != expected_principal:
        raise ValueError("enrollment packet principal does not match the expected principal")
    nonce = enrollment_nonce(packet)
    if nonce != expected_nonce:
        raise ValueError("enrollment packet nonce does not match the expected nonce")
    attestation = request_attestation(base, nonce)
    receipt = verify_attestation_for_packet(
        packet,
        attestation,
        nonce,
        tee_verify_command,
        expected_tee_verifier_identity_sha256,
    )
    receipt["downloadedPacketSha256"] = actual_packet_sha256
    receipt["expectedPrincipalId"] = expected_principal
    receipt["checks"].extend(["downloaded-file-digest", "expected-principal", "expected-nonce"])
    packet["verificationReceipt"] = receipt
    return packet


def verify_previously_verified_packet(
    packet_path: Path,
    *,
    base: str,
    tee_verify_command: str | None,
    expected_tee_verifier_identity_sha256: str | None = None,
) -> dict[str, object]:
    packet = load_enrollment_packet(packet_path)
    attestation_base, _ = enrollment_install_session(packet, base=base)
    nonce = enrollment_nonce(packet)
    attestation = request_attestation(attestation_base, nonce)
    if attestation.get("nonce") != nonce:
        raise ValueError("live attestation nonce does not match enrollment packet")
    verify_runtime_digest(attestation)
    verified_quote = verify_quote(
        attestation,
        tee_verify_command,
        expected_tee_verifier_identity_sha256,
    )
    claims = verified_quote.get("claims")
    if not isinstance(claims, dict) or claims.get("nonce") != nonce:
        raise ValueError("attestation quote nonce does not match enrollment packet")
    public_key_pem = attestation.get("response_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation is missing the response signing public key")
    response_key_id = spki_hash_from_public_key_pem(public_key_pem)
    if attestation.get("response_signing_key_id") != response_key_id:
        raise ValueError("attestation response signing key hash does not match public key")
    verify_enrollment_packet_signature(
        packet,
        attestation=attestation,
        response_key_id=response_key_id,
    )
    validate_enrollment_tooling(packet)
    verify_enrollment_measurements(
        packet,
        attestation=attestation,
        response_key_id=response_key_id,
    )
    return packet


def authenticated_agent_instructions(packet: dict[str, object]) -> str:
    handoff = packet.get("agentHandoff")
    instructions = handoff.get("authenticatedInstructions") if isinstance(handoff, dict) else None
    if instructions is None and isinstance(handoff, dict):
        instructions = handoff.get("instructionsText")
    if not isinstance(instructions, str) or not instructions.strip():
        raise ValueError(
            "verified enrollment packet is missing agentHandoff.authenticatedInstructions"
        )
    if len(instructions.encode("utf-8")) > 1024 * 1024:
        raise ValueError("verified enrollment instructions exceed 1048576 bytes")
    if "\x00" in instructions:
        raise ValueError("verified enrollment instructions contain a NUL byte")
    return instructions


def emit_instructions(packet: dict[str, object]) -> None:
    sys.stdout.write(authenticated_agent_instructions(packet))


def sign_setup_enrollment_receipt(
    verified_packet: dict[str, object],
    *,
    setup_session_id: str,
    enrollment_session_id: str,
    assignment: SetupAssignment,
    expected_assignment_digest: str,
    trust_profile_sha256: str,
    verifier_provider: str,
    expected_verifier_key_id: str,
    signing_key: Ed25519PrivateKey,
    verifier_nonce: str,
    egress_evidence: VerifiedAgentEgressEvidence,
    development_fixture: bool,
    receipt_id: str | None = None,
    ttl_seconds: int = 300,
    now_unix: int | None = None,
) -> dict[str, object]:
    canonical_uuid(setup_session_id, label="setup session ID")
    canonical_uuid(enrollment_session_id, label="enrollment session ID")
    if receipt_id is None:
        receipt_id = str(uuid.uuid4())
    canonical_uuid(receipt_id, label="receipt ID")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
        raise ValueError("setup receipt TTL must be between 1 and 900 seconds")
    if not secrets.compare_digest(assignment.digest, expected_assignment_digest):
        raise ValueError("setup assignment does not match the expected assignment digest")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", trust_profile_sha256) is None:
        raise ValueError("setup trust profile digest is malformed")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_verifier_key_id) is None:
        raise ValueError("expected enrollment verifier key ID is malformed")

    public_key_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_trust = Ed25519TrustRoot(verifier_provider, public_key_der)
    if not secrets.compare_digest(verifier_trust.key_id, expected_verifier_key_id):
        raise ValueError("setup receipt signing key does not match the expected enrollment verifier key ID")
    if not development_fixture and secrets.compare_digest(
        verifier_trust.key_id, egress_evidence.evidence_key_id
    ):
        raise ValueError("production receipt and egress evidence signing keys must be distinct")

    verification = verified_packet.get("verificationReceipt")
    if not isinstance(verification, dict):
        raise ValueError("verified enrollment packet is missing its local verification receipt")
    packet_sha256 = verification.get("packetSha256")
    if not isinstance(packet_sha256, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", packet_sha256) is None:
        raise ValueError("verified enrollment packet digest is unavailable")
    attestation_evidence = {
        "quote_provider": verification.get("quoteProvider"),
        "quote_sha256": verification.get("attestationQuoteSha256"),
        "verified_claims_sha256": verification.get("verifiedClaimsSha256"),
        "verifier_identity_sha256": verification.get("quoteVerifierIdentitySha256"),
        "self_rooted": verification.get("quoteSelfRooted"),
        "debug": verification.get("quoteDebug"),
        "assurance": verification.get("attestationAssurance"),
    }
    validate_attestation_evidence_binding(
        attestation_evidence,
        require_production=not development_fixture,
    )
    if verified_packet.get("principalId") != assignment.principal_id:
        raise ValueError("verified enrollment packet principal does not match the setup assignment")

    pinning = verified_packet.get("pinning")
    if not isinstance(pinning, dict) or pinning.get("policyHash") != assignment.policy_hash:
        raise ValueError("verified enrollment packet policy does not match the setup assignment")
    routes = verified_packet.get("allowedRoutes")
    matching_routes = (
        [route for route in routes if isinstance(route, dict) and route.get("id") == assignment.route_id]
        if isinstance(routes, list)
        else []
    )
    if len(matching_routes) != 1 or matching_routes[0].get("credentialRef") != assignment.credential_id:
        raise ValueError("verified enrollment packet route and credential do not match the setup assignment")

    ca = verified_packet.get("ca")
    install_session = ca.get("installSession") if isinstance(ca, dict) else None
    if not isinstance(install_session, dict) or install_session.get("id") != enrollment_session_id:
        raise ValueError("verified enrollment packet capability does not match the enrollment session")
    nonce = enrollment_nonce(verified_packet)
    if not secrets.compare_digest(nonce, verifier_nonce):
        raise ValueError("verified enrollment packet nonce does not match the setup verifier nonce")

    issued_at = int(time.time()) if now_unix is None else now_unix
    if type(issued_at) is not int or issued_at < 1:
        raise ValueError("setup receipt issue time must be a positive integer Unix timestamp")
    statement: dict[str, object] = {
        "receipt_id": receipt_id,
        "setup_session_id": setup_session_id,
        "assignment": assignment.as_document(),
        "assignment_digest": assignment.digest,
        "enrollment_session_id": enrollment_session_id,
        "enrollment_packet_sha256": packet_sha256,
        "verifier_nonce_sha256": sha256_digest(verifier_nonce.encode("ascii")),
        "trust_profile_sha256": trust_profile_sha256,
        "verifier_provider": verifier_provider,
        "assurance_mode": "development-fixture" if development_fixture else "production",
        "attestation_evidence": attestation_evidence,
        "egress_evidence": egress_evidence.as_receipt_binding(),
        "decision": "verified",
        "checks": list(ENROLLMENT_CHECKS),
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + ttl_seconds,
    }
    signature = signing_key.sign(canonical_json_bytes(statement))
    return {
        "apiVersion": ENROLLMENT_RECEIPT_API_VERSION,
        "kind": "EnrollmentVerifierReceipt",
        "statement": statement,
        "signing_key_id": verifier_trust.key_id,
        "signature": "ed25519:" + canonical_base64url(signature),
    }


def emit_packet(packet: dict[str, object]) -> None:
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    print()


def _workload_issuance_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Explicit one-exchange operator modes, separate from local provisioning."""
    if not (args.request_workload_issuance_options or args.submit_workload_issuance):
        return False
    common_pins = ("packet", "packet-signing-key", "issuer", "authorization", "request",
        "tls-ca", "cookie", "csrf")
    issue_pins = ("private-key", "options", "assertion")
    pin_names = (*common_pins, *issue_pins, "approval")
    allowed = {
        "--request-workload-issuance-options", "--submit-workload-issuance",
        "--expected-principal", "--expected-nonce", "--workload-output-directory",
        "--workload-timeout-ms", "--workload-origin", "--workload-endpoint-address",
        "--workload-endpoint-port", "--workload-server-name", "--workload-server-spki-sha256",
        *("--workload-" + name + suffix for name in pin_names for suffix in ("", "-sha256")),
    }
    supplied = {item.split("=", 1)[0] for item in sys.argv[1:] if item.startswith("--")}
    if supplied - allowed:
        parser.error("operator workload issuance accepts only its explicit pinned inputs; no bearer or proxy options")

    def argument(name: str):
        return getattr(args, "workload_" + name.replace("-", "_"))

    required = [
        ("--expected-principal", args.expected_principal),
        ("--expected-nonce", args.expected_nonce),
        *(("--workload-" + name, argument(name)) for name in (
            "output-directory", "origin", "endpoint-address", "endpoint-port", "server-name",
            "server-spki-sha256")),
    ]
    required_pins = common_pins
    if args.submit_workload_issuance:
        required_pins += issue_pins
        if argument("approval") is not None or argument("approval-sha256") is not None:
            required_pins += ("approval",)
    elif any(argument(name + suffix) is not None
            for name in (*issue_pins, "approval") for suffix in ("", "-sha256")):
        parser.error("options-only mode cannot accept a private key, assertion or continuation receipt")
    required.extend(("--workload-" + name + suffix, argument(name + suffix))
        for name in required_pins for suffix in ("", "-sha256"))
    missing = [flag for flag, value in required if value is None or value == ""]
    if missing:
        parser.error("operator workload issuance requires " + ", ".join(missing))

    from . import workload_identity_submission as submission
    from ._workload_operator_http import OperatorEndpoint
    from ._workload_stream import WorkloadClientError
    from ._workload_tls import PinnedFile

    def pin(name: str) -> PinnedFile:
        return PinnedFile(argument(name), argument(name + "-sha256"))

    def description(value: PinnedFile) -> dict[str, str]:
        return {"path": os.fspath(value.path), "sha256": value.sha256}

    connection = OperatorEndpoint(origin=args.workload_origin,
        endpoint=(args.workload_endpoint_address, args.workload_endpoint_port),
        server_name=args.workload_server_name, trust=pin("tls-ca"),
        server_spki_sha256=args.workload_server_spki_sha256,
        cookie=pin("cookie"), csrf=pin("csrf"))
    common = {"packet": pin("packet"), "packet_signing_key": pin("packet-signing-key"),
        "issuer": pin("issuer"), "authorization": pin("authorization"), "request": pin("request"),
        "expected_principal": args.expected_principal, "expected_nonce": args.expected_nonce,
        "output_directory": args.workload_output_directory, "timeout_ms": args.workload_timeout_ms,
        "connection": connection}
    try:
        exit_code = 0
        if args.request_workload_issuance_options:
            options = submission.request_issuance_options(**common)
            result = {"status": "options-received", "response": description(options.response),
                "action": options.action, "resourceId": options.resource_id,
                "payloadDigest": options.payload_digest}
        else:
            submitted = submission.submit_issuance(**common, private_key=pin("private-key"),
                options=pin("options"), assertion=pin("assertion"),
                approval=pin("approval") if args.workload_approval is not None else None)
            statuses = {"certificate-issued": 0, "approval-required": 3,
                "issuance-outcome-unknown": 4, "refused": 5}
            if type(submitted.status) is not str or submitted.status not in statuses:
                raise WorkloadClientError("operator workload submission status is invalid")
            exit_code = statuses[submitted.status]
            result = {"status": submitted.status, "response": description(submitted.response)}
            if submitted.identity is not None:
                result["clientCertificate"] = description(submitted.identity.client_certificate)
                result["clientPrivateKey"] = description(submitted.identity.client_private_key)
        print(json.dumps({"schema": "serverware.workloadIdentitySubmissionResult/v1", **result,
            "proxyAuthenticated": False, "enrollmentComplete": False, "automaticRetryAllowed": False},
            indent=2, sort_keys=True))
        if exit_code:
            raise SystemExit(exit_code)
    except (OSError, ValueError):
        raise WorkloadClientError(
            "operator workload request did not complete; retain all artifacts and do not automatically retry"
        ) from None
    return True


def _extract_native_bootstrap_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Data-only bounded capture extraction, never verification or network use."""
    if not args.extract_native_bootstrap_packet:
        return False
    allowed = {"--extract-native-bootstrap-packet", "--workload-capture", "--workload-capture-sha256",
        "--workload-request", "--workload-request-sha256", "--workload-output-directory",
        "--workload-timeout-ms"}
    supplied = {item.split("=", 1)[0] for item in sys.argv[1:] if item.startswith("--")}
    if supplied - allowed:
        parser.error("native capture extraction accepts only explicit capture/request pins and local output")
    required = ("capture", "capture_sha256", "request", "request_sha256", "output_directory")
    missing = ["--workload-" + name.replace("_", "-") for name in required
        if getattr(args, "workload_" + name) in (None, "")]
    if missing:
        parser.error("native capture extraction requires " + ", ".join(missing))
    from .native_bootstrap_capture import extract_packet
    from ._workload_tls import PinnedFile

    pin = extract_packet(capture=PinnedFile(args.workload_capture, args.workload_capture_sha256),
        target_request=PinnedFile(args.workload_request, args.workload_request_sha256),
        output_directory=args.workload_output_directory, timeout_ms=args.workload_timeout_ms)
    print(json.dumps({"schema": "serverware.nativeBootstrapPacketExtractionResult/v1",
        "status": "unverified-packet-extracted", "packet": {"path": os.fspath(pin.path), "sha256": pin.sha256},
        "okForAction": False, "issuanceAuthorized": False,
        "proxyAuthenticated": False, "enrollmentComplete": False}, indent=2, sort_keys=True))
    return True


def _native_workload_issuance_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Explicit native operator modes; no legacy packet-key or manifest alias."""
    if not (args.request_native_workload_issuance_options or args.submit_native_workload_issuance):
        return False
    common_pins = ("packet", "issuer", "authorization", "request", "tls-ca", "cookie", "csrf")
    issue_pins = ("private-key", "options", "assertion")
    pin_names = (*common_pins, *issue_pins, "approval")
    allowed = {"--request-native-workload-issuance-options", "--submit-native-workload-issuance",
        "--expected-principal", "--expected-nonce", "--workload-output-directory", "--workload-timeout-ms",
        "--workload-origin", "--workload-endpoint-address", "--workload-endpoint-port",
        "--workload-server-name", "--workload-server-spki-sha256", "--workload-san-dns", "--workload-san-uri",
        *("--workload-" + name + suffix for name in pin_names for suffix in ("", "-sha256"))}
    supplied = {item.split("=", 1)[0] for item in sys.argv[1:] if item.startswith("--")}
    if supplied - allowed:
        parser.error("native workload issuance accepts only explicit native originals and pinned operator inputs")

    def argument(name: str):
        return getattr(args, "workload_" + name.replace("-", "_"))

    required = [("--expected-principal", args.expected_principal), ("--expected-nonce", args.expected_nonce),
        *(("--workload-" + name, argument(name)) for name in ("output-directory", "origin",
            "endpoint-address", "endpoint-port", "server-name", "server-spki-sha256"))]
    required_pins = common_pins
    if args.submit_native_workload_issuance:
        required_pins += issue_pins
        if argument("approval") is not None or argument("approval-sha256") is not None:
            required_pins += ("approval",)
    elif any(argument(name + suffix) is not None
            for name in (*issue_pins, "approval") for suffix in ("", "-sha256")):
        parser.error("native options-only mode cannot accept private key, assertion or continuation inputs")
    required.extend(("--workload-" + name + suffix, argument(name + suffix))
        for name in required_pins for suffix in ("", "-sha256"))
    missing = [flag for flag, value in required if value is None or value == ""]
    if missing:
        parser.error("native workload issuance requires " + ", ".join(missing))
    if (not args.workload_san_dns and not args.workload_san_uri
            or len(set(args.workload_san_dns)) != len(args.workload_san_dns)
            or len(set(args.workload_san_uri)) != len(args.workload_san_uri)):
        parser.error("native workload issuance requires explicit unique target DNS/URI SANs")
    from . import native_workload_identity_submission as submission
    from ._workload_operator_http import OperatorEndpoint
    from ._workload_stream import WorkloadClientError
    from ._workload_tls import PinnedFile

    def pin(name: str) -> PinnedFile:
        return PinnedFile(argument(name), argument(name + "-sha256"))

    def description(value: PinnedFile) -> dict[str, str]:
        return {"path": os.fspath(value.path), "sha256": value.sha256}

    connection = OperatorEndpoint(origin=args.workload_origin,
        endpoint=(args.workload_endpoint_address, args.workload_endpoint_port),
        server_name=args.workload_server_name, trust=pin("tls-ca"),
        server_spki_sha256=args.workload_server_spki_sha256, cookie=pin("cookie"), csrf=pin("csrf"))
    common = {"connection": connection, "packet": pin("packet"), "issuer": pin("issuer"),
        "authorization": pin("authorization"), "request": pin("request"),
        "expected_principal": args.expected_principal, "expected_nonce": args.expected_nonce,
        "requested_sans": {"dnsNames": sorted(args.workload_san_dns), "uris": sorted(args.workload_san_uri)},
        "output_directory": args.workload_output_directory, "timeout_ms": args.workload_timeout_ms}
    try:
        exit_code = 0
        if args.request_native_workload_issuance_options:
            options = submission.request_issuance_options(**common)
            result = {"status": "options-received", "response": description(options.response),
                "action": options.action, "resourceId": options.resource_id, "payloadDigest": options.payload_digest}
        else:
            submitted = submission.submit_issuance(**common, private_key=pin("private-key"),
                options=pin("options"), assertion=pin("assertion"),
                approval=pin("approval") if args.workload_approval is not None else None)
            statuses = {"certificate-issued": 0, "approval-required": 3,
                "issuance-outcome-unknown": 4, "refused": 5}
            if type(submitted.status) is not str or submitted.status not in statuses:
                raise WorkloadClientError("native workload submission status is invalid")
            exit_code = statuses[submitted.status]
            result = {"status": submitted.status, "response": description(submitted.response)}
            if submitted.identity is not None:
                result["clientCertificate"] = description(submitted.identity.client_certificate)
                result["clientPrivateKey"] = description(submitted.identity.client_private_key)
        print(json.dumps({"schema": "serverware.nativeWorkloadIdentitySubmissionResult/v1", **result,
            "proxyAuthenticated": False, "enrollmentComplete": False, "automaticRetryAllowed": False},
            indent=2, sort_keys=True))
        if exit_code:
            raise SystemExit(exit_code)
    except (OSError, ValueError):
        raise WorkloadClientError(
            "native workload request did not complete; retain all artifacts and do not automatically retry"
        ) from None
    return True


def _workload_bootstrap_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Explicit local request-first mode; no packet, admin or network authority."""
    if not args.prepare_workload_bootstrap:
        return False
    supplied = {item.split("=", 1)[0] for item in sys.argv[1:] if item.startswith("--")}
    allowed = {"--prepare-workload-bootstrap", "--expected-principal", "--expected-nonce",
        "--workload-issuer", "--workload-issuer-sha256", "--workload-output-directory",
        "--workload-timeout-ms", "--workload-san-dns", "--workload-san-uri"}
    if supplied - allowed:
        parser.error("local workload bootstrap accepts only its explicit issuer, identity and output inputs")
    required = (("--expected-principal", args.expected_principal),
        ("--expected-nonce", args.expected_nonce), ("--workload-issuer", args.workload_issuer),
        ("--workload-issuer-sha256", args.workload_issuer_sha256),
        ("--workload-output-directory", args.workload_output_directory))
    missing = [flag for flag, value in required if value is None or value == ""]
    if missing:
        parser.error("local workload bootstrap requires " + ", ".join(missing))
    from .workload_identity_bootstrap import prepare_bootstrap
    from ._workload_tls import PinnedFile

    prepared = prepare_bootstrap(
        issuer=PinnedFile(args.workload_issuer, args.workload_issuer_sha256),
        expected_principal=args.expected_principal, expected_nonce=args.expected_nonce,
        requested_sans={"dnsNames": sorted(args.workload_san_dns),
            "uris": sorted(args.workload_san_uri)},
        output_directory=args.workload_output_directory, timeout_ms=args.workload_timeout_ms)

    def description(pin: PinnedFile) -> dict[str, str]:
        return {"path": os.fspath(pin.path), "sha256": pin.sha256}

    print(json.dumps({"schema": "serverware.workloadIdentityLocalResult/v1",
        "profile": "request-first-p256-bootstrap-v1", "status": "bootstrap-prepared-local-only",
        "request": description(prepared.request), "csr": description(prepared.csr),
        "privateKey": description(prepared.private_key), "issuanceAuthorized": False,
        "proxyAuthenticated": False, "enrollmentComplete": False}, indent=2, sort_keys=True))
    return True


def _workload_identity_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Local-only provisioning; never fall through into enrollment networking."""
    selected = args.prepare_workload_identity or args.admit_workload_certificate
    supplied = {item.split("=", 1)[0] for item in sys.argv[1:] if item.startswith("--")}
    if not selected:
        if any(flag.startswith("--workload-") for flag in supplied):
            parser.error("--workload-* inputs require an explicit workload provisioning mode")
        return False
    allowed = {
        "--prepare-workload-identity", "--admit-workload-certificate",
        "--expected-principal", "--expected-nonce", "--workload-packet",
        "--workload-packet-sha256", "--workload-packet-signing-key",
        "--workload-packet-signing-key-sha256", "--workload-issuer",
        "--workload-issuer-sha256", "--workload-output-directory",
        "--workload-timeout-ms", "--workload-san-dns", "--workload-san-uri",
        "--workload-request", "--workload-request-sha256", "--workload-private-key",
        "--workload-private-key-sha256", "--workload-certificate", "--workload-certificate-sha256",
    }
    if supplied - allowed:
        parser.error("local workload provisioning does not accept enrollment, receipt or network options")
    required = (
        ("--expected-principal", args.expected_principal),
        ("--expected-nonce", args.expected_nonce),
        ("--workload-packet", args.workload_packet),
        ("--workload-packet-sha256", args.workload_packet_sha256),
        ("--workload-packet-signing-key", args.workload_packet_signing_key),
        ("--workload-packet-signing-key-sha256", args.workload_packet_signing_key_sha256),
        ("--workload-issuer", args.workload_issuer),
        ("--workload-issuer-sha256", args.workload_issuer_sha256),
        ("--workload-output-directory", args.workload_output_directory),
    )
    admission = (
        ("--workload-request", args.workload_request),
        ("--workload-request-sha256", args.workload_request_sha256),
        ("--workload-private-key", args.workload_private_key),
        ("--workload-private-key-sha256", args.workload_private_key_sha256),
        ("--workload-certificate", args.workload_certificate),
        ("--workload-certificate-sha256", args.workload_certificate_sha256),
    )
    if args.admit_workload_certificate:
        required += admission
        if args.workload_san_dns or args.workload_san_uri:
            parser.error("certificate admission takes SANs only from the authenticated retained request")
    elif any(value is not None for _flag, value in admission):
        parser.error("fresh identity preparation cannot accept an existing request, key or certificate")
    missing = [flag for flag, value in required if value is None or value == ""]
    if missing:
        parser.error("local workload provisioning requires " + ", ".join(missing))
    # Import only for these explicit local modes. These helpers perform no
    # network calls and cannot consume an admin or CA-install session token.
    from . import workload_identity_provisioning as provisioning
    from ._workload_tls import PinnedFile

    common = {
        "packet": PinnedFile(args.workload_packet, args.workload_packet_sha256),
        "packet_signing_key": PinnedFile(args.workload_packet_signing_key,
            args.workload_packet_signing_key_sha256),
        "issuer": PinnedFile(args.workload_issuer, args.workload_issuer_sha256),
        "expected_principal": args.expected_principal,
        "expected_nonce": args.expected_nonce,
        "output_directory": args.workload_output_directory,
        "timeout_ms": args.workload_timeout_ms,
    }

    def description(pin: PinnedFile) -> dict[str, str]:
        return {"path": os.fspath(pin.path), "sha256": pin.sha256}

    if args.prepare_workload_identity:
        prepared = provisioning.prepare_identity(**common, selected_sans={
            "dnsNames": sorted(args.workload_san_dns), "uris": sorted(args.workload_san_uri)})
        result = {"status": "prepared-local-only", "request": description(prepared.request),
            "csr": description(prepared.csr), "privateKey": description(prepared.private_key)}
    else:
        admitted = provisioning.admit_certificate(**common,
            request=PinnedFile(args.workload_request, args.workload_request_sha256),
            private_key=PinnedFile(args.workload_private_key, args.workload_private_key_sha256),
            certificate=PinnedFile(args.workload_certificate, args.workload_certificate_sha256))
        result = {"status": "certificate-admitted-local-only",
            "clientCertificate": description(admitted.client_certificate),
            "clientPrivateKey": description(admitted.client_private_key)}
    print(json.dumps({"schema": "serverware.workloadIdentityLocalResult/v1", **result,
        "issuanceAuthorized": False, "proxyAuthenticated": False, "enrollmentComplete": False},
        indent=2, sort_keys=True))
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate or verify a Serverware agent enrollment packet, or sign a setup receipt."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{ENROLLMENT_CLI_COMMAND} {__version__}",
    )
    parser.add_argument("--base", default=os.getenv("SERVERWARE_PUBLIC_URL", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument(
        "--verify-packet",
        type=Path,
        metavar="PATH",
        help="verify this exact downloaded packet and emit it with verificationReceipt",
    )
    parser.add_argument(
        "--verified-packet",
        type=Path,
        metavar="PATH",
        help="revalidate a packet and its verificationReceipt against fresh attestation",
    )
    parser.add_argument(
        "--emit-verified-instructions",
        "--emit-instructions",
        dest="emit_instructions",
        action="store_true",
        help="emit only agentHandoff.authenticatedInstructions after packet verification",
    )
    parser.add_argument("--expected-packet-sha256")
    parser.add_argument("--expected-principal")
    parser.add_argument("--expected-nonce")
    workload_modes = parser.add_mutually_exclusive_group()
    workload_modes.add_argument("--prepare-workload-bootstrap", action="store_true",
        help="locally prepare one request-first P-256 key/CSR; no packet, certificate or issuance authority")
    workload_modes.add_argument("--prepare-workload-identity", action="store_true",
        help="locally prepare one packet-bound P-256 key and public CSR/request; never contact an issuer")
    workload_modes.add_argument("--admit-workload-certificate", action="store_true",
        help="locally admit one directly issued workload leaf against retained originals and a pinned issuer")
    workload_modes.add_argument("--request-workload-issuance-options", action="store_true",
        help="make one pinned operator HTTPS options request; never submit issuance")
    workload_modes.add_argument("--submit-workload-issuance", action="store_true",
        help="explicitly submit once with pinned options and fresh assertion; never automatically retry")
    workload_modes.add_argument("--extract-native-bootstrap-packet", action="store_true",
        help="extract exact native packet bytes from a pinned capture; no signature or quote authority")
    workload_modes.add_argument("--request-native-workload-issuance-options", action="store_true",
        help="request fresh native issuance options from the pinned operator endpoint; no CA contact")
    workload_modes.add_argument("--submit-native-workload-issuance", action="store_true",
        help="submit native originals once and admit the returned leaf against the retained request key")
    for name in ("packet", "packet-signing-key", "issuer", "request", "private-key", "certificate",
            "authorization", "tls-ca", "cookie", "csrf", "options", "assertion", "approval", "capture"):
        parser.add_argument("--workload-" + name, type=Path)
        parser.add_argument("--workload-" + name + "-sha256")
    parser.add_argument("--workload-origin", help="exact HTTPS origin only, without path or trailing slash")
    parser.add_argument("--workload-endpoint-address", help="independently selected literal IP; no DNS dialing")
    parser.add_argument("--workload-endpoint-port", type=int)
    parser.add_argument("--workload-server-name", help="exact TLS certificate name and HTTP origin host")
    parser.add_argument("--workload-server-spki-sha256", help="independent sha256: pin for the TLS leaf SPKI")
    parser.add_argument("--workload-output-directory", type=Path,
        help="existing current-user-owned mode-0700 directory; fixed outputs are never overwritten")
    parser.add_argument("--workload-timeout-ms", type=int, default=30_000)
    parser.add_argument("--workload-san-dns", action="append", default=[],
        help="exact requested DNS SAN; packet-bound modes require signed permission; repeat for multiple values")
    parser.add_argument("--workload-san-uri", action="append", default=[],
        help="exact requested URI/SPIFFE SAN; packet-bound modes require signed permission; repeat for multiple values")
    parser.add_argument(
        "--sign-setup-receipt",
        action="store_true",
        help="verify --verify-packet and emit only a signed setup enrollment verifier receipt",
    )
    parser.add_argument("--setup-session-id")
    parser.add_argument("--enrollment-session-id")
    parser.add_argument("--route-id")
    parser.add_argument("--credential-id")
    parser.add_argument("--credential-version", type=int)
    parser.add_argument("--policy-hash")
    parser.add_argument("--route-policy-digest")
    parser.add_argument("--expected-assignment-digest")
    parser.add_argument("--trust-profile-sha256")
    parser.add_argument("--verifier-provider")
    parser.add_argument("--setup-receipt-signing-key", type=Path)
    parser.add_argument("--expected-verifier-key-id")
    parser.add_argument("--egress-evidence", type=Path)
    parser.add_argument("--egress-evidence-trusted-public-key", type=Path)
    parser.add_argument("--egress-evidence-provider")
    parser.add_argument("--expected-egress-evidence-key-id")
    parser.add_argument("--expected-tee-verifier-identity-sha256")
    parser.add_argument(
        "--development-receipt-fixture",
        action="store_true",
        help="mark local dev quote and egress evidence as a production-ineligible fixture",
    )
    parser.add_argument("--signing-key-password-env")
    parser.add_argument("--receipt-id")
    parser.add_argument("--receipt-ttl-seconds", type=int, default=300)
    parser.add_argument("--principal-id")
    parser.add_argument("--proxy-url")
    parser.add_argument("--proxy-egress-cidr", action="append")
    parser.add_argument("--control-plane-url", default=None)
    parser.add_argument("--namespace", default="serverware-agents")
    parser.add_argument("--selector", action="append", default=[], help="pod selector label as key=value")
    parser.add_argument("--ca-mount-path", default="/etc/serverware/serverware-ca.pem")
    parser.add_argument("--ttl-seconds", type=int, default=300)
    parser.add_argument(
        "--tee-verify-command",
        default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"),
        help="external TEE quote verifier command for non-development attestations",
    )
    args = parser.parse_args()

    if (_extract_native_bootstrap_mode(parser, args) or _native_workload_issuance_mode(parser, args)
            or _workload_bootstrap_mode(parser, args) or _workload_issuance_mode(parser, args)
            or _workload_identity_mode(parser, args)):
        return

    if args.verify_packet is not None and args.verified_packet is not None:
        parser.error("--verify-packet and --verified-packet are mutually exclusive")
    if args.verified_packet is not None and not args.emit_instructions:
        parser.error("--verified-packet requires --emit-instructions")
    if args.emit_instructions and args.verify_packet is None and args.verified_packet is None:
        parser.error("--emit-instructions requires --verify-packet or --verified-packet")
    if args.sign_setup_receipt and args.emit_instructions:
        parser.error("--sign-setup-receipt and --emit-instructions are mutually exclusive")

    if args.verified_packet is not None:
        emit_instructions(
            verify_previously_verified_packet(
                args.verified_packet,
                base=args.base,
                tee_verify_command=args.tee_verify_command,
                expected_tee_verifier_identity_sha256=(
                    args.expected_tee_verifier_identity_sha256
                ),
            )
        )
        return

    if args.sign_setup_receipt:
        required = (
            ("--verify-packet", args.verify_packet),
            ("--expected-packet-sha256", args.expected_packet_sha256),
            ("--expected-principal", args.expected_principal),
            ("--expected-nonce", args.expected_nonce),
            ("--setup-session-id", args.setup_session_id),
            ("--enrollment-session-id", args.enrollment_session_id),
            ("--route-id", args.route_id),
            ("--credential-id", args.credential_id),
            ("--credential-version", args.credential_version),
            ("--policy-hash", args.policy_hash),
            ("--route-policy-digest", args.route_policy_digest),
            ("--expected-assignment-digest", args.expected_assignment_digest),
            ("--trust-profile-sha256", args.trust_profile_sha256),
            ("--verifier-provider", args.verifier_provider),
            ("--setup-receipt-signing-key", args.setup_receipt_signing_key),
            ("--expected-verifier-key-id", args.expected_verifier_key_id),
            ("--egress-evidence", args.egress_evidence),
            ("--egress-evidence-trusted-public-key", args.egress_evidence_trusted_public_key),
            ("--egress-evidence-provider", args.egress_evidence_provider),
            ("--expected-egress-evidence-key-id", args.expected_egress_evidence_key_id),
        )
        missing = [flag for flag, value in required if value is None or value == ""]
        if missing:
            parser.error(f"setup receipt signing mode requires {', '.join(missing)}")
        if not args.development_receipt_fixture:
            if not args.tee_verify_command:
                raise ValueError("production receipt signing requires an external TEE quote verifier command")
            if not args.expected_tee_verifier_identity_sha256:
                raise ValueError("production receipt signing requires --expected-tee-verifier-identity-sha256")
        signing_key = load_setup_receipt_signing_key(
            args.setup_receipt_signing_key,
            password_env=args.signing_key_password_env,
        )
        verified_packet = verify_downloaded_packet(
            args.verify_packet,
            base=args.base,
            tee_verify_command=args.tee_verify_command,
            expected_packet_sha256=args.expected_packet_sha256,
            expected_principal=args.expected_principal,
            expected_nonce=args.expected_nonce,
            expected_tee_verifier_identity_sha256=(
                args.expected_tee_verifier_identity_sha256
            ),
        )
        local_verification = verified_packet.get("verificationReceipt")
        if not isinstance(local_verification, dict):
            raise ValueError("verified enrollment packet is missing verification evidence")
        if not args.development_receipt_fixture:
            if not secrets.compare_digest(
                str(local_verification.get("quoteVerifierIdentitySha256") or ""),
                args.expected_tee_verifier_identity_sha256,
            ):
                raise ValueError("TEE quote verifier evidence identity does not match the production pin")
        egress_trust = load_trusted_ed25519_public_key(
            args.egress_evidence_trusted_public_key,
            provider=args.egress_evidence_provider,
        )
        if not secrets.compare_digest(
            egress_trust.key_id, args.expected_egress_evidence_key_id
        ):
            raise ValueError("egress evidence signing key does not match the expected key ID")
        egress_raw = read_file_snapshot(
            args.egress_evidence,
            label="agent egress evidence",
            max_bytes=MAX_EGRESS_EVIDENCE_BYTES,
            require_nofollow=True,
        )
        egress_evidence = verify_agent_egress_evidence(
            egress_raw,
            trust=egress_trust,
            packet=verified_packet,
            enrollment_session_id=args.enrollment_session_id,
            allow_development_fixture=args.development_receipt_fixture,
        )
        assignment = SetupAssignment(
            principal_id=args.expected_principal,
            route_id=args.route_id,
            credential_id=args.credential_id,
            credential_version=args.credential_version,
            policy_hash=args.policy_hash,
            route_policy_digest=args.route_policy_digest,
        )
        emit_packet(
            sign_setup_enrollment_receipt(
                verified_packet,
                setup_session_id=args.setup_session_id,
                enrollment_session_id=args.enrollment_session_id,
                assignment=assignment,
                expected_assignment_digest=args.expected_assignment_digest,
                trust_profile_sha256=args.trust_profile_sha256,
                verifier_provider=args.verifier_provider,
                expected_verifier_key_id=args.expected_verifier_key_id,
                signing_key=signing_key,
                verifier_nonce=args.expected_nonce,
                egress_evidence=egress_evidence,
                development_fixture=args.development_receipt_fixture,
                receipt_id=args.receipt_id,
                ttl_seconds=args.receipt_ttl_seconds,
            )
        )
        return

    if args.verify_packet is not None:
        missing = [
            flag
            for flag, value in (
                ("--expected-packet-sha256", args.expected_packet_sha256),
                ("--expected-principal", args.expected_principal),
                ("--expected-nonce", args.expected_nonce),
            )
            if not value
        ]
        if missing:
            parser.error(f"verification mode requires {', '.join(missing)}")
        verified_packet = verify_downloaded_packet(
            args.verify_packet,
            base=args.base,
            tee_verify_command=args.tee_verify_command,
            expected_packet_sha256=args.expected_packet_sha256,
            expected_principal=args.expected_principal,
            expected_nonce=args.expected_nonce,
            expected_tee_verifier_identity_sha256=(
                args.expected_tee_verifier_identity_sha256
            ),
        )
        if args.emit_instructions:
            emit_instructions(verified_packet)
        else:
            emit_packet(verified_packet)
        return

    missing = [
        flag
        for flag, value in (
            ("--principal-id", args.principal_id),
            ("--proxy-url", args.proxy_url),
            ("--proxy-egress-cidr", args.proxy_egress_cidr),
        )
        if not value
    ]
    if missing:
        parser.error(f"generation mode requires {', '.join(missing)}")

    selector: dict[str, str] = {}
    for item in args.selector:
        key, sep, value = item.partition("=")
        if not sep or not key or not value:
            raise SystemExit(f"invalid --selector {item!r}; expected key=value")
        selector[key] = value

    base = args.base.rstrip("/")
    nonce = secrets.token_urlsafe(32)
    payload = {
        "principalId": args.principal_id,
        "proxyUrl": args.proxy_url,
        "controlPlaneUrl": args.control_plane_url or base,
        "proxyEgressCidrs": args.proxy_egress_cidr,
        "namespace": args.namespace,
        "podSelector": selector,
        "caMountPath": args.ca_mount_path,
        "nonce": nonce,
        "ttlSeconds": args.ttl_seconds,
    }
    request = urllib.request.Request(
        f"{base}/api/agents/enrollment",
        data=(canonical_json(payload) + "\n").encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Admin-Token": args.admin_token,
            "Authorization": f"Bearer {args.admin_token}",
        },
        method="POST",
    )
    response = request_bytes(
        request,
        timeout=15,
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
        allow_loopback_http_tokens=True,
    )
    packet = parse_json_object(
        response.body,
        label="enrollment response",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )
    attestation = request_attestation(base, nonce)
    packet["verificationReceipt"] = verify_attestation_for_packet(
        packet,
        attestation,
        nonce,
        args.tee_verify_command,
        args.expected_tee_verifier_identity_sha256,
    )
    emit_packet(packet)


def console_main() -> int:
    try:
        main()
    except (OSError, urllib.error.URLError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(console_main())
