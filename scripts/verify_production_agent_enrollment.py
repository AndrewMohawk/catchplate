#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from catchplate_agent_trust.enrollment import load_trusted_ed25519_public_key, read_file_snapshot
from catchplate_agent_trust.receipts import (
    EnrollmentReceiptExpected,
    SetupAssignment,
    canonical_json_bytes,
    parse_strict_json_object,
    sha256_digest,
    verify_agent_egress_evidence,
    verify_enrollment_verifier_receipt,
)


MAX_PACKET_BYTES = 8 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_EGRESS_EVIDENCE_BYTES = 128 * 1024
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def require_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be sha256:<64 lowercase hexadecimal characters>")
    return value


def strict_snapshot(path: Path, *, label: str, max_bytes: int) -> bytes:
    return read_file_snapshot(
        path,
        label=label,
        max_bytes=max_bytes,
        require_nofollow=True,
    )


def signed_packet_digest(packet: dict[str, Any]) -> str:
    authenticity = packet.get("authenticity")
    statement = authenticity.get("statement") if isinstance(authenticity, dict) else None
    if not isinstance(statement, dict):
        raise ValueError("production enrollment packet is missing its signed authenticity statement")
    claimed = require_digest(
        statement.get("packetSha256"), "production enrollment packet signed digest"
    )
    unsigned_packet = dict(packet)
    unsigned_packet.pop("authenticity", None)
    computed = sha256_digest(canonical_json_bytes(unsigned_packet))
    if not hmac.compare_digest(computed, claimed):
        raise ValueError("production enrollment packet content does not match its signed digest")
    statement_digest = require_digest(
        authenticity.get("statementSha256"), "production enrollment statement digest"
    )
    computed_statement_digest = sha256_digest(canonical_json_bytes(statement))
    if not hmac.compare_digest(computed_statement_digest, statement_digest):
        raise ValueError("production enrollment authenticity statement digest mismatch")
    return computed


def atomic_write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)):
        raise ValueError("production enrollment verification output must be a regular non-symlink file")
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify(args: argparse.Namespace) -> dict[str, Any]:
    assignment = SetupAssignment(
        principal_id=args.principal_id,
        route_id=args.route_id,
        credential_id=args.credential_id,
        credential_version=args.credential_version,
        policy_hash=require_digest(args.policy_hash, "expected policy hash"),
        route_policy_digest=require_digest(
            args.route_policy_digest, "expected route policy digest"
        ),
    )
    expected_assignment_digest = require_digest(
        args.expected_assignment_digest, "expected assignment digest"
    )
    if not hmac.compare_digest(assignment.digest, expected_assignment_digest):
        raise ValueError("independently supplied assignment digest does not match the expected assignment")

    packet_raw = strict_snapshot(
        args.enrollment_packet,
        label="production enrollment packet",
        max_bytes=MAX_PACKET_BYTES,
    )
    expected_packet_file_digest = require_digest(
        args.expected_enrollment_packet_file_sha256,
        "expected production enrollment packet file digest",
    )
    actual_packet_file_digest = sha256_digest(packet_raw)
    if not hmac.compare_digest(actual_packet_file_digest, expected_packet_file_digest):
        raise ValueError("production enrollment packet file digest does not match its independent precommitment")
    packet = parse_strict_json_object(
        packet_raw,
        label="production enrollment packet",
        max_bytes=MAX_PACKET_BYTES,
    )
    expected_packet_digest = require_digest(
        args.enrollment_packet_sha256, "expected signed enrollment packet digest"
    )
    computed_packet_digest = signed_packet_digest(packet)
    if not hmac.compare_digest(computed_packet_digest, expected_packet_digest):
        raise ValueError("production enrollment packet signed digest does not match the expected digest")
    if packet.get("principalId") != assignment.principal_id:
        raise ValueError("production enrollment packet principal does not match the assignment")
    authenticity = packet["authenticity"]
    if authenticity["statement"].get("principalId") != assignment.principal_id:
        raise ValueError("production enrollment signature principal does not match the assignment")
    packet_nonce = packet.get("nonce")
    if not isinstance(packet_nonce, str) or not hmac.compare_digest(
        sha256_digest(packet_nonce.encode("ascii")),
        require_digest(args.verifier_nonce_sha256, "expected verifier nonce digest"),
    ):
        raise ValueError("production enrollment packet nonce does not match the verifier nonce")
    if authenticity["statement"].get("nonce") != packet_nonce:
        raise ValueError("production enrollment signature nonce does not match the packet")
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict) or pinning.get("policyHash") != assignment.policy_hash:
        raise ValueError("production enrollment packet policy does not match the assignment")
    if authenticity["statement"].get("policyHash") != assignment.policy_hash:
        raise ValueError("production enrollment signature policy does not match the assignment")
    allowed_routes = packet.get("allowedRoutes")
    matching_routes = (
        [
            route
            for route in allowed_routes
            if isinstance(route, dict) and route.get("id") == assignment.route_id
        ]
        if isinstance(allowed_routes, list)
        else []
    )
    if (
        len(matching_routes) != 1
        or matching_routes[0].get("credentialRef") != assignment.credential_id
    ):
        raise ValueError(
            "production enrollment packet route and credential do not match the assignment"
        )
    ca = packet.get("ca")
    install_session = ca.get("installSession") if isinstance(ca, dict) else None
    if (
        not isinstance(install_session, dict)
        or install_session.get("id") != args.enrollment_session_id
    ):
        raise ValueError(
            "production enrollment packet capability does not match the enrollment session"
        )

    receipt_trust = load_trusted_ed25519_public_key(
        args.receipt_trusted_public_key,
        provider=args.receipt_provider,
    )
    expected_receipt_key_id = require_digest(
        args.expected_receipt_key_id, "expected enrollment receipt key ID"
    )
    if not secrets.compare_digest(receipt_trust.key_id, expected_receipt_key_id):
        raise ValueError("production enrollment receipt trust root does not match its expected key ID")
    expected = EnrollmentReceiptExpected(
        receipt_id=args.receipt_id,
        setup_session_id=args.setup_session_id,
        assignment=assignment,
        enrollment_session_id=args.enrollment_session_id,
        enrollment_packet_sha256=expected_packet_digest,
        verifier_nonce_sha256=require_digest(
            args.verifier_nonce_sha256, "expected verifier nonce digest"
        ),
        trust_profile_sha256=require_digest(
            args.trust_profile_sha256, "expected trust profile digest"
        ),
    )
    receipt_raw = strict_snapshot(
        args.receipt,
        label="production enrollment receipt",
        max_bytes=MAX_RECEIPT_BYTES,
    )
    receipt = verify_enrollment_verifier_receipt(
        receipt_raw,
        trust=receipt_trust,
        expected=expected,
        clock=lambda: int(time.time()),
        require_production=True,
    )

    egress_trust = load_trusted_ed25519_public_key(
        args.egress_evidence_trusted_public_key,
        provider=args.egress_evidence_provider,
    )
    expected_egress_key_id = require_digest(
        args.expected_egress_evidence_key_id, "expected launcher egress evidence key ID"
    )
    if not secrets.compare_digest(egress_trust.key_id, expected_egress_key_id):
        raise ValueError("launcher egress evidence trust root does not match its expected key ID")
    if secrets.compare_digest(receipt_trust.key_id, egress_trust.key_id):
        raise ValueError("production enrollment receipt and egress evidence must use distinct trust roots")
    egress_raw = strict_snapshot(
        args.egress_evidence,
        label="production launcher egress evidence",
        max_bytes=MAX_EGRESS_EVIDENCE_BYTES,
    )
    egress_document = parse_strict_json_object(
        egress_raw,
        label="production launcher egress evidence",
        max_bytes=MAX_EGRESS_EVIDENCE_BYTES,
    )
    if egress_raw != canonical_json_bytes(egress_document):
        raise ValueError("production launcher egress evidence must use exact canonical JSON bytes")
    egress = verify_agent_egress_evidence(
        egress_raw,
        trust=egress_trust,
        packet=packet,
        enrollment_session_id=args.enrollment_session_id,
        allow_development_fixture=False,
    )
    receipt_egress = dict(receipt.egress_evidence)
    if egress.as_receipt_binding() != receipt_egress:
        raise ValueError("production receipt does not bind the supplied launcher egress evidence exactly")

    return {
        "apiVersion": "catchplate.productionAgentEnrollmentVerification/v1",
        "kind": "ProductionAgentEnrollmentVerification",
        "ok": True,
        "verifiedAtUnix": int(time.time()),
        "receiptId": receipt.receipt_id,
        "receiptSha256": receipt.receipt_sha256,
        "receiptKeyId": receipt.verifier_key_id,
        "receiptProvider": receipt.verifier_provider,
        "setupSessionId": receipt.setup_session_id,
        "enrollmentSessionId": receipt.enrollment_session_id,
        "assignmentDigest": assignment.digest,
        "enrollmentPacketSha256": receipt.enrollment_packet_sha256,
        "enrollmentPacketFileSha256": actual_packet_file_digest,
        "attestationEvidenceSha256": sha256_digest(
            canonical_json_bytes(dict(receipt.attestation_evidence))
        ),
        "egressEvidenceId": egress.evidence_id,
        "egressEvidenceSha256": egress.evidence_sha256,
        "egressEvidenceKeyId": egress.evidence_key_id,
        "egressEvidenceProvider": egress.evidence_provider,
        "networkNamespaceSha256": egress.network_namespace_sha256,
        "firewallStateSha256": egress.firewall_state_sha256,
        "assuranceMode": receipt.assurance_mode,
        "decision": receipt.decision,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify externally supplied production v3 enrollment and launcher egress evidence."
    )
    parser.add_argument("--enrollment-packet", type=Path, required=True)
    parser.add_argument("--expected-enrollment-packet-file-sha256", required=True)
    parser.add_argument("--enrollment-packet-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-trusted-public-key", type=Path, required=True)
    parser.add_argument("--receipt-provider", required=True)
    parser.add_argument("--expected-receipt-key-id", required=True)
    parser.add_argument("--egress-evidence", type=Path, required=True)
    parser.add_argument("--egress-evidence-trusted-public-key", type=Path, required=True)
    parser.add_argument("--egress-evidence-provider", required=True)
    parser.add_argument("--expected-egress-evidence-key-id", required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--setup-session-id", required=True)
    parser.add_argument("--enrollment-session-id", required=True)
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--credential-id", required=True)
    parser.add_argument("--credential-version", type=int, required=True)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--route-policy-digest", required=True)
    parser.add_argument("--expected-assignment-digest", required=True)
    parser.add_argument("--verifier-nonce-sha256", required=True)
    parser.add_argument("--trust-profile-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = verify(args)
        atomic_write_private(args.out, result)
        print(canonical_json_bytes(result).decode("ascii"))
    except Exception as exc:
        print(
            canonical_json_bytes({"ok": False, "error": str(exc)}).decode("ascii"),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
