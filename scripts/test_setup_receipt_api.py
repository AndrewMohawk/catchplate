#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.requests import Request


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from catchplate.setup_receipts import (  # noqa: E402
    ENROLLMENT_CHECKS,
    HARDWARE_CHECKS,
    Ed25519TrustRoot,
    SetupAssignment,
    canonical_base64url,
    canonical_json_bytes,
    sha256_digest,
)


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def trust_fixture(
    seed: int, provider: str
) -> tuple[Ed25519PrivateKey, Ed25519TrustRoot]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, Ed25519TrustRoot(provider, public_der)


def signed_document(
    *,
    api_version: str,
    kind: str,
    statement: dict[str, Any],
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
    claimed_key_id: str | None = None,
) -> dict[str, Any]:
    return {
        "apiVersion": api_version,
        "kind": kind,
        "statement": statement,
        "signing_key_id": claimed_key_id or trust.key_id,
        "signature": "ed25519:"
        + canonical_base64url(private_key.sign(canonical_json_bytes(statement))),
    }


def encoded_document(document: dict[str, Any]) -> str:
    return b64url(canonical_json_bytes(document))


def json_request(raw: bytes) -> Request:
    consumed = False

    async def receive() -> dict[str, Any]:
        nonlocal consumed
        if consumed:
            return {"type": "http.request", "body": b"", "more_body": False}
        consumed = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 12345),
            "server": ("catchplate.test", 443),
        },
        receive,
    )


def envelope_request(payload: dict[str, Any]) -> Request:
    return json_request(canonical_json_bytes(payload))


def expect_http_error(
    http_exception: type[BaseException],
    status_code: int,
    callback: Callable[[], Any],
    *,
    detail_contains: str | None = None,
) -> BaseException:
    try:
        callback()
    except http_exception as exc:
        actual_status = getattr(exc, "status_code", None)
        if actual_status != status_code:
            raise AssertionError(
                f"expected HTTP {status_code}, received {actual_status}: {exc}"
            ) from exc
        detail = getattr(exc, "detail", None)
        if detail_contains is not None and detail_contains not in str(detail):
            raise AssertionError(
                f"HTTP {status_code} detail did not contain {detail_contains!r}: {detail!r}"
            ) from exc
        return exc
    raise AssertionError(f"expected HTTP {status_code}")


def evidence(kind: str, label: str) -> list[dict[str, Any]]:
    return [
        {
            "kind": kind,
            "document": {
                "kind": "CatchplateSetupRuntimeEvidence",
                "result": "verified",
                "subject": label,
            },
            "verifier_key_id": "runtime-verifier:test",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
    ]


def advance_to_enrollment(
    db: Any,
    *,
    owner_id: str,
    assignment: SetupAssignment,
    label: str,
) -> dict[str, Any]:
    session = db.create_setup_session(
        owner_id=owner_id,
        current_assignee_id=owner_id,
        template_id=f"template:{label}",
        principal_id=assignment.principal_id,
        route_id=assignment.route_id,
        route_policy_digest=assignment.route_policy_digest,
        actor_id=owner_id,
    )
    session = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_credential",
        actor_id=owner_id,
        updates={
            "credential_id": assignment.credential_id,
            "credential_version": assignment.credential_version,
            "route_policy_digest": assignment.route_policy_digest,
        },
    )
    session = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_candidate",
        actor_id=owner_id,
        updates={
            "policy_hash": assignment.policy_hash,
            "assignment_digest": assignment.digest,
            "canary_id": f"canary:{label}",
            "route_policy_digest": assignment.route_policy_digest,
        },
    )
    session = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="activate_policy",
        actor_id=owner_id,
    )
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_enrollment",
        actor_id=owner_id,
        updates={
            "enrollment_session_id": str(uuid.uuid4()),
            "enrollment_packet_digest": digest(f"{label}:enrollment-packet"),
            "verifier_nonce_hash": digest(f"{label}:verifier-nonce"),
        },
    )


def enrollment_receipt(
    *,
    session: dict[str, Any],
    assignment: SetupAssignment,
    now: int,
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
    trust_profile_digest: str,
    expires_at: int | None = None,
    claimed_key_id: str | None = None,
) -> dict[str, Any]:
    statement = {
        "receipt_id": str(uuid.uuid4()),
        "setup_session_id": session["id"],
        "assignment": assignment.as_document(),
        "assignment_digest": assignment.digest,
        "enrollment_session_id": session["enrollment_session_id"],
        "enrollment_packet_sha256": session["enrollment_packet_digest"],
        "verifier_nonce_sha256": session["verifier_nonce_hash"],
        "trust_profile_sha256": trust_profile_digest,
        "verifier_provider": trust.provider,
        "decision": "verified",
        "checks": list(ENROLLMENT_CHECKS),
        "issued_at_unix": now - 5,
        "expires_at_unix": expires_at if expires_at is not None else now + 300,
    }
    return signed_document(
        api_version="catchplate.enrollmentVerifierReceipt/v2",
        kind="EnrollmentVerifierReceipt",
        statement=statement,
        private_key=private_key,
        trust=trust,
        claimed_key_id=claimed_key_id,
    )


def hardware_assurance(
    *,
    challenge: bytes,
    now: int,
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
    release_identity_digest: str,
    host_identity_digest: str,
) -> dict[str, Any]:
    statement = {
        "verifier": {
            "name": "setup-api-independent-verifier",
            "organization": "Catchplate test assurance lab",
            "independent": True,
        },
        "issued_at_unix": now,
        "expires_at_unix": now + 300,
        "challenge_nonce": canonical_base64url(challenge),
        "current_host_identity": {
            "scheme": "catchplate.currentHostIdentity/v1",
            "machine_id_sha256": digest("machine-id"),
            "product_uuid_sha256": digest("product-uuid"),
            "boot_id_sha256": digest("boot-id"),
            "identity_sha256": host_identity_digest,
            "observed_at_unix": now,
        },
        "attestation_document_sha256": digest("attestation-document"),
        "eif": {
            "image_sha384": "sha384:" + "1" * 96,
            "build_manifest": {
                "apiVersion": "catchplate.eifBuildManifest/v1",
                "release_identity_sha256": release_identity_digest,
            },
            "build_manifest_sha256": digest("build-manifest"),
            "signature_verified": True,
            "evidence_sha256": digest("eif-evidence"),
        },
        "pcrs": {
            "PCR0": "sha384:" + "2" * 96,
            "PCR1": "sha384:" + "3" * 96,
            "PCR2": "sha384:" + "4" * 96,
        },
        "enclave": {
            "cid": 16,
            "parent_cid": 3,
            "vsock_port": 5000,
            "cid_evidence_sha256": digest("cid-evidence"),
            "vsock_evidence_sha256": digest("vsock-evidence"),
            "vsock_handshake_verified": True,
        },
        "key_custody": {
            "recipient_key_generated_in_enclave": True,
            "kms_recipient_bound": True,
            "plaintext_key_exported": False,
            "parent_process_key_access": False,
            "kms_recipient_bindings_sha256": digest("kms-recipient-bindings"),
            "evidence_sha256": digest("key-custody-evidence"),
        },
        "no_parent_key": {
            "verified": True,
            "parent_key_material_absent": True,
            "evidence_sha256": digest("no-parent-key-evidence"),
        },
        "release_bindings": {"release_identity_sha256": release_identity_digest},
        "artifact_bindings": {
            "nitro_evidence_sha256": digest("nitro-evidence"),
            "production_host_preflight_sha256": digest("host-preflight"),
        },
    }
    return signed_document(
        api_version="catchplate.hardwareAssurance/v1",
        kind="CatchplateHardwareAssurance",
        statement=statement,
        private_key=private_key,
        trust=trust,
    )


def hardware_verification_receipt(
    *,
    session: dict[str, Any],
    assignment: SetupAssignment,
    challenge: bytes,
    assurance: dict[str, Any],
    proxy_statement_digest: str,
    trust_profile_digest: str,
    now: int,
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
) -> dict[str, Any]:
    assurance_statement = assurance["statement"]
    statement = {
        "receipt_id": str(uuid.uuid4()),
        "setup_session_id": session["id"],
        "assignment": assignment.as_document(),
        "assignment_digest": assignment.digest,
        "runtime_evidence_sha256": session["runtime_evidence_digest"],
        "challenge": canonical_base64url(challenge),
        "challenge_sha256": sha256_digest(challenge),
        "hardware_assurance_sha256": sha256_digest(canonical_json_bytes(assurance)),
        "hardware_statement_sha256": sha256_digest(
            canonical_json_bytes(assurance_statement)
        ),
        "hardware_verifier_provider": trust.provider,
        "hardware_verifier_key_id": trust.key_id,
        "release_identity_sha256": assurance_statement["eif"]["build_manifest"][
            "release_identity_sha256"
        ],
        "current_host_identity_sha256": assurance_statement["current_host_identity"][
            "identity_sha256"
        ],
        "proxy_server_statement_sha256": proxy_statement_digest,
        "trust_profile_sha256": trust_profile_digest,
        "decision": "verified",
        "checks": list(HARDWARE_CHECKS),
        "issued_at_unix": now,
        "expires_at_unix": now + 300,
    }
    return signed_document(
        api_version="catchplate.setupHardwareVerification/v1",
        kind="SetupHardwareVerification",
        statement=statement,
        private_key=private_key,
        trust=trust,
    )


def final_receipt(
    *,
    completion_identity: dict[str, Any],
    challenge_digest: str,
    release_identity_digest: str,
    hardware_key_id: str,
    host_identity_digest: str,
    proxy_statement_digest: str,
    now: int,
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
    completion_digest: str | None = None,
) -> dict[str, Any]:
    statement = {
        "authority_provider": trust.provider,
        "consumption_id": "consumption:setup-api:" + uuid.uuid4().hex,
        "status": "consumed",
        "issued_at_unix": now,
        "expires_at_unix": now + 300,
        "challenge_nonce_sha256": challenge_digest,
        "completion_identity_sha256": completion_digest
        or completion_identity["sha256"],
        "release_identity_sha256": release_identity_digest,
        "hardware_verifier_key_id": hardware_key_id,
        "current_host_identity_sha256": host_identity_digest,
        "proxy_server_statement_sha256": proxy_statement_digest,
    }
    return signed_document(
        api_version="catchplate.finalChallengeReceipt/v1",
        kind="FinalChallengeConsumption",
        statement=statement,
        private_key=private_key,
        trust=trust,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="catchplate-setup-receipt-api-") as tmp:
        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
        os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["CATCHPLATE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "0"
        os.environ["CATCHPLATE_CONTROL_PLANE_TWO_PERSON_REQUIRED"] = "0"
        for name in (
            "CATCHPLATE_METADATA_STORE_POSTGRES_DSN",
            "CATCHPLATE_GRANT_STORE_POSTGRES_DSN",
            "CATCHPLATE_AUDIT_STORE_POSTGRES_DSN",
        ):
            os.environ.pop(name, None)

        from fastapi import HTTPException

        from catchplate import app as app_module
        from catchplate import db
        from catchplate.auth import AdminIdentity
        from catchplate.setup_receipt_service import build_setup_receipt_trust_profile

        enrollment_key, enrollment_trust = trust_fixture(
            11, "independent-enrollment-verifier"
        )
        hardware_key, hardware_trust = trust_fixture(
            12, "independent-hardware-verifier"
        )
        final_key, final_trust = trust_fixture(13, "off-host-final-authority")
        profile = build_setup_receipt_trust_profile(
            enrollment_verifier=enrollment_trust,
            hardware_verifier=hardware_trust,
            final_authority=final_trust,
        )

        operator = AdminIdentity(
            "user:setup-receipt-operator",
            frozenset({"attestation_operator"}),
            "test",
        )
        reviewer = AdminIdentity(
            operator.user_id,
            frozenset({"attestation_reviewer"}),
            "test",
        )
        wrong_assignee = AdminIdentity(
            "user:wrong-assignee",
            frozenset({"admin", "attestation_operator", "attestation_reviewer"}),
            "test",
        )
        assignment = SetupAssignment(
            principal_id="agent:setup-receipt-api",
            route_id="route.gmail.read",
            credential_id="credential:google-primary",
            credential_version=7,
            policy_hash=digest("policy"),
            route_policy_digest=digest("route-policy"),
        )

        original_profile = app_module.setup_receipt_trust_profile
        original_consumed_check = (
            app_module._setup_enrollment_is_authoritatively_consumed
        )
        original_two_person_required = app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED
        original_two_person_actions = app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS
        app_module.setup_receipt_trust_profile = lambda: profile
        app_module._setup_enrollment_is_authoritatively_consumed = lambda _item: None
        try:
            db.init_db()
            trust_response = app_module.setup_receipt_trust(_=operator)
            if trust_response != {
                "apiVersion": "catchplate.setupReceiptTrustProfile/v1",
                "digest": profile.digest,
                "enrollmentVerifier": {
                    "provider": enrollment_trust.provider,
                    "keyId": enrollment_trust.key_id,
                },
                "hardwareVerifier": {
                    "provider": hardware_trust.provider,
                    "keyId": hardware_trust.key_id,
                },
                "finalAuthority": {
                    "provider": final_trust.provider,
                    "keyId": final_trust.key_id,
                },
            }:
                raise AssertionError(
                    f"receipt trust endpoint returned the wrong profile: {trust_response}"
                )

            now = int(time.time())
            session = advance_to_enrollment(
                db,
                owner_id=operator.user_id,
                assignment=assignment,
                label="primary",
            )
            valid_enrollment = enrollment_receipt(
                session=session,
                assignment=assignment,
                now=now,
                private_key=enrollment_key,
                trust=enrollment_trust,
                trust_profile_digest=profile.digest,
            )
            enrollment_payload = {
                "expectedRevision": session["revision"],
                "receipt": encoded_document(valid_enrollment),
            }

            expect_http_error(
                HTTPException,
                403,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"],
                        envelope_request(enrollment_payload),
                        identity=wrong_assignee,
                    )
                ),
                detail_contains="current assignee",
            )
            duplicate_raw = (
                '{"expectedRevision":%d,"expectedRevision":%d,"receipt":"%s"}'
                % (
                    session["revision"],
                    session["revision"],
                    encoded_document(valid_enrollment),
                )
            ).encode("ascii")
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"],
                        json_request(duplicate_raw),
                        identity=operator,
                    )
                ),
                detail_contains="invalid_json",
            )
            float_raw = (
                '{"expectedRevision":%d.0,"receipt":"%s"}'
                % (session["revision"], encoded_document(valid_enrollment))
            ).encode("ascii")
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"], json_request(float_raw), identity=operator
                    )
                ),
                detail_contains="invalid_json",
            )

            forged_enrollment = enrollment_receipt(
                session=session,
                assignment=assignment,
                now=now,
                private_key=hardware_key,
                trust=enrollment_trust,
                trust_profile_digest=profile.digest,
                claimed_key_id=enrollment_trust.key_id,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"],
                                "receipt": encoded_document(forged_enrollment),
                            }
                        ),
                        identity=operator,
                    )
                ),
                detail_contains="invalid_signature",
            )
            expired_enrollment = enrollment_receipt(
                session=session,
                assignment=assignment,
                now=now,
                private_key=enrollment_key,
                trust=enrollment_trust,
                trust_profile_digest=profile.digest,
                expires_at=now - 1,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"],
                                "receipt": encoded_document(expired_enrollment),
                            }
                        ),
                        identity=operator,
                    )
                ),
                detail_contains="invalid_time",
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"] - 1,
                                "receipt": encoded_document(valid_enrollment),
                            }
                        ),
                        identity=operator,
                    )
                ),
                detail_contains="setup_session_stale_revision",
            )
            if db.get_setup_session(session["id"])["revision"] != session["revision"]:
                raise AssertionError(
                    "rejected enrollment receipts mutated the setup session"
                )

            enrollment_response = asyncio.run(
                app_module.setup_session_enrollment_receipt(
                    session["id"],
                    envelope_request(enrollment_payload),
                    identity=operator,
                )
            )
            if enrollment_response["session"]["phase"] != "ca_installed":
                raise AssertionError(
                    f"enrollment receipt did not install the CA: {enrollment_response}"
                )
            session = db.get_setup_session(session["id"], include_evidence=True)
            if not (
                session["enrollment_verifier_key_id"] == enrollment_trust.key_id
                and session["enrollment_verifier_receipt_digest"]
                and len(session["evidence"]) == 1
            ):
                raise AssertionError("enrollment receipt bindings were not persisted")

            replay_session = advance_to_enrollment(
                db,
                owner_id=operator.user_id,
                assignment=assignment,
                label="cross-session-replay",
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_enrollment_receipt(
                        replay_session["id"],
                        envelope_request(
                            {
                                "expectedRevision": replay_session["revision"],
                                "receipt": encoded_document(valid_enrollment),
                            }
                        ),
                        identity=operator,
                    )
                ),
                detail_contains="binding_mismatch",
            )
            if (
                db.get_setup_session(replay_session["id"])["phase"]
                != "enrollment_issued"
            ):
                raise AssertionError(
                    "cross-session receipt replay changed the target session"
                )

            session = db.transition_setup_session(
                session["id"],
                expected_revision=session["revision"],
                transition="record_canary_evidence",
                actor_id=operator.user_id,
                evidence=evidence("canary_result", "primary-canary"),
            )
            session = db.transition_setup_session(
                session["id"],
                expected_revision=session["revision"],
                transition="record_runtime_evidence",
                actor_id=operator.user_id,
                evidence=evidence("runtime_verification", "primary-runtime"),
            )
            challenge_response = app_module.setup_session_attestation_challenge(
                session["id"],
                app_module.SetupSessionRevisionRequest(
                    expectedRevision=session["revision"]
                ),
                identity=operator,
            )
            if challenge_response["session"]["phase"] != "runtime_verified":
                raise AssertionError("issuing a challenge changed the runtime phase")
            challenge = base64.urlsafe_b64decode(
                challenge_response["challenge"]["value"]
                + "=" * (-len(challenge_response["challenge"]["value"]) % 4)
            )
            if not (
                len(challenge) == 32
                and challenge_response["challenge"]["sha256"]
                == sha256_digest(challenge)
                and challenge_response["challenge"]["trustProfileDigest"]
                == profile.digest
            ):
                raise AssertionError(
                    f"attestation challenge response was not exact: {challenge_response}"
                )

            retry_response = app_module.setup_session_attestation_challenge(
                session["id"],
                app_module.SetupSessionRevisionRequest(
                    expectedRevision=challenge_response["session"]["revision"]
                ),
                identity=operator,
            )
            if not (
                retry_response["challenge"] == challenge_response["challenge"]
                and retry_response["session"]["revision"]
                == challenge_response["session"]["revision"]
                and retry_response["audit"]
                == {"claimed": 0, "audited": 0, "failed": 0}
            ):
                raise AssertionError(
                    "retrying an unexpired challenge was not idempotent"
                )

            session = db.get_setup_session(session["id"], include_evidence=True)
            release_identity_digest = digest("release-identity")
            host_identity_digest = digest("current-host-identity")
            proxy_statement = canonical_json_bytes(
                {"apiVersion": "catchplate.testProxyResponseStatement/v1"}
            )
            proxy_statement_digest = sha256_digest(proxy_statement)
            wrong_assurance = hardware_assurance(
                challenge=b"w" * 32,
                now=now,
                private_key=hardware_key,
                trust=hardware_trust,
                release_identity_digest=release_identity_digest,
                host_identity_digest=host_identity_digest,
            )
            wrong_hardware = hardware_verification_receipt(
                session=session,
                assignment=assignment,
                challenge=b"w" * 32,
                assurance=wrong_assurance,
                proxy_statement_digest=proxy_statement_digest,
                trust_profile_digest=profile.digest,
                now=now,
                private_key=hardware_key,
                trust=hardware_trust,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_hardware_verification(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"],
                                "hardwareAssurance": encoded_document(wrong_assurance),
                                "proxyServerStatement": b64url(proxy_statement),
                                "receipt": encoded_document(wrong_hardware),
                            }
                        ),
                        identity=operator,
                    )
                ),
                detail_contains="challenge does not match",
            )

            assurance = hardware_assurance(
                challenge=challenge,
                now=now,
                private_key=hardware_key,
                trust=hardware_trust,
                release_identity_digest=release_identity_digest,
                host_identity_digest=host_identity_digest,
            )
            hardware_receipt = hardware_verification_receipt(
                session=session,
                assignment=assignment,
                challenge=challenge,
                assurance=assurance,
                proxy_statement_digest=proxy_statement_digest,
                trust_profile_digest=profile.digest,
                now=now,
                private_key=hardware_key,
                trust=hardware_trust,
            )
            hardware_response = asyncio.run(
                app_module.setup_session_hardware_verification(
                    session["id"],
                    envelope_request(
                        {
                            "expectedRevision": session["revision"],
                            "hardwareAssurance": encoded_document(assurance),
                            "proxyServerStatement": b64url(proxy_statement),
                            "receipt": encoded_document(hardware_receipt),
                        }
                    ),
                    identity=operator,
                )
            )
            if hardware_response["session"]["phase"] != "hardware_verified":
                raise AssertionError(
                    f"hardware receipt did not verify the setup: {hardware_response}"
                )
            completion_identity = hardware_response["completionIdentity"]
            session = db.get_setup_session(
                session["id"], include_evidence=True, include_events=True
            )
            if not (
                session["hardware_verifier_key_id"] == hardware_trust.key_id
                and session["hardware_assurance_digest"]
                == sha256_digest(canonical_json_bytes(assurance))
                and session["hardware_verification_receipt_digest"]
                == sha256_digest(canonical_json_bytes(hardware_receipt))
                and session["trust_profile_digest"] == profile.digest
            ):
                raise AssertionError(
                    "hardware verification bindings were not persisted"
                )
            hardware_evidence = next(
                item
                for item in session["evidence"]
                if item["kind"] == "hardware_assurance"
            )["document"]
            stored_assurance = base64.urlsafe_b64decode(
                hardware_evidence["hardwareAssuranceBase64url"]
                + "="
                * (-len(hardware_evidence["hardwareAssuranceBase64url"]) % 4)
            )
            stored_proxy_statement = base64.urlsafe_b64decode(
                hardware_evidence["proxyServerStatementBase64url"]
                + "="
                * (-len(hardware_evidence["proxyServerStatementBase64url"]) % 4)
            )
            if not (
                stored_assurance == canonical_json_bytes(assurance)
                and stored_proxy_statement == proxy_statement
                and hardware_evidence["hardwareAssuranceSha256"]
                == sha256_digest(stored_assurance)
                and hardware_evidence["proxyServerStatementSha256"]
                == sha256_digest(stored_proxy_statement)
                and hardware_evidence["verificationReceipt"] == hardware_receipt
            ):
                raise AssertionError(
                    "hardware evidence did not retain the exact verified artifacts"
                )

            wrong_final = final_receipt(
                completion_identity=completion_identity,
                challenge_digest=sha256_digest(challenge),
                release_identity_digest=release_identity_digest,
                hardware_key_id=hardware_trust.key_id,
                host_identity_digest=host_identity_digest,
                proxy_statement_digest=proxy_statement_digest,
                now=now,
                private_key=final_key,
                trust=final_trust,
                completion_digest=digest("wrong-completion-identity"),
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: asyncio.run(
                    app_module.setup_session_final_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"],
                                "receipt": encoded_document(wrong_final),
                            }
                        ),
                        identity=reviewer,
                    )
                ),
                detail_contains="binding_mismatch",
            )
            valid_final = final_receipt(
                completion_identity=completion_identity,
                challenge_digest=sha256_digest(challenge),
                release_identity_digest=release_identity_digest,
                hardware_key_id=hardware_trust.key_id,
                host_identity_digest=host_identity_digest,
                proxy_statement_digest=proxy_statement_digest,
                now=now,
                private_key=final_key,
                trust=final_trust,
            )
            app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = True
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = (
                "setup.attestation.finalize",
            )
            approval_required = expect_http_error(
                HTTPException,
                428,
                lambda: asyncio.run(
                    app_module.setup_session_final_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": session["revision"],
                                "receipt": encoded_document(valid_final),
                            }
                        ),
                        identity=reviewer,
                    )
                ),
                detail_contains="control_plane_approval_required",
            )
            approval_id = approval_required.detail["approvalId"]
            approval = db.approve_control_plane_approval(
                approval_id, actor_id="user:independent-attestation-reviewer"
            )
            if not approval or approval["status"] != "approved":
                raise AssertionError("final receipt approval was not approved")
            original_insert_setup_event = db._insert_setup_event

            def fail_final_transition(*_args: Any, **_kwargs: Any) -> None:
                raise RuntimeError("injected final transition failure")

            db._insert_setup_event = fail_final_transition
            try:
                try:
                    asyncio.run(
                        app_module.setup_session_final_receipt(
                            session["id"],
                            envelope_request(
                                {
                                    "expectedRevision": session["revision"],
                                    "receipt": encoded_document(valid_final),
                                    "mfa": {"approvalId": approval_id},
                                }
                            ),
                            identity=reviewer,
                        )
                    )
                except RuntimeError as exc:
                    if str(exc) != "injected final transition failure":
                        raise
                else:
                    raise AssertionError("injected final transition failure was ignored")
            finally:
                db._insert_setup_event = original_insert_setup_event
            approval_after_failure = db.get_control_plane_approval(approval_id)
            session_after_failure = db.get_setup_session(session["id"])
            if not (
                approval_after_failure
                and approval_after_failure["status"] == "approved"
                and session_after_failure
                and session_after_failure["phase"] == "hardware_verified"
                and session_after_failure["revision"] == session["revision"]
            ):
                raise AssertionError(
                    "final receipt approval consumption and setup transition did not roll back together"
                )
            final_response = asyncio.run(
                app_module.setup_session_final_receipt(
                    session["id"],
                    envelope_request(
                        {
                            "expectedRevision": session["revision"],
                            "receipt": encoded_document(valid_final),
                            "mfa": {"approvalId": approval_id},
                        }
                    ),
                    identity=reviewer,
                )
            )
            if final_response["session"]["phase"] != "completion_pending_audit":
                raise AssertionError(
                    "the accepted final receipt skipped the audit-pending phase"
                )
            for _attempt in range(16):
                if final_response["session"]["phase"] == "complete":
                    break
                final_response = asyncio.run(
                    app_module.setup_session_final_receipt(
                        session["id"],
                        envelope_request(
                            {
                                "expectedRevision": final_response["session"][
                                    "revision"
                                ],
                                "receipt": encoded_document(valid_final),
                            }
                        ),
                        identity=reviewer,
                    )
                )
            if not (
                final_response["session"]["phase"] == "complete"
                and final_response["session"]["status"] == "complete"
                and final_response["completionIdentity"]["sha256"]
                == completion_identity["sha256"]
                and final_response["finalReceipt"]["authorityKeyId"]
                == final_trust.key_id
            ):
                raise AssertionError(
                    f"final receipt did not complete the setup: {final_response}"
                )
            completed = db.get_setup_session(
                session["id"], include_evidence=True, include_events=True
            )
            final_transitions = [
                item["transition"]
                for item in completed["events"]
                if item["transition"]
                in {"record_final_challenge_receipt", "system_complete"}
            ]
            if final_transitions != [
                "record_final_challenge_receipt",
                "system_complete",
            ]:
                raise AssertionError(
                    "final setup did not traverse completion_pending_audit before complete"
                )
            final_event = next(
                item
                for item in completed["events"]
                if item["transition"] == "record_final_challenge_receipt"
            )
            if not (
                final_event["event"]["to_phase"] == "completion_pending_audit"
                and final_event["audit_status"] == "audited"
                and completed["final_authority_key_id"] == final_trust.key_id
                and completed["final_receipt_digest"]
            ):
                raise AssertionError("final receipt was not audit-gated and persisted")
        finally:
            app_module.setup_receipt_trust_profile = original_profile
            app_module._setup_enrollment_is_authoritatively_consumed = (
                original_consumed_check
            )
            app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = (
                original_two_person_required
            )
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = original_two_person_actions

    print(json.dumps({"ok": True, "setup_receipt_api": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
