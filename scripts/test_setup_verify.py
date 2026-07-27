#!/usr/bin/env python3
from __future__ import annotations

import copy
import base64
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

NONCE = "setup-verification-nonce-0123456789abcdef"
PRINCIPAL_ID = "agent:demo"
ROUTE_ID = "demo.echo"
SCOPE = "scope.read"
PROVIDER_SUBJECT = "google-subject-setup-verification"
ACCESS_TOKEN = "setup-access-token-must-never-be-disclosed"
REFRESH_TOKEN = "setup-refresh-token-must-never-be-disclosed"
ADMIN_TOKEN = "setup-verification-admin-token"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def check_by_id(result: dict[str, Any], check_id: str) -> dict[str, Any]:
    matches = [item for item in result.get("checks", []) if item.get("id") == check_id]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {check_id!r} check, found {matches}")
    return matches[0]


def assert_check(result: dict[str, Any], check_id: str, status: str) -> None:
    check = check_by_id(result, check_id)
    if check.get("status") != status:
        raise AssertionError(f"{check_id} was {check.get('status')!r}, expected {status!r}: {check}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-setup-verify-") as tmp:
        data_dir = Path(tmp)
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(data_dir / "policy-bundle.json")
        os.environ["SERVERWARE_POLICY_SIGNING_KEY"] = str(data_dir / "policy-signing-ed25519.pem")
        os.environ["SERVERWARE_POLICY_SIGNING_PUBLIC_KEY"] = str(data_dir / "policy-signing-ed25519.pub.pem")
        os.environ["SERVERWARE_ADMIN_TOKEN"] = ADMIN_TOKEN
        os.environ["SERVERWARE_ADMIN_USER"] = "user:setup-verifier"
        os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        for name in (
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
            "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        ):
            os.environ.pop(name, None)

        from pydantic import ValidationError
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from serverware import app as app_module
        from serverware import db
        from serverware.auth import AdminIdentity
        from serverware.policy_bundle import (
            PolicyBundleError,
            compile_policy_bundle,
            demo_policy_bundle,
            write_policy_bundle,
        )
        from serverware.setup_receipts import (
            Ed25519TrustRoot,
            EnrollmentReceiptExpected,
            ReceiptVerificationError,
            SetupAssignment,
            canonical_json_bytes,
        )

        receipt_key = Ed25519PrivateKey.generate()
        receipt_trust = Ed25519TrustRoot(
            "production-enrollment-verifier",
            receipt_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        receipt_assignment = SetupAssignment(
            principal_id="agent:setup-receipt-test",
            route_id="route.setup-receipt-test",
            credential_id="credential.setup-receipt-test",
            credential_version=1,
            policy_hash="sha256:" + "1" * 64,
            route_policy_digest="sha256:" + "2" * 64,
        )
        receipt_expected = EnrollmentReceiptExpected(
            receipt_id=str(uuid.uuid4()),
            setup_session_id=str(uuid.uuid4()),
            assignment=receipt_assignment,
            enrollment_session_id=str(uuid.uuid4()),
            enrollment_packet_sha256="sha256:" + "3" * 64,
            verifier_nonce_sha256="sha256:" + "4" * 64,
            trust_profile_sha256="sha256:" + "5" * 64,
        )
        receipt_now = int(time.time())
        receipt_statement: dict[str, Any] = {
            "receipt_id": receipt_expected.receipt_id,
            "setup_session_id": receipt_expected.setup_session_id,
            "assignment": receipt_assignment.as_document(),
            "assignment_digest": receipt_assignment.digest,
            "enrollment_session_id": receipt_expected.enrollment_session_id,
            "enrollment_packet_sha256": receipt_expected.enrollment_packet_sha256,
            "verifier_nonce_sha256": receipt_expected.verifier_nonce_sha256,
            "trust_profile_sha256": receipt_expected.trust_profile_sha256,
            "verifier_provider": receipt_trust.provider,
            "assurance_mode": "production",
            "attestation_evidence": {
                "quote_provider": "aws-nitro-enclaves",
                "quote_sha256": "sha256:" + "6" * 64,
                "verified_claims_sha256": "sha256:" + "7" * 64,
                "verifier_identity_sha256": "sha256:" + "8" * 64,
                "self_rooted": False,
                "debug": False,
                "assurance": {
                    "class": "hardware-backed",
                    "debug": False,
                    "hardware_proof": True,
                    "workload_custody_proven": True,
                    "tls_peer_binding_proven": True,
                    "fact_origin": "independent-verifier",
                    "completion_eligible": True,
                },
            },
            "egress_evidence": {
                "evidence_id": str(uuid.uuid4()),
                "evidence_sha256": "sha256:" + "9" * 64,
                "evidence_mode": "production-launcher",
                "evidence_provider": "measured-agent-launcher",
                "evidence_key_id": "sha256:" + "a" * 64,
                "network_namespace_sha256": "sha256:" + "b" * 64,
                "firewall_state_sha256": "sha256:" + "c" * 64,
                "allow_results_sha256": "sha256:" + "d" * 64,
                "deny_result_sha256": "sha256:" + "e" * 64,
                "observed_at_unix": receipt_now,
            },
            "decision": "verified",
            "checks": list(app_module._ENROLLMENT_RECEIPT_V3_CHECKS),
            "issued_at_unix": receipt_now,
            "expires_at_unix": receipt_now + 300,
        }

        def signed_v3(statement: dict[str, Any]) -> bytes:
            signature = receipt_key.sign(canonical_json_bytes(statement))
            return canonical_json_bytes(
                {
                    "apiVersion": app_module._ENROLLMENT_RECEIPT_V3,
                    "kind": "EnrollmentVerifierReceipt",
                    "statement": statement,
                    "signing_key_id": receipt_trust.key_id,
                    "signature": "ed25519:"
                    + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
                }
            )

        original_release_channel = app_module.RELEASE_CHANNEL
        app_module.RELEASE_CHANNEL = "prod"
        try:
            verified_v3 = app_module._verify_setup_enrollment_receipt(
                signed_v3(receipt_statement),
                trust=receipt_trust,
                expected=receipt_expected,
                clock=lambda: receipt_now,
            )
            if verified_v3.receipt_id != receipt_expected.receipt_id:
                raise AssertionError("production v3 enrollment receipt lost its receipt binding")
            dev_statement = copy.deepcopy(receipt_statement)
            dev_statement["attestation_evidence"]["quote_provider"] = "dev-signed-quote"
            try:
                app_module._verify_setup_enrollment_receipt(
                    signed_v3(dev_statement),
                    trust=receipt_trust,
                    expected=receipt_expected,
                    clock=lambda: receipt_now,
                )
            except ReceiptVerificationError:
                pass
            else:
                raise AssertionError("production setup accepted a dev-signed quote receipt")
            try:
                app_module._verify_setup_enrollment_receipt(
                    canonical_json_bytes(
                        {
                            "apiVersion": "serverware.enrollmentVerifierReceipt/v2",
                            "kind": "EnrollmentVerifierReceipt",
                        }
                    ),
                    trust=receipt_trust,
                    expected=receipt_expected,
                    clock=lambda: receipt_now,
                )
            except ReceiptVerificationError:
                pass
            else:
                raise AssertionError("production setup accepted a legacy v2 enrollment receipt")
        finally:
            app_module.RELEASE_CHANNEL = original_release_channel

        db.init_db()
        oauth_secret = canonical_json(
            {
                "access_token": ACCESS_TOKEN,
                "refresh_token": REFRESH_TOKEN,
                "token_type": "Bearer",
                "scope": SCOPE,
            }
        )
        oauth_metadata = {
            "oauth": True,
            "refreshable": True,
            "provider": "google.oauth2",
            "provider_id": "google",
            "provider_subject": PROVIDER_SUBJECT,
            "provider_account": "setup-verifier@example.test",
            "provider_identity_verified": True,
            "scopes": [SCOPE],
            "token_type": "Bearer",
            "injection_field": "access_token",
        }

        def create_oauth_credential(name: str, **metadata_updates: Any) -> dict[str, Any]:
            metadata = copy.deepcopy(oauth_metadata)
            for key, value in metadata_updates.items():
                if value is None:
                    metadata.pop(key, None)
                else:
                    metadata[key] = value
            # Each synthetic row represents a separate OAuth grant family; the
            # test varies stored policy bindings rather than reconnect behavior.
            metadata.setdefault(
                "oauth_client_id",
                "setup-verification-" + hashlib.sha256(name.encode("utf-8")).hexdigest(),
            )
            return db.create_credential(name, "oauth2", oauth_secret, metadata)

        exact_credential = create_oauth_credential("Setup verification exact OAuth")
        wrong_credential = create_oauth_credential("Setup verification wrong OAuth")
        missing_scope_credential = create_oauth_credential("Setup verification missing scope", scopes=None)
        wrong_scope_credential = create_oauth_credential(
            "Setup verification wrong scope",
            scopes=["scope.other"],
        )
        over_scoped_credential = create_oauth_credential(
            "Setup verification over-scoped",
            scopes=[SCOPE, "scope.extra"],
        )
        wrong_injection_credential = create_oauth_credential(
            "Setup verification wrong injection",
            injection_field="refresh_token",
        )

        jit_policy = {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 30,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "requestDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:setup-verifier"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["hardware"],
                    "requireHardwareAttestation": True,
                },
            },
        }
        invalid_composed = demo_policy_bundle(exact_credential["id"])
        invalid_composed_route = invalid_composed["routes"][0]
        invalid_composed_route["jit"] = {**copy.deepcopy(jit_policy), "maxUses": 2}
        invalid_composed_route.setdefault("constraints", []).append(
            {
                "id": "setup-atomic-quota",
                "type": "rateLimit",
                "max": 2,
                "windowSeconds": 60,
                "store": "shared",
                "key": {"scope": ["principal", "credential", "route"]},
            }
        )
        try:
            compile_policy_bundle(invalid_composed, validate_schema=True)
        except PolicyBundleError:
            pass
        else:
            raise AssertionError(
                "policy admission accepted multi-use JIT composed with shared quota"
            )

        def activate_policy(
            credential_id: str,
            *,
            provider: str | None = "google",
            provider_subject: str | None = PROVIDER_SUBJECT,
            scopes: list[str] | None = None,
            injection: dict[str, Any] | None = None,
        ):
            bundle = demo_policy_bundle(credential_id)
            bundle["principals"].append(
                {
                    "id": "agent:unassigned",
                    "sourceCidrs": ["127.0.0.1/32"],
                    "requiredHeaders": {"X-Serverware-Agent": "unassigned-agent"},
                }
            )
            policy_credential = bundle["credentials"][0]
            if provider is None:
                policy_credential.pop("provider", None)
            else:
                policy_credential["provider"] = provider
            if provider_subject is None:
                policy_credential.pop("providerSubject", None)
            else:
                policy_credential["providerSubject"] = provider_subject
            policy_credential["scopes"] = [SCOPE] if scopes is None else scopes
            if injection is None:
                policy_credential["injection"] = {"type": "bearer", "field": "access_token"}
            elif injection:
                policy_credential["injection"] = injection
            else:
                policy_credential.pop("injection", None)
            route = next(item for item in bundle["routes"] if item["id"] == ROUTE_ID)
            route["jit"] = copy.deepcopy(jit_policy)
            return write_policy_bundle(bundle)

        baseline_snapshot = activate_policy(exact_credential["id"])
        attestation_state: dict[str, Any] = {
            "nonce": None,
            "policy_hash": None,
            "hardware": False,
        }

        def test_attestation(nonce: str) -> dict[str, Any]:
            snapshot = app_module.get_policy_snapshot()
            if snapshot is None:
                raise AssertionError("test policy unexpectedly disappeared")
            hardware = attestation_state["hardware"] is True
            return {
                "nonce": attestation_state["nonce"] or nonce,
                "policy_bundle_digest": attestation_state["policy_hash"] or snapshot.hash,
                "runtime_manifest_digest": "sha256:" + "1" * 64,
                "source_tree_digest": "sha256:" + "2" * 64,
                "data_plane_binary_digest": "sha256:" + "3" * 64,
                "response_signing_key_id": "sha256:" + "4" * 64,
                "policy_high_water_digest": "sha256:" + "5" * 64,
                "tee_platform": "test-hardware" if hardware else "software-fixture",
                "assurance": {
                    "class": "hardware" if hardware else "software",
                    "hardware_proof": hardware,
                    "workload_custody_proven": hardware,
                    "tls_peer_binding_proven": hardware,
                },
            }

        original_attestation_document = app_module.attestation_document
        app_module.attestation_document = test_attestation
        identity = AdminIdentity(
            "user:setup-verifier",
            frozenset({"auditor"}),
            "test",
        )
        responses: list[dict[str, Any]] = []
        current_enrollment_session_id: str | None = None

        hostile_enrollment = app_module.AgentEnrollmentCreate.model_validate(
            {
                "principalId": PRINCIPAL_ID,
                "proxyUrl": "http://127.0.0.1:8080",
                "controlPlaneUrl": "https://attacker.example",
                "proxyEgressCidrs": ["127.0.0.1/32"],
                "nonce": NONCE,
                "ttlSeconds": 300,
            }
        )
        try:
            app_module.agent_enrollment(
                hostile_enrollment,
                identity=AdminIdentity("user:setup-verifier", frozenset({"policy_author"}), "test"),
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 400 or "SERVERWARE_PUBLIC_URL" not in str(exc.detail):
                raise AssertionError(f"hostile enrollment origin failed incorrectly: {exc.detail}") from exc
        else:
            raise AssertionError("enrollment accepted an operator-controlled control-plane origin")

        def request_body(
            *,
            principal_id: str = PRINCIPAL_ID,
            route_id: str = ROUTE_ID,
            credential_id: str = exact_credential["id"],
            nonce: str = NONCE,
        ) -> dict[str, Any]:
            current_snapshot = app_module.get_policy_snapshot()
            raw_route = next(
                (
                    item
                    for item in ((current_snapshot.raw.get("routes") or []) if current_snapshot else [])
                    if isinstance(item, dict) and item.get("id") == route_id
                ),
                None,
            )
            route_policy_digest = (
                "sha256:" + hashlib.sha256(canonical_json(raw_route).encode("utf-8")).hexdigest()
                if raw_route is not None
                else "sha256:" + "0" * 64
            )
            body = {
                "principalId": principal_id,
                "routeId": route_id,
                "credentialId": credential_id,
                "routePolicyDigest": route_policy_digest,
                "nonce": nonce,
            }
            if current_enrollment_session_id is not None:
                body["enrollmentSessionId"] = current_enrollment_session_id
            return body

        def verify(payload: dict[str, Any]) -> dict[str, Any]:
            request = app_module.SetupVerificationRequest.model_validate(payload)
            result = app_module.setup_verification(request, identity=identity)
            serialized = canonical_json(result)
            for secret in (ACCESS_TOKEN, REFRESH_TOKEN):
                if secret in serialized:
                    raise AssertionError("setup verification response disclosed OAuth token material")
            responses.append(result)
            return result

        def assert_configuration_failure(
            label: str,
            payload: dict[str, Any],
            failed_check: str,
            *,
            passing_checks: tuple[str, ...] = (),
        ) -> dict[str, Any]:
            result = verify(payload)
            if result.get("configurationReady") is not False or result.get("runtimeVerified") is not False:
                raise AssertionError(f"{label} did not fail closed: {result}")
            if result.get("nextAction") != "repair_active_assignment":
                raise AssertionError(f"{label} returned an unsafe next action: {result}")
            assert_check(result, failed_check, "fail")
            for check_id in passing_checks:
                assert_check(result, check_id, "pass")
            return result

        try:
            exact = verify(request_body())
            if not exact["configurationReady"]:
                raise AssertionError(f"exact active OAuth assignment was not ready: {exact}")
            for item in exact["checks"]:
                if item["required"] and item["status"] != "pass":
                    raise AssertionError(f"exact assignment failed required check: {item}")
            expected_assignment = {
                "principalId": PRINCIPAL_ID,
                "routeId": ROUTE_ID,
                "credentialId": exact_credential["id"],
                "credentialVersion": exact_credential["credential_version"],
                "policyHash": baseline_snapshot.hash,
                "routePolicyDigest": request_body()["routePolicyDigest"],
            }
            if exact["assignment"] != expected_assignment:
                raise AssertionError(f"exact assignment changed: {exact['assignment']}")
            expected_digest = "sha256:" + hashlib.sha256(
                canonical_json(expected_assignment).encode("utf-8")
            ).hexdigest()
            if exact["assignmentDigest"] != expected_digest:
                raise AssertionError(f"assignment digest did not bind the exact assignment: {exact}")
            if exact["attestation"]["nonce"] != NONCE:
                raise AssertionError(f"verification response lost its nonce binding: {exact}")
            current_binding = check_by_id(exact, "attestation.serverClaims")
            if current_binding.get("evidence", {}).get("policyHash") != baseline_snapshot.hash:
                raise AssertionError(f"attestation did not name the active policy: {current_binding}")
            if exact["runtimeVerified"] or exact["hardwareVerified"] or exact["fullyVerified"]:
                raise AssertionError(f"configuration proof was conflated with runtime or hardware proof: {exact}")
            if exact["nextAction"] != "verify_enrollment_and_install_ca":
                raise AssertionError(f"missing runtime evidence returned wrong next action: {exact}")
            assert_check(exact, "runtime.credentialRelease", "pending")
            assert_check(exact, "runtime.responseReleased", "pending")
            assert_check(exact, "runtime.jitConsumption", "pending")

            assert_configuration_failure(
                "mismatched reviewed route policy",
                {**request_body(), "routePolicyDigest": "sha256:" + "f" * 64},
                "route.policyBinding",
                passing_checks=("route.active", "route.principalBinding"),
            )

            activate_policy(exact_credential["id"], provider="google.oauth2")
            provider_alias = verify(request_body())
            if not provider_alias["configurationReady"]:
                raise AssertionError(f"canonical OAuth provider alias was rejected: {provider_alias}")
            assert_check(provider_alias, "credential.providerBinding", "pass")
            baseline_snapshot = activate_policy(exact_credential["id"])

            assert_configuration_failure(
                "missing route",
                request_body(route_id="route:missing"),
                "route.active",
            )
            assert_configuration_failure(
                "wrong active route",
                request_body(route_id="demo.stream"),
                "credential.routeBinding",
                passing_checks=("route.active", "route.principalBinding", "credential.active"),
            )
            assert_configuration_failure(
                "missing principal",
                request_body(principal_id="agent:missing"),
                "principal.active",
            )
            assert_configuration_failure(
                "wrong active principal",
                request_body(principal_id="agent:unassigned"),
                "route.principalBinding",
                passing_checks=("principal.active", "route.active", "credential.active"),
            )
            assert_configuration_failure(
                "missing credential",
                request_body(credential_id="credential:missing"),
                "credential.active",
            )
            assert_configuration_failure(
                "wrong active credential",
                request_body(credential_id=wrong_credential["id"]),
                "credential.policyDeclaration",
                passing_checks=("principal.active", "route.active", "credential.active"),
            )

            for label, credential, failed_check in (
                ("missing OAuth grant scopes", missing_scope_credential, "credential.scopeBinding"),
                ("wrong OAuth grant scopes", wrong_scope_credential, "credential.scopeBinding"),
                ("over-scoped OAuth grant", over_scoped_credential, "credential.scopeBinding"),
            ):
                activate_policy(credential["id"])
                assert_configuration_failure(
                    label,
                    request_body(credential_id=credential["id"]),
                    failed_check,
                    passing_checks=(
                        "credential.active",
                        "credential.policyDeclaration",
                        "credential.routeBinding",
                        "credential.injectionBinding",
                        "credential.providerBinding",
                    ),
                )

            for label, provider, provider_subject in (
                ("missing signed provider binding", None, None),
                ("wrong signed provider binding", "x", PROVIDER_SUBJECT),
            ):
                activate_policy(
                    exact_credential["id"],
                    provider=provider,
                    provider_subject=provider_subject,
                )
                assert_configuration_failure(
                    label,
                    request_body(),
                    "credential.providerBinding",
                    passing_checks=(
                        "credential.active",
                        "credential.policyDeclaration",
                        "credential.routeBinding",
                        "credential.injectionBinding",
                        "credential.scopeBinding",
                    ),
                )

            for label, injection in (
                ("missing signed injection field binding", {"type": "bearer"}),
                ("wrong signed injection binding", {"type": "bearer", "field": "refresh_token"}),
            ):
                try:
                    activate_policy(exact_credential["id"], injection=injection)
                except PolicyBundleError:
                    pass
                else:
                    raise AssertionError(f"{label} was accepted into the active signed policy")

            activate_policy(wrong_injection_credential["id"])
            assert_configuration_failure(
                "wrong stored injection binding",
                request_body(credential_id=wrong_injection_credential["id"]),
                "credential.injectionBinding",
                passing_checks=(
                    "credential.active",
                    "credential.policyDeclaration",
                    "credential.routeBinding",
                    "credential.providerBinding",
                    "credential.scopeBinding",
                ),
            )

            baseline_snapshot = activate_policy(exact_credential["id"])
            attestation_state["nonce"] = "wrong-attestation-nonce-0123456789abcdef"
            assert_configuration_failure(
                "wrong attestation nonce",
                request_body(),
                "attestation.serverClaims",
            )
            attestation_state["nonce"] = None
            attestation_state["policy_hash"] = "sha256:" + "0" * 64
            assert_configuration_failure(
                "stale attestation policy",
                request_body(),
                "attestation.serverClaims",
            )
            attestation_state["policy_hash"] = None

            attestation_state["hardware"] = True
            hardware_only = verify(request_body())
            if hardware_only["hardwareVerified"] or hardware_only["runtimeVerified"] or hardware_only["fullyVerified"]:
                raise AssertionError(f"server hardware claims were mistaken for independent proof: {hardware_only}")
            if hardware_only["nextAction"] != "verify_enrollment_and_install_ca":
                raise AssertionError(f"server hardware claims skipped enrollment proof: {hardware_only}")
            attestation_state["hardware"] = False

            credential_version = int(exact_credential["credential_version"])

            def runtime_event(**updates: Any) -> dict[str, Any]:
                event = {
                    "principal_id": PRINCIPAL_ID,
                    "route_id": ROUTE_ID,
                    "policy_hash": baseline_snapshot.hash,
                    "credential_id": exact_credential["id"],
                    "credential_version": credential_version,
                    "request_digest": "sha256:" + "6" * 64,
                    "operation_digest": "sha256:" + "7" * 64,
                    "flow_id": "sha256:" + "4" * 64,
                    "grant_id": "grant:exact-setup-verification",
                    "approval_id": "approval:exact-setup-verification",
                    "approval_request_id": "approval:exact-setup-verification",
                }
                if current_enrollment_session_id is not None:
                    event["enrollment_session_id"] = current_enrollment_session_id
                event.update(updates)
                return event

            db.record_audit_event(
                "data_plane.credential.release_started",
                runtime_event(),
                actor_type="data-plane",
                actor_id="spiffe://test/stale-release",
            )
            session, _ = app_module._create_ca_install_session(
                created_by="user:setup-verifier",
                nonce=NONCE,
                ttl_seconds=300,
                policy_hash=baseline_snapshot.hash,
                principal_id=PRINCIPAL_ID,
                purpose="agent-enrollment",
            )
            session_state = app_module._read_ca_install_sessions()
            stored_session = session_state["sessions"][session["id"]]
            stored_session.update(
                {
                    "status": "consumed",
                    "consumed_at": app_module._now_iso(),
                    "consumed_by": "user:setup-verifier",
                    "enrollment_packet_sha256": "sha256:" + "8" * 64,
                    "allowed_assignments": [
                        {
                            "route_id": ROUTE_ID,
                            "credential_id": exact_credential["id"],
                            "credential_version": credential_version,
                        }
                    ],
                }
            )
            app_module._write_ca_install_sessions(session_state)
            current_enrollment_session_id = str(session["id"])
            stale_release = verify(request_body())
            if stale_release["runtimeVerified"] or stale_release["nextAction"] != "enroll_agent_and_exercise_route":
                raise AssertionError(f"pre-enrollment release evidence was accepted: {stale_release}")
            assert_check(stale_release, "enrollment.caCapabilityConsumed", "pass")

            db.record_audit_event(
                "data_plane.credential.release_started",
                runtime_event(route_id="route:wrong"),
                actor_type="data-plane",
                actor_id="spiffe://test/wrong-release",
            )
            wrong_release = verify(request_body())
            if wrong_release["runtimeVerified"] or wrong_release["nextAction"] != "enroll_agent_and_exercise_route":
                raise AssertionError(f"mismatched release evidence was accepted: {wrong_release}")
            assert_check(wrong_release, "runtime.credentialRelease", "pending")

            db.record_audit_event(
                "data_plane.credential.release_started",
                runtime_event(enrollment_session_id=None),
                actor_type="data-plane",
                actor_id="spiffe://test/uncorrelated-release",
            )
            uncorrelated_release = verify(request_body())
            if uncorrelated_release["runtimeVerified"]:
                raise AssertionError(f"release without enrollment correlation was accepted: {uncorrelated_release}")
            assert_check(uncorrelated_release, "runtime.credentialRelease", "pending")

            db.record_audit_event(
                "data_plane.credential.release_started",
                runtime_event(),
                actor_type="data-plane",
                actor_id="spiffe://test/exact-release",
            )
            released = verify(request_body())
            if released["runtimeVerified"] or released["nextAction"] != "approve_and_retry_exact_request":
                raise AssertionError(f"exact release did not transition to pending JIT: {released}")
            assert_check(released, "runtime.credentialRelease", "pass")
            assert_check(released, "runtime.responseReleased", "pending")
            assert_check(released, "runtime.jitConsumption", "pending")

            db.record_audit_event(
                "data_plane.jit.grant_consumed",
                runtime_event(
                    flow_id="sha256:" + "1" * 64,
                    grant_id="grant:unrelated-retry",
                    approval_id="approval:unrelated-retry",
                    approval_request_id="approval:unrelated-retry",
                ),
                actor_type="data-plane",
                actor_id="spiffe://test/unrelated-retry-jit",
            )
            db.record_audit_event(
                "jit.grant.consumed",
                runtime_event(
                    flow_id="sha256:" + "1" * 64,
                    grant_id="grant:unrelated-retry",
                    approval_id="approval:unrelated-retry",
                    approval_request_id="approval:unrelated-retry",
                ),
                actor_type="proxy",
                actor_id=ROUTE_ID,
            )
            unrelated_retry = verify(request_body())
            if unrelated_retry["runtimeVerified"]:
                raise AssertionError(
                    "identical request digests from an unrelated flow/grant were cross-paired: "
                    f"{unrelated_retry}"
                )

            db.record_audit_event(
                "data_plane.jit.grant_consumed",
                runtime_event(credential_version=credential_version + 1),
                actor_type="data-plane",
                actor_id="spiffe://test/wrong-jit",
            )
            wrong_jit = verify(request_body())
            if wrong_jit["runtimeVerified"] or wrong_jit["nextAction"] != "approve_and_retry_exact_request":
                raise AssertionError(f"mismatched JIT evidence was accepted: {wrong_jit}")

            db.record_audit_event(
                "data_plane.jit.grant_consumed",
                runtime_event(),
                actor_type="data-plane",
                actor_id="spiffe://test/exact-jit",
            )
            data_plane_only = verify(request_body())
            if data_plane_only["runtimeVerified"] or data_plane_only["nextAction"] != "approve_and_retry_exact_request":
                raise AssertionError(f"data-plane-only JIT evidence was accepted: {data_plane_only}")
            db.record_audit_event(
                "jit.grant.consumed",
                runtime_event(request_digest="sha256:" + "9" * 64),
                actor_type="proxy",
                actor_id=ROUTE_ID,
            )
            mismatched_authoritative = verify(request_body())
            if mismatched_authoritative["runtimeVerified"]:
                raise AssertionError(f"cross-request JIT evidence was accepted: {mismatched_authoritative}")
            db.record_audit_event(
                "jit.grant.consumed",
                runtime_event(),
                actor_type="proxy",
                actor_id=ROUTE_ID,
            )
            no_response = verify(request_body())
            if no_response["runtimeVerified"] or no_response["nextAction"] != "wait_for_validated_response_evidence":
                raise AssertionError(f"pre-send and JIT evidence were accepted without a response: {no_response}")
            assert_check(no_response, "runtime.responseReleased", "pending")

            db.record_audit_event(
                "data_plane.response.released",
                runtime_event(
                    outcome="released",
                    upstream_status=200,
                    response_body_sha256="sha256:" + "e" * 64,
                    response_validation={"mode": "buffered", "validated": True},
                ),
                actor_type="data-plane",
                actor_id="spiffe://test/exact-response",
            )
            runtime_verified = verify(request_body())
            if not runtime_verified["runtimeVerified"] or runtime_verified["hardwareVerified"]:
                raise AssertionError(
                    f"exact runtime evidence did not remain distinct from hardware: {runtime_verified}"
                )
            if runtime_verified.get("runtimeEvidenceAssurance") != {
                "classification": "authenticated-correlated-telemetry",
                "independentExecutionAttestation": False,
                "producerIdentity": "scoped-bearer-and-server-derived-instance",
                "summary": (
                    "The compatibility runtimeVerified field means the required "
                    "gateway and authoritative-store telemetry correlated. It does "
                    "not independently attest which measured code authored those events."
                ),
            }:
                raise AssertionError(
                    "runtime verification did not disclose its authenticated-telemetry "
                    f"assurance ceiling: {runtime_verified}"
                )
            if (
                runtime_verified["fullyVerified"]
                or runtime_verified["nextAction"] != "verify_on_hardware_backed_deployment"
            ):
                raise AssertionError(f"software runtime proof overclaimed full verification: {runtime_verified}")
            assert_check(runtime_verified, "runtime.credentialRelease", "pass")
            assert_check(runtime_verified, "runtime.responseReleased", "pass")
            assert_check(runtime_verified, "runtime.jitConsumption", "pass")

            db.record_audit_event(
                "data_plane.jit.grant_consumed",
                runtime_event(
                    request_digest="sha256:" + "a" * 64,
                    operation_digest="sha256:" + "b" * 64,
                ),
                actor_type="data-plane",
                actor_id="spiffe://test/newer-unmatched-data-plane",
            )
            db.record_audit_event(
                "jit.grant.consumed",
                runtime_event(
                    request_digest="sha256:" + "c" * 64,
                    operation_digest="sha256:" + "d" * 64,
                ),
                actor_type="proxy",
                actor_id=ROUTE_ID,
            )
            concurrent_evidence = verify(request_body())
            if not concurrent_evidence["runtimeVerified"]:
                raise AssertionError(f"newer mismatched JIT events hid a valid evidence pair: {concurrent_evidence}")

            attestation_state["hardware"] = True
            hardware_claim_only = verify(request_body())
            if not hardware_claim_only["runtimeVerified"] or hardware_claim_only["hardwareVerified"] or hardware_claim_only["fullyVerified"]:
                raise AssertionError(f"server hardware claim overrode independent verification: {hardware_claim_only}")
            if hardware_claim_only["nextAction"] != "verify_on_hardware_backed_deployment":
                raise AssertionError(f"hardware claim returned wrong next action: {hardware_claim_only}")

            valid_body = request_body()
            malformed_cases: list[tuple[str, dict[str, Any]]] = [
                ("extra field", {**valid_body, "unexpected": True}),
                ("missing nonce", {key: value for key, value in valid_body.items() if key != "nonce"}),
                ("short nonce", {**valid_body, "nonce": "too-short"}),
                ("invalid nonce alphabet", {**valid_body, "nonce": "!" * 32}),
                (
                    "missing route policy digest",
                    {key: value for key, value in valid_body.items() if key != "routePolicyDigest"},
                ),
                ("invalid route policy digest", {**valid_body, "routePolicyDigest": "sha256:short"}),
                ("empty route", {**valid_body, "routeId": ""}),
                ("oversized principal", {**valid_body, "principalId": "p" * 257}),
                ("non-string credential", {**valid_body, "credentialId": {"id": exact_credential["id"]}}),
            ]
            for label, malformed in malformed_cases:
                try:
                    app_module.SetupVerificationRequest.model_validate(malformed)
                except ValidationError:
                    pass
                else:
                    raise AssertionError(f"{label} request was not rejected")
            try:
                app_module.SetupVerificationRequest.model_validate_json(b'{"principalId":')
            except ValidationError:
                pass
            else:
                raise AssertionError("malformed JSON was not rejected")

            setup_audits = db.search_audit_events(
                event_type="setup.verification.checked",
                limit=100,
                scan_limit=500,
            )
            audit_items = setup_audits.get("items")
            if not isinstance(audit_items, list) or len(audit_items) != len(responses):
                raise AssertionError(
                    "successful setup verifications were not audited exactly once: "
                    f"{len(responses)} responses, {audit_items}"
                )
            serialized_audits = canonical_json(audit_items)
            for secret in (ACCESS_TOKEN, REFRESH_TOKEN):
                if secret in serialized_audits:
                    raise AssertionError("setup verification audit disclosed OAuth token material")
            allowed_audit_fields = {
                "assignment",
                "assignment_digest",
                "configuration_ready",
                "runtime_verified",
                "hardware_verified",
                "next_action",
            }
            for item in audit_items:
                event = item.get("event")
                if not isinstance(event, dict) or set(event) != allowed_audit_fields:
                    raise AssertionError(
                        f"setup verification audit retained unexpected request or evidence data: {item}"
                    )
        finally:
            app_module.attestation_document = original_attestation_document

    print("setup verification tests passed")


if __name__ == "__main__":
    main()
