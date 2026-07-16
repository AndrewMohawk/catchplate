#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
NONCE = "enrollment-test-nonce-0123456789abcdef"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-agent-enrollment-") as tmp:
        for name in tuple(os.environ):
            if name.startswith("SERVERWARE_"):
                os.environ.pop(name)
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(Path(tmp) / "policy-bundle.json")
        os.environ["SERVERWARE_POLICY_SIGNING_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pem")
        os.environ["SERVERWARE_POLICY_SIGNING_PUBLIC_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pub.pem")
        os.environ["SERVERWARE_TEE_QUOTE_PROVIDER"] = "dev-signed-quote"

        from serverware.attestation import sign_quote
        from serverware.enrollment import (
            AgentEnrollmentError,
            build_agent_enrollment,
            canonical_control_plane_url,
        )
        from serverware.policy_bundle import compile_policy_bundle, demo_policy_bundle, sign_policy_bundle
        from serverware.response_identity import response_public_key_info
        from serverware.setup_receipts import (
            Ed25519TrustRoot,
            EnrollmentReceiptExpected,
            FixedClock,
            SetupAssignment,
            canonical_json_bytes,
            sha256_digest,
            verify_enrollment_verifier_receipt,
        )
        from generate_agent_enrollment import (
            MAX_ENROLLMENT_PACKET_BYTES,
            enrollment_nonce,
            load_enrollment_packet,
            verify_attestation_for_packet,
            verify_packet,
        )

        signed = sign_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
        snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=False)
        runtime_manifest = {"binary": "serverware-test", "mode": "agent-enrollment"}
        runtime_manifest_digest = "sha256:" + hashlib.sha256(
            repr(sorted(runtime_manifest.items())).encode("utf-8")
        ).hexdigest()
        attestation = {
            "policy_signing_key_id": (signed.get("metadata") or {}).get("signingKeyId"),
            "rollback_epoch": 1,
            "policy_sequence": 1,
            "policy_high_water_digest": "sha256:" + "9" * 64,
            "release_channel": "prod",
            "ca_intermediate_spki_sha256": "sha256:" + "a" * 64,
            "data_plane_binary_digest": "sha256:" + "b" * 64,
            "runtime_manifest_digest": runtime_manifest_digest,
            "response_signing_key_id": response_public_key_info()["spki_sha256"],
            "provenance_digest": "sha256:" + "c" * 64,
            "image_signatures_digest": "sha256:" + "d" * 64,
            "source_tree_digest": "sha256:" + "e" * 64,
        }
        packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://serverware.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            namespace="agents",
            pod_selector={"app": "release-bot"},
            nonce=NONCE,
        )

        assert packet["apiVersion"] == "serverware.agentEnrollment/v1", packet
        assert packet["principalId"] == "agent:demo-proxy-token", packet
        assert packet["pinning"]["policyHash"] == snapshot.hash, packet
        assert packet["pinning"]["runtimeManifestDigest"] == attestation["runtime_manifest_digest"], packet
        assert packet["pinning"]["responseSigningKeyId"] == attestation["response_signing_key_id"], packet
        assert packet["identity"]["requiredHeaders"] == {"X-Serverware-Agent": "demo-token-agent"}, packet
        proxy_auth = packet["identity"]["proxyAuthorization"]
        assert proxy_auth["tokenId"] == "demo-sidecar-token", proxy_auth
        serialized = canonical_json(packet)
        assert "demo-agent-proxy-token" not in serialized, serialized
        assert "tokenSha256" not in serialized, serialized
        assert "cred-demo-bearer" in serialized, packet
        assert packet["environment"]["HTTPS_PROXY"] == "http://10.42.0.10:8080", packet
        assert packet["ca"]["installMethod"] == "verifier-mediated-attestation", packet
        assert packet["serverware"]["proxyHostMappings"] == [], packet
        route_by_id = {route.id: route for route in snapshot.routes}
        assert packet["allowedRoutes"], packet
        for allowed_route in packet["allowedRoutes"]:
            compiled_route = route_by_id[allowed_route["id"]]
            assert len(allowed_route["urls"]) == len(compiled_route.path_templates), allowed_route
            assert len(allowed_route["paths"]) == len(compiled_route.path_templates), allowed_route
            assert allowed_route["url"] == allowed_route["urls"][0], allowed_route
            assert all(url.startswith(f"{compiled_route.scheme}://{compiled_route.host}:") for url in allowed_route["urls"]), allowed_route
            assert all(url.endswith(path) for url, path in zip(allowed_route["urls"], allowed_route["paths"], strict=True)), allowed_route
        handoff = packet["agentHandoff"]
        assert handoff["caInstall"]["destinationPath"] == "/etc/serverware/serverware-ca.pem", handoff
        assert handoff["caInstall"]["command"].endswith("/etc/serverware/serverware-ca.pem"), handoff
        assert handoff["requiredProxyHeaders"] == packet["identity"]["requiredHeaders"], handoff
        assert handoff["requiredProviderHeaders"] == packet["identity"]["requiredHeaders"], handoff
        assert handoff["proxyAuthorization"] == {
            "required": True,
            "provisionSeparately": True,
            "tokenId": "demo-sidecar-token",
        }, handoff
        assert handoff["requestHandling"] == {
            "approvalRequired": {
                "statusCode": 428,
                "approvalIdField": "approval_id",
                "operatorPathField": "approval_url",
                "operatorPathTemplate": "/approvals/{approval_id}",
                "retryAfterField": "retry_after_seconds",
                "retryRule": "retry-the-identical-request-only-after-human-approval",
            },
            "stopAndReportStatusCodes": [403],
            "stopAndReportStatusClasses": [5],
            "bypassForbidden": True,
            "credentialHandling": "never-request-store-print-or-cache-provider-credentials",
        }, handoff
        assert any("HTTP 428" in step and "identical request" in step for step in handoff["sequence"]), handoff
        assert any("HTTP 403 or 5xx" in step and "never bypass" in step for step in handoff["sequence"]), handoff
        assert len(handoff["allowedUrls"]) == sum(len(item["urls"]) for item in packet["allowedRoutes"]), handoff

        policy = packet["egress"]["kubernetesNetworkPolicy"]
        spec = policy["spec"]
        assert spec["podSelector"]["matchLabels"] == {"app": "release-bot"}, policy
        assert spec["policyTypes"] == ["Egress"], policy
        assert spec["egress"] == [
            {
                "to": [{"ipBlock": {"cidr": "10.42.0.10/32"}}],
                "ports": [{"protocol": "TCP", "port": 8080}],
            }
        ], policy
        assert packet["egress"]["denyByDefault"] is True, packet
        assert any(rule.endswith("--dport 8080 -j ACCEPT") for rule in packet["egress"]["iptables"]), packet
        assert packet["canaries"]["allow"], packet
        assert packet["canaries"]["deny"][0]["expectedError"] == "unknown_route_denied", packet
        assert packet["nonce"] == NONCE and packet["expiresAtEpochMs"] > packet["issuedAtEpochMs"], packet
        authenticity = packet["authenticity"]
        unsigned_packet = json.loads(json.dumps(packet))
        unsigned_packet.pop("authenticity")
        packet_sha256 = "sha256:" + hashlib.sha256(canonical_json(unsigned_packet).encode("utf-8")).hexdigest()
        assert authenticity["statement"]["packetSha256"] == packet_sha256, authenticity
        response_public_key = serialization.load_pem_public_key(response_public_key_info()["pem"].encode("ascii"))
        signature = authenticity["signature"].split(":", 1)[1]
        response_public_key.verify(
            base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
            canonical_json(authenticity["statement"]).encode("utf-8"),
        )
        def live_attestation(nonce: str) -> dict[str, object]:
            value: dict[str, object] = {
                **attestation,
                "nonce": nonce,
                "runtime_manifest": runtime_manifest,
                "policy_bundle_digest": snapshot.hash,
                "response_signing_public_key_pem": response_public_key_info()["pem"],
            }
            quote_fields = (
                "runtime_manifest_digest",
                "policy_bundle_digest",
                "policy_sequence",
                "policy_high_water_digest",
                "ca_intermediate_spki_sha256",
                "data_plane_binary_digest",
                "rollback_epoch",
                "provenance_digest",
                "image_signatures_digest",
                "source_tree_digest",
                "response_signing_key_id",
                "release_channel",
            )
            claims = {field: value[field] for field in quote_fields}
            claims["nonce"] = nonce
            value["quote"] = sign_quote(claims)
            return value

        verification_attestation = live_attestation(NONCE)
        receipt = verify_packet(packet, verification_attestation, NONCE)
        assert receipt["packetSha256"] == packet_sha256, receipt
        assert "packet-signature" in receipt["checks"], receipt
        full_receipt = verify_attestation_for_packet(packet, verification_attestation, NONCE, None)
        assert full_receipt["packetSha256"] == packet_sha256, full_receipt
        wrong_policy_key_attestation = dict(verification_attestation)
        wrong_policy_key_attestation["policy_signing_key_id"] = "sha256:" + "0" * 64
        try:
            verify_packet(packet, wrong_policy_key_attestation, NONCE)
        except ValueError as exc:
            assert "policySigningKeyId" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a mismatched policy signing key pin")
        tampered_packet = json.loads(json.dumps(packet))
        tampered_packet["principalId"] = "agent:tampered"
        try:
            verify_packet(tampered_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "digest mismatch" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a tampered signed packet")

        expired_packet = json.loads(json.dumps(packet))
        expired_packet["issuedAtEpochMs"] = 1
        expired_packet["expiresAtEpochMs"] = 2
        try:
            verify_packet(expired_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "not currently valid" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted an expired packet")

        packet_with_receipt = json.loads(json.dumps(packet))
        packet_with_receipt["verificationReceipt"] = {"ok": True}
        try:
            verify_packet(packet_with_receipt, verification_attestation, NONCE)
        except ValueError as exc:
            assert "untrusted verificationReceipt" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted an existing untrusted receipt")

        quote_nonce_mismatch = live_attestation("different-enrollment-nonce-0123456789abcdef")
        quote_nonce_mismatch["nonce"] = NONCE
        try:
            verify_attestation_for_packet(packet, quote_nonce_mismatch, NONCE, None)
        except ValueError as exc:
            assert "quote claim nonce" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a quote for a different nonce")

        missing_nonce_packet = json.loads(json.dumps(packet))
        missing_nonce_packet.pop("nonce")
        try:
            enrollment_nonce(missing_nonce_packet)
        except ValueError as exc:
            assert "valid nonce" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a packet without a nonce")

        mismatched_attestation = live_attestation("different-enrollment-nonce-0123456789abcdef")
        try:
            verify_attestation_for_packet(packet, mismatched_attestation, NONCE, None)
        except ValueError as exc:
            assert "live attestation nonce" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a mismatched live attestation nonce")

        packet_path = Path(tmp) / "portal-enrollment.json"
        packet_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
        assert load_enrollment_packet(packet_path) == packet

        duplicate_path = Path(tmp) / "duplicate-enrollment.json"
        duplicate_path.write_text('{"nonce":"first-nonce-0123456789abcdef","nonce":"second-nonce-0123456789abcdef"}\n')
        try:
            load_enrollment_packet(duplicate_path)
        except ValueError as exc:
            assert "duplicate key" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted duplicate JSON keys")

        float_path = Path(tmp) / "float-enrollment.json"
        float_path.write_text('{"issuedAtEpochMs":1.5}\n', encoding="utf-8")
        try:
            load_enrollment_packet(float_path)
        except ValueError as exc:
            assert "floating-point" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a floating-point packet value")

        symlink_path = Path(tmp) / "symlink-enrollment.json"
        symlink_path.symlink_to(packet_path)
        try:
            load_enrollment_packet(symlink_path)
        except ValueError as exc:
            assert "non-symlink" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier followed an enrollment packet symlink")

        non_object_path = Path(tmp) / "array-enrollment.json"
        non_object_path.write_text("[]\n", encoding="utf-8")
        try:
            load_enrollment_packet(non_object_path)
        except ValueError as exc:
            assert "JSON object" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a non-object packet")

        oversized_path = Path(tmp) / "oversized-enrollment.json"
        with oversized_path.open("wb") as oversized_file:
            oversized_file.truncate(MAX_ENROLLMENT_PACKET_BYTES + 1)
        try:
            load_enrollment_packet(oversized_path)
        except ValueError as exc:
            assert "exceeds" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted an oversized packet")

        setup_session_id = str(uuid.uuid4())
        setup_enrollment_session_id = str(uuid.uuid4())
        setup_receipt_id = str(uuid.uuid4())
        setup_install_session = {
            "id": setup_enrollment_session_id,
            "nonce": NONCE,
            "token": "setup-install-token-0123456789abcdef0123456789",
            "tokenHeader": "X-Serverware-CA-Install-Token",
            "policyUrl": f"/api/ca/install-sessions/{setup_enrollment_session_id}/policy",
            "downloadUrl": f"/api/ca/install-sessions/{setup_enrollment_session_id}/ca.pem",
            "expiresAt": "2099-01-01T00:00:00+00:00",
        }
        setup_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://serverware.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            namespace="agents",
            pod_selector={"app": "release-bot"},
            nonce=NONCE,
            ca_install_session=setup_install_session,
        )
        setup_route = next(
            route
            for route in setup_packet["allowedRoutes"]
            if isinstance(route.get("credentialRef"), str)
        )
        setup_assignment = SetupAssignment(
            principal_id=str(setup_packet["principalId"]),
            route_id=str(setup_route["id"]),
            credential_id=str(setup_route["credentialRef"]),
            credential_version=7,
            policy_hash=str(setup_packet["pinning"]["policyHash"]),
            route_policy_digest=sha256_digest(b"setup-route-policy"),
        )
        setup_trust_profile_digest = sha256_digest(b"setup-receipt-trust-profile")
        setup_packet_path = Path(tmp) / "setup-enrollment.json"
        setup_packet_path.write_text(json.dumps(setup_packet, indent=2) + "\n", encoding="utf-8")
        setup_signing_key = Ed25519PrivateKey.generate()
        setup_signing_key_path = Path(tmp) / "setup-enrollment-verifier.pem"
        setup_signing_key_path.write_bytes(
            setup_signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        setup_signing_key_path.chmod(0o600)
        setup_trust = Ed25519TrustRoot(
            "independent-enrollment-verifier",
            setup_signing_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        class EnrollmentHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                return

            def send_json(self, value: object, status: int = 200) -> None:
                body = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path != "/attestation":
                    self.send_json({"error": "not_found"}, 404)
                    return
                nonce_values = urllib.parse.parse_qs(parsed.query).get("nonce", [])
                if len(nonce_values) != 1:
                    self.send_json({"error": "nonce_required"}, 400)
                    return
                self.send_json(live_attestation(nonce_values[0]))

            def do_POST(self) -> None:
                if self.path != "/api/agents/enrollment":
                    self.send_json({"error": "not_found"}, 404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                generated = build_agent_enrollment(
                    snapshot=snapshot,
                    principal_id=payload["principalId"],
                    attestation=attestation,
                    proxy_url=payload["proxyUrl"],
                    control_plane_url=payload["controlPlaneUrl"],
                    proxy_egress_cidrs=payload["proxyEgressCidrs"],
                    namespace=payload["namespace"],
                    pod_selector=payload["podSelector"],
                    ca_mount_path=payload["caMountPath"],
                    nonce=payload["nonce"],
                    ttl_seconds=payload["ttlSeconds"],
                )
                self.send_json(generated)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EnrollmentHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            exact_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate_agent_enrollment.py"),
                    "--base",
                    base,
                    "--verify-packet",
                    str(packet_path),
                    "--expected-packet-sha256",
                    "sha256:" + hashlib.sha256(packet_path.read_bytes()).hexdigest(),
                    "--expected-principal",
                    str(packet["principalId"]),
                    "--expected-nonce",
                    NONCE,
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            if exact_result.returncode != 0:
                raise AssertionError(f"exact packet verification failed: {exact_result.stderr}")
            verified_packet = json.loads(exact_result.stdout)
            verified_receipt = verified_packet.pop("verificationReceipt", None)
            assert verified_packet == packet, (verified_packet, packet)
            assert verified_receipt and verified_receipt["nonce"] == NONCE, verified_receipt
            assert verified_receipt["downloadedPacketSha256"] == (
                "sha256:" + hashlib.sha256(packet_path.read_bytes()).hexdigest()
            ), verified_receipt

            setup_receipt_command = [
                sys.executable,
                str(ROOT / "scripts" / "generate_agent_enrollment.py"),
                "--base",
                base,
                "--verify-packet",
                str(setup_packet_path),
                "--expected-packet-sha256",
                "sha256:" + hashlib.sha256(setup_packet_path.read_bytes()).hexdigest(),
                "--expected-principal",
                setup_assignment.principal_id,
                "--expected-nonce",
                NONCE,
                "--sign-setup-receipt",
                "--setup-session-id",
                setup_session_id,
                "--enrollment-session-id",
                setup_enrollment_session_id,
                "--route-id",
                setup_assignment.route_id,
                "--credential-id",
                setup_assignment.credential_id,
                "--credential-version",
                str(setup_assignment.credential_version),
                "--policy-hash",
                setup_assignment.policy_hash,
                "--route-policy-digest",
                setup_assignment.route_policy_digest,
                "--expected-assignment-digest",
                setup_assignment.digest,
                "--trust-profile-sha256",
                setup_trust_profile_digest,
                "--verifier-provider",
                setup_trust.provider,
                "--setup-receipt-signing-key",
                str(setup_signing_key_path),
                "--expected-verifier-key-id",
                setup_trust.key_id,
                "--receipt-id",
                setup_receipt_id,
            ]
            setup_receipt_result = subprocess.run(
                setup_receipt_command,
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            if setup_receipt_result.returncode != 0:
                raise AssertionError(f"setup receipt signing failed: {setup_receipt_result.stderr}")
            setup_receipt = json.loads(setup_receipt_result.stdout)
            assert set(setup_receipt) == {
                "apiVersion",
                "kind",
                "statement",
                "signing_key_id",
                "signature",
            }, setup_receipt
            assert "principalId" not in setup_receipt, setup_receipt
            assert "verificationReceipt" not in setup_receipt, setup_receipt
            setup_statement = setup_receipt["statement"]
            expected_setup_receipt = EnrollmentReceiptExpected(
                receipt_id=setup_receipt_id,
                setup_session_id=setup_session_id,
                assignment=setup_assignment,
                enrollment_session_id=setup_enrollment_session_id,
                enrollment_packet_sha256=setup_packet["authenticity"]["statement"]["packetSha256"],
                verifier_nonce_sha256=sha256_digest(NONCE.encode("ascii")),
                trust_profile_sha256=setup_trust_profile_digest,
            )
            verified_setup_receipt = verify_enrollment_verifier_receipt(
                canonical_json_bytes(setup_receipt),
                trust=setup_trust,
                expected=expected_setup_receipt,
                clock=FixedClock(setup_statement["issued_at_unix"]),
            )
            assert verified_setup_receipt.assignment == setup_assignment, verified_setup_receipt
            assert verified_setup_receipt.verifier_key_id == setup_trust.key_id, verified_setup_receipt

            def replace_cli_value(command: list[str], flag: str, value: str) -> list[str]:
                changed = list(command)
                changed[changed.index(flag) + 1] = value
                return changed

            def expect_setup_receipt_failure(command: list[str], message: str) -> None:
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=os.environ.copy(),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == 1, result
                assert not result.stdout, result.stdout
                assert message in result.stderr, result.stderr

            expect_setup_receipt_failure(
                replace_cli_value(
                    setup_receipt_command,
                    "--expected-assignment-digest",
                    "sha256:" + "0" * 64,
                ),
                "expected assignment digest",
            )
            expect_setup_receipt_failure(
                replace_cli_value(
                    setup_receipt_command,
                    "--enrollment-session-id",
                    str(uuid.uuid4()),
                ),
                "does not match the enrollment session",
            )
            substituted_assignment = SetupAssignment(
                principal_id=setup_assignment.principal_id,
                route_id="route.substituted",
                credential_id=setup_assignment.credential_id,
                credential_version=setup_assignment.credential_version,
                policy_hash=setup_assignment.policy_hash,
                route_policy_digest=setup_assignment.route_policy_digest,
            )
            substituted_assignment_command = replace_cli_value(
                setup_receipt_command,
                "--route-id",
                substituted_assignment.route_id,
            )
            substituted_assignment_command = replace_cli_value(
                substituted_assignment_command,
                "--expected-assignment-digest",
                substituted_assignment.digest,
            )
            expect_setup_receipt_failure(
                substituted_assignment_command,
                "route and credential do not match",
            )
            expect_setup_receipt_failure(
                replace_cli_value(
                    setup_receipt_command,
                    "--expected-verifier-key-id",
                    "sha256:" + "0" * 64,
                ),
                "does not match the expected enrollment verifier key ID",
            )
            symlinked_signing_key = Path(tmp) / "setup-enrollment-verifier-symlink.pem"
            symlinked_signing_key.symlink_to(setup_signing_key_path)
            expect_setup_receipt_failure(
                replace_cli_value(
                    setup_receipt_command,
                    "--setup-receipt-signing-key",
                    str(symlinked_signing_key),
                ),
                "non-symlink",
            )
            setup_signing_key_path.chmod(0o644)
            expect_setup_receipt_failure(
                setup_receipt_command,
                "must not be accessible by group or other users",
            )

            substituted_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate_agent_enrollment.py"),
                    "--base",
                    base,
                    "--verify-packet",
                    str(packet_path),
                    "--expected-packet-sha256",
                    "sha256:" + "0" * 64,
                    "--expected-principal",
                    str(packet["principalId"]),
                    "--expected-nonce",
                    NONCE,
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            assert substituted_result.returncode == 1, substituted_result
            assert "does not match the expected file" in substituted_result.stderr, substituted_result.stderr

            tampered_path = Path(tmp) / "tampered-enrollment.json"
            tampered_path.write_text(json.dumps(tampered_packet) + "\n", encoding="utf-8")
            tampered_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate_agent_enrollment.py"),
                    "--base",
                    base,
                    "--verify-packet",
                    str(tampered_path),
                    "--expected-packet-sha256",
                    "sha256:" + hashlib.sha256(tampered_path.read_bytes()).hexdigest(),
                    "--expected-principal",
                    str(tampered_packet["principalId"]),
                    "--expected-nonce",
                    NONCE,
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            assert tampered_result.returncode == 1, tampered_result
            assert not tampered_result.stdout, tampered_result.stdout
            assert "digest mismatch" in tampered_result.stderr, tampered_result.stderr

            generation_result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate_agent_enrollment.py"),
                    "--base",
                    base,
                    "--admin-token",
                    "test-admin-token",
                    "--principal-id",
                    "agent:demo-proxy-token",
                    "--proxy-url",
                    "http://10.42.0.10:8080",
                    "--proxy-egress-cidr",
                    "10.42.0.10/32",
                    "--selector",
                    "app=release-bot",
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )
            if generation_result.returncode != 0:
                raise AssertionError(f"generation mode compatibility failed: {generation_result.stderr}")
            generated_packet = json.loads(generation_result.stdout)
            assert generated_packet["principalId"] == "agent:demo-proxy-token", generated_packet
            assert generated_packet["verificationReceipt"]["nonce"] == generated_packet["nonce"], generated_packet
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

        incomplete_attestation = dict(attestation)
        incomplete_attestation.pop("runtime_manifest_digest")
        try:
            build_agent_enrollment(
                snapshot=snapshot,
                principal_id="agent:demo-proxy-token",
                attestation=incomplete_attestation,
                proxy_url="http://10.42.0.10:8080",
                control_plane_url="https://serverware.example",
                proxy_egress_cidrs=["10.42.0.10/32"],
                nonce=NONCE,
            )
        except AgentEnrollmentError as exc:
            assert "runtimeManifestDigest" in str(exc), exc
        else:
            raise AssertionError("enrollment accepted an attestation without a runtime-manifest pin")

        hostname_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://serverware-proxy.internal:8080",
            control_plane_url="https://serverware.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            namespace="agents",
            pod_selector={"app": "release-bot"},
            nonce=NONCE,
        )
        expected_mapping = [{"ip": "10.42.0.10", "hostnames": ["serverware-proxy.internal"]}]
        assert hostname_packet["serverware"]["proxyHostMappings"] == expected_mapping, hostname_packet
        assert hostname_packet["egress"]["hostAliases"] == expected_mapping, hostname_packet
        assert hostname_packet["egress"]["etcHosts"] == ["10.42.0.10 serverware-proxy.internal"], hostname_packet

        install_session = {
            "id": "install-session-0123456789abcdef",
            "nonce": NONCE,
            "token": "install-token-0123456789abcdef0123456789",
            "tokenHeader": "X-Serverware-CA-Install-Token",
            "policyUrl": "/api/ca/install-sessions/install-session-0123456789abcdef/policy",
            "downloadUrl": "/api/ca/install-sessions/install-session-0123456789abcdef/ca.pem",
            "expiresAt": "2026-07-14T12:00:00+00:00",
        }
        capability_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://SERVERWARE.EXAMPLE:443/",
            proxy_egress_cidrs=["10.42.0.10/32"],
            nonce=NONCE,
            ca_install_session=install_session,
        )
        assert capability_packet["serverware"]["controlPlaneUrl"] == "https://serverware.example"
        assert capability_packet["ca"]["installSession"] == install_session
        assert capability_packet["identity"]["requiredHeaders"] == {
            "X-Serverware-Agent": "demo-token-agent"
        }
        assert capability_packet["agentHandoff"]["requiredProxyHeaders"] == {
            "X-Serverware-Agent": "demo-token-agent",
            "X-Serverware-Enrollment-Session": install_session["id"],
        }
        assert capability_packet["agentHandoff"]["requiredProviderHeaders"] == {
            "X-Serverware-Agent": "demo-token-agent"
        }

        for origin, expected in (
            ("https://SERVERWARE.EXAMPLE:443/", "https://serverware.example"),
            ("https://serverware.example:8443", "https://serverware.example:8443"),
            ("https://[2001:0DB8:0:0:0:0:0:1]:443/", "https://[2001:db8::1]"),
            ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
            ("http://LOCALHOST:80/", "http://localhost"),
            ("http://127.0.0.2:80", "http://127.0.0.2"),
            ("http://[::1]:80/", "http://[::1]"),
        ):
            assert canonical_control_plane_url(origin) == expected, origin

        for invalid_origin in (
            "https://[::1",
            "https://serverware.example:not-a-port",
            "https://server ware.example",
            " https://serverware.example",
            "https://serverware.\u200bexample",
            "https://serverware.example:0",
            "https://bad_label.example",
            "https://-bad.example",
            "https://bad-.example",
            "https://bad..example",
            "https://\ud800.example",
            "http://serverware.example",
            "https://user@serverware.example",
            "https://serverware.example/api",
            "https://serverware.example?mode=enroll",
            "https://serverware.example#enroll",
        ):
            try:
                canonical_control_plane_url(invalid_origin)
            except AgentEnrollmentError:
                pass
            else:
                raise AssertionError(f"accepted invalid control plane origin: {invalid_origin!r}")

        malformed_session = dict(install_session, policyUrl="https://attacker.example/policy")
        try:
            build_agent_enrollment(
                snapshot=snapshot,
                principal_id="agent:demo-proxy-token",
                attestation=attestation,
                proxy_url="http://10.42.0.10:8080",
                control_plane_url="https://serverware.example",
                proxy_egress_cidrs=["10.42.0.10/32"],
                nonce=NONCE,
                ca_install_session=malformed_session,
            )
        except AgentEnrollmentError as exc:
            assert "relative URL" in str(exc), exc
        else:
            raise AssertionError("enrollment accepted an absolute verifier capability URL")

        for kwargs, expected in (
            (
                {
                    "principal_id": "agent:missing",
                    "proxy_egress_cidrs": ["10.42.0.10/32"],
                },
                "principal not found",
            ),
            (
                {
                    "principal_id": "agent:demo",
                    "proxy_egress_cidrs": ["0.0.0.0/0"],
                },
                "universal routes",
            ),
            (
                {
                    "principal_id": "agent:demo",
                    "proxy_egress_cidrs": ["10.42.0.20/32"],
                },
                "not contained",
            ),
            (
                {
                    "principal_id": "agent:demo",
                    "proxy_egress_cidrs": ["10.42.0.10/32"],
                    "ca_mount_path": "../serverware-ca.pem",
                },
                "canonical absolute file path",
            ),
        ):
            try:
                build_agent_enrollment(
                    snapshot=snapshot,
                    attestation=attestation,
                    proxy_url="http://10.42.0.10:8080",
                    control_plane_url="https://serverware.example",
                    namespace="agents",
                    pod_selector={"app": "release-bot"},
                    nonce=NONCE,
                    **kwargs,
                )
            except AgentEnrollmentError as exc:
                assert expected in str(exc), exc
            else:
                raise AssertionError(f"expected enrollment failure containing {expected!r}")

        try:
            build_agent_enrollment(
                snapshot=snapshot,
                principal_id="agent:demo",
                attestation=attestation,
                proxy_url="http://serverware-proxy.internal:8080",
                control_plane_url="https://serverware.example",
                proxy_egress_cidrs=["10.42.0.0/24"],
                nonce=NONCE,
            )
        except AgentEnrollmentError as exc:
            assert "exact /32 or /128" in str(exc), exc
        else:
            raise AssertionError("hostname proxy accepted an unpinned network CIDR without DNS egress")

        try:
            build_agent_enrollment(
                snapshot=snapshot,
                principal_id="agent:demo",
                attestation=attestation,
                proxy_url="http://10.42.0.10:8080",
                control_plane_url="https://serverware.example",
                proxy_egress_cidrs=["10.42.0.10/32"],
                nonce="short",
            )
        except AgentEnrollmentError as exc:
            assert "nonce" in str(exc), exc
        else:
            raise AssertionError("enrollment accepted a short challenge nonce")

    print(canonical_json({"ok": True, "agent_enrollment": "pass"}))


if __name__ == "__main__":
    main()
