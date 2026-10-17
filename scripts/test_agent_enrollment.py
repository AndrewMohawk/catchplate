#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
import http.server
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
NONCE = "enrollment-test-nonce-0123456789abcdef"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def signed_document(
    *,
    api_version: str,
    kind: str,
    statement: dict[str, object],
    signing_key: Ed25519PrivateKey,
) -> dict[str, object]:
    public_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = signing_key.sign(canonical_json(statement).encode("ascii"))
    return {
        "apiVersion": api_version,
        "kind": kind,
        "statement": statement,
        "signing_key_id": "sha256:" + hashlib.sha256(public_der).hexdigest(),
        "signature": "ed25519:"
        + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def main() -> None:
    configured_data_dir = os.environ.get("CATCHPLATE_DATA_DIR")
    temp_parent = (
        configured_data_dir
        if configured_data_dir
        and Path(configured_data_dir).is_dir()
        and os.access(configured_data_dir, os.W_OK)
        else None
    )
    with tempfile.TemporaryDirectory(prefix="catchplate-agent-enrollment-", dir=temp_parent) as tmp:
        for name in tuple(os.environ):
            if name.startswith("CATCHPLATE_"):
                os.environ.pop(name)
        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        os.environ["CATCHPLATE_POLICY_BUNDLE"] = str(Path(tmp) / "policy-bundle.json")
        os.environ["CATCHPLATE_POLICY_SIGNING_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pem")
        os.environ["CATCHPLATE_POLICY_SIGNING_PUBLIC_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pub.pem")
        os.environ["CATCHPLATE_TEE_QUOTE_PROVIDER"] = "dev-signed-quote"

        from catchplate.attestation import sign_quote
        from catchplate.enrollment import (
            AgentEnrollmentError,
            build_agent_enrollment,
            canonical_control_plane_url,
            render_agent_handoff_instructions,
            _safe_allow_canaries,
        )
        from catchplate.policy_bundle import compile_policy_bundle, demo_policy_bundle, sign_policy_bundle
        from catchplate.response_identity import response_public_key_info, sign_statement
        from catchplate_agent_trust import (
            DISTRIBUTION_NAME,
            ENROLLMENT_CLI_COMMAND,
            ENROLLMENT_TOOLING_API_VERSION,
            __version__ as ENROLLMENT_CLI_VERSION,
        )
        from catchplate_agent_trust.receipts import (
            EGRESS_EVIDENCE_API_VERSION,
            Ed25519TrustRoot,
            EnrollmentReceiptExpected,
            FixedClock,
            SetupAssignment,
            canonical_json_bytes,
            sha256_digest,
            verify_agent_egress_evidence,
            verify_enrollment_verifier_receipt,
        )
        from catchplate_agent_trust.attestation import enrollment_install_session, verify_quote
        from catchplate_agent_trust.http import (
            HttpClientError,
            request_bytes as clean_room_request_bytes,
        )
        from generate_agent_enrollment import (
            MAX_ENROLLMENT_PACKET_BYTES,
            enrollment_nonce,
            load_enrollment_packet,
            sign_setup_enrollment_receipt,
            verify_attestation_for_packet,
            verify_downloaded_packet,
            verify_packet,
        )

        signed = sign_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
        snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=False)
        runtime_manifest = {"binary": "catchplate-test", "mode": "agent-enrollment"}
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
            control_plane_url="https://catchplate.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            namespace="agents",
            pod_selector={"app": "release-bot"},
            nonce=NONCE,
        )

        assert packet["apiVersion"] == "catchplate.agentEnrollment/v1", packet
        assert packet["tooling"] == {
            "apiVersion": ENROLLMENT_TOOLING_API_VERSION,
            "command": ENROLLMENT_CLI_COMMAND,
            "distribution": DISTRIBUTION_NAME,
            "version": ENROLLMENT_CLI_VERSION,
            "versionCheck": [ENROLLMENT_CLI_COMMAND, "--version"],
            "expectedVersionOutput": (
                f"{ENROLLMENT_CLI_COMMAND} {ENROLLMENT_CLI_VERSION}"
            ),
        }, packet
        assert packet["principalId"] == "agent:demo-proxy-token", packet
        assert packet["pinning"]["policyHash"] == snapshot.hash, packet
        assert packet["pinning"]["runtimeManifestDigest"] == attestation["runtime_manifest_digest"], packet
        assert packet["pinning"]["responseSigningKeyId"] == attestation["response_signing_key_id"], packet
        assert packet["identity"]["requiredHeaders"] == {"X-Catchplate-Agent": "demo-token-agent"}, packet
        proxy_auth = packet["identity"]["proxyAuthorization"]
        assert proxy_auth["tokenId"] == "demo-sidecar-token", proxy_auth
        serialized = canonical_json(packet)
        assert "demo-agent-proxy-token" not in serialized, serialized
        assert "tokenSha256" not in serialized, serialized
        assert "cred-demo-bearer" in serialized, packet
        assert packet["environment"]["HTTPS_PROXY"] == "http://10.42.0.10:8080", packet
        assert packet["ca"]["installMethod"] == "verifier-mediated-attestation", packet
        assert packet["catchplate"]["proxyHostMappings"] == [], packet
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
        assert handoff["caInstall"]["destinationPath"] == "/etc/catchplate/catchplate-ca.pem", handoff
        assert handoff["caInstall"]["command"].endswith("/etc/catchplate/catchplate-ca.pem"), handoff
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
        instructions = handoff["authenticatedInstructions"]
        assert instructions == render_agent_handoff_instructions(packet), instructions
        sequence_positions = [
            instructions.index(f"{index}. {step}")
            for index, step in enumerate(handoff["sequence"], 1)
        ]
        assert sequence_positions == sorted(sequence_positions), instructions
        assert "DENY-BY-DEFAULT EGRESS (APPLY BEFORE AGENT START)" in instructions, instructions
        assert "CANARIES (RUN BEFORE AGENT START)" in instructions, instructions
        for requirement in packet["egress"]["notes"]:
            assert requirement in instructions, (requirement, instructions)
        firewall = packet["egress"]["firewall"]
        assert firewall["backend"] == "nftables", firewall
        assert firewall["tableFamily"] == "inet", firewall
        assert firewall["scope"] == "launcher-verified-agent-network-namespace", firewall
        assert firewall["verification"]["chainPolicy"] == "drop", firewall
        assert firewall["verification"]["failureAction"].startswith("do-not-start-agent"), firewall
        assert "ip daddr 10.42.0.10/32 tcp dport 8080 accept" in firewall["ruleset"], firewall
        firewall_script = firewall["applyAndVerifyScript"]
        assert "nft --check --file" in firewall_script, firewall_script
        assert "nft --file" in firewall_script, firewall_script
        assert "nft --json list table" in firewall_script, firewall_script
        assert "CATCHPLATE_AGENT_NETNS_ID" in firewall_script, firewall_script
        assert "iptables" not in firewall_script and "flush ruleset" not in firewall_script, firewall_script
        assert "delete table" not in firewall_script and "-P OUTPUT" not in firewall_script, firewall_script
        syntax_result = subprocess.run(
            ["/bin/sh", "-n"],
            input=firewall_script,
            text=True,
            capture_output=True,
            check=False,
        )
        assert syntax_result.returncode == 0, syntax_result.stderr
        missing_tool_result = subprocess.run(
            ["/bin/sh"],
            input=firewall_script,
            env={"PATH": ""},
            text=True,
            capture_output=True,
            check=False,
        )
        assert missing_tool_result.returncode != 0, missing_tool_result
        assert "required firewall tool is unavailable" in missing_tool_result.stderr, missing_tool_result
        for allowed_url in handoff["allowedUrls"]:
            assert allowed_url in instructions, (allowed_url, instructions)
        deny_canary = packet["canaries"]["deny"][0]
        for field in ("url", "expectedError"):
            assert str(deny_canary[field]) in instructions, instructions
        bootstrap = handoff["instructionsText"]
        binding = handoff["verificationBinding"]
        assert binding["mode"] == "emit-verified-instructions", binding
        assert binding["toolingContractPath"] == "tooling", binding
        assert binding["expectedPrincipal"] == packet["principalId"], binding
        assert binding["expectedNonce"] == NONCE, binding
        assert binding["expectedPins"] == packet["pinning"], binding
        assert binding["circularDigestAssumption"] is False, binding
        assert binding["portalIntegration"] == {
            "digestDomain": "exact-bytes-written-to-downloaded-packet-file",
            "digestTransport": "authenticated-metadata-separate-from-packet-body",
            "copyAction": "export-packet-path-and-authenticated-sha256-then-run-instructionsText",
            "mustNot": "derive-the-expected-digest-from-the-same-untrusted-file-being-verified",
        }, binding
        assert binding["pinVerification"].startswith("compare-every-signed-pinning-field"), binding
        assert binding["installedCliInvocation"] == [
            "catchplate-enrollment",
            "--base",
            "https://catchplate.example",
            "--verify-packet",
            "${CATCHPLATE_PACKET_PATH}",
            "--expected-packet-sha256",
            "${CATCHPLATE_PACKET_SHA256}",
            "--expected-principal",
            "agent:demo-proxy-token",
            "--expected-nonce",
            NONCE,
            "--emit-verified-instructions",
        ], binding
        assert 'exec catchplate-enrollment \\' in bootstrap, bootstrap
        assert (
            f'test "$(catchplate-enrollment --version)" = '
            f"'{ENROLLMENT_CLI_COMMAND} {ENROLLMENT_CLI_VERSION}'"
        ) in bootstrap, bootstrap
        assert '--verify-packet "$CATCHPLATE_PACKET_PATH"' in bootstrap, bootstrap
        assert '--expected-packet-sha256 "$CATCHPLATE_PACKET_SHA256"' in bootstrap, bootstrap
        assert "--expected-principal agent:demo-proxy-token" in bootstrap, bootstrap
        assert f"--expected-nonce {NONCE}" in bootstrap, bootstrap
        assert "--emit-verified-instructions" in bootstrap, bootstrap
        assert canonical_json(packet["pinning"]) in bootstrap, bootstrap
        assert "Never calculate CATCHPLATE_PACKET_SHA256" in bootstrap, bootstrap
        bootstrap_syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=bootstrap,
            text=True,
            capture_output=True,
            check=False,
        )
        assert bootstrap_syntax.returncode == 0, bootstrap_syntax.stderr
        assert "tokenSha256" not in bootstrap and "demo-agent-proxy-token" not in bootstrap, bootstrap

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
        assert "iptables" not in packet["egress"], packet
        assert packet["canaries"]["allow"], packet
        for canary in packet["canaries"]["allow"]:
            assert canary["method"] in {"GET", "HEAD"}, canary
            assert canary["bodyPolicy"] == "forbidden", canary
            assert canary["automaticExecution"] is True, canary
            assert not any(key.lower() in {"body", "payload", "data", "json", "form"} for key in canary), canary
        assert packet["canaries"]["automaticAllowPolicy"] == {
            "allowedMethods": ["GET", "HEAD"],
            "requestBodies": "forbidden",
            "writeMethods": "never-automatically-execute",
        }, packet
        assert packet["canaries"]["writeRoutePreviews"], packet
        assert all(item["automaticExecution"] is False for item in packet["canaries"]["writeRoutePreviews"]), packet
        assert _safe_allow_canaries(
            [{"id": "write-only", "methods": ["POST", "PUT", "DELETE"], "urls": ["https://example.test/write"]}]
        ) == []
        mixed_canaries = _safe_allow_canaries(
            [{"id": "mixed", "methods": ["POST", "GET"], "urls": ["https://example.test/resource"]}]
        )
        assert mixed_canaries == [
            {
                "name": "allowed non-mutating route must pass policy evaluation",
                "routeId": "mixed",
                "method": "GET",
                "url": "https://example.test/resource",
                "bodyPolicy": "forbidden",
                "automaticExecution": True,
            }
        ], mixed_canaries
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
        external_attestation = json.loads(json.dumps(verification_attestation))
        external_attestation["quote"] = {
            "provider": "aws-nitro-enclaves",
            "claims": external_attestation["quote"]["claims"],
        }
        verifier_path = Path(tmp) / "external-tee-verifier"
        verifier_source = """#!/usr/bin/env python3
import json
import os
import sys

for forbidden in (
    "ALL_PROXY",
    "HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "PYTHONPATH",
    "CATCHPLATE_VERIFIER_SECRET",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
):
    if forbidden in os.environ:
        raise SystemExit("inherited forbidden environment: " + forbidden)
payload = json.load(sys.stdin)
print(json.dumps({
    "claims": payload["attestation"]["quote"]["claims"],
    "evidence_identity_sha256": "sha256:" + "0" * 64,
    "assurance": {
        "class": "hardware-backed",
        "debug": False,
        "hardware_proof": True,
        "workload_custody_proven": True,
        "tls_peer_binding_proven": True,
        "fact_origin": "independent-verifier",
        "completion_eligible": True
    }
}, sort_keys=True))
"""
        verifier_path.write_text(verifier_source, encoding="utf-8")
        verifier_path.chmod(0o700)
        verifier_identity = sha256_digest(verifier_path.read_bytes())
        hostile_environment = {
            "ALL_PROXY": "http://proxy.invalid:9000",
            "HOME": str(Path(tmp) / "hostile-home"),
            "HTTP_PROXY": "http://proxy.invalid:9000",
            "HTTPS_PROXY": "http://proxy.invalid:9000",
            "NO_PROXY": "",
            "PYTHONPATH": str(Path(tmp) / "hostile-pythonpath"),
            "CATCHPLATE_VERIFIER_SECRET": "must-not-cross-process-boundary",
            "all_proxy": "http://proxy.invalid:9000",
            "http_proxy": "http://proxy.invalid:9000",
            "https_proxy": "http://proxy.invalid:9000",
            "no_proxy": "",
        }
        previous_environment = {name: os.environ.get(name) for name in hostile_environment}
        os.environ.update(hostile_environment)
        try:
            external_verification = verify_quote(
                external_attestation,
                str(verifier_path),
                verifier_identity,
            )
        finally:
            for name, previous in previous_environment.items():
                if previous is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = previous
        assert external_verification["evidence_identity_sha256"] == verifier_identity
        assert external_verification["evidence_identity_sha256"] != "sha256:" + "0" * 64

        race_verifier_path = Path(tmp) / "race-external-tee-verifier"
        race_verifier_path.write_text(verifier_source, encoding="utf-8")
        race_verifier_path.chmod(0o700)
        race_verifier_identity = sha256_digest(race_verifier_path.read_bytes())
        race_marker = Path(tmp) / "race-replacement-verifier-ran"
        race_replacement_path = Path(tmp) / "race-external-tee-verifier-replacement"
        race_replacement_path.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(race_marker)!r}).write_text('invoked', encoding='ascii')\n",
            encoding="utf-8",
        )
        race_replacement_path.chmod(0o700)
        real_subprocess_run = subprocess.run

        def replace_path_at_launch(*args: object, **kwargs: object) -> object:
            os.replace(race_replacement_path, race_verifier_path)
            return real_subprocess_run(*args, **kwargs)

        with mock.patch(
            "catchplate_agent_trust.attestation.subprocess.run",
            side_effect=replace_path_at_launch,
        ):
            race_verification = verify_quote(
                external_attestation,
                str(race_verifier_path),
                race_verifier_identity,
            )
        assert race_verification["evidence_identity_sha256"] == race_verifier_identity
        assert not race_marker.exists()

        verifier_symlink = Path(tmp) / "external-tee-verifier-symlink"
        verifier_symlink.symlink_to(verifier_path)
        try:
            verify_quote(external_attestation, str(verifier_symlink), verifier_identity)
        except ValueError as exc:
            assert "non-symlink" in str(exc), exc
        else:
            raise AssertionError("external TEE verifier accepted a symlink executable")
        try:
            verify_quote(external_attestation, verifier_path.name, verifier_identity)
        except ValueError as exc:
            assert "absolute path" in str(exc), exc
        else:
            raise AssertionError("external TEE verifier accepted a PATH-relative executable")

        verifier_invocation_marker = Path(tmp) / "substituted-verifier-ran"
        verifier_path.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(verifier_invocation_marker)!r}).write_text('invoked', encoding='ascii')\n",
            encoding="utf-8",
        )
        verifier_path.chmod(0o700)
        try:
            verify_quote(external_attestation, str(verifier_path), verifier_identity)
        except ValueError as exc:
            assert "does not match the expected digest" in str(exc), exc
        else:
            raise AssertionError("external TEE verifier accepted a substituted executable")
        assert not verifier_invocation_marker.exists()

        receipt = verify_packet(packet, verification_attestation, NONCE)
        assert receipt["packetSha256"] == packet_sha256, receipt
        assert "packet-signature" in receipt["checks"], receipt
        assert "tooling-contract" in receipt["checks"], receipt
        assert "tooling-version" in receipt["checks"], receipt
        full_receipt = verify_attestation_for_packet(packet, verification_attestation, NONCE, None)
        assert full_receipt["packetSha256"] == packet_sha256, full_receipt

        def resign_enrollment_packet(value: dict[str, object]) -> dict[str, object]:
            resigned = json.loads(json.dumps(value))
            resigned.pop("authenticity", None)
            resigned_packet_sha256 = "sha256:" + hashlib.sha256(
                canonical_json(resigned).encode("utf-8")
            ).hexdigest()
            statement = dict(packet["authenticity"]["statement"])
            statement["packetSha256"] = resigned_packet_sha256
            resigned["authenticity"] = {
                "statement": statement,
                "statementSha256": "sha256:" + hashlib.sha256(
                    canonical_json(statement).encode("utf-8")
                ).hexdigest(),
                "signature": sign_statement(statement),
            }
            return resigned

        missing_tooling_packet = json.loads(json.dumps(packet))
        missing_tooling_packet.pop("tooling")
        missing_tooling_packet = resign_enrollment_packet(missing_tooling_packet)
        try:
            verify_packet(missing_tooling_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "missing the required tooling contract" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a signed packet without tooling")

        wrong_tooling_version_packet = json.loads(json.dumps(packet))
        wrong_tooling_version_packet["tooling"]["version"] = "999.0.0"
        wrong_tooling_version_packet["tooling"]["expectedVersionOutput"] = (
            f"{ENROLLMENT_CLI_COMMAND} 999.0.0"
        )
        wrong_tooling_version_packet = resign_enrollment_packet(wrong_tooling_version_packet)
        try:
            verify_packet(wrong_tooling_version_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "requires catchplate-enrollment version" in str(exc), exc
            assert ENROLLMENT_CLI_VERSION in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a wrong required tooling version")

        open_tooling_schema_packet = json.loads(json.dumps(packet))
        open_tooling_schema_packet["tooling"]["unexpected"] = True
        open_tooling_schema_packet = resign_enrollment_packet(open_tooling_schema_packet)
        try:
            verify_packet(open_tooling_schema_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "closed schema" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted an open tooling contract")
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
            "tokenHeader": "X-Catchplate-CA-Install-Token",
            "policyUrl": f"/api/ca/install-sessions/{setup_enrollment_session_id}/policy",
            "downloadUrl": f"/api/ca/install-sessions/{setup_enrollment_session_id}/ca.pem",
            "expiresAt": "2099-01-01T00:00:00+00:00",
        }
        setup_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://catchplate.example",
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
        setup_public_key_path = Path(tmp) / "setup-enrollment-verifier.pub.pem"
        setup_public_key_path.write_bytes(
            setup_signing_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        egress_signing_key = Ed25519PrivateKey.generate()
        egress_provider = "development-egress-fixture"
        egress_trust = Ed25519TrustRoot(
            egress_provider,
            egress_signing_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        egress_public_key_path = Path(tmp) / "egress-evidence.pub.pem"
        egress_public_key_path.write_bytes(
            egress_signing_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        setup_firewall = setup_packet["egress"]["firewall"]
        setup_firewall_verification = setup_firewall["verification"]
        setup_allow_results = [
            {
                "route_id": canary["routeId"],
                "method": canary["method"],
                "url": canary["url"],
                "outcome": "allowed",
                "status_code": 204,
                "response_evidence_sha256": sha256_digest(
                    f"allow:{canary['routeId']}".encode("utf-8")
                ),
            }
            for canary in setup_packet["canaries"]["allow"]
        ]
        setup_deny_canary = setup_packet["canaries"]["deny"][0]
        setup_deny_result = {
            "method": setup_deny_canary["method"],
            "url": setup_deny_canary["url"],
            "outcome": "denied",
            "status_code": setup_deny_canary["expectedStatus"],
            "error": setup_deny_canary["expectedError"],
            "response_evidence_sha256": sha256_digest(b"deny-canary-response"),
        }
        egress_evidence_id = str(uuid.uuid4())
        egress_statement: dict[str, object] = {
            "evidence_id": egress_evidence_id,
            "packet_sha256": setup_packet["authenticity"]["statement"]["packetSha256"],
            "principal_id": setup_packet["principalId"],
            "enrollment_session_id": setup_enrollment_session_id,
            "evidence_mode": "development-fixture",
            "evidence_provider": egress_provider,
            "launcher_recorded_network_namespace": "net:[4026532999]",
            "observed_network_namespace": "net:[4026532999]",
            "firewall": {
                "backend": setup_firewall["backend"],
                "table_family": setup_firewall["tableFamily"],
                "table_name": setup_firewall["tableName"],
                "chain_name": setup_firewall_verification["chainName"],
                "chain_hook": setup_firewall_verification["chainHook"],
                "chain_policy": setup_firewall_verification["chainPolicy"],
                "ruleset_sha256": sha256_digest(setup_firewall["ruleset"].encode("utf-8")),
                "installed_state_sha256": sha256_digest(b"fixture nft --json installed state"),
                "expected_rule_comments": setup_firewall_verification["expectedRuleComments"],
                "installed": True,
            },
            "allow_canaries": setup_allow_results,
            "deny_canary": setup_deny_result,
            "observed_at_unix": setup_packet["issuedAtEpochMs"] // 1000,
        }
        egress_document = signed_document(
            api_version=EGRESS_EVIDENCE_API_VERSION,
            kind="AgentEgressEvidence",
            statement=egress_statement,
            signing_key=egress_signing_key,
        )
        egress_evidence_path = Path(tmp) / "agent-egress-evidence.json"
        egress_evidence_path.write_bytes(canonical_json_bytes(egress_document))
        verified_egress = verify_agent_egress_evidence(
            egress_evidence_path.read_bytes(),
            trust=egress_trust,
            packet=setup_packet,
            enrollment_session_id=setup_enrollment_session_id,
            allow_development_fixture=True,
        )
        assert verified_egress.evidence_id == egress_evidence_id, verified_egress
        assert verified_egress.network_namespace_sha256 == sha256_digest(
            b"net:[4026532999]"
        ), verified_egress

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
            hostile_proxy_hits: list[str] = []

            class HostileProxyHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, _format: str, *args: object) -> None:
                    return

                def do_GET(self) -> None:
                    hostile_proxy_hits.append(self.path)
                    body = b'{"hostile_proxy":true}\n'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            hostile_proxy = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0), HostileProxyHandler
            )
            hostile_proxy_thread = threading.Thread(
                target=hostile_proxy.serve_forever,
                daemon=True,
            )
            hostile_proxy_thread.start()
            proxy_url = f"http://127.0.0.1:{hostile_proxy.server_port}"
            proxy_environment = {
                "ALL_PROXY": proxy_url,
                "HTTP_PROXY": proxy_url,
                "HTTPS_PROXY": proxy_url,
                "NO_PROXY": "",
                "all_proxy": proxy_url,
                "http_proxy": proxy_url,
                "https_proxy": proxy_url,
                "no_proxy": "",
            }
            previous_proxies = {name: os.environ.get(name) for name in proxy_environment}
            os.environ.update(proxy_environment)
            original_getaddrinfo = socket.getaddrinfo

            def direct_target_getaddrinfo(
                host: str, port: int | str, *args: object, **kwargs: object
            ) -> list[tuple[object, ...]]:
                if host == "direct-target.invalid":
                    host = "127.0.0.1"
                return original_getaddrinfo(host, port, *args, **kwargs)

            try:
                direct_url = (
                    f"http://direct-target.invalid:{server.server_port}"
                    f"/attestation?nonce={NONCE}"
                )
                with mock.patch("socket.getaddrinfo", side_effect=direct_target_getaddrinfo):
                    direct_response = clean_room_request_bytes(
                        direct_url,
                        timeout=5,
                        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
                    )
                assert json.loads(direct_response.body)["nonce"] == NONCE
                assert hostile_proxy_hits == [], hostile_proxy_hits

                token_request = urllib.request.Request(
                    direct_url,
                    headers={"Authorization": "Bearer must-not-cross-plaintext"},
                )
                try:
                    clean_room_request_bytes(
                        token_request,
                        timeout=5,
                        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
                        allow_loopback_http_tokens=True,
                    )
                except HttpClientError as exc:
                    assert "token-bearing plaintext HTTP" in str(exc), exc
                else:
                    raise AssertionError("clean-room HTTP sent a token to non-loopback plaintext")

                loopback_token_request = urllib.request.Request(
                    f"{base}/attestation?nonce={NONCE}",
                    headers={"X-Catchplate-Admin-Token": "loopback-development-token"},
                )
                try:
                    clean_room_request_bytes(
                        loopback_token_request,
                        timeout=5,
                        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
                    )
                except HttpClientError as exc:
                    assert "explicit loopback development" in str(exc), exc
                else:
                    raise AssertionError("clean-room HTTP allowed an implicit plaintext token exception")
                loopback_response = clean_room_request_bytes(
                    loopback_token_request,
                    timeout=5,
                    max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
                    allow_loopback_http_tokens=True,
                )
                assert json.loads(loopback_response.body)["nonce"] == NONCE
                assert hostile_proxy_hits == [], hostile_proxy_hits
            finally:
                for name, previous in previous_proxies.items():
                    if previous is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = previous
                hostile_proxy.shutdown()
                hostile_proxy.server_close()
                hostile_proxy_thread.join(timeout=5)

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
                env={**os.environ, "SOURCE_DATE_EPOCH": "1767225600"},
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

            package_source = Path(tmp) / "package-source"
            package_source.mkdir()
            shutil.copy2(ROOT / "pyproject.toml", package_source / "pyproject.toml")
            shutil.copy2(
                ROOT / "catchplate_agent_trust" / "requirements.lock",
                package_source / "requirements.lock",
            )
            shutil.copytree(ROOT / "catchplate_agent_trust", package_source / "catchplate_agent_trust")
            (package_source / "scripts").mkdir()
            shutil.copy2(
                ROOT / "scripts" / "verify_onboarding_evidence.py",
                package_source / "scripts" / "verify_onboarding_evidence.py",
            )
            wheel_dir = Path(tmp) / "wheel"
            wheel_dir.mkdir()
            packaging_python = getattr(sys, "_base_executable", None) or shutil.which("python3") or sys.executable
            wheel_result = subprocess.run(
                [
                    packaging_python,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-build-isolation",
                    "--no-deps",
                    "--wheel-dir",
                    str(wheel_dir),
                    str(package_source),
                ],
                cwd=Path(tmp),
                env={**os.environ, "SOURCE_DATE_EPOCH": "1767225600"},
                text=True,
                capture_output=True,
                check=False,
            )
            if wheel_result.returncode != 0:
                raise AssertionError(f"clean-room wheel build failed: {wheel_result.stderr}")
            expected_wheel_name = (
                f"catchplate_enrollment-{ENROLLMENT_CLI_VERSION}-py3-none-any.whl"
            )
            wheels = list(wheel_dir.glob("catchplate_enrollment-*.whl"))
            assert [wheel.name for wheel in wheels] == [expected_wheel_name], (
                wheels,
                wheel_result.stdout,
            )
            second_wheel_dir = Path(tmp) / "wheel-second-build"
            second_wheel_dir.mkdir()
            second_wheel_result = subprocess.run(
                [
                    packaging_python,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-build-isolation",
                    "--no-deps",
                    "--wheel-dir",
                    str(second_wheel_dir),
                    str(package_source),
                ],
                cwd=Path(tmp),
                env={**os.environ, "SOURCE_DATE_EPOCH": "1767225600"},
                text=True,
                capture_output=True,
                check=False,
            )
            if second_wheel_result.returncode != 0:
                raise AssertionError(
                    f"second deterministic wheel build failed: {second_wheel_result.stderr}"
                )
            second_wheels = list(second_wheel_dir.glob("catchplate_enrollment-*.whl"))
            assert [wheel.name for wheel in second_wheels] == [expected_wheel_name], second_wheels
            assert wheels[0].name == second_wheels[0].name
            assert wheels[0].read_bytes() == second_wheels[0].read_bytes(), (
                hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
                hashlib.sha256(second_wheels[0].read_bytes()).hexdigest(),
            )

            dependency_wheel_result = subprocess.run(
                [
                    packaging_python,
                    "-m",
                    "pip",
                    "download",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--dest",
                    str(wheel_dir),
                    "--requirement",
                    str(package_source / "requirements.lock"),
                ],
                cwd=Path(tmp),
                text=True,
                capture_output=True,
                check=False,
            )
            if dependency_wheel_result.returncode != 0:
                raise AssertionError(
                    "hash-locked clean-room dependency download failed: "
                    + dependency_wheel_result.stderr
                )

            clean_venv = Path(tmp) / "clean-room-venv"
            venv_result = subprocess.run(
                [packaging_python, "-m", "venv", str(clean_venv)],
                cwd=Path(tmp),
                text=True,
                capture_output=True,
                check=False,
            )
            if venv_result.returncode != 0:
                raise AssertionError(f"clean-room venv creation failed: {venv_result.stderr}")
            clean_bin = clean_venv / ("Scripts" if os.name == "nt" else "bin")
            clean_python = clean_bin / ("python.exe" if os.name == "nt" else "python")
            dependency_install_result = subprocess.run(
                [
                    str(clean_python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(wheel_dir),
                    "--require-hashes",
                    "--requirement",
                    str(package_source / "requirements.lock"),
                ],
                cwd=Path(tmp),
                text=True,
                capture_output=True,
                check=False,
            )
            if dependency_install_result.returncode != 0:
                raise AssertionError(
                    "hash-locked clean-room dependency install failed: "
                    + dependency_install_result.stderr
                )
            install_result = subprocess.run(
                [
                    str(clean_python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(wheel_dir),
                    "--no-deps",
                    str(wheels[0]),
                ],
                cwd=Path(tmp),
                text=True,
                capture_output=True,
                check=False,
            )
            if install_result.returncode != 0:
                raise AssertionError(f"clean-room wheel install failed: {install_result.stderr}")

            clean_env = os.environ.copy()
            clean_env.pop("PYTHONPATH", None)
            clean_env["PYTHONNOUSERSITE"] = "1"
            module_result = subprocess.run(
                [
                    str(clean_python),
                    "-c",
                    "import catchplate_agent_trust.enrollment as m; print(m.__file__)",
                ],
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            assert module_result.returncode == 0, module_result.stderr
            assert str(ROOT) not in module_result.stdout, module_result.stdout

            enrollment_executable = clean_bin / (
                "catchplate-enrollment.exe" if os.name == "nt" else "catchplate-enrollment"
            )
            metadata_result = subprocess.run(
                [
                    str(clean_python),
                    "-c",
                    (
                        "import importlib.metadata as m,json,catchplate_agent_trust as p;"
                        f"d=m.distribution({DISTRIBUTION_NAME!r});"
                        "print(json.dumps({'distributionVersion':d.version,"
                        "'packageVersion':p.__version__,'entryPoints':"
                        "sorted([{'name':e.name,'value':e.value} for e in d.entry_points "
                        "if e.group=='console_scripts'],"
                        "key=lambda e:(e['name'],e['value']))}))"
                    ),
                ],
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            assert metadata_result.returncode == 0, metadata_result.stderr
            installed_metadata = json.loads(metadata_result.stdout)
            assert installed_metadata["distributionVersion"] == ENROLLMENT_CLI_VERSION
            assert installed_metadata["packageVersion"] == ENROLLMENT_CLI_VERSION
            assert {
                "name": ENROLLMENT_CLI_COMMAND,
                "value": "catchplate_agent_trust.enrollment:console_main",
            } in installed_metadata["entryPoints"], installed_metadata
            version_result = subprocess.run(
                [str(enrollment_executable), "--version"],
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            assert version_result.returncode == 0, version_result.stderr
            assert version_result.stdout.strip() == (
                f"{ENROLLMENT_CLI_COMMAND} {ENROLLMENT_CLI_VERSION}"
            ), version_result
            installed_verify_result = subprocess.run(
                [
                    str(enrollment_executable),
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
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            if installed_verify_result.returncode != 0:
                raise AssertionError(
                    f"installed clean-room packet verification failed: {installed_verify_result.stderr}"
                )
            installed_packet = json.loads(installed_verify_result.stdout)
            assert installed_packet["verificationReceipt"]["packetSha256"] == packet_sha256, installed_packet

            installed_instructions_result = subprocess.run(
                [
                    str(enrollment_executable),
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
                    "--emit-verified-instructions",
                ],
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            if installed_instructions_result.returncode != 0:
                raise AssertionError(
                    "installed verified-instructions invocation failed: "
                    + installed_instructions_result.stderr
                )
            assert installed_instructions_result.stdout == handoff["authenticatedInstructions"], (
                installed_instructions_result.stdout,
                handoff["authenticatedInstructions"],
            )

            attestation_executable = clean_bin / (
                "catchplate-attestation.exe" if os.name == "nt" else "catchplate-attestation"
            )
            attestation_help = subprocess.run(
                [str(attestation_executable), "--help"],
                cwd=Path(tmp),
                env=clean_env,
                text=True,
                capture_output=True,
                check=False,
            )
            assert attestation_help.returncode == 0, attestation_help.stderr
            assert "--enrollment-packet" in attestation_help.stdout, attestation_help.stdout

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
                "--egress-evidence",
                str(egress_evidence_path),
                "--egress-evidence-trusted-public-key",
                str(egress_public_key_path),
                "--egress-evidence-provider",
                egress_provider,
                "--expected-egress-evidence-key-id",
                egress_trust.key_id,
                "--development-receipt-fixture",
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
                require_production=False,
            )
            assert verified_setup_receipt.assignment == setup_assignment, verified_setup_receipt
            assert verified_setup_receipt.verifier_key_id == setup_trust.key_id, verified_setup_receipt
            assert verified_setup_receipt.assurance_mode == "development-fixture", verified_setup_receipt
            assert verified_setup_receipt.attestation_evidence["quote_provider"] == "dev-signed-quote"
            assert verified_setup_receipt.attestation_evidence["debug"] is True
            assert verified_setup_receipt.attestation_evidence["self_rooted"] is True
            assert verified_setup_receipt.egress_evidence == verified_egress.as_receipt_binding()

            production_egress_signing_key = Ed25519PrivateKey.generate()
            production_egress_provider = "catchplate-launcher-v1"
            production_egress_trust = Ed25519TrustRoot(
                production_egress_provider,
                production_egress_signing_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            production_egress_public_key_path = (
                Path(tmp) / "production-egress-evidence.pub.pem"
            )
            production_egress_public_key_path.write_bytes(
                production_egress_signing_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            production_egress_statement = json.loads(json.dumps(egress_statement))
            production_egress_statement.update(
                {
                    "evidence_id": str(uuid.uuid4()),
                    "evidence_mode": "production-launcher",
                    "evidence_provider": production_egress_provider,
                }
            )
            production_egress_document = signed_document(
                api_version=EGRESS_EVIDENCE_API_VERSION,
                kind="AgentEgressEvidence",
                statement=production_egress_statement,
                signing_key=production_egress_signing_key,
            )
            production_egress_path = Path(tmp) / "production-agent-egress-evidence.json"
            production_egress_path.write_bytes(
                canonical_json_bytes(production_egress_document)
            )
            verified_production_egress = verify_agent_egress_evidence(
                production_egress_path.read_bytes(),
                trust=production_egress_trust,
                packet=setup_packet,
                enrollment_session_id=setup_enrollment_session_id,
                allow_development_fixture=False,
            )

            production_packet = json.loads(json.dumps(setup_packet))
            production_packet["verificationReceipt"] = {
                "packetSha256": setup_packet["authenticity"]["statement"]["packetSha256"],
                "quoteProvider": "aws-nitro-enclaves",
                "attestationQuoteSha256": sha256_digest(b"production-nitro-quote"),
                "verifiedClaimsSha256": sha256_digest(b"production-verified-claims"),
                "quoteVerifierIdentitySha256": sha256_digest(
                    b"pinned-production-tee-verifier"
                ),
                "quoteSelfRooted": False,
                "quoteDebug": False,
                "attestationAssurance": {
                    "class": "hardware-backed",
                    "debug": False,
                    "hardware_proof": True,
                    "workload_custody_proven": True,
                    "tls_peer_binding_proven": True,
                    "fact_origin": "independent-verifier",
                    "completion_eligible": True,
                },
            }
            production_receipt_id = str(uuid.uuid4())
            production_receipt = sign_setup_enrollment_receipt(
                production_packet,
                setup_session_id=setup_session_id,
                enrollment_session_id=setup_enrollment_session_id,
                assignment=setup_assignment,
                expected_assignment_digest=setup_assignment.digest,
                trust_profile_sha256=setup_trust_profile_digest,
                verifier_provider=setup_trust.provider,
                expected_verifier_key_id=setup_trust.key_id,
                signing_key=setup_signing_key,
                verifier_nonce=NONCE,
                egress_evidence=verified_production_egress,
                development_fixture=False,
                receipt_id=production_receipt_id,
                now_unix=int(time.time()),
            )
            production_packet_path = Path(tmp) / "production-enrollment-packet.json"
            production_packet_path.write_bytes(canonical_json_bytes(setup_packet))
            production_receipt_path = Path(tmp) / "production-enrollment-receipt.json"
            production_receipt_path.write_bytes(canonical_json_bytes(production_receipt))
            expected_production_receipt = EnrollmentReceiptExpected(
                receipt_id=production_receipt_id,
                setup_session_id=setup_session_id,
                assignment=setup_assignment,
                enrollment_session_id=setup_enrollment_session_id,
                enrollment_packet_sha256=setup_packet["authenticity"]["statement"][
                    "packetSha256"
                ],
                verifier_nonce_sha256=sha256_digest(NONCE.encode("ascii")),
                trust_profile_sha256=setup_trust_profile_digest,
            )
            setup_public_key_der = setup_signing_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            for unsafe_receipt_provider in (
                "development-enrollment-verifier",
                "fixture-enrollment-verifier",
                "test-enrollment-verifier",
            ):
                unsafe_provider_statement = json.loads(
                    json.dumps(production_receipt["statement"])
                )
                unsafe_provider_statement["verifier_provider"] = unsafe_receipt_provider
                unsafe_provider_receipt = signed_document(
                    api_version=str(production_receipt["apiVersion"]),
                    kind=str(production_receipt["kind"]),
                    statement=unsafe_provider_statement,
                    signing_key=setup_signing_key,
                )
                try:
                    verify_enrollment_verifier_receipt(
                        canonical_json_bytes(unsafe_provider_receipt),
                        trust=Ed25519TrustRoot(
                            unsafe_receipt_provider,
                            setup_public_key_der,
                        ),
                        expected=expected_production_receipt,
                        clock=FixedClock(unsafe_provider_statement["issued_at_unix"]),
                        require_production=True,
                    )
                except ValueError as exc:
                    assert "development receipt verifier providers" in str(exc), exc
                else:
                    raise AssertionError(
                        "production receipt accepted an unsafe verifier provider: "
                        + unsafe_receipt_provider
                    )
            production_verification_path = Path(tmp) / "production-verification.json"
            production_verification_command = [
                sys.executable,
                str(ROOT / "scripts" / "verify_production_agent_enrollment.py"),
                "--enrollment-packet",
                str(production_packet_path),
                "--expected-enrollment-packet-file-sha256",
                sha256_digest(production_packet_path.read_bytes()),
                "--enrollment-packet-sha256",
                setup_packet["authenticity"]["statement"]["packetSha256"],
                "--receipt",
                str(production_receipt_path),
                "--receipt-trusted-public-key",
                str(setup_public_key_path),
                "--receipt-provider",
                setup_trust.provider,
                "--expected-receipt-key-id",
                setup_trust.key_id,
                "--egress-evidence",
                str(production_egress_path),
                "--egress-evidence-trusted-public-key",
                str(production_egress_public_key_path),
                "--egress-evidence-provider",
                production_egress_provider,
                "--expected-egress-evidence-key-id",
                production_egress_trust.key_id,
                "--receipt-id",
                production_receipt_id,
                "--setup-session-id",
                setup_session_id,
                "--enrollment-session-id",
                setup_enrollment_session_id,
                "--principal-id",
                setup_assignment.principal_id,
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
                "--verifier-nonce-sha256",
                sha256_digest(NONCE.encode("ascii")),
                "--trust-profile-sha256",
                setup_trust_profile_digest,
                "--out",
                str(production_verification_path),
            ]
            production_script_environment = {
                **os.environ,
                "PYTHONPATH": str(ROOT),
            }
            production_verification_result = subprocess.run(
                production_verification_command,
                cwd=ROOT,
                env=production_script_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert production_verification_result.returncode == 0, (
                production_verification_result.stderr
            )
            production_verification = json.loads(production_verification_result.stdout)
            assert production_verification["ok"] is True, production_verification
            assert production_verification["assuranceMode"] == "production"
            assert production_verification["egressEvidenceId"] == (
                production_egress_statement["evidence_id"]
            )
            assert json.loads(production_verification_path.read_text(encoding="ascii"))[
                "receiptId"
            ] == production_receipt_id

            def replaced_command_value(
                command: list[str], flag: str, value: str
            ) -> list[str]:
                changed = list(command)
                changed[changed.index(flag) + 1] = value
                return changed

            development_receipt_path = Path(tmp) / "development-enrollment-receipt.json"
            development_receipt_path.write_bytes(canonical_json_bytes(setup_receipt))
            development_receipt_out = Path(tmp) / "development-receipt-verification.json"
            development_receipt_command = replaced_command_value(
                production_verification_command,
                "--receipt",
                str(development_receipt_path),
            )
            development_receipt_command = replaced_command_value(
                development_receipt_command,
                "--receipt-id",
                setup_receipt_id,
            )
            development_receipt_command = replaced_command_value(
                development_receipt_command,
                "--out",
                str(development_receipt_out),
            )
            development_receipt_result = subprocess.run(
                development_receipt_command,
                cwd=ROOT,
                env=production_script_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert development_receipt_result.returncode == 1, development_receipt_result
            assert "must use production assurance" in development_receipt_result.stderr
            assert not development_receipt_out.exists()

            fixture_egress_out = Path(tmp) / "fixture-egress-verification.json"
            fixture_egress_command = replaced_command_value(
                production_verification_command,
                "--egress-evidence",
                str(egress_evidence_path),
            )
            for flag, value in (
                ("--egress-evidence-trusted-public-key", str(egress_public_key_path)),
                ("--egress-evidence-provider", egress_provider),
                ("--expected-egress-evidence-key-id", egress_trust.key_id),
                ("--out", str(fixture_egress_out)),
            ):
                fixture_egress_command = replaced_command_value(
                    fixture_egress_command,
                    flag,
                    value,
                )
            fixture_egress_result = subprocess.run(
                fixture_egress_command,
                cwd=ROOT,
                env=production_script_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert fixture_egress_result.returncode == 1, fixture_egress_result
            assert "requires non-fixture launcher egress evidence" in fixture_egress_result.stderr
            assert not fixture_egress_out.exists()

            tampered_receipt = json.loads(json.dumps(setup_receipt))
            tampered_receipt["statement"]["attestation_evidence"]["quote_sha256"] = (
                "sha256:" + "0" * 64
            )
            try:
                verify_enrollment_verifier_receipt(
                    canonical_json_bytes(tampered_receipt),
                    trust=setup_trust,
                    expected=expected_setup_receipt,
                    clock=FixedClock(setup_statement["issued_at_unix"]),
                    require_production=False,
                )
            except ValueError as exc:
                assert "signature" in str(exc), exc
            else:
                raise AssertionError("enrollment receipt accepted a changed quote digest")

            for field, value, expected_error in (
                (
                    "observed_network_namespace",
                    "net:[4026533000]",
                    "network namespace",
                ),
                ("allow_canaries", [], "allow canary"),
            ):
                changed_statement = json.loads(json.dumps(egress_statement))
                changed_statement[field] = value
                changed_document = signed_document(
                    api_version=EGRESS_EVIDENCE_API_VERSION,
                    kind="AgentEgressEvidence",
                    statement=changed_statement,
                    signing_key=egress_signing_key,
                )
                try:
                    verify_agent_egress_evidence(
                        canonical_json_bytes(changed_document),
                        trust=egress_trust,
                        packet=setup_packet,
                        enrollment_session_id=setup_enrollment_session_id,
                        allow_development_fixture=True,
                    )
                except ValueError as exc:
                    assert expected_error in str(exc), exc
                else:
                    raise AssertionError(f"egress evidence accepted changed {field}")

            verified_setup_packet = verify_downloaded_packet(
                setup_packet_path,
                base=base,
                tee_verify_command=None,
                expected_packet_sha256="sha256:"
                + hashlib.sha256(setup_packet_path.read_bytes()).hexdigest(),
                expected_principal=setup_assignment.principal_id,
                expected_nonce=NONCE,
            )

            install_base, verified_install_session = enrollment_install_session(
                verified_setup_packet,
                base="https://catchplate.example",
            )
            assert install_base == "https://catchplate.example", install_base
            assert verified_install_session == setup_install_session, verified_install_session

            def resign_verified_enrollment_packet(
                value: dict[str, object],
            ) -> dict[str, object]:
                resigned = json.loads(json.dumps(value))
                receipt = resigned.pop("verificationReceipt")
                authenticity = resigned.pop("authenticity")
                packet_digest = "sha256:" + hashlib.sha256(
                    canonical_json(resigned).encode("utf-8")
                ).hexdigest()
                statement = dict(authenticity["statement"])
                statement["packetSha256"] = packet_digest
                statement_digest = "sha256:" + hashlib.sha256(
                    canonical_json(statement).encode("utf-8")
                ).hexdigest()
                resigned["authenticity"] = {
                    "statement": statement,
                    "statementSha256": statement_digest,
                    "signature": sign_statement(statement),
                }
                receipt["packetSha256"] = packet_digest
                receipt["statementSha256"] = statement_digest
                resigned["verificationReceipt"] = receipt
                return resigned

            def expect_attestation_install_rejection(
                packet_value: dict[str, object],
                expected_error: str,
            ) -> None:
                try:
                    enrollment_install_session(
                        packet_value,
                        base="https://catchplate.example",
                    )
                except ValueError as exc:
                    assert expected_error in str(exc), exc
                else:
                    raise AssertionError(
                        "catchplate-attestation accepted a hostile enrollment packet"
                    )

            missing_tooling_install_packet = json.loads(
                json.dumps(verified_setup_packet)
            )
            missing_tooling_install_packet.pop("tooling")
            expect_attestation_install_rejection(
                resign_verified_enrollment_packet(missing_tooling_install_packet),
                "missing the required tooling contract",
            )

            wrong_tooling_install_packet = json.loads(
                json.dumps(verified_setup_packet)
            )
            wrong_tooling_install_packet["tooling"]["version"] = "999.0.0"
            expect_attestation_install_rejection(
                resign_verified_enrollment_packet(wrong_tooling_install_packet),
                "requires catchplate-enrollment version",
            )

            open_tooling_install_packet = json.loads(json.dumps(verified_setup_packet))
            open_tooling_install_packet["tooling"]["unexpected"] = True
            expect_attestation_install_rejection(
                resign_verified_enrollment_packet(open_tooling_install_packet),
                "closed schema",
            )

            for missing_receipt_check in ("tooling-contract", "tooling-version"):
                missing_check_packet = json.loads(json.dumps(verified_setup_packet))
                missing_check_packet["verificationReceipt"]["checks"].remove(
                    missing_receipt_check
                )
                expect_attestation_install_rejection(
                    missing_check_packet,
                    "missing required tooling checks",
                )

            def expect_production_quote_rejection(
                packet_value: dict[str, object], expected_error: str
            ) -> None:
                try:
                    sign_setup_enrollment_receipt(
                        packet_value,
                        setup_session_id=setup_session_id,
                        enrollment_session_id=setup_enrollment_session_id,
                        assignment=setup_assignment,
                        expected_assignment_digest=setup_assignment.digest,
                        trust_profile_sha256=setup_trust_profile_digest,
                        verifier_provider=setup_trust.provider,
                        expected_verifier_key_id=setup_trust.key_id,
                        signing_key=setup_signing_key,
                        verifier_nonce=NONCE,
                        egress_evidence=verified_egress,
                        development_fixture=False,
                        receipt_id=setup_receipt_id,
                    )
                except ValueError as exc:
                    assert expected_error in str(exc), exc
                else:
                    raise AssertionError("production receipt signing accepted unsafe quote evidence")

            expect_production_quote_rejection(
                verified_setup_packet,
                "development, debug, self-rooted",
            )
            debug_packet = json.loads(json.dumps(verified_setup_packet))
            debug_verification = debug_packet["verificationReceipt"]
            debug_verification.update(
                {
                    "quoteProvider": "aws-nitro-enclaves",
                    "quoteVerifierIdentitySha256": "sha256:" + "1" * 64,
                    "quoteSelfRooted": False,
                    "quoteDebug": True,
                    "attestationAssurance": {
                        "class": "hardware-backed",
                        "debug": True,
                        "hardware_proof": True,
                        "workload_custody_proven": True,
                        "tls_peer_binding_proven": True,
                        "fact_origin": "independent-verifier",
                        "completion_eligible": True,
                    },
                }
            )
            expect_production_quote_rejection(
                debug_packet,
                "development, debug, self-rooted",
            )
            self_rooted_packet = json.loads(json.dumps(debug_packet))
            self_rooted_verification = self_rooted_packet["verificationReceipt"]
            self_rooted_verification["quoteDebug"] = False
            self_rooted_verification["quoteSelfRooted"] = True
            self_rooted_verification["attestationAssurance"]["debug"] = False
            expect_production_quote_rejection(
                self_rooted_packet,
                "development, debug, self-rooted",
            )

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

            production_without_verifier_pin = list(setup_receipt_command)
            production_without_verifier_pin.remove("--development-receipt-fixture")
            production_without_verifier_pin.extend(
                ["--tee-verify-command", str(verifier_path)]
            )
            expect_setup_receipt_failure(
                production_without_verifier_pin,
                "production receipt signing requires --expected-tee-verifier-identity-sha256",
            )
            assert not verifier_invocation_marker.exists()

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
                "egress evidence enrollment session mismatch",
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
                control_plane_url="https://catchplate.example",
                proxy_egress_cidrs=["10.42.0.10/32"],
                nonce=NONCE,
            )
        except AgentEnrollmentError as exc:
            assert "runtimeManifestDigest" in str(exc), exc
        else:
            raise AssertionError("enrollment accepted an attestation without a runtime-manifest pin")

        write_only_raw = demo_policy_bundle("cred-demo-bearer")
        write_only_raw["routes"] = [
            route for route in write_only_raw["routes"] if route.get("id") == "demo.upload.stream"
        ]
        write_only_signed = sign_policy_bundle(write_only_raw)
        write_only_snapshot = compile_policy_bundle(
            write_only_signed,
            verify_signature=True,
            validate_schema=False,
        )
        write_only_attestation = dict(
            attestation,
            policy_signing_key_id=(write_only_signed.get("metadata") or {}).get("signingKeyId"),
            policy_sequence=(write_only_signed.get("metadata") or {}).get("sequence"),
        )
        write_only_packet = build_agent_enrollment(
            snapshot=write_only_snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=write_only_attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://catchplate.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            nonce=NONCE,
        )
        assert write_only_packet["canaries"]["allow"] == [], write_only_packet
        assert write_only_packet["canaries"]["allowStatus"] == "manual-review-required-no-safe-route", write_only_packet
        assert write_only_packet["canaries"]["writeRoutePreviews"], write_only_packet
        assert all(
            preview["automaticExecution"] is False
            for preview in write_only_packet["canaries"]["writeRoutePreviews"]
        ), write_only_packet
        write_only_instructions = write_only_packet["agentHandoff"]["authenticatedInstructions"]
        assert "do not execute a write as a canary" in write_only_instructions, write_only_instructions
        assert "never substitute a write request" in " ".join(
            write_only_packet["agentHandoff"]["sequence"]
        ), write_only_packet

        dual_stack_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://catchplate.example",
            proxy_egress_cidrs=["10.42.0.10/32", "2001:db8::10/128"],
            nonce=NONCE,
        )
        dual_stack_ruleset = dual_stack_packet["egress"]["firewall"]["ruleset"]
        assert "ip daddr 10.42.0.10/32 tcp dport 8080 accept" in dual_stack_ruleset, dual_stack_ruleset
        assert "ip6 daddr 2001:db8::10/128 tcp dport 8080 accept" in dual_stack_ruleset, dual_stack_ruleset
        assert dual_stack_ruleset.count("table inet ") == 1, dual_stack_ruleset

        hostname_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://catchplate-proxy.internal:8080",
            control_plane_url="https://catchplate.example",
            proxy_egress_cidrs=["10.42.0.10/32"],
            namespace="agents",
            pod_selector={"app": "release-bot"},
            nonce=NONCE,
        )
        expected_mapping = [{"ip": "10.42.0.10", "hostnames": ["catchplate-proxy.internal"]}]
        assert hostname_packet["catchplate"]["proxyHostMappings"] == expected_mapping, hostname_packet
        assert hostname_packet["egress"]["hostAliases"] == expected_mapping, hostname_packet
        assert hostname_packet["egress"]["etcHosts"] == ["10.42.0.10 catchplate-proxy.internal"], hostname_packet

        install_session = {
            "id": "install-session-0123456789abcdef",
            "nonce": NONCE,
            "token": "install-token-0123456789abcdef0123456789",
            "tokenHeader": "X-Catchplate-CA-Install-Token",
            "policyUrl": "/api/ca/install-sessions/install-session-0123456789abcdef/policy",
            "downloadUrl": "/api/ca/install-sessions/install-session-0123456789abcdef/ca.pem",
            "expiresAt": "2026-07-14T12:00:00+00:00",
        }
        capability_packet = build_agent_enrollment(
            snapshot=snapshot,
            principal_id="agent:demo-proxy-token",
            attestation=attestation,
            proxy_url="http://10.42.0.10:8080",
            control_plane_url="https://CATCHPLATE.EXAMPLE:443/",
            proxy_egress_cidrs=["10.42.0.10/32"],
            nonce=NONCE,
            ca_install_session=install_session,
        )
        assert capability_packet["catchplate"]["controlPlaneUrl"] == "https://catchplate.example"
        assert capability_packet["ca"]["installSession"] == install_session
        assert capability_packet["identity"]["requiredHeaders"] == {
            "X-Catchplate-Agent": "demo-token-agent"
        }
        assert capability_packet["agentHandoff"]["requiredProxyHeaders"] == {
            "X-Catchplate-Agent": "demo-token-agent",
            "X-Catchplate-Enrollment-Session": install_session["id"],
        }
        assert capability_packet["agentHandoff"]["requiredProviderHeaders"] == {
            "X-Catchplate-Agent": "demo-token-agent"
        }

        for origin, expected in (
            ("https://CATCHPLATE.EXAMPLE:443/", "https://catchplate.example"),
            ("https://catchplate.example:8443", "https://catchplate.example:8443"),
            ("https://[2001:0DB8:0:0:0:0:0:1]:443/", "https://[2001:db8::1]"),
            ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
            ("http://LOCALHOST:80/", "http://localhost"),
            ("http://127.0.0.2:80", "http://127.0.0.2"),
            ("http://[::1]:80/", "http://[::1]"),
        ):
            assert canonical_control_plane_url(origin) == expected, origin

        for invalid_origin in (
            "https://[::1",
            "https://catchplate.example:not-a-port",
            "https://server ware.example",
            " https://catchplate.example",
            "https://catchplate.\u200bexample",
            "https://catchplate.example:0",
            "https://bad_label.example",
            "https://-bad.example",
            "https://bad-.example",
            "https://bad..example",
            "https://\ud800.example",
            "http://catchplate.example",
            "https://user@catchplate.example",
            "https://catchplate.example/api",
            "https://catchplate.example?mode=enroll",
            "https://catchplate.example#enroll",
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
                control_plane_url="https://catchplate.example",
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
                    "proxy_egress_cidrs": ["::/0"],
                },
                "universal routes",
            ),
            (
                {
                    "principal_id": "agent:demo",
                    "proxy_egress_cidrs": ["not-a-cidr"],
                },
                "invalid proxy egress CIDR",
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
                    "ca_mount_path": "../catchplate-ca.pem",
                },
                "canonical absolute file path",
            ),
        ):
            try:
                build_agent_enrollment(
                    snapshot=snapshot,
                    attestation=attestation,
                    proxy_url="http://10.42.0.10:8080",
                    control_plane_url="https://catchplate.example",
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
                proxy_url="http://catchplate-proxy.internal:8080",
                control_plane_url="https://catchplate.example",
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
                control_plane_url="https://catchplate.example",
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
