#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
NONCE = "enrollment-test-nonce-0123456789abcdef"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-agent-enrollment-") as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(Path(tmp) / "policy-bundle.json")
        os.environ["SERVERWARE_POLICY_SIGNING_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pem")
        os.environ["SERVERWARE_POLICY_SIGNING_PUBLIC_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pub.pem")

        from serverware.enrollment import AgentEnrollmentError, build_agent_enrollment
        from serverware.policy_bundle import compile_policy_bundle, demo_policy_bundle, sign_policy_bundle
        from serverware.response_identity import response_public_key_info
        from generate_agent_enrollment import verify_packet

        signed = sign_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
        snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=False)
        attestation = {
            "policy_signing_key_id": (signed.get("metadata") or {}).get("signingKeyId"),
            "rollback_epoch": 1,
            "policy_sequence": 1,
            "policy_high_water_digest": "sha256:" + "9" * 64,
            "release_channel": "prod",
            "ca_intermediate_spki_sha256": "sha256:" + "a" * 64,
            "data_plane_binary_digest": "sha256:" + "b" * 64,
            "runtime_manifest_digest": "sha256:" + "f" * 64,
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
        assert handoff["proxyAuthorization"] == {
            "required": True,
            "provisionSeparately": True,
            "tokenId": "demo-sidecar-token",
        }, handoff
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
        verification_attestation = {
            **attestation,
            "nonce": NONCE,
            "policy_bundle_digest": snapshot.hash,
            "response_signing_public_key_pem": response_public_key_info()["pem"],
        }
        receipt = verify_packet(packet, verification_attestation, NONCE)
        assert receipt["packetSha256"] == packet_sha256, receipt
        assert "packet-signature" in receipt["checks"], receipt
        tampered_packet = json.loads(json.dumps(packet))
        tampered_packet["principalId"] = "agent:tampered"
        try:
            verify_packet(tampered_packet, verification_attestation, NONCE)
        except ValueError as exc:
            assert "digest mismatch" in str(exc), exc
        else:
            raise AssertionError("enrollment verifier accepted a tampered signed packet")

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
