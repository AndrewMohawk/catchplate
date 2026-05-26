#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


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

        signed = sign_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
        snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=False)
        attestation = {
            "policy_signing_key_id": (signed.get("metadata") or {}).get("signingKeyId"),
            "rollback_epoch": 1,
            "release_channel": "prod",
            "ca_intermediate_spki_sha256": "sha256:" + "a" * 64,
            "data_plane_binary_digest": "sha256:" + "b" * 64,
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
        )

        assert packet["apiVersion"] == "serverware.agentEnrollment/v1", packet
        assert packet["principalId"] == "agent:demo-proxy-token", packet
        assert packet["pinning"]["policyHash"] == snapshot.hash, packet
        assert packet["identity"]["requiredHeaders"] == {"X-Serverware-Agent": "demo-token-agent"}, packet
        proxy_auth = packet["identity"]["proxyAuthorization"]
        assert proxy_auth["tokenId"] == "demo-sidecar-token", proxy_auth
        serialized = canonical_json(packet)
        assert "demo-agent-proxy-token" not in serialized, serialized
        assert "tokenSha256" not in serialized, serialized
        assert "cred-demo-bearer" in serialized, packet
        assert packet["environment"]["HTTPS_PROXY"] == "http://10.42.0.10:8080", packet
        assert packet["ca"]["installMethod"] == "verifier-mediated-attestation", packet

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
        ):
            try:
                build_agent_enrollment(
                    snapshot=snapshot,
                    attestation=attestation,
                    proxy_url="http://10.42.0.10:8080",
                    control_plane_url="https://serverware.example",
                    namespace="agents",
                    pod_selector={"app": "release-bot"},
                    **kwargs,
                )
            except AgentEnrollmentError as exc:
                assert expected in str(exc), exc
            else:
                raise AssertionError(f"expected enrollment failure containing {expected!r}")

    print(canonical_json({"ok": True, "agent_enrollment": "pass"}))


if __name__ == "__main__":
    main()
