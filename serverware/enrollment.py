from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from serverware.policy_bundle import PolicySnapshot


class AgentEnrollmentError(ValueError):
    pass


def _canonical_name(value: str, *, prefix: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    slug = re.sub(r"-+", "-", slug) or "agent"
    name = f"{prefix}-{slug}"
    return name[:63].rstrip("-")


def _validate_cidrs(values: list[str] | tuple[str, ...]) -> list[str]:
    cidrs: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise AgentEnrollmentError(f"invalid proxy egress CIDR: {text}") from exc
        if network.prefixlen == 0:
            raise AgentEnrollmentError("proxy egress CIDRs must not be universal routes")
        cidrs.append(str(network))
    if not cidrs:
        raise AgentEnrollmentError("at least one Serverware proxy egress CIDR is required")
    return cidrs


def _proxy_port(proxy_url: str) -> int:
    parsed = urlsplit(proxy_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AgentEnrollmentError("proxyUrl must be an http or https URL")
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _render_path_template(template: str) -> str:
    return re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "example", template)


def _raw_principal(snapshot: PolicySnapshot, principal_id: str) -> dict[str, Any]:
    for principal in snapshot.raw.get("principals") or []:
        if isinstance(principal, dict) and principal.get("id") == principal_id:
            return principal
    raise AgentEnrollmentError(f"principal not found: {principal_id}")


def _principal_routes(snapshot: PolicySnapshot, principal_id: str) -> list[dict[str, Any]]:
    routes = []
    for route in snapshot.routes:
        if principal_id not in route.principals and "*" not in route.principals:
            continue
        path = _render_path_template(route.path_templates[0])
        routes.append(
            {
                "id": route.id,
                "methods": sorted(route.methods),
                "url": f"{route.scheme}://{route.host}:{route.port}{path}",
                "credentialRef": route.credential_ref,
                "adapter": route.adapter_type,
                "jitRequired": bool(route.jit.get("required")),
            }
        )
    return routes


def _identity_block(raw_principal: dict[str, Any]) -> dict[str, Any]:
    proxy_auth = raw_principal.get("proxyAuthorization")
    safe_proxy_auth = None
    if isinstance(proxy_auth, dict):
        safe_proxy_auth = {
            "scheme": proxy_auth.get("scheme", "Bearer"),
            "tokenId": proxy_auth.get("tokenId"),
            "sourceCidrs": list(proxy_auth.get("sourceCidrs") or []),
            "expiresAtEpochMs": proxy_auth.get("expiresAtEpochMs"),
            "tokenHashConfigured": bool(proxy_auth.get("tokenSha256")),
        }
    elif isinstance(proxy_auth, str):
        safe_proxy_auth = {"legacyExactHeaderRequired": True}

    return {
        "sourceCidrs": list(raw_principal.get("sourceCidrs") or []),
        "requiredHeaders": dict(raw_principal.get("requiredHeaders") or {}),
        "proxyAuthorization": safe_proxy_auth,
        "trustedHeaderInjectionRequired": bool(raw_principal.get("requiredHeaders")),
    }


def _network_policy(
    *,
    name: str,
    namespace: str,
    pod_selector: dict[str, str],
    proxy_cidrs: list[str],
    proxy_port: int,
) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": pod_selector},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [{"ipBlock": {"cidr": cidr}} for cidr in proxy_cidrs],
                    "ports": [{"protocol": "TCP", "port": proxy_port}],
                }
            ],
        },
    }


def _iptables_rules(proxy_cidrs: list[str], proxy_port: int) -> list[str]:
    rules = [
        "iptables -P OUTPUT DROP",
        "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for cidr in proxy_cidrs:
        rules.append(f"iptables -A OUTPUT -p tcp -d {cidr} --dport {proxy_port} -j ACCEPT")
    rules.append('iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited')
    return rules


def build_agent_enrollment(
    *,
    snapshot: PolicySnapshot,
    principal_id: str,
    attestation: dict[str, Any],
    proxy_url: str,
    control_plane_url: str,
    proxy_egress_cidrs: list[str] | tuple[str, ...],
    namespace: str = "serverware-agents",
    pod_selector: dict[str, str] | None = None,
    ca_mount_path: str = "/etc/serverware/serverware-ca.pem",
) -> dict[str, Any]:
    if principal_id not in snapshot.principals:
        raise AgentEnrollmentError(f"principal not found: {principal_id}")
    proxy_cidrs = _validate_cidrs(proxy_egress_cidrs)
    port = _proxy_port(proxy_url)
    selector = dict(pod_selector or {"serverware-principal": _canonical_name(principal_id, prefix="principal")})
    policy_name = _canonical_name(principal_id, prefix="serverware-egress")
    raw_principal = _raw_principal(snapshot, principal_id)
    routes = _principal_routes(snapshot, principal_id)
    metadata = snapshot.raw.get("metadata") or {}
    proxy_host = urlsplit(proxy_url).hostname or ""
    proxy_host_is_ip = True
    try:
        ipaddress.ip_address(proxy_host)
    except ValueError:
        proxy_host_is_ip = False

    return {
        "apiVersion": "serverware.agentEnrollment/v1",
        "kind": "AgentEnrollment",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "principalId": principal_id,
        "serverware": {
            "controlPlaneUrl": control_plane_url.rstrip("/"),
            "proxyUrl": proxy_url,
            "proxyHostIsIpAddress": proxy_host_is_ip,
        },
        "pinning": {
            "policyHash": snapshot.hash,
            "policySigningKeyId": metadata.get("signingKeyId") or attestation.get("policy_signing_key_id"),
            "rollbackEpoch": metadata.get("rollbackEpoch") or attestation.get("rollback_epoch"),
            "releaseChannel": attestation.get("release_channel"),
            "caIntermediateSpkiSha256": attestation.get("ca_intermediate_spki_sha256"),
            "dataPlaneBinaryDigest": attestation.get("data_plane_binary_digest"),
            "provenanceDigest": attestation.get("provenance_digest"),
            "imageSignaturesDigest": attestation.get("image_signatures_digest"),
            "sourceTreeDigest": attestation.get("source_tree_digest"),
        },
        "identity": _identity_block(raw_principal),
        "environment": {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "",
            "SSL_CERT_FILE": ca_mount_path,
            "REQUESTS_CA_BUNDLE": ca_mount_path,
            "NODE_EXTRA_CA_CERTS": ca_mount_path,
        },
        "ca": {
            "installPath": ca_mount_path,
            "installMethod": "verifier-mediated-attestation",
            "spkiSha256": attestation.get("ca_intermediate_spki_sha256"),
        },
        "allowedRoutes": routes,
        "egress": {
            "denyByDefault": True,
            "allowedProxyCidrs": proxy_cidrs,
            "allowedProxyPort": port,
            "kubernetesNetworkPolicy": _network_policy(
                name=policy_name,
                namespace=namespace,
                pod_selector=selector,
                proxy_cidrs=proxy_cidrs,
                proxy_port=port,
            ),
            "iptables": _iptables_rules(proxy_cidrs, port),
            "notes": [
                "Apply the egress policy before injecting credentials or enabling agent traffic.",
                "Use proxy IPs or platform-specific service CIDRs; Kubernetes NetworkPolicy does not enforce FQDN egress.",
            ],
        },
        "canaries": {
            "allow": routes[:3],
            "deny": [
                {
                    "name": "unknown route must fail closed",
                    "method": "GET",
                    "url": "https://example.invalid/serverware-deny-canary",
                    "expectedStatus": 403,
                    "expectedError": "unknown_route_denied",
                }
            ],
        },
    }
