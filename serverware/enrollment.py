from __future__ import annotations

import ipaddress
import hashlib
import re
import shlex
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from serverware.policy_bundle import PolicySnapshot
from serverware.response_identity import canonical_json, response_public_key_info, sign_statement


class AgentEnrollmentError(ValueError):
    pass


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ENROLLMENT_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
CAPABILITY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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


def canonical_control_plane_url(value: str) -> str:
    text = str(value)
    if any(char.isspace() or unicodedata.category(char).startswith("C") for char in text):
        raise AgentEnrollmentError("control plane URL must not contain whitespace or control characters")
    try:
        parsed = urlsplit(text)
        host = parsed.hostname
    except ValueError as exc:
        raise AgentEnrollmentError("control plane URL is malformed") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or "?" in text
        or "#" in text
        or parsed.path not in {"", "/"}
    ):
        raise AgentEnrollmentError("control plane URL must be a canonical HTTP(S) origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AgentEnrollmentError("control plane URL has an invalid port") from exc
    if port == 0:
        raise AgentEnrollmentError("control plane URL port must be between 1 and 65535")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise AgentEnrollmentError("control plane URL hostname is not valid IDNA") from exc
        labels = canonical_host.split(".")
        if len(canonical_host) > 253 or any(DNS_LABEL_RE.fullmatch(label) is None for label in labels):
            raise AgentEnrollmentError("control plane URL hostname contains an invalid DNS label")
        is_loopback = canonical_host == "localhost"
    else:
        canonical_host = address.compressed
        is_loopback = address.is_loopback
        if isinstance(address, ipaddress.IPv6Address):
            canonical_host = f"[{canonical_host}]"

    if parsed.scheme == "http" and not is_loopback:
        raise AgentEnrollmentError("control plane URL must use HTTPS outside loopback development")
    default_port = 443 if parsed.scheme == "https" else 80
    authority = canonical_host if port in {None, default_port} else f"{canonical_host}:{port}"
    return f"{parsed.scheme}://{authority}"


def _validated_ca_install_session(value: dict[str, Any], *, nonce: str) -> dict[str, Any]:
    required = {"id", "nonce", "token", "tokenHeader", "policyUrl", "downloadUrl", "expiresAt"}
    if set(value) != required:
        raise AgentEnrollmentError("enrollment CA install session fields are invalid")
    if value.get("nonce") != nonce:
        raise AgentEnrollmentError("enrollment CA install session nonce mismatch")
    if (
        not isinstance(value.get("id"), str)
        or re.fullmatch(r"[A-Za-z0-9_-]{24,128}", value["id"]) is None
    ):
        raise AgentEnrollmentError("enrollment CA install session ID is invalid")
    if not isinstance(value.get("token"), str) or not CAPABILITY_TOKEN_RE.fullmatch(value["token"]):
        raise AgentEnrollmentError("enrollment CA install session token is invalid")
    if value.get("tokenHeader") != "X-Serverware-CA-Install-Token":
        raise AgentEnrollmentError("enrollment CA install session token header is invalid")
    for field in ("policyUrl", "downloadUrl"):
        relative = value.get(field)
        parsed = urlsplit(relative) if isinstance(relative, str) else None
        if (
            parsed is None
            or not relative.startswith("/")
            or relative.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise AgentEnrollmentError(f"enrollment CA install session {field} must be a relative URL")
    if not isinstance(value.get("expiresAt"), str) or len(value["expiresAt"]) > 64:
        raise AgentEnrollmentError("enrollment CA install session expiry is invalid")
    return dict(value)


def _proxy_endpoint(proxy_url: str) -> tuple[str, int, bool]:
    parsed = urlsplit(proxy_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AgentEnrollmentError("proxyUrl must be an http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise AgentEnrollmentError("proxyUrl must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise AgentEnrollmentError("proxyUrl must contain only a proxy authority")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise AgentEnrollmentError("proxyUrl port is invalid") from exc
    try:
        ipaddress.ip_address(parsed.hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False
    return parsed.hostname, port, host_is_ip


def _proxy_host_mappings(proxy_host: str, proxy_host_is_ip: bool, proxy_cidrs: list[str]) -> list[dict[str, Any]]:
    networks = [ipaddress.ip_network(value, strict=False) for value in proxy_cidrs]
    if proxy_host_is_ip:
        address = ipaddress.ip_address(proxy_host)
        if not any(address in network for network in networks):
            raise AgentEnrollmentError("proxyUrl IP is not contained in an allowed proxy egress CIDR")
        return []

    host_addresses = [
        str(network.network_address)
        for network in networks
        if network.prefixlen == network.max_prefixlen
    ]
    if not host_addresses:
        raise AgentEnrollmentError(
            "hostname proxyUrl requires at least one exact /32 or /128 proxy egress CIDR for DNS-free pinning"
        )
    return [{"ip": address, "hostnames": [proxy_host]} for address in host_addresses]


def _render_path_template(template: str) -> str:
    return re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "example", template)


def _validate_ca_mount_path(value: str) -> str:
    path = str(value).strip()
    parts = path.split("/")
    if (
        not path.startswith("/")
        or len(path) > 512
        or any(part in {"", ".", ".."} for part in parts[1:-1])
        or not parts[-1]
        or any(ord(char) < 32 for char in path)
    ):
        raise AgentEnrollmentError("caMountPath must be a canonical absolute file path")
    return path


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
        paths = [_render_path_template(template) for template in route.path_templates]
        urls = [f"{route.scheme}://{route.host}:{route.port}{path}" for path in paths]
        routes.append(
            {
                "id": route.id,
                "methods": sorted(route.methods),
                "url": urls[0],
                "urls": urls,
                "paths": paths,
                "credentialRef": route.credential_ref,
                "adapter": route.adapter_type,
                "jitRequired": bool(route.jit.get("required")),
            }
        )
    return routes


def policy_principal_summaries(snapshot: PolicySnapshot) -> list[dict[str, Any]]:
    raw_principals = {
        principal.get("id"): principal
        for principal in (snapshot.raw.get("principals") or [])
        if isinstance(principal, dict) and isinstance(principal.get("id"), str)
    }
    summaries = []
    for principal_id in sorted(snapshot.principals):
        raw_principal = raw_principals.get(principal_id) or {}
        route_count = sum(
            1
            for route in snapshot.routes
            if principal_id in route.principals or "*" in route.principals
        )
        summaries.append(
            {
                "id": principal_id,
                "routeCount": route_count,
                "requiredHeaders": dict(raw_principal.get("requiredHeaders") or {}),
                "sourceCidrs": list(raw_principal.get("sourceCidrs") or []),
                "proxyAuthorizationConfigured": bool(raw_principal.get("proxyAuthorization")),
            }
        )
    return summaries


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


def _required_enrollment_pins(snapshot: PolicySnapshot, attestation: dict[str, Any]) -> dict[str, Any]:
    metadata = snapshot.raw.get("metadata") or {}
    digest_fields = {
        "policySigningKeyId": metadata.get("signingKeyId") or attestation.get("policy_signing_key_id"),
        "caIntermediateSpkiSha256": attestation.get("ca_intermediate_spki_sha256"),
        "dataPlaneBinaryDigest": attestation.get("data_plane_binary_digest"),
        "runtimeManifestDigest": attestation.get("runtime_manifest_digest"),
        "responseSigningKeyId": attestation.get("response_signing_key_id"),
        "provenanceDigest": attestation.get("provenance_digest"),
        "imageSignaturesDigest": attestation.get("image_signatures_digest"),
        "sourceTreeDigest": attestation.get("source_tree_digest"),
        "policyHighWaterDigest": attestation.get("policy_high_water_digest"),
    }
    for label, value in digest_fields.items():
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise AgentEnrollmentError(f"attestation is missing required {label} sha256 pin")
    rollback_epoch = metadata.get("rollbackEpoch") or attestation.get("rollback_epoch")
    if not isinstance(rollback_epoch, int) or isinstance(rollback_epoch, bool) or rollback_epoch < 1:
        raise AgentEnrollmentError("attestation is missing required positive rollbackEpoch pin")
    if attestation.get("rollback_epoch") not in {None, rollback_epoch}:
        raise AgentEnrollmentError("attestation rollback epoch does not match the signed policy")
    policy_sequence = metadata.get("sequence")
    if not isinstance(policy_sequence, int) or isinstance(policy_sequence, bool) or policy_sequence < 1:
        raise AgentEnrollmentError("signed policy is missing a positive sequence")
    if attestation.get("policy_sequence") != policy_sequence:
        raise AgentEnrollmentError("attestation policy sequence does not match the signed policy")
    release_channel = attestation.get("release_channel")
    if not isinstance(release_channel, str) or not release_channel:
        raise AgentEnrollmentError("attestation is missing required releaseChannel pin")
    return {
        "policyHash": snapshot.hash,
        **digest_fields,
        "rollbackEpoch": rollback_epoch,
        "policySequence": policy_sequence,
        "releaseChannel": release_channel,
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
    nonce: str,
    ttl_seconds: int = 300,
    ca_install_session: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if principal_id not in snapshot.principals:
        raise AgentEnrollmentError(f"principal not found: {principal_id}")
    proxy_cidrs = _validate_cidrs(proxy_egress_cidrs)
    if ENROLLMENT_NONCE_RE.fullmatch(nonce) is None:
        raise AgentEnrollmentError("enrollment nonce must be 32-256 base64url characters")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 30 <= ttl_seconds <= 900:
        raise AgentEnrollmentError("enrollment ttlSeconds must be between 30 and 900")
    ca_mount_path = _validate_ca_mount_path(ca_mount_path)
    control_plane_url = canonical_control_plane_url(control_plane_url)
    proxy_host, port, proxy_host_is_ip = _proxy_endpoint(proxy_url)
    host_mappings = _proxy_host_mappings(proxy_host, proxy_host_is_ip, proxy_cidrs)
    selector = dict(pod_selector or {"serverware-principal": _canonical_name(principal_id, prefix="principal")})
    policy_name = _canonical_name(principal_id, prefix="serverware-egress")
    raw_principal = _raw_principal(snapshot, principal_id)
    routes = _principal_routes(snapshot, principal_id)
    identity = _identity_block(raw_principal)
    environment = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "NO_PROXY": "",
        "SSL_CERT_FILE": ca_mount_path,
        "REQUESTS_CA_BUNDLE": ca_mount_path,
        "NODE_EXTRA_CA_CERTS": ca_mount_path,
    }
    validated_install_session = (
        _validated_ca_install_session(ca_install_session, nonce=nonce)
        if ca_install_session is not None
        else None
    )
    required_proxy_headers = dict(identity.get("requiredHeaders") or {})
    if validated_install_session is not None:
        required_proxy_headers["X-Serverware-Enrollment-Session"] = validated_install_session["id"]
    pinning = _required_enrollment_pins(snapshot, attestation)
    issued_at_epoch_ms = int(time.time() * 1000)
    packet = {
        "apiVersion": "serverware.agentEnrollment/v1",
        "kind": "AgentEnrollment",
        "generatedAt": datetime.fromtimestamp(issued_at_epoch_ms / 1000, tz=timezone.utc).isoformat(),
        "issuedAtEpochMs": issued_at_epoch_ms,
        "expiresAtEpochMs": issued_at_epoch_ms + ttl_seconds * 1000,
        "nonce": nonce,
        "principalId": principal_id,
        "serverware": {
            "controlPlaneUrl": control_plane_url.rstrip("/"),
            "proxyUrl": proxy_url,
            "proxyHostIsIpAddress": proxy_host_is_ip,
            "proxyHostMappings": host_mappings,
        },
        "pinning": pinning,
        "identity": identity,
        "environment": environment,
        "ca": {
            "installPath": ca_mount_path,
            "installMethod": "verifier-mediated-attestation",
            "spkiSha256": attestation.get("ca_intermediate_spki_sha256"),
            **(
                {"installSession": validated_install_session}
                if validated_install_session is not None
                else {}
            ),
        },
        "allowedRoutes": routes,
        "agentHandoff": {
            "caInstall": {
                "verifiedSourcePath": ".tmp/serverware-ca.pem",
                "destinationPath": ca_mount_path,
                "command": f"install -D -m 0644 .tmp/serverware-ca.pem {shlex.quote(ca_mount_path)}",
            },
            "proxyEnvironment": environment,
            "requiredProxyHeaders": required_proxy_headers,
            "requiredProviderHeaders": identity.get("requiredHeaders") or {},
            "proxyAuthorization": {
                "required": bool(identity.get("proxyAuthorization")),
                "provisionSeparately": bool(identity.get("proxyAuthorization")),
                "tokenId": (identity.get("proxyAuthorization") or {}).get("tokenId"),
            },
            "allowedUrls": [url for route in routes for url in route["urls"]],
            "sequence": [
                "Verify attestation and install the returned CA at destinationPath.",
                "Apply deny-by-default egress before starting the agent.",
                "Provision proxy authorization separately when required; it is never embedded here.",
                "Set requiredProxyHeaders on CONNECT, requiredProviderHeaders inside the tunnel, and the enrollment header on a direct plain-HTTP proxy request.",
                "Run allow and deny canaries, then start the agent with normal provider URLs.",
            ],
        },
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
            "hostAliases": host_mappings,
            "etcHosts": [
                f"{mapping['ip']} {' '.join(mapping['hostnames'])}"
                for mapping in host_mappings
            ],
            "notes": [
                "Apply the egress policy before injecting credentials or enabling agent traffic.",
                "Apply hostAliases or etcHosts before deny-by-default egress when proxyUrl uses a hostname.",
                "Proxy hostname mappings are pinned to exact /32 or /128 CIDRs; unrestricted DNS egress is not added.",
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
    packet_sha256 = "sha256:" + hashlib.sha256(canonical_json(packet).encode("utf-8")).hexdigest()
    response_key = response_public_key_info()
    if response_key["spki_sha256"] != pinning["responseSigningKeyId"]:
        raise AgentEnrollmentError("enrollment response signing key does not match attestation pin")
    statement = {
        "version": "serverware.agentEnrollmentSignature/v1",
        "packetSha256": packet_sha256,
        "principalId": principal_id,
        "nonce": nonce,
        "issuedAtEpochMs": packet["issuedAtEpochMs"],
        "expiresAtEpochMs": packet["expiresAtEpochMs"],
        "policyHash": pinning["policyHash"],
        "runtimeManifestDigest": pinning["runtimeManifestDigest"],
        "responseSigningKeyId": pinning["responseSigningKeyId"],
    }
    packet["authenticity"] = {
        "statement": statement,
        "statementSha256": "sha256:" + hashlib.sha256(canonical_json(statement).encode("utf-8")).hexdigest(),
        "signature": sign_statement(statement),
    }
    return packet
