from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from serverware.policy_bundle import PolicySnapshot
from serverware.response_identity import canonical_json, response_public_key_info, sign_statement
from serverware_agent_trust import enrollment_tooling_contract
from serverware_agent_trust.workload_transport import validate_mtls_identity, validate_workload_transport


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
        # Public policy selectors are requirements, not issued credentials or
        # evidence that a trusted ingress completed a client handshake.
        mtls = None
        if raw_principal.get("mtls") is not None:
            try:
                mtls = validate_mtls_identity(raw_principal["mtls"])
            except ValueError as exc:
                raise AgentEnrollmentError(str(exc)) from exc
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
                "mtlsConfigured": mtls is not None,
                "mtls": mtls,
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

    identity = {
        "sourceCidrs": list(raw_principal.get("sourceCidrs") or []),
        "requiredHeaders": dict(raw_principal.get("requiredHeaders") or {}),
        "proxyAuthorization": safe_proxy_auth,
        "trustedHeaderInjectionRequired": bool(raw_principal.get("requiredHeaders")),
    }
    # A null raw policy value means unconfigured, as in policy validation.
    # Only normalized public selectors cross into the signed handoff; never
    # certificate/key material, file paths or arbitrary policy fields.
    if raw_principal.get("mtls") is not None:
        try:
            identity["mtls"] = validate_mtls_identity(raw_principal["mtls"])
        except ValueError as exc:
            raise AgentEnrollmentError(str(exc)) from exc
    return identity


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


def _nftables_firewall(
    *,
    principal_id: str,
    nonce: str,
    proxy_cidrs: list[str],
    proxy_port: int,
) -> dict[str, Any]:
    table_suffix = hashlib.sha256(f"{principal_id}\0{nonce}".encode("utf-8")).hexdigest()[:16]
    table_name = f"sw_agent_{table_suffix}"
    marker_prefix = f"serverware:{table_suffix}"
    allow_rules: list[str] = []
    expected_rule_comments: list[str] = []
    for index, cidr in enumerate(proxy_cidrs):
        network = ipaddress.ip_network(cidr, strict=True)
        address_family = "ip" if network.version == 4 else "ip6"
        comment = f"{marker_prefix}:allow:{index}"
        expected_rule_comments.append(comment)
        allow_rules.append(
            f'        {address_family} daddr {network} tcp dport {proxy_port} '
            f'accept comment "{comment}"'
        )
    deny_comment = f"{marker_prefix}:deny"
    expected_rule_comments.append(deny_comment)
    ruleset_lines = [
        f"table inet {table_name} {{",
        "    chain output {",
        "        type filter hook output priority -10; policy drop;",
        *allow_rules,
        f'        reject comment "{deny_comment}"',
        "    }",
        "}",
    ]
    ruleset = "\n".join(ruleset_lines) + "\n"
    expected_comments_json = json.dumps(expected_rule_comments, separators=(",", ":"))
    apply_script = f"""#!/bin/sh
set -eu

for tool in nft python3 mktemp readlink id uname chmod cat rm; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "required firewall tool is unavailable: $tool" >&2; exit 1; }}
done
[ "$(uname -s)" = Linux ] || {{ echo "nftables enrollment enforcement requires Linux" >&2; exit 1; }}
[ "$(id -u)" -eq 0 ] || {{ echo "nftables enrollment enforcement requires root in the agent network namespace" >&2; exit 1; }}
: "${{SERVERWARE_AGENT_NETNS_ID:?set SERVERWARE_AGENT_NETNS_ID to the launcher-recorded agent network namespace identity}}"
actual_netns="$(readlink /proc/self/ns/net)"
[ "$actual_netns" = "$SERVERWARE_AGENT_NETNS_ID" ] || {{ echo "agent network namespace identity mismatch" >&2; exit 1; }}

table_name={shlex.quote(table_name)}
if nft list table inet "$table_name" >/dev/null 2>&1; then
  echo "refusing to replace an existing firewall table: $table_name" >&2
  exit 1
fi

rules_file="$(mktemp)"
state_file="$(mktemp)"
trap 'rm -f "$rules_file" "$state_file"' EXIT HUP INT TERM
chmod 0600 "$rules_file" "$state_file"
cat >"$rules_file" <<'SERVERWARE_NFT_RULESET'
{ruleset}SERVERWARE_NFT_RULESET

# --check validates the complete dual-stack transaction before any rule is installed.
nft --check --file "$rules_file"
nft --file "$rules_file"
nft --json list table inet "$table_name" >"$state_file"
python3 - "$state_file" "$table_name" {shlex.quote(expected_comments_json)} <<'SERVERWARE_VERIFY_NFT'
import json
import sys

state_path, expected_table, expected_comments_json = sys.argv[1:]
with open(state_path, "r", encoding="utf-8") as handle:
    document = json.load(handle)
objects = document.get("nftables")
if not isinstance(objects, list):
    raise SystemExit("nftables verification output is malformed")
tables = [item.get("table") for item in objects if isinstance(item, dict) and isinstance(item.get("table"), dict)]
chains = [item.get("chain") for item in objects if isinstance(item, dict) and isinstance(item.get("chain"), dict)]
rules = [item.get("rule") for item in objects if isinstance(item, dict) and isinstance(item.get("rule"), dict)]
if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != expected_table:
    raise SystemExit("installed nftables table identity mismatch")
if len(chains) != 1:
    raise SystemExit("installed nftables policy must contain exactly one chain")
chain = chains[0]
if any(chain.get(key) != value for key, value in {{
    "family": "inet",
    "table": expected_table,
    "name": "output",
    "type": "filter",
    "hook": "output",
    "policy": "drop",
}}.items()):
    raise SystemExit("installed nftables output chain is not deny-by-default")
expected_comments = json.loads(expected_comments_json)
actual_comments = [rule.get("comment") for rule in rules]
if sorted(actual_comments) != sorted(expected_comments) or len(actual_comments) != len(expected_comments):
    raise SystemExit("installed nftables rules do not exactly match the enrollment policy")
print(json.dumps({{"ok": True, "backend": "nftables", "table": expected_table}}, sort_keys=True))
SERVERWARE_VERIFY_NFT
"""
    return {
        "backend": "nftables",
        "tableFamily": "inet",
        "tableName": table_name,
        "scope": "launcher-verified-agent-network-namespace",
        "requiredTools": ["nft", "python3", "mktemp", "readlink", "id", "uname", "chmod", "cat", "rm"],
        "ruleset": ruleset,
        "applyAndVerifyScript": apply_script,
        "verification": {
            "required": True,
            "tableFamily": "inet",
            "tableName": table_name,
            "chainName": "output",
            "chainHook": "output",
            "chainPolicy": "drop",
            "expectedRuleComments": expected_rule_comments,
            "failureAction": "do-not-start-agent-and-keep-any-installed-deny-policy-active",
        },
    }


def _safe_allow_canaries(routes: list[dict[str, Any]], *, limit: int = 3) -> list[dict[str, Any]]:
    canaries: list[dict[str, Any]] = []
    for route in routes:
        safe_methods = sorted(set(route.get("methods") or []).intersection({"GET", "HEAD"}))
        urls = route.get("urls") or []
        if not safe_methods or not urls:
            continue
        method = "HEAD" if "HEAD" in safe_methods else "GET"
        canaries.append(
            {
                "name": "allowed non-mutating route must pass policy evaluation",
                "routeId": route.get("id"),
                "method": method,
                "url": urls[0],
                "bodyPolicy": "forbidden",
                "automaticExecution": True,
            }
        )
        if len(canaries) >= limit:
            break
    return canaries


def _write_route_previews(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    previews: list[dict[str, Any]] = []
    for route in routes:
        write_methods = sorted(set(route.get("methods") or []).difference({"GET", "HEAD"}))
        if not write_methods:
            continue
        previews.append(
            {
                "routeId": route.get("id"),
                "methods": write_methods,
                "urls": list(route.get("urls") or []),
                "automaticExecution": False,
                "manualReviewRequired": True,
            }
        )
    return previews


def _render_verified_instructions_bootstrap(packet: dict[str, Any]) -> str:
    principal_id = packet.get("principalId")
    nonce = packet.get("nonce")
    serverware = packet.get("serverware")
    pinning = packet.get("pinning")
    if (
        not isinstance(principal_id, str)
        or not isinstance(nonce, str)
        or not isinstance(serverware, dict)
        or not isinstance(pinning, dict)
    ):
        raise AgentEnrollmentError("enrollment packet cannot render a verified-instructions bootstrap")
    control_plane_url = serverware.get("controlPlaneUrl")
    tooling = packet.get("tooling")
    if not isinstance(control_plane_url, str) or not isinstance(tooling, dict):
        raise AgentEnrollmentError("enrollment packet control plane URL is invalid")
    expected_version_output = tooling.get("expectedVersionOutput")
    if not isinstance(expected_version_output, str):
        raise AgentEnrollmentError("enrollment packet tooling contract is invalid")
    return "\n".join(
        [
            "#!/bin/sh",
            "set -eu",
            "",
            "# Obtain both values from the authenticated portal download response.",
            "# Never calculate SERVERWARE_PACKET_SHA256 from an untrusted packet and trust that same value.",
            ': "${SERVERWARE_PACKET_PATH:?path to the exact packet downloaded from the authenticated portal}"',
            ': "${SERVERWARE_PACKET_SHA256:?authenticated portal SHA-256 for those exact downloaded bytes}"',
            "",
            (
                f"test \"$(serverware-enrollment --version)\" = "
                f"{shlex.quote(expected_version_output)} || "
                "{ echo \"required serverware-enrollment version is unavailable\" >&2; exit 1; }"
            ),
            "",
            "exec serverware-enrollment \\",
            f"  --base {shlex.quote(control_plane_url)} \\",
            '  --verify-packet "$SERVERWARE_PACKET_PATH" \\',
            '  --expected-packet-sha256 "$SERVERWARE_PACKET_SHA256" \\',
            f"  --expected-principal {shlex.quote(principal_id)} \\",
            f"  --expected-nonce {shlex.quote(nonce)} \\",
            "  --emit-verified-instructions",
            "",
            "# The CLI emits agentHandoff.authenticatedInstructions only after checking the exact file digest,",
            "# expected principal, expected nonce, packet signature, live attestation, and every signed pin.",
            f"# Expected signed pin evidence: {canonical_json(pinning)}",
        ]
    ) + "\n"


def render_agent_handoff_instructions(packet: dict[str, Any]) -> str:
    """Render the signed machine-readable handoff without dropping requirements."""
    handoff = packet.get("agentHandoff")
    egress = packet.get("egress")
    canaries = packet.get("canaries")
    serverware = packet.get("serverware")
    if not all(isinstance(value, dict) for value in (handoff, egress, canaries, serverware)):
        raise AgentEnrollmentError("enrollment packet is missing agent handoff requirements")

    def require_mapping(parent: dict[str, Any], field: str) -> dict[str, Any]:
        value = parent.get(field)
        if not isinstance(value, dict):
            raise AgentEnrollmentError(f"agent handoff {field} must be an object")
        return value

    def require_list(parent: dict[str, Any], field: str) -> list[Any]:
        value = parent.get(field)
        if not isinstance(value, list):
            raise AgentEnrollmentError(f"agent handoff {field} must be an array")
        return value

    ca_install = require_mapping(handoff, "caInstall")
    proxy_environment = require_mapping(handoff, "proxyEnvironment")
    proxy_headers = require_mapping(handoff, "requiredProxyHeaders")
    provider_headers = require_mapping(handoff, "requiredProviderHeaders")
    proxy_authorization = require_mapping(handoff, "proxyAuthorization")
    request_handling = require_mapping(handoff, "requestHandling")
    approval = require_mapping(request_handling, "approvalRequired")
    sequence = require_list(handoff, "sequence")
    allowed_urls = require_list(handoff, "allowedUrls")
    egress_notes = require_list(egress, "notes")
    firewall = require_mapping(egress, "firewall")
    firewall_verification = require_mapping(firewall, "verification")
    etc_hosts = require_list(egress, "etcHosts")
    allow_canaries = require_list(canaries, "allow")
    deny_canaries = require_list(canaries, "deny")
    write_route_previews = require_list(canaries, "writeRoutePreviews")
    mtls = None
    identity = packet.get("identity")
    if isinstance(identity, dict) and "mtls" in identity:
        try:
            mtls = validate_mtls_identity(identity["mtls"])
        except ValueError as exc:
            raise AgentEnrollmentError(str(exc)) from exc

    if any(not isinstance(step, str) or not step for step in sequence):
        raise AgentEnrollmentError("agent handoff sequence contains an invalid step")
    if egress.get("denyByDefault") is not True:
        raise AgentEnrollmentError("agent handoff must require deny-by-default egress")
    if firewall.get("backend") != "nftables" or firewall_verification.get("required") is not True:
        raise AgentEnrollmentError("agent handoff must require verified nftables enforcement")
    for canary in allow_canaries:
        if not isinstance(canary, dict):
            raise AgentEnrollmentError("agent handoff allow canary must be an object")
        if canary.get("method") not in {"GET", "HEAD"}:
            raise AgentEnrollmentError("agent handoff allow canaries must use GET or HEAD")
        if canary.get("bodyPolicy") != "forbidden" or canary.get("automaticExecution") is not True:
            raise AgentEnrollmentError("agent handoff allow canaries must forbid request bodies")

    lines = [
        "SERVERWARE AGENT HANDOFF",
        f"Principal: {packet.get('principalId')}",
        f"Control plane: {serverware.get('controlPlaneUrl')}",
        f"Proxy: {serverware.get('proxyUrl')}",
        "",
        "REQUIRED SEQUENCE (SIGNED ORDER)",
    ]
    lines.extend(f"{index}. {step}" for index, step in enumerate(sequence, start=1))
    lines.extend(
        [
            "",
            "CA INSTALLATION",
            f"Verified source: {ca_install.get('verifiedSourcePath')}",
            f"Destination: {ca_install.get('destinationPath')}",
            f"Command: {ca_install.get('command')}",
            "",
            "PROXY ENVIRONMENT",
        ]
    )
    lines.extend(
        f"export {name}={shlex.quote(str(proxy_environment[name]))}"
        for name in sorted(proxy_environment)
    )
    if mtls is not None:
        lines.extend(
            [
                "",
                "PROXY TLS CLIENT IDENTITY",
                f"Exact signed public selectors: {canonical_json(mtls)}",
                "Provision a matching client certificate and its private key separately; this packet contains neither material nor an authorization to issue it.",
                "Provision independently verified outer proxy CA trust separately. The installed provider MITM CA is not implicitly the outer proxy trust root.",
                "Require outer TLS1.3 and verify the proxy server certificate name against the HTTPS proxy authority before sending CONNECT or workload traffic.",
                "Bind this client certificate and private key only to the outer proxy TLS connection. Do not use a provider-TLS client-certificate option or install the private key globally.",
                "Proxy environment variables alone cannot satisfy this identity requirement. Stop if the SDK or its reviewed adapter cannot separately configure outer proxy TLS and inner provider TLS.",
                "Complete this separate provisioning and transport setup before allow/deny canaries or agent startup; these instructions do not assert successful provisioning, handshake or enrollment admission.",
            ]
        )
    lines.extend(
        [
            "",
            f"Required CONNECT proxy headers: {canonical_json(proxy_headers)}",
            f"Required tunneled provider headers: {canonical_json(provider_headers)}",
            "Proxy authorization: "
            f"required={str(bool(proxy_authorization.get('required'))).lower()}, "
            f"provisionSeparately={str(bool(proxy_authorization.get('provisionSeparately'))).lower()}, "
            f"tokenId={proxy_authorization.get('tokenId') or 'none'}",
            "",
            "REQUEST AND ERROR HANDLING",
            "HTTP 428: send "
            f"{approval.get('operatorPathField')} to the operator, honor "
            f"{approval.get('retryAfterField')}, and {approval.get('retryRule')}.",
            "Stop and report status codes: "
            + ", ".join(str(value) for value in request_handling.get("stopAndReportStatusCodes") or []),
            "Stop and report status classes: "
            + ", ".join(f"{value}xx" for value in request_handling.get("stopAndReportStatusClasses") or []),
            f"Bypass forbidden: {str(bool(request_handling.get('bypassForbidden'))).lower()}",
            f"Credential handling: {request_handling.get('credentialHandling')}",
            "",
            "DENY-BY-DEFAULT EGRESS (APPLY BEFORE AGENT START)",
            "Allowed proxy destinations: "
            + ", ".join(
                f"{cidr}:tcp/{egress.get('allowedProxyPort')}"
                for cidr in egress.get("allowedProxyCidrs") or []
            ),
            "Kubernetes NetworkPolicy: " + canonical_json(egress.get("kubernetesNetworkPolicy")),
            "nftables enforcement backend: " + str(firewall.get("backend")),
            "nftables dedicated table: "
            + f"{firewall.get('tableFamily')} {firewall.get('tableName')}",
            "Required enforcement scope: " + str(firewall.get("scope")),
            "Apply and verify the following signed script; a nonzero exit forbids agent startup:",
        ]
    )
    lines.extend(f"  {line}" for line in str(firewall.get("applyAndVerifyScript") or "").splitlines())
    lines.append("Pinned /etc/hosts entries:")
    lines.extend(f"  {entry}" for entry in etc_hosts)
    lines.append("Egress requirements:")
    lines.extend(f"  {note}" for note in egress_notes)
    lines.extend(["", "CANARIES (RUN BEFORE AGENT START)", "ALLOW:"])
    if allow_canaries:
        lines.extend("  " + canonical_json(canary) for canary in allow_canaries)
    else:
        lines.append("  NONE: no explicit GET/HEAD route is assigned; do not execute a write as a canary.")
    lines.append("DENY:")
    for canary in deny_canaries:
        if not isinstance(canary, dict):
            raise AgentEnrollmentError("agent handoff deny canary must be an object")
        lines.append("  " + canonical_json(canary))
    lines.append("WRITE ROUTE PREVIEWS (NEVER AUTOMATICALLY EXECUTE):")
    if write_route_previews:
        lines.extend("  " + canonical_json(preview) for preview in write_route_previews)
    else:
        lines.append("  NONE")
    lines.extend(["", "ALLOWED UPSTREAM URLS"])
    lines.extend(f"  {url}" for url in allowed_urls)
    return "\n".join(lines) + "\n"


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
    if "mtls" in identity and urlsplit(proxy_url).scheme != "https":
        raise AgentEnrollmentError("mTLS principal enrollment requires an HTTPS proxyUrl")
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
    firewall = _nftables_firewall(
        principal_id=principal_id,
        nonce=nonce,
        proxy_cidrs=proxy_cidrs,
        proxy_port=port,
    )
    allow_canaries = _safe_allow_canaries(routes)
    write_route_previews = _write_route_previews(routes)
    issued_at_epoch_ms = int(time.time() * 1000)
    packet = {
        "apiVersion": "serverware.agentEnrollment/v1",
        "kind": "AgentEnrollment",
        "tooling": enrollment_tooling_contract(),
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
            "requestHandling": {
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
            },
            "allowedUrls": [url for route in routes for url in route["urls"]],
            "verificationBinding": {
                "mode": "emit-verified-instructions",
                "installedCli": "serverware-enrollment",
                "toolingContractPath": "tooling",
                "downloadedPacketPathEnvironmentVariable": "SERVERWARE_PACKET_PATH",
                "downloadedPacketSha256EnvironmentVariable": "SERVERWARE_PACKET_SHA256",
                "downloadedPacketSha256Source": "authenticated-portal-metadata-for-exact-download-bytes",
                "portalIntegration": {
                    "digestDomain": "exact-bytes-written-to-downloaded-packet-file",
                    "digestTransport": "authenticated-metadata-separate-from-packet-body",
                    "copyAction": "export-packet-path-and-authenticated-sha256-then-run-instructionsText",
                    "mustNot": "derive-the-expected-digest-from-the-same-untrusted-file-being-verified",
                },
                "expectedPrincipal": principal_id,
                "expectedNonce": nonce,
                "expectedPins": pinning,
                "installedCliInvocation": [
                    "serverware-enrollment",
                    "--base",
                    control_plane_url.rstrip("/"),
                    "--verify-packet",
                    "${SERVERWARE_PACKET_PATH}",
                    "--expected-packet-sha256",
                    "${SERVERWARE_PACKET_SHA256}",
                    "--expected-principal",
                    principal_id,
                    "--expected-nonce",
                    nonce,
                    "--emit-verified-instructions",
                ],
                "authenticatedOutputField": "agentHandoff.authenticatedInstructions",
                "pinVerification": "compare-every-signed-pinning-field-to-fresh-live-attestation-before-output",
                "circularDigestAssumption": False,
            },
            "sequence": [
                "Verify attestation and install the returned CA at destinationPath.",
                "Run the signed nftables applyAndVerifyScript inside the launcher-recorded agent network namespace; any preflight, apply, or verification failure forbids agent startup.",
                "Provision proxy authorization separately when required; it is never embedded here.",
                *(
                    [
                        "Provision the separately held outer proxy TLS client certificate/private key and independently verified proxy CA trust for the signed identity.mtls selectors; require TLS1.3 and proxy server-name verification, and stop unless the SDK or reviewed adapter separates outer proxy TLS from inner provider TLS."
                    ]
                    if "mtls" in identity
                    else []
                ),
                "Set requiredProxyHeaders on CONNECT, requiredProviderHeaders inside the tunnel, and the enrollment header on a direct plain-HTTP proxy request.",
                (
                    "Run only the signed bodyless GET/HEAD allow canaries and the deny canary, then start the agent with normal provider URLs."
                    if allow_canaries
                    else "No automatic allow canary is available; never substitute a write request, record manual review, run the deny canary, and keep the agent stopped until the assignment is approved."
                ),
                "On HTTP 428, send approval_url to the operator, wait for approval, honor retry_after_seconds, and retry only the identical request.",
                "On HTTP 403 or 5xx, stop and report the route and error; never bypass Serverware or request provider credentials.",
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
            "firewall": firewall,
            "hostAliases": host_mappings,
            "etcHosts": [
                f"{mapping['ip']} {' '.join(mapping['hostnames'])}"
                for mapping in host_mappings
            ],
            "notes": [
                "Apply and verify the egress policy before injecting credentials or enabling agent traffic; enrollment fails closed on any nonzero result.",
                "The dedicated nftables table is installed atomically in one inet transaction and does not flush, replace, or change policies on unrelated firewall tables or chains.",
                "Run the firewall installer only inside the launcher-recorded agent network namespace; SERVERWARE_AGENT_NETNS_ID must match /proc/self/ns/net.",
                "Apply hostAliases or etcHosts before deny-by-default egress when proxyUrl uses a hostname.",
                "Proxy hostname mappings are pinned to exact /32 or /128 CIDRs; unrestricted DNS egress is not added.",
            ],
        },
        "canaries": {
            "automaticAllowPolicy": {
                "allowedMethods": ["GET", "HEAD"],
                "requestBodies": "forbidden",
                "writeMethods": "never-automatically-execute",
            },
            "allow": allow_canaries,
            "allowStatus": "ready" if allow_canaries else "manual-review-required-no-safe-route",
            "writeRoutePreviews": write_route_previews,
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
    try:
        validate_workload_transport(packet)
    except ValueError as exc:
        raise AgentEnrollmentError(str(exc)) from exc
    packet["agentHandoff"]["authenticatedInstructions"] = render_agent_handoff_instructions(packet)
    packet["agentHandoff"]["instructionsText"] = _render_verified_instructions_bootstrap(packet)
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
