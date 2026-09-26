"""Internal extraction from a genuinely authenticated enrollment packet.

Only the same-call pinned-key enrollment verifier may supply this input. This
module does not authenticate a dict, trust a verificationReceipt, execute any
handoff commands, or establish CA, firewall, credential or production admission.
The copied settings remain requirements; the client-material owner separately
joins actual certificates/keys and anchors the retained expiry monotonically.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ._workload_http import encode_connect, encode_request
from ._workload_stream import Budget, WorkloadClientError, _endpoint, _require_name
from .workload_transport import validate_mtls_identity, validate_workload_transport


_MAX_FIELDS = 128
_MAX_TEXT = 4096
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_SESSION = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")
_BEARER = re.compile(r"Bearer [A-Za-z0-9._~+/-]+=*\Z")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)\Z"
)
_SESSION_HEADER = "x-serverware-enrollment-session"


@dataclass(frozen=True, repr=False)
class WorkloadHandoff:
    proxy_ip: str
    proxy_port: int
    proxy_server_name: str
    proxy_headers: tuple[tuple[str, str], ...]
    provider_headers: tuple[tuple[str, str], ...]
    mtls: dict[str, object]
    interception_ca_spki_sha256: str
    issued_at_epoch_ms: int
    expires_at_epoch_ms: int
    principal_id: str
    nonce: str


def _object(value: object, label: str, *, exact: set[str] | None = None) -> dict:
    if (
        type(value) is not dict or len(value) > _MAX_FIELDS
        or any(type(key) is not str for key in value)
        or (exact is not None and set(value) != exact)
    ):
        raise WorkloadClientError(f"signed workload {label} has an unsupported object shape")
    return value


def _text(value: object, label: str, maximum: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str or not 1 <= len(value) <= maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WorkloadClientError(f"signed workload {label} is not bounded text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise WorkloadClientError(f"signed workload {label} is not UTF-8") from exc
    if size > maximum:
        raise WorkloadClientError(f"signed workload {label} exceeds its byte bound")
    return value


def _timestamp(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= (1 << 63) - 1:
        raise WorkloadClientError(f"signed workload {label} is not a bounded positive timestamp")
    return value


def _session_expiry(value: object) -> int:
    text = _text(value, "CA install session expiry", 64)
    if _UTC_TIMESTAMP.fullmatch(text) is None:
        raise WorkloadClientError("signed workload CA install session expiry must be UTC RFC3339")
    try:
        instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
        elapsed = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise WorkloadClientError("signed workload CA install session expiry is invalid") from exc
    # Integer arithmetic never rounds a fractional expiry into a later instant.
    milliseconds = (elapsed.days * 86_400 + elapsed.seconds) * 1000 + elapsed.microseconds // 1000
    return _timestamp(milliseconds, "CA install session expiry")


def _headers(value: object, label: str, budget: Budget) -> dict[str, str]:
    fields = _object(value, label)
    result: dict[str, str] = {}
    total = 0
    for name, item in fields.items():
        budget.check()
        if type(item) is not str or len(name) > 32 * 1024 or len(item) > 32 * 1024:
            raise WorkloadClientError(f"signed workload {label} contains oversized/nontext fields")
        lower = name.lower()
        if lower in result:
            raise WorkloadClientError(f"signed workload {label} repeats a case-insensitive name")
        total += len(name) + len(item) + 4
        if total > 32 * 1024:
            raise WorkloadClientError(f"signed workload {label} exceeds its header byte bound")
        result[lower] = item
    return result


def _networks(value: object, budget: Budget) -> list:
    if type(value) is not list or not 1 <= len(value) <= _MAX_FIELDS:
        raise WorkloadClientError("signed workload proxy CIDR inventory must contain 1..128 entries")
    networks = []
    for item in value:
        budget.check()
        text = _text(item, "proxy CIDR", 64)
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            raise WorkloadClientError("signed workload proxy CIDR is not canonical") from exc
        if str(network) != text or network.prefixlen == 0:
            raise WorkloadClientError("signed workload proxy CIDR is noncanonical or universal")
        networks.append(network)
    return networks


def _source_cidrs(value: object, budget: Budget) -> None:
    # These remain requirements on trusted ingress's actual peer. Validating
    # their signed shape is not evidence of this client's observed source IP.
    if type(value) is not list or len(value) > _MAX_FIELDS:
        raise WorkloadClientError("signed workload source CIDR inventory exceeds its bound")
    for source in value:
        budget.check()
        try:
            text = _text(source, "source CIDR", 64)
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            raise WorkloadClientError("signed workload source CIDR is invalid") from exc
        if str(network) != text:
            raise WorkloadClientError("signed workload source CIDR is not canonical")


def _proxy(packet: dict, proxy_ip: str, budget: Budget) -> tuple[str, int]:
    serverware = _object(packet.get("serverware"), "serverware", exact={
        "controlPlaneUrl", "proxyUrl", "proxyHostIsIpAddress", "proxyHostMappings",
    })
    proxy_url = _text(serverware.get("proxyUrl"), "proxy URL")
    parsed = urlsplit(proxy_url)
    name = parsed.hostname
    if name is None:
        raise WorkloadClientError("signed workload proxy name is absent")
    _require_name(name)
    port = parsed.port or 443  # validate_workload_transport already denies port zero.
    _endpoint((proxy_ip, port))
    address = ipaddress.ip_address(proxy_ip)
    egress = _object(packet.get("egress"), "egress")
    if egress.get("denyByDefault") is not True:
        raise WorkloadClientError("signed workload egress must require deny-by-default")
    if type(egress.get("allowedProxyPort")) is not int or egress["allowedProxyPort"] != port:
        raise WorkloadClientError("signed workload proxy port differs from its egress port")
    networks = _networks(egress.get("allowedProxyCidrs"), budget)
    if not any(address.version == network.version and address in network for network in networks):
        raise WorkloadClientError("selected workload proxy IP is outside the signed CIDRs")
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        literal = None
    if type(serverware.get("proxyHostIsIpAddress")) is not bool or (
        serverware["proxyHostIsIpAddress"] != (literal is not None)
    ):
        raise WorkloadClientError("signed workload proxy address classification differs")
    expected_mappings = [] if literal is not None else [
        {"ip": str(network.network_address), "hostnames": [name]}
        for network in networks if network.prefixlen == network.max_prefixlen
    ]
    mappings = serverware.get("proxyHostMappings")
    aliases = egress.get("hostAliases")
    hosts = egress.get("etcHosts")
    if any(type(value) is not list or len(value) > _MAX_FIELDS for value in (mappings, aliases, hosts)):
        raise WorkloadClientError("signed workload host-mapping inventories exceed their bounds")
    for mapping in mappings:
        budget.check()
        _object(mapping, "proxy host mapping", exact={"ip", "hostnames"})
        _text(mapping.get("ip"), "mapped proxy IP", 45)
        if type(mapping.get("hostnames")) is not list or mapping["hostnames"] != [name]:
            raise WorkloadClientError("signed workload proxy mapping names differ")
    expected_hosts = [f"{mapping['ip']} {name}" for mapping in expected_mappings]
    if mappings != expected_mappings or aliases != expected_mappings or hosts != expected_hosts:
        raise WorkloadClientError("signed workload proxy mappings, host aliases or hosts entries differ")
    if literal is not None:
        if address != literal:
            raise WorkloadClientError("selected workload proxy IP differs from the signed literal URL")
    elif not expected_mappings or not any(mapping["ip"] == proxy_ip for mapping in expected_mappings):
        raise WorkloadClientError("selected workload proxy IP is not an exact signed hostname mapping")
    return name, port


def _authorization(identity: dict, handoff: dict, supplied: str | None,
                   expires: int, budget: Budget) -> tuple[str | None, int]:
    metadata = identity.get("proxyAuthorization")
    required = metadata is not None
    instruction = _object(handoff.get("proxyAuthorization"), "proxy authorization", exact={
        "required", "provisionSeparately", "tokenId",
    })
    if instruction.get("required") is not required or instruction.get("provisionSeparately") is not required:
        raise WorkloadClientError("signed workload proxy authorization requirements differ")
    if not required:
        if instruction.get("tokenId") is not None or supplied is not None:
            raise WorkloadClientError("workload cannot supply unsigned proxy authorization")
        return None, expires
    metadata = _object(metadata, "proxy authorization metadata")
    if type(supplied) is not str or not 1 <= len(supplied) <= _MAX_TEXT or supplied != supplied.strip():
        raise WorkloadClientError("required workload proxy authorization must be separately supplied")
    if set(metadata) == {"legacyExactHeaderRequired"}:
        if metadata["legacyExactHeaderRequired"] is not True or instruction.get("tokenId") is not None:
            raise WorkloadClientError("legacy workload proxy authorization cannot declare a token ID")
        # The packet deliberately contains no legacy secret to compare here.
        # The actual trusted proxy must verify the separately supplied header.
        return supplied, expires
    _object(metadata, "Bearer authorization metadata", exact={
        "scheme", "tokenId", "sourceCidrs", "expiresAtEpochMs", "tokenHashConfigured",
    })
    if metadata.get("scheme") != "Bearer" or _BEARER.fullmatch(supplied) is None:
        raise WorkloadClientError("workload proxy authorization must be one exact Bearer token")
    if type(metadata.get("tokenHashConfigured")) is not bool:
        raise WorkloadClientError("signed workload token-hash requirement is malformed")
    token_id = metadata.get("tokenId")
    if token_id is not None:
        _text(token_id, "proxy token ID", 512)
    if instruction.get("tokenId") != token_id:
        raise WorkloadClientError("signed workload proxy token IDs differ")
    _source_cidrs(metadata.get("sourceCidrs"), budget)
    if metadata.get("expiresAtEpochMs") is not None:
        expires = min(expires, _timestamp(metadata["expiresAtEpochMs"], "proxy token expiry"))
    return supplied, expires


def extract_workload_handoff(packet: dict[str, object], *, proxy_ip: str,
                             proxy_authorization: str | None, budget: Budget) -> WorkloadHandoff:
    """Extract requirements only after genuine same-call packet authentication."""
    budget.check()
    packet = _object(packet, "packet")
    if packet.get("apiVersion") != "serverware.agentEnrollment/v1" or packet.get("kind") != "AgentEnrollment":
        raise WorkloadClientError("signed workload enrollment version differs")
    identity = _object(packet.get("identity"), "identity", exact={
        "sourceCidrs", "requiredHeaders", "proxyAuthorization", "trustedHeaderInjectionRequired", "mtls",
    })
    try:
        validate_workload_transport(packet)
        mtls = validate_mtls_identity(identity["mtls"])
    except ValueError as exc:
        raise WorkloadClientError(str(exc)) from exc
    _source_cidrs(identity.get("sourceCidrs"), budget)
    budget.check()
    name, port = _proxy(packet, proxy_ip, budget)
    principal = _text(packet.get("principalId"), "principal", 1024)
    nonce = _text(packet.get("nonce"), "nonce", 256)
    if _NONCE.fullmatch(nonce) is None:
        raise WorkloadClientError("signed workload nonce is invalid")
    issued = _timestamp(packet.get("issuedAtEpochMs"), "issuance")
    expires = _timestamp(packet.get("expiresAtEpochMs"), "expiry")
    if not 1 <= expires - issued <= 900_000:
        raise WorkloadClientError("signed workload enrollment lifetime exceeds its bound")
    handoff = _object(packet.get("agentHandoff"), "agent handoff")
    required = _headers(identity.get("requiredHeaders"), "identity headers", budget)
    provider = _headers(handoff.get("requiredProviderHeaders"), "provider headers", budget)
    proxy = _headers(handoff.get("requiredProxyHeaders"), "proxy headers", budget)
    if provider != required or identity.get("trustedHeaderInjectionRequired") is not bool(required):
        raise WorkloadClientError("signed workload identity/provider header copies differ")
    # Reuse the actual request encoder for syntax, framing and proxy-only field
    # restrictions. No bytes are sent and no provider target is admitted here.
    encode_request("GET", "/", "validation.invalid:443", provider, b"")
    ca = _object(packet.get("ca"), "interception CA")
    pinning = _object(packet.get("pinning"), "measurement pins")
    ca_spki = _text(ca.get("spkiSha256"), "interception CA SPKI", 71)
    if _SHA256.fullmatch(ca_spki) is None or pinning.get("caIntermediateSpkiSha256") != ca_spki:
        raise WorkloadClientError("signed workload interception CA pins differ")
    expected_proxy = dict(required)
    if "installSession" in ca:
        session = _object(ca["installSession"], "CA install session", exact={
            "id", "nonce", "token", "tokenHeader", "policyUrl", "downloadUrl", "expiresAt",
        })
        session_id = _text(session.get("id"), "enrollment session ID", 128)
        if _SESSION.fullmatch(session_id) is None or session.get("nonce") != nonce:
            raise WorkloadClientError("signed workload enrollment session ID or nonce differs")
        expected_proxy[_SESSION_HEADER] = session_id
        expires = min(expires, _session_expiry(session.get("expiresAt")))
    if proxy != expected_proxy:
        raise WorkloadClientError("signed workload proxy headers differ from identity/session requirements")
    authorization, expires = _authorization(identity, handoff, proxy_authorization, expires, budget)
    if authorization is not None:
        proxy["proxy-authorization"] = authorization
    authority = f"[{name}]:{port}" if ":" in name else f"{name}:{port}"
    encode_connect(authority, proxy)
    now_ms = time.time_ns() // 1_000_000
    if not issued <= now_ms < expires:
        raise WorkloadClientError("signed workload enrollment, install session or proxy authorization is not current")
    budget.check()
    return WorkloadHandoff(
        proxy_ip=proxy_ip, proxy_port=port, proxy_server_name=name,
        proxy_headers=tuple(sorted(proxy.items())), provider_headers=tuple(sorted(provider.items())),
        mtls=mtls, interception_ca_spki_sha256=ca_spki,
        issued_at_epoch_ms=issued, expires_at_epoch_ms=expires, principal_id=principal, nonce=nonce,
    )
