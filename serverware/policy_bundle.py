from __future__ import annotations

import copy
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware.config import (
    POLICY_BUNDLE_PATH,
    POLICY_SIGNING_KEY_PATH,
    POLICY_SIGNING_PUBLIC_KEY_PATH,
    SCHEMA_DIR,
    ensure_data_dirs,
)


SUPPORTED_ADAPTERS = {"generic.rest", "gmail.v1", "x.v2", "npm.registry"}
SUPPORTED_CONSTRAINTS = {
    "rateLimit",
    "operationPolicy",
    "queryDateWindow",
    "queryNumericBounds",
    "jsonBody",
    "responseDateWindow",
}
REQUIRED_JIT_BINDING_FIELDS = {
    "principal",
    "routeId",
    "credentialRef",
    "credentialVersion",
    "policyHash",
    "method",
    "authority",
    "path",
    "bodySha256",
}


class PolicyBundleError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def policy_hash(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(signature_payload(value)).encode("utf-8")).hexdigest()


def signature_payload(value: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    metadata = unsigned.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
    return unsigned


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_policy_private_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if POLICY_SIGNING_KEY_PATH.exists():
        key = serialization.load_pem_private_key(POLICY_SIGNING_KEY_PATH.read_bytes(), password=None)
        _write_policy_public_key(key.public_key())
        return key
    key = Ed25519PrivateKey.generate()
    POLICY_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(POLICY_SIGNING_KEY_PATH, 0o600)
    _write_policy_public_key(key.public_key())
    return key


def _write_policy_public_key(public_key: Ed25519PublicKey) -> None:
    POLICY_SIGNING_PUBLIC_KEY_PATH.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(POLICY_SIGNING_PUBLIC_KEY_PATH, 0o644)


def policy_public_key() -> Ed25519PublicKey:
    return _load_policy_private_key().public_key()


def policy_public_key_pem() -> str:
    return policy_public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def policy_public_key_hash() -> str:
    der = policy_public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def sign_policy_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(raw)
    signed.setdefault("metadata", {})
    signed["metadata"]["signingKeyId"] = policy_public_key_hash()
    signed["metadata"].pop("signature", None)
    signature = _load_policy_private_key().sign(canonical_json(signature_payload(signed)).encode("utf-8"))
    signed["metadata"]["signature"] = "ed25519:" + _b64e(signature)
    return signed


def verify_policy_signature(raw: dict[str, Any]) -> None:
    signature_value = (raw.get("metadata") or {}).get("signature")
    if not isinstance(signature_value, str) or not signature_value.startswith("ed25519:"):
        raise PolicyBundleError("policy bundle must include metadata.signature using ed25519")
    signature = _b64d(signature_value.split(":", 1)[1])
    try:
        policy_public_key().verify(signature, canonical_json(signature_payload(raw)).encode("utf-8"))
    except InvalidSignature as exc:
        raise PolicyBundleError("policy bundle signature verification failed") from exc


def _load_schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def validate_policy_schema(raw: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator, ValidationError
    except Exception as exc:
        raise PolicyBundleError("jsonschema package is required for policy validation") from exc

    bundle_schema = _load_schema(SCHEMA_DIR / "policy-bundle.v1.schema.json")
    try:
        Draft202012Validator(bundle_schema).validate(raw)
        for route in raw.get("routes") or []:
            adapter = route.get("adapter") or {}
            adapter_type = adapter.get("type")
            if not adapter_type:
                continue
            schema_path = SCHEMA_DIR / "adapters" / f"{adapter_type}.schema.json"
            if schema_path.exists():
                Draft202012Validator(_load_schema(schema_path)).validate(adapter.get("config") or {})
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise PolicyBundleError(f"policy schema validation failed{location}: {exc.message}") from exc


def _path_template_to_regex(template: str) -> re.Pattern[str]:
    if not template.startswith("/"):
        raise PolicyBundleError(f"path template must start with /: {template}")
    if template.endswith("/**"):
        prefix = re.escape(template[:-3].rstrip("/"))
        return re.compile(rf"^{prefix}(?:/.*)?$")

    parts: list[str] = []
    for segment in template.strip("/").split("/"):
        if segment == "*":
            parts.append(r"[^/]+")
        elif segment == "**":
            parts.append(r".*")
        elif segment.startswith("{") and segment.endswith("}"):
            name = segment[1:-1]
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                raise PolicyBundleError(f"invalid path variable {segment} in {template}")
            parts.append(rf"(?P<{name}>[^/]+)")
        else:
            parts.append(re.escape(segment))
    body = "/".join(parts)
    return re.compile(rf"^/{body}/?$")


@dataclass(frozen=True)
class ProxyAuthorizationPolicy:
    scheme: str = "Bearer"
    token_sha256: str | None = None
    source_cidrs: tuple[str, ...] = ()
    expires_at_epoch_ms: int | None = None
    legacy_exact: str | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in self.source_cidrs)

    def matches(self, client_ip: str | None, raw_header: str | None) -> bool:
        if not raw_header:
            return False
        if self.legacy_exact is not None:
            return hmac.compare_digest(raw_header, self.legacy_exact)
        if self.expires_at_epoch_ms is not None and int(time.time() * 1000) >= self.expires_at_epoch_ms:
            return False
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            if not any(ip in network for network in self.networks):
                return False
        scheme, _, token = raw_header.strip().partition(" ")
        if not token or scheme.lower() != self.scheme.lower():
            return False
        digest = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        return bool(self.token_sha256) and hmac.compare_digest(digest, self.token_sha256)

    @classmethod
    def from_raw(cls, raw: Any) -> "ProxyAuthorizationPolicy | None":
        if raw is None:
            return None
        if isinstance(raw, str):
            return cls(legacy_exact=raw)
        if not isinstance(raw, dict):
            raise PolicyBundleError("principal proxyAuthorization must be a string or object")
        return cls(
            scheme=str(raw.get("scheme") or "Bearer"),
            token_sha256=str(raw.get("tokenSha256") or ""),
            source_cidrs=tuple(raw.get("sourceCidrs") or ()),
            expires_at_epoch_ms=int(raw["expiresAtEpochMs"]) if raw.get("expiresAtEpochMs") is not None else None,
        )


def _header_value(headers: Any, name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    lower = name.lower()
    value = headers.get(lower)
    if value is not None:
        return value
    for key, candidate in getattr(headers, "items", lambda: [])():
        if str(key).lower() == lower:
            return candidate
    return None


@dataclass(frozen=True)
class PrincipalPolicy:
    id: str
    source_cidrs: tuple[str, ...] = ()
    required_headers: dict[str, str] = field(default_factory=dict)
    proxy_authorization: ProxyAuthorizationPolicy | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in self.source_cidrs)

    def matches(self, client_ip: str | None, headers: Any) -> bool:
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            if not any(ip in network for network in self.networks):
                return False

        for name, expected in self.required_headers.items():
            if _header_value(headers, name) != expected:
                return False

        if self.proxy_authorization and not self.proxy_authorization.matches(client_ip, _header_value(headers, "Proxy-Authorization")):
            return False

        return True


@dataclass(frozen=True)
class CredentialPolicy:
    id: str
    provider: str = "generic"
    scopes: tuple[str, ...] = ()
    injection: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoutePolicy:
    id: str
    principals: tuple[str, ...]
    host: str
    port: int
    scheme: str
    methods: frozenset[str]
    path_templates: tuple[str, ...]
    path_regexes: tuple[re.Pattern[str], ...]
    credential_ref: str | None
    adapter_type: str
    adapter_config: dict[str, Any]
    constraints: tuple[dict[str, Any], ...] = ()
    jit: dict[str, Any] = field(default_factory=dict)

    def match_path(self, path: str) -> dict[str, str] | None:
        for regex in self.path_regexes:
            match = regex.match(path)
            if match:
                return match.groupdict()
        return None


@dataclass(frozen=True)
class RouteMatch:
    route: RoutePolicy
    params: dict[str, str]


@dataclass(frozen=True)
class PolicySnapshot:
    raw: dict[str, Any]
    hash: str
    principals: dict[str, PrincipalPolicy]
    credentials: dict[str, CredentialPolicy]
    routes: tuple[RoutePolicy, ...]

    def identify_principal(self, client_ip: str | None, headers: Any) -> PrincipalPolicy | None:
        for principal in self.principals.values():
            if principal.matches(client_ip, headers):
                return principal
        return None

    def match_route(self, scheme: str, host: str, port: int, method: str, path: str, principal_id: str) -> RouteMatch | None:
        normalized_host = host.lower().rstrip(".")
        normalized_method = method.upper()
        for route in self.routes:
            if route.scheme != scheme.lower():
                continue
            if route.host != normalized_host:
                continue
            if route.port != port:
                continue
            if principal_id not in route.principals and "*" not in route.principals:
                continue
            params = route.match_path(path)
            if params is None:
                continue
            if normalized_method not in route.methods:
                continue
            return RouteMatch(route=route, params=params)
        return None


_SNAPSHOT_CACHE: tuple[float | None, PolicySnapshot | None] = (None, None)


def _load_raw_policy(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            from ruamel.yaml import YAML
        except Exception as exc:
            raise PolicyBundleError("YAML policy bundles require ruamel.yaml") from exc
        loaded = YAML(typ="safe").load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise PolicyBundleError("policy bundle must be an object")
    return loaded


def _validate_constraints(route_id: str, constraints: Any) -> tuple[dict[str, Any], ...]:
    if constraints is None:
        return ()
    if not isinstance(constraints, list):
        raise PolicyBundleError(f"route {route_id} constraints must be an array")
    compiled: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, constraint in enumerate(constraints):
        if not isinstance(constraint, dict):
            raise PolicyBundleError(f"route {route_id} constraint {index} must be an object")
        constraint_id = str(constraint.get("id") or "")
        if not constraint_id:
            raise PolicyBundleError(f"route {route_id} constraint {index} must define id")
        if constraint_id in seen_ids:
            raise PolicyBundleError(f"route {route_id} has duplicate constraint id {constraint_id}")
        seen_ids.add(constraint_id)
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_CONSTRAINTS:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has unsupported type {constraint_type}")
        phase = constraint.get("phase", "request")
        if phase not in {"request", "response", "both"}:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has invalid phase {phase}")
        store = constraint.get("store", "local")
        if store not in {"local", "shared"}:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has invalid store {store}")
        if constraint_type == "rateLimit":
            if int(constraint.get("max") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} must define max >= 1")
            if int(constraint.get("windowSeconds") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} must define windowSeconds >= 1")
        elif constraint_type == "operationPolicy":
            if not (constraint.get("allowedOperations") or constraint.get("deniedOperations")):
                raise PolicyBundleError(
                    f"route {route_id} operationPolicy {constraint_id} must define allowedOperations or deniedOperations"
                )
        elif constraint_type in {"queryDateWindow", "queryNumericBounds"}:
            if not constraint.get("parameters"):
                raise PolicyBundleError(f"route {route_id} {constraint_type} {constraint_id} must define parameters")
            if constraint_type == "queryDateWindow" and int(constraint.get("maxAgeDays") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} must define maxAgeDays >= 1")
        elif constraint_type == "jsonBody":
            if not (
                constraint.get("allowedFields")
                or constraint.get("requiredFields")
                or constraint.get("deniedFields")
                or constraint.get("fields")
            ):
                raise PolicyBundleError(f"route {route_id} jsonBody {constraint_id} must define at least one field rule")
        elif constraint_type == "responseDateWindow":
            if int(constraint.get("maxAgeDays") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define maxAgeDays >= 1")
            if not constraint.get("dateFields"):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define dateFields")
        compiled.append(dict(constraint))
    return tuple(compiled)


def compile_policy_bundle(raw: dict[str, Any], *, verify_signature: bool = False, validate_schema: bool = False) -> PolicySnapshot:
    if validate_schema:
        validate_policy_schema(raw)
    if verify_signature:
        verify_policy_signature(raw)
    if raw.get("apiVersion") != "serverware.policy/v1":
        raise PolicyBundleError("apiVersion must be serverware.policy/v1")
    if raw.get("kind") != "PolicyBundle":
        raise PolicyBundleError("kind must be PolicyBundle")

    principal_items = raw.get("principals") or []
    credential_items = raw.get("credentials") or []
    route_items = raw.get("routes") or []
    if not principal_items:
        raise PolicyBundleError("at least one principal is required")

    principals: dict[str, PrincipalPolicy] = {}
    for item in principal_items:
        principal_id = item["id"]
        if principal_id in principals:
            raise PolicyBundleError(f"duplicate principal: {principal_id}")
        principals[principal_id] = PrincipalPolicy(
            id=principal_id,
            source_cidrs=tuple(item.get("sourceCidrs") or ()),
            required_headers=dict(item.get("requiredHeaders") or {}),
            proxy_authorization=ProxyAuthorizationPolicy.from_raw(item.get("proxyAuthorization")),
        )

    credentials: dict[str, CredentialPolicy] = {}
    for item in credential_items:
        credential_id = item["id"]
        if credential_id in credentials:
            raise PolicyBundleError(f"duplicate credential: {credential_id}")
        credentials[credential_id] = CredentialPolicy(
            id=credential_id,
            provider=item.get("provider", "generic"),
            scopes=tuple(item.get("scopes") or ()),
            injection=dict(item.get("injection") or {"type": "bearer"}),
        )

    routes: list[RoutePolicy] = []
    seen_routes: set[str] = set()
    for item in route_items:
        route_id = item["id"]
        if route_id in seen_routes:
            raise PolicyBundleError(f"duplicate route: {route_id}")
        seen_routes.add(route_id)

        match = item.get("match") or {}
        methods = frozenset(method.upper() for method in (match.get("methods") or []))
        if not methods:
            raise PolicyBundleError(f"route {route_id} must define methods")
        paths = tuple(match.get("paths") or ())
        if not paths:
            raise PolicyBundleError(f"route {route_id} must define paths")
        adapter = item.get("adapter") or {"type": "generic.rest", "config": {}}
        adapter_type = adapter.get("type", "generic.rest")
        adapter_config = dict(adapter.get("config") or {})
        if adapter_type not in SUPPORTED_ADAPTERS:
            raise PolicyBundleError(f"route {route_id} uses unsupported adapter {adapter_type}")
        credential_ref = item.get("credentialRef")
        if credential_ref and credential_ref not in credentials:
            raise PolicyBundleError(f"route {route_id} references unknown credential {credential_ref}")
        if credential_ref and adapter_type == "generic.rest":
            request_config = adapter_config.get("request") or {}
            response_config = adapter_config.get("response") or {}
            if not request_config or not response_config:
                raise PolicyBundleError(
                    f"route {route_id} uses credentialed generic.rest and must define request and response schemas"
                )
            if "maxBodyBytes" not in request_config or "maxBodyBytes" not in response_config:
                raise PolicyBundleError(
                    f"route {route_id} uses credentialed generic.rest and must define request/response maxBodyBytes"
                )
        route_principals = tuple(item.get("principals") or ())
        for principal_id in route_principals:
            if principal_id != "*" and principal_id not in principals:
                raise PolicyBundleError(f"route {route_id} references unknown principal {principal_id}")
        jit = dict(item.get("jit") or {})
        if jit.get("required"):
            for required_key in ("mode", "ttlSeconds", "maxUses", "consumeOn", "binding", "approvers"):
                if required_key not in jit:
                    raise PolicyBundleError(f"route {route_id} JIT policy must define {required_key}")
            binding = jit.get("binding") or {}
            if binding.get("type") not in {"requestDigest", "operationDigest"}:
                raise PolicyBundleError(f"route {route_id} JIT binding must define requestDigest or operationDigest")
            binding_fields = set(binding.get("fields") or [])
            missing_fields = sorted(REQUIRED_JIT_BINDING_FIELDS - binding_fields)
            if missing_fields:
                raise PolicyBundleError(
                    f"route {route_id} JIT binding is missing required fields: {', '.join(missing_fields)}"
                )
            approvers = jit.get("approvers") or {}
            if int(approvers.get("quorum", 0)) < 1:
                raise PolicyBundleError(f"route {route_id} JIT policy must define approver quorum")
            if not approvers.get("users"):
                raise PolicyBundleError(f"route {route_id} JIT policy must define allowed approver users")
            authn = approvers.get("authn") or {}
            if authn.get("webauthnRequired") and not authn.get("allowedAuthenticatorClasses"):
                raise PolicyBundleError(f"route {route_id} WebAuthn JIT policy must define allowed authenticator classes")
        constraints = _validate_constraints(route_id, item.get("constraints"))

        routes.append(
            RoutePolicy(
                id=route_id,
                principals=route_principals,
                scheme=(match.get("scheme") or "https").lower(),
                host=(match["host"]).lower().rstrip("."),
                port=int(match.get("port", 443)),
                methods=methods,
                path_templates=paths,
                path_regexes=tuple(_path_template_to_regex(path) for path in paths),
                credential_ref=credential_ref,
                adapter_type=adapter_type,
                adapter_config=adapter_config,
                constraints=constraints,
                jit=jit,
            )
        )

    routes.sort(key=lambda route: max(len(path) for path in route.path_templates), reverse=True)
    return PolicySnapshot(
        raw=raw,
        hash=policy_hash(raw),
        principals=principals,
        credentials=credentials,
        routes=tuple(routes),
    )


def get_policy_snapshot() -> PolicySnapshot | None:
    global _SNAPSHOT_CACHE
    path = POLICY_BUNDLE_PATH
    if not path.exists():
        _SNAPSHOT_CACHE = (None, None)
        return None
    mtime = path.stat().st_mtime
    cached_mtime, cached_snapshot = _SNAPSHOT_CACHE
    if cached_snapshot and cached_mtime == mtime:
        return cached_snapshot
    try:
        snapshot = compile_policy_bundle(_load_raw_policy(path), verify_signature=True, validate_schema=True)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, PolicyBundleError):
        _SNAPSHOT_CACHE = (mtime, None)
        return None
    _SNAPSHOT_CACHE = (mtime, snapshot)
    return snapshot


def write_policy_bundle(raw: dict[str, Any], path: Path = POLICY_BUNDLE_PATH) -> PolicySnapshot:
    ensure_data_dirs()
    signed = sign_policy_bundle(raw)
    snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")
    global _SNAPSHOT_CACHE
    _SNAPSHOT_CACHE = (path.stat().st_mtime, snapshot)
    return snapshot


def demo_policy_bundle(credential_id: str = "cred-demo-bearer") -> dict[str, Any]:
    proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-agent-proxy-token").hexdigest()
    bound_proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-bound-proxy-token").hexdigest()
    return {
        "apiVersion": "serverware.policy/v1",
        "kind": "PolicyBundle",
        "metadata": {
            "id": "serverware-demo",
            "sequence": 1,
            "rollbackEpoch": 1,
        },
        "defaults": {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "principals": [
            {
                "id": "agent:demo",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-agent"},
            },
            {
                "id": "agent:demo-proxy-token",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-token-agent"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "demo-sidecar-token",
                    "tokenSha256": proxy_token_sha256,
                    "sourceCidrs": ["0.0.0.0/0", "::/0"],
                    "expiresAtEpochMs": 4102444800000,
                },
            },
            {
                "id": "agent:demo-source-bound-proxy-token",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-bound-agent"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "demo-bound-sidecar-token",
                    "tokenSha256": bound_proxy_token_sha256,
                    "sourceCidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"],
                    "expiresAtEpochMs": 4102444800000,
                },
            }
        ],
        "credentials": [
            {
                "id": credential_id,
                "provider": "demo",
                "scopes": ["demo"],
                "injection": {"type": "bearer", "header": "Authorization"},
            }
        ],
        "routes": [
            {
                "id": "demo.echo",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET", "POST"],
                    "paths": ["/echo"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "bodyMode": "any",
                            "maxBodyBytes": 65536,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "method",
                                "path",
                                "query",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": ["/stream-bytes"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": ["chunks", "chunkSize"],
                            "allowedHeaders": [],
                            "bodyMode": "none",
                            "maxBodyBytes": 0,
                        },
                        "response": {
                            "mode": "stream",
                            "maxBodyBytes": 1048576,
                        },
                    },
                },
            },
            {
                "id": "demo.upload.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/upload-bytes"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "bodyMode": "stream",
                            "maxBodyBytes": 1048576,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "method",
                                "path",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                                "bytes",
                                "sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.jsonl.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/jsonl-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonlStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonlStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.array.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-array-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonArrayStream",
                            "maxBodyBytes": 1048576,
                            "maxItemBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonArrayStream",
                            "maxBodyBytes": 1048576,
                            "maxItemBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.sse.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-sse-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonSseStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "maxEventBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonSseStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "maxEventBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.nested.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-nested-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": [
                                "requestId",
                                "profile.email",
                                "profile.settings.theme",
                                "items.id",
                                "items.details.safe",
                                "audit.trace",
                            ],
                            "bodyMode": "jsonNestedStream",
                            "maxBodyBytes": 1048576,
                            "maxNestedBytes": 262144,
                        },
                        "response": {
                            "mode": "jsonNestedStream",
                            "maxBodyBytes": 1048576,
                            "maxNestedBytes": 262144,
                            "allowedFields": [
                                "requestId",
                                "profile.email",
                                "profile.settings.theme",
                                "items.id",
                                "items.details.safe",
                                "audit.trace",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.form.urlencoded.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/form-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": ["kept", "safe"],
                            "bodyMode": "formUrlencodedStream",
                            "maxBodyBytes": 1048576,
                            "maxPairBytes": 8192,
                        },
                        "response": {
                            "mode": "formUrlencodedStream",
                            "maxBodyBytes": 1048576,
                            "maxPairBytes": 8192,
                            "allowedFields": [
                                "kept",
                                "safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.csv.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/csv-redact"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["content-type"],
                            "allowedFields": ["id", "public", "safe_note"],
                            "bodyMode": "csvStream",
                            "maxBodyBytes": 1048576,
                            "maxRecordBytes": 8192,
                        },
                        "response": {
                            "mode": "csvStream",
                            "maxBodyBytes": 1048576,
                            "maxRecordBytes": 8192,
                            "allowedFields": [
                                "id",
                                "public",
                                "safe_note",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.gmail.recent",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": [
                        "/gmail/v1/users/{user}/messages",
                        "/gmail/v1/users/{user}/messages/{message_id}",
                    ],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "gmail.v1",
                    "config": {
                        "maxAgeDays": 30,
                        "maxResults": 10,
                        "forceQuery": True,
                        "allowMessageGetOnlyFromPriorSearch": True,
                        "cacheTtlSeconds": 1800,
                        "denyEquivalentEndpoints": ["threads", "history", "attachments", "imap"],
                        "response": {
                            "validateInternalDate": True,
                            "validateListByMetadataFetch": True,
                            "allowedFields": [
                                "id",
                                "threadId",
                                "labelIds",
                                "snippet",
                                "internalDate",
                                "payload.headers",
                            ],
                            "onViolation": "block",
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "gmail-list-response-30d",
                        "type": "responseDateWindow",
                        "phase": "response",
                        "description": "List responses may only release message metadata proven to be inside the last 30 days.",
                        "items": ["messages"],
                        "dateFields": ["internalDate"],
                        "formats": ["epochMillis"],
                        "maxAgeDays": 30,
                        "required": False,
                    },
                ],
            },
            {
                "id": "demo.x.tweet.one_per_day",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/2/tweets"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "controlledWrite",
                        "blockWrites": False,
                        "appIds": ["demo-x-app"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "data.id",
                                "data.text",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-only-tweet-create",
                        "type": "operationPolicy",
                        "description": "This controlled-write route can only use the tweet-create operation.",
                        "allowedOperations": ["tweets.write"],
                    },
                    {
                        "id": "x-one-tweet-per-day",
                        "type": "rateLimit",
                        "description": "A principal can publish at most one tweet per day with this credential.",
                        "max": 1,
                        "windowSeconds": 86400,
                        "store": "shared",
                        "key": {
                            "scope": ["principal", "credential", "route", "operation"],
                        },
                    },
                    {
                        "id": "x-tweet-body-shape",
                        "type": "jsonBody",
                        "description": "Tweets must be plain text posts with no media, polls, or hidden write side effects.",
                        "contentTypes": ["application/json"],
                        "allowedFields": ["text", "reply_settings"],
                        "requiredFields": ["text"],
                        "deniedFields": ["media", "poll", "direct_message_deep_link", "for_super_followers_only"],
                        "fields": {
                            "text": {"type": "string", "minLength": 1, "maxLength": 280},
                            "reply_settings": {"type": "string", "enum": ["following", "mentionedUsers"]},
                        },
                    },
                ],
            },
            {
                "id": "demo.x.search.recent",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": ["/2/tweets/search/recent"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "recentSearchOnly",
                        "blockWrites": True,
                        "appIds": ["demo-x-app"],
                        "allowedReadOperations": ["search.read"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "data.id",
                                "data.text",
                                "data.created_at",
                                "meta.result_count",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-search-start-time-7d",
                        "type": "queryDateWindow",
                        "description": "Search cursors cannot ask for tweets older than seven days.",
                        "parameters": ["start_time", "end_time"],
                        "maxAgeDays": 7,
                        "formats": ["rfc3339", "date"],
                        "required": False,
                    },
                    {
                        "id": "x-search-result-cap",
                        "type": "queryNumericBounds",
                        "description": "Result pages stay bounded even when SDK defaults are overridden.",
                        "parameters": ["max_results"],
                        "min": 1,
                        "max": 100,
                        "integer": True,
                    },
                    {
                        "id": "x-search-response-7d",
                        "type": "responseDateWindow",
                        "phase": "response",
                        "description": "The upstream response must not contain tweets outside the same seven-day window.",
                        "dateFields": ["data.created_at"],
                        "formats": ["rfc3339", "date"],
                        "maxAgeDays": 7,
                        "required": False,
                    },
                ],
            },
            {
                "id": "demo.x.readonly",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET", "POST", "DELETE"],
                    "paths": ["/2/**"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "readOnly",
                        "blockWrites": True,
                        "appIds": ["demo-x-app"],
                        "allowedReadOperations": ["tweets.read"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "data.id",
                                "data.text",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-readonly-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "The broad X route remains read-only even if the method list is widened for compatibility.",
                        "allowedOperations": ["tweets.read"],
                    },
                ],
            },
            {
                "id": "demo.npm.publish.jit",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["PUT", "POST"],
                    "paths": ["/npm/{package}", "/npm/-/package/{package}/dist-tags/{tag}"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "npm.registry",
                    "config": {
                        "operations": ["publish", "distTagWrite"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "package",
                                "published",
                                "tag",
                                "dist_tag_written",
                                "authorization_present",
                                "authorization_scheme",
                                "authorization_sha256",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "npm-sensitive-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "Only publish and dist-tag writes may reach this JIT-protected npm route.",
                        "allowedOperations": ["npm.publish", "npm.distTagWrite"],
                        "deniedOperations": ["npm.tokenWrite", "npm.metadataWrite"],
                    },
                ],
                "jit": {
                    "required": True,
                    "mode": "perOperation",
                    "ttlSeconds": 30,
                    "maxUses": 1,
                    "consumeOn": "forwardStart",
                    "binding": {
                        "type": "operationDigest",
                        "fields": [
                            "principal",
                            "routeId",
                            "credentialRef",
                            "credentialVersion",
                            "policyHash",
                            "method",
                            "authority",
                            "path",
                            "bodySha256",
                            "packageName",
                            "packageVersion",
                            "tarballIntegrity",
                        ],
                    },
                    "approvers": {
                        "quorum": 1,
                        "users": ["user:demo"],
                        "authn": {
                            "webauthnRequired": True,
                            "userVerification": "discouraged",
                            "allowedAuthenticatorClasses": ["dev"],
                            "requireHardwareAttestation": False,
                        },
                    },
                },
            },
        ],
    }


def request_url_parts(pretty_url: str) -> tuple[str, str, int, str]:
    parts = urlsplit(pretty_url)
    scheme = parts.scheme or "https"
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, host, port, parts.path or "/"
