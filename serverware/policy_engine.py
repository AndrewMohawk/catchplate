from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlunsplit

from mitmproxy import http

from serverware import db, runtime
from serverware.adapters import get_adapter, preflight_request_admission
from serverware.constraints import (
    _request_value_predicate_matches,
    evaluate_request_constraints,
    evaluate_response_binding_sources,
    evaluate_response_constraints,
    shared_durable_budget_claims,
    shared_rate_limit_claims,
    traversal_budget_claims,
)
from serverware.policies import PolicyDecision
from serverware.policy_bundle import (
    CredentialPolicy,
    PolicyBundleError,
    PolicySnapshot,
    PrincipalPolicy,
    PROVIDER_ACCOUNT_OPERATION_FIELD,
    RoutePolicy,
    adapter_operation_field_names,
    adapter_operation_query_fields,
    strict_json_loads,
    canonical_json,
    credential_injection_target,
    get_policy_snapshot,
    is_serverware_internal_header,
    normalized_credential_provider,
    provider_account_scope_value,
    required_oauth_scopes_for_operation,
    validate_raw_absolute_target,
    validate_request_target_path,
    validated_request_url_parts,
    validated_request_urlsplit,
    validate_discard_headers,
)


SENSITIVE_QUERY_KEYS = {"access_token", "api_key", "apikey", "key", "token", "auth", "authorization"}
SECRET_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
STANDARD_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SERVERWARE_SERVICE_AUTH_HEADERS = {
    "x-serverware-admin-token",
    "x-serverware-audit-anchor-token",
    "x-serverware-ca-install-token",
    "x-serverware-csrf-token",
    "x-serverware-data-plane-token",
}
RESPONSE_PROOF_NONCE_HEADER = "x-serverware-proof-nonce"
_RESPONSE_CREDENTIAL_GUARD_ATTR = "_serverware_response_credential_guard"
_RESPONSE_CONTENT_ENCODING_VALIDATED_KEY = (
    "serverware_response_content_encoding_validated"
)
_RELEASE_AUTHORIZATION_ID_MAX_BYTES = 256
_REQUEST_HEADER_NAME_MAX_BYTES = 128
_REQUEST_HEADER_VALUE_MAX_BYTES = 16 * 1024
_REQUEST_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE_RE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$")
_CREDENTIAL_INJECTION_FIELDS = {
    "bearer": frozenset({"type", "header", "field", "prefix"}),
    "basic": frozenset({"type", "header", "field", "username"}),
    "header": frozenset({"type", "name", "field", "prefix"}),
    "query": frozenset({"type", "name", "field"}),
    "cookie": frozenset({"type", "name", "field"}),
}
_MAX_REQUEST_QUERY_FIELDS = 256
_QUERY_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_UINT64_MAX = (1 << 64) - 1
RAW_INGRESS_TARGET_METADATA_KEY = "serverware_raw_absolute_target"
RAW_INGRESS_VALIDATED_METADATA_KEY = "serverware_raw_target_validated"
LEGACY_MITM_TRANSPORT_METADATA_KEY = (
    "serverware_legacy_mitm_transport"
)
_POLICY_ENGINE_CONSTRAINTS = {
    "requestValue",
    "slidingWindowLimit",
    "weightedBudget",
    "traversalBudget",
    "responseEnvelope",
}


def _canonical_credential_version(credential_version: int) -> str:
    if (
        type(credential_version) is not int
        or credential_version < 0
        or credential_version > _UINT64_MAX
    ):
        raise ValueError("credential version must be an unsigned 64-bit integer")
    return "none" if credential_version == 0 else str(credential_version)


def _legacy_constraint_route(route: RoutePolicy) -> Any:
    return type(
        "_LegacyConstraintRoute",
        (),
        {
            "id": route.id,
            "constraints": tuple(
                constraint
                for constraint in route.constraints
                if constraint.get("type") not in _POLICY_ENGINE_CONSTRAINTS
            ),
        },
    )()


@dataclass
class RequestEvaluation:
    decision: PolicyDecision
    snapshot: PolicySnapshot | None = None
    principal: PrincipalPolicy | None = None
    route: RoutePolicy | None = None
    credential_policy: CredentialPolicy | None = None
    params: dict[str, str] | None = None
    request_digest: str | None = None
    operation_digest: str | None = None
    attempt_id: str | None = None
    binding_digest: str | None = None
    release_state: str | None = None


@dataclass(frozen=True)
class _RequestMutationSnapshot:
    pretty_url: str
    headers: tuple[tuple[Any, Any], ...]
    raw_content: Any


class _ResponseCredentialGuard:
    def __init__(self) -> None:
        self._patterns: list[bytearray] = []

    def add_text_encodings(self, value: str) -> None:
        raw = value.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest().encode("ascii")
        candidates = [
            raw,
            quote(value, safe="").encode("ascii"),
            quote_plus(value, safe="").encode("ascii"),
            base64.b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b"="),
            digest,
            b"sha256:" + digest,
        ]
        for ensure_ascii in (False, True):
            encoded = json.dumps(value, ensure_ascii=ensure_ascii)
            candidates.append(encoded[1:-1].encode("utf-8"))
        for candidate in candidates:
            if candidate and not any(pattern == candidate for pattern in self._patterns):
                self._patterns.append(bytearray(candidate))

    def detects(self, value: bytes) -> bool:
        return any(value.find(pattern) >= 0 for pattern in self._patterns)

    def detects_response(self, response: Any) -> bool:
        if not response:
            return False
        raw_content = getattr(response, "raw_content", None)
        if isinstance(raw_content, (bytes, bytearray)) and self.detects(bytes(raw_content)):
            return True
        try:
            content = response.content
        except Exception:
            content = None
        if isinstance(content, (bytes, bytearray)) and content != raw_content and self.detects(bytes(content)):
            return True
        headers = getattr(response, "headers", {})
        fields = getattr(headers, "fields", None)
        values = (value for _, value in fields) if fields is not None else headers.values()
        for value in values:
            encoded = value if isinstance(value, bytes) else str(value).encode("utf-8")
            if self.detects(encoded):
                return True
        return False

    def clear(self) -> None:
        for pattern in self._patterns:
            pattern[:] = b"\x00" * len(pattern)
        self._patterns.clear()


def _install_response_credential_guard(flow: http.HTTPFlow, guard: _ResponseCredentialGuard) -> None:
    existing = getattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, None)
    if isinstance(existing, _ResponseCredentialGuard):
        existing.clear()
    setattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, guard)


def _take_response_credential_guard(flow: http.HTTPFlow) -> _ResponseCredentialGuard | None:
    guard = getattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, None)
    if hasattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR):
        delattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR)
    return guard if isinstance(guard, _ResponseCredentialGuard) else None


def redact_url(
    url: str,
    *,
    sensitive_query_keys: tuple[str, ...] = (),
) -> str:
    parts = validated_request_urlsplit(url)
    sensitive_keys = SENSITIVE_QUERY_KEYS | {
        key.lower() for key in sensitive_query_keys if isinstance(key, str) and key
    }
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in sensitive_keys:
            query.append((key, "redacted"))
        else:
            query.append((key, value))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query, quote_via=quote),
            parts.fragment,
        )
    )


def _pre_policy_audit_url(url: str) -> str:
    try:
        parts = validated_request_urlsplit(url)
    except (TypeError, ValueError):
        return "invalid://request-target"
    # Query names and values are never audit material, including after routing.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _validated_pre_policy_audit_url(parts: Any) -> str:
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _audit_url(flow: http.HTTPFlow) -> str:
    preserved = flow.metadata.get("serverware_audit_url")
    if isinstance(preserved, str) and preserved:
        return _pre_policy_audit_url(preserved)
    return _pre_policy_audit_url(flow.request.pretty_url)


def _client_ip(flow: http.HTTPFlow) -> str | None:
    peername = getattr(flow.client_conn, "peername", None) or getattr(flow.client_conn, "address", None)
    if isinstance(peername, tuple) and peername:
        return str(peername[0])
    return None


def _verified_mtls_evidence(flow: http.HTTPFlow) -> dict[str, Any] | None:
    connection = getattr(flow, "client_conn", None)
    if (
        connection is None
        or getattr(connection, "serverware_mtls_verified", None) is not True
    ):
        return None
    raw = getattr(connection, "serverware_mtls_evidence", None)
    allowed = {
        "san_spiffe_ids",
        "san_dns_names",
        "san_uris",
        "certificate_sha256",
        "spki_sha256",
        "issuer_spki_sha256",
    }
    if not isinstance(raw, dict) or set(raw) - allowed:
        return None
    evidence: dict[str, Any] = {"verified": True}
    for field_name in ("san_spiffe_ids", "san_dns_names", "san_uris"):
        values = raw.get(field_name, ())
        if (
            not isinstance(values, (list, tuple))
            or len(values) > 32
            or any(
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or len(value.encode("utf-8")) > 2048
                for value in values
            )
            or len(values) != len(set(values))
        ):
            return None
        evidence[field_name] = tuple(values)
    for field_name in (
        "certificate_sha256",
        "spki_sha256",
        "issuer_spki_sha256",
    ):
        value = raw.get(field_name)
        if value is not None and (
            not isinstance(value, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
        ):
            return None
        evidence[field_name] = value
    return evidence


def _request_body(flow: http.HTTPFlow) -> bytes:
    try:
        raw = flow.request.raw_content
    except Exception as exc:
        raise ValueError("request body bytes are unavailable") from exc
    if not isinstance(raw, bytes):
        raise ValueError("request body is not buffered bytes")
    get_content = getattr(flow.request, "get_content", None)
    if not callable(get_content):
        raise ValueError("request body access is unavailable")
    try:
        decoded = get_content(strict=True)
    except Exception as exc:
        raise ValueError("request body access failed") from exc
    if not isinstance(decoded, bytes):
        raise ValueError("request body access did not return bytes")
    return raw


def _body_sha256(flow: http.HTTPFlow) -> str:
    return "sha256:" + hashlib.sha256(_request_body(flow)).hexdigest()


def _strict_query_pairs(raw_query: str) -> list[tuple[str, str]]:
    if not isinstance(raw_query, str):
        raise ValueError("request query is not text")
    try:
        raw = raw_query.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("request query contains raw non-ASCII") from exc
    if "+" in raw_query:
        raise ValueError(
            "request query must encode space as %20 and literal plus as %2B"
        )
    if raw_query:
        for pair in raw_query.split("&"):
            if pair.count("=") != 1:
                raise ValueError(
                    "request query pairs must contain exactly one equals delimiter"
                )
            key, _ = pair.split("=", 1)
            if not key:
                raise ValueError("request query contains an empty key")
    unreserved = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    decoded = bytearray()
    index = 0
    while index < len(raw):
        value = raw[index]
        if value != 0x25:
            if value not in unreserved and value not in b"&=":
                raise ValueError(
                    "request query contains a raw reserved delimiter or separator"
                )
            decoded.append(value)
            index += 1
            continue
        if (
            index + 2 >= len(raw)
            or chr(raw[index + 1]) not in _QUERY_HEX_DIGITS
            or chr(raw[index + 2]) not in _QUERY_HEX_DIGITS
        ):
            raise ValueError("request query contains a malformed percent escape")
        hex_pair = raw[index + 1 : index + 3].decode("ascii")
        decoded_value = int(hex_pair, 16)
        if (
            decoded_value == 0x25
            or decoded_value == 0x5C
            or decoded_value < 0x20
            or decoded_value == 0x7F
            or decoded_value in unreserved
        ):
            raise ValueError("request query contains a forbidden or ambiguous percent escape")
        if any(character in b"abcdef" for character in raw[index + 1 : index + 3]):
            raise ValueError("request query uses a non-canonical percent encoding")
        decoded.append(decoded_value)
        index += 3
    try:
        decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("request query is not valid UTF-8 after decoding") from exc
    if not raw_query:
        return []
    try:
        pairs = parse_qsl(
            raw_query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_REQUEST_QUERY_FIELDS,
            separator="&",
        )
    except (UnicodeError, ValueError) as exc:
        raise ValueError("request query is malformed") from exc
    keys: set[str] = set()
    for key, _ in pairs:
        if key in keys:
            raise ValueError("request query contains a duplicate decoded key")
        keys.add(key)
    if pairs != sorted(pairs):
        raise ValueError("request query pairs are not in canonical order")
    if raw_query != _canonical_query_wire(pairs):
        raise ValueError("request query is not in exact canonical wire form")
    return pairs


def _validated_canonical_query_pairs(raw_pairs: Any) -> list[tuple[str, str]]:
    if not isinstance(raw_pairs, (list, tuple)):
        raise ValueError("canonical request query must be an array")
    pairs: list[tuple[str, str]] = []
    keys: set[str] = set()
    for item in raw_pairs:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise ValueError("canonical request query entry is invalid")
        key, value = item
        try:
            key.encode("utf-8")
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("canonical request query is not valid UTF-8 text") from exc
        if key in keys:
            raise ValueError("canonical request query contains a duplicate key")
        keys.add(key)
        pairs.append((key, value))
    if pairs != sorted(pairs):
        raise ValueError("canonical request query is not in canonical order")
    return pairs


def _canonical_query_wire(raw_pairs: Any) -> str:
    pairs = _validated_canonical_query_pairs(raw_pairs)
    return urlencode(
        pairs,
        doseq=False,
        safe="",
        encoding="utf-8",
        errors="strict",
        quote_via=quote,
    )


def _set_request_query_wire(
    flow: http.HTTPFlow,
    pairs: list[tuple[str, str]],
) -> str:
    wire_query = _canonical_query_wire(pairs)
    raw_url = str(flow.request.pretty_url)
    base_url = raw_url.split("?", 1)[0]
    parts = validated_request_urlsplit(base_url)
    target_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, wire_query, "")
    )
    try:
        flow.request.url = target_url
    except Exception:
        pass
    if validated_request_urlsplit(flow.request.pretty_url).query != wire_query:
        try:
            flow.request.pretty_url = target_url
        except Exception as exc:
            raise ValueError("request query could not be serialized canonically") from exc
    if validated_request_urlsplit(flow.request.pretty_url).query != wire_query:
        raise ValueError("request query could not be serialized canonically")
    query_view = getattr(flow.request, "query", None)
    if isinstance(query_view, dict):
        query_view.clear()
        query_view.update(pairs)
    return wire_query


def _canonicalize_provider_query(
    flow: http.HTTPFlow,
    *,
    trusted_query_view: bool = False,
) -> list[tuple[str, str]]:
    query_view = getattr(flow.request, "query", None)
    query_items = getattr(query_view, "items", None)
    if trusted_query_view and callable(query_items):
        try:
            raw_pairs = list(query_items(multi=True))
        except TypeError:
            raw_pairs = list(query_items())
        pairs = _validated_canonical_query_pairs(sorted(raw_pairs))
    else:
        pairs = _strict_query_pairs(
            validated_request_urlsplit(flow.request.pretty_url).query
        )
    _set_request_query_wire(flow, pairs)
    return pairs


def _canonical_authority(url: str) -> str:
    parts = validated_request_urlsplit(url)
    host = (parts.hostname or "").rstrip(".").lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid request authority port") from exc
    default_port = 443 if parts.scheme.lower() == "https" else 80 if parts.scheme.lower() == "http" else None
    return f"{host}:{port}" if port is not None and port != default_port else host


def _physical_request_header_entries(flow: http.HTTPFlow) -> list[tuple[Any, Any]]:
    header_container = flow.request.headers
    items = getattr(header_container, "items", None)
    if callable(items):
        try:
            return list(items(multi=True))
        except TypeError:
            pass
        except Exception as exc:
            raise ValueError("request physical headers are unavailable") from exc

    fields = getattr(header_container, "fields", None)
    if fields is not None:
        try:
            return list(fields)
        except Exception as exc:
            raise ValueError("request physical headers are unavailable") from exc

    if isinstance(header_container, Mapping):
        return list(header_container.items())
    raise ValueError(
        "request header container does not expose unmerged physical fields"
    )


def _request_header_text(value: Any, *, name: bool) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("ascii" if name else "latin-1")
        except UnicodeDecodeError as exc:
            raise ValueError("request contains a non-text HTTP header") from exc
    raise ValueError("request contains a non-text HTTP header")


def _validate_response_content_encoding(
    flow: http.HTTPFlow,
) -> PolicyDecision:
    if flow.metadata.get(_RESPONSE_CONTENT_ENCODING_VALIDATED_KEY) is True:
        return PolicyDecision(True)
    response = getattr(flow, "response", None)
    if response is None:
        return PolicyDecision(
            False,
            "upstream response is missing",
            502,
            {"error": "upstream_response_missing"},
        )
    headers = response.headers
    entries: list[tuple[Any, Any]]
    fields = getattr(headers, "fields", None)
    if fields is not None:
        try:
            entries = list(fields)
        except Exception:
            return PolicyDecision(
                False,
                "upstream response headers are unavailable",
                502,
                {"error": "response_headers_unavailable"},
            )
    else:
        items = getattr(headers, "items", None)
        if callable(items):
            try:
                entries = list(items(multi=True))
            except TypeError:
                entries = list(items())
            except Exception:
                return PolicyDecision(
                    False,
                    "upstream response headers are unavailable",
                    502,
                    {"error": "response_headers_unavailable"},
                )
        elif isinstance(headers, Mapping):
            entries = list(headers.items())
        else:
            return PolicyDecision(
                False,
                "upstream response headers are unavailable",
                502,
                {"error": "response_headers_unavailable"},
            )
    encodings: list[str] = []
    try:
        for raw_name, raw_value in entries:
            name = _request_header_text(raw_name, name=True)
            value = _request_header_text(raw_value, name=False)
            if name.lower() == "content-encoding":
                encodings.append(value)
    except ValueError:
        return PolicyDecision(
            False,
            "upstream Content-Encoding is invalid",
            502,
            {"error": "response_content_encoding_invalid"},
        )
    if len(encodings) > 1 or (
        len(encodings) == 1 and encodings[0] != "identity"
    ):
        return PolicyDecision(
            False,
            "upstream Content-Encoding is unsupported or ambiguous",
            502,
            {"error": "response_content_encoding_denied"},
        )
    flow.metadata[_RESPONSE_CONTENT_ENCODING_VALIDATED_KEY] = True
    return PolicyDecision(True)


def _normalized_request_headers(flow: http.HTTPFlow) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in _physical_request_header_entries(flow):
        raw_name_text = _request_header_text(raw_name, name=True)
        raw_value_text = _request_header_text(raw_value, name=False)
        if (
            not raw_name_text
            or len(raw_name_text.encode("utf-8")) > _REQUEST_HEADER_NAME_MAX_BYTES
            or _REQUEST_HEADER_NAME_RE.fullmatch(raw_name_text) is None
        ):
            raise ValueError("request contains an invalid or oversized header name")
        if (
            len(raw_value_text.encode("utf-8")) > _REQUEST_HEADER_VALUE_MAX_BYTES
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in raw_value_text
            )
        ):
            raise ValueError(
                f"request contains an invalid or oversized value for header {raw_name_text.lower()}"
            )
        name = raw_name_text.lower()
        if name in headers:
            raise ValueError(f"request repeats header {name} after case normalization")
        headers[name] = raw_value_text
    return headers


def _capture_request_mutation_snapshot(
    flow: http.HTTPFlow,
) -> _RequestMutationSnapshot:
    return _RequestMutationSnapshot(
        pretty_url=str(flow.request.pretty_url),
        headers=tuple(_physical_request_header_entries(flow)),
        raw_content=flow.request.raw_content,
    )


def _restore_request_mutation_snapshot(
    flow: http.HTTPFlow,
    snapshot: _RequestMutationSnapshot,
) -> None:
    flow.request.pretty_url = snapshot.pretty_url
    headers = flow.request.headers
    if hasattr(headers, "fields"):
        headers.fields = tuple(snapshot.headers)
    else:
        clear = getattr(headers, "clear", None)
        if not callable(clear):
            raise ValueError("request headers cannot be restored")
        clear()
        add = getattr(headers, "add", None)
        for name, value in snapshot.headers:
            if callable(add):
                add(name, value)
            else:
                headers[name] = value
    flow.request.raw_content = snapshot.raw_content
    query_view = getattr(flow.request, "query", None)
    if isinstance(query_view, dict):
        query_view.clear()
        query_view.update(
            _strict_query_pairs(
                validated_request_urlsplit(snapshot.pretty_url).query
            )
        )
    guard = _take_response_credential_guard(flow)
    if guard is not None:
        guard.clear()


def _discard_declared_request_headers(
    flow: http.HTTPFlow,
    route: RoutePolicy,
    principal: PrincipalPolicy,
    credential_policy: CredentialPolicy | None,
) -> tuple[str, ...]:
    if not isinstance(route.adapter_config, dict):
        raise PolicyBundleError(f"route {route.id} adapter policy must be an object")
    request_config = route.adapter_config.get("request")
    if not isinstance(request_config, dict):
        raise PolicyBundleError(f"route {route.id} request policy must be an object")
    raw_allowed_headers = request_config.get("allowedHeaders", [])
    raw_required_headers = request_config.get("requiredHeaders", {})
    if (
        not isinstance(raw_allowed_headers, list)
        or any(not isinstance(name, str) for name in raw_allowed_headers)
        or not isinstance(raw_required_headers, dict)
        or any(not isinstance(name, str) for name in raw_required_headers)
    ):
        raise PolicyBundleError(
            f"route {route.id} request header policy is malformed"
        )
    required_headers = {name.lower() for name in raw_required_headers}
    target = credential_injection_target(credential_policy.injection) if credential_policy else None
    credential_header = target[1] if target is not None and target[0] == "header" else None
    discard_headers = validate_discard_headers(
        route.id,
        request_config,
        allowed_headers={
            name.lower() for name in raw_allowed_headers
        },
        required_headers=required_headers,
        credential_header=credential_header,
        principal_identity_headers={
            str(name).lower() for name in principal.required_headers
        },
    )

    normalized_headers = _normalized_request_headers(flow)
    present_names = [
        name for name in discard_headers if name in normalized_headers
    ]
    # A public digest would expose low-entropy header values to offline guessing.
    # Until a dedicated audit HMAC key exists, retain only closed presence metadata.
    discarded_header_evidence = {
        "schema": "serverware.discardedRequestHeaders/v1",
        "declared_names": list(discard_headers),
        "present_names": present_names,
        "present_count": len(present_names),
        "raw_values_logged": False,
        "value_commitment": None,
        "value_commitment_reason": "no_dedicated_audit_hmac_key",
    }
    metadata = getattr(flow, "metadata", None)
    if isinstance(metadata, dict):
        metadata["serverware_discarded_request_headers"] = discarded_header_evidence
    discard_set = set(discard_headers)
    for raw_name, _ in _physical_request_header_entries(flow):
        raw_name_text = _request_header_text(raw_name, name=True)
        if raw_name_text.lower() in discard_set:
            del flow.request.headers[raw_name_text]
    if discard_set.intersection(_normalized_request_headers(flow)):
        raise ValueError("declared request header discard was incomplete")
    return discard_headers


def _canonical_forwarded_request_headers(
    flow: http.HTTPFlow,
    credential_policy: CredentialPolicy | None,
) -> dict[str, str]:
    headers = _normalized_request_headers(flow)
    nominated = {
        name.strip().lower()
        for name in headers.get("connection", "").split(",")
        if name.strip()
    }
    for name in nominated:
        if name in headers:
            raise ValueError(f"Connection nominates supplied header {name}")
    target = credential_injection_target(credential_policy.injection) if credential_policy else None
    credential_header = target[1] if target and target[0] == "header" else None
    forwarded = {
        name: value
        for name, value in headers.items()
        if name not in STANDARD_HOP_BY_HOP_HEADERS
        and name not in nominated
        and name != "authorization"
        and name != credential_header
        and name not in {"host", "content-length", "x-serverware-agent"}
        and name not in SERVERWARE_SERVICE_AUTH_HEADERS
        and not is_serverware_internal_header(name)
        and name != RESPONSE_PROOF_NONCE_HEADER
    }
    forwarded["host"] = _canonical_authority(flow.request.pretty_url)
    body_length = len(_request_body(flow))
    configured_length = headers.get("content-length")
    if configured_length is not None:
        try:
            parsed_length = int(configured_length)
        except ValueError as exc:
            raise ValueError("invalid content-length") from exc
        if parsed_length < 0 or parsed_length != body_length:
            raise ValueError("content-length does not match buffered request body")
        forwarded["content-length"] = str(parsed_length)
    elif body_length:
        forwarded["content-length"] = str(body_length)
    return dict(sorted(forwarded.items()))


def _credential_injection_collision(
    flow: http.HTTPFlow,
    credential_policy: CredentialPolicy | None,
) -> PolicyDecision | None:
    if credential_policy is None:
        return None
    try:
        _, target = _validated_credential_injection_contract(
            credential_policy.injection
        )
    except ValueError:
        return PolicyDecision(
            False,
            "credential injection target is invalid",
            500,
            {"error": "credential_injection_target_invalid"},
        )
    try:
        headers = _normalized_request_headers(flow)
    except ValueError as exc:
        return PolicyDecision(
            False,
            str(exc),
            400,
            {"error": "invalid_forwarding_headers", "detail": str(exc)},
        )
    location, name = target
    if location == "header" and name in headers:
        return PolicyDecision(
            False,
            f"agent header collides with credential injection: {name}",
            403,
            {"error": "credential_injection_header_collision", "header": name},
        )
    if location == "query":
        try:
            query = _strict_query_pairs(
                validated_request_urlsplit(flow.request.pretty_url).query
            )
        except ValueError:
            return PolicyDecision(
                False,
                "request query is invalid",
                400,
                {"error": "request_query_invalid"},
            )
        if any(key == name for key, _ in query):
            return PolicyDecision(
                False,
                "agent query collides with credential injection",
                403,
                {"error": "credential_injection_query_collision", "queryKey": name},
            )
    return None


def _bind_provider_account_scope(
    route: RoutePolicy,
    credential_policy: CredentialPolicy | None,
    operation_fields: dict[str, str],
) -> PolicyDecision | None:
    constraints = [
        str(constraint.get("id") or "unnamed")
        for constraint in route.constraints
        if constraint.get("type")
        in {"rateLimit", "slidingWindowLimit", "weightedBudget"}
        and PROVIDER_ACCOUNT_OPERATION_FIELD
        in set(((constraint.get("key") or {}).get("operationFields") or []))
    ]
    if not constraints:
        return None
    provider_account = (
        provider_account_scope_value(
            credential_policy.provider,
            credential_policy.provider_subject,
        )
        if credential_policy is not None
        else None
    )
    if provider_account is None:
        return PolicyDecision(
            False,
            "provider account identity is unavailable for account-scoped quota",
            500,
            {
                "error": "provider_account_identity_unavailable",
                "constraint_ids": constraints,
            },
        )
    operation_fields[PROVIDER_ACCOUNT_OPERATION_FIELD] = provider_account
    return None


def _json_scalar_at_path(payload: Any, path: str) -> str | None:
    value = payload
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -(2**63) <= value <= 2**63 - 1
    ):
        return str(value)
    return None


def _typed_request_value_values(
    flow: http.HTTPFlow,
    *,
    rule: dict[str, Any],
    params: dict[str, str],
    operation_fields: dict[str, str],
    json_body: Any,
    form_values: dict[str, list[str]],
) -> list[str]:
    source = rule.get("source")
    name = str(rule.get("name") or "")
    if source == "pathParam":
        value = params.get(name)
        return [value] if isinstance(value, str) else []
    if source == "query":
        parts = validated_request_urlsplit(flow.request.pretty_url)
        return [
            value
            for key, value in _strict_query_pairs(parts.query)
            if key == name
        ]
    if source == "header":
        values: list[str] = []
        for raw_name, raw_value in _physical_request_header_entries(flow):
            if _request_header_text(raw_name, name=True).lower() == name:
                values.append(_request_header_text(raw_value, name=False))
        return values
    if source == "jsonBody":
        value = _json_scalar_at_path(json_body, name)
        return [value] if value is not None else []
    if source == "formBody":
        return list(form_values.get(name) or [])
    if source == "operationField":
        value = operation_fields.get(name)
        return [value] if isinstance(value, str) else []
    return []


def _evaluate_typed_request_values(
    flow: http.HTTPFlow,
    route: RoutePolicy,
    params: dict[str, str],
    operation_fields: dict[str, str],
) -> tuple[PolicyDecision, Any]:
    request_value_constraints = [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "requestValue"
    ]
    filtered_route = _legacy_constraint_route(route)
    if not request_value_constraints:
        return PolicyDecision(True), filtered_route
    body = flow.request.raw_content or b""
    needs_json = any(
        rule.get("source") == "jsonBody"
        for constraint in request_value_constraints
        for rule in constraint.get("rules") or []
    )
    needs_form = any(
        rule.get("source") == "formBody"
        for constraint in request_value_constraints
        for rule in constraint.get("rules") or []
    )
    json_body: Any = None
    form_values: dict[str, list[str]] = {}
    try:
        if needs_json:
            json_body = strict_json_loads(body)
            if not isinstance(json_body, dict):
                raise ValueError("JSON requestValue body must be an object")
        if needs_form:
            text = body.decode("utf-8")
            pairs = parse_qsl(
                text,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=256,
            )
            if urlencode(pairs, doseq=True, quote_via=quote_plus) != text:
                raise ValueError("form requestValue body is not canonical")
            for key, value in pairs:
                form_values.setdefault(key, []).append(value)
    except (TypeError, UnicodeError, ValueError):
        return (
            PolicyDecision(
                False,
                "typed request value evidence is malformed",
                400,
                {"error": "request_value_evidence_malformed"},
            ),
            filtered_route,
        )
    captures: dict[str, str] = {}
    for constraint in request_value_constraints:
        constraint_id = str(constraint.get("id") or "unnamed")
        for rule_index, rule in enumerate(constraint.get("rules") or []):
            values = _typed_request_value_values(
                flow,
                rule=rule,
                params=params,
                operation_fields=operation_fields,
                json_body=json_body,
                form_values=form_values,
            )
            if len(values) != 1:
                return (
                    PolicyDecision(
                        False,
                        (
                            "required request value is missing"
                            if not values
                            else "request value must occur exactly once"
                        ),
                        403,
                        {
                            "error": (
                                "request_value_missing"
                                if not values
                                else "request_value_ambiguous"
                            ),
                            "constraint_id": constraint_id,
                            "source": rule.get("source"),
                            "name": rule.get("name"),
                            "ruleIndex": rule_index,
                        },
                    ),
                    filtered_route,
                )
            predicate = rule.get("predicate")
            if (
                not isinstance(predicate, dict)
                or not _request_value_predicate_matches(
                    predicate, values[0]
                )
            ):
                return (
                    PolicyDecision(
                        False,
                        "request value is outside the allowed policy",
                        403,
                        {
                            "error": "request_value_predicate_denied",
                            "constraint_id": constraint_id,
                            "source": rule.get("source"),
                            "name": rule.get("name"),
                            "ruleIndex": rule_index,
                        },
                    ),
                    filtered_route,
                )
            capture = rule.get("capture")
            if isinstance(capture, str):
                if capture in operation_fields or capture in captures:
                    return (
                        PolicyDecision(
                            False,
                            "request value capture collides with operation evidence",
                            503,
                            {
                                "error": "constraint_invalid_request_value",
                                "constraint_id": constraint_id,
                                "capture": capture,
                            },
                        ),
                        filtered_route,
                    )
                captures[capture] = values[0]
    operation_fields.update(captures)
    return PolicyDecision(True), filtered_route


def _durable_policy_key(
    constraint: dict[str, Any],
    *,
    principal_id: str,
    route: RoutePolicy,
    credential_version: int,
    operation_fields: dict[str, str],
) -> str:
    key = constraint.get("key") or {}
    scope = key.get("scope") or []
    material: dict[str, Any] = {
        "constraintId": constraint.get("id"),
    }
    for name in scope:
        if name == "principal":
            material[name] = principal_id
        elif name == "credential":
            material[name] = route.credential_ref or ""
        elif name == "credentialVersion":
            material[name] = credential_version
        elif name == "route":
            material[name] = route.id
        elif name == "operation":
            material[name] = operation_fields.get("operation") or ""
    for field_name in key.get("operationFields") or []:
        material[f"operation.{field_name}"] = operation_fields.get(
            field_name
        ) or ""
    return _digest(material)


def _single_request_evidence_value(
    flow: http.HTTPFlow,
    source: str,
    field_name: str,
) -> str | None:
    if source == "query":
        values = [
            value
            for key, value in _strict_query_pairs(
                validated_request_urlsplit(flow.request.pretty_url).query
            )
            if key == field_name
        ]
    elif source == "header":
        values = [
            _request_header_text(raw_value, name=False)
            for raw_name, raw_value in _physical_request_header_entries(flow)
            if _request_header_text(raw_name, name=True).lower()
            == field_name
        ]
    elif source == "jsonBody":
        payload = strict_json_loads(flow.request.raw_content or b"")
        value = _json_scalar_at_path(payload, field_name)
        values = [value] if value is not None else []
    else:
        raise ValueError("unsupported durable request evidence source")
    if len(values) > 1:
        raise ValueError("durable request evidence is ambiguous")
    return values[0] if values else None


def _durable_policy_claims(
    flow: http.HTTPFlow,
    *,
    snapshot: PolicySnapshot,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_version: int,
    operation_fields: dict[str, str],
) -> list[dict[str, Any]]:
    claims = shared_durable_budget_claims(
        route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=credential_version,
        policy_hash=snapshot.hash,
        operation_fields=operation_fields,
    )
    operation = operation_fields.get("operation") or ""
    query_pairs = _strict_query_pairs(
        validated_request_urlsplit(flow.request.pretty_url).query
    )
    for constraint in route.constraints:
        if constraint.get("type") != "traversalBudget":
            continue
        constraint_id = str(constraint.get("id") or "unnamed")
        operations = constraint.get("operations")
        if operations is not None and operation not in operations:
            continue
        traversal = constraint["traversal"]
        cursor_policy = traversal["cursor"]
        admitted_query_fields = adapter_operation_query_fields(
            route.adapter_type,
            route.adapter_config,
            operation,
        )
        if admitted_query_fields is None:
            raise ValueError(
                f"traversal budget {constraint_id} operation query catalog is unavailable"
            )
        cursor_query_field = (
            str(cursor_policy["requestField"])
            if cursor_policy["requestSource"] == "query"
            else None
        )
        if cursor_query_field is not None and cursor_query_field not in admitted_query_fields:
            raise ValueError(
                f"traversal budget {constraint_id} cursor query is not admitted for operation {operation}"
            )
        expected_lineage_fields = admitted_query_fields - (
            {cursor_query_field} if cursor_query_field is not None else set()
        )
        configured_lineage_fields = set(
            traversal["lineage"]["queryFields"]
        )
        if configured_lineage_fields != expected_lineage_fields:
            raise ValueError(
                f"traversal budget {constraint_id} query lineage is incomplete"
            )
        actual_query_fields = {key for key, _value in query_pairs}
        if not actual_query_fields.issubset(
            expected_lineage_fields
            | ({cursor_query_field} if cursor_query_field is not None else set())
        ):
            raise ValueError(
                f"traversal budget {constraint_id} request has an unbound shaping query"
            )
        cursor = _single_request_evidence_value(
            flow,
            str(cursor_policy["requestSource"]),
            str(cursor_policy["requestField"]),
        )
        canonical_query_fields: dict[str, str | None] = {}
        for field_name in sorted(expected_lineage_fields):
            values = [
                value for key, value in query_pairs if key == field_name
            ]
            if len(values) > 1:
                raise ValueError(
                    f"traversal budget {constraint_id} query lineage is ambiguous"
                )
            canonical_query_fields[field_name] = (
                values[0] if values else None
            )
        isolated_route = type(
            "_TraversalClaimRoute",
            (),
            {"id": route.id, "constraints": (constraint,)},
        )()
        claims.extend(
            traversal_budget_claims(
                isolated_route,
                principal_id=principal.id,
                credential_ref=route.credential_ref,
                credential_version=credential_version,
                policy_hash=snapshot.hash,
                operation_fields=operation_fields,
                canonical_query_fields=canonical_query_fields,
                request_cursor_values=(
                    {str(cursor_policy["requestField"]): cursor}
                    if cursor is not None
                    else {}
                ),
            )
        )
    return claims


def _canonical_request(
    flow: http.HTTPFlow,
    *,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_version: str,
    policy_hash: str,
    operation_fields: dict[str, str],
    forwarded_headers: dict[str, str],
    discard_headers: tuple[str, ...],
) -> dict[str, Any]:
    parts = validated_request_urlsplit(flow.request.pretty_url)
    query = _strict_query_pairs(parts.query)
    if parts.query != _canonical_query_wire(query):
        raise ValueError("request query is not in canonical wire form")
    request = {
        "method": flow.request.method.upper(),
        "scheme": parts.scheme,
        "authority": _canonical_authority(flow.request.pretty_url),
        "path": parts.path or "/",
        "query": query,
        "headers": forwarded_headers,
        "body_sha256": _body_sha256(flow),
    }
    version = 1
    if discard_headers:
        version = 2
        request["discard_headers"] = list(discard_headers)
    return {
        "v": version,
        "principal": principal.id,
        "client_ip": _client_ip(flow),
        "route_id": route.id,
        "credential_ref": route.credential_ref,
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request": request,
        "operation": operation_fields,
    }


def _digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _operation_digest(canonical_request: dict[str, Any]) -> str:
    operation_view = {
        "principal": canonical_request["principal"],
        "route_id": canonical_request["route_id"],
        "credential_ref": canonical_request["credential_ref"],
        "credential_version": canonical_request["credential_version"],
        "policy_hash": canonical_request["policy_hash"],
        "request": canonical_request["request"],
        "operation": canonical_request["operation"],
    }
    return _digest(operation_view)


def _audit_context(
    *,
    snapshot: PolicySnapshot,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_id: str | None,
    credential_version: int,
    request_digest: str | None,
    operation_digest: str | None,
    attempt_id: str | None = None,
    binding_digest: str | None = None,
    release_state: str | None = None,
    discarded_request_headers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "principal_id": principal.id,
        "policy_hash": snapshot.hash,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "release_state": release_state,
        "route_adapter": route.adapter_type,
        "discarded_request_headers": discarded_request_headers,
    }


def _strip_identity_headers(flow: http.HTTPFlow, principal: PrincipalPolicy) -> None:
    identity_headers = {
        str(name).lower() for name in principal.required_headers
    } | {
        "proxy-authorization",
        "x-serverware-agent",
        *SERVERWARE_SERVICE_AUTH_HEADERS,
    }
    for raw_name in list(flow.request.headers):
        name = str(raw_name).lower()
        if name in identity_headers or is_serverware_internal_header(name):
            del flow.request.headers[raw_name]


def _strip_identity_content_encoding(
    flow: http.HTTPFlow,
    expected_content_encoding: str | None,
) -> None:
    headers = _normalized_request_headers(flow)
    content_encoding = headers.get("content-encoding")
    if content_encoding != expected_content_encoding:
        raise ValueError("request Content-Encoding changed after raw admission")
    if content_encoding is None:
        return
    if content_encoding != "identity":
        raise ValueError("request Content-Encoding changed after raw admission")

    physical_name: Any | None = None
    for raw_name, _ in _physical_request_header_entries(flow):
        if _request_header_text(raw_name, name=True).lower() == "content-encoding":
            physical_name = raw_name
            break
    if physical_name is None:
        raise ValueError("identity request Content-Encoding is unavailable")
    try:
        del flow.request.headers[physical_name]
    except Exception as exc:
        raise ValueError(
            "identity request Content-Encoding could not be removed"
        ) from exc
    if "content-encoding" in _normalized_request_headers(flow):
        raise ValueError("identity request Content-Encoding removal was incomplete")


def _identity_header_names(principal: PrincipalPolicy) -> set[str]:
    return {
        str(name).lower() for name in principal.required_headers
    } | {
        "proxy-authorization",
        "x-serverware-agent",
        *SERVERWARE_SERVICE_AUTH_HEADERS,
    }


def _provider_request_matches_canonical(
    flow: http.HTTPFlow,
    canonical_request: dict[str, Any],
    credential_policy: CredentialPolicy | None,
    credential: dict[str, Any] | None = None,
) -> bool:
    request = canonical_request.get("request")
    if not isinstance(request, dict):
        return False
    try:
        parts = validated_request_urlsplit(flow.request.pretty_url)
        query = _strict_query_pairs(parts.query)
        if parts.query != _canonical_query_wire(query):
            return False
        expected_query = _validated_canonical_query_pairs(request.get("query"))
        target = (
            credential_injection_target(credential_policy.injection)
            if credential_policy is not None
            else None
        )
        if target is not None and target[0] == "query":
            injected = [
                (key, value) for key, value in query if key == target[1]
            ]
            if len(injected) != 1 or not isinstance(credential, dict):
                return False
            injection = credential_policy.injection or {
                "type": credential.get("kind", "query")
            }
            expected_secret = _secret_for_injection(
                str(credential["secret"]),
                injection,
            )
            if injected[0][1] != expected_secret:
                return False
            query = [(key, value) for key, value in query if key != target[1]]
        return (
            flow.request.method.upper() == request.get("method")
            and parts.scheme == request.get("scheme")
            and _canonical_authority(flow.request.pretty_url)
            == request.get("authority")
            and (parts.path or "/") == request.get("path")
            and query == expected_query
            and _canonical_forwarded_request_headers(flow, credential_policy)
            == request.get("headers")
            and _body_sha256(flow) == request.get("body_sha256")
        )
    except (KeyError, TypeError, ValueError):
        return False


def _canonical_oauth_scopes(raw_scopes: Any, *, field_name: str) -> frozenset[str]:
    if not isinstance(raw_scopes, list) or not raw_scopes:
        raise ValueError(f"{field_name} must be a non-empty array")
    scopes: list[str] = []
    for scope in raw_scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or any(character.isspace() for character in scope)
        ):
            raise ValueError(f"{field_name} contains an invalid scope")
        scopes.append(scope)
    if len(scopes) > 64 or any(len(scope.encode("utf-8")) > 512 for scope in scopes):
        raise ValueError(f"{field_name} is too large")
    if len(scopes) != len(set(scopes)):
        raise ValueError(f"{field_name} contains duplicate scopes")
    return frozenset(scopes)


def _credential_metadata_scopes(metadata: dict[str, Any]) -> frozenset[str]:
    populated = [
        metadata[name]
        for name in ("scopes", "scope")
        if metadata.get(name) is not None
    ]
    if not populated:
        return frozenset()
    normalized: list[frozenset[str]] = []
    for raw_scopes in populated:
        if isinstance(raw_scopes, str):
            scopes = [item for item in raw_scopes.split() if item]
        elif isinstance(raw_scopes, list) and all(
            isinstance(item, str) and item for item in raw_scopes
        ):
            scopes = raw_scopes
        else:
            raise ValueError("credential scope metadata is invalid")
        if len(scopes) != len(set(scopes)):
            raise ValueError("credential scope metadata contains duplicates")
        normalized.append(frozenset(scopes))
    if any(scopes != normalized[0] for scopes in normalized[1:]):
        raise ValueError("credential scope aliases are contradictory")
    return normalized[0]


def _consistent_metadata_alias(
    metadata: dict[str, Any],
    names: tuple[str, ...],
    *,
    normalize: Any = None,
    required: bool = True,
) -> str | None:
    values: list[str] = []
    normalized: list[str] = []
    for name in names:
        if metadata.get(name) is None:
            continue
        value = metadata[name]
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value.encode("utf-8")) > 2048
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError(f"credential metadata alias {name} is invalid")
        values.append(value)
        normalized.append(normalize(value) if normalize is not None else value)
    if not values:
        if required:
            raise ValueError("credential metadata binding alias is missing")
        return None
    if any(value != normalized[0] for value in normalized[1:]):
        raise ValueError("credential metadata aliases are contradictory")
    return values[0]


def _credential_policy_binding_decision(
    route: RoutePolicy,
    credential_policy: CredentialPolicy,
    credential: dict[str, Any],
    operation: str,
) -> PolicyDecision | None:
    metadata = credential.get("metadata") or {}
    if not isinstance(metadata, dict):
        return PolicyDecision(
            False,
            "credential metadata is invalid",
            503,
            {"error": "credential_policy_binding_invalid"},
        )

    policy_provider = normalized_credential_provider(credential_policy.provider)
    try:
        stored_provider_value = _consistent_metadata_alias(
            metadata,
            ("provider_id", "provider"),
            normalize=normalized_credential_provider,
        )
        stored_provider = normalized_credential_provider(stored_provider_value)
        _consistent_metadata_alias(
            metadata,
            ("provider_account", "account"),
            required=False,
        )
    except ValueError as exc:
        return PolicyDecision(
            False,
            str(exc),
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "provider"},
        )
    if stored_provider != policy_provider:
        return PolicyDecision(
            False,
            "stored credential provider does not match the active signed policy",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "provider"},
        )
    if credential_policy.kind == "oauth2" and credential.get("kind") != "oauth2":
        return PolicyDecision(
            False,
            "signed provider account binding requires a verified OAuth credential",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
        )

    binding = route.adapter_config.get("credentialBinding")
    if not isinstance(binding, dict):
        return PolicyDecision(
            False,
            "route credential binding is unavailable",
            503,
            {"error": "credential_policy_binding_invalid", "binding": "route"},
        )
    if (
        binding.get("credentialType") != credential_policy.kind
        or normalized_credential_provider(binding.get("provider")) != policy_provider
        or binding.get("subjects") != [credential_policy.provider_subject]
    ):
        return PolicyDecision(
            False,
            "route credential binding does not match the signed credential",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "route"},
        )

    if credential.get("kind") == "oauth2":
        try:
            _consistent_metadata_alias(
                metadata, ("provider_subject", "account_subject")
            )
            stored_client_id = _consistent_metadata_alias(
                metadata,
                ("oauth_client_id", "client_id", "x_app_id", "app_id"),
            )
        except ValueError as exc:
            return PolicyDecision(
                False,
                str(exc),
                409,
                {
                    "error": "credential_policy_binding_mismatch",
                    "binding": "credentialAliases",
                },
            )
        try:
            stored_scopes_from_aliases = _credential_metadata_scopes(metadata)
        except ValueError as exc:
            contradictory = "contradictory" in str(exc)
            return PolicyDecision(
                False,
                str(exc),
                409 if contradictory else 503,
                {
                    "error": (
                        "credential_policy_binding_mismatch"
                        if contradictory
                        else "credential_policy_binding_invalid"
                    ),
                    "binding": (
                        "credentialAliases" if contradictory else "scope"
                    ),
                },
            )
        try:
            verified_provider, stored_subject = db.validate_managed_oauth_identity(metadata)
        except db.ManagedOAuthCredentialError as exc:
            return PolicyDecision(
                False,
                str(exc),
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
            )
        if normalized_credential_provider(verified_provider) != policy_provider:
            return PolicyDecision(
                False,
                "verified OAuth provider does not match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "provider"},
            )
        policy_subject = credential_policy.provider_subject
        if (
            not isinstance(policy_subject, str)
            or not policy_subject
            or stored_subject != policy_subject
        ):
            return PolicyDecision(
                False,
                "stored OAuth account does not match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
            )
        try:
            stored_scopes = _canonical_oauth_scopes(
                list(stored_scopes_from_aliases),
                field_name="OAuth credential metadata scopes",
            )
            policy_scopes = _canonical_oauth_scopes(
                list(credential_policy.scopes),
                field_name="signed policy OAuth scopes",
            )
        except ValueError as exc:
            return PolicyDecision(
                False,
                str(exc),
                503,
                {"error": "credential_policy_binding_invalid", "binding": "scope"},
            )
        if stored_scopes != policy_scopes:
            return PolicyDecision(
                False,
                "stored OAuth scopes do not exactly match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "scope"},
            )
        if (
            not isinstance(stored_client_id, str)
            or not credential_policy.oauth_client_id
            or not hmac.compare_digest(
                stored_client_id, credential_policy.oauth_client_id
            )
            or binding.get("clientIds") != [stored_client_id]
            or (
                route.adapter_type == "x.v2"
                and route.adapter_config.get("appIds") != [stored_client_id]
            )
        ):
            return PolicyDecision(
                False,
                "stored OAuth client does not match the active signed policy",
                409,
                {
                    "error": "credential_policy_binding_mismatch",
                    "binding": "oauthClientId",
                },
            )
        required_scopes = binding.get("requiredScopes")
        operation_scopes = required_oauth_scopes_for_operation(
            route.adapter_type, operation
        )
        if (
            not isinstance(required_scopes, list)
            or not required_scopes
            or operation_scopes is None
            or not operation_scopes.issubset(set(required_scopes))
            or not operation_scopes.issubset(stored_scopes)
            or not set(required_scopes).issubset(stored_scopes)
        ):
            return PolicyDecision(
                False,
                "stored OAuth scopes do not satisfy the route binding",
                409,
                {
                    "error": "credential_policy_binding_mismatch",
                    "binding": "requiredScopes",
                },
            )
        oauth_injection = credential_policy.injection
        if (
            not isinstance(oauth_injection, dict)
            or oauth_injection.get("type") != "bearer"
            or str(oauth_injection.get("header") or "Authorization").lower()
            != "authorization"
            or oauth_injection.get("field") != "access_token"
            or oauth_injection.get("prefix", "Bearer ") != "Bearer "
            or (
                metadata.get("injection_field") is not None
                and metadata.get("injection_field") != "access_token"
            )
            or (
                metadata.get("injection_prefix") is not None
                and metadata.get("injection_prefix") != "Bearer "
            )
        ):
            return PolicyDecision(
                False,
                "managed OAuth injection does not match the signed policy",
                409,
                {
                    "error": "credential_policy_binding_mismatch",
                    "binding": "injection",
                },
            )
        return None

    if credential_policy.kind != "static" or credential.get("kind") == "oauth2":
        return PolicyDecision(
            False,
            "stored credential type does not match the active signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "credentialType",
            },
        )
    try:
        stored_subject = _consistent_metadata_alias(
            metadata, ("provider_subject", "account_subject")
        )
        stored_secret_class = _consistent_metadata_alias(
            metadata, ("secret_class", "token_class")
        )
    except ValueError as exc:
        return PolicyDecision(
            False,
            str(exc),
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "credentialAliases",
            },
        )
    try:
        stored_scopes = _credential_metadata_scopes(metadata)
    except ValueError as exc:
        contradictory = "contradictory" in str(exc)
        return PolicyDecision(
            False,
            str(exc),
            409 if contradictory else 503,
            {
                "error": (
                    "credential_policy_binding_mismatch"
                    if contradictory
                    else "credential_policy_binding_invalid"
                ),
                "binding": (
                    "credentialAliases" if contradictory else "scope"
                ),
            },
        )
    policy_scopes = frozenset(credential_policy.scopes)
    if stored_scopes != policy_scopes:
        return PolicyDecision(
            False,
            "stored credential scopes do not exactly match the active signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "scope",
            },
        )
    injection = credential_policy.injection
    injection_type = injection.get("type") if isinstance(injection, dict) else None
    if credential.get("kind") != injection_type:
        return PolicyDecision(
            False,
            "stored credential kind does not match the signed injection type",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "injectionType",
            },
        )
    if injection_type in {"header", "query", "cookie"} and injection.get(
        "name"
    ) != metadata.get("injection_name"):
        return PolicyDecision(
            False,
            "stored credential injection name does not match the signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "injectionName",
            },
        )
    if injection_type == "basic" and injection.get("username") != metadata.get(
        "username"
    ):
        return PolicyDecision(
            False,
            "stored credential Basic username does not match the signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "injectionUsername",
            },
        )
    if metadata.get("injection_field") is not None and injection.get(
        "field"
    ) != metadata.get("injection_field"):
        return PolicyDecision(
            False,
            "stored credential injection field does not match the signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "injectionField",
            },
        )
    if metadata.get("injection_prefix") is not None and injection.get(
        "prefix"
    ) != metadata.get("injection_prefix"):
        return PolicyDecision(
            False,
            "stored credential injection prefix does not match the signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "injectionPrefix",
            },
        )
    if (
        not isinstance(stored_subject, str)
        or not hmac.compare_digest(
            stored_subject, credential_policy.provider_subject or ""
        )
    ):
        return PolicyDecision(
            False,
            "stored credential account does not match the active signed policy",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "providerSubject",
            },
        )
    expected_secret_class = binding.get("secretClass")
    if (
        not isinstance(expected_secret_class, str)
        or stored_secret_class != expected_secret_class
    ):
        return PolicyDecision(
            False,
            "stored credential class does not match the route binding",
            409,
            {
                "error": "credential_policy_binding_mismatch",
                "binding": "secretClass",
            },
        )
    return None


def _secret_for_injection(secret: str, injection: dict[str, Any]) -> str:
    field = injection.get("field")
    if not field:
        return secret
    if not isinstance(field, str) or not SECRET_FIELD_PATH_RE.fullmatch(field):
        raise ValueError("credential injection field must be a dotted object path")
    try:
        value: Any = strict_json_loads(secret)
    except Exception as exc:
        raise ValueError(f"credential secret is not JSON for field {field}") from exc
    for part in str(field).split("."):
        if not part:
            continue
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"credential secret missing field {field}")
        value = value[part]
    if not isinstance(value, str) or not value:
        raise ValueError(f"credential secret field {field} is not a non-empty string")
    return value


def _validated_credential_injection_contract(
    raw: Any,
) -> tuple[str, tuple[str, str]]:
    if not isinstance(raw, dict):
        raise ValueError("credential injection must be an object")
    injection_type = raw.get("type")
    allowed_fields = _CREDENTIAL_INJECTION_FIELDS.get(injection_type)
    if allowed_fields is None or set(raw) - allowed_fields:
        raise ValueError("credential injection type or fields are invalid")

    field = raw.get("field")
    if field is not None and (
        not isinstance(field, str)
        or len(field) > 256
        or SECRET_FIELD_PATH_RE.fullmatch(field) is None
    ):
        raise ValueError("credential injection field is invalid")

    prefix = raw.get("prefix")
    if prefix is not None and (
        not isinstance(prefix, str)
        or len(prefix.encode("utf-8")) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in prefix)
    ):
        raise ValueError("credential injection prefix is invalid")

    if injection_type == "basic":
        username = raw.get("username")
        if (
            not isinstance(username, str)
            or not username
            or len(username.encode("utf-8")) > 256
            or any(
                character == ":"
                or character.isspace()
                or ord(character) < 32
                or ord(character) == 127
                for character in username
            )
        ):
            raise ValueError("Basic credential username is invalid")

    if injection_type in {"header", "query", "cookie"}:
        name = raw.get("name")
        if (
            not isinstance(name, str)
            or len(name.encode("ascii", errors="ignore")) != len(name)
            or not 1 <= len(name) <= _REQUEST_HEADER_NAME_MAX_BYTES
            or _REQUEST_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise ValueError("credential injection target name is invalid")

    target = credential_injection_target(raw)
    if target is None:
        raise ValueError("credential injection has no enforceable target")
    location, target_name = target
    if location == "header":
        if (
            not target_name
            or len(target_name.encode("ascii", errors="ignore")) != len(target_name)
            or len(target_name) > _REQUEST_HEADER_NAME_MAX_BYTES
            or _REQUEST_HEADER_NAME_RE.fullmatch(target_name) is None
        ):
            raise ValueError("credential injection header is invalid")
        reserved_target_is_canonical = (
            injection_type in {"bearer", "basic"}
            and target_name == "authorization"
        ) or (injection_type == "cookie" and target_name == "cookie")
        if (
            (
                target_name in STANDARD_HOP_BY_HOP_HEADERS
                or target_name in {"host", "content-length", "content-encoding"}
                or target_name in SERVERWARE_SERVICE_AUTH_HEADERS
                or target_name == RESPONSE_PROOF_NONCE_HEADER
                or target_name == "proxy-authorization"
                or (target_name == "cookie" and injection_type != "cookie")
                or (target_name == "authorization" and injection_type == "header")
                or is_serverware_internal_header(target_name)
            )
            and not reserved_target_is_canonical
        ):
            raise ValueError("credential injection header is reserved")
    elif location != "query":
        raise ValueError("credential injection location is invalid")
    return str(injection_type), target


def _bounded_credential_component(value: str, *, context: str) -> str:
    if not value or len(value.encode("utf-8")) > _REQUEST_HEADER_VALUE_MAX_BYTES:
        raise ValueError(f"{context} credential value is empty or too large")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{context} credential value contains control characters")
    return value


def _bounded_credential_header_value(value: str, *, context: str) -> str:
    _bounded_credential_component(value, context=context)
    if value != value.strip(" "):
        raise ValueError(f"{context} credential header has outer whitespace")
    return value


def _inject_credential(flow: http.HTTPFlow, credential_policy: CredentialPolicy, credential: dict[str, Any]) -> str:
    injection = credential_policy.injection
    injection_type, _ = _validated_credential_injection_contract(injection)
    if credential.get("kind") == "oauth2" and (
        injection_type != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise ValueError("managed OAuth credential injection is not canonical access-token-only bearer")
    secret = _secret_for_injection(str(credential["secret"]), injection)
    if not secret or len(secret.encode("utf-8")) > _REQUEST_HEADER_VALUE_MAX_BYTES:
        raise ValueError("credential value is empty or too large")
    guard = _ResponseCredentialGuard()
    guard.add_text_encodings(secret)
    installed = False
    try:
        if injection_type == "bearer":
            header = injection.get("header", "Authorization")
            _bounded_credential_header_value(secret, context="bearer")
            value = _bounded_credential_header_value(
                f"{injection.get('prefix', 'Bearer ')}{secret}",
                context="bearer",
            )
            flow.request.headers[header] = value
            guard.add_text_encodings(value)
            reason = f"injected bearer into {header}"
        elif injection_type == "header":
            name = injection.get("name", "X-Api-Key")
            _bounded_credential_header_value(secret, context="header")
            value = _bounded_credential_header_value(
                f"{injection.get('prefix', '')}{secret}",
                context="header",
            )
            flow.request.headers[name] = value
            guard.add_text_encodings(value)
            reason = f"injected header {name}"
        elif injection_type == "query":
            name = injection.get("name", "access_token")
            _bounded_credential_component(secret, context="query")
            query = _strict_query_pairs(
                validated_request_urlsplit(flow.request.pretty_url).query
            )
            if any(key == name for key, _ in query):
                raise ValueError("credential query target is already present")
            query.append((name, secret))
            query.sort()
            _set_request_query_wire(flow, query)
            reason = "injected query credential"
        elif injection_type == "cookie":
            name = injection.get("name", "serverware_token")
            _bounded_credential_component(secret, context="cookie")
            if _COOKIE_VALUE_RE.fullmatch(secret) is None:
                raise ValueError("cookie credential is not a canonical cookie-octet value")
            current = flow.request.headers.get("Cookie", "")
            flow.request.headers["Cookie"] = f"{current}{'; ' if current else ''}{name}={secret}"
            guard.add_text_encodings(f"{name}={secret}")
            reason = f"injected cookie {name}"
        elif injection_type == "basic":
            username = injection["username"]
            password_text = secret
            _bounded_credential_component(
                password_text,
                context="Basic password",
            )
            raw = f"{username}:{password_text}"
            token = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            value = _bounded_credential_header_value(
                f"Basic {token}",
                context="Basic",
            )
            flow.request.headers[injection.get("header", "Authorization")] = value
            guard.add_text_encodings(password_text)
            guard.add_text_encodings(raw)
            guard.add_text_encodings(token)
            guard.add_text_encodings(value)
            reason = "injected basic authorization"
        else:
            raise ValueError(f"unknown injection type {injection_type}")
        _install_response_credential_guard(flow, guard)
        installed = True
        return reason
    finally:
        if not installed:
            guard.clear()


def _release_lifecycle(flow: http.HTTPFlow) -> dict[str, Any] | None:
    lifecycle = flow.metadata.get("serverware_release_authorization")
    return lifecycle if isinstance(lifecycle, dict) else None


def _release_guard(flow: http.HTTPFlow) -> runtime.ReleaseAuthorizationGuard | None:
    guard = flow.metadata.get("serverware_release_authorization_guard")
    return (
        guard
        if isinstance(guard, runtime.ReleaseAuthorizationGuard)
        else None
    )


def _valid_release_authorization_identity(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value.encode("utf-8")) <= _RELEASE_AUTHORIZATION_ID_MAX_BYTES
        and all(character.isprintable() for character in value)
    )


def _validated_successful_release_reserve(
    reserved: dict[str, Any],
    *,
    attempt_id: str,
    jit_required: bool,
) -> dict[str, str | int | None] | None:
    binding_digest = reserved.get("binding_digest")
    reservation_expires_at_epoch_ms = reserved.get(
        "reservation_expires_at_epoch_ms"
    )
    grant_id = reserved.get("grant_id")
    approval_request_id = reserved.get("approval_request_id")
    exact_lifecycle = (
        reserved.get("authorized") is True
        and reserved.get("state") == "reserved"
        and reserved.get("reason") == "reserved"
        and reserved.get("attempt_id") == attempt_id
        and isinstance(binding_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", binding_digest) is not None
        and reserved.get("completion_outcome") is None
        and isinstance(reservation_expires_at_epoch_ms, int)
        and not isinstance(reservation_expires_at_epoch_ms, bool)
        and 0 <= reservation_expires_at_epoch_ms <= _UINT64_MAX
        and reserved.get("dispatch_started_at_epoch_ms") is None
        and reserved.get("dispatch_expires_at_epoch_ms") is None
        and reserved.get("retry_after_seconds") == 0
        and not isinstance(reserved.get("retry_after_seconds"), bool)
        and reserved.get("approval_status") is None
        and reserved.get("approval_expires_at") is None
        and reserved.get("approval_created") is None
    )
    if not exact_lifecycle:
        return None
    if jit_required:
        if not (
            _valid_release_authorization_identity(grant_id)
            and _valid_release_authorization_identity(approval_request_id)
        ):
            return None
    elif grant_id is not None or approval_request_id is not None:
        return None
    return {
        "binding_digest": binding_digest,
        "reservation_expires_at_epoch_ms": reservation_expires_at_epoch_ms,
        "grant_id": grant_id,
        "approval_request_id": approval_request_id,
    }


def _store_release_lifecycle(
    flow: http.HTTPFlow,
    *,
    attempt_id: str,
    binding_digest: str,
    state: str,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    reservation_expires_at_epoch_ms: int | None = None,
    quotas: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    lifecycle = {
        "attempt_id": attempt_id,
        "flow_id": attempt_id,
        "binding_digest": binding_digest,
        "state": state,
        "dispatch_attempted": False,
        "quotas": [dict(item) for item in (quotas or [])],
    }
    if grant_id is not None:
        lifecycle["grant_id"] = grant_id
        flow.metadata["serverware_release_grant_id"] = grant_id
    if approval_request_id is not None:
        lifecycle["approval_request_id"] = approval_request_id
        flow.metadata["serverware_release_approval_request_id"] = approval_request_id
    if reservation_expires_at_epoch_ms is not None:
        lifecycle["reservation_expires_at_epoch_ms"] = reservation_expires_at_epoch_ms
    flow.metadata["serverware_release_authorization"] = lifecycle
    flow.metadata["serverware_release_attempt_id"] = attempt_id
    flow.metadata["serverware_release_binding_digest"] = binding_digest
    flow.metadata["serverware_release_state"] = state
    return lifecycle


def _set_release_state(
    flow: http.HTTPFlow,
    lifecycle: dict[str, Any],
    state: str,
    *,
    outcome: str | None = None,
) -> None:
    lifecycle["state"] = state
    if outcome is not None:
        lifecycle["completion_outcome"] = outcome
    flow.metadata["serverware_release_state"] = state
    if outcome is not None:
        flow.metadata["serverware_release_completion_outcome"] = outcome


def complete_release_authorization(
    flow: http.HTTPFlow,
    outcome: str,
) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    guard = _release_guard(flow)
    durable_completion = flow.metadata.get(
        "serverware_durable_policy_completion"
    )
    effective_outcome = outcome
    if lifecycle is not None and lifecycle.get("durable_policy") is not None:
        if outcome == "forwarded":
            if (
                isinstance(durable_completion, dict)
                and durable_completion.get("outcome") == "unknown"
            ):
                effective_outcome = "unknown"
            elif (
                not isinstance(durable_completion, dict)
                or durable_completion.get("outcome") != "forwarded"
            ):
                (
                    failure_reason,
                    response_body_sha256,
                    traversal_evidence,
                ) = _durable_failure_evidence(
                    flow,
                    body=(
                        flow.response.raw_content
                        if flow.response is not None
                        and isinstance(flow.response.raw_content, bytes)
                        else b""
                    ),
                    reason="durable_response_completion_missing",
                )
                durable_completion = {
                    "outcome": "unknown",
                    "response_evidence": traversal_evidence,
                    "response_body_sha256": response_body_sha256,
                    "failure_reason": failure_reason,
                    "uncertainty": "charged_fail_closed",
                }
                effective_outcome = "unknown"
        elif outcome == "unknown" and (
            not isinstance(durable_completion, dict)
            or durable_completion.get("outcome") != "unknown"
        ):
            (
                failure_reason,
                response_body_sha256,
                traversal_evidence,
            ) = _durable_failure_evidence(
                flow,
                body=(
                    flow.response.raw_content
                    if flow.response is not None
                    and isinstance(flow.response.raw_content, bytes)
                    else b""
                ),
                reason="provider_outcome_uncertain",
            )
            durable_completion = {
                "outcome": "unknown",
                "response_evidence": traversal_evidence,
                "response_body_sha256": response_body_sha256,
                "failure_reason": failure_reason,
                "uncertainty": "charged_fail_closed",
            }
            dispatch_deadline = lifecycle.get(
                "dispatch_expires_at_epoch_ms"
            )
            if type(dispatch_deadline) is int:
                durable_completion[
                    "dispatch_deadline_at_epoch_ms"
                ] = dispatch_deadline
        if isinstance(durable_completion, dict):
            flow.metadata[
                "serverware_durable_policy_completion"
            ] = copy.deepcopy(durable_completion)

    def release_completion_denial(
        decision: PolicyDecision,
    ) -> PolicyDecision:
        return decision

    if outcome == "not_forwarded" and guard is not None:
        result = guard.cancel_not_forwarded_once()
        if result is None:
            if guard.cleanup_error:
                if lifecycle is not None:
                    lifecycle["cleanup_state"] = "cleanup_unknown"
                    lifecycle["cleanup_error"] = guard.cleanup_error_detail
                    _set_release_state(
                        flow,
                        lifecycle,
                        "cleanup_unknown",
                        outcome="not_forwarded",
                    )
                else:
                    flow.metadata["serverware_release_state"] = "cleanup_unknown"
                    flow.metadata[
                        "serverware_release_completion_outcome"
                    ] = "not_forwarded"
                    flow.metadata[
                        "serverware_release_cleanup_error"
                    ] = guard.cleanup_error_detail
            return release_completion_denial(
                PolicyDecision(
                    False,
                    "release authorization completion is uncertain",
                    503,
                    {
                        "error": (
                            "release_authorization_completion_uncertain"
                        )
                    },
                )
            )
        if lifecycle is not None and result.get("state") in {"absent", "cancelled"}:
            lifecycle["cleanup_state"] = result.get("state")
            lifecycle["quotas"] = [dict(item) for item in result.get("quotas") or []]
            lifecycle["dispatch_started_at_epoch_ms"] = None
            lifecycle["dispatch_expires_at_epoch_ms"] = None
            if isinstance(result.get("durable_policy"), dict):
                lifecycle["durable_policy"] = copy.deepcopy(
                    result["durable_policy"]
                )
                flow.metadata[
                    "serverware_durable_policy_reservation"
                ] = copy.deepcopy(result["durable_policy"])
            _set_release_state(
                flow,
                lifecycle,
                "cancelled",
                outcome="not_forwarded",
            )
        return PolicyDecision(True)
    if lifecycle is None:
        return PolicyDecision(True)
    state = str(lifecycle.get("state") or "")
    terminal_states = {
        "cancelled",
        "cleanup_unknown",
        "committed",
        "committed_indeterminate",
    }
    if state in terminal_states:
        if lifecycle.get("completion_outcome") in {None, effective_outcome}:
            return PolicyDecision(True)
        return release_completion_denial(
            PolicyDecision(
                False,
                (
                    "release authorization already completed with a "
                    "different outcome"
                ),
                503,
                {"error": "release_authorization_completion_conflict"},
            )
        )
    if state not in {"reserved", "dispatching"}:
        return release_completion_denial(
            PolicyDecision(
                False,
                "release authorization lifecycle is invalid",
                503,
                {"error": "release_authorization_lifecycle_invalid"},
            )
        )
    try:
        completion_arguments = {
            "attempt_id": str(lifecycle["attempt_id"]),
            "binding_digest": str(lifecycle["binding_digest"]),
            "outcome": effective_outcome,
            "grant_id": lifecycle.get("grant_id"),
            "approval_request_id": lifecycle.get(
                "approval_request_id"
            ),
            "previous_lifecycle": lifecycle,
        }
        if lifecycle.get("durable_policy") is not None:
            completion_arguments["durable_completion"] = (
                {
                    key: copy.deepcopy(value)
                    for key, value in durable_completion.items()
                    if key != "outcome"
                }
                if isinstance(durable_completion, dict)
                else None
            )
        result = runtime.complete_release_authorization(
            **completion_arguments
        )
    except Exception:
        return release_completion_denial(
            PolicyDecision(
                False,
                "release authorization completion is uncertain",
                503,
                {"error": "release_authorization_completion_uncertain"},
            )
        )
    try:
        runtime.validate_complete_release_authorization_response(
            result,
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            outcome=effective_outcome,
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
            previous_lifecycle=lifecycle,
        )
    except Exception:
        return release_completion_denial(
            PolicyDecision(
                False,
                "release authorization completion state is invalid",
                503,
                {"error": "release_authorization_completion_invalid"},
            )
        )
    try:
        lifecycle["quotas"] = [dict(item) for item in result["quotas"]]
        lifecycle["dispatch_started_at_epoch_ms"] = result.get(
            "dispatch_started_at_epoch_ms"
        )
        lifecycle["dispatch_expires_at_epoch_ms"] = result.get(
            "dispatch_expires_at_epoch_ms"
        )
        if isinstance(result.get("durable_policy"), dict):
            lifecycle["durable_policy"] = copy.deepcopy(
                result["durable_policy"]
            )
            flow.metadata[
                "serverware_durable_policy_reservation"
            ] = copy.deepcopy(result["durable_policy"])
        _set_release_state(
            flow,
            lifecycle,
            str(result["state"]),
            outcome=str(result["completion_outcome"]),
        )
        if guard is not None:
            guard.mark_terminal()
    except Exception:
        return release_completion_denial(
            PolicyDecision(
                False,
                "release authorization completion state is invalid",
                503,
                {"error": "release_authorization_completion_invalid"},
            )
        )
    durable = lifecycle.get("durable_policy")
    if isinstance(durable, dict):
        if durable.get("state") == "denied":
            return PolicyDecision(
                False,
                "durable traversal response budget denied",
                502,
                {
                    "error": "durable_traversal_response_denied",
                    "reason": durable.get("failure_reason"),
                },
            )
        if durable.get("state") == "indeterminate":
            return PolicyDecision(
                False,
                "durable policy response completion is indeterminate",
                503,
                {"error": "durable_policy_response_indeterminate"},
            )
    return PolicyDecision(True)


def dispatch_release_authorization(flow: http.HTTPFlow) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    if lifecycle is None:
        if runtime.atomic_release_authorization_enabled():
            return PolicyDecision(
                False,
                "release authorization lifecycle is missing",
                503,
                {"error": "release_authorization_lifecycle_missing"},
            )
        return PolicyDecision(True)
    if lifecycle.get("state") != "reserved":
        return PolicyDecision(
            False,
            "release authorization is not reserved",
            503,
            {"error": "release_authorization_not_reserved"},
        )
    reservation_expires_at = lifecycle.get("reservation_expires_at_epoch_ms")
    if (
        not isinstance(reservation_expires_at, int)
        or isinstance(reservation_expires_at, bool)
        or reservation_expires_at <= int(time.time() * 1000)
    ):
        cancellation = complete_release_authorization(flow, "not_forwarded")
        if not cancellation.allowed:
            return cancellation
        return PolicyDecision(
            False,
            "release authorization reservation is expired",
            503,
            {"error": "release_authorization_reservation_expired"},
        )
    lifecycle["dispatch_attempted"] = True
    guard = _release_guard(flow)
    durable = lifecycle.get("durable_policy")
    dispatch_deadline_at_epoch_ms = None
    try:
        if durable is not None:
            dispatch_deadline_at_epoch_ms = (
                runtime.release_authorization_dispatch_deadline(lifecycle)
            )
        dispatch_arguments = {
            "attempt_id": str(lifecycle["attempt_id"]),
            "binding_digest": str(lifecycle["binding_digest"]),
            "grant_id": lifecycle.get("grant_id"),
            "approval_request_id": lifecycle.get(
                "approval_request_id"
            ),
            "previous_lifecycle": lifecycle,
        }
        if dispatch_deadline_at_epoch_ms is not None:
            dispatch_arguments[
                "dispatch_deadline_at_epoch_ms"
            ] = dispatch_deadline_at_epoch_ms
        result = runtime.dispatch_release_authorization(
            **dispatch_arguments
        )
    except runtime.ReleaseAuthorizationClientError:
        if guard is not None:
            guard.mark_dispatch_authorized()
            guard.mark_dispatch_uncertain()
        complete_release_authorization(flow, "unknown")
        return PolicyDecision(
            False,
            "release authorization dispatch is uncertain",
            503,
            {"error": "release_authorization_dispatch_uncertain"},
        )
    try:
        runtime.validate_dispatch_release_authorization_response(
            result,
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
            previous_lifecycle=lifecycle,
        )
    except runtime.ReleaseAuthorizationClientError:
        if guard is not None:
            guard.mark_dispatch_authorized()
            guard.mark_dispatch_uncertain()
        complete_release_authorization(flow, "unknown")
        return PolicyDecision(
            False,
            "release authorization dispatch state is invalid",
            503,
            {"error": "release_authorization_dispatch_invalid"},
        )
    lifecycle["dispatch_started_at_epoch_ms"] = result[
        "dispatch_started_at_epoch_ms"
    ]
    lifecycle["dispatch_expires_at_epoch_ms"] = result[
        "dispatch_expires_at_epoch_ms"
    ]
    lifecycle["quotas"] = [dict(item) for item in result["quotas"]]
    if durable is not None:
        returned_durable = result.get("durable_policy")
        if (
            not isinstance(returned_durable, dict)
            or returned_durable.get("state") != "dispatched"
        ):
            if guard is not None:
                guard.mark_dispatch_authorized()
                guard.mark_dispatch_uncertain()
            complete_release_authorization(flow, "unknown")
            return PolicyDecision(
                False,
                "durable policy dispatch state is invalid",
                503,
                {"error": "durable_policy_dispatch_invalid"},
            )
        lifecycle["durable_policy"] = copy.deepcopy(returned_durable)
        flow.metadata[
            "serverware_durable_policy_reservation"
        ] = copy.deepcopy(returned_durable)
    flow.metadata["serverware_release_dispatch_expires_at_epoch_ms"] = result[
        "dispatch_expires_at_epoch_ms"
    ]
    _set_release_state(flow, lifecycle, "dispatch_authorized")
    if guard is not None:
        guard.mark_dispatch_authorized()
    return PolicyDecision(True)


def mark_provider_dispatch_uncertain(flow: http.HTTPFlow) -> None:
    lifecycle = _release_lifecycle(flow)
    guard = _release_guard(flow)
    if lifecycle is None:
        if flow.metadata.get("serverware_atomic_reservation_required") is True:
            raise RuntimeError("release authorization lifecycle is missing")
        return
    if lifecycle.get("state") != "dispatch_authorized" or guard is None:
        raise RuntimeError("release authorization is not dispatch-authorized")
    guard.mark_dispatch_uncertain()
    _set_release_state(flow, lifecycle, "dispatching")


def complete_release_authorization_for_error(flow: http.HTTPFlow) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    guard = _release_guard(flow)
    dispatch_is_uncertain = bool(
        (
            lifecycle is not None
            and (
                lifecycle.get("dispatch_attempted")
                or lifecycle.get("state")
                in {
                    "cleanup_unknown",
                    "committed",
                    "dispatch_authorized",
                    "dispatching",
                    "committed_indeterminate",
                }
            )
        )
        or (guard is not None and guard.dispatch_uncertain)
    )
    provider_outcome = (
        "unknown" if dispatch_is_uncertain else "not_forwarded"
    )
    try:
        if lifecycle is None and guard is not None and guard.requires_not_forwarded:
            release_decision = complete_release_authorization(
                flow, "not_forwarded"
            )
        elif lifecycle is None:
            release_decision = PolicyDecision(True)
        elif lifecycle.get("state") in {
            "cancelled",
            "cleanup_unknown",
            "committed",
            "committed_indeterminate",
        }:
            release_decision = PolicyDecision(True)
        else:
            release_decision = complete_release_authorization(
                flow, provider_outcome
            )
    except Exception:
        release_decision = PolicyDecision(
            False,
            "release authorization transport cleanup is uncertain",
            503,
            {"error": "release_authorization_transport_cleanup_uncertain"},
        )
    return release_decision


def _legacy_mitm_route_admission(
    flow: http.HTTPFlow,
    route: RoutePolicy,
) -> PolicyDecision | None:
    if route.credential_header is not None:
        return PolicyDecision(
            False,
            "credential header replacement requires the Rust decision gate",
            503,
            {"error": "python_credential_header_replacement_unsupported"},
        )
    if flow.metadata.get(LEGACY_MITM_TRANSPORT_METADATA_KEY) is not True:
        return None
    if route.credential_ref:
        return PolicyDecision(
            False,
            "credential-bearing routes require the Rust decision gate",
            503,
            {"error": "legacy_mitm_credential_transport_denied"},
        )
    if route.resolved_cidrs is not None:
        return PolicyDecision(
            False,
            "signed provider CIDRs require a socket-owning decision gate",
            503,
            {"error": "legacy_mitm_resolved_cidrs_unsupported"},
        )
    return None


def evaluate_request(flow: http.HTTPFlow) -> RequestEvaluation:
    try:
        raw_target = flow.request.pretty_url
        if flow.metadata.get(RAW_INGRESS_VALIDATED_METADATA_KEY) is True:
            raw_target = flow.metadata.get(RAW_INGRESS_TARGET_METADATA_KEY)
            if (
                not isinstance(raw_target, str)
                or str(flow.request.pretty_url) != raw_target
            ):
                raise ValueError(
                    "validated raw ingress target no longer matches request fields"
                )
        validated_target = validate_raw_absolute_target(raw_target)
        path_has_encoded_slash = validate_request_target_path(
            raw_target,
            _validated_parts=validated_target,
        )
        scheme = validated_target.scheme
        host = validated_target.hostname or ""
        port = validated_target.port or (443 if scheme == "https" else 80)
        path = validated_target.path or "/"
    except Exception:
        # Invalid raw targets are rejected before policy, audit, identity,
        # credential, JIT, or quota state is consulted.
        return RequestEvaluation(
            PolicyDecision(
                False,
                "invalid absolute request target",
                400,
                {"error": "invalid_request_target"},
            )
        )

    safe_url = _validated_pre_policy_audit_url(validated_target)
    try:
        _normalized_request_headers(flow)
    except ValueError as exc:
        flow.metadata["serverware_audit_url"] = safe_url
        decision = PolicyDecision(
            False,
            "invalid forwarding headers",
            400,
            {"error": "invalid_forwarding_headers", "detail": str(exc)},
        )
        runtime.log_request(
            None,
            flow.request.method,
            safe_url,
            "blocked",
            400,
            decision.reason,
        )
        return RequestEvaluation(decision)

    flow.metadata["serverware_audit_url"] = safe_url
    snapshot = get_policy_snapshot()
    if not snapshot:
        decision = PolicyDecision(False, "policy bundle missing", 503, {"error": "policy_bundle_missing"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 503, decision.reason)
        return RequestEvaluation(decision)

    principal = snapshot.identify_principal(
        _client_ip(flow),
        flow.request.headers,
        _verified_mtls_evidence(flow),
    )
    if not principal:
        decision = PolicyDecision(False, "client principal denied", 403, {"error": "client_principal_denied"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, decision.reason)
        return RequestEvaluation(decision, snapshot=snapshot)

    match = snapshot.match_route(scheme, host, port, flow.request.method, path, principal.id)
    if not match:
        decision = PolicyDecision(False, "unknown route denied", 403, {"error": "unknown_route_denied"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, decision.reason)
        return RequestEvaluation(decision, snapshot=snapshot, principal=principal)

    route = match.route
    params = match.params
    transport_denial = _legacy_mitm_route_admission(flow, route)
    if transport_denial is not None:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            transport_denial.status_code,
            transport_denial.reason,
            {
                "principal_id": principal.id,
                "policy_hash": snapshot.hash,
                "credential_id": route.credential_ref,
                "credential_version": 0,
                "request_digest": None,
                "operation_digest": None,
                "route_adapter": route.adapter_type,
                "transport": "legacy_mitmproxy",
            },
        )
        return RequestEvaluation(
            transport_denial,
            snapshot=snapshot,
            principal=principal,
            route=route,
            params=params,
        )
    if path_has_encoded_slash and route.adapter_type != "npm.registry":
        decision = PolicyDecision(
            False,
            "encoded path separator is not allowed for this adapter",
            400,
            {
                "error": "encoded_path_separator_denied",
                "adapter": route.adapter_type,
            },
        )
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
        )
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            params=params,
        )
    adapter = get_adapter(route.adapter_type)
    credential_policy = snapshot.credentials.get(route.credential_ref or "")
    try:
        original_request = _capture_request_mutation_snapshot(flow)
    except (TypeError, ValueError):
        decision = PolicyDecision(
            False,
            "request state cannot be preserved",
            400,
            {"error": "request_state_unavailable"},
        )
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
        )
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_policy=credential_policy,
            params=params,
        )
    flow.metadata.update(
        {
            "serverware_audit_url": safe_url,
            "serverware_route_id": route.id,
            "serverware_policy_hash": snapshot.hash,
            "serverware_principal_id": principal.id,
            "serverware_credential_id": route.credential_ref,
            "serverware_credential_version": 0,
        }
    )
    pre_policy_audit_context = _audit_context(
        snapshot=snapshot,
        principal=principal,
        route=route,
        credential_id=route.credential_ref,
        credential_version=0,
        request_digest=None,
        operation_digest=None,
    )

    def pre_reserve_denial(decision: PolicyDecision) -> RequestEvaluation:
        try:
            _restore_request_mutation_snapshot(flow, original_request)
        except Exception:
            decision = PolicyDecision(
                False,
                "denied request state could not be restored",
                503,
                {"error": "request_mutation_rollback_failed"},
            )
        denial_audit_context = dict(pre_policy_audit_context)
        if (decision.payload or {}).get("constraint_type") == "responseBinding":
            denial_audit_context["response_validation"] = {
                "ok": False,
                **{
                    key: decision.payload[key]
                    for key in ("error", "constraint_id", "constraint_type", "binding_id")
                    if key in decision.payload
                },
            }
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
            denial_audit_context,
        )
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_policy=credential_policy,
            params=params,
        )

    if route.credential_ref and credential_policy is None:
        return pre_reserve_denial(
            PolicyDecision(False, "credential policy missing", 500, {"error": "credential_missing"})
        )
    try:
        preflight_headers = _normalized_request_headers(flow)
    except ValueError as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request preflight headers are invalid",
                400,
                {
                    "error": "invalid_forwarding_headers",
                    "detail": str(exc),
                },
            )
        )
    decision = preflight_request_admission(
        flow,
        route,
        preflight_headers,
    )
    if not decision.allowed:
        return pre_reserve_denial(decision)
    try:
        discard_headers = _discard_declared_request_headers(
            flow,
            route,
            principal,
            credential_policy,
        )
    except PolicyBundleError:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request header discard policy is invalid",
                500,
                {"error": "discard_header_policy_invalid"},
            )
        )
    except ValueError as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "invalid forwarding headers",
                400,
                {"error": "invalid_forwarding_headers", "detail": str(exc)},
            )
        )
    pre_policy_audit_context["discarded_request_headers"] = flow.metadata.get(
        "serverware_discarded_request_headers"
    )
    _strip_identity_headers(flow, principal)
    try:
        _strict_query_pairs(
            validated_request_urlsplit(flow.request.pretty_url).query
        )
    except ValueError:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request query is invalid",
                400,
                {"error": "request_query_invalid"},
            )
        )
    try:
        decision = adapter.rewrite_request(flow, route, params)
    except Exception:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite failed",
                500,
                {"error": "request_rewrite_failed"},
            )
        )
    if not decision.allowed:
        return pre_reserve_denial(decision)
    try:
        _canonicalize_provider_query(flow, trusted_query_view=True)
    except ValueError:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite produced an invalid query",
                500,
                {"error": "request_rewrite_query_invalid"},
            )
        )

    try:
        rewritten_headers = _normalized_request_headers(flow)
    except ValueError as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite produced invalid headers",
                500,
                {
                    "error": "request_rewrite_headers_invalid",
                    "detail": str(exc),
                },
            )
        )
    if set(discard_headers).intersection(rewritten_headers):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite reintroduced a discarded header",
                500,
                {"error": "discarded_header_reintroduced"},
            )
        )
    if rewritten_headers.get("content-encoding") != preflight_headers.get(
        "content-encoding"
    ):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite changed Content-Encoding after raw admission",
                500,
                {"error": "request_rewrite_content_encoding_changed"},
            )
        )
    identity_headers = _identity_header_names(principal)
    if any(
        name in identity_headers or is_serverware_internal_header(name)
        for name in rewritten_headers
    ):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite reintroduced an identity selector header",
                500,
                {"error": "identity_header_reintroduced"},
            )
        )

    try:
        (
            rewritten_path_has_encoded_slash,
            rewritten_scheme,
            rewritten_host,
            rewritten_port,
            rewritten_path,
        ) = validated_request_url_parts(
            flow.request.pretty_url
        )
    except (TypeError, ValueError):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite produced an invalid target",
                500,
                {"error": "rewritten_request_invalid"},
            )
        )
    if (
        rewritten_path_has_encoded_slash
        and route.adapter_type != "npm.registry"
    ):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite introduced an encoded path separator",
                500,
                {"error": "rewritten_encoded_path_separator_denied"},
            )
        )
    rewritten_match = snapshot.match_route(
        rewritten_scheme,
        rewritten_host,
        rewritten_port,
        flow.request.method,
        rewritten_path,
        principal.id,
    )
    if rewritten_match is None or rewritten_match.route.id != route.id:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request rewrite moved outside the authorized route",
                500,
                {"error": "rewritten_request_route_mismatch"},
            )
        )
    params = rewritten_match.params
    safe_url = _pre_policy_audit_url(flow.request.pretty_url)
    flow.metadata["serverware_audit_url"] = safe_url

    collision_decision = _credential_injection_collision(flow, credential_policy)
    if collision_decision is not None:
        return pre_reserve_denial(collision_decision)

    credential_generation: dict[str, Any] | None = None
    credential_generation_digest: str | None = None
    if route.credential_ref:
        try:
            credential_generation = runtime.get_credential_generation(
                route.credential_ref
            )
        except Exception:
            return pre_reserve_denial(
                PolicyDecision(
                    False,
                    "credential generation metadata is unavailable",
                    503,
                    {"error": "credential_generation_unavailable"},
                )
            )
        if not isinstance(credential_generation, dict):
            return pre_reserve_denial(
                PolicyDecision(
                    False,
                    "credential missing",
                    500,
                    {"error": "credential_missing"},
                )
            )
        credential_version_value = credential_generation.get(
            "credential_version"
        )
        if type(credential_version_value) is not int:
            return pre_reserve_denial(
                PolicyDecision(
                    False,
                    "credential version is invalid",
                    500,
                    {"error": "credential_version_invalid"},
                )
            )
        credential_version_int = credential_version_value
        metadata = credential_generation.get("metadata")
        if not isinstance(metadata, dict):
            return pre_reserve_denial(
                PolicyDecision(
                    False,
                    "credential generation metadata is invalid",
                    503,
                    {"error": "credential_generation_invalid"},
                )
            )
        metadata_decision = adapter.validate_credential_metadata(
            route,
            metadata,
        )
        if not metadata_decision.allowed:
            return pre_reserve_denial(metadata_decision)
        credential_generation_digest = _digest(
            {
                "id": credential_generation.get("id"),
                "kind": credential_generation.get("kind"),
                "credential_version": credential_version_int,
                "metadata": metadata,
                "lifecycle_status": credential_generation.get(
                    "lifecycle_status"
                ),
            }
        )
    else:
        credential_version_int = 0

    decision = adapter.validate_request(flow, route, params)
    if not decision.allowed:
        return pre_reserve_denial(decision)
    try:
        operation_fields = adapter.operation_fields(flow, route, params)
    except (TypeError, ValueError):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request operation classification failed",
                403,
                {"error": "request_operation_invalid"},
            )
        )
    operation = operation_fields.get("operation")
    operation_catalog = (
        adapter_operation_field_names(route.adapter_type, str(operation))
        if route.adapter_type != "generic.rest"
        else None
    )
    if (
        not isinstance(operation, str)
        or not operation
        or (
            route.adapter_type != "generic.rest"
            and (
                operation_catalog is None
                or not set(operation_fields).issubset(operation_catalog)
            )
        )
    ):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "typed adapter emitted unknown operation evidence",
                503,
                {"error": "request_operation_evidence_invalid"},
            )
        )
    if credential_generation is not None:
        binding_decision = _credential_policy_binding_decision(
            route,
            credential_policy,
            credential_generation,
            operation,
        )
        if binding_decision is not None:
            return pre_reserve_denial(binding_decision)
        if route.adapter_type == "x.v2":
            try:
                flow.metadata["serverware_x_app_id"] = (
                    _consistent_metadata_alias(
                        credential_generation["metadata"],
                        ("x_app_id", "app_id", "oauth_client_id", "client_id"),
                    )
                )
            except ValueError:
                return pre_reserve_denial(
                    PolicyDecision(
                        False,
                        "X application identity aliases are contradictory",
                        409,
                        {
                            "error": "credential_policy_binding_mismatch",
                            "binding": "oauthClientId",
                        },
                    )
                )
    provider_account_decision = _bind_provider_account_scope(
        route,
        credential_policy,
        operation_fields,
    )
    if provider_account_decision is not None:
        return pre_reserve_denial(provider_account_decision)
    typed_value_decision, request_constraint_route = (
        _evaluate_typed_request_values(
            flow,
            route,
            params,
            operation_fields,
        )
    )
    if not typed_value_decision.allowed:
        return pre_reserve_denial(typed_value_decision)
    constraint_decision = evaluate_request_constraints(
        flow,
        request_constraint_route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=0,
        operation_fields=operation_fields,
        consume_rate_limits=False,
        policy_hash=snapshot.hash,
        skip_rate_limits=True,
    )
    if not constraint_decision.allowed:
        return pre_reserve_denial(constraint_decision)
    response_binding_source_decision = evaluate_response_binding_sources(route, operation_fields)
    if not response_binding_source_decision.allowed:
        return pre_reserve_denial(response_binding_source_decision)

    try:
        _strip_identity_content_encoding(
            flow,
            preflight_headers.get("content-encoding"),
        )
        forwarded_headers = _canonical_forwarded_request_headers(
            flow,
            credential_policy,
        )
    except ValueError as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request final admission headers are invalid",
                400,
                {
                    "error": "request_final_admission_headers_invalid",
                    "detail": str(exc),
                },
            )
        )

    try:
        credential_version = _canonical_credential_version(
            credential_version_int
        )
    except ValueError:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "credential version is invalid",
                500,
                {"error": "credential_version_invalid"},
            )
        )
    flow.metadata["serverware_credential_version"] = credential_version_int

    atomic_mode = runtime.atomic_release_authorization_enabled()
    rate_preview = evaluate_request_constraints(
        flow,
        _legacy_constraint_route(route),
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=credential_version_int,
        operation_fields=operation_fields,
        consume_rate_limits=False,
        policy_hash=snapshot.hash,
        rate_limits_only=True,
        skip_shared_rate_limits=atomic_mode,
    )
    if not rate_preview.allowed:
        return pre_reserve_denial(rate_preview)

    canonical_request = _canonical_request(
        flow,
        principal=principal,
        route=route,
        credential_version=credential_version,
        policy_hash=snapshot.hash,
        operation_fields=operation_fields,
        forwarded_headers=forwarded_headers,
        discard_headers=discard_headers,
    )
    request_digest = _digest(canonical_request)
    operation_digest = _operation_digest(canonical_request)
    try:
        durable_policy_claims = _durable_policy_claims(
            flow,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_version=credential_version_int,
            operation_fields=operation_fields,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "durable policy evidence is invalid",
                403,
                {
                    "error": "durable_policy_evidence_invalid",
                    "detail": str(exc),
                },
            )
        )
    jit = route.jit or {}
    jit_required = bool(jit.get("required"))
    attempt_id: str | None = None
    binding_digest: str | None = None
    release_state: str | None = None
    lifecycle: dict[str, Any] | None = None
    reservation_guard: runtime.ReleaseAuthorizationGuard | None = None
    expected_identity: runtime.ReleaseAuthorizationExpectedIdentity | None = None
    credential_request_authority: dict[str, Any] | None = None
    credential_release_authorization: dict[str, Any] | None = None
    durable_policy_reservation: dict[str, Any] | None = None

    def audit_context() -> dict[str, Any]:
        return _audit_context(
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_id=route.credential_ref,
            credential_version=credential_version_int,
            request_digest=request_digest,
            operation_digest=operation_digest,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            release_state=(lifecycle or {}).get("state", release_state),
            discarded_request_headers=flow.metadata.get(
                "serverware_discarded_request_headers"
            ),
        )

    def evaluation(decision: PolicyDecision) -> RequestEvaluation:
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_policy=credential_policy,
            params=params,
            request_digest=request_digest,
            operation_digest=operation_digest,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            release_state=(lifecycle or {}).get("state", release_state),
        )

    def block_after_reserve(decision: PolicyDecision) -> RequestEvaluation:
        nonlocal release_state, durable_policy_reservation
        if (
            reservation_guard is not None
            and reservation_guard.requires_not_forwarded
        ):
            try:
                cancellation = complete_release_authorization(
                    flow,
                    "not_forwarded",
                )
            except Exception:
                cancellation = PolicyDecision(
                    False,
                    "release authorization completion is uncertain",
                    503,
                    {"error": "release_authorization_completion_uncertain"},
                )
            release_state = str((lifecycle or {}).get("state") or release_state)
            if not cancellation.allowed:
                decision = cancellation
            elif durable_policy_reservation is not None:
                durable_policy_reservation = copy.deepcopy(
                    (lifecycle or {}).get("durable_policy")
                )
                flow.metadata[
                    "serverware_durable_policy_reservation"
                ] = copy.deepcopy(durable_policy_reservation)
        try:
            discard_response_guards(flow)
        except Exception:
            decision = PolicyDecision(
                False,
                "response credential guard cleanup failed",
                503,
                {"error": "response_credential_guard_cleanup_failed"},
            )
        try:
            _restore_request_mutation_snapshot(flow, original_request)
        except Exception:
            decision = PolicyDecision(
                False,
                "denied request state could not be restored",
                503,
                {"error": "request_mutation_rollback_failed"},
            )
        try:
            runtime.log_request(
                route.id,
                flow.request.method,
                safe_url,
                "blocked",
                decision.status_code,
                decision.reason,
                audit_context(),
            )
        except Exception:
            flow.metadata["serverware_audit_delivery_uncertain"] = True
        return evaluation(decision)

    rate_limit_constraints = [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "rateLimit"
        and (constraint.get("phase") or "request") == "request"
    ]
    local_rate_limit_constraints = [
        constraint
        for constraint in rate_limit_constraints
        if constraint.get("store", "local") == "local"
    ]
    shared_rate_limit_constraints = [
        constraint
        for constraint in rate_limit_constraints
        if constraint.get("store", "local") == "shared"
    ]
    credential_route_controlled = bool(
        jit_required
        or shared_rate_limit_constraints
        or any(
            constraint.get("type")
            in {
                "slidingWindowLimit",
                "weightedBudget",
                "traversalBudget",
            }
            for constraint in route.constraints
        )
    )
    if len(local_rate_limit_constraints) > 1:
        return block_after_reserve(
            PolicyDecision(
                False,
                "multiple local quota counters cannot be consumed atomically",
                503,
                {"error": "atomic_local_rate_limits_unsupported"},
            )
        )
    if (
        not atomic_mode
        and (credential_route_controlled or jit_required)
    ):
        return block_after_reserve(
            PolicyDecision(
                False,
                "controlled authorization requires the atomic release authority",
                503,
                {"error": "atomic_release_authorization_required"},
            )
        )

    try:
        flow.metadata.update(
            {
                "serverware_route_id": route.id,
                "serverware_policy_hash": snapshot.hash,
                "serverware_principal_id": principal.id,
                "serverware_credential_id": route.credential_ref,
                "serverware_credential_version": credential_version_int,
                "serverware_request_digest": request_digest,
                "serverware_operation_digest": operation_digest,
                "serverware_operation": dict(operation_fields),
                "serverware_discarded_request_headers": flow.metadata.get(
                    "serverware_discarded_request_headers"
                ),
                "serverware_route": route,
                "serverware_params": params,
                "serverware_credential_policy": credential_policy,
                "serverware_credential_lease_binding": None,
                "serverware_bound_credential_lease": None,
                "serverware_durable_policy_claims": copy.deepcopy(
                    durable_policy_claims
                ),
                "serverware_durable_policy_reservation": None,
                "serverware_atomic_reservation_required": atomic_mode,
                "serverware_local_rate_limit_mode": (
                    "conservative_non_refundable"
                    if local_rate_limit_constraints
                    else None
                ),
            }
        )
        runtime.prune_expired_caches()
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "request preparation failed",
                503,
                {"error": "request_preparation_failed"},
            )
        )

    if atomic_mode:
        attempt_id = "sha256:" + hashlib.sha256(
            (
                "serverware-python-release-attempt-v1:"
                + str(uuid.uuid4())
            ).encode("ascii")
        ).hexdigest()
        try:
            shared_quotas = shared_rate_limit_claims(
                route,
                principal_id=principal.id,
                credential_ref=route.credential_ref,
                credential_version=credential_version_int,
                operation_fields=operation_fields,
            )
            expected_identity = runtime.expected_release_authorization_identity(
                attempt_id=attempt_id,
                flow_id=attempt_id,
                principal_id=principal.id,
                route_id=route.id,
                credential_ref=route.credential_ref,
                credential_version=credential_version_int,
                policy_hash=snapshot.hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                operation_context=dict(operation_fields),
                shared_quotas=shared_quotas,
                require_jit_grant=jit_required,
            )
            expected_binding_digest = expected_identity.binding_digest
            durable_policy_binding = runtime.durable_policy_reserve_binding(
                expected_identity,
                durable_policy_claims,
            )
            reservation_guard = runtime.ReleaseAuthorizationGuard(
                expected_identity,
                durable_policy=durable_policy_binding,
            )
            flow.metadata[
                "serverware_release_authorization_guard"
            ] = reservation_guard
            reserve_arguments = {
                "guard": reservation_guard,
                "operation_context": dict(operation_fields),
                "canonical_request": canonical_request,
                "shared_quotas": shared_quotas,
            }
            if durable_policy_claims:
                reserve_arguments[
                    "durable_policy_claims"
                ] = durable_policy_claims
            reserved = runtime.reserve_expected_release_authorization(
                **reserve_arguments
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization reserve is uncertain",
                    503,
                    {"error": "release_authorization_reserve_uncertain"},
                )
            )
        try:
            runtime.validate_reserve_release_authorization_response(
                reserved,
                attempt_id=attempt_id,
                require_jit_grant=jit_required,
                expected_binding_digest=expected_binding_digest,
                expected_shared_quotas=shared_quotas,
                expected_durable_policy=durable_policy_binding,
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization reserve state is invalid",
                    503,
                    {"error": "release_authorization_reserve_invalid"},
                )
            )
        binding_digest = str(reserved.get("binding_digest") or "")
        release_state = str(reserved.get("state") or "")
        if release_state == "denied":
            if reservation_guard.phase != "denied":
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "release authorization denial did not disarm its guard",
                        503,
                        {"error": "release_authorization_guard_invalid"},
                    )
                )
            reason = str(reserved.get("reason") or "release_authorization_denied")
            if jit_required and reason in {"jit_grant_unavailable", "jit_grant_expired"}:
                approval_id = reserved.get("approval_request_id")
                approval_status = reserved.get("approval_status")
                approval_expires_at = reserved.get("approval_expires_at")
                approval_created = reserved.get("approval_created")
                retry_after_seconds = reserved.get("retry_after_seconds")
                if (
                    not isinstance(approval_id, str)
                    or not approval_id
                    or approval_status != "pending"
                    or not isinstance(approval_created, bool)
                    or not isinstance(approval_expires_at, str)
                    or not approval_expires_at
                    or not isinstance(retry_after_seconds, int)
                    or isinstance(retry_after_seconds, bool)
                    or retry_after_seconds < 1
                ):
                    return block_after_reserve(
                        PolicyDecision(
                            False,
                            "jit approval response is invalid",
                            503,
                            {"error": "jit_approval_response_invalid"},
                        )
                    )
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "jit approval required",
                        428,
                        {
                            "error": "serverware_approval_required",
                            "approval_id": approval_id,
                            "approval_url": f"/approvals/{approval_id}",
                            "approval_status": approval_status,
                            "approval_created": approval_created,
                            "request_digest": request_digest,
                            "operation_digest": operation_digest,
                            "route_id": route.id,
                            "principal": principal.id,
                            "expires_at": approval_expires_at,
                            "retry_after_seconds": retry_after_seconds,
                        },
                    )
                )
            if reason == "shared_quota_denied":
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "credential use rate limit exceeded",
                        429,
                        {
                            "error": "credential_rate_limit_exceeded",
                            "retry_after_seconds": int(reserved.get("retry_after_seconds") or 1),
                            "store": "shared",
                        },
                    )
                )
            if reason == "durable_policy_denied":
                retry_after_seconds = reserved.get("retry_after_seconds")
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "durable policy budget denied",
                        429,
                        {
                            "error": "durable_policy_budget_exceeded",
                            "retry_after_seconds": (
                                retry_after_seconds
                                if type(retry_after_seconds) is int
                                and retry_after_seconds > 0
                                else 1
                            ),
                        },
                    )
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization denied",
                    503,
                    {"error": "release_authorization_denied", "reason": reason},
                )
            )
        validated_reserve = _validated_successful_release_reserve(
            reserved,
            attempt_id=attempt_id,
            jit_required=jit_required,
        )
        if validated_reserve is None:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization reserve state is invalid",
                    503,
                    {"error": "release_authorization_reserve_invalid"},
                )
            )
        binding_digest = str(validated_reserve["binding_digest"])
        try:
            if reservation_guard.phase != "reserved":
                raise runtime.ReleaseAuthorizationClientError(
                    "release authorization reserve did not promote its guard"
                )
            lifecycle = _store_release_lifecycle(
                flow,
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                state="reserved",
                grant_id=validated_reserve["grant_id"],
                approval_request_id=validated_reserve["approval_request_id"],
                reservation_expires_at_epoch_ms=validated_reserve[
                    "reservation_expires_at_epoch_ms"
                ],
                quotas=reserved["quotas"],
            )
            if durable_policy_binding is not None:
                durable_policy_reservation = copy.deepcopy(
                    reserved.get("durable_policy")
                )
                if (
                    not isinstance(durable_policy_reservation, dict)
                    or durable_policy_reservation.get("state") != "reserved"
                ):
                    raise runtime.ReleaseAuthorizationClientError(
                        "release authorization v2 durable reserve is missing"
                    )
                lifecycle["durable_policy"] = copy.deepcopy(
                    durable_policy_reservation
                )
                flow.metadata[
                    "serverware_durable_policy_reservation"
                ] = copy.deepcopy(durable_policy_reservation)
            if route.credential_ref:
                credential_request_authority = (
                    runtime.credential_lease_request_authority(
                        expected_identity,
                        reserved,
                        operation_context=dict(operation_fields),
                        controlled=credential_route_controlled,
                    )
                )
                credential_release_authorization = (
                    runtime.credential_lease_release_authorization(
                        expected_identity,
                        reserved,
                    )
                )
                lifecycle["credential_release_authorization"] = copy.deepcopy(
                    credential_release_authorization
                )
                lifecycle["credential_request_authority"] = copy.deepcopy(
                    credential_request_authority
                )
        except Exception:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization lifecycle could not be retained",
                    503,
                    {"error": "release_authorization_lifecycle_invalid"},
                )
            )

    if atomic_mode and (
        reservation_guard is None
        or reservation_guard.phase != "reserved"
        or _release_guard(flow) is not reservation_guard
        or lifecycle is None
        or lifecycle.get("state") != "reserved"
        or lifecycle.get("attempt_id") != reservation_guard.expected.attempt_id
        or lifecycle.get("binding_digest")
        != reservation_guard.expected.binding_digest
    ):
        return block_after_reserve(
            PolicyDecision(
                False,
                "release authorization guard was not retained",
                503,
                {"error": "release_authorization_guard_missing"},
            )
        )

    grant_lookup = {
        "principal_id": principal.id,
        "route_id": route.id,
        "credential_id": route.credential_ref or "",
        "credential_version": credential_version_int,
        "policy_hash": snapshot.hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
    }
    grant_preview: dict[str, Any] = {}
    if jit_required and not atomic_mode:
        try:
            grant_preview = db.find_jit_grant_result(**grant_lookup)
        except Exception:
            return block_after_reserve(
                PolicyDecision(False, "jit grant store unavailable", 503, {"error": "jit_grant_store_unavailable"})
            )
        if not grant_preview.get("available"):
            try:
                approval = db.ensure_jit_approval_request(
                    route_id=route.id,
                    method=flow.request.method,
                    url=safe_url,
                    principal_id=principal.id,
                    credential_id=route.credential_ref or "",
                    credential_version=credential_version_int,
                    policy_hash=snapshot.hash,
                    request_digest=request_digest,
                    operation_digest=operation_digest,
                    canonical_request=canonical_request,
                    redacted_display={
                        "method": flow.request.method,
                        "url": safe_url,
                        "route_id": route.id,
                        "principal": principal.id,
                        "operation": operation_fields,
                        "body_sha256": canonical_request["request"]["body_sha256"],
                    },
                    pending_ttl_seconds=300,
                    grant_ttl_seconds=int(jit.get("ttlSeconds", 30)),
                    grant_max_uses=int(jit.get("maxUses", 1)),
                    **db.jit_approver_policy_arguments(jit),
                )
            except Exception:
                return block_after_reserve(
                    PolicyDecision(False, "jit approval store unavailable", 503, {"error": "jit_approval_store_unavailable"})
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "jit approval required",
                    428,
                    {
                        "error": "serverware_approval_required",
                        "approval_id": approval["id"],
                        "approval_url": f"/approvals/{approval['id']}",
                        "request_digest": request_digest,
                        "operation_digest": operation_digest,
                        "route_id": route.id,
                        "principal": principal.id,
                        "expires_at": approval["expires_at"],
                        "retry_after_seconds": 3,
                    },
                )
            )

    bound_credential_lease: runtime.BoundCredentialLease | None = None
    try:
        if route.credential_ref and route.adapter_type == "gmail.v1":
            if credential_route_controlled:
                bound_credential_lease = runtime.get_bound_credential_lease(
                    route.credential_ref,
                    request_authority=credential_request_authority,
                    release_authorization=credential_release_authorization,
                    expected_release_identity=expected_identity,
                    jit_policy=jit,
                )
            else:
                bound_credential_lease = runtime.get_bound_credential_lease(
                    route.credential_ref
                )
            credential = (
                bound_credential_lease.credential
                if bound_credential_lease is not None
                else None
            )
        else:
            credential = (
                (
                    runtime.get_credential(
                        route.credential_ref,
                        request_authority=credential_request_authority,
                        release_authorization=credential_release_authorization,
                        expected_release_identity=expected_identity,
                        jit_policy=jit,
                    )
                    if credential_route_controlled
                    else runtime.get_credential(route.credential_ref)
                )
                if route.credential_ref
                else None
            )
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "credential unavailable",
                503,
                {"error": "credential_unavailable"},
            )
        )
    loaded_credential_version = (
        (credential or {}).get("credential_version")
        if isinstance(credential, dict)
        else None
    )
    if route.credential_ref and (
        type(loaded_credential_version) is not int
        or loaded_credential_version != credential_version_int
    ):
        return block_after_reserve(
            PolicyDecision(
                False,
                "credential changed during authorization",
                409,
                {"error": "credential_version_changed"},
            )
        )
    if route.credential_ref and isinstance(credential, dict):
        loaded_metadata = credential.get("metadata")
        try:
            loaded_generation_digest = _digest(
                {
                    "id": credential.get("id"),
                    "kind": credential.get("kind"),
                    "credential_version": loaded_credential_version,
                    "metadata": loaded_metadata,
                    "lifecycle_status": credential.get("lifecycle_status"),
                }
            )
        except Exception:
            loaded_generation_digest = None
        if (
            not isinstance(credential_generation_digest, str)
            or not isinstance(loaded_generation_digest, str)
            or not hmac.compare_digest(
                credential_generation_digest,
                loaded_generation_digest,
            )
        ):
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "credential generation changed during authorization",
                    409,
                    {"error": "credential_generation_changed"},
                )
            )
    try:
        credential_decision = adapter.validate_credential(route, credential)
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "credential validation failed",
                500,
                {"error": "credential_validation_failed"},
            )
        )
    if not credential_decision.allowed:
        return block_after_reserve(credential_decision)

    injection_reason = "no credential configured"
    if credential_policy and credential:
        try:
            injection_reason = _inject_credential(
                flow,
                credential_policy,
                credential,
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "credential injection failed",
                    500,
                    {"error": "credential_injection_failed"},
                )
            )
    flow.metadata["serverware_credential_lease_binding"] = (
        bound_credential_lease.binding
        if bound_credential_lease is not None
        else None
    )
    flow.metadata["serverware_bound_credential_lease"] = bound_credential_lease

    try:
        prepared_headers = _normalized_request_headers(flow)
        provider_request_matches = _provider_request_matches_canonical(
            flow,
            canonical_request,
            credential_policy,
            credential,
        )
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "request preparation could not be verified",
                500,
                {"error": "request_preparation_verification_failed"},
            )
        )
    if set(discard_headers).intersection(prepared_headers):
        return block_after_reserve(
            PolicyDecision(
                False,
                "request preparation reintroduced a discarded header",
                500,
                {"error": "discarded_header_reintroduced"},
            )
        )
    if any(
        name in _identity_header_names(principal)
        or is_serverware_internal_header(name)
        for name in prepared_headers
    ):
        return block_after_reserve(
            PolicyDecision(
                False,
                "request preparation reintroduced an identity selector header",
                500,
                {"error": "identity_header_reintroduced"},
            )
        )
    if not provider_request_matches:
        return block_after_reserve(
            PolicyDecision(
                False,
                "provider request differs from its canonical authorization",
                500,
                {"error": "provider_request_binding_changed"},
            )
        )

    # Local counters intentionally remain fail-closed and non-refundable.
    # Shared counters and JIT grants are the only state owned by the atomic
    # release guard and control-plane not_forwarded terminalization.
    try:
        rate_limit_decision = evaluate_request_constraints(
            flow,
            _legacy_constraint_route(route),
            principal_id=principal.id,
            credential_ref=route.credential_ref,
            credential_version=credential_version_int,
            operation_fields=operation_fields,
            consume_rate_limits=True,
            policy_hash=snapshot.hash,
            rate_limits_only=True,
            skip_shared_rate_limits=atomic_mode,
        )
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "request rate-limit validation failed",
                503,
                {"error": "rate_limit_validation_failed"},
            )
        )
    if not rate_limit_decision.allowed:
        return block_after_reserve(rate_limit_decision)

    if jit_required and not atomic_mode:
        try:
            grant_commit = db.consume_jit_grant_result(
                **grant_lookup,
                flow_id=str(uuid.uuid4()),
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(False, "jit grant store unavailable", 503, {"error": "jit_grant_store_unavailable"})
            )
        if not grant_commit.get("consumed"):
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "approved JIT grant changed before final consumption",
                    409,
                    {
                        "error": "jit_grant_commit_race",
                        "reason": grant_commit.get("reason"),
                        "approval_id": grant_preview.get("approval_id"),
                    },
                )
            )

    try:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "allowed",
            None,
            injection_reason,
            audit_context(),
        )
    except Exception:
        flow.metadata["serverware_audit_delivery_uncertain"] = True
        return block_after_reserve(
            PolicyDecision(
                False,
                "request audit delivery failed",
                503,
                {"error": "request_audit_delivery_failed"},
            )
        )
    return evaluation(PolicyDecision(True))


def _fresh_gmail_metadata_authorization(
    flow: http.HTTPFlow,
    route: RoutePolicy,
) -> tuple[str, float]:
    credential_policy = flow.metadata.get("serverware_credential_policy")
    if not isinstance(credential_policy, CredentialPolicy):
        raise ValueError("Gmail metadata credential policy is missing")
    credential_ref = route.credential_ref
    expected_version = flow.metadata.get("serverware_credential_version")
    if (
        not isinstance(credential_ref, str)
        or not credential_ref
        or credential_policy.id != credential_ref
        or type(expected_version) is not int
        or expected_version < 1
    ):
        raise ValueError("Gmail metadata credential binding is missing")
    parent_binding = flow.metadata.get("serverware_credential_lease_binding")
    if not isinstance(parent_binding, runtime.CredentialLeaseBinding):
        raise ValueError("Gmail metadata parent credential binding is missing")
    bound_lease = flow.metadata.get("serverware_bound_credential_lease")
    if not isinstance(bound_lease, runtime.BoundCredentialLease):
        raise ValueError("Gmail metadata credential is unavailable")
    credential = bound_lease.credential
    child_binding = bound_lease.binding
    if type(credential.get("credential_version")) is not int or (
        credential["credential_version"] != expected_version
    ):
        raise ValueError("Gmail metadata credential version changed")
    if (
        parent_binding.credential_id != credential_ref
        or child_binding.credential_id != parent_binding.credential_id
        or child_binding.credential_version != parent_binding.credential_version
        or child_binding.credential_version != expected_version
        or not hmac.compare_digest(
            child_binding.secret_fingerprint,
            parent_binding.secret_fingerprint,
        )
    ):
        raise ValueError("Gmail metadata credential generation changed")
    expires_at_monotonic = min(
        parent_binding.expires_at_monotonic,
        child_binding.expires_at_monotonic,
    )
    if expires_at_monotonic - time.monotonic() < 0.250:
        raise ValueError("Gmail metadata credential lease is expiring")
    injection = credential_policy.injection or {}
    if (
        credential.get("kind") != "oauth2"
        or injection.get("type") != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise ValueError("Gmail metadata credential injection is not canonical OAuth bearer")
    token = _secret_for_injection(str(credential.get("secret") or ""), injection)
    authorization = f"Bearer {token}"
    try:
        encoded = authorization.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("Gmail metadata authorization is invalid") from exc
    if (
        len(encoded) > 16 * 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in authorization)
    ):
        raise ValueError("Gmail metadata authorization is invalid")
    guard = getattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, None)
    if not isinstance(guard, _ResponseCredentialGuard):
        guard = _ResponseCredentialGuard()
        _install_response_credential_guard(flow, guard)
    guard.add_text_encodings(token)
    guard.add_text_encodings(authorization)
    return authorization, expires_at_monotonic


def prepare_response(flow: http.HTTPFlow) -> PolicyDecision:
    raw_body = (
        flow.response.raw_content
        if flow.response is not None
        and isinstance(flow.response.raw_content, bytes)
        else b""
    )

    def preparation_denial(decision: PolicyDecision) -> PolicyDecision:
        durable = _terminalize_durable_response_failure(
            flow,
            body=raw_body,
            reason=str(
                (decision.payload or {}).get("error")
                or decision.reason
            ),
        )
        return _combine_cleanup_uncertainty(
            decision,
            durable,
            error="response_preparation_and_durable_cleanup_uncertain",
            reason=(
                "response preparation and durable policy cleanup are "
                "uncertain"
            ),
        )

    encoding_decision = _validate_response_content_encoding(flow)
    if not encoding_decision.allowed:
        return preparation_denial(encoding_decision)
    route = flow.metadata.get("serverware_route")
    params = flow.metadata.get("serverware_params") or {}
    if not route:
        if flow.metadata.get("serverware_blocked_response") is True:
            return PolicyDecision(True)
        return preparation_denial(
            PolicyDecision(
                False,
                "response policy context missing",
                502,
                {"error": "response_policy_context_missing"},
            )
        )
    envelope_decision = _evaluate_response_envelope(flow, route)
    if not envelope_decision.allowed:
        return preparation_denial(envelope_decision)
    adapter = get_adapter(route.adapter_type)
    try:
        decision = adapter.prepare_response(
            flow,
            route,
            params,
            authorization_factory=lambda: _fresh_gmail_metadata_authorization(flow, route),
        )
    except Exception:
        decision = PolicyDecision(
            False,
            "response preparation failed closed",
            503,
            {"error": "response_preparation_failed_closed"},
        )
    if not decision.allowed:
        terminal_decision = preparation_denial(decision)
        runtime.log_request(
            flow.metadata.get("serverware_route_id"),
            flow.request.method,
            _audit_url(flow),
            "blocked",
            decision.status_code,
            decision.reason,
            {
                "principal_id": flow.metadata.get("serverware_principal_id"),
                "policy_hash": flow.metadata.get("serverware_policy_hash"),
                "credential_id": flow.metadata.get("serverware_credential_id"),
                "credential_version": flow.metadata.get("serverware_credential_version"),
                "request_digest": flow.metadata.get("serverware_request_digest"),
                "operation_digest": flow.metadata.get("serverware_operation_digest"),
                "attempt_id": flow.metadata.get("serverware_release_attempt_id"),
                "binding_digest": flow.metadata.get("serverware_release_binding_digest"),
                "release_state": flow.metadata.get("serverware_release_state"),
                "discarded_request_headers": flow.metadata.get(
                    "serverware_discarded_request_headers"
                ),
            },
        )
        return terminal_decision
    return decision


def discard_response_guards(flow: http.HTTPFlow) -> None:
    guard = _take_response_credential_guard(flow)
    if guard is not None:
        guard.clear()


def _physical_response_header_entries(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    if flow.response is None:
        return []
    headers = flow.response.headers
    fields = getattr(headers, "fields", None)
    raw_items = fields if fields is not None else list(headers.items())
    entries: list[tuple[str, str]] = []
    for raw_name, raw_value in raw_items:
        try:
            name = (
                bytes(raw_name).decode("ascii")
                if isinstance(raw_name, (bytes, bytearray))
                else str(raw_name)
            )
            value = (
                bytes(raw_value).decode("latin-1")
                if isinstance(raw_value, (bytes, bytearray))
                else str(raw_value)
            )
        except (UnicodeError, ValueError) as exc:
            raise ValueError("response header is not bounded text") from exc
        if (
            _REQUEST_HEADER_NAME_RE.fullmatch(name) is None
            or len(name.encode("ascii")) > _REQUEST_HEADER_NAME_MAX_BYTES
            or len(value.encode("latin-1")) > _REQUEST_HEADER_VALUE_MAX_BYTES
            or "\r" in value
            or "\n" in value
        ):
            raise ValueError("response header is not canonical")
        entries.append((name.lower(), value))
    return entries


def _evaluate_response_envelope(
    flow: http.HTTPFlow,
    route: RoutePolicy,
) -> PolicyDecision:
    if flow.response is None:
        return PolicyDecision(
            False,
            "upstream response is missing",
            502,
            {"error": "response_envelope_missing"},
        )
    operation_fields = flow.metadata.get("serverware_operation") or {}
    operation = (
        operation_fields.get("operation")
        if isinstance(operation_fields, dict)
        else None
    )
    constraints = [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "responseEnvelope"
        and (
            constraint.get("operations") is None
            or operation in constraint.get("operations", [])
        )
    ]
    if not constraints:
        return PolicyDecision(
            False,
            "response envelope policy is missing for the operation",
            502,
            {"error": "response_envelope_policy_missing"},
        )
    try:
        entries = _physical_response_header_entries(flow)
    except ValueError:
        return PolicyDecision(
            False,
            "response headers are not canonical",
            502,
            {"error": "response_envelope_header_malformed"},
        )
    values_by_name: dict[str, list[str]] = {}
    for name, value in entries:
        values_by_name.setdefault(name, []).append(value)
    duplicate_names = sorted(
        name for name, values in values_by_name.items() if len(values) != 1
    )
    if duplicate_names:
        return PolicyDecision(
            False,
            "upstream response contains duplicate physical headers",
            502,
            {
                "error": "response_envelope_header_evidence_invalid",
                "headers": duplicate_names,
            },
        )
    raw_body = flow.response.raw_content
    if not isinstance(raw_body, bytes):
        return PolicyDecision(
            False,
            "response body bytes are unavailable",
            502,
            {"error": "response_envelope_body_unavailable"},
        )
    excluded_transport_headers = {
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    semantic_names = set(values_by_name) - excluded_transport_headers
    for constraint in constraints:
        constraint_id = str(constraint.get("id") or "unnamed")
        if flow.response.status_code not in constraint.get("statusCodes", []):
            return PolicyDecision(
                False,
                "upstream response status is not allowed",
                502,
                {
                    "error": "response_envelope_status_denied",
                    "constraint_id": constraint_id,
                },
            )
        body_presence = constraint.get("bodyPresence")
        if (body_presence == "required" and not raw_body) or (
            body_presence == "forbidden" and raw_body
        ):
            return PolicyDecision(
                False,
                "upstream response body presence is not allowed",
                502,
                {
                    "error": "response_envelope_body_presence_denied",
                    "constraint_id": constraint_id,
                },
            )
        content_types = constraint.get("contentTypes") or []
        physical_content_types = values_by_name.get("content-type") or []
        if body_presence == "forbidden":
            if physical_content_types:
                return PolicyDecision(
                    False,
                    "bodyless response declared a content type",
                    502,
                    {
                        "error": "response_envelope_content_type_denied",
                        "constraint_id": constraint_id,
                    },
                )
        elif (
            len(physical_content_types) != 1
            or physical_content_types[0] not in content_types
        ):
            return PolicyDecision(
                False,
                "upstream response content type is not allowed",
                502,
                {
                    "error": "response_envelope_content_type_denied",
                    "constraint_id": constraint_id,
                },
            )
        allowed_names = set(
            constraint.get("allowedResponseHeaderNames") or []
        )
        if not semantic_names.issubset(allowed_names):
            return PolicyDecision(
                False,
                "upstream response header is not allowed",
                502,
                {
                    "error": "response_envelope_header_denied",
                    "constraint_id": constraint_id,
                    "headers": sorted(semantic_names - allowed_names),
                },
            )
        header_rules = constraint.get("responseHeaderRules") or []
        if (
            not isinstance(header_rules, list)
            or len(header_rules) != len(allowed_names)
            or {
                str(rule.get("name") or "")
                for rule in header_rules
                if isinstance(rule, dict)
            }
            != allowed_names
        ):
            return PolicyDecision(
                False,
                "response envelope header rules are incomplete or ambiguous",
                502,
                {
                    "error": "response_envelope_policy_invalid",
                    "constraint_id": constraint_id,
                },
            )
        if any(len(values_by_name.get(name) or []) > 1 for name in allowed_names):
            return PolicyDecision(
                False,
                "allowed response header occurred more than once",
                502,
                {
                    "error": "response_envelope_header_evidence_invalid",
                    "constraint_id": constraint_id,
                },
            )
        for rule in header_rules:
            name = str(rule.get("name") or "")
            values = values_by_name.get(name) or []
            if not values and rule.get("required") is False:
                continue
            if len(values) != 1:
                return PolicyDecision(
                    False,
                    "upstream response header evidence is missing or ambiguous",
                    502,
                    {
                        "error": "response_envelope_header_evidence_invalid",
                        "constraint_id": constraint_id,
                        "header": name,
                    },
                )
            predicate = rule.get("predicate")
            if (
                not isinstance(predicate, dict)
                or not _request_value_predicate_matches(
                    predicate, values[0]
                )
            ):
                return PolicyDecision(
                    False,
                    "upstream response header value is denied",
                    502,
                    {
                        "error": "response_envelope_header_value_denied",
                        "constraint_id": constraint_id,
                        "header": name,
                    },
                )
    return PolicyDecision(True)


def _response_json_path(payload: Any, path: str) -> Any:
    value = payload
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def _durable_failure_reason(reason: str) -> str:
    if (
        isinstance(reason, str)
        and reason
        and reason == reason.strip()
        and len(reason.encode("utf-8")) <= 256
        and all(ord(character) >= 32 and ord(character) != 127 for character in reason)
    ):
        return reason
    return "durable_policy_terminal_failure"


def _durable_failure_evidence(
    flow: http.HTTPFlow,
    *,
    body: bytes,
    reason: str,
) -> tuple[str, str, list[dict[str, Any]]]:
    claims = flow.metadata.get("serverware_durable_policy_claims")
    if not isinstance(claims, list):
        raise ValueError("durable policy claims are missing")
    del reason
    failure_reason = (
        "provider_outcome_or_response_validation_uncertain"
    )
    response_body_sha256 = (
        "sha256:" + hashlib.sha256(body).hexdigest()
    )
    evidence = [
        {
            "constraint_id": claim["constraint_id"],
            "lineage_digest": claim["lineage_digest"],
            "request_cursor_digest": claim["request_cursor_digest"],
            "outcome": "indeterminate",
            "reason": failure_reason,
            "response_body_sha256": response_body_sha256,
        }
        for claim in claims
        if claim.get("type") == "traversalBudget"
    ]
    return failure_reason, response_body_sha256, evidence


def _prepare_durable_response_evidence(
    flow: http.HTTPFlow,
    *,
    validated_decoded_body: bytes,
) -> tuple[PolicyDecision, list[dict[str, Any]]]:
    reservation = flow.metadata.get("serverware_durable_policy_reservation")
    if reservation is None:
        return PolicyDecision(True), []
    claims = flow.metadata.get("serverware_durable_policy_claims")
    if not isinstance(claims, list):
        return (
            PolicyDecision(
                False,
                "durable policy claims are missing",
                503,
                {"error": "durable_policy_claims_missing"},
            ),
            [],
        )
    traversal_claims = [
        claim for claim in claims if claim.get("type") == "traversalBudget"
    ]
    evidence: list[dict[str, Any]] = []
    raw_body = validated_decoded_body
    try:
        payload = (
            strict_json_loads(raw_body)
            if traversal_claims and isinstance(raw_body, bytes)
            else None
        )
        if traversal_claims and not isinstance(payload, dict):
            raise ValueError("traversal response must be a JSON object")
        for claim in traversal_claims:
            cursor = _response_json_path(
                payload, str(claim["response_cursor_field"])
            )
            if cursor is not None and (
                not isinstance(cursor, str)
                or not cursor
                or len(cursor.encode("utf-8")) > 4096
            ):
                raise ValueError("traversal response cursor is invalid")
            records = _response_json_path(
                payload, str(claim["record_count_field"])
            )
            if not isinstance(records, list):
                raise ValueError("traversal response record evidence is missing")
            evidence.append(
                {
                    "constraint_id": claim["constraint_id"],
                    "lineage_digest": claim["lineage_digest"],
                    "request_cursor_digest": claim[
                        "request_cursor_digest"
                    ],
                    "response_digest": (
                        "sha256:" + hashlib.sha256(raw_body).hexdigest()
                    ),
                    "next_cursor_digest": (
                        "sha256:"
                        + hashlib.sha256(cursor.encode("utf-8")).hexdigest()
                        if cursor is not None
                        else None
                    ),
                    "record_count": len(records),
                    "decoded_bytes": len(raw_body or b""),
                    "validation": "passed",
                }
            )
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        return (
            PolicyDecision(
                False,
                "traversal response evidence is invalid",
                502,
                {
                    "error": "traversal_response_evidence_invalid",
                    "detail": str(exc),
                },
            ),
            [],
        )
    return PolicyDecision(True), evidence


def _complete_durable_response_state(
    flow: http.HTTPFlow,
    *,
    response_evidence: list[dict[str, Any]],
) -> PolicyDecision:
    reservation = flow.metadata.get("serverware_durable_policy_reservation")
    if reservation is None:
        return PolicyDecision(True)
    del response_evidence
    if not isinstance(reservation, dict):
        return PolicyDecision(
            False,
            "durable policy response state is invalid",
            503,
            {"error": "durable_policy_response_commit_invalid"},
        )
    if reservation.get("state") == "indeterminate":
        return PolicyDecision(
            False,
            "durable policy response completion is indeterminate",
            503,
            {
                "error": "durable_policy_response_indeterminate",
                "reason": reservation.get("failure_reason"),
            },
        )
    if reservation.get("state") == "denied":
        return PolicyDecision(
            False,
            "durable traversal response budget denied",
            502,
            {
                "error": "durable_traversal_response_denied",
                "reason": reservation.get("failure_reason"),
            },
        )
    if reservation.get("state") != "committed":
        return PolicyDecision(
            False,
            "durable policy response was not atomically completed",
            503,
            {"error": "durable_policy_response_commit_missing"},
        )
    return PolicyDecision(True)


def _validate_final_response_body(
    flow: http.HTTPFlow,
) -> PolicyDecision:
    expected_digest = flow.metadata.get(
        "serverware_response_validation_body_sha256"
    )
    if (
        not isinstance(expected_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest) is None
    ):
        return PolicyDecision(
            False,
            "response validation body digest is missing",
            503,
            {"error": "response_validation_body_digest_missing"},
        )
    completion = flow.metadata.get(
        "serverware_durable_policy_completion"
    )
    if isinstance(completion, dict) and completion.get("outcome") == "forwarded":
        durable_digest = completion.get("response_body_sha256")
        if (
            not isinstance(durable_digest, str)
            or not hmac.compare_digest(expected_digest, durable_digest)
        ):
            return PolicyDecision(
                False,
                "durable response body binding disagrees with validation",
                503,
                {"error": "durable_response_body_binding_mismatch"},
            )
    body = (
        flow.response.raw_content
        if flow.response is not None
        and isinstance(flow.response.raw_content, bytes)
        else None
    )
    actual_digest = (
        "sha256:" + hashlib.sha256(body).hexdigest()
        if body is not None
        else None
    )
    if (
        not isinstance(expected_digest, str)
        or actual_digest is None
        or not hmac.compare_digest(expected_digest, actual_digest)
    ):
        return PolicyDecision(
            False,
            "response changed after policy validation",
            503,
            {"error": "response_changed_after_validation"},
        )
    return PolicyDecision(True)


def validate_response_completion(flow: http.HTTPFlow) -> PolicyDecision:
    body_decision = _validate_final_response_body(flow)
    if not body_decision.allowed:
        return body_decision
    completion_decision = _complete_durable_response_state(
        flow,
        response_evidence=[],
    )
    if not completion_decision.allowed:
        return completion_decision
    if flow.metadata.get("serverware_response_release_audit_logged") is True:
        return completion_decision
    audit_context = flow.metadata.get(
        "serverware_response_validation_audit_context"
    )
    if not isinstance(audit_context, dict):
        return PolicyDecision(
            False,
            "response release audit context is missing",
            503,
            {"error": "response_release_audit_context_missing"},
        )
    release_audit_context = copy.deepcopy(audit_context)
    release_audit_context["release_state"] = flow.metadata.get(
        "serverware_release_state"
    )
    release_audit_context["completion_outcome"] = flow.metadata.get(
        "serverware_release_completion_outcome"
    )
    release_audit_context["response_release"] = {"ok": True}
    try:
        runtime.log_request(
            flow.metadata.get("serverware_route_id"),
            flow.request.method,
            _audit_url(flow),
            "response_release_authorized",
            (
                flow.response.status_code
                if flow.response is not None
                else None
            ),
            None,
            release_audit_context,
        )
    except Exception:
        return PolicyDecision(
            False,
            "response release audit failed closed",
            503,
            {"error": "response_release_audit_failed_closed"},
        )
    flow.metadata["serverware_response_release_audit_logged"] = True
    return completion_decision


def _terminalize_durable_response_failure(
    flow: http.HTTPFlow,
    *,
    body: bytes,
    reason: str,
) -> PolicyDecision | None:
    return _terminalize_durable_transport_outcome(
        flow,
        provider_outcome="unknown",
        body=body,
        reason=reason,
    )


def _terminalize_durable_transport_outcome(
    flow: http.HTTPFlow,
    *,
    provider_outcome: str,
    body: bytes,
    reason: str,
) -> PolicyDecision | None:
    if provider_outcome not in {"forwarded", "not_forwarded", "unknown"}:
        return PolicyDecision(
            False,
            "durable policy cleanup outcome is invalid",
            503,
            {"error": "durable_policy_cleanup_outcome_invalid"},
        )
    reservation = flow.metadata.get("serverware_durable_policy_reservation")
    if reservation is None or (
        isinstance(reservation, dict)
        and reservation.get("state")
        in {"committed", "aborted", "indeterminate", "denied"}
    ):
        return None
    try:
        if provider_outcome == "not_forwarded":
            flow.metadata.pop(
                "serverware_durable_policy_completion",
                None,
            )
            return None
        (
            failure_reason,
            response_body_sha256,
            traversal_evidence,
        ) = _durable_failure_evidence(
            flow,
            body=body,
            reason=reason,
        )
        completion = {
            "outcome": "unknown",
            "response_evidence": traversal_evidence,
            "response_body_sha256": response_body_sha256,
            "failure_reason": failure_reason,
            "uncertainty": "charged_fail_closed",
        }
        lifecycle = _release_lifecycle(flow)
        dispatch_deadline = (
            lifecycle.get("dispatch_expires_at_epoch_ms")
            if isinstance(lifecycle, dict)
            else None
        )
        if type(dispatch_deadline) is int:
            completion[
                "dispatch_deadline_at_epoch_ms"
            ] = dispatch_deadline
        flow.metadata[
            "serverware_durable_policy_completion"
        ] = completion
    except Exception:
        return PolicyDecision(
            False,
            "durable policy response cleanup is uncertain",
            503,
            {"error": "durable_policy_response_cleanup_uncertain"},
        )
    return None


def _combine_cleanup_uncertainty(
    primary: PolicyDecision,
    secondary: PolicyDecision | None,
    *,
    error: str,
    reason: str,
) -> PolicyDecision:
    if secondary is None or secondary.allowed:
        return primary
    if primary.allowed:
        return secondary
    return PolicyDecision(
        False,
        reason,
        503,
        {
            "error": error,
            "primary": {
                "reason": primary.reason,
                "error": (primary.payload or {}).get("error"),
            },
            "durable": {
                "reason": secondary.reason,
                "error": (secondary.payload or {}).get("error"),
            },
        },
    )


def evaluate_response(flow: http.HTTPFlow) -> PolicyDecision:
    encoding_decision = _validate_response_content_encoding(flow)
    if not encoding_decision.allowed:
        body = flow.response.raw_content if flow.response else b""
        cleanup = _terminalize_durable_response_failure(
            flow,
            body=body or b"",
            reason=str(
                (encoding_decision.payload or {}).get("error")
                or encoding_decision.reason
            ),
        )
        discard_response_guards(flow)
        return cleanup or encoding_decision
    response_credential_guard = _take_response_credential_guard(flow)
    try:
        return _evaluate_response(flow, response_credential_guard)
    except Exception:
        body = (
            flow.response.raw_content
            if flow.response is not None
            and isinstance(flow.response.raw_content, bytes)
            else b""
        )
        decision = PolicyDecision(
            False,
            "response evaluation failed closed",
            503,
            {"error": "response_evaluation_failed_closed"},
        )
        cleanup = _terminalize_durable_response_failure(
            flow,
            body=body,
            reason="response_evaluation_failed_closed",
        )
        return _combine_cleanup_uncertainty(
            decision,
            cleanup,
            error="response_evaluation_and_durable_cleanup_uncertain",
            reason=(
                "response evaluation and durable policy cleanup are "
                "uncertain"
            ),
        )
    finally:
        if response_credential_guard:
            response_credential_guard.clear()


def _evaluate_response(
    flow: http.HTTPFlow,
    response_credential_guard: _ResponseCredentialGuard | None,
) -> PolicyDecision:
    route = flow.metadata.get("serverware_route")
    params = flow.metadata.get("serverware_params") or {}
    route_id = flow.metadata.get("serverware_route_id")
    if not route:
        if flow.metadata.get("serverware_blocked_response") is True:
            return PolicyDecision(True)
        safe_url = _audit_url(flow)
        runtime.log_request(
            route_id,
            flow.request.method,
            safe_url,
            "blocked",
            502,
            "response policy context missing",
        )
        return PolicyDecision(
            False,
            "response policy context missing",
            502,
            {"error": "response_policy_context_missing"},
        )
    status_code = flow.response.status_code if flow.response else None
    raw_upstream_response = flow.response.raw_content if flow.response else b""
    upstream_response_body_sha256 = (
        "sha256:" + hashlib.sha256(raw_upstream_response or b"").hexdigest()
    )

    def response_denial(decision: PolicyDecision) -> PolicyDecision:
        cleanup = _terminalize_durable_response_failure(
            flow,
            body=raw_upstream_response or b"",
            reason=str((decision.payload or {}).get("error") or decision.reason),
        )
        return cleanup or decision

    audit_context = {
        "principal_id": flow.metadata.get("serverware_principal_id"),
        "policy_hash": flow.metadata.get("serverware_policy_hash"),
        "credential_id": flow.metadata.get("serverware_credential_id"),
        "credential_version": flow.metadata.get("serverware_credential_version"),
        "request_digest": flow.metadata.get("serverware_request_digest"),
        "operation_digest": flow.metadata.get("serverware_operation_digest"),
        "attempt_id": flow.metadata.get("serverware_release_attempt_id"),
        "binding_digest": flow.metadata.get("serverware_release_binding_digest"),
        "release_state": flow.metadata.get("serverware_release_state"),
        "completion_outcome": flow.metadata.get(
            "serverware_release_completion_outcome"
        ),
        "route_adapter": getattr(route, "adapter_type", None),
        "discarded_request_headers": flow.metadata.get(
            "serverware_discarded_request_headers"
        ),
    }
    envelope_decision = _evaluate_response_envelope(flow, route)
    if not envelope_decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            envelope_decision.status_code,
            envelope_decision.reason,
            audit_context,
        )
        return response_denial(envelope_decision)
    response_binding_audit: dict[str, Any] | None = None
    if status_code is not None and 200 <= status_code < 300:
        semantic_decision = evaluate_response_constraints(
            flow,
            _legacy_constraint_route(route),
            constraint_types={"responseJson", "responseBinding"},
        )
        if not semantic_decision.allowed:
            payload = semantic_decision.payload or {}
            response_binding_audit = {
                key: payload[key]
                for key in (
                    "error",
                    "constraint_id",
                    "constraint_type",
                    "binding_id",
                    "evidence_digest",
                )
                if key in payload
            }
            denied_audit_context = dict(audit_context)
            denied_audit_context["response_validation"] = {
                "ok": False,
                **response_binding_audit,
            }
            denied_audit_context["response_body_sha256"] = upstream_response_body_sha256
            runtime.log_request(
                route_id,
                flow.request.method,
                _audit_url(flow),
                "blocked",
                semantic_decision.status_code,
                semantic_decision.reason,
                denied_audit_context,
            )
            return response_denial(semantic_decision)
        if semantic_decision.payload.get("bindings"):
            response_binding_audit = {
                "ok": True,
                "bindings": semantic_decision.payload["bindings"],
            }
    constraint_decision = (
        evaluate_response_constraints(
            flow,
            _legacy_constraint_route(route),
            constraint_types={"responseDateWindow"},
        )
        if status_code is not None and 200 <= status_code < 300
        else PolicyDecision(True)
    )
    if not constraint_decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            constraint_decision.status_code,
            constraint_decision.reason,
            audit_context,
        )
        return response_denial(constraint_decision)
    adapter = get_adapter(route.adapter_type)
    decision = adapter.validate_response(flow, route, params)
    if not decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            decision.status_code,
            decision.reason,
            audit_context,
        )
        return response_denial(decision)
    finalizer = getattr(adapter, "finalize_response", None)
    if finalizer is None:
        finalize_decision = PolicyDecision(True)
    else:
        try:
            finalize_decision = finalizer(flow, route, params)
        except Exception:
            finalize_decision = PolicyDecision(
                False,
                "response finalization failed closed",
                503,
                {"error": "response_finalization_failed_closed"},
            )
    if not finalize_decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            finalize_decision.status_code,
            finalize_decision.reason,
            audit_context,
        )
        return response_denial(finalize_decision)
    if (
        response_credential_guard
        and response_credential_guard.detects_response(flow.response)
    ):
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            502,
            "response credential reflection denied",
            audit_context,
        )
        return response_denial(
            PolicyDecision(
                False,
                "response credential reflection denied",
                502,
                {"error": "response_credential_reflection"},
            )
        )
    final_body = (
        flow.response.raw_content
        if flow.response is not None
        and isinstance(flow.response.raw_content, bytes)
        else b""
    )
    flow.metadata["serverware_response_validation_body_sha256"] = (
        "sha256:" + hashlib.sha256(final_body).hexdigest()
    )
    evidence_decision, durable_response_evidence = (
        _prepare_durable_response_evidence(
            flow,
            validated_decoded_body=final_body,
        )
    )
    if not evidence_decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
            "blocked",
            evidence_decision.status_code,
            evidence_decision.reason,
            audit_context,
        )
        return response_denial(evidence_decision)
    lifecycle = _release_lifecycle(flow)
    if lifecycle is not None and lifecycle.get("durable_policy") is not None:
        dispatch_deadline = lifecycle.get("dispatch_expires_at_epoch_ms")
        if type(dispatch_deadline) is not int:
            return response_denial(
                PolicyDecision(
                    False,
                    "durable policy dispatch deadline is missing",
                    503,
                    {"error": "durable_policy_dispatch_deadline_missing"},
                )
            )
        flow.metadata["serverware_durable_policy_completion"] = {
            "outcome": "forwarded",
            "response_evidence": copy.deepcopy(durable_response_evidence),
            "response_body_sha256": (
                "sha256:" + hashlib.sha256(final_body).hexdigest()
            ),
            "dispatch_deadline_at_epoch_ms": dispatch_deadline,
        }
    if response_binding_audit is not None:
        audit_context = dict(audit_context)
        audit_context["response_validation"] = response_binding_audit
        audit_context["response_body_sha256"] = upstream_response_body_sha256
    flow.metadata["serverware_response_validation_audit_context"] = (
        copy.deepcopy(audit_context)
    )
    flow.metadata.pop("serverware_response_release_audit_logged", None)
    runtime.log_request(
        route_id,
        flow.request.method,
        _audit_url(flow),
        "response_validated",
        status_code,
        None,
        audit_context,
    )
    return finalize_decision
