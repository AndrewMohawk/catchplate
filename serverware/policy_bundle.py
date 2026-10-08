from __future__ import annotations

import copy
import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, parse_qsl, quote, urlencode, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware.config import (
    POLICY_BUNDLE_PATH,
    POLICY_MIN_ROLLBACK_EPOCH,
    POLICY_MIN_SEQUENCE,
    POLICY_SIGNING_KEY_PATH,
    POLICY_SIGNING_PUBLIC_KEY_PATH,
    RELEASE_CHANNEL,
    SCHEMA_DIR,
    ensure_data_dirs,
)


class FrozenDict(dict):
    def _immutable(self, *_: Any, **__: Any) -> None:
        raise TypeError("compiled policy mappings are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __copy__(self) -> dict[Any, Any]:
        return dict(self)

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[Any, Any]:
        copied = {
            copy.deepcopy(key, memo): copy.deepcopy(value, memo)
            for key, value in self.items()
        }
        memo[id(self)] = copied
        return copied


class FrozenList(list):
    def _immutable(self, *_: Any, **__: Any) -> None:
        raise TypeError("compiled policy lists are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __copy__(self) -> list[Any]:
        return list(self)

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        copied = [copy.deepcopy(value, memo) for value in self]
        memo[id(self)] = copied
        return copied


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return FrozenDict(
            {
                _deep_freeze(key): _deep_freeze(item)
                for key, item in value.items()
            }
        )
    if isinstance(value, list):
        return FrozenList(_deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_deep_freeze(item) for item in value)
    return value


SUPPORTED_ADAPTERS = {"generic.rest", "gmail.v1", "x.v2", "npm.registry"}
MANAGED_OAUTH_PROVIDERS = {
    "google",
    "google.oauth",
    "google.oauth2",
    "twitter",
    "x",
    "x.oauth",
    "x.oauth2",
}
X_V2_BOUNDED_READ_OPERATIONS = frozenset(
    {
        "accountActivity.read",
        "activity.read",
        "analytics.read",
        "bookmarks.read",
        "chat.read",
        "communities.read",
        "compliance.read",
        "connections.read",
        "directMessages.read",
        "insights.read",
        "lists.read",
        "media.read",
        "news.read",
        "notes.read",
        "schema.read",
        "search.read",
        "spaces.read",
        "trends.read",
        "tweets.read",
        "usage.read",
        "users.read",
        "webhooks.read",
    }
)
GMAIL_OPERATION_REQUIRED_OAUTH_SCOPES = {
    "gmail.messages.list": frozenset(
        {"https://www.googleapis.com/auth/gmail.readonly"}
    ),
    "gmail.message.get": frozenset(
        {"https://www.googleapis.com/auth/gmail.readonly"}
    ),
}
X_OPERATION_REQUIRED_OAUTH_SCOPES = {
    "accountActivity.read": frozenset({"tweet.read", "users.read"}),
    "activity.read": frozenset({"tweet.read", "users.read"}),
    "analytics.read": frozenset({"tweet.read", "users.read"}),
    "bookmarks.read": frozenset(
        {"bookmark.read", "tweet.read", "users.read"}
    ),
    "chat.read": frozenset({"dm.read", "tweet.read", "users.read"}),
    "communities.read": frozenset({"tweet.read", "users.read"}),
    "compliance.read": frozenset({"tweet.read", "users.read"}),
    "connections.read": frozenset({"follows.read", "users.read"}),
    "directMessages.read": frozenset(
        {"dm.read", "tweet.read", "users.read"}
    ),
    "insights.read": frozenset({"tweet.read", "users.read"}),
    "lists.read": frozenset({"list.read", "tweet.read", "users.read"}),
    "media.read": frozenset({"tweet.read", "users.read"}),
    "news.read": frozenset({"tweet.read", "users.read"}),
    "notes.read": frozenset({"tweet.read", "users.read"}),
    "schema.read": frozenset({"tweet.read", "users.read"}),
    "search.read": frozenset({"tweet.read", "users.read"}),
    "spaces.read": frozenset({"space.read", "tweet.read", "users.read"}),
    "trends.read": frozenset({"tweet.read", "users.read"}),
    "tweets.read": frozenset({"tweet.read", "users.read"}),
    "usage.read": frozenset({"tweet.read", "users.read"}),
    "users.read": frozenset({"users.read"}),
    "webhooks.read": frozenset({"tweet.read", "users.read"}),
    "tweets.write": frozenset(
        {"tweet.read", "tweet.write", "users.read"}
    ),
}
X_V2_RECENT_SEARCH_PATHS = frozenset(
    {
        "/2/tweets/counts/recent",
        "/2/tweets/search/recent",
    }
)
PROVIDER_ACCOUNT_OPERATION_FIELD = "providerAccount"
NPM_WRITE_OPERATIONS = frozenset(
    {"publish", "unpublish", "distTagWrite", "tokenWrite", "metadataWrite"}
)
FORBIDDEN_UPSTREAM_METADATA_CIDRS = (
    "169.254.169.254/32",
    "169.254.170.0/24",
    "100.100.100.200/32",
    "192.0.0.192/32",
    "fd00:ec2::/64",
    "fd20:ce::/64",
)
FORBIDDEN_UPSTREAM_METADATA_NETWORKS = tuple(
    ipaddress.ip_network(cidr, strict=True)
    for cidr in FORBIDDEN_UPSTREAM_METADATA_CIDRS
)
IPV4_MAPPED_IPV6_NETWORK = ipaddress.ip_network("::ffff:0:0/96", strict=True)
DEMO_UPSTREAM_RESOLVED_CIDRS = ("172.16.0.0/12",)
NPM_PUBLIC_REGISTRY_HOST = "registry.npmjs.org"
NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT = "npm-public-registry-receipt-v1"
NPM_PUBLIC_REGISTRY_RECEIPT_FIELDS = ("ok", "published")
MAX_POLICY_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_POLICY_SIGNING_KEY_BYTES = 64 * 1024
POLICY_HIGH_WATER_TRUST_BOUNDARY = (
    "Policy rollback protection assumes the metadata high-water store cannot be "
    "rolled back with the policy file. A coherent rollback of both a local SQLite "
    "store and the policy file cannot be detected internally and requires external "
    "storage, snapshot, or monotonic-counter protection."
)
PROVIDER_REQUEST_PROFILE_FIELDS = frozenset(
    {
        "allowedHeaders",
        "discardHeaders",
        "allowedQueryKeys",
        "allowedMediaTypes",
        "maxBodyBytes",
        "valueRules",
    }
)
PROVIDER_REQUEST_PROFILE_REQUIRED_FIELDS = (
    PROVIDER_REQUEST_PROFILE_FIELDS - {"discardHeaders"}
)
GMAIL_V1_REQUEST_HEADERS = (
    "accept",
    "accept-encoding",
    "user-agent",
    "x-goog-api-client",
    "x-goog-request-params",
    "x-goog-user-project",
)
GMAIL_V1_REQUEST_QUERY_KEYS = (
    "$.xgafv",
    "alt",
    "fields",
    "format",
    "includeSpamTrash",
    "labelIds",
    "maxResults",
    "metadataHeaders",
    "pageToken",
    "prettyPrint",
    "q",
    "quotaUser",
)
X_V2_REQUEST_HEADERS = ("accept", "accept-encoding", "user-agent")

# Frozen from the official X OpenAPI document at https://api.twitter.com/2/openapi.json
# on 2026-07-16. Policy changes are required before a newly published query key is usable.
X_V2_RECENT_SEARCH_QUERY_KEYS = (
    "end_time",
    "expansions",
    "granularity",
    "max_results",
    "media.fields",
    "next_token",
    "place.fields",
    "poll.fields",
    "query",
    "search_count.fields",
    "since_id",
    "sort_order",
    "start_time",
    "tweet.fields",
    "until_id",
    "user.fields",
)
GMAIL_V1_OPERATION_QUERY_KEYS = {
    "gmail.messages.list": frozenset(GMAIL_V1_REQUEST_QUERY_KEYS),
    "gmail.message.get": frozenset(
        {
            "$.xgafv",
            "alt",
            "fields",
            "format",
            "metadataHeaders",
            "prettyPrint",
            "quotaUser",
        }
    ),
}
X_V2_OPERATION_FIELDS = frozenset(
    {"operation", "tweetId", "userId", "username", "listId", "spaceId"}
)
GMAIL_V1_OPERATION_FIELDS = {
    "gmail.messages.list": frozenset({"operation", "gmailUser"}),
    "gmail.message.get": frozenset(
        {"operation", "gmailUser", "messageId"}
    ),
}
NPM_OPERATION_FIELDS = {
    "npm.publish": frozenset(
        {
            "operation",
            "packageName",
            "packageVersion",
            "revision",
            "tarballIntegrity",
            "attachmentName",
            "attachmentBytes",
        }
    ),
    "npm.unpublish": frozenset(
        {"operation", "packageName", "revision", "tarball"}
    ),
    "npm.distTagWrite": frozenset(
        {"operation", "packageName", "packageVersion", "tag"}
    ),
    "npm.tokenWrite": frozenset({"operation", "tokenKey"}),
    "npm.tokenCreate": frozenset({"operation"}),
    "npm.metadataWrite": frozenset(
        {"operation", "packageName", "revision", "scope", "team"}
    ),
}
X_V2_BOUNDED_READ_QUERY_KEYS = (
    "analytics.fields",
    "chat_conversation.fields",
    "chat_message_event.fields",
    "command",
    "community.fields",
    "compliance_job.fields",
    "connection.fields",
    "days",
    "dm_event.fields",
    "end_time",
    "endpoints",
    "engagement.fields",
    "event_types",
    "exclude",
    "expansions",
    "granularity",
    "ids",
    "list.fields",
    "max_age_hours",
    "max_results",
    "max_trends",
    "media.fields",
    "media_analytics.fields",
    "media_id",
    "media_keys",
    "news.fields",
    "next_token",
    "note.fields",
    "pagination_token",
    "personalized_trend.fields",
    "place.fields",
    "poll.fields",
    "post_selection",
    "public_key.fields",
    "query",
    "requested_metrics",
    "search_count.fields",
    "since_id",
    "sort_order",
    "space.fields",
    "start_time",
    "state",
    "status",
    "test_mode",
    "topic.fields",
    "trend.fields",
    "tweet.fields",
    "tweet_ids",
    "type",
    "until_id",
    "usage.fields",
    "user.fields",
    "user_ids",
    "usernames",
    "webhook_config.fields",
)
NPM_REGISTRY_REQUEST_HEADERS = (
    "accept",
    "accept-encoding",
    "npm-auth-type",
    "npm-command",
    "npm-in-ci",
    "npm-otp",
    "npm-scope",
    "user-agent",
)


def required_oauth_scopes_for_operation(
    adapter_type: str,
    operation: str,
) -> frozenset[str] | None:
    catalog = {
        "gmail.v1": GMAIL_OPERATION_REQUIRED_OAUTH_SCOPES,
        "x.v2": X_OPERATION_REQUIRED_OAUTH_SCOPES,
    }.get(adapter_type)
    if catalog is None:
        return frozenset()
    return catalog.get(operation)


def adapter_operation_field_names(
    adapter_type: str,
    operation: str,
    generic_fields: set[str] | frozenset[str] = frozenset(),
) -> frozenset[str] | None:
    if adapter_type == "generic.rest":
        return frozenset({"operation", *generic_fields})
    if adapter_type == "gmail.v1":
        return GMAIL_V1_OPERATION_FIELDS.get(operation)
    if adapter_type == "x.v2":
        return (
            X_V2_OPERATION_FIELDS
            if operation in X_OPERATION_REQUIRED_OAUTH_SCOPES
            else None
        )
    if adapter_type == "npm.registry":
        return NPM_OPERATION_FIELDS.get(operation)
    return None


def adapter_operation_query_fields(
    adapter_type: str,
    adapter_config: dict[str, Any],
    operation: str,
) -> frozenset[str] | None:
    if adapter_type == "generic.rest":
        return frozenset(
            (adapter_config.get("request") or {}).get("allowedQueryKeys") or []
        )
    if adapter_type == "gmail.v1":
        return GMAIL_V1_OPERATION_QUERY_KEYS.get(operation)
    if adapter_type == "x.v2":
        if operation == "search.read":
            return frozenset(X_V2_RECENT_SEARCH_QUERY_KEYS)
        return frozenset(
            (adapter_config.get("request") or {}).get("allowedQueryKeys") or []
        )
    if adapter_type == "npm.registry":
        return frozenset()
    return None
SUPPORTED_CONSTRAINTS = {
    "rateLimit",
    "slidingWindowLimit",
    "weightedBudget",
    "traversalBudget",
    "operationPolicy",
    "queryDateWindow",
    "queryNumericBounds",
    "requestTimeWindow",
    "requestValue",
    "jsonBody",
    "formBody",
    "responseDateWindow",
    "responseJson",
    "responseBinding",
    "responseEnvelope",
}
RESPONSE_CONSTRAINTS = {
    "responseDateWindow",
    "responseJson",
    "responseBinding",
    "responseEnvelope",
}
REQUEST_CONSTRAINTS = SUPPORTED_CONSTRAINTS - RESPONSE_CONSTRAINTS - {
    "traversalBudget"
}
FAIL_CLOSED_DEFAULTS = {
    "action": "deny",
    "failMode": "closed",
    "unknownHosts": "block",
    "unknownPaths": "block",
    "validationFailure": "block",
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
    "query",
    "selectedHeaders",
    "bodySha256",
}
STREAMING_RESPONSE_MODES = {
    "stream",
    "jsonlStream",
    "jsonArrayStream",
    "jsonSseStream",
    "jsonNestedStream",
    "formUrlencodedStream",
    "csvStream",
}
STRUCTURED_STREAMING_MODES = STREAMING_RESPONSE_MODES - {"stream"}
CREDENTIAL_BEARING_GENERIC_REQUEST_BODY_MODES = frozenset(
    {"none", "json", "formUrlencoded"}
)
BUFFERED_PASSTHROUGH_RESPONSE_MODE = "bufferedPassthrough"
CREDENTIAL_BEARING_GENERIC_RESPONSE_MODES = frozenset(
    {"headersOnly", "json", BUFFERED_PASSTHROUGH_RESPONSE_MODE}
)
GENERIC_REQUEST_MEDIA_TYPES = {
    "json": "application/json",
    "formUrlencoded": "application/x-www-form-urlencoded",
    "jsonlStream": "application/x-ndjson",
    "jsonArrayStream": "application/json",
    "jsonSseStream": "text/event-stream",
    "jsonNestedStream": "application/json",
    "formUrlencodedStream": "application/x-www-form-urlencoded",
    "csvStream": "text/csv",
}
PROJECTED_RESPONSE_MODES = {"json"} | STRUCTURED_STREAMING_MODES
BUFFERED_RESPONSE_MODES = {"any", "headersOnly", "json"}
SUPPORTED_RESPONSE_MODES = (
    BUFFERED_RESPONSE_MODES | STREAMING_RESPONSE_MODES | {BUFFERED_PASSTHROUGH_RESPONSE_MODE}
)
FORBIDDEN_AGENT_CREDENTIAL_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
}
NON_FORWARDABLE_AGENT_HEADERS = FORBIDDEN_AGENT_CREDENTIAL_HEADERS | {
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-serverware-agent",
    "x-serverware-admin-token",
    "x-serverware-audit-anchor-token",
    "x-serverware-ca-install-token",
    "x-serverware-csrf-token",
    "x-serverware-data-plane-token",
    "x-serverware-proof-nonce",
}
RAW_REQUEST_ADMISSION_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
}
MAX_DISCARD_REQUEST_HEADERS = 16
RESERVED_DISCARD_REQUEST_HEADERS = NON_FORWARDABLE_AGENT_HEADERS | {
    "api-key",
    "authentication-info",
    "baggage",
    "content-digest",
    "content-encoding",
    "content-md5",
    "content-range",
    "content-type",
    "cookie2",
    "date",
    "digest",
    "dpop",
    "expect",
    "forwarded",
    "idempotency-key",
    "origin",
    "proxy-authentication-info",
    "range",
    "referer",
    "repr-digest",
    "signature",
    "signature-input",
    "traceparent",
    "tracestate",
    "via",
    "want-content-digest",
    "want-digest",
    "www-authenticate",
    "x-access-token",
    "x-api-key",
    "x-authorization",
    "x-auth-token",
    "x-client-cert",
    "x-csrf-token",
    "x-forwarded-client-cert",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
    "x-ssl-client-cert",
    "x-xsrf-token",
}
RESERVED_DISCARD_REQUEST_HEADER_PREFIXES = (
    "authorization-",
    "cookie-",
    "if-",
    "npm-",
    "proxy-",
    "sec-",
    "x-amz-",
    "x-forwarded-",
    "x-goog-",
    "x-ms-",
    "x-serverware-",
)
RESERVED_DISCARD_REQUEST_HEADER_SUFFIXES = (
    "-api-key",
    "-auth",
    "-authorization",
    "-credential",
    "-identity",
    "-proof",
    "-signature",
    "-token",
)
SERVERWARE_INTERNAL_HEADER_PREFIX = "x-serverware-"
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-language",
        "etag",
        "last-modified",
        "retry-after",
        "www-authenticate",
    }
)
MAX_PROVIDER_RESPONSE_BODY_BYTES = 1024 * 1024
MAX_PROVIDER_ERROR_BODY_BYTES = 64 * 1024
MAX_RAW_ABSOLUTE_TARGET_BYTES = 64 * 1024
MAX_RAW_QUERY_FIELDS = 256
RESPONSE_FIELD_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
OPERATION_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
JSON_OPERATION_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
HTTP_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
CREDENTIAL_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
SHA256_IDENTITY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SPIFFE_ID_RE = re.compile(
    r"^spiffe://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$"
)
DNS_SAN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
OAUTH_BINDING_FIELDS = frozenset(
    {"provider", "providerSubjects", "clientIds", "requiredScopes"}
)
CREDENTIAL_INJECTION_FIELDS = {
    "bearer": frozenset({"type", "header", "field", "prefix"}),
    "basic": frozenset({"type", "header", "field", "username"}),
    "header": frozenset({"type", "name", "field", "prefix"}),
    "query": frozenset({"type", "name", "field"}),
    "cookie": frozenset({"type", "name", "field"}),
}
REQUIRED_REQUEST_HEADER_RULE_FIELDS = {"type", "minLength", "maxLength", "pattern"}
FIELD_RULE_FIELDS = {
    "required",
    "type",
    "enum",
    "equals",
    "minLength",
    "maxLength",
    "pattern",
    "min",
    "max",
    "minItems",
    "maxItems",
}
FIELD_RULE_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}
CONSTRAINT_COMMON_FIELDS = {"id", "description", "type", "phase", "statusCode", "extensions"}
CONSTRAINT_TYPE_FIELDS = {
    "rateLimit": {
        "store",
        "max",
        "windowSeconds",
        "calendarWindow",
        "windowSemantics",
        "key",
    },
    "slidingWindowLimit": {
        "store",
        "windowSeconds",
        "max",
        "windowSemantics",
        "measure",
        "reservationMode",
        "onOverflow",
        "key",
    },
    "weightedBudget": {
        "store",
        "windowSeconds",
        "max",
        "windowSemantics",
        "measure",
        "reservationMode",
        "onOverflow",
        "key",
        "weight",
    },
    "traversalBudget": {
        "traversal",
        "operations",
    },
    "operationPolicy": {"allowedOperations", "deniedOperations"},
    "queryDateWindow": {"parameters", "required", "formats", "maxAgeDays", "allowFutureSkewSeconds"},
    "queryNumericBounds": {"parameters", "required", "min", "max", "integer"},
    "requestTimeWindow": {"timezone", "notBefore", "notAfter", "weekdays", "dailyWindows"},
    "requestValue": {"rules"},
    "jsonBody": {"contentTypes", "allowedFields", "requiredFields", "deniedFields", "fields"},
    "formBody": {"contentTypes", "allowedFields", "requiredFields", "deniedFields", "fields"},
    "responseDateWindow": {
        "required",
        "formats",
        "maxAgeDays",
        "allowFutureSkewSeconds",
        "items",
        "dateFields",
        "operations",
    },
    "responseJson": {"required", "items", "fields", "operations"},
    "responseBinding": {"successStatusCodes", "contentTypes", "bindings", "operations"},
    "responseEnvelope": {
        "statusCodes",
        "bodyPresence",
        "contentTypes",
        "allowedResponseHeaderNames",
        "responseHeaderRules",
        "operations",
    },
}


class PolicyBundleError(ValueError):
    pass


def _is_finite_json_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _validate_finite_json_numbers(value: Any) -> None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not _is_finite_json_number(value):
            raise ValueError("JSON number must be finite and representable")
        return
    if isinstance(value, dict):
        for item in value.values():
            _validate_finite_json_numbers(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_finite_json_numbers(item)


def strict_json_loads(raw: str | bytes | bytearray) -> Any:
    text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    def finite_float(text: str) -> float:
        value = float(text)
        if not _is_finite_json_number(value):
            raise ValueError("JSON number must be finite and representable")
        return value

    def finite_int(text: str) -> int:
        if text == "-0":
            raise ValueError("JSON integer must use canonical zero")
        value = int(text)
        if not _is_finite_json_number(value):
            raise ValueError("JSON number must be finite and representable")
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_keys,
        parse_float=finite_float,
        parse_int=finite_int,
        parse_constant=reject_constant,
    )


def _admit_policy_json_object(raw: Any) -> None:
    if not isinstance(raw, dict):
        raise PolicyBundleError("policy bundle must be an object")
    try:
        canonical_json(raw)
    except (OverflowError, TypeError, ValueError) as exc:
        raise PolicyBundleError(f"policy bundle contains an invalid JSON value: {exc}") from exc


def normalized_credential_provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    aliases = {
        "twitter": "x",
        "x.oauth": "x",
        "x.oauth2": "x",
        "google.oauth": "google",
        "google.oauth2": "google",
    }
    return aliases.get(provider, provider)


def valid_traversal_query_name(value: Any) -> bool:
    """An exact decoded query key, not a response path or URL-encoded name."""
    if not isinstance(value, str) or not value:
        return False
    try:
        byte_count = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return byte_count <= 256 and not any(
        ord(character) < 32 or 127 <= ord(character) <= 159
        for character in value
    )


def valid_traversal_request_field(source: Any, value: Any) -> bool:
    if not valid_traversal_query_name(value):
        return False
    if source == "query":
        return True
    return (
        source == "header"
        and value == value.lower()
        and HTTP_HEADER_NAME_RE.fullmatch(value) is not None
    )


def is_serverware_internal_header(value: Any) -> bool:
    return str(value).strip().lower().startswith(SERVERWARE_INTERNAL_HEADER_PREFIX)


def provider_account_scope_value(provider: str, provider_subject: str | None) -> str | None:
    provider = normalized_credential_provider(provider)
    if not provider or not provider_subject:
        return None
    material = f"{provider}\0{provider_subject}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def credential_injection_target(injection: dict[str, Any]) -> tuple[str, str] | None:
    if not isinstance(injection, dict):
        return None
    injection_type = injection.get("type", "bearer")
    if not isinstance(injection_type, str):
        return None

    def target_value(name: str, default: str) -> str | None:
        value = injection.get(name, default)
        return value if isinstance(value, str) else None

    if injection_type == "bearer":
        value = target_value("header", "Authorization")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "header":
        value = target_value("name", "X-Api-Key")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "basic":
        value = target_value("header", "Authorization")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "cookie":
        return "header", "cookie"
    if injection_type == "query":
        value = target_value("name", "access_token")
        return ("query", value) if value is not None else None
    return None


def canonical_json(value: Any) -> str:
    _validate_finite_json_numbers(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def policy_hash(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(policy_signature_bytes(value)).hexdigest()


def policy_signature_bytes(value: dict[str, Any]) -> bytes:
    if value.get("apiVersion") == "serverware.policy/v2":
        from serverware.policy_route_authority import canonical
        return canonical(signature_payload(value))
    return canonical_json(signature_payload(value)).encode("utf-8")


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


@dataclass(frozen=True)
class SecureFileIdentity:
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    file_sha256: str

    @property
    def stat_components(self) -> tuple[int, ...]:
        return (
            self.device,
            self.inode,
            self.owner_uid,
            self.owner_gid,
            self.mode,
            self.nlink,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
        )


@dataclass(frozen=True)
class SecureDirectoryIdentity:
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    nlink: int

    @property
    def stat_components(self) -> tuple[int, ...]:
        return (
            self.device,
            self.inode,
            self.owner_uid,
            self.owner_gid,
            self.mode,
            self.nlink,
        )


@dataclass(frozen=True)
class PolicySigningTrustIdentity:
    public_key_file: SecureFileIdentity
    signing_key_id: str
    revocation_digest: str


@dataclass(frozen=True)
class PolicySigningTrust:
    public_key: Ed25519PublicKey
    identity: PolicySigningTrustIdentity


_POLICY_SIGNING_KEY_THREAD_LOCK = threading.RLock()
_POLICY_SIGNING_KEY_LOCK_STATE = threading.local()


def _policy_path_protections_are_production() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in {
        "dev",
        "development",
        "local",
        "test",
    }


def _validate_secure_directory_stat(
    directory_stat: os.stat_result,
    *,
    label: str,
    leaf: bool,
    mutation_target: bool,
    trusted_lock_namespace: bool = False,
    allow_service_owned_lock_leaf: bool = False,
) -> None:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise PolicyBundleError(f"{label} directory path is not a directory")
    if directory_stat.st_nlink < 1:
        raise PolicyBundleError(f"{label} directory is unlinked")
    effective_uid = os.geteuid()
    if directory_stat.st_uid not in {0, effective_uid}:
        raise PolicyBundleError(
            f"{label} directory ancestry has an untrusted owner"
        )
    permissions = stat.S_IMODE(directory_stat.st_mode)
    if not permissions & stat.S_IXUSR:
        raise PolicyBundleError(f"{label} directory is not owner-searchable")
    trusted_lock_owner = directory_stat.st_uid == 0 or (
        leaf
        and allow_service_owned_lock_leaf
        and directory_stat.st_uid == effective_uid
    )
    if trusted_lock_namespace and (
        not trusted_lock_owner or permissions & 0o022
    ):
        raise PolicyBundleError(
            f"{label} production lock ancestry must be root-owned, except "
            "for its protected service-owned leaf, and not group/world writable"
        )
    if (
        leaf
        and mutation_target
        and (
            directory_stat.st_uid != effective_uid
            or not permissions & stat.S_IWUSR
        )
    ):
        raise PolicyBundleError(
            f"{label} mutation directory must be owned and writable by "
            "the service effective user"
        )
    writable_by_others = bool(permissions & 0o022)
    if _policy_path_protections_are_production():
        if writable_by_others:
            raise PolicyBundleError(
                f"{label} directory ancestry must not be group/world writable"
            )
    elif writable_by_others and not (
        not leaf
        and directory_stat.st_uid == 0
        and bool(permissions & stat.S_ISVTX)
    ):
        raise PolicyBundleError(
            f"{label} development directory ancestry is insecure"
        )


def _secure_absolute_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if _policy_path_protections_are_production():
        return absolute
    # macOS development temp paths commonly traverse the root-owned /var
    # compatibility symlink. Production never canonicalizes path ancestry.
    return Path(os.path.realpath(os.fspath(absolute.parent))) / absolute.name


def _open_secure_parent_directory(
    path: Path,
    *,
    label: str,
    create_for_development: bool = False,
    mutation_target: bool = False,
    trusted_lock_namespace: bool = False,
) -> tuple[Path, str, int, SecureDirectoryIdentity]:
    absolute = _secure_absolute_path(path)
    if absolute.name in {"", ".", ".."}:
        raise PolicyBundleError(f"{label} path is invalid")
    if (
        create_for_development
        and not _policy_path_protections_are_production()
    ):
        absolute.parent.mkdir(parents=True, exist_ok=True)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(os.path.sep, flags)
    except OSError as exc:
        raise PolicyBundleError(f"{label} directory root is unavailable") from exc
    try:
        root_stat = os.fstat(descriptor)
        _validate_secure_directory_stat(
            root_stat,
            label=label,
            leaf=False,
            mutation_target=mutation_target,
            trusted_lock_namespace=trusted_lock_namespace,
        )
        components = absolute.parent.parts[1:]
        for index, component in enumerate(components):
            if component in {"", ".", ".."}:
                raise PolicyBundleError(f"{label} directory path is invalid")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise PolicyBundleError(
                    f"{label} directory path must not contain symlinks"
                ) from exc
            try:
                child_stat = os.fstat(child)
                _validate_secure_directory_stat(
                    child_stat,
                    label=label,
                    leaf=index == len(components) - 1,
                    mutation_target=mutation_target,
                    trusted_lock_namespace=trusted_lock_namespace,
                )
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        parent_stat = os.fstat(descriptor)
        _validate_secure_directory_stat(
            parent_stat,
            label=label,
            leaf=True,
            mutation_target=mutation_target,
            trusted_lock_namespace=trusted_lock_namespace,
        )
        identity = SecureDirectoryIdentity(
            device=parent_stat.st_dev,
            inode=parent_stat.st_ino,
            owner_uid=parent_stat.st_uid,
            owner_gid=parent_stat.st_gid,
            mode=parent_stat.st_mode,
            nlink=parent_stat.st_nlink,
        )
        return absolute, absolute.name, descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def _recheck_secure_parent_directory(
    path: Path,
    *,
    label: str,
    expected: SecureDirectoryIdentity,
    mutation_target: bool = False,
    trusted_lock_namespace: bool = False,
) -> None:
    _, _, descriptor, current = _open_secure_parent_directory(
        path,
        label=label,
        mutation_target=mutation_target,
        trusted_lock_namespace=trusted_lock_namespace,
    )
    try:
        if current.stat_components != expected.stat_components:
            raise PolicyBundleError(f"{label} parent directory changed")
    finally:
        os.close(descriptor)


def _secure_stat_components(file_stat: os.stat_result) -> tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_uid,
        file_stat.st_gid,
        file_stat.st_mode,
        file_stat.st_nlink,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _validate_secure_file_stat(
    file_stat: os.stat_result,
    *,
    label: str,
    expected_mode: int,
    maximum_size: int | None = None,
    allow_empty: bool = False,
) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise PolicyBundleError(f"{label} must be a non-symlink regular file")
    if file_stat.st_uid != os.geteuid():
        raise PolicyBundleError(
            f"{label} must be owned by the service effective user"
        )
    if stat.S_IMODE(file_stat.st_mode) != expected_mode:
        raise PolicyBundleError(f"{label} must use mode {expected_mode:04o}")
    if file_stat.st_nlink != 1:
        raise PolicyBundleError(f"{label} must not be hardlinked")
    if maximum_size is not None and (
        file_stat.st_size > maximum_size
        or (not allow_empty and file_stat.st_size < 1)
    ):
        minimum = 0 if allow_empty else 1
        raise PolicyBundleError(
            f"{label} must contain {minimum}-{maximum_size} bytes"
        )


def _secure_path_exists(path: Path, *, label: str) -> bool:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(path, label=label)
    )
    try:
        try:
            os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            exists = True
        except FileNotFoundError:
            exists = False
        except OSError as exc:
            raise PolicyBundleError(f"{label} cannot be inspected") from exc
    finally:
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label=label,
        expected=parent_identity,
    )
    return exists


def _read_secure_file_stat(
    path: Path,
    *,
    label: str,
    expected_mode: int,
    maximum_size: int,
) -> os.stat_result:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(path, label=label)
    )
    try:
        try:
            current = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PolicyBundleError(f"{label} is unavailable") from exc
        _validate_secure_file_stat(
            current,
            label=label,
            expected_mode=expected_mode,
            maximum_size=maximum_size,
        )
    finally:
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label=label,
        expected=parent_identity,
    )
    return current


def _read_stable_secure_file(
    path: Path,
    *,
    label: str,
    expected_mode: int,
    maximum_size: int,
) -> tuple[bytes, SecureFileIdentity]:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(path, label=label)
    )
    try:
        try:
            path_stat_before = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PolicyBundleError(f"{label} is unavailable") from exc
        _validate_secure_file_stat(
            path_stat_before,
            label=label,
            expected_mode=expected_mode,
            maximum_size=maximum_size,
        )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(basename, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise PolicyBundleError(
                f"{label} must be a readable non-symlink regular file"
            ) from exc
        try:
            file_stat_before = os.fstat(descriptor)
            _validate_secure_file_stat(
                file_stat_before,
                label=label,
                expected_mode=expected_mode,
                maximum_size=maximum_size,
            )
            if _secure_stat_components(path_stat_before) != (
                _secure_stat_components(file_stat_before)
            ):
                raise PolicyBundleError(f"{label} changed while it was opened")
            payload = bytearray()
            while len(payload) <= maximum_size:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, maximum_size + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            file_stat_after = os.fstat(descriptor)
            try:
                path_stat_after = os.stat(
                    basename,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise PolicyBundleError(
                    f"{label} changed while it was read"
                ) from exc
            components = _secure_stat_components(file_stat_before)
            if (
                len(payload) != file_stat_before.st_size
                or len(payload) > maximum_size
                or _secure_stat_components(file_stat_after) != components
                or _secure_stat_components(path_stat_after) != components
            ):
                raise PolicyBundleError(f"{label} changed while it was read")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label=label,
        expected=parent_identity,
    )
    payload_bytes = bytes(payload)
    return payload_bytes, SecureFileIdentity(
        device=file_stat_after.st_dev,
        inode=file_stat_after.st_ino,
        owner_uid=file_stat_after.st_uid,
        owner_gid=file_stat_after.st_gid,
        mode=file_stat_after.st_mode,
        nlink=file_stat_after.st_nlink,
        size=file_stat_after.st_size,
        mtime_ns=file_stat_after.st_mtime_ns,
        ctime_ns=file_stat_after.st_ctime_ns,
        file_sha256="sha256:" + hashlib.sha256(payload_bytes).hexdigest(),
    )


def _atomic_write_secure_file(
    path: Path,
    payload: bytes,
    *,
    label: str,
    mode: int,
) -> None:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(
            path,
            label=label,
            create_for_development=True,
            mutation_target=True,
        )
    )
    temporary_name: str | None = None
    try:
        try:
            existing = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise PolicyBundleError(f"{label} cannot be inspected") from exc
        if existing is not None:
            _validate_secure_file_stat(
                existing,
                label=label,
                expected_mode=mode,
                allow_empty=True,
            )
        temporary_descriptor: int | None = None
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(16):
            temporary_name = f".{basename}.{secrets.token_hex(16)}.tmp"
            try:
                temporary_descriptor = os.open(
                    temporary_name,
                    flags,
                    mode,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                temporary_name = None
                continue
            except OSError as exc:
                raise PolicyBundleError(
                    f"temporary {label} cannot be created"
                ) from exc
        if temporary_descriptor is None or temporary_name is None:
            raise PolicyBundleError(f"temporary {label} name allocation failed")
        try:
            os.fchmod(temporary_descriptor, mode)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(temporary_descriptor, remaining)
                if written < 1:
                    raise PolicyBundleError(f"temporary {label} write failed")
                remaining = remaining[written:]
            os.fsync(temporary_descriptor)
            temporary_stat = os.fstat(temporary_descriptor)
            _validate_secure_file_stat(
                temporary_stat,
                label=f"temporary {label}",
                expected_mode=mode,
                allow_empty=True,
            )
        finally:
            os.close(temporary_descriptor)
        os.replace(
            temporary_name,
            basename,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        installed_stat = os.stat(
            basename,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _validate_secure_file_stat(
            installed_stat,
            label=label,
            expected_mode=mode,
            allow_empty=True,
        )
        if (
            installed_stat.st_dev,
            installed_stat.st_ino,
            installed_stat.st_size,
        ) != (
            temporary_stat.st_dev,
            temporary_stat.st_ino,
            temporary_stat.st_size,
        ):
            raise PolicyBundleError(f"{label} changed during installation")
        os.fsync(parent_descriptor)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label=label,
        expected=parent_identity,
        mutation_target=True,
    )


def _unlink_secure_file(
    path: Path,
    *,
    label: str,
    expected_mode: int,
    maximum_size: int,
) -> None:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(
            path,
            label=label,
            mutation_target=True,
        )
    )
    try:
        try:
            existing = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PolicyBundleError(f"{label} cannot be inspected") from exc
        _validate_secure_file_stat(
            existing,
            label=label,
            expected_mode=expected_mode,
            maximum_size=maximum_size,
        )
        os.unlink(basename, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label=label,
        expected=parent_identity,
        mutation_target=True,
    )


@contextmanager
def _exclusive_secure_file_lock(
    lock_path: Path,
    *,
    label: str,
    thread_lock: threading.RLock,
    state: threading.local,
    trusted_lock_namespace: bool = False,
    precreated_lock: bool = False,
    expected_mode: int = 0o600,
    directory_lock: bool = False,
):
    with thread_lock:
        depth = int(getattr(state, "depth", 0))
        if depth:
            state.depth = depth + 1
            try:
                yield
            finally:
                state.depth = depth
            return

        _, basename, parent_descriptor, parent_identity = (
            _open_secure_parent_directory(
                lock_path,
                label=label,
                create_for_development=not precreated_lock and not directory_lock,
                mutation_target=not precreated_lock and not directory_lock,
                trusted_lock_namespace=trusted_lock_namespace,
            )
        )
        flags = (
            (os.O_RDONLY if precreated_lock or directory_lock else os.O_RDWR)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | (getattr(os, "O_DIRECTORY", 0) if directory_lock else 0)
        )
        created = False
        descriptor: int | None = None
        try:
            if precreated_lock or directory_lock:
                try:
                    descriptor = os.open(
                        basename,
                        flags,
                        dir_fd=parent_descriptor,
                    )
                except OSError as exc:
                    raise PolicyBundleError(
                        f"{label} must be a pre-created non-symlink "
                        + ("directory" if directory_lock else "regular file")
                    ) from exc
            else:
                try:
                    descriptor = os.open(
                        basename,
                        flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                    created = True
                except FileExistsError:
                    try:
                        descriptor = os.open(
                            basename,
                            flags,
                            dir_fd=parent_descriptor,
                        )
                    except OSError as exc:
                        raise PolicyBundleError(
                            f"{label} must be a non-symlink regular file"
                        ) from exc
                except OSError as exc:
                    raise PolicyBundleError(f"{label} cannot be created") from exc
            if descriptor is None:
                raise PolicyBundleError(f"{label} cannot be opened")
            if created:
                os.fchmod(descriptor, 0o600)
                os.fsync(parent_descriptor)
            path_stat = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            descriptor_stat = os.fstat(descriptor)
            if directory_lock:
                _validate_secure_directory_stat(
                    path_stat,
                    label=label,
                    leaf=True,
                    mutation_target=True,
                    trusted_lock_namespace=trusted_lock_namespace,
                    allow_service_owned_lock_leaf=True,
                )
                _validate_secure_directory_stat(
                    descriptor_stat,
                    label=label,
                    leaf=True,
                    mutation_target=True,
                    trusted_lock_namespace=trusted_lock_namespace,
                    allow_service_owned_lock_leaf=True,
                )
                path_components = SecureDirectoryIdentity(
                    device=path_stat.st_dev,
                    inode=path_stat.st_ino,
                    owner_uid=path_stat.st_uid,
                    owner_gid=path_stat.st_gid,
                    mode=path_stat.st_mode,
                    nlink=path_stat.st_nlink,
                ).stat_components
                descriptor_components = SecureDirectoryIdentity(
                    device=descriptor_stat.st_dev,
                    inode=descriptor_stat.st_ino,
                    owner_uid=descriptor_stat.st_uid,
                    owner_gid=descriptor_stat.st_gid,
                    mode=descriptor_stat.st_mode,
                    nlink=descriptor_stat.st_nlink,
                ).stat_components
            else:
                _validate_secure_file_stat(
                    path_stat,
                    label=label,
                    expected_mode=expected_mode,
                    allow_empty=True,
                )
                _validate_secure_file_stat(
                    descriptor_stat,
                    label=label,
                    expected_mode=expected_mode,
                    allow_empty=True,
                )
                path_components = _secure_stat_components(path_stat)
                descriptor_components = _secure_stat_components(descriptor_stat)
            if path_components != descriptor_components:
                raise PolicyBundleError(f"{label} changed while it was opened")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            _recheck_secure_parent_directory(
                lock_path,
                label=label,
                expected=parent_identity,
                mutation_target=not precreated_lock and not directory_lock,
                trusted_lock_namespace=trusted_lock_namespace,
            )
            locked_path_stat = os.stat(
                basename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            locked_descriptor_stat = os.fstat(descriptor)
            locked_path_components = (
                SecureDirectoryIdentity(
                    device=locked_path_stat.st_dev,
                    inode=locked_path_stat.st_ino,
                    owner_uid=locked_path_stat.st_uid,
                    owner_gid=locked_path_stat.st_gid,
                    mode=locked_path_stat.st_mode,
                    nlink=locked_path_stat.st_nlink,
                ).stat_components
                if directory_lock
                else _secure_stat_components(locked_path_stat)
            )
            locked_descriptor_components = (
                SecureDirectoryIdentity(
                    device=locked_descriptor_stat.st_dev,
                    inode=locked_descriptor_stat.st_ino,
                    owner_uid=locked_descriptor_stat.st_uid,
                    owner_gid=locked_descriptor_stat.st_gid,
                    mode=locked_descriptor_stat.st_mode,
                    nlink=locked_descriptor_stat.st_nlink,
                ).stat_components
                if directory_lock
                else _secure_stat_components(locked_descriptor_stat)
            )
            if (
                locked_path_components != locked_descriptor_components
                or (not directory_lock and locked_descriptor_stat.st_nlink != 1)
            ):
                raise PolicyBundleError(f"{label} changed while it was locked")
            state.depth = 1
            try:
                yield
            finally:
                state.depth = 0
                _recheck_secure_parent_directory(
                    lock_path,
                    label=label,
                    expected=parent_identity,
                    mutation_target=not precreated_lock and not directory_lock,
                    trusted_lock_namespace=trusted_lock_namespace,
                )
                final_path_stat = os.stat(
                    basename,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                final_descriptor_stat = os.fstat(descriptor)
                final_path_components = (
                    SecureDirectoryIdentity(
                        device=final_path_stat.st_dev,
                        inode=final_path_stat.st_ino,
                        owner_uid=final_path_stat.st_uid,
                        owner_gid=final_path_stat.st_gid,
                        mode=final_path_stat.st_mode,
                        nlink=final_path_stat.st_nlink,
                    ).stat_components
                    if directory_lock
                    else _secure_stat_components(final_path_stat)
                )
                final_descriptor_components = (
                    SecureDirectoryIdentity(
                        device=final_descriptor_stat.st_dev,
                        inode=final_descriptor_stat.st_ino,
                        owner_uid=final_descriptor_stat.st_uid,
                        owner_gid=final_descriptor_stat.st_gid,
                        mode=final_descriptor_stat.st_mode,
                        nlink=final_descriptor_stat.st_nlink,
                    ).stat_components
                    if directory_lock
                    else _secure_stat_components(final_descriptor_stat)
                )
                if final_path_components != final_descriptor_components:
                    raise PolicyBundleError(f"{label} changed while it was held")
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_descriptor)


@contextmanager
def _policy_signing_key_lock():
    lock_path = Path(str(POLICY_SIGNING_KEY_PATH) + ".lock")
    with _exclusive_secure_file_lock(
        lock_path,
        label="policy signing key lock",
        thread_lock=_POLICY_SIGNING_KEY_THREAD_LOCK,
        state=_POLICY_SIGNING_KEY_LOCK_STATE,
    ):
        yield


def _public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_key_id(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _load_private_key_locked(*, create: bool) -> Ed25519PrivateKey | None:
    try:
        private_payload, _ = _read_stable_secure_file(
            POLICY_SIGNING_KEY_PATH,
            label="policy signing private key",
            expected_mode=0o600,
            maximum_size=MAX_POLICY_SIGNING_KEY_BYTES,
        )
    except PolicyBundleError:
        if not _secure_path_exists(
            POLICY_SIGNING_KEY_PATH,
            label="policy signing private key",
        ):
            if not create:
                return None
            private_key = Ed25519PrivateKey.generate()
            private_key_payload = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            _atomic_write_secure_file(
                POLICY_SIGNING_KEY_PATH,
                private_key_payload,
                label="policy signing private key",
                mode=0o600,
            )
            persisted_payload, _ = _read_stable_secure_file(
                POLICY_SIGNING_KEY_PATH,
                label="policy signing private key",
                expected_mode=0o600,
                maximum_size=MAX_POLICY_SIGNING_KEY_BYTES,
            )
            if not hmac.compare_digest(persisted_payload, private_key_payload):
                raise PolicyBundleError(
                    "persisted policy signing private key changed during creation"
                )
            return private_key
        raise
    try:
        private_key = serialization.load_pem_private_key(
            private_payload, password=None
        )
    except (TypeError, ValueError) as exc:
        raise PolicyBundleError("policy signing private key is invalid") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise PolicyBundleError("policy signing private key must use Ed25519")
    return private_key


def _load_policy_private_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    with _policy_signing_key_lock():
        private_key_exists = _secure_path_exists(
            POLICY_SIGNING_KEY_PATH,
            label="policy signing private key",
        )
        public_key_exists = _secure_path_exists(
            POLICY_SIGNING_PUBLIC_KEY_PATH,
            label="policy signing public key",
        )
        if public_key_exists and not private_key_exists:
            raise PolicyBundleError(
                "policy signing private key is unavailable for trusted public key"
            )
        private_key = _load_private_key_locked(create=True)
        if private_key is None:
            raise PolicyBundleError("policy signing private key is unavailable")
        expected_public_payload = _public_key_pem(private_key.public_key())
        try:
            public_payload, _ = _read_stable_secure_file(
                POLICY_SIGNING_PUBLIC_KEY_PATH,
                label="policy signing public key",
                expected_mode=0o644,
                maximum_size=MAX_POLICY_SIGNING_KEY_BYTES,
            )
        except PolicyBundleError:
            if not _secure_path_exists(
                POLICY_SIGNING_PUBLIC_KEY_PATH,
                label="policy signing public key",
            ):
                _atomic_write_secure_file(
                    POLICY_SIGNING_PUBLIC_KEY_PATH,
                    expected_public_payload,
                    label="policy signing public key",
                    mode=0o644,
                )
                public_payload = expected_public_payload
            else:
                raise
        if not hmac.compare_digest(public_payload, expected_public_payload):
            raise PolicyBundleError(
                "policy signing private key does not match trusted public key"
            )
        return private_key


def _revoked_policy_signing_key_ids() -> tuple[tuple[str, ...], str]:
    raw = os.environ.get("SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS", "")
    values = tuple(sorted({value.strip() for value in raw.split(",") if value.strip()}))
    if any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in values):
        raise PolicyBundleError(
            "policy signing key revocation input contains a noncanonical digest"
        )
    digest = "sha256:" + hashlib.sha256(
        canonical_json(list(values)).encode("utf-8")
    ).hexdigest()
    return values, digest


def _load_policy_signing_trust() -> PolicySigningTrust:
    public_payload, public_identity = _read_stable_secure_file(
        POLICY_SIGNING_PUBLIC_KEY_PATH,
        label="policy signing public key",
        expected_mode=0o644,
        maximum_size=MAX_POLICY_SIGNING_KEY_BYTES,
    )
    try:
        public_key = serialization.load_pem_public_key(public_payload)
    except (TypeError, ValueError) as exc:
        raise PolicyBundleError("policy signing public key is invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise PolicyBundleError("policy signing public key must use Ed25519")
    signing_key_id = _public_key_id(public_key)
    revoked_key_ids, revocation_digest = _revoked_policy_signing_key_ids()
    if signing_key_id in revoked_key_ids:
        raise PolicyBundleError("policy signing key is revoked")
    return PolicySigningTrust(
        public_key=public_key,
        identity=PolicySigningTrustIdentity(
            public_key_file=public_identity,
            signing_key_id=signing_key_id,
            revocation_digest=revocation_digest,
        ),
    )


def policy_public_key() -> Ed25519PublicKey:
    try:
        return _load_policy_signing_trust().public_key
    except PolicyBundleError:
        _load_policy_private_key()
        return _load_policy_signing_trust().public_key


def policy_public_key_pem() -> str:
    return policy_public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def policy_public_key_hash() -> str:
    return _public_key_id(policy_public_key())


def sign_policy_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    _admit_policy_json_object(raw)
    if raw.get("apiVersion") == "serverware.policy/v2":
        from serverware.policy_route_authority import admit
        admit(raw)
    private_key = _load_policy_private_key()
    signing_key_id = _public_key_id(private_key.public_key())
    trust = _load_policy_signing_trust()
    if signing_key_id != trust.identity.signing_key_id:
        raise PolicyBundleError(
            "policy signing private key does not match trusted public key"
        )
    signed = copy.deepcopy(raw)
    signed.setdefault("metadata", {})
    signed["metadata"]["signingKeyId"] = signing_key_id
    signed["metadata"].pop("signature", None)
    signature = private_key.sign(policy_signature_bytes(signed))
    signed["metadata"]["signature"] = "ed25519:" + _b64e(signature)
    return signed


def verify_policy_signature(
    raw: dict[str, Any],
    *,
    signing_trust: PolicySigningTrust | None = None,
) -> PolicySigningTrust:
    _admit_policy_json_object(raw)
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        raise PolicyBundleError("policy bundle metadata is missing")
    trust = signing_trust or _load_policy_signing_trust()
    if metadata.get("signingKeyId") != trust.identity.signing_key_id:
        raise PolicyBundleError(
            "policy bundle signing key identity does not match trusted public key"
        )
    signature_value = metadata.get("signature")
    if not isinstance(signature_value, str) or not signature_value.startswith("ed25519:"):
        raise PolicyBundleError("policy bundle must include metadata.signature using ed25519")
    try:
        signature = _b64d(signature_value.split(":", 1)[1])
    except (TypeError, ValueError) as exc:
        raise PolicyBundleError("policy bundle signature encoding is invalid") from exc
    try:
        trust.public_key.verify(
            signature,
            policy_signature_bytes(raw),
        )
    except InvalidSignature as exc:
        raise PolicyBundleError("policy bundle signature verification failed") from exc
    return trust


def _load_schema(path: Path) -> dict[str, Any]:
    loaded = strict_json_loads(path.read_text())
    if not isinstance(loaded, dict):
        raise PolicyBundleError(f"JSON schema must be an object: {path}")
    return loaded


def _canonical_network_host(
    value: Any,
    context: str,
    *,
    normalize_dns_case: bool,
    allow_ipv6: bool,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value.endswith(".")
        or any(
            ord(character) <= 32
            or ord(character) == 127
            or ord(character) > 127
            or character in "\\%@/?#[]"
            for character in value
        )
    ):
        raise PolicyBundleError(
            f"{context} host must be a canonical ASCII DNS, IPv4, or IPv6 host"
        )
    if ":" in value:
        if not allow_ipv6:
            raise PolicyBundleError(
                f"{context} IPv6 host is not admitted by the standard v1 policy contract"
            )
        try:
            address = ipaddress.IPv6Address(value)
        except ValueError as exc:
            raise PolicyBundleError(
                f"{context} host is not valid IPv6"
            ) from exc
        if address.ipv4_mapped is not None or str(address) != value:
            raise PolicyBundleError(
                f"{context} IPv6 host must use canonical compressed lower-case form"
            )
        return value
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        address = None
    if address is not None:
        if str(address) != value:
            raise PolicyBundleError(
                f"{context} IPv4 host must use canonical dotted-decimal form"
            )
        return value
    canonical = value.lower()
    if (not normalize_dns_case and value != canonical) or all(
        character.isdigit() or character == "." for character in value
    ):
        raise PolicyBundleError(
            f"{context} DNS host must be lower-case and not an ambiguous numeric form"
        )
    for label in canonical.split("."):
        if (
            not 1 <= len(label) <= 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character == "-"))
                for character in label
            )
        ):
            raise PolicyBundleError(
                f"{context} DNS host contains an invalid label"
            )
    return canonical


def _canonical_route_host(value: Any, route_id: str) -> str:
    return _canonical_network_host(
        value,
        f"route {route_id}",
        normalize_dns_case=False,
        allow_ipv6=False,
    )


def _canonical_cidr(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 64
    ):
        raise PolicyBundleError(f"{context} must be a canonical IPv4 or IPv6 CIDR")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PolicyBundleError(
            f"{context} must use a network address and explicit canonical prefix"
        ) from exc
    if isinstance(network, ipaddress.IPv6Network):
        if network.network_address.ipv4_mapped is not None:
            raise PolicyBundleError(f"{context} cannot use IPv4-mapped IPv6")
        canonical = f"{network.network_address.compressed}/{network.prefixlen}"
    else:
        canonical = f"{network.network_address}/{network.prefixlen}"
    if value != canonical:
        raise PolicyBundleError(f"{context} must equal canonical CIDR {canonical}")
    return canonical


def _bounded_unique_strings(
    value: Any,
    *,
    context: str,
    maximum_items: int,
    maximum_bytes: int,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= maximum_items
        or any(
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item.encode("utf-8")) > maximum_bytes
            or (pattern is not None and pattern.fullmatch(item) is None)
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise PolicyBundleError(
            f"{context} must contain 1-{maximum_items} unique canonical strings"
        )
    return tuple(value)


def _validate_mtls_identity_policy(
    principal_id: str, raw: Any
) -> dict[str, tuple[str, ...]] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyBundleError(f"principal {principal_id} mtls must be an object")
    allowed = {
        "verifiedByTrustedIngress",
        "sanSpiffeIds",
        "sanDnsNames",
        "sanUris",
        "certificateSha256",
        "spkiSha256",
        "issuerSpkiSha256",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyBundleError(
            f"principal {principal_id} mtls has unsupported fields: {', '.join(unknown)}"
        )
    if raw.get("verifiedByTrustedIngress") is not True:
        raise PolicyBundleError(
            f"principal {principal_id} mtls requires verifiedByTrustedIngress"
        )
    compiled: dict[str, tuple[str, ...]] = {}
    for field_name, pattern, maximum_bytes in (
        ("sanSpiffeIds", SPIFFE_ID_RE, 2048),
        ("sanDnsNames", DNS_SAN_RE, 253),
        (
            "sanUris",
            re.compile(r"^[a-z][a-z0-9+.-]*:[^\s\x00-\x1f\x7f]{1,2040}$"),
            2048,
        ),
    ):
        if field_name not in raw:
            continue
        compiled[field_name] = _bounded_unique_strings(
            raw[field_name],
            context=f"principal {principal_id} mtls.{field_name}",
            maximum_items=32,
            maximum_bytes=maximum_bytes,
            pattern=pattern,
        )
    for field_name in (
        "certificateSha256",
        "spkiSha256",
        "issuerSpkiSha256",
    ):
        value = raw.get(field_name)
        if value is None:
            continue
        if not isinstance(value, str) or SHA256_IDENTITY_RE.fullmatch(value) is None:
            raise PolicyBundleError(
                f"principal {principal_id} mtls.{field_name} must be sha256"
            )
        compiled[field_name] = (value,)
    if not any(
        field_name in compiled
        for field_name in (
            "sanSpiffeIds",
            "sanDnsNames",
            "sanUris",
            "certificateSha256",
            "spkiSha256",
        )
    ):
        raise PolicyBundleError(
            f"principal {principal_id} mtls must define at least one verified identity"
        )
    return compiled


def validate_policy_schema(raw: dict[str, Any]) -> None:
    _admit_policy_json_object(raw)
    try:
        from jsonschema import Draft202012Validator, ValidationError, validators
        from referencing import Registry, Resource
    except Exception as exc:
        raise PolicyBundleError("jsonschema package is required for policy validation") from exc

    def validate_less_than_or_equal(
        validator: Any,
        relation: Any,
        instance: Any,
        schema: Any,
    ) -> Any:
        del validator, schema
        if not isinstance(instance, dict) or not isinstance(relation, dict):
            return
        left_name = relation.get("left")
        right_name = relation.get("right")
        left = instance.get(left_name) if isinstance(left_name, str) else None
        right = instance.get(right_name) if isinstance(right_name, str) else None
        if (
            isinstance(left, (int, float))
            and not isinstance(left, bool)
            and isinstance(right, (int, float))
            and not isinstance(right, bool)
            and left > right
        ):
            yield ValidationError(f"{left_name} must not exceed {right_name}")

    ServerwareSchemaValidator = validators.extend(
        Draft202012Validator,
        {
            "x-serverware-less-than-or-equal": validate_less_than_or_equal,
        },
    )

    legacy_schema = _load_schema(SCHEMA_DIR / "policy-bundle.v1.schema.json")
    bundle_schema = (_load_schema(SCHEMA_DIR / "policy-bundle.v2.schema.json")
        if raw.get("apiVersion") == "serverware.policy/v2" else legacy_schema)
    adapter_schemas = [
        _load_schema(SCHEMA_DIR / "adapters" / f"{adapter}.schema.json")
        for adapter in sorted(SUPPORTED_ADAPTERS)
    ]
    registry = Registry().with_resources(
        (
            str(schema["$id"]),
            Resource.from_contents(schema),
        )
        for schema in [legacy_schema, bundle_schema, *adapter_schemas]
    )
    try:
        ServerwareSchemaValidator(
            bundle_schema,
            registry=registry,
        ).validate(raw)
        for route in raw.get("routes") or []:
            adapter = route.get("adapter") or {}
            adapter_type = adapter.get("type")
            if not adapter_type:
                continue
            schema_path = SCHEMA_DIR / "adapters" / f"{adapter_type}.schema.json"
            if schema_path.exists():
                ServerwareSchemaValidator(
                    _load_schema(schema_path),
                    registry=registry,
                ).validate(adapter.get("config") or {})
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise PolicyBundleError(f"policy schema validation failed{location}: {exc.message}") from exc
    except Exception as exc:
        raise PolicyBundleError(
            f"policy schema reference resolution failed: {exc}"
        ) from exc


def _reject_unknown_adapter_fields(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    context: str,
) -> None:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        if not reference.startswith("#/"):
            return
        resolved: Any = root_schema
        for segment in reference[2:].split("/"):
            if not isinstance(resolved, dict) or segment not in resolved:
                raise PolicyBundleError(
                    f"{context} has an unresolved local schema reference"
                )
            resolved = resolved[segment]
        if not isinstance(resolved, dict):
            raise PolicyBundleError(
                f"{context} has an invalid local schema reference"
            )
        _reject_unknown_adapter_fields(
            value, resolved, root_schema, context
        )
        return
    if isinstance(value, dict):
        properties = schema.get("properties")
        if (
            schema.get("additionalProperties") is False
            and isinstance(properties, dict)
        ):
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise PolicyBundleError(
                    f"{context} has unsupported fields: {', '.join(unknown)}"
                )
        if isinstance(properties, dict):
            for name, child in value.items():
                child_schema = properties.get(name)
                if isinstance(child_schema, dict):
                    _reject_unknown_adapter_fields(
                        child,
                        child_schema,
                        root_schema,
                        f"{context}.{name}",
                    )
    elif isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _reject_unknown_adapter_fields(
                    item,
                    item_schema,
                    root_schema,
                    f"{context}[{index}]",
                )


def _validate_closed_adapter_contract(
    route_id: str,
    adapter: Any,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(adapter, dict) or set(adapter) != {"type", "config"}:
        raise PolicyBundleError(
            f"route {route_id} adapter must contain exactly type and config"
        )
    adapter_type = adapter.get("type")
    if not isinstance(adapter_type, str) or adapter_type not in SUPPORTED_ADAPTERS:
        raise PolicyBundleError(
            f"route {route_id} uses unsupported adapter {adapter_type}"
        )
    config = adapter.get("config")
    if not isinstance(config, dict):
        raise PolicyBundleError(
            f"route {route_id} adapter config must be an object"
        )
    schema_path = SCHEMA_DIR / "adapters" / f"{adapter_type}.schema.json"
    if not schema_path.is_file():
        raise PolicyBundleError(
            f"route {route_id} adapter {adapter_type} has no closed schema"
        )
    schema = _load_schema(schema_path)
    properties = schema.get("properties")
    required = schema.get("required")
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or not isinstance(properties, dict)
        or not isinstance(required, list)
        or any(not isinstance(field, str) for field in required)
    ):
        raise PolicyBundleError(
            f"route {route_id} adapter {adapter_type} schema is not a closed contract"
        )
    unknown = sorted(set(config) - set(properties))
    missing = sorted(set(required) - set(config))
    if unknown or missing:
        raise PolicyBundleError(
            f"route {route_id} adapter {adapter_type} config is not closed: "
            f"missing={missing} unknown={unknown}"
        )
    _reject_unknown_adapter_fields(
        config,
        schema,
        schema,
        f"route {route_id} adapter {adapter_type} config",
    )
    return adapter_type, dict(config)


def _validate_route_credential_binding(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    credential: CredentialPolicy | None,
    paths: tuple[str, ...],
) -> None:
    binding = adapter_config.get("credentialBinding")
    if credential is None:
        if adapter_type != "generic.rest":
            raise PolicyBundleError(
                f"route {route_id} {adapter_type} requires a credential binding"
            )
        if (
            adapter_config.get("credentialMode") != "none"
            or binding is not None
            or adapter_config.get("noCredentialProof")
            != {
                "credentialRefAbsent": True,
                "secretInjectionDisabled": True,
                "sensitiveHeadersForwarded": False,
                "authorizationForwarded": False,
            }
        ):
            raise PolicyBundleError(
                f"route {route_id} no-credential generic.rest policy lacks "
                "the exact non-secret proof"
            )
        return
    if (
        adapter_type == "generic.rest"
        and adapter_config.get("credentialMode") != "required"
    ):
        raise PolicyBundleError(
            f"route {route_id} credential-bearing generic.rest policy must "
            "set credentialMode required"
        )
    if not isinstance(binding, dict):
        raise PolicyBundleError(
            f"route {route_id} credential-bearing adapter requires credentialBinding"
        )
    expected_fields = (
        {"credentialType", "provider", "subjects", "clientIds", "requiredScopes"}
        if credential.kind == "oauth2"
        else {"credentialType", "provider", "subjects", "secretClass"}
    )
    if set(binding) != expected_fields:
        raise PolicyBundleError(
            f"route {route_id} credentialBinding fields do not match "
            f"credential type {credential.kind}"
        )
    subjects = binding.get("subjects")
    if (
        binding.get("credentialType") != credential.kind
        or binding.get("provider") != credential.provider
        or subjects != [credential.provider_subject]
    ):
        raise PolicyBundleError(
            f"route {route_id} credentialBinding provider/account does not "
            "match credential {credential.id}"
        )
    if credential.kind == "oauth2":
        client_ids = binding.get("clientIds")
        required_scopes = binding.get("requiredScopes")
        if (
            client_ids != [credential.oauth_client_id]
            or not isinstance(required_scopes, list)
            or not required_scopes
            or not set(required_scopes).issubset(set(credential.scopes))
        ):
            raise PolicyBundleError(
                f"route {route_id} credentialBinding OAuth client or scopes "
                f"do not match credential {credential.id}"
            )
        expected_provider = {
            "gmail.v1": "google",
            "x.v2": "x",
        }.get(adapter_type)
        if expected_provider is not None and credential.provider != expected_provider:
            raise PolicyBundleError(
                f"route {route_id} {adapter_type} requires provider {expected_provider}"
            )
        if adapter_type in {"gmail.v1", "x.v2"}:
            required_for_operations: set[str] = set()
            for operation in _declared_route_operations(
                adapter_type, adapter_config, paths
            ):
                operation_scopes = required_oauth_scopes_for_operation(
                    adapter_type, operation
                )
                if operation_scopes is None:
                    raise PolicyBundleError(
                        f"route {route_id} OAuth operation {operation} has no "
                        "typed scope mapping"
                    )
                required_for_operations.update(operation_scopes)
            if not required_for_operations.issubset(set(required_scopes)):
                raise PolicyBundleError(
                    f"route {route_id} credentialBinding.requiredScopes omits "
                    "scopes required by its admitted operations: "
                    f"{sorted(required_for_operations - set(required_scopes))}"
                )
        if adapter_type == "x.v2" and adapter_config.get("appIds") != client_ids:
            raise PolicyBundleError(
                f"route {route_id} X appIds must exactly equal credentialBinding.clientIds"
            )
    elif adapter_type in {"gmail.v1", "x.v2"}:
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} requires an OAuth credential"
        )
    else:
        secret_class = binding.get("secretClass")
        injection_type = credential.injection.get("type")
        secret_class_matches = (
            injection_type == "bearer"
            and adapter_type == "npm.registry"
            and secret_class
            in {"automationToken", "granularAccessToken", "legacyToken"}
        ) or secret_class == {
            "bearer": "bearerToken",
            "basic": "basicPassword",
            "header": "customHeader",
            "query": "queryToken",
            "cookie": "cookie",
        }.get(injection_type)
        if not secret_class_matches:
            raise PolicyBundleError(
                f"route {route_id} credentialBinding secretClass does not "
                "match its static credential injection"
            )


def _path_template_to_regex(template: str) -> re.Pattern[str]:
    if not template.startswith("/"):
        raise PolicyBundleError(f"path template must start with /: {template}")
    segments = template.strip("/").split("/") if template != "/" else []
    if "**" in segments[:-1]:
        raise PolicyBundleError(f"recursive wildcard must be the final path segment: {template}")
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


def _path_specificity(template: str) -> tuple[int, ...]:
    scores: list[int] = []
    for segment in template.strip("/").split("/"):
        if segment == "**":
            scores.append(0)
        elif segment == "*":
            scores.append(1)
        elif segment.startswith("{") and segment.endswith("}"):
            scores.append(2)
        else:
            scores.append(3)
    return tuple(scores)


def _path_shape(template: str) -> tuple[str, ...]:
    shape: list[str] = []
    for segment in template.strip("/").split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            shape.append("{}")
        else:
            shape.append(segment)
    return tuple(shape)


def parse_bounded_pattern(pattern: str) -> tuple[str, tuple[tuple[int, int], ...], int, int] | None:
    if len(pattern) > 256 or not pattern.isascii() or not pattern.startswith("^") or not pattern.endswith("$"):
        return None
    body = pattern[1:-1]
    class_start = body.find("[")
    if class_start < 0:
        return None
    class_end = body.find("]", class_start + 1)
    if class_end < 0:
        return None
    prefix = body[:class_start]
    if any(character in prefix for character in "\\[]{}"):
        return None
    character_class = body[class_start + 1 : class_end].encode("ascii")
    if not character_class:
        return None
    quantifier = body[class_end + 1 :]
    match = re.fullmatch(r"\{([0-9]+),([0-9]+)\}", quantifier)
    if match is None:
        return None
    minimum, maximum = (int(value) for value in match.groups())
    if minimum > maximum or maximum > 4096:
        return None
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(character_class):
        if index + 2 < len(character_class) and character_class[index + 1] == ord("-"):
            start, end = character_class[index], character_class[index + 2]
            if start > end:
                return None
            ranges.append((start, end))
            index += 3
        else:
            ranges.append((character_class[index], character_class[index]))
            index += 1
    return prefix, tuple(ranges), minimum, maximum


def bounded_pattern_matches(pattern: str, value: str) -> bool | None:
    parsed = parse_bounded_pattern(pattern)
    if parsed is None:
        return None
    prefix, ranges, minimum, maximum = parsed
    if not value.startswith(prefix):
        return False
    remainder = value[len(prefix) :].encode("utf-8")
    return minimum <= len(remainder) <= maximum and all(
        any(start <= byte <= end for start, end in ranges) for byte in remainder
    )


def _validate_safe_pattern(route_id: str, constraint_id: str, field: str, rule: dict[str, Any]) -> None:
    pattern = rule.get("pattern")
    if pattern is None:
        return
    if not isinstance(pattern, str) or parse_bounded_pattern(pattern) is None:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} pattern must use the bounded runtime grammar"
        )
    maximum_length = rule.get("maxLength")
    if type(maximum_length) is not int or not 0 <= maximum_length <= 4096:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} pattern requires maxLength <= 4096"
        )


def _validate_field_rule(
    route_id: str,
    constraint_id: str,
    field: str,
    rule: dict[str, Any],
    *,
    form: bool = False,
) -> None:
    unknown = sorted(set(rule) - FIELD_RULE_FIELDS)
    if unknown:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} has unsupported rules: {', '.join(unknown)}"
        )
    if "required" in rule and not isinstance(rule["required"], bool):
        raise PolicyBundleError(f"route {route_id} constraint {constraint_id} field {field} required must be boolean")
    expected_type = rule.get("type")
    allowed_types = FIELD_RULE_TYPES - ({"object", "null"} if form else set())
    if expected_type is not None and (
        not isinstance(expected_type, str) or expected_type not in allowed_types
    ):
        raise PolicyBundleError(f"route {route_id} constraint {constraint_id} field {field} has unsupported type")
    typed_rule_families = (
        (("minLength", "maxLength", "pattern"), {"string"}, "string"),
        (("min", "max"), {"number", "integer"}, "number or integer"),
        (("minItems", "maxItems"), {"array"}, "array"),
    )
    for names, compatible_types, label in typed_rule_families:
        configured = [name for name in names if name in rule]
        if configured and expected_type not in compatible_types:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} rules "
                f"{', '.join(configured)} require explicit type {label}"
            )
    enum = rule.get("enum")
    if enum is not None and (
        not isinstance(enum, list)
        or not enum
        or any(value in enum[:index] for index, value in enumerate(enum))
    ):
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} enum must be non-empty and unique"
        )
    for minimum_name, maximum_name in (("minLength", "maxLength"), ("minItems", "maxItems")):
        for name in (minimum_name, maximum_name):
            if name in rule and (type(rule[name]) is not int or rule[name] < 0):
                raise PolicyBundleError(
                    f"route {route_id} constraint {constraint_id} field {field} {name} must be a non-negative integer"
                )
        if minimum_name in rule and maximum_name in rule and rule[minimum_name] > rule[maximum_name]:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} {minimum_name} must not exceed {maximum_name}"
            )
    for name in ("min", "max"):
        value = rule.get(name)
        if value is not None and (
            not _is_finite_json_number(value)
        ):
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} {name} must be a finite number"
            )
    if rule.get("min") is not None and rule.get("max") is not None and rule["min"] > rule["max"]:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} min must not exceed max"
        )
    _validate_safe_pattern(route_id, constraint_id, field, rule)


def _validate_response_json_field_rule(
    route_id: str,
    constraint_id: str,
    field: str,
    rule: dict[str, Any],
) -> None:
    _validate_field_rule(route_id, constraint_id, field, rule)
    expected_type = rule.get("type")
    if rule.get("required") is not True or expected_type not in FIELD_RULE_TYPES:
        raise PolicyBundleError(
            f"route {route_id} responseJson {constraint_id} field {field} "
            "must be required and explicitly typed"
        )
    bounded = "equals" in rule or "enum" in rule
    if expected_type == "string":
        bounded = bounded or "maxLength" in rule
    elif expected_type in {"number", "integer"}:
        bounded = bounded or ("min" in rule and "max" in rule)
    elif expected_type == "array":
        bounded = bounded or "maxItems" in rule
    if not bounded:
        raise PolicyBundleError(
            f"route {route_id} responseJson {constraint_id} field {field} "
            "must define a bounded type/value predicate"
        )


def _validate_credential_injection(credential_id: str, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyBundleError(f"credential {credential_id} injection must be an object")
    injection = dict(raw)
    injection_type = injection.get("type")
    if not isinstance(injection_type, str) or injection_type not in CREDENTIAL_INJECTION_FIELDS:
        raise PolicyBundleError(f"credential {credential_id} has unsupported injection type {injection_type!r}")
    unsupported_fields = set(injection) - CREDENTIAL_INJECTION_FIELDS[injection_type]
    if unsupported_fields:
        rendered = ", ".join(repr(name) for name in sorted(unsupported_fields, key=repr))
        raise PolicyBundleError(
            f"credential {credential_id} {injection_type} injection has unsupported fields: {rendered}"
        )

    field = injection.get("field")
    if field is not None and (
        not isinstance(field, str)
        or len(field) > 256
        or CREDENTIAL_FIELD_PATH_RE.fullmatch(field) is None
    ):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection field")

    prefix = injection.get("prefix")
    if prefix is not None and (
        not isinstance(prefix, str)
        or len(prefix) > 128
        or "\r" in prefix
        or "\n" in prefix
    ):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection prefix")

    if injection_type == "basic":
        username = injection.get("username")
        if (
            not isinstance(username, str)
            or not username
            or len(username) > 256
            or any(
                character == ":"
                or character.isspace()
                or ord(character) < 32
                or ord(character) == 127
                for character in username
            )
        ):
            raise PolicyBundleError(f"credential {credential_id} has an invalid Basic username")

    if injection_type in {"header", "query", "cookie"}:
        name = injection.get("name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or HTTP_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise PolicyBundleError(f"credential {credential_id} has an invalid {injection_type} injection name")

    target = credential_injection_target(injection)
    if target is None:
        raise PolicyBundleError(f"credential {credential_id} has no enforceable injection target")
    location, name = target
    if location == "header":
        if not name or len(name) > 128 or HTTP_HEADER_NAME_RE.fullmatch(name) is None:
            raise PolicyBundleError(f"credential {credential_id} has an invalid injection header")
        reserved_target_is_canonical = (
            injection_type in {"bearer", "basic"} and name == "authorization"
        ) or (injection_type == "cookie" and name == "cookie")
        if (
            (name in NON_FORWARDABLE_AGENT_HEADERS and not reserved_target_is_canonical)
            or name.startswith("x-serverware-")
        ):
            raise PolicyBundleError(f"credential {credential_id} uses a forbidden injection header {name}")
    elif not name or len(name) > 128 or any(ord(character) < 33 or ord(character) == 127 for character in name):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection query key")
    return injection


def _validate_managed_oauth_injection(credential_id: str, provider: str, injection: dict[str, Any]) -> None:
    if provider.strip().lower() not in MANAGED_OAUTH_PROVIDERS:
        return
    if (
        injection.get("type") != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise PolicyBundleError(
            f"OAuth credential {credential_id} must inject only access_token as canonical Authorization Bearer"
        )


def _validate_generic_required_headers(
    route_id: str,
    request_config: dict[str, Any],
    allowed_headers: set[str],
) -> set[str]:
    raw = request_config.get("requiredHeaders") or {}
    if not isinstance(raw, dict) or len(raw) > 16:
        raise PolicyBundleError(
            f"route {route_id} generic.rest requiredHeaders must be an object with at most 16 entries"
        )
    required_headers: set[str] = set()
    for name, rule in raw.items():
        if (
            not isinstance(name, str)
            or name != name.lower()
            or len(name) > 128
            or HTTP_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header names must be lower-case HTTP field names"
            )
        if name in RAW_REQUEST_ADMISSION_HEADERS:
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} cannot "
                "select raw request framing or encoding"
            )
        if name not in allowed_headers or name in NON_FORWARDABLE_AGENT_HEADERS:
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} is not an allowed forwarded header"
            )
        if not isinstance(rule, dict):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} rule must be an object"
            )
        unknown = sorted(set(rule) - REQUIRED_REQUEST_HEADER_RULE_FIELDS)
        if unknown:
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} has unsupported rules: {', '.join(unknown)}"
            )
        if rule.get("type") != "string":
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} type must be string"
            )
        minimum = rule.get("minLength")
        maximum = rule.get("maxLength")
        if (
            type(minimum) is not int
            or type(maximum) is not int
            or minimum < 1
            or maximum < minimum
            or maximum > 8192
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} must define lengths between 1 and 8192"
            )
        pattern = rule.get("pattern")
        if pattern is not None and (
            not isinstance(pattern, str)
            or parse_bounded_pattern(pattern) is None
            or maximum > 4096
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} pattern must use the bounded runtime grammar"
            )
        required_headers.add(name)
    return required_headers


def _normalized_header_aliases(
    values: set[str] | frozenset[str],
) -> set[str]:
    return {str(value).strip().lower().replace("_", "-") for value in values}


def validate_discard_headers(
    route_id: str,
    request_config: Any,
    *,
    allowed_headers: set[str] | frozenset[str] = frozenset(),
    required_headers: set[str] | frozenset[str] = frozenset(),
    credential_header: str | None = None,
    principal_identity_headers: set[str] | frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    if not isinstance(request_config, dict):
        raise PolicyBundleError(f"route {route_id} request policy must be an object")
    raw = request_config.get("discardHeaders", [])
    if not isinstance(raw, list) or len(raw) > MAX_DISCARD_REQUEST_HEADERS:
        raise PolicyBundleError(
            f"route {route_id} discardHeaders must be an array with at most "
            f"{MAX_DISCARD_REQUEST_HEADERS} entries"
        )
    all_names_are_strings = all(isinstance(name, str) for name in raw)
    if all_names_are_strings and raw != sorted(raw):
        raise PolicyBundleError(
            f"route {route_id} discardHeaders must use strict lexicographic order"
        )

    admitted: list[str] = []
    aliases: set[str] = set()
    for name in raw:
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or name != name.lower()
            or "_" in name
            or HTTP_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise PolicyBundleError(
                f"route {route_id} discardHeaders must contain lower-case canonical HTTP field names"
            )
        alias = name.replace("_", "-")
        if name in admitted or alias in aliases:
            raise PolicyBundleError(
                f"route {route_id} discardHeaders must be unique including underscore aliases"
            )
        if name != "npm-session" and (
            alias in RESERVED_DISCARD_REQUEST_HEADERS
            or any(
                alias.startswith(prefix)
                for prefix in RESERVED_DISCARD_REQUEST_HEADER_PREFIXES
            )
            or any(
                alias.endswith(suffix)
                for suffix in RESERVED_DISCARD_REQUEST_HEADER_SUFFIXES
            )
        ):
            raise PolicyBundleError(
                f"route {route_id} discardHeaders contains reserved header {name}"
            )
        admitted.append(name)
        aliases.add(alias)

    collisions = aliases.intersection(_normalized_header_aliases(allowed_headers))
    if collisions:
        raise PolicyBundleError(
            f"route {route_id} discardHeaders overlaps allowedHeaders: {sorted(collisions)}"
        )
    collisions = aliases.intersection(_normalized_header_aliases(required_headers))
    if collisions:
        raise PolicyBundleError(
            f"route {route_id} discardHeaders overlaps requiredHeaders: {sorted(collisions)}"
        )
    collisions = aliases.intersection(
        _normalized_header_aliases(principal_identity_headers)
    )
    if collisions:
        raise PolicyBundleError(
            f"route {route_id} discardHeaders overlaps principal identity headers: "
            f"{sorted(collisions)}"
        )
    if (
        credential_header is not None
        and credential_header.strip().lower().replace("_", "-") in aliases
    ):
        raise PolicyBundleError(
            f"route {route_id} discardHeaders overlaps the credential injection header"
        )
    return tuple(admitted)


@dataclass(frozen=True)
class ProxyAuthorizationPolicy:
    scheme: str = "Bearer"
    token_sha256: str | None = None
    source_cidrs: tuple[str, ...] = ()
    expires_at_epoch_ms: int | None = None
    legacy_exact: str | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=True) for cidr in self.source_cidrs)

    def matches(self, client_ip: str | None, raw_header: str | None) -> bool:
        if not isinstance(raw_header, str) or not raw_header:
            return False
        if self.legacy_exact is not None:
            return hmac.compare_digest(
                raw_header.encode("utf-8"),
                self.legacy_exact.encode("utf-8"),
            )
        if self.expires_at_epoch_ms is not None and int(time.time() * 1000) >= self.expires_at_epoch_ms:
            return False
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except (TypeError, ValueError):
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
        allowed_fields = {
            "scheme",
            "tokenId",
            "tokenSha256",
            "sourceCidrs",
            "expiresAtEpochMs",
        }
        if (
            set(raw) - allowed_fields
            or not {"scheme", "tokenSha256"}.issubset(raw)
        ):
            raise PolicyBundleError(
                "principal proxyAuthorization has unsupported or missing fields"
            )
        source_cidrs = tuple(
            _canonical_cidr(
                cidr,
                "principal proxyAuthorization sourceCidrs entry",
            )
            for cidr in (raw.get("sourceCidrs") or ())
        )
        token_id = raw.get("tokenId")
        token_sha256 = raw.get("tokenSha256")
        expires_at_epoch_ms = raw.get("expiresAtEpochMs")
        if (
            raw.get("scheme") != "Bearer"
            or (
                token_id is not None
                and (
                    not isinstance(token_id, str)
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", token_id
                    )
                    is None
                )
            )
            or not isinstance(token_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", token_sha256) is None
            or (
                expires_at_epoch_ms is not None
                and (
                    not isinstance(expires_at_epoch_ms, int)
                    or isinstance(expires_at_epoch_ms, bool)
                    or expires_at_epoch_ms <= 0
                )
            )
            or len(source_cidrs) != len(set(source_cidrs))
        ):
            raise PolicyBundleError(
                "principal proxyAuthorization contract is invalid"
            )
        return cls(
            scheme="Bearer",
            token_sha256=token_sha256,
            source_cidrs=source_cidrs,
            expires_at_epoch_ms=expires_at_epoch_ms,
        )


def _normalize_identity_headers(headers: Any) -> dict[str, str] | None:
    if headers is None:
        return {}
    physical_fields = getattr(headers, "fields", None)
    if isinstance(physical_fields, (list, tuple)):
        items = physical_fields
    else:
        item_source = getattr(headers, "multi_items", None)
        if not callable(item_source):
            item_source = getattr(headers, "items", None)
        if not callable(item_source):
            return None
        try:
            items = item_source()
        except Exception:
            return None
    normalized: dict[str, str] = {}
    try:
        for index, (name, value) in enumerate(items):
            if index >= 256:
                return None
            if isinstance(name, bytes):
                name = name.decode("ascii")
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            if (
                not isinstance(name, str)
                or not name
                or "_" in name
                or len(name) > 128
                or HTTP_HEADER_NAME_RE.fullmatch(name) is None
                or not isinstance(value, str)
                or len(value.encode("utf-8")) > 8192
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in value
                )
            ):
                return None
            lower_name = name.lower()
            if lower_name in normalized:
                return None
            normalized[lower_name] = value
    except Exception:
        return None
    return normalized


def _header_value(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


_RUNTIME_MTLS_FIELDS = frozenset(
    {
        "verified",
        "san_spiffe_ids",
        "san_dns_names",
        "san_uris",
        "certificate_sha256",
        "spki_sha256",
        "issuer_spki_sha256",
    }
)
_RUNTIME_MTLS_URI_RE = re.compile(
    r"^[a-z][a-z0-9+.-]*:[^\s\x00-\x1f\x7f]{1,2040}$"
)


def _normalize_runtime_mtls_evidence(
    evidence: Any,
) -> tuple[bool, dict[str, Any] | None]:
    if evidence is None:
        return True, None
    if (
        not isinstance(evidence, dict)
        or set(evidence) - _RUNTIME_MTLS_FIELDS
        or evidence.get("verified") is not True
    ):
        return False, None
    normalized: dict[str, Any] = {"verified": True}
    for field_name, pattern, maximum_bytes in (
        ("san_spiffe_ids", SPIFFE_ID_RE, 2048),
        ("san_dns_names", DNS_SAN_RE, 253),
        ("san_uris", _RUNTIME_MTLS_URI_RE, 2048),
    ):
        if field_name not in evidence:
            continue
        values = evidence[field_name]
        if (
            not isinstance(values, (list, tuple))
            or len(values) > 32
            or any(
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or len(value.encode("utf-8")) > maximum_bytes
                or pattern.fullmatch(value) is None
                for value in values
            )
            or len(values) != len(set(values))
        ):
            return False, None
        normalized[field_name] = tuple(values)
    for field_name in (
        "certificate_sha256",
        "spki_sha256",
        "issuer_spki_sha256",
    ):
        if field_name not in evidence:
            continue
        value = evidence[field_name]
        if not isinstance(value, str) or SHA256_IDENTITY_RE.fullmatch(value) is None:
            return False, None
        normalized[field_name] = value
    return True, normalized


@dataclass(frozen=True)
class MTLSIdentityPolicy:
    san_spiffe_ids: tuple[str, ...] = ()
    san_dns_names: tuple[str, ...] = ()
    san_uris: tuple[str, ...] = ()
    certificate_sha256: tuple[str, ...] = ()
    spki_sha256: tuple[str, ...] = ()
    issuer_spki_sha256: tuple[str, ...] = ()

    def matches(self, evidence: dict[str, Any] | None) -> bool:
        if evidence is None or evidence.get("verified") is not True:
            return False
        expected = {
            "san_spiffe_ids": self.san_spiffe_ids,
            "san_dns_names": self.san_dns_names,
            "san_uris": self.san_uris,
            "certificate_sha256": self.certificate_sha256,
            "spki_sha256": self.spki_sha256,
            "issuer_spki_sha256": self.issuer_spki_sha256,
        }
        for field_name, allowed in expected.items():
            if not allowed:
                continue
            actual = evidence.get(field_name)
            if field_name.endswith("_sha256"):
                if not isinstance(actual, str) or actual not in allowed:
                    return False
                continue
            if (
                not isinstance(actual, (list, tuple))
                or not actual
                or any(not isinstance(value, str) for value in actual)
                or not set(actual).intersection(allowed)
            ):
                return False
        return True


@dataclass(frozen=True)
class PrincipalPolicy:
    id: str
    source_cidrs: tuple[str, ...] = ()
    required_headers: dict[str, str] = field(default_factory=dict)
    proxy_authorization: ProxyAuthorizationPolicy | None = None
    mtls: MTLSIdentityPolicy | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=True) for cidr in self.source_cidrs)

    def matches(
        self,
        client_ip: str | None,
        headers: dict[str, str],
        mtls_evidence: dict[str, Any] | None = None,
    ) -> bool:
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except (TypeError, ValueError):
                return False
            if not any(ip in network for network in self.networks):
                return False

        for name, expected in self.required_headers.items():
            if _header_value(headers, name) != expected:
                return False

        if self.mtls is not None and not self.mtls.matches(mtls_evidence):
            return False

        if self.proxy_authorization and not self.proxy_authorization.matches(client_ip, _header_value(headers, "Proxy-Authorization")):
            return False

        return True


def _principal_required_headers(
    principal: PrincipalPolicy,
) -> dict[str, str] | None:
    normalized: dict[str, str] = {}
    for name, value in principal.required_headers.items():
        lower_name = name.lower()
        previous = normalized.get(lower_name)
        if previous is not None and previous != value:
            return None
        normalized[lower_name] = value
    return normalized


def _proxy_authorization_accepts_exact(
    policy: ProxyAuthorizationPolicy,
    raw_header: str,
) -> bool:
    if policy.legacy_exact is not None:
        return hmac.compare_digest(
            raw_header.encode("utf-8"),
            policy.legacy_exact.encode("utf-8"),
        )
    scheme, _, token = raw_header.strip().partition(" ")
    if not token or scheme.lower() != policy.scheme.lower():
        return False
    digest = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
    return bool(policy.token_sha256) and hmac.compare_digest(
        digest, policy.token_sha256
    )


def _proxy_authorization_policies_overlap(
    left: ProxyAuthorizationPolicy,
    right: ProxyAuthorizationPolicy,
) -> bool:
    if left.legacy_exact is not None:
        return _proxy_authorization_accepts_exact(right, left.legacy_exact)
    if right.legacy_exact is not None:
        return _proxy_authorization_accepts_exact(left, right.legacy_exact)
    return bool(left.token_sha256) and hmac.compare_digest(
        left.token_sha256, right.token_sha256 or ""
    )


def _principal_network_dimensions(
    principal: PrincipalPolicy,
) -> tuple[tuple[ipaddress._BaseNetwork, ...], ...]:
    dimensions: list[tuple[ipaddress._BaseNetwork, ...]] = []
    if principal.source_cidrs:
        dimensions.append(principal.networks)
    proxy_authorization = principal.proxy_authorization
    if (
        proxy_authorization is not None
        and proxy_authorization.legacy_exact is None
        and proxy_authorization.source_cidrs
    ):
        dimensions.append(proxy_authorization.networks)
    return tuple(dimensions)


def _network_dimensions_overlap(
    dimensions: tuple[tuple[ipaddress._BaseNetwork, ...], ...],
) -> bool:
    if not dimensions:
        return True
    candidates = [network for dimension in dimensions for network in dimension]
    return any(
        all(
            any(
                candidate.version == network.version
                and candidate.subnet_of(network)
                for network in dimension
            )
            for dimension in dimensions
        )
        for candidate in candidates
    )


def _principal_selectors_overlap(
    left: PrincipalPolicy,
    right: PrincipalPolicy,
) -> bool:
    left_headers = _principal_required_headers(left)
    right_headers = _principal_required_headers(right)
    if left_headers is None or right_headers is None:
        return False
    for name in set(left_headers).intersection(right_headers):
        if left_headers[name] != right_headers[name]:
            return False

    proxy_exact_values = {
        headers["proxy-authorization"]
        for headers in (left_headers, right_headers)
        if "proxy-authorization" in headers
    }
    if len(proxy_exact_values) > 1:
        return False
    proxy_policies = [
        principal.proxy_authorization
        for principal in (left, right)
        if principal.proxy_authorization is not None
    ]
    if proxy_exact_values:
        exact_value = next(iter(proxy_exact_values))
        if any(
            not _proxy_authorization_accepts_exact(policy, exact_value)
            for policy in proxy_policies
        ):
            return False
    elif len(proxy_policies) == 2 and not _proxy_authorization_policies_overlap(
        proxy_policies[0], proxy_policies[1]
    ):
        return False

    network_dimensions = (
        _principal_network_dimensions(left)
        + _principal_network_dimensions(right)
    )
    if not _network_dimensions_overlap(network_dimensions):
        return False

    if left.mtls is not None and right.mtls is not None:
        for field_name in (
            "certificate_sha256",
            "spki_sha256",
            "issuer_spki_sha256",
        ):
            left_values = getattr(left.mtls, field_name)
            right_values = getattr(right.mtls, field_name)
            if (
                left_values
                and right_values
                and not set(left_values).intersection(right_values)
            ):
                return False
    return True


@dataclass(frozen=True)
class CredentialPolicy:
    id: str
    kind: str = "static"
    provider: str = "generic"
    provider_subject: str | None = None
    oauth_client_id: str | None = None
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
    resolved_cidrs: tuple[str, ...] | None = None
    constraints: tuple[dict[str, Any], ...] = ()
    jit: dict[str, Any] = field(default_factory=dict)

    def match_path(self, path: str) -> dict[str, str] | None:
        candidate = self.match_path_with_specificity(path)
        return candidate[0] if candidate else None

    def match_path_with_specificity(self, path: str) -> tuple[dict[str, str], tuple[int, ...]] | None:
        matches: list[tuple[dict[str, str], tuple[int, ...]]] = []
        for template, regex in zip(self.path_templates, self.path_regexes, strict=True):
            match = regex.match(path)
            if match:
                matches.append((match.groupdict(), _path_specificity(template)))
        return max(matches, key=lambda item: item[1]) if matches else None


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
    compiled_route_authority: Any = None

    def identify_principal(
        self, client_ip: str | None, headers: Any, mtls_evidence: Any = None
    ) -> PrincipalPolicy | None:
        normalized_headers = _normalize_identity_headers(headers)
        mtls_valid, normalized_mtls = _normalize_runtime_mtls_evidence(
            mtls_evidence
        )
        if normalized_headers is None or not mtls_valid:
            return None
        matches = [
            principal
            for principal in self.principals.values()
            if principal.matches(
                client_ip,
                normalized_headers,
                normalized_mtls,
            )
        ]
        return matches[0] if len(matches) == 1 else None

    def match_route(self, scheme: str, host: str, port: int, method: str, path: str, principal_id: str) -> RouteMatch | None:
        normalized_host = host.lower().rstrip(".")
        normalized_method = method.upper()
        matches: list[tuple[tuple[int, ...], RoutePolicy, dict[str, str]]] = []
        for route in self.routes:
            if route.scheme != scheme.lower():
                continue
            if route.host != normalized_host:
                continue
            if route.port != port:
                continue
            if principal_id not in route.principals and "*" not in route.principals:
                continue
            path_match = route.match_path_with_specificity(path)
            if path_match is None:
                continue
            if normalized_method not in route.methods:
                continue
            params, specificity = path_match
            matches.append((specificity, route, params))
        if not matches:
            return None
        best_specificity = max(item[0] for item in matches)
        best = [item for item in matches if item[0] == best_specificity]
        if len(best) != 1:
            return None
        _, route, params = best[0]
        return RouteMatch(route=route, params=params)


def _fresh_policy_snapshot(snapshot: PolicySnapshot) -> PolicySnapshot:
    principals = FrozenDict(
        {
            principal_id: PrincipalPolicy(
                id=principal.id,
                source_cidrs=principal.source_cidrs,
                required_headers=_deep_freeze(
                    copy.deepcopy(principal.required_headers)
                ),
                proxy_authorization=principal.proxy_authorization,
                mtls=principal.mtls,
            )
            for principal_id, principal in snapshot.principals.items()
        }
    )
    credentials = FrozenDict(
        {
            credential_id: CredentialPolicy(
                id=credential.id,
                kind=credential.kind,
                provider=credential.provider,
                provider_subject=credential.provider_subject,
                oauth_client_id=credential.oauth_client_id,
                scopes=credential.scopes,
                injection=_deep_freeze(copy.deepcopy(credential.injection)),
            )
            for credential_id, credential in snapshot.credentials.items()
        }
    )
    routes = tuple(
        RoutePolicy(
            id=route.id,
            principals=route.principals,
            host=route.host,
            port=route.port,
            scheme=route.scheme,
            methods=route.methods,
            path_templates=route.path_templates,
            path_regexes=route.path_regexes,
            credential_ref=route.credential_ref,
            adapter_type=route.adapter_type,
            adapter_config=_deep_freeze(copy.deepcopy(route.adapter_config)),
            resolved_cidrs=route.resolved_cidrs,
            constraints=tuple(
                _deep_freeze(copy.deepcopy(constraint))
                for constraint in route.constraints
            ),
            jit=_deep_freeze(copy.deepcopy(route.jit)),
        )
        for route in snapshot.routes
    )
    return PolicySnapshot(
        raw=_deep_freeze(copy.deepcopy(snapshot.raw)),
        hash=snapshot.hash,
        principals=principals,
        credentials=credentials,
        routes=routes,
        compiled_route_authority=snapshot.compiled_route_authority,
    )


@dataclass(frozen=True)
class PolicyFileIdentity:
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    file_sha256: str

    @property
    def stat_components(self) -> tuple[int, ...]:
        return (
            self.device,
            self.inode,
            self.owner_uid,
            self.owner_gid,
            self.mode,
            self.nlink,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
        )


PolicySnapshotCache = tuple[
    PolicyFileIdentity | None,
    PolicySnapshot | None,
    PolicySigningTrustIdentity | None,
]
_SNAPSHOT_CACHE: PolicySnapshotCache | None = (None, None, None)
_SNAPSHOT_CACHE_LOCK = threading.RLock()
_POLICY_PUBLICATION_THREAD_LOCK = threading.RLock()
_POLICY_PUBLICATION_LOCK_STATE = threading.local()
_PRODUCTION_POLICY_PUBLICATION_LOCK_PATH = POLICY_BUNDLE_PATH.parent
POLICY_PUBLICATION_LOCK_TRUST_BOUNDARY = (
    "Production locks the pre-existing active-policy directory inode through an "
    "O_RDONLY descriptor. Its service-owned mutation leaf cannot be renamed "
    "because every ancestor is root-owned and non-group/world-writable; shared "
    "policy-volume mounts therefore share one lock inode. Root, mount-namespace, "
    "or deployment control-plane replacement remains outside this boundary."
)


def _policy_publication_lock_path() -> Path:
    if _policy_path_protections_are_production():
        return _PRODUCTION_POLICY_PUBLICATION_LOCK_PATH
    return Path(str(POLICY_BUNDLE_PATH) + ".publish.lock")


@contextmanager
def _policy_publication_lock():
    production = _policy_path_protections_are_production()
    with _exclusive_secure_file_lock(
        _policy_publication_lock_path(),
        label="policy publication lock",
        thread_lock=_POLICY_PUBLICATION_THREAD_LOCK,
        state=_POLICY_PUBLICATION_LOCK_STATE,
        trusted_lock_namespace=production,
        directory_lock=production,
    ):
        yield


def _policy_publication_lock_held() -> bool:
    return int(getattr(_POLICY_PUBLICATION_LOCK_STATE, "depth", 0)) > 0


def _policy_file_stat_components(file_stat: os.stat_result) -> tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_uid,
        file_stat.st_gid,
        file_stat.st_mode,
        file_stat.st_nlink,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _validate_policy_file_stat(file_stat: os.stat_result) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise PolicyBundleError(
            "policy bundle must be a non-symlink regular file"
        )
    if file_stat.st_uid != os.geteuid():
        raise PolicyBundleError(
            "policy bundle must be owned by the service effective user"
        )
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise PolicyBundleError("policy bundle must use mode 0600")
    if file_stat.st_nlink != 1:
        raise PolicyBundleError("policy bundle must not be hardlinked")
    if not 1 <= file_stat.st_size <= MAX_POLICY_BUNDLE_BYTES:
        raise PolicyBundleError(
            f"policy bundle must contain 1-{MAX_POLICY_BUNDLE_BYTES} bytes"
        )


def _read_stable_policy_file(
    path: Path,
) -> tuple[bytes, PolicyFileIdentity]:
    payload, identity = _read_stable_secure_file(
        path,
        label="policy bundle",
        expected_mode=0o600,
        maximum_size=MAX_POLICY_BUNDLE_BYTES,
    )
    return payload, PolicyFileIdentity(
        device=identity.device,
        inode=identity.inode,
        owner_uid=identity.owner_uid,
        owner_gid=identity.owner_gid,
        mode=identity.mode,
        nlink=identity.nlink,
        size=identity.size,
        mtime_ns=identity.mtime_ns,
        ctime_ns=identity.ctime_ns,
        file_sha256=identity.file_sha256,
    )


def _recheck_policy_path_identity(
    path: Path,
    expected: PolicyFileIdentity,
) -> None:
    _, basename, parent_descriptor, parent_identity = (
        _open_secure_parent_directory(path, label="policy bundle")
    )
    try:
        current = os.stat(
            basename,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        os.close(parent_descriptor)
        raise PolicyBundleError(
            "policy bundle changed after verification"
        ) from exc
    try:
        _validate_policy_file_stat(current)
        if _policy_file_stat_components(current) != expected.stat_components:
            raise PolicyBundleError("policy bundle changed after verification")
    finally:
        os.close(parent_descriptor)
    _recheck_secure_parent_directory(
        path,
        label="policy bundle",
        expected=parent_identity,
    )


def _recheck_policy_signing_trust(
    expected: PolicySigningTrustIdentity,
) -> None:
    if _load_policy_signing_trust().identity != expected:
        raise PolicyBundleError(
            "policy signing trust changed during verification"
        )


def _decode_raw_policy(path: Path, payload: bytes) -> dict[str, Any]:
    text = payload.decode("utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            from ruamel.yaml import YAML
        except Exception as exc:
            raise PolicyBundleError("YAML policy bundles require ruamel.yaml") from exc
        loaded = YAML(typ="safe").load(text)
    else:
        loaded = strict_json_loads(text)
    if not isinstance(loaded, dict):
        raise PolicyBundleError("policy bundle must be an object")
    return loaded


def _require_policy_file_publication_settled(path, *, identity=None):
    if Path(path) != POLICY_BUNDLE_PATH:
        return  # Independently selected non-active diagnostic loaders are unchanged.
    try:
        from serverware.control_plane_policy_file_publication import require_loadable
        require_loadable(path, expected_identity=identity)
    except Exception:
        raise PolicyBundleError("active policy publication is unresolved or unavailable") from None


class PolicyBundleLoader:
    def __init__(self, path: Path):
        self.path = path
        self.cache: PolicySnapshotCache | None = None

    def load(self) -> PolicySnapshot | None:
        return self._load_locked()

    def _load_locked(self) -> PolicySnapshot | None:
        try:
            _require_policy_file_publication_settled(self.path)
            path_stat = _read_secure_file_stat(
                self.path,
                label="policy bundle",
                expected_mode=0o600,
                maximum_size=MAX_POLICY_BUNDLE_BYTES,
            )
        except PolicyBundleError:
            try:
                missing = not _secure_path_exists(
                    self.path,
                    label="policy bundle",
                )
            except PolicyBundleError:
                missing = False
            if missing:
                self.cache = (None, None, None)
                return None
            self.cache = None
            return None

        cached_identity: PolicyFileIdentity | None = None
        cached_snapshot: PolicySnapshot | None = None
        cached_trust_identity: PolicySigningTrustIdentity | None = None
        if isinstance(self.cache, tuple) and len(self.cache) == 3:
            cached_identity, cached_snapshot, cached_trust_identity = self.cache
        try:
            current_trust = _load_policy_signing_trust()
        except PolicyBundleError:
            self.cache = None
            return None
        if (
            isinstance(cached_identity, PolicyFileIdentity)
            and cached_snapshot is not None
            and cached_trust_identity == current_trust.identity
            and cached_identity.stat_components
            == _policy_file_stat_components(path_stat)
        ):
            try:
                verify_policy_high_water(cached_snapshot)
                _recheck_policy_path_identity(self.path, cached_identity)
                _recheck_policy_signing_trust(cached_trust_identity)
                verify_policy_high_water(cached_snapshot)
                _require_policy_file_publication_settled(self.path, identity=cached_identity)
            except PolicyBundleError:
                self.cache = None
                return None
            return _fresh_policy_snapshot(cached_snapshot)

        try:
            payload, identity = _read_stable_policy_file(self.path)
            signing_trust = _load_policy_signing_trust()
            snapshot = compile_policy_bundle(
                _decode_raw_policy(self.path, payload),
                verify_signature=True,
                validate_schema=True,
                signing_trust=signing_trust,
            )
            verify_policy_high_water(snapshot)
            _recheck_policy_path_identity(self.path, identity)
            _recheck_policy_signing_trust(signing_trust.identity)
            verify_policy_high_water(snapshot)
            _require_policy_file_publication_settled(self.path, identity=identity)
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            PolicyBundleError,
        ):
            self.cache = None
            return None
        self.cache = (identity, snapshot, signing_trust.identity)
        return _fresh_policy_snapshot(snapshot)


_POLICY_BUNDLE_LOADER = PolicyBundleLoader(POLICY_BUNDLE_PATH)


def _parse_policy_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_clock_minutes(value: Any) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value) is None:
        return None
    hour, minute = value.split(":", 1)
    return int(hour) * 60 + int(minute)


def _validate_request_value_predicate(
    route_id: str,
    constraint_id: str,
    rule_index: int,
    predicate: Any,
) -> str:
    label = f"route {route_id} requestValue {constraint_id} rule {rule_index}"
    if not isinstance(predicate, dict):
        raise PolicyBundleError(f"{label} predicate must be an object")
    kind = predicate.get("kind")
    fields_by_kind = {
        "equals": {"kind", "value"},
        "enum": {"kind", "values"},
        "pattern": {"kind", "pattern", "maxLength"},
        "stringLength": {"kind", "minLength", "maxLength"},
        "numeric": {"kind", "min", "max", "integer"},
    }
    allowed = fields_by_kind.get(kind)
    if allowed is None:
        raise PolicyBundleError(f"{label} has unsupported predicate kind {kind}")
    unknown = sorted(set(predicate) - allowed)
    if unknown:
        raise PolicyBundleError(f"{label} predicate has unsupported fields: {', '.join(unknown)}")

    if kind == "equals":
        value = predicate.get("value")
        if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
            raise PolicyBundleError(f"{label} equals value must be a string of at most 4096 bytes")
    elif kind == "enum":
        values = predicate.get("values")
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 32
            or any(not isinstance(value, str) or len(value.encode("utf-8")) > 4096 for value in values)
            or len(values) != len(set(values))
        ):
            raise PolicyBundleError(f"{label} enum must contain 1-32 unique strings of at most 4096 bytes")
    elif kind == "pattern":
        pattern = predicate.get("pattern")
        maximum = predicate.get("maxLength")
        if (
            not isinstance(pattern, str)
            or parse_bounded_pattern(pattern) is None
            or type(maximum) is not int
            or not 1 <= maximum <= 4096
        ):
            raise PolicyBundleError(
                f"{label} pattern must use the anchored bounded runtime grammar with maxLength 1-4096"
            )
    elif kind == "stringLength":
        minimum = predicate.get("minLength")
        maximum = predicate.get("maxLength")
        if minimum is None and maximum is None:
            raise PolicyBundleError(f"{label} stringLength must define minLength or maxLength")
        if any(
            value is not None and (type(value) is not int or not 0 <= value <= 4096)
            for value in (minimum, maximum)
        ) or (minimum is not None and maximum is not None and minimum > maximum):
            raise PolicyBundleError(f"{label} has invalid stringLength bounds")
    else:
        minimum = predicate.get("min")
        maximum = predicate.get("max")
        if minimum is None and maximum is None:
            raise PolicyBundleError(f"{label} numeric predicate must define min or max")
        if any(value is not None and not _is_finite_json_number(value) for value in (minimum, maximum)):
            raise PolicyBundleError(f"{label} numeric bounds must be finite numbers")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise PolicyBundleError(f"{label} numeric min must not exceed max")
        if "integer" in predicate and not isinstance(predicate["integer"], bool):
            raise PolicyBundleError(f"{label} numeric integer must be boolean")
        if predicate.get("integer") is True and any(
            value is not None
            and (type(value) is not int or not -(2**63) <= value <= 2**63 - 1)
            for value in (minimum, maximum)
        ):
            raise PolicyBundleError(
                f"{label} integer numeric bounds must be signed 64-bit integers"
            )
    return str(kind)


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
        irrelevant_fields = sorted(set(constraint) - CONSTRAINT_COMMON_FIELDS - CONSTRAINT_TYPE_FIELDS[constraint_type])
        if irrelevant_fields:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} type {constraint_type} has unsupported fields: "
                f"{', '.join(irrelevant_fields)}"
            )
        phase = constraint.get("phase", "request")
        expected_phase = (
            "request" if constraint_type in REQUEST_CONSTRAINTS else "response"
        )
        if constraint_type != "traversalBudget" and phase != expected_phase:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} type {constraint_type} "
                f"must use phase {expected_phase}"
            )
        if constraint_type == "traversalBudget" and "phase" in constraint:
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} has fixed "
                "request-and-response phases and cannot declare phase"
            )
        store = constraint.get("store", "local")
        if store not in {"local", "shared"}:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has invalid store {store}")
        if constraint.get("operations") is not None and constraint_type not in {
            "responseDateWindow",
            "responseJson",
            "responseBinding",
            "responseEnvelope",
            "traversalBudget",
        }:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} operations are supported only for response constraints"
            )
        if constraint_type == "rateLimit":
            max_count = constraint.get("max")
            window_seconds = constraint.get("windowSeconds")
            calendar_window = constraint.get("calendarWindow")
            if not isinstance(max_count, int) or isinstance(max_count, bool) or not 1 <= max_count <= 1_000_000_000:
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must define integer max between 1 and 1000000000"
                )
            if (window_seconds is None) == (calendar_window is None):
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must define exactly one of windowSeconds or calendarWindow"
                )
            if window_seconds is not None and (
                not isinstance(window_seconds, int)
                or isinstance(window_seconds, bool)
                or not 1 <= window_seconds <= 31_536_000
            ):
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must define windowSeconds between 1 and 31536000"
                )
            if calendar_window is not None:
                if calendar_window not in {"utcDay", "utcIsoWeek", "utcMonth"}:
                    raise PolicyBundleError(
                        f"route {route_id} rateLimit {constraint_id} has invalid calendarWindow"
                    )
                if store != "shared":
                    raise PolicyBundleError(
                        f"route {route_id} rateLimit {constraint_id} calendarWindow requires store shared"
                    )
            expected_semantics = (
                "calendarUTC"
                if calendar_window is not None
                else "fixedFromFirstUse"
            )
            if constraint.get("windowSemantics") != expected_semantics:
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must use "
                    f"windowSemantics {expected_semantics}"
                )
            raw_key_policy = constraint.get("key")
            if raw_key_policy is not None and not isinstance(raw_key_policy, dict):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} key must be an object")
            key_policy = raw_key_policy or {}
            scope = key_policy.get("scope") or ["principal", "credential", "route", "operation"]
            allowed_scope = {"principal", "credential", "credentialVersion", "route", "operation"}
            if not isinstance(scope, list) or not scope or any(
                not isinstance(item, str) or item not in allowed_scope for item in scope
            ):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} has unsupported key scope")
            operation_fields = key_policy.get("operationFields") or []
            if not isinstance(operation_fields, list) or any(
                not isinstance(field, str)
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", field) is None
                for field in operation_fields
            ):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} has invalid operationFields")
        elif constraint_type in {"slidingWindowLimit", "weightedBudget"}:
            if store != "shared":
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} requires store shared"
                )
            window_seconds = constraint.get("windowSeconds")
            maximum = constraint.get("max")
            if (
                type(window_seconds) is not int
                or not 1 <= window_seconds <= 31_536_000
                or type(maximum) is not int
                or not 1
                <= maximum
                <= (
                    9_007_199_254_740_991
                    if constraint_type == "weightedBudget"
                    else 1_000_000_000
                )
                or constraint.get("windowSemantics") != "sliding"
                or constraint.get("measure")
                != (
                    "weightedCanonicalInteger"
                    if constraint_type == "weightedBudget"
                    else "operationCount"
                )
                or constraint.get("reservationMode")
                != "atomicReserveCommitRelease"
                or constraint.get("onOverflow") != "deny"
                or "calendarWindow" in constraint
            ):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} "
                    "has invalid sliding-window bounds or reservation semantics"
                )
            weight = constraint.get("weight")
            if constraint_type == "weightedBudget":
                if (
                    not isinstance(weight, dict)
                    or set(weight)
                    != {
                        "source",
                        "field",
                        "representation",
                        "unit",
                        "minimumPerOperation",
                        "maximumPerOperation",
                    }
                    or weight.get("source")
                    not in {"requestValue", "operationField"}
                    or not isinstance(weight.get("field"), str)
                    or RESPONSE_FIELD_PATH_RE.fullmatch(weight["field"]) is None
                    or weight.get("representation")
                    != "canonicalNonNegativeInteger"
                    or not isinstance(weight.get("unit"), str)
                    or re.fullmatch(
                        r"[a-z][a-z0-9._-]{0,31}", weight["unit"]
                    )
                    is None
                    or type(weight.get("minimumPerOperation")) is not int
                    or type(weight.get("maximumPerOperation")) is not int
                    or not 0
                    <= weight["minimumPerOperation"]
                    <= weight["maximumPerOperation"]
                    <= 9_007_199_254_740_991
                    or weight["maximumPerOperation"] < 1
                ):
                    raise PolicyBundleError(
                        f"route {route_id} weightedBudget {constraint_id} "
                        "weight is invalid"
                    )
            elif weight is not None:
                raise PolicyBundleError(
                    f"route {route_id} slidingWindowLimit {constraint_id} "
                    "cannot declare weight"
                )
            raw_key_policy = constraint.get("key")
            if not isinstance(raw_key_policy, dict):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} "
                    "key must be an object"
                )
            key_policy = raw_key_policy
            scope = key_policy.get("scope")
            allowed_scope = {
                "principal",
                "credential",
                "credentialVersion",
                "route",
                "operation",
            }
            if (
                not isinstance(scope, list)
                or not scope
                or any(
                    not isinstance(item, str) or item not in allowed_scope
                    for item in scope
                )
                or len(scope) != len(set(scope))
            ):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} "
                    "key scope is invalid"
                )
            operation_fields = key_policy.get("operationFields") or []
            if (
                not isinstance(operation_fields, list)
                or len(operation_fields) > 16
                or any(
                    not isinstance(field, str)
                    or OPERATION_FIELD_NAME_RE.fullmatch(field) is None
                    for field in operation_fields
                )
                or len(operation_fields) != len(set(operation_fields))
            ):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} "
                    "operationFields are invalid"
                )
        elif constraint_type == "traversalBudget":
            traversal = constraint.get("traversal")
            if not isinstance(traversal, dict) or set(traversal) != {
                "store",
                "phases",
                "cursor",
                "lineage",
                "limits",
                "accounting",
                "onReplay",
                "onCrossLineage",
                "onMissingEvidence",
            }:
                raise PolicyBundleError(
                    f"route {route_id} traversalBudget {constraint_id} is invalid"
                )
            cursor = traversal.get("cursor")
            lineage = traversal.get("lineage")
            limits = traversal.get("limits")
            accounting = traversal.get("accounting")
            if (
                isinstance(cursor, dict)
                and cursor.get("requestSource") == "jsonBody"
            ):
                raise PolicyBundleError(
                    f"route {route_id} traversalBudget {constraint_id} JSON body "
                    "cursors are unsupported until request-body membership is "
                    "committed by the durable evidence wire"
                )
            if (
                traversal.get("store") != "shared"
                or traversal.get("phases") != ["request", "response"]
                or traversal.get("onReplay") != "deny"
                or traversal.get("onCrossLineage") != "deny"
                or traversal.get("onMissingEvidence") != "deny"
                or not isinstance(cursor, dict)
                or set(cursor)
                != {
                    "requestSource",
                    "requestField",
                    "responseField",
                    "digest",
                    "firstPageMayOmit",
                }
                or cursor.get("requestSource")
                not in {"query", "header"}
                or not valid_traversal_request_field(
                    cursor.get("requestSource"), cursor.get("requestField")
                )
                or not isinstance(cursor.get("responseField"), str)
                or len(cursor["responseField"]) > 256
                or RESPONSE_FIELD_PATH_RE.fullmatch(cursor["responseField"])
                is None
                or cursor.get("digest") != "sha256"
                or cursor.get("firstPageMayOmit") is not True
                or not isinstance(lineage, dict)
                or set(lineage) != {"scope", "queryFields", "queryDigest"}
                or lineage.get("scope")
                != ["principal", "route", "credential", "credentialVersion"]
                or lineage.get("queryDigest") != "sha256"
                or not isinstance(lineage.get("queryFields"), list)
                or not 1 <= len(lineage["queryFields"]) <= 32
                or any(
                    not valid_traversal_query_name(field)
                    for field in lineage["queryFields"]
                )
                or len(lineage["queryFields"])
                != len(set(lineage["queryFields"]))
                or (
                    cursor.get("requestSource") == "query"
                    and cursor.get("requestField")
                    in lineage["queryFields"]
                )
                or not isinstance(limits, dict)
                or set(limits)
                != {
                    "maxPages",
                    "maxLifetimeSeconds",
                    "maxRecords",
                    "maxDecodedBytes",
                }
                or type(limits.get("maxPages")) is not int
                or not 1 <= limits["maxPages"] <= 10_000
                or type(limits.get("maxLifetimeSeconds")) is not int
                or not 1 <= limits["maxLifetimeSeconds"] <= 86_400
                or type(limits.get("maxRecords")) is not int
                or not 1 <= limits["maxRecords"] <= 10_000_000
                or type(limits.get("maxDecodedBytes")) is not int
                or not 1 <= limits["maxDecodedBytes"] <= 1_073_741_824
                or not isinstance(accounting, dict)
                or set(accounting)
                != {"recordCountField", "byteSource", "commit"}
                or not isinstance(accounting.get("recordCountField"), str)
                or len(accounting["recordCountField"]) > 256
                or RESPONSE_FIELD_PATH_RE.fullmatch(
                    accounting["recordCountField"]
                )
                is None
                or accounting.get("byteSource")
                != "validatedDecodedResponseBytes"
                or accounting.get("commit")
                != "atomicAfterResponseValidation"
            ):
                raise PolicyBundleError(
                    f"route {route_id} traversalBudget {constraint_id} "
                    "has an invalid closed traversal contract"
                )
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
            if constraint_type == "queryDateWindow" and not constraint.get("formats"):
                raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} must define formats")
            if constraint_type == "queryDateWindow":
                formats = constraint.get("formats")
                allowed_formats = {"rfc3339", "date", "epochSeconds", "epochMillis"}
                if (
                    not isinstance(formats, list)
                    or any(not isinstance(item, str) or item not in allowed_formats for item in formats)
                    or len(formats) != len(set(formats))
                ):
                    raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} has invalid formats")
                if not isinstance(constraint.get("required"), bool):
                    raise PolicyBundleError(
                        f"route {route_id} queryDateWindow {constraint_id} "
                        "must explicitly declare required"
                    )
            if constraint_type == "queryNumericBounds":
                minimum = constraint.get("min")
                maximum = constraint.get("max")
                if minimum is None and maximum is None:
                    raise PolicyBundleError(
                        f"route {route_id} queryNumericBounds {constraint_id} must define min or max"
                    )
                for name, value in (("min", minimum), ("max", maximum)):
                    if value is not None and (
                        not _is_finite_json_number(value)
                    ):
                        raise PolicyBundleError(
                            f"route {route_id} queryNumericBounds {constraint_id} {name} must be a finite number"
                        )
                if minimum is not None and maximum is not None and minimum > maximum:
                    raise PolicyBundleError(
                        f"route {route_id} queryNumericBounds {constraint_id} min must not exceed max"
                    )
        elif constraint_type == "requestTimeWindow":
            if constraint.get("timezone") != "UTC":
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} must use timezone UTC"
                )
            if not any(constraint.get(field) for field in ("notBefore", "notAfter", "weekdays", "dailyWindows")):
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} must define at least one bound"
                )
            not_before = (
                _parse_policy_timestamp(constraint.get("notBefore")) if constraint.get("notBefore") is not None else None
            )
            not_after = (
                _parse_policy_timestamp(constraint.get("notAfter")) if constraint.get("notAfter") is not None else None
            )
            if constraint.get("notBefore") is not None and not_before is None:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notBefore must be RFC3339"
                )
            if constraint.get("notAfter") is not None and not_after is None:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notAfter must be RFC3339"
                )
            if not_before is not None and not_after is not None and not_before >= not_after:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notBefore must precede notAfter"
                )
            weekdays = constraint.get("weekdays")
            allowed_weekdays = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
            if weekdays is not None and (
                not isinstance(weekdays, list)
                or not weekdays
                or any(not isinstance(day, str) or day not in allowed_weekdays for day in weekdays)
                or len(weekdays) != len(set(weekdays))
            ):
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} has invalid weekdays"
                )
            daily_windows = constraint.get("dailyWindows")
            if daily_windows is not None:
                if not isinstance(daily_windows, list) or not daily_windows:
                    raise PolicyBundleError(
                        f"route {route_id} requestTimeWindow {constraint_id} has invalid dailyWindows"
                    )
                intervals: list[tuple[int, int]] = []
                for window in daily_windows:
                    if not isinstance(window, dict) or set(window) != {"start", "end"}:
                        raise PolicyBundleError(
                            f"route {route_id} requestTimeWindow {constraint_id} has invalid daily window"
                        )
                    start = _parse_clock_minutes(window.get("start"))
                    end = _parse_clock_minutes(window.get("end"))
                    if start is None or end is None or start >= end:
                        raise PolicyBundleError(
                            f"route {route_id} requestTimeWindow {constraint_id} daily windows must be increasing UTC times"
                        )
                    intervals.append((start, end))
                intervals.sort()
                if any(start < previous_end for (_, previous_end), (start, _) in zip(intervals, intervals[1:])):
                    raise PolicyBundleError(
                        f"route {route_id} requestTimeWindow {constraint_id} daily windows must not overlap"
                    )
        elif constraint_type == "requestValue":
            rules = constraint.get("rules")
            if not isinstance(rules, list) or not 1 <= len(rules) <= 16:
                raise PolicyBundleError(
                    f"route {route_id} requestValue {constraint_id} must define 1-16 rules"
                )
            seen_sources: set[tuple[str, str]] = set()
            seen_captures: set[str] = set()
            for rule_index, rule in enumerate(rules):
                label = f"route {route_id} requestValue {constraint_id} rule {rule_index}"
                if not isinstance(rule, dict) or not {"source", "name", "predicate"}.issubset(rule):
                    raise PolicyBundleError(f"{label} must define source, name, and predicate")
                unknown = sorted(set(rule) - {"source", "name", "predicate", "capture"})
                if unknown:
                    raise PolicyBundleError(f"{label} has unsupported fields: {', '.join(unknown)}")
                source = rule.get("source")
                name = rule.get("name")
                if source not in {
                    "pathParam",
                    "query",
                    "header",
                    "jsonBody",
                    "formBody",
                    "operationField",
                }:
                    raise PolicyBundleError(f"{label} has unsupported source {source}")
                if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 256:
                    raise PolicyBundleError(f"{label} name must contain 1-256 bytes")
                source_key = (str(source), name)
                if source_key in seen_sources:
                    raise PolicyBundleError(f"{label} duplicates source {source}:{name}")
                seen_sources.add(source_key)
                _validate_request_value_predicate(route_id, constraint_id, rule_index, rule.get("predicate"))
                capture = rule.get("capture")
                if capture is not None:
                    if (
                        not isinstance(capture, str)
                        or OPERATION_FIELD_NAME_RE.fullmatch(capture) is None
                        or capture == "operation"
                        or capture in seen_captures
                    ):
                        raise PolicyBundleError(f"{label} capture is invalid, reserved, or duplicated")
                    seen_captures.add(capture)
        elif constraint_type in {"jsonBody", "formBody"}:
            allowed_fields = constraint.get("allowedFields")
            if not isinstance(allowed_fields, list) or not allowed_fields:
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} must define non-empty allowedFields "
                    "so unknown fields fail closed"
                )
            for field, rule in (constraint.get("fields") or {}).items():
                if not isinstance(rule, dict):
                    raise PolicyBundleError(
                        f"route {route_id} {constraint_type} {constraint_id} field {field} rule must be an object"
                    )
                _validate_field_rule(
                    route_id,
                    constraint_id,
                    str(field),
                    rule,
                    form=constraint_type == "formBody",
                )
        elif constraint_type == "responseJson":
            if "required" in constraint and not isinstance(constraint["required"], bool):
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} required must be boolean"
                )
            fields = constraint.get("fields")
            if not isinstance(fields, dict) or not fields:
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} must define non-empty fields"
                )
            items = constraint.get("items")
            if items is not None and (
                not isinstance(items, list)
                or not items
                or any(
                    not isinstance(item, str)
                    or len(item) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(item) is None
                    for item in items
                )
                or len(items) != len(set(items))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} has invalid items"
                )
            for field, rule in fields.items():
                if (
                    not isinstance(field, str)
                    or len(field) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
                    or not isinstance(rule, dict)
                    or not rule
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseJson {constraint_id} field {field} has an invalid rule"
                    )
                _validate_response_json_field_rule(
                    route_id, constraint_id, field, rule
                )
        elif constraint_type == "responseDateWindow":
            if int(constraint.get("maxAgeDays") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define maxAgeDays >= 1")
            date_fields = constraint.get("dateFields")
            if (
                not isinstance(date_fields, list)
                or not 1 <= len(date_fields) <= 32
                or any(
                    not isinstance(field_name, str)
                    or len(field_name) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(field_name) is None
                    for field_name in date_fields
                )
                or len(date_fields) != len(set(date_fields))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseDateWindow {constraint_id} "
                    "must define 1-32 unique dateFields"
                )
            items = constraint.get("items")
            if items is not None and (
                not isinstance(items, list)
                or not 1 <= len(items) <= 16
                or any(
                    not isinstance(item, str)
                    or len(item) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(item) is None
                    for item in items
                )
                or len(items) != len(set(items))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseDateWindow {constraint_id} "
                    "has invalid items"
                )
            if not constraint.get("formats"):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define formats")
            formats = constraint.get("formats")
            allowed_formats = {"rfc3339", "date", "epochSeconds", "epochMillis"}
            if (
                not isinstance(formats, list)
                or any(not isinstance(item, str) or item not in allowed_formats for item in formats)
                or len(formats) != len(set(formats))
            ):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} has invalid formats")
        elif constraint_type == "responseBinding":
            success_status_codes = constraint.get("successStatusCodes")
            if (
                not isinstance(success_status_codes, list)
                or not 1 <= len(success_status_codes) <= 8
                or any(
                    isinstance(status, bool)
                    or not isinstance(status, int)
                    or not 200 <= status <= 299
                    for status in success_status_codes
                )
                or len(success_status_codes) != len(set(success_status_codes))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} must define 1-8 unique 2xx successStatusCodes"
                )
            content_types = constraint.get("contentTypes")
            if (
                not isinstance(content_types, list)
                or not 1 <= len(content_types) <= 4
                or any(
                    not isinstance(content_type, str)
                    or content_type != content_type.lower()
                    or re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", content_type)
                    is None
                    for content_type in content_types
                )
                or len(content_types) != len(set(content_types))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} must define 1-4 unique lower-case contentTypes"
                )
            bindings = constraint.get("bindings")
            if not isinstance(bindings, list) or not 1 <= len(bindings) <= 8:
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} must define 1-8 bindings"
                )
            seen_binding_ids: set[str] = set()
            seen_response_fields: set[str] = set()
            required_fields = {"id", "operationField", "responseField", "comparison"}
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != required_fields:
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} has an invalid binding"
                    )
                binding_id = binding.get("id")
                operation_field = binding.get("operationField")
                response_field = binding.get("responseField")
                if (
                    not isinstance(binding_id, str)
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", binding_id) is None
                    or binding_id in seen_binding_ids
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} has an invalid or duplicate binding id"
                    )
                if (
                    not isinstance(operation_field, str)
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", operation_field) is None
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} binding {binding_id} has an invalid operationField"
                    )
                if (
                    not isinstance(response_field, str)
                    or len(response_field) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(response_field) is None
                    or response_field in seen_response_fields
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} binding {binding_id} has an invalid or duplicate responseField"
                    )
                if binding.get("comparison") not in {"exactString", "canonicalInteger"}:
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} binding {binding_id} has an invalid comparison"
                    )
                seen_binding_ids.add(binding_id)
                seen_response_fields.add(response_field)
        elif constraint_type == "responseEnvelope":
            status_codes = constraint.get("statusCodes")
            if (
                not isinstance(status_codes, list)
                or not 1 <= len(status_codes) <= 16
                or any(
                    type(status) is not int or not 100 <= status <= 599
                    for status in status_codes
                )
                or len(status_codes) != len(set(status_codes))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseEnvelope {constraint_id} "
                    "must define 1-16 unique statuses"
                )
            body_presence = constraint.get("bodyPresence")
            content_types = constraint.get("contentTypes")
            if (
                not isinstance(content_types, list)
                or len(content_types) > 4
                or any(
                    not isinstance(content_type, str)
                    or content_type != content_type.lower()
                    or _MEDIA_TYPE_RE.fullmatch(content_type) is None
                    for content_type in content_types
                )
                or len(content_types) != len(set(content_types))
                or body_presence not in {"required", "forbidden"}
                or (body_presence == "required" and not content_types)
                or (body_presence == "forbidden" and bool(content_types))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseEnvelope {constraint_id} "
                    "has an invalid body/content-type contract"
                )
            allowed_headers = constraint.get("allowedResponseHeaderNames")
            forbidden_response_headers = {
                "authorization",
                "connection",
                "content-encoding",
                "content-length",
                "content-type",
                "cookie",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "set-cookie",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            }
            if (
                not isinstance(allowed_headers, list)
                or len(allowed_headers) > 32
                or any(
                    not isinstance(name, str)
                    or name != name.lower()
                    or HTTP_HEADER_NAME_RE.fullmatch(name) is None
                    or name in forbidden_response_headers
                    for name in allowed_headers
                )
                or len(allowed_headers) != len(set(allowed_headers))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseEnvelope {constraint_id} "
                    "allowedResponseHeaderNames is invalid"
                )
            header_rules = constraint.get("responseHeaderRules")
            if (
                not isinstance(header_rules, list)
                or len(header_rules) > 32
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseEnvelope {constraint_id} "
                    "responseHeaderRules are invalid"
                )
            seen_header_rules: set[str] = set()
            for rule_index, rule in enumerate(header_rules):
                if (
                    not isinstance(rule, dict)
                    or set(rule) != {"name", "required", "predicate"}
                    or not isinstance(rule.get("name"), str)
                    or rule["name"] not in set(allowed_headers)
                    or rule["name"] in seen_header_rules
                    or not isinstance(rule.get("required"), bool)
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseEnvelope {constraint_id} "
                        f"header rule {rule_index} is invalid"
                    )
                predicate = rule.get("predicate")
                _validate_request_value_predicate(
                    route_id,
                    constraint_id,
                    rule_index,
                    predicate,
                )
                if predicate.get("kind") not in {"equals", "enum", "pattern"}:
                    raise PolicyBundleError(
                        f"route {route_id} responseEnvelope {constraint_id} "
                        f"header rule {rule_index} predicate is not exact and bounded"
                    )
                seen_header_rules.add(rule["name"])
            if seen_header_rules != set(allowed_headers):
                raise PolicyBundleError(
                    f"route {route_id} responseEnvelope {constraint_id} "
                    "must define exactly one value rule for every allowed "
                    "response header"
                )
        if constraint_type in RESPONSE_CONSTRAINTS or constraint_type == "traversalBudget":
            operations = constraint.get("operations")
            if operations is not None and (
                not isinstance(operations, list)
                or not operations
                or any(
                    not isinstance(operation, str)
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", operation) is None
                    for operation in operations
                )
                or len(set(operations)) != len(operations)
            ):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} has invalid operations"
                )
        if constraint.get("extensions"):
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} declares unattested extensions"
            )
        compiled.append(dict(constraint))
    return tuple(compiled)


def _validate_provider_account_rate_limits(
    route_id: str,
    constraints: tuple[dict[str, Any], ...],
    credential: CredentialPolicy | None,
) -> None:
    identity_scopes = {"principal", "credential", "credentialVersion"}
    for constraint in constraints:
        if constraint.get("type") not in {
            "rateLimit",
            "slidingWindowLimit",
            "weightedBudget",
        }:
            continue
        key = constraint.get("key") or {}
        operation_fields = set(key.get("operationFields") or [])
        if PROVIDER_ACCOUNT_OPERATION_FIELD not in operation_fields:
            continue
        scope = set(key.get("scope") or ["principal", "credential", "route", "operation"])
        conflicting = sorted(scope.intersection(identity_scopes))
        if conflicting:
            raise PolicyBundleError(
                f"route {route_id} provider-account rate limit {constraint.get('id')} "
                f"must not be partitioned by {', '.join(conflicting)}"
            )
        if credential is None or provider_account_scope_value(
            credential.provider, credential.provider_subject
        ) is None:
            raise PolicyBundleError(
                f"route {route_id} provider-account rate limit {constraint.get('id')} "
                "requires a signed credential providerSubject"
            )


def _validate_response_body_limit(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
    maximum: int,
) -> None:
    value = profile.get("maxBodyBytes")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        raise PolicyBundleError(
            f"route {route_id} {profile_name} maxBodyBytes must be an integer between 1 and {maximum}"
        )


def _validate_response_field_paths(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
) -> tuple[str, ...]:
    if "allowedFields" not in profile:
        raise PolicyBundleError(f"route {route_id} {profile_name} is missing allowedFields")
    fields = profile.get("allowedFields")
    if not isinstance(fields, list):
        raise PolicyBundleError(f"route {route_id} {profile_name} allowedFields must be an array")
    if not fields:
        raise PolicyBundleError(f"route {route_id} {profile_name} allowedFields must not be empty")
    if len(fields) > 64:
        raise PolicyBundleError(
            f"route {route_id} {profile_name} allowedFields must contain at most 64 paths"
        )
    if any(
        not isinstance(field, str)
        or len(field) > 256
        or RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
        for field in fields
    ):
        raise PolicyBundleError(
            f"route {route_id} {profile_name} allowedFields must use 1-256 character bounded dotted paths"
        )
    if len(fields) != len(set(fields)):
        raise PolicyBundleError(f"route {route_id} {profile_name} allowedFields must be unique")
    return tuple(fields)


def _validate_credential_response_projections(
    route_id: str,
    adapter_type: str,
    response: Any,
) -> None:
    if not isinstance(response, dict):
        raise PolicyBundleError(
            f"route {route_id} credential-bearing response policy is missing"
        )

    success_mode = "json" if adapter_type == "gmail.v1" else response.get("mode")
    if success_mode in PROJECTED_RESPONSE_MODES:
        mode_name = "JSON" if success_mode == "json" else str(success_mode)
        _validate_response_field_paths(
            route_id,
            response,
            f"credential-bearing {mode_name} success response",
        )

    error = response.get("error")
    if isinstance(error, dict) and error.get("mode") == "json":
        _validate_response_field_paths(
            route_id,
            error,
            "credential-bearing JSON error response",
        )


def _validate_credential_request_body_constraint(
    route_id: str,
    adapter_type: str,
    request_mode: str,
    credential_ref: str | None,
    constraints: tuple[dict[str, Any], ...],
) -> None:
    if adapter_type != "generic.rest" or not credential_ref:
        return
    if request_mode not in CREDENTIAL_BEARING_GENERIC_REQUEST_BODY_MODES:
        raise PolicyBundleError(
            f"route {route_id} credential-bearing generic.rest request bodyMode "
            f"{request_mode!r} is outside the closed buffered allowlist"
        )
    required_constraint = {
        "json": "jsonBody",
        "formUrlencoded": "formBody",
    }.get(request_mode)
    if required_constraint is None:
        return
    if any(
        constraint.get("type") == required_constraint
        and isinstance(constraint.get("allowedFields"), list)
        and bool(constraint["allowedFields"])
        for constraint in constraints
    ):
        return
    raise PolicyBundleError(
        f"route {route_id} credential-bearing generic.rest bodyMode {request_mode} requires "
        f"a {required_constraint} constraint with non-empty allowedFields"
    )


def _validate_generic_operation_sources(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    paths: tuple[str, ...],
) -> dict[str, str]:
    if adapter_type != "generic.rest":
        return {}
    request = adapter_config.get("request") or {}
    operation = request.get("operation")
    if operation is None:
        return {}
    if not isinstance(operation, dict):
        raise PolicyBundleError(f"route {route_id} generic.rest request.operation must be an object")
    unsupported_fields = sorted(
        set(operation) - {"name", "bodySha256Field", "formFields", "jsonFields", "pathParams"}
    )
    if unsupported_fields:
        raise PolicyBundleError(
            f"route {route_id} generic.rest request.operation has unsupported fields: "
            f"{unsupported_fields}"
        )
    operation_name = operation.get("name")
    if not isinstance(operation_name, str) or not 1 <= len(operation_name) <= 128:
        raise PolicyBundleError(
            f"route {route_id} generic.rest request.operation.name must contain 1-128 characters"
        )

    source_kinds: dict[str, str] = {}
    body_mode = request.get("bodyMode")
    for config_key, source_kind, required_mode in (
        ("formFields", "form", "formUrlencoded"),
        ("jsonFields", "json", "json"),
        ("pathParams", "path", None),
    ):
        configured = operation.get(config_key, [])
        source_name_re = (
            JSON_OPERATION_FIELD_NAME_RE
            if config_key == "jsonFields"
            else OPERATION_FIELD_NAME_RE
        )
        if (
            not isinstance(configured, list)
            or len(configured) > 16
            or any(
                not isinstance(source_name, str)
                or source_name_re.fullmatch(source_name) is None
                for source_name in configured
            )
            or len(configured) != len(set(configured))
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest request.operation.{config_key} must define "
                "at most 16 unique operation field names"
            )
        if configured and required_mode is not None and body_mode != required_mode:
            raise PolicyBundleError(
                f"route {route_id} generic.rest request.operation.{config_key} requires "
                f"bodyMode {required_mode}"
            )
        for source_name in configured:
            if source_name == "operation" or source_name in source_kinds:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest request.operation source {source_name} "
                    "is reserved or duplicated"
                )
            source_kinds[source_name] = source_kind

    body_sha256_field = operation.get("bodySha256Field")
    if "bodySha256Field" in operation:
        if (
            not isinstance(body_sha256_field, str)
            or OPERATION_FIELD_NAME_RE.fullmatch(body_sha256_field) is None
            or body_sha256_field == "operation"
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest request.operation.bodySha256Field "
                "must name one valid non-reserved operation field"
            )
        if body_mode not in {"json", "formUrlencoded"}:
            raise PolicyBundleError(
                f"route {route_id} generic.rest request.operation.bodySha256Field requires "
                "buffered bodyMode json or formUrlencoded"
            )
        if body_sha256_field in source_kinds:
            raise PolicyBundleError(
                f"route {route_id} generic.rest request.operation source {body_sha256_field} "
                "is duplicated by bodySha256Field"
            )
        source_kinds[body_sha256_field] = "bodySha256"

    configured_path_params = {
        source_name
        for source_name, source_kind in source_kinds.items()
        if source_kind == "path"
    }
    path_source_positions: list[dict[str, int]] = []
    for path in paths:
        positions: dict[str, int] = {}
        for index, segment in enumerate(path.strip("/").split("/")):
            if not (segment.startswith("{") and segment.endswith("}")):
                continue
            placeholder = segment[1:-1]
            if placeholder in positions:
                raise PolicyBundleError(
                    f"route {route_id} path {path} repeats placeholder {placeholder}"
                )
            positions[placeholder] = index
        for path_param in configured_path_params:
            if path_param not in positions:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest request.operation.pathParams source {path_param} "
                    "must be a placeholder in every matched path"
                )
        path_source_positions.append(positions)

    for left_index, left_path in enumerate(paths):
        for right_index in range(left_index + 1, len(paths)):
            right_path = paths[right_index]
            if (
                _path_specificity(left_path) != _path_specificity(right_path)
                or _path_shape(left_path) != _path_shape(right_path)
            ):
                continue
            for path_param in configured_path_params:
                if (
                    path_source_positions[left_index][path_param]
                    != path_source_positions[right_index][path_param]
                ):
                    raise PolicyBundleError(
                        f"route {route_id} generic.rest request.operation.pathParams source "
                        f"{path_param} maps to different segments in ambiguous path templates "
                        f"{left_path} and {right_path}"
                    )
    return source_kinds


def _validate_request_value_sources(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    paths: tuple[str, ...],
    constraints: tuple[dict[str, Any], ...],
    operation_source_kinds: dict[str, str],
) -> dict[str, str]:
    request_value_constraints = [
        constraint for constraint in constraints if constraint.get("type") == "requestValue"
    ]
    if not request_value_constraints:
        return {}
    operation_catalogs = [
        adapter_operation_field_names(adapter_type, operation, set(operation_source_kinds))
        for operation in _declared_route_operations(adapter_type, adapter_config, paths)
    ]
    if not operation_catalogs or any(catalog is None for catalog in operation_catalogs):
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} has no closed operation-field catalog"
        )
    # A source must exist for every operation, but a capture must not overwrite
    # a field emitted by even one operation (for example Gmail get's messageId).
    guaranteed_operation_fields = set.intersection(
        *(set(catalog) for catalog in operation_catalogs if catalog is not None)
    )
    possible_operation_fields = set.union(
        *(set(catalog) for catalog in operation_catalogs if catalog is not None)
    )
    request = adapter_config.get("request") or {}
    allowed_query = set(request.get("allowedQueryKeys") or [])
    allowed_headers = {
        str(name).lower() for name in request.get("allowedHeaders") or []
    }
    path_placeholders: list[set[str]] = []
    for path in paths:
        placeholders = {
            segment[1:-1]
            for segment in path.strip("/").split("/")
            if segment.startswith("{") and segment.endswith("}")
        }
        path_placeholders.append(placeholders)

    captures: dict[str, str] = {}
    seen_sources: set[tuple[str, str]] = set()
    for constraint in request_value_constraints:
        constraint_id = str(constraint.get("id") or "unnamed")
        for rule_index, rule in enumerate(constraint.get("rules") or []):
            source = str(rule.get("source") or "")
            name = str(rule.get("name") or "")
            label = f"route {route_id} requestValue {constraint_id} rule {rule_index}"
            source_key = (source, name)
            if source_key in seen_sources:
                raise PolicyBundleError(f"{label} duplicates route source {source}:{name}")
            seen_sources.add(source_key)
            if source == "pathParam":
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None or any(
                    name not in placeholders for placeholders in path_placeholders
                ):
                    raise PolicyBundleError(
                        f"{label} pathParam {name} must be a placeholder in every matched path"
                    )
            elif source == "query":
                if name not in allowed_query:
                    raise PolicyBundleError(
                        f"{label} query {name} is not admitted by the adapter request profile"
                    )
            elif source == "header":
                if name != name.lower() or HTTP_HEADER_NAME_RE.fullmatch(name) is None:
                    raise PolicyBundleError(
                        f"{label} header name must be a lower-case HTTP field name"
                    )
                if name not in allowed_headers:
                    raise PolicyBundleError(
                        f"{label} header {name} is not admitted by the adapter request profile"
                    )
            elif source == "jsonBody":
                body_mode = request.get("bodyMode")
                json_body_admitted = (
                    adapter_type == "generic.rest" and body_mode == "json"
                ) or (
                    adapter_type == "x.v2"
                    and adapter_config.get("mode") == "controlledWrite"
                ) or adapter_type == "npm.registry"
                if (
                    not json_body_admitted
                    or len(name) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(name) is None
                ):
                    raise PolicyBundleError(
                        f"{label} jsonBody {name} is not admitted by the adapter request profile"
                    )
            elif source == "formBody":
                if (
                    adapter_type != "generic.rest"
                    or request.get("bodyMode") != "formUrlencoded"
                    or len(name) > 256
                    or OPERATION_FIELD_NAME_RE.fullmatch(name) is None
                ):
                    raise PolicyBundleError(
                        f"{label} formBody {name} is not admitted by the adapter request profile"
                    )
            elif source == "operationField":
                if name not in guaranteed_operation_fields:
                    raise PolicyBundleError(
                        f"{label} operationField {name} is not emitted by the typed adapter"
                    )
            capture = rule.get("capture")
            if capture is None:
                continue
            capture = str(capture)
            if (
                capture in possible_operation_fields
                or capture in captures
                or capture in {"operation", "providerAccount"}
            ):
                raise PolicyBundleError(
                    f"{label} capture {capture} collides with another operation field"
                )
            predicate = rule.get("predicate") or {}
            captures[capture] = (
                "requestValueInteger"
                if predicate.get("kind") == "numeric" and predicate.get("integer") is True
                else "requestValueString"
            )
    return captures


def _validate_response_binding_sources(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    source_kinds: dict[str, str],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    response_bindings = [
        constraint for constraint in constraints if constraint.get("type") == "responseBinding"
    ]
    if not response_bindings:
        return
    if adapter_type not in {"generic.rest", "npm.registry"}:
        raise PolicyBundleError(
            f"route {route_id} responseBinding is currently supported only for generic.rest and npm.registry"
        )
    response = adapter_config.get("response") or {}
    if (
        response.get("mode") != "json"
        or not 1 <= int(response.get("maxBodyBytes") or 0) <= 65536
    ):
        raise PolicyBundleError(
            f"route {route_id} responseBinding requires a buffered JSON response capped at 65536 bytes"
        )
    if adapter_type == "npm.registry":
        configured_operations = {
            f"npm.{operation}" for operation in adapter_config.get("operations") or []
        }
        for constraint in response_bindings:
            constraint_id = str(constraint.get("id") or "unnamed")
            operations = constraint.get("operations") or []
            if operations != ["npm.publish"] or "npm.publish" not in configured_operations:
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} must be scoped only to configured npm.publish"
                )
            bound_sources: set[str] = set()
            for binding in constraint.get("bindings") or []:
                source = str(binding.get("operationField") or "")
                if source not in {
                    "packageName",
                    "packageVersion",
                    "tarballIntegrity",
                }:
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} source {source} "
                        "is not a captured npm.publish field"
                    )
                if binding.get("comparison") != "exactString":
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} npm.publish source {source} "
                        "must use exactString"
                    )
                bound_sources.add(source)
            if not {"packageName", "packageVersion"}.issubset(bound_sources):
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} must bind npm.publish "
                    "packageName and packageVersion"
                )
        return

    request = adapter_config.get("request") or {}
    operation = request.get("operation") or {}
    operation_name = operation.get("name")
    if not isinstance(operation_name, str) or not operation_name:
        raise PolicyBundleError(
            f"route {route_id} responseBinding requires generic.rest request.operation.name"
        )
    available_fields = {"operation"}
    available_fields.update(source_kinds)
    body_constraints: dict[str, list[dict[str, Any]]] = {
        source_kind: [
            constraint
            for constraint in constraints
            if constraint.get("type") == constraint_type
        ]
        for source_kind, constraint_type in (("form", "formBody"), ("json", "jsonBody"))
    }
    for constraint in response_bindings:
        constraint_id = str(constraint.get("id") or "unnamed")
        operations = constraint.get("operations") or []
        if operations and operation_name not in operations:
            raise PolicyBundleError(
                f"route {route_id} responseBinding {constraint_id} does not include its configured operation"
            )
        for binding in constraint.get("bindings") or []:
            source = str(binding.get("operationField") or "")
            if source not in available_fields:
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} source {source} "
                    "is not captured by generic.rest request.operation"
                )
            if source == "operation":
                continue
            source_kind = source_kinds[source]
            if source_kind == "path":
                if binding.get("comparison") != "exactString":
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} path source {source} "
                        "must use exactString"
                    )
                continue
            if source_kind == "bodySha256":
                if binding.get("comparison") != "exactString":
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} bodySha256 source "
                        f"{source} must use exactString"
                    )
                continue
            if source_kind in {"requestValueString", "requestValueInteger"}:
                expected_comparison = (
                    "canonicalInteger"
                    if source_kind == "requestValueInteger"
                    else "exactString"
                )
                if binding.get("comparison") != expected_comparison:
                    raise PolicyBundleError(
                        f"route {route_id} responseBinding {constraint_id} requestValue source {source} "
                        f"must use {expected_comparison}"
                    )
                continue
            source_constraints = body_constraints[source_kind]
            required_fields = {
                str(field)
                for source_constraint in source_constraints
                for field in source_constraint.get("requiredFields") or []
            }
            if source not in required_fields:
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} source {source} "
                    f"must be required by {source_kind}Body"
                )
            field_rules = {
                str(field): rule
                for source_constraint in source_constraints
                for field, rule in (source_constraint.get("fields") or {}).items()
            }
            expected_type = (
                "integer"
                if binding.get("comparison") == "canonicalInteger"
                else "string"
            )
            if (field_rules.get(source) or {}).get("type") != expected_type:
                raise PolicyBundleError(
                    f"route {route_id} responseBinding {constraint_id} source {source} "
                    f"must use {source_kind}Body type {expected_type}"
                )


def _validate_durable_policy_sources(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    paths: tuple[str, ...],
    operation_source_kinds: dict[str, str],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    request = adapter_config.get("request") or {}
    allowed_query = set(request.get("allowedQueryKeys") or [])
    allowed_headers = {
        str(name).lower() for name in request.get("allowedHeaders") or []
    }
    for constraint in constraints:
        constraint_type = constraint.get("type")
        constraint_id = str(constraint.get("id") or "unnamed")
        if constraint_type in {"queryDateWindow", "queryNumericBounds"}:
            parameters = set(constraint.get("parameters") or [])
            if not parameters.issubset(allowed_query):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} "
                    "references query keys not admitted by the typed adapter"
                )
        if constraint_type == "weightedBudget":
            weight = constraint.get("weight") or {}
            field_name = str(weight.get("field") or "")
            source_kind = operation_source_kinds.get(field_name)
            expected_kind = weight.get("source")
            if (
                source_kind is None
                or (
                    expected_kind == "requestValue"
                    and not source_kind.startswith("requestValue")
                )
                or (
                    expected_kind == "operationField"
                    and source_kind.startswith("requestValue")
                )
                or source_kind not in {
                    "requestValueInteger",
                    "json",
                    "form",
                }
            ):
                raise PolicyBundleError(
                    f"route {route_id} weightedBudget {constraint_id} weight "
                    f"field {field_name} is not a canonical integer {expected_kind}"
                )
            if source_kind in {"json", "form"}:
                body_constraint_type = (
                    "jsonBody" if source_kind == "json" else "formBody"
                )
                body_proofs = [
                    proof
                    for proof in constraints
                    if proof.get("type") == body_constraint_type
                    and field_name in set(proof.get("requiredFields") or [])
                    and (proof.get("fields") or {})
                    .get(field_name, {})
                    .get("type")
                    == "integer"
                ]
                if not body_proofs:
                    raise PolicyBundleError(
                        f"route {route_id} weightedBudget {constraint_id} "
                        f"field {field_name} requires a mandatory integer "
                        f"{body_constraint_type} proof"
                    )
        if constraint_type != "traversalBudget":
            continue
        traversal = constraint.get("traversal") or {}
        cursor = traversal.get("cursor") or {}
        lineage = traversal.get("lineage") or {}
        request_source = cursor.get("requestSource")
        request_field = cursor.get("requestField")
        if request_source == "query" and request_field not in allowed_query:
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} cursor query "
                f"{request_field} is not admitted by the adapter"
            )
        if request_source == "header" and request_field not in allowed_headers:
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} cursor header "
                f"{request_field} is not admitted by the adapter"
            )
        if request_source == "jsonBody":
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} JSON body "
                "cursors are unsupported until request-body membership is "
                "committed by the durable evidence wire"
            )
        query_fields = set(lineage.get("queryFields") or [])
        if not query_fields.issubset(allowed_query):
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} lineage "
                "queryFields are not admitted by the adapter"
            )
        if request_source == "query" and request_field in query_fields:
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} cursor "
                "cannot be part of the stable query lineage"
            )
        operations = constraint.get("operations") or sorted(
            _declared_route_operations(adapter_type, adapter_config, paths)
        )
        expected_sets: list[frozenset[str]] = []
        for operation in operations:
            admitted = adapter_operation_query_fields(
                adapter_type, adapter_config, str(operation)
            )
            if admitted is None:
                raise PolicyBundleError(
                    f"route {route_id} traversalBudget {constraint_id} "
                    f"operation {operation} has no typed query catalog"
                )
            if request_source == "query" and request_field not in admitted:
                raise PolicyBundleError(
                    f"route {route_id} traversalBudget {constraint_id} cursor query "
                    f"{request_field} is not admitted for operation {operation}"
                )
            expected_sets.append(
                admitted
                - (
                    {str(request_field)}
                    if request_source == "query"
                    else set()
                )
            )
        if (
            not expected_sets
            or any(expected != expected_sets[0] for expected in expected_sets)
            or query_fields != set(expected_sets[0])
        ):
            raise PolicyBundleError(
                f"route {route_id} traversalBudget {constraint_id} lineage "
                "queryFields must exactly cover every mutable shaping query "
                "field except the configured cursor"
            )


def _declared_route_operations(
    adapter_type: str,
    adapter_config: dict[str, Any],
    paths: tuple[str, ...],
) -> set[str]:
    if adapter_type == "gmail.v1":
        operations: set[str] = set()
        for path in paths:
            if "{message_id}" in path:
                operations.add("gmail.message.get")
            else:
                operations.add("gmail.messages.list")
        return operations
    if adapter_type == "x.v2":
        if adapter_config.get("mode") == "controlledWrite":
            return {"tweets.write"}
        return set(adapter_config.get("allowedReadOperations") or [])
    if adapter_type == "npm.registry":
        return {
            f"npm.{operation}"
            for operation in adapter_config.get("operations") or []
        }
    operation = (adapter_config.get("request") or {}).get("operation") or {}
    name = operation.get("name")
    return {name} if isinstance(name, str) and name else set()


def _validate_response_envelope_coverage(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    paths: tuple[str, ...],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    operations = _declared_route_operations(
        adapter_type, adapter_config, paths
    )
    envelopes = [
        constraint
        for constraint in constraints
        if constraint.get("type") == "responseEnvelope"
    ]
    if not envelopes:
        raise PolicyBundleError(
            f"route {route_id} must define at least one responseEnvelope"
        )
    covered: set[str] = set()
    for envelope in envelopes:
        scoped = envelope.get("operations")
        if scoped is None:
            covered.update(operations)
            continue
        unknown = set(scoped) - operations
        if unknown:
            raise PolicyBundleError(
                f"route {route_id} responseEnvelope references unknown "
                f"operations: {sorted(unknown)}"
            )
        covered.update(scoped)
    if operations and covered != operations:
        raise PolicyBundleError(
            f"route {route_id} responseEnvelope coverage is incomplete: "
            f"missing={sorted(operations - covered)}"
        )


def _validate_response_headers(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
) -> None:
    headers = profile.get("allowedHeaders")
    if not isinstance(headers, list) or len(headers) > len(SAFE_RESPONSE_HEADERS):
        raise PolicyBundleError(f"route {route_id} {profile_name} must define bounded allowedHeaders")
    if any(not isinstance(header, str) or header not in SAFE_RESPONSE_HEADERS for header in headers):
        raise PolicyBundleError(
            f"route {route_id} {profile_name} allowedHeaders must be lower-case safe response headers"
        )
    if len(headers) != len(set(headers)):
        raise PolicyBundleError(f"route {route_id} {profile_name} allowedHeaders must be unique")


def _validate_bounded_response_profiles(
    route_id: str,
    response: Any,
    adapter_name: str,
) -> tuple[str, ...]:
    if not isinstance(response, dict):
        raise PolicyBundleError(f"route {route_id} {adapter_name} policy must define response enforcement")
    profile_name = f"{adapter_name} success response"
    _validate_response_body_limit(route_id, response, profile_name, MAX_PROVIDER_RESPONSE_BODY_BYTES)
    fields = _validate_response_field_paths(route_id, response, profile_name)
    _validate_response_headers(route_id, response, profile_name)

    error = response.get("error")
    if not isinstance(error, dict):
        raise PolicyBundleError(f"route {route_id} {adapter_name} policy must define an error response profile")
    if error.get("mode") != "json":
        raise PolicyBundleError(f"route {route_id} {adapter_name} error response mode must be json")
    if error.get("onInvalid") != "block":
        raise PolicyBundleError(f"route {route_id} {adapter_name} invalid error responses must block")
    error_profile_name = f"{adapter_name} error response"
    _validate_response_body_limit(route_id, error, error_profile_name, MAX_PROVIDER_ERROR_BODY_BYTES)
    _validate_response_field_paths(route_id, error, error_profile_name)
    _validate_response_headers(route_id, error, error_profile_name)
    return fields


def validate_buffered_passthrough_response(
    route_id: str,
    adapter_type: str,
    response: Any,
    constraints: tuple[dict[str, Any], ...] = (),
) -> None:
    """Validate the opt-in whole-JSON contract, independently of schema loading."""
    if not isinstance(response, dict):
        return
    error = response.get("error")
    if response.get("mode") != BUFFERED_PASSTHROUGH_RESPONSE_MODE:
        if "bodyFormat" in response or (
            isinstance(error, dict)
            and ("bodyFormat" in error or error.get("mode") == BUFFERED_PASSTHROUGH_RESPONSE_MODE)
        ):
            raise PolicyBundleError(
                f"route {route_id} bufferedPassthrough requires paired explicit success and error profiles"
            )
        return
    if adapter_type != "generic.rest":
        raise PolicyBundleError(f"route {route_id} bufferedPassthrough is supported only by generic.rest")
    if any(
        constraint.get("type")
        in {"slidingWindowLimit", "weightedBudget", "traversalBudget", "responseBinding"}
        for constraint in constraints
    ):
        raise PolicyBundleError(
            f"route {route_id} bufferedPassthrough does not support durable claims or responseBinding"
        )
    common_fields = {"mode", "bodyFormat", "maxBodyBytes", "contentTypes", "allowedHeaders"}
    for profile, terminal_field, maximum in (
        (response, "error", 16 * 1024 * 1024),
        (error, "onInvalid", MAX_PROVIDER_ERROR_BODY_BYTES),
    ):
        label = f"bufferedPassthrough {'success' if terminal_field == 'error' else 'error'} response"
        if not isinstance(profile, dict) or set(profile) != common_fields | {terminal_field}:
            raise PolicyBundleError(f"route {route_id} {label} must define exactly its closed profile fields")
        if (
            profile.get("mode") != BUFFERED_PASSTHROUGH_RESPONSE_MODE
            or profile.get("bodyFormat") != "json"
            or profile.get("contentTypes") != ["application/json"]
            or (terminal_field == "onInvalid" and profile.get("onInvalid") != "block")
        ):
            raise PolicyBundleError(f"route {route_id} {label} must use bounded JSON and block on invalid")
        _validate_response_body_limit(route_id, profile, label, maximum)
        _validate_response_headers(route_id, profile, label)


def _validate_optional_response_release_contract(
    route_id: str,
    response: dict[str, Any],
    adapter_name: str,
) -> None:
    if response.get("mode") == BUFFERED_PASSTHROUGH_RESPONSE_MODE:
        validate_buffered_passthrough_response(route_id, adapter_name, response)
        return
    if response.get("mode") in PROJECTED_RESPONSE_MODES:
        _validate_response_field_paths(route_id, response, f"{adapter_name} success response")
    if "allowedHeaders" in response:
        _validate_response_headers(route_id, response, f"{adapter_name} success response")
    error = response.get("error")
    if error is None:
        return
    if not isinstance(error, dict) or error.get("mode") != "json" or error.get("onInvalid") != "block":
        raise PolicyBundleError(
            f"route {route_id} {adapter_name} error response must use bounded json and block on invalid"
        )
    _validate_response_body_limit(
        route_id, error, f"{adapter_name} error response", MAX_PROVIDER_ERROR_BODY_BYTES
    )
    _validate_response_field_paths(route_id, error, f"{adapter_name} error response")
    _validate_response_headers(route_id, error, f"{adapter_name} error response")


def _validate_public_npm_publish_response_contract(
    route_id: str,
    adapter_config: dict[str, Any],
    response: dict[str, Any],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    if adapter_config.get("publishResponseContract") != NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT:
        raise PolicyBundleError(
            f"route {route_id} public npm.publish requires "
            f"publishResponseContract {NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT}"
        )
    max_body_bytes = response.get("maxBodyBytes")
    if (
        response.get("mode") != "json"
        or not isinstance(max_body_bytes, int)
        or isinstance(max_body_bytes, bool)
        or not 1 <= max_body_bytes <= 65536
    ):
        raise PolicyBundleError(
            f"route {route_id} public npm.publish response contract requires buffered JSON "
            "capped at 65536 bytes"
        )
    if response.get("allowedFields") != list(NPM_PUBLIC_REGISTRY_RECEIPT_FIELDS):
        raise PolicyBundleError(
            f"route {route_id} public npm.publish response must project exactly ok and published"
        )
    if response.get("allowedHeaders") != []:
        raise PolicyBundleError(
            f"route {route_id} public npm.publish response must not release upstream headers"
        )

    publish_response_constraints = [
        constraint
        for constraint in constraints
        if constraint.get("type") in {"responseBinding", "responseJson"}
        and (
            constraint.get("operations") is None
            or "npm.publish" in constraint.get("operations", [])
        )
    ]
    if publish_response_constraints:
        raise PolicyBundleError(
            f"route {route_id} public npm.publish receipt must not use responseBinding or responseJson"
        )


def _validate_signed_npm_publish_response_contract(
    route_id: str,
    response: dict[str, Any],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    max_body_bytes = response.get("maxBodyBytes")
    if (
        response.get("mode") != "json"
        or not isinstance(max_body_bytes, int)
        or isinstance(max_body_bytes, bool)
        or not 1 <= max_body_bytes <= 65536
    ):
        raise PolicyBundleError(
            f"route {route_id} signed npm.publish response contract requires buffered JSON "
            "capped at 65536 bytes"
        )

    response_bindings = [
        constraint
        for constraint in constraints
        if constraint.get("type") == "responseBinding"
        and constraint.get("operations") == ["npm.publish"]
    ]
    response_json_constraints = [
        constraint
        for constraint in constraints
        if constraint.get("type") == "responseJson"
        and constraint.get("operations") == ["npm.publish"]
    ]
    if not response_bindings:
        raise PolicyBundleError(
            f"route {route_id} signed npm.publish requires a responseBinding scoped only to npm.publish"
        )
    for constraint in response_bindings:
        constraint_id = str(constraint.get("id") or "unnamed")
        success_status_codes = constraint.get("successStatusCodes") or []
        if any(status not in {200, 201} for status in success_status_codes):
            raise PolicyBundleError(
                f"route {route_id} responseBinding {constraint_id} npm.publish "
                "successStatusCodes may contain only 200 or 201"
            )
        if constraint.get("contentTypes") != ["application/json"]:
            raise PolicyBundleError(
                f"route {route_id} responseBinding {constraint_id} npm.publish "
                "contentTypes must be exactly application/json"
            )

    if not response_json_constraints:
        raise PolicyBundleError(
            f"route {route_id} signed npm.publish requires a responseJson success constraint "
            "scoped only to npm.publish"
        )
    if not any(
        constraint.get("required") is True
        and isinstance((constraint.get("fields") or {}).get("published"), dict)
        and (constraint.get("fields") or {})["published"].get("required") is True
        and (constraint.get("fields") or {})["published"].get("type") == "boolean"
        and (constraint.get("fields") or {})["published"].get("equals") is True
        for constraint in response_json_constraints
    ):
        raise PolicyBundleError(
            f"route {route_id} signed npm.publish responseJson success constraint must require "
            "published to equal true"
        )


def provider_request_profile(adapter_type: str, mode: str | None = None) -> dict[str, Any]:
    if adapter_type == "gmail.v1":
        return {
            "allowedHeaders": list(GMAIL_V1_REQUEST_HEADERS),
            "discardHeaders": [],
            "allowedQueryKeys": list(GMAIL_V1_REQUEST_QUERY_KEYS),
            "allowedMediaTypes": [],
            "maxBodyBytes": 0,
            "valueRules": [],
        }
    if adapter_type == "x.v2":
        if mode == "recentSearchOnly":
            query_keys = X_V2_RECENT_SEARCH_QUERY_KEYS
            media_types: tuple[str, ...] = ()
            max_body_bytes = 0
        elif mode == "readOnly":
            query_keys = X_V2_BOUNDED_READ_QUERY_KEYS
            media_types = ()
            max_body_bytes = 0
        elif mode == "controlledWrite":
            query_keys = ()
            media_types = ("application/json",)
            max_body_bytes = 65536
        else:
            raise PolicyBundleError(f"unsupported x.v2 request profile mode {mode!r}")
        return {
            "allowedHeaders": list(X_V2_REQUEST_HEADERS),
            "discardHeaders": [],
            "allowedQueryKeys": list(query_keys),
            "allowedMediaTypes": list(media_types),
            "maxBodyBytes": max_body_bytes,
            "valueRules": [],
        }
    if adapter_type == "npm.registry":
        return {
            "allowedHeaders": list(NPM_REGISTRY_REQUEST_HEADERS),
            "discardHeaders": ["npm-session"],
            "allowedQueryKeys": [],
            "allowedMediaTypes": ["application/json"],
            "maxBodyBytes": 16 * 1024 * 1024,
            "valueRules": [],
        }
    raise PolicyBundleError(f"adapter {adapter_type} does not have a provider request profile")


def _validate_provider_request_profile(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
) -> None:
    request = adapter_config.get("request")
    if not isinstance(request, dict):
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} must define an exact provider request profile"
        )
    if (
        not PROVIDER_REQUEST_PROFILE_REQUIRED_FIELDS.issubset(request)
        or not set(request).issubset(PROVIDER_REQUEST_PROFILE_FIELDS)
    ):
        missing = sorted(PROVIDER_REQUEST_PROFILE_REQUIRED_FIELDS - set(request))
        unknown = sorted(set(request) - PROVIDER_REQUEST_PROFILE_FIELDS)
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} request profile fields are invalid: "
            f"missing={missing} unknown={unknown}"
        )

    for field_name in (
        "allowedHeaders",
        "allowedQueryKeys",
        "allowedMediaTypes",
    ):
        values = request.get(field_name)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            or len(values) != len(set(values))
        ):
            raise PolicyBundleError(
                f"route {route_id} {adapter_type} request {field_name} must contain unique strings"
            )
    value_rules = request.get("valueRules")
    if not isinstance(value_rules, list) or len(value_rules) > 16:
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} request valueRules must be a bounded array"
        )
    discard_headers = request.get("discardHeaders", [])
    if (
        not isinstance(discard_headers, list)
        or any(not isinstance(value, str) or not value for value in discard_headers)
        or len(discard_headers) != len(set(discard_headers))
    ):
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} request discardHeaders must contain unique strings"
        )
    for field_name, values in (
        ("allowedHeaders", request["allowedHeaders"]),
        ("discardHeaders", discard_headers),
        ("allowedMediaTypes", request["allowedMediaTypes"]),
    ):
        if any(value != value.lower() for value in values):
            raise PolicyBundleError(
                f"route {route_id} {adapter_type} request {field_name} must be lower-case"
            )

    expected = provider_request_profile(adapter_type, str(adapter_config.get("mode") or ""))
    for field_name in ("allowedHeaders", "allowedQueryKeys", "allowedMediaTypes"):
        if set(request[field_name]) != set(expected[field_name]):
            raise PolicyBundleError(
                f"route {route_id} {adapter_type} request {field_name} must match the exact "
                "provider profile"
            )
    required_discard_headers = set(expected["discardHeaders"])
    if required_discard_headers and (
        "discardHeaders" not in request
        or not required_discard_headers.issubset(discard_headers)
    ):
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} request discardHeaders must explicitly "
            f"include the provider preset: {sorted(required_discard_headers)}"
        )
    if (
        type(request.get("maxBodyBytes")) is not int
        or request.get("maxBodyBytes") != expected["maxBodyBytes"]
    ):
        raise PolicyBundleError(
            f"route {route_id} {adapter_type} request maxBodyBytes must equal "
            f"{expected['maxBodyBytes']}"
        )


def _validate_adapter_security_invariants(
    route_id: str,
    host: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    credential_ref: str | None,
    jit: dict[str, Any],
    methods: frozenset[str],
    paths: tuple[str, ...],
    constraints: tuple[dict[str, Any], ...],
    signed_policy: bool,
) -> None:
    if adapter_type in {"gmail.v1", "x.v2", "npm.registry"}:
        _validate_provider_request_profile(route_id, adapter_type, adapter_config)

    if adapter_type == "gmail.v1":
        if not credential_ref:
            raise PolicyBundleError(f"route {route_id} Gmail policy must bind a credential")
        if adapter_config.get("forceQuery") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must force the bounded age query")
        if adapter_config.get("allowMessageGetOnlyFromPriorSearch") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must require prior age proof for message reads")
        for field_name in ("maxAgeDays", "maxResults", "cacheTtlSeconds"):
            value = adapter_config.get(field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise PolicyBundleError(f"route {route_id} Gmail policy must define positive {field_name}")
        response = adapter_config.get("response")
        response_fields = _validate_bounded_response_profiles(route_id, response, "Gmail")
        assert isinstance(response, dict)
        if response.get("validateInternalDate") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must validate response internalDate")
        if not isinstance(response.get("validateListByMetadataFetch"), bool):
            raise PolicyBundleError(
                f"route {route_id} Gmail policy must explicitly configure list metadata age proof"
            )
        validate_list_by_metadata = response["validateListByMetadataFetch"]
        metadata_fetch = response.get("metadataFetch")
        if validate_list_by_metadata and not isinstance(metadata_fetch, dict):
            raise PolicyBundleError(
                f"route {route_id} Gmail list metadata age proof requires metadataFetch"
            )
        if metadata_fetch is not None:
            if not isinstance(metadata_fetch, dict):
                raise PolicyBundleError(
                    f"route {route_id} Gmail metadataFetch must be an object"
                )
            metadata_fetch_bounds = {
                "maxMessages": 32,
                "perRequestTimeoutMs": 3000,
                "totalTimeoutMs": 10000,
                "maxBodyBytes": 8192,
            }
            if set(metadata_fetch) != set(metadata_fetch_bounds):
                raise PolicyBundleError(
                    f"route {route_id} Gmail metadataFetch must define only "
                    "maxMessages, perRequestTimeoutMs, totalTimeoutMs, and maxBodyBytes"
                )
            for field_name, maximum in metadata_fetch_bounds.items():
                value = metadata_fetch.get(field_name)
                if type(value) is not int or not 1 <= value <= maximum:
                    raise PolicyBundleError(
                        f"route {route_id} Gmail metadataFetch {field_name} must be an integer "
                        f"between 1 and {maximum}"
                    )
            if metadata_fetch["maxMessages"] > adapter_config["maxResults"]:
                raise PolicyBundleError(
                    f"route {route_id} Gmail metadataFetch maxMessages must not exceed maxResults"
                )
            if metadata_fetch["perRequestTimeoutMs"] > metadata_fetch["totalTimeoutMs"]:
                raise PolicyBundleError(
                    f"route {route_id} Gmail metadataFetch perRequestTimeoutMs "
                    "must not exceed totalTimeoutMs"
                )
        if validate_list_by_metadata and "id" not in response_fields:
            raise PolicyBundleError(
                f"route {route_id} Gmail list metadata age proof requires id in allowedFields"
            )
        if response.get("onViolation") != "block":
            raise PolicyBundleError(f"route {route_id} Gmail response violations must block")
        message_header_names = response.get("allowedMessageHeaderNames")
        if "payload.headers" in response_fields:
            if (
                not isinstance(message_header_names, list)
                or not message_header_names
                or len(message_header_names) > 64
                or any(
                    not isinstance(name, str)
                    or not name
                    or len(name) > 128
                    or ":" in name
                    or "\r" in name
                    or "\n" in name
                    for name in message_header_names
                )
                or len({name.lower() for name in message_header_names}) != len(message_header_names)
            ):
                raise PolicyBundleError(
                    f"route {route_id} Gmail payload.headers requires 1-64 unique allowedMessageHeaderNames"
                )
        elif "allowedMessageHeaderNames" in response:
            raise PolicyBundleError(
                f"route {route_id} Gmail allowedMessageHeaderNames requires payload.headers in allowedFields"
            )

    if adapter_type == "x.v2":
        if not credential_ref:
            raise PolicyBundleError(f"route {route_id} X policy must bind a credential")
        mode = adapter_config.get("mode")
        allowed_reads = set(adapter_config.get("allowedReadOperations") or [])
        response_mode = str((adapter_config.get("response") or {}).get("mode") or "")
        if mode in {"readOnly", "recentSearchOnly"}:
            if methods != {"GET"}:
                raise PolicyBundleError(f"route {route_id} X read policy may only match GET")
            if not allowed_reads:
                raise PolicyBundleError(f"route {route_id} X read policy must allow explicit read operations")
            if mode == "recentSearchOnly" and allowed_reads != {"search.read"}:
                raise PolicyBundleError(
                    f"route {route_id} X recent-search policy may only allow search.read"
                )
            if mode == "recentSearchOnly" and not set(paths).issubset(X_V2_RECENT_SEARCH_PATHS):
                raise PolicyBundleError(
                    f"route {route_id} X recent-search policy may only match exact recent-search endpoints"
                )
            if response_mode == "stream":
                raise PolicyBundleError(
                    f"route {route_id} X bounded reads cannot use an unvalidated stream response"
                )
        elif mode == "controlledWrite":
            if methods != {"POST"} or set(paths) != {"/2/tweets"}:
                raise PolicyBundleError(
                    f"route {route_id} controlled X writes currently support only POST /2/tweets"
                )
            operation_policies = [
                set(constraint.get("allowedOperations") or [])
                for constraint in constraints
                if constraint.get("type") == "operationPolicy"
            ]
            if {"tweets.write"} not in operation_policies:
                raise PolicyBundleError(
                    f"route {route_id} controlled X post writes require a tweets.write operation allowlist"
                )
            if not any(constraint.get("type") == "jsonBody" for constraint in constraints):
                raise PolicyBundleError(
                    f"route {route_id} controlled X post writes require an explicit JSON body policy"
                )
            if response_mode == "stream":
                raise PolicyBundleError(f"route {route_id} controlled X writes cannot stream responses")

    if adapter_type == "npm.registry":
        operations = set(adapter_config.get("operations") or [])
        write_operations = operations.intersection(NPM_WRITE_OPERATIONS)
        response = adapter_config.get("response")
        _validate_bounded_response_profiles(route_id, response, "npm")
        publish_response_contract = adapter_config.get("publishResponseContract")
        if publish_response_contract is not None and (
            host != NPM_PUBLIC_REGISTRY_HOST or "publish" not in operations
        ):
            raise PolicyBundleError(
                f"route {route_id} {NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT} is valid only for "
                f"npm.publish on {NPM_PUBLIC_REGISTRY_HOST}"
            )
        if not write_operations:
            return
        assert isinstance(response, dict)
        if response.get("mode") != "json":
            raise PolicyBundleError(f"route {route_id} npm writes require a bounded json success response")
        if "publish" in operations:
            if host == NPM_PUBLIC_REGISTRY_HOST:
                _validate_public_npm_publish_response_contract(
                    route_id, adapter_config, response, constraints
                )
            elif signed_policy:
                _validate_signed_npm_publish_response_contract(route_id, response, constraints)
        authn = ((jit.get("approvers") or {}).get("authn") or {}) if isinstance(jit, dict) else {}
        authenticator_classes = set(authn.get("allowedAuthenticatorClasses") or [])
        if (
            jit.get("required") is not True
            or jit.get("mode") != "perOperation"
            or jit.get("maxUses") != 1
            or jit.get("consumeOn") != "forwardStart"
            or authn.get("webauthnRequired") is not True
            or authn.get("userVerification") != "required"
            or authn.get("requireHardwareAttestation") is not True
            or not authenticator_classes
            or not authenticator_classes.issubset({"yubikey", "hardware"})
        ):
            raise PolicyBundleError(
                f"route {route_id} npm writes require one-use, hardware-attested WebAuthn JIT"
            )


def _validate_route_resolved_cidrs(
    route_id: str,
    match: dict[str, Any],
) -> tuple[str, ...] | None:
    if "resolvedCidrs" not in match:
        return None

    raw_cidrs = match["resolvedCidrs"]
    if not isinstance(raw_cidrs, list) or not 1 <= len(raw_cidrs) <= 32:
        raise PolicyBundleError(
            f"route {route_id} resolvedCidrs must contain 1-32 canonical CIDRs"
        )

    normalized_cidrs: list[str] = []
    seen: set[str] = set()
    for raw_cidr in raw_cidrs:
        if not isinstance(raw_cidr, str) or not raw_cidr or "%" in raw_cidr:
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs must contain canonical CIDR strings without zone IDs"
            )
        try:
            network = ipaddress.ip_network(raw_cidr, strict=True)
        except ValueError as exc:
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs contains an invalid or host-bit CIDR"
            ) from exc

        normalized = str(network)
        if normalized in seen:
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs must be unique after normalization"
            )
        seen.add(normalized)
        if raw_cidr != normalized:
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs contains a noncanonical CIDR"
            )
        if isinstance(network, ipaddress.IPv6Network) and network.overlaps(
            IPV4_MAPPED_IPV6_NETWORK
        ):
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs cannot include IPv4-mapped IPv6 space"
            )
        if any(
            network.version == forbidden.version and network.overlaps(forbidden)
            for forbidden in FORBIDDEN_UPSTREAM_METADATA_NETWORKS
        ):
            raise PolicyBundleError(
                f"route {route_id} resolvedCidrs overlaps a forbidden metadata range"
            )
        normalized_cidrs.append(normalized)

    return tuple(normalized_cidrs)


def _x_route_search_age_days(route: RoutePolicy) -> int | None:
    if (
        route.adapter_type != "x.v2"
        or "GET" not in route.methods
        or "search.read"
        not in set(route.adapter_config.get("allowedReadOperations") or [])
    ):
        return None
    if (
        route.adapter_config.get("mode") != "recentSearchOnly"
        or not route.path_templates
        or not set(route.path_templates).issubset(X_V2_RECENT_SEARCH_PATHS)
    ):
        raise PolicyBundleError(
            f"X search route {route.id} must use only the exact recent-search "
            "path family; broad, all-search, and alternate paths are denied"
        )
    request_bounds = [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "queryDateWindow"
        and constraint.get("required") is True
        and set(constraint.get("parameters") or [])
        == {"start_time", "end_time"}
        and constraint.get("formats") == ["rfc3339"]
    ]
    response_bounds = [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "responseDateWindow"
        and constraint.get("required") is True
        and (
            constraint.get("operations") is None
            or constraint.get("operations") == ["search.read"]
        )
        and constraint.get("items") == ["data"]
        and constraint.get("dateFields") == ["created_at"]
        and constraint.get("formats") == ["rfc3339"]
    ]
    if len(request_bounds) != 1 or len(response_bounds) != 1:
        raise PolicyBundleError(
            f"X search route {route.id} requires one non-vacuous exact "
            "request and response seven-day proof"
        )
    request_days = int(request_bounds[0].get("maxAgeDays") or 0)
    response_days = int(response_bounds[0].get("maxAgeDays") or 0)
    if request_days != 7 or response_days != 7:
        raise PolicyBundleError(
            f"X search route {route.id} must bind both request and response "
            "evidence to exactly seven days"
        )
    return 7


def _validate_x_search_route_conflicts(routes: list[RoutePolicy]) -> None:
    x_routes = [
        route
        for route in routes
        if route.adapter_type == "x.v2"
        and "GET" in route.methods
        and "search.read"
        in set(route.adapter_config.get("allowedReadOperations") or [])
    ]
    for route in x_routes:
        _x_route_search_age_days(route)
    for index, left in enumerate(x_routes):
        for right in x_routes[index + 1 :]:
            shared_principals = set(left.principals).intersection(
                right.principals
            )
            if (
                "*" not in left.principals
                and "*" not in right.principals
                and not shared_principals
            ):
                continue
            if left.credential_ref != right.credential_ref:
                continue
            left_days = _x_route_search_age_days(left)
            right_days = _x_route_search_age_days(right)
            if left_days != right_days or left_days is None:
                raise PolicyBundleError(
                    f"X search routes {left.id} and {right.id} expose the same "
                    "principal/credential through conflicting age boundaries; "
                    "split the principal or credential, or make both request "
                    "and response limits identical"
                )


def compile_policy_bundle(
    raw: dict[str, Any],
    *,
    verify_signature: bool = False,
    validate_schema: bool = False,
    enforce_signed_policy_constraints: bool = False,
    signing_trust: PolicySigningTrust | None = None,
) -> PolicySnapshot:
    _admit_policy_json_object(raw)
    if validate_schema:
        validate_policy_schema(raw)
    if verify_signature:
        verify_policy_signature(raw, signing_trust=signing_trust)
    if raw.get("apiVersion") not in {"serverware.policy/v1", "serverware.policy/v2"}:
        raise PolicyBundleError("apiVersion must select a supported signed policy profile")
    if raw.get("kind") != "PolicyBundle":
        raise PolicyBundleError("kind must be PolicyBundle")

    metadata = raw.get("metadata") or {}
    signed_policy = enforce_signed_policy_constraints or (
        isinstance(metadata.get("signature"), str)
        and metadata["signature"].startswith("ed25519:")
    )
    if "validFrom" in metadata:
        raise PolicyBundleError("metadata.validFrom is unsupported until activation-time enforcement is implemented")
    defaults = raw.get("defaults")
    if not isinstance(defaults, dict):
        raise PolicyBundleError("policy bundle must define explicit fail-closed defaults")
    for name, expected in FAIL_CLOSED_DEFAULTS.items():
        if defaults.get(name) != expected:
            raise PolicyBundleError(f"defaults.{name} must be {expected}")

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
        source_cidrs = tuple(
            _canonical_cidr(
                cidr,
                f"principal {principal_id} sourceCidrs entry",
            )
            for cidr in (item.get("sourceCidrs") or ())
        )
        if len(source_cidrs) != len(set(source_cidrs)):
            raise PolicyBundleError(
                f"principal {principal_id} sourceCidrs must be unique"
            )
        mtls_raw = _validate_mtls_identity_policy(
            principal_id, item.get("mtls")
        )
        mtls = (
            MTLSIdentityPolicy(
                san_spiffe_ids=mtls_raw.get("sanSpiffeIds", ()),
                san_dns_names=mtls_raw.get("sanDnsNames", ()),
                san_uris=mtls_raw.get("sanUris", ()),
                certificate_sha256=mtls_raw.get("certificateSha256", ()),
                spki_sha256=mtls_raw.get("spkiSha256", ()),
                issuer_spki_sha256=mtls_raw.get("issuerSpkiSha256", ()),
            )
            if mtls_raw is not None
            else None
        )
        required_headers = dict(item.get("requiredHeaders") or {})
        required_header_names: set[str] = set()
        for name, expected in required_headers.items():
            if (
                not isinstance(name, str)
                or "_" in name
                or len(name) > 128
                or HTTP_HEADER_NAME_RE.fullmatch(name) is None
                or not isinstance(expected, str)
                or not expected
                or len(expected.encode("utf-8")) > 8192
                or any(ord(character) < 32 or ord(character) == 127 for character in expected)
            ):
                raise PolicyBundleError(
                    f"principal {principal_id} requiredHeaders must use bounded "
                    "HTTP field names and non-empty text values"
                )
            lower_name = name.lower()
            if lower_name in required_header_names:
                raise PolicyBundleError(
                    f"principal {principal_id} requiredHeaders must not contain "
                    "case-insensitive duplicate field names"
                )
            required_header_names.add(lower_name)
            if name.lower() in RAW_REQUEST_ADMISSION_HEADERS:
                raise PolicyBundleError(
                    f"principal {principal_id} cannot use raw request framing or "
                    f"encoding header {name} as an identity selector"
                )
        proxy_authorization = ProxyAuthorizationPolicy.from_raw(item.get("proxyAuthorization"))
        if not (source_cidrs or mtls or proxy_authorization):
            raise PolicyBundleError(f"principal {principal_id} must define at least one enforceable identity selector")
        source_anchor = bool(source_cidrs) and all(
            ipaddress.ip_network(cidr, strict=True).prefixlen > 0
            for cidr in source_cidrs
        )
        proxy_source_anchor = bool(
            proxy_authorization is not None
            and proxy_authorization.legacy_exact is None
            and proxy_authorization.source_cidrs
            and all(
                ipaddress.ip_network(cidr, strict=True).prefixlen > 0
                for cidr in proxy_authorization.source_cidrs
            )
        )
        if required_headers and not (
            source_anchor or mtls is not None or proxy_source_anchor
        ):
            raise PolicyBundleError(
                f"principal {principal_id} requiredHeaders require a "
                "non-universal source CIDR, verified mtls identity, or "
                "source-bound nonlegacy proxyAuthorization"
            )
        if source_cidrs and all(
            ipaddress.ip_network(cidr, strict=True).prefixlen == 0
            for cidr in source_cidrs
        ) and mtls is None and proxy_authorization is None:
            raise PolicyBundleError(
                f"principal {principal_id} cannot use universal CIDRs as its sole trust anchor"
            )
        principals[principal_id] = PrincipalPolicy(
            id=principal_id,
            source_cidrs=source_cidrs,
            required_headers=required_headers,
            proxy_authorization=proxy_authorization,
            mtls=mtls,
        )

    principal_policies = list(principals.values())
    if any(
        not _principal_selectors_overlap(principal, principal)
        for principal in principal_policies
    ):
        raise PolicyBundleError(
            "principal identity selector set cannot match a coherent request"
        )
    for index, left in enumerate(principal_policies):
        for right in principal_policies[index + 1 :]:
            if _principal_selectors_overlap(left, right):
                raise PolicyBundleError(
                    "principal identity selector sets overlap; identity must be "
                    "statically unambiguous"
                )

    credentials: dict[str, CredentialPolicy] = {}
    for item in credential_items:
        credential_id = item["id"]
        if credential_id in credentials:
            raise PolicyBundleError(f"duplicate credential: {credential_id}")
        kind = item.get("credentialType")
        if kind not in {"oauth2", "static"}:
            raise PolicyBundleError(
                f"credential {credential_id} has an unsupported credentialType"
            )
        provider = str(item.get("provider") or "")
        if (
            not provider
            or normalized_credential_provider(provider) != provider
            or re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", provider) is None
        ):
            raise PolicyBundleError(
                f"credential {credential_id} has a noncanonical provider"
            )
        provider_subject = item.get("providerSubject")
        if (
            not isinstance(provider_subject, str)
            or not provider_subject
            or provider_subject != provider_subject.strip()
            or len(provider_subject.encode("utf-8")) > 512
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in provider_subject
            )
        ):
            raise PolicyBundleError(
                f"credential {credential_id} has an invalid provider subject"
            )
        oauth_client_id = item.get("oauthClientId")
        raw_scopes = item.get("scopes")
        if kind == "oauth2":
            if (
                not isinstance(oauth_client_id, str)
                or not oauth_client_id
                or oauth_client_id != oauth_client_id.strip()
                or len(oauth_client_id.encode("utf-8")) > 512
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in oauth_client_id
                )
            ):
                raise PolicyBundleError(
                    f"OAuth credential {credential_id} requires a canonical oauthClientId"
                )
            scopes = _bounded_unique_strings(
                raw_scopes,
                context=f"OAuth credential {credential_id} scopes",
                maximum_items=64,
                maximum_bytes=512,
            )
            if any(any(character.isspace() for character in scope) for scope in scopes):
                raise PolicyBundleError(
                    f"OAuth credential {credential_id} scopes cannot contain whitespace"
                )
        else:
            if oauth_client_id is not None or raw_scopes is not None:
                raise PolicyBundleError(
                    f"static credential {credential_id} cannot declare OAuth fields"
                )
            oauth_client_id = None
            scopes = ()
        injection = _validate_credential_injection(
            credential_id,
            item.get("injection"),
        )
        if kind == "oauth2":
            _validate_managed_oauth_injection(credential_id, provider, injection)
        credentials[credential_id] = CredentialPolicy(
            id=credential_id,
            kind=kind,
            provider=provider,
            provider_subject=provider_subject,
            oauth_client_id=oauth_client_id,
            scopes=scopes,
            injection=injection,
        )

    routes: list[RoutePolicy] = []
    seen_routes: set[str] = set()
    for item in route_items:
        route_id = item["id"]
        if route_id in seen_routes:
            raise PolicyBundleError(f"duplicate route: {route_id}")
        seen_routes.add(route_id)

        match = item.get("match") or {}
        route_host = _canonical_route_host(match.get("host"), route_id)
        resolved_cidrs = _validate_route_resolved_cidrs(route_id, match)
        methods = frozenset(method.upper() for method in (match.get("methods") or []))
        if not methods:
            raise PolicyBundleError(f"route {route_id} must define methods")
        paths = tuple(match.get("paths") or ())
        if not paths:
            raise PolicyBundleError(f"route {route_id} must define paths")
        route_principals = tuple(item.get("principals") or ())
        for principal_id in route_principals:
            if principal_id != "*" and principal_id not in principals:
                raise PolicyBundleError(
                    f"route {route_id} references unknown principal {principal_id}"
                )
        adapter_type, adapter_config = _validate_closed_adapter_contract(
            route_id,
            item.get("adapter"),
        )
        credential_ref = item.get("credentialRef")
        if credential_ref and credential_ref not in credentials:
            raise PolicyBundleError(f"route {route_id} references unknown credential {credential_ref}")
        _validate_route_credential_binding(
            route_id,
            adapter_type,
            adapter_config,
            credentials.get(credential_ref) if credential_ref else None,
            paths,
        )
        validate_buffered_passthrough_response(
            route_id, adapter_type, adapter_config.get("response")
        )
        if adapter_type != "gmail.v1":
            response_config = adapter_config.get("response")
            if not isinstance(response_config, dict):
                raise PolicyBundleError(f"route {route_id} response policy missing")
            response_mode = response_config.get("mode")
            supported_modes = SUPPORTED_RESPONSE_MODES if adapter_type == "generic.rest" else BUFFERED_RESPONSE_MODES | {"stream"}
            if not isinstance(response_mode, str) or response_mode not in supported_modes:
                raise PolicyBundleError(f"route {route_id} response mode {response_mode!r} is unsupported")
            max_response_bytes = response_config.get("maxBodyBytes")
            if (
                isinstance(max_response_bytes, bool)
                or not isinstance(max_response_bytes, int)
                or max_response_bytes < 0
                or max_response_bytes > 16 * 1024 * 1024
            ):
                raise PolicyBundleError(
                    f"route {route_id} response maxBodyBytes must be an integer between 0 and 16777216"
                )
            if credential_ref:
                _validate_credential_response_projections(
                    route_id,
                    adapter_type,
                    response_config,
                )
            if adapter_type not in {"npm.registry"}:
                _validate_optional_response_release_contract(
                    route_id, response_config, adapter_type
                )
            if (
                response_mode in STREAMING_RESPONSE_MODES
                and response_config.get("allowedHeaders")
            ):
                raise PolicyBundleError(
                    f"route {route_id} streaming responses cannot release upstream headers"
                )
        elif credential_ref:
            _validate_credential_response_projections(
                route_id,
                adapter_type,
                adapter_config.get("response"),
            )
        request_mode = str(((adapter_config.get("request") or {}).get("bodyMode") or ""))
        response_mode = str(((adapter_config.get("response") or {}).get("mode") or ""))
        if (
            credential_ref
            and adapter_type == "generic.rest"
            and response_mode not in CREDENTIAL_BEARING_GENERIC_RESPONSE_MODES
        ):
            raise PolicyBundleError(
                f"route {route_id} credential-bearing generic.rest response mode "
                "must be headersOnly, json or bufferedPassthrough"
            )
        if credential_ref and response_mode in {"any", "stream"}:
            raise PolicyBundleError(
                f"route {route_id} credential-bearing responses require projection or structured validation"
            )
        if (
            credential_ref
            and adapter_type == "generic.rest"
            and request_mode not in CREDENTIAL_BEARING_GENERIC_REQUEST_BODY_MODES
        ):
            raise PolicyBundleError(
                f"route {route_id} credential-bearing generic.rest request bodyMode "
                f"{request_mode!r} is outside the closed buffered allowlist"
            )
        if (
            credential_ref
            and request_mode in STRUCTURED_STREAMING_MODES
            and not methods.issubset({"GET", "HEAD", "OPTIONS"})
        ):
            raise PolicyBundleError(
                f"route {route_id} credential-bearing mutating request streams must buffer before forwarding"
            )
        if adapter_type == "generic.rest":
            request_config = adapter_config.get("request") or {}
            response_config = adapter_config.get("response") or {}
            if not request_config or not response_config:
                raise PolicyBundleError(
                    f"route {route_id} uses generic.rest and must define request and response schemas"
                )
            missing_request = sorted(
                key for key in ("allowedHeaders", "allowedQueryKeys", "bodyMode", "maxBodyBytes") if key not in request_config
            )
            missing_response = sorted(key for key in ("mode", "maxBodyBytes") if key not in response_config)
            if missing_request or missing_response:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest policy is missing explicit controls: "
                    f"request={missing_request} response={missing_response}"
                )
            if request_mode in STRUCTURED_STREAMING_MODES:
                _validate_response_field_paths(
                    route_id,
                    request_config,
                    f"generic.rest {request_mode} request",
                )
            raw_allowed_headers = request_config.get("allowedHeaders")
            if not isinstance(raw_allowed_headers, list) or any(
                not isinstance(header, str)
                or not header
                or len(header) > 128
                or HTTP_HEADER_NAME_RE.fullmatch(header) is None
                for header in raw_allowed_headers
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedHeaders must contain HTTP field names"
                )
            allowed_headers = [header.lower() for header in raw_allowed_headers]
            if len(allowed_headers) != len(set(allowed_headers)):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedHeaders must be unique after normalization"
                )
            allowed_header_set = set(allowed_headers)
            forbidden_headers = sorted(
                header
                for header in allowed_header_set
                if header in NON_FORWARDABLE_AGENT_HEADERS
                or is_serverware_internal_header(header)
            )
            if forbidden_headers:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allows credential, framing, transport, "
                    "or internal headers "
                    f"supplied by the agent: {forbidden_headers}"
                )
            required_headers = _validate_generic_required_headers(
                route_id,
                request_config,
                allowed_header_set,
            )
            raw_allowed_media_types = request_config.get("allowedMediaTypes")
            if raw_allowed_media_types is not None and (
                not isinstance(raw_allowed_media_types, list)
                or any(
                    not isinstance(media_type, str)
                    or media_type != media_type.lower()
                    or _MEDIA_TYPE_RE.fullmatch(media_type) is None
                    for media_type in raw_allowed_media_types
                )
                or len(raw_allowed_media_types) != len(set(raw_allowed_media_types))
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedMediaTypes must contain "
                    "unique lower-case media types"
                )
            expected_request_media_type = GENERIC_REQUEST_MEDIA_TYPES.get(
                request_mode
            )
            if (
                expected_request_media_type is not None
                and raw_allowed_media_types != [expected_request_media_type]
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest bodyMode {request_mode} requires "
                    f"the exact allowedMediaTypes contract "
                    f"[{expected_request_media_type!r}]"
                )
            if request_mode == "none" and raw_allowed_media_types not in (
                None,
                [],
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest bodyMode none cannot admit "
                    "request media types"
                )
            raw_allowed_query = request_config.get("allowedQueryKeys")
            if not isinstance(raw_allowed_query, list) or any(
                not isinstance(key, str) or not key or len(key) > 256 for key in raw_allowed_query
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedQueryKeys must contain bounded strings"
                )
            if len(raw_allowed_query) != len(set(raw_allowed_query)):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedQueryKeys must be unique"
                )
            if credential_ref:
                target = credential_injection_target(credentials[credential_ref].injection)
                if target is not None:
                    location, name = target
                    if location == "header" and (name in allowed_header_set or name in required_headers):
                        raise PolicyBundleError(
                            f"route {route_id} generic.rest agent header {name} collides with credential injection"
                        )
                    if location == "query" and name in set(raw_allowed_query):
                        raise PolicyBundleError(
                            f"route {route_id} generic.rest agent query key {name} collides with credential injection"
                        )
        request_config = adapter_config.get("request") or {}
        allowed_headers_for_discard = {
            str(name).lower()
            for name in request_config.get("allowedHeaders") or []
        }
        raw_required_headers = request_config.get("requiredHeaders") or {}
        required_headers_for_discard = (
            {str(name).lower() for name in raw_required_headers}
            if isinstance(raw_required_headers, dict)
            else set()
        )
        credential_target = (
            credential_injection_target(credentials[credential_ref].injection)
            if credential_ref
            else None
        )
        credential_header = (
            credential_target[1]
            if credential_target is not None and credential_target[0] == "header"
            else None
        )
        principal_identity_headers = {
            str(name).lower()
            for principal_id, principal_policy in principals.items()
            if "*" in route_principals or principal_id in route_principals
            for name in principal_policy.required_headers
        }
        provider_identity_collisions = _normalized_header_aliases(
            allowed_headers_for_discard | required_headers_for_discard
        ).intersection(_normalized_header_aliases(principal_identity_headers))
        if provider_identity_collisions:
            raise PolicyBundleError(
                f"route {route_id} provider request headers collide with principal "
                f"identity headers: {', '.join(sorted(provider_identity_collisions))}"
            )
        validate_discard_headers(
            route_id,
            request_config,
            allowed_headers=allowed_headers_for_discard,
            required_headers=required_headers_for_discard,
            credential_header=credential_header,
            principal_identity_headers=principal_identity_headers,
        )
        jit = dict(item.get("jit") or {})
        if jit:
            for required_key in ("mode", "ttlSeconds", "maxUses", "consumeOn", "binding", "approvers"):
                if required_key not in jit:
                    raise PolicyBundleError(f"route {route_id} JIT policy must define {required_key}")
            if jit.get("mode") != "perOperation":
                raise PolicyBundleError(f"route {route_id} JIT mode must be perOperation")
            if jit.get("consumeOn") != "forwardStart":
                raise PolicyBundleError(f"route {route_id} JIT consumeOn must be forwardStart")
            binding = jit.get("binding") or {}
            if binding.get("type") not in {"requestDigest", "operationDigest"}:
                raise PolicyBundleError(
                    f"route {route_id} JIT binding must use requestDigest or operationDigest"
                )
            binding_fields = set(binding.get("fields") or [])
            missing_fields = sorted(REQUIRED_JIT_BINDING_FIELDS - binding_fields)
            if missing_fields:
                raise PolicyBundleError(
                    f"route {route_id} JIT binding is missing required fields: {', '.join(missing_fields)}"
                )
            approvers = jit.get("approvers") or {}
            if int(approvers.get("quorum", 0)) != 1:
                raise PolicyBundleError(f"route {route_id} JIT approver quorum must be 1")
            approver_users = approvers.get("users")
            if not isinstance(approver_users, list) or not approver_users:
                raise PolicyBundleError(f"route {route_id} JIT policy must define allowed approver users")
            if len(approver_users) > 32 or len(set(approver_users)) != len(approver_users):
                raise PolicyBundleError(
                    f"route {route_id} JIT approver users must contain 1-32 unique IDs"
                )
            if any(
                not isinstance(user_id, str)
                or re.fullmatch(
                    r"(?:user|oidc):[A-Za-z0-9][A-Za-z0-9._:@+|/\-]{0,239}",
                    user_id,
                )
                is None
                for user_id in approver_users
            ):
                raise PolicyBundleError(
                    f"route {route_id} JIT approvers must use explicit user: or oidc: IDs"
                )
            authn = approvers.get("authn") or {}
            if authn.get("webauthnRequired") and not authn.get("allowedAuthenticatorClasses"):
                raise PolicyBundleError(f"route {route_id} WebAuthn JIT policy must define allowed authenticator classes")
        raw_route_constraints = item.get("constraints")
        if raw_route_constraints is not None and not isinstance(
            raw_route_constraints, list
        ):
            raise PolicyBundleError(
                f"route {route_id} constraints must be an array"
            )
        raw_constraints = list(raw_route_constraints or [])
        adapter_value_rules = (adapter_config.get("request") or {}).get(
            "valueRules"
        )
        if adapter_value_rules:
            raw_constraints.append(
                {
                    "id": "adapter.request.valueRules",
                    "type": "requestValue",
                    "rules": copy.deepcopy(adapter_value_rules),
                }
            )
        constraints = _validate_constraints(route_id, raw_constraints)
        validate_buffered_passthrough_response(
            route_id, adapter_type, adapter_config.get("response"), constraints
        )
        shared_rate_limits = [
            constraint
            for constraint in constraints
            if constraint.get("type") == "rateLimit"
            and constraint.get("store", "local") == "shared"
        ]
        if jit.get("required") is True and shared_rate_limits and (
            jit.get("maxUses") != 1 or jit.get("consumeOn") != "forwardStart"
        ):
            raise PolicyBundleError(
                f"route {route_id} composed JIT and shared quotas require "
                "maxUses=1 and consumeOn=forwardStart"
            )
        _validate_credential_request_body_constraint(
            route_id,
            adapter_type,
            request_mode,
            credential_ref,
            constraints,
        )
        operation_source_kinds = _validate_generic_operation_sources(
            route_id,
            adapter_type,
            adapter_config,
            paths,
        )
        operation_source_kinds.update(
            _validate_request_value_sources(
                route_id,
                adapter_type,
                adapter_config,
                paths,
                constraints,
                operation_source_kinds,
            )
        )
        _validate_durable_policy_sources(
            route_id,
            adapter_type,
            adapter_config,
            paths,
            operation_source_kinds,
            constraints,
        )
        _validate_response_envelope_coverage(
            route_id,
            adapter_type,
            adapter_config,
            paths,
            constraints,
        )
        _validate_response_binding_sources(
            route_id,
            adapter_type,
            adapter_config,
            operation_source_kinds,
            constraints,
        )
        _validate_provider_account_rate_limits(
            route_id,
            constraints,
            credentials.get(credential_ref) if credential_ref else None,
        )
        _validate_adapter_security_invariants(
            route_id,
            route_host,
            adapter_type,
            adapter_config,
            credential_ref,
            jit,
            methods,
            paths,
            constraints,
            signed_policy,
        )
        response_mode = str((adapter_config.get("response") or {}).get("mode") or "")
        if response_mode in STREAMING_RESPONSE_MODES and any(
            constraint.get("type")
            in {
                "responseDateWindow",
                "responseJson",
                "responseBinding",
                "traversalBudget",
            }
            for constraint in constraints
        ):
            raise PolicyBundleError(
                f"route {route_id} cannot stream a response that requires whole-response constraint validation"
            )

        routes.append(
            RoutePolicy(
                id=route_id,
                principals=route_principals,
                scheme=(match.get("scheme") or "https").lower(),
                host=route_host,
                port=int(match.get("port", 443)),
                methods=methods,
                path_templates=paths,
                path_regexes=tuple(_path_template_to_regex(path) for path in paths),
                credential_ref=credential_ref,
                adapter_type=adapter_type,
                adapter_config=adapter_config,
                resolved_cidrs=resolved_cidrs,
                constraints=constraints,
                jit=jit,
            )
        )

    _validate_x_search_route_conflicts(routes)
    for index, left in enumerate(routes):
        for right in routes[index + 1 :]:
            if (left.scheme, left.host, left.port) != (right.scheme, right.host, right.port):
                continue
            if not left.methods.intersection(right.methods):
                continue
            if not set(left.principals).intersection(right.principals) and "*" not in left.principals and "*" not in right.principals:
                continue
            for left_path in left.path_templates:
                for right_path in right.path_templates:
                    if _path_shape(left_path) == _path_shape(right_path) and _path_specificity(left_path) == _path_specificity(right_path):
                        raise PolicyBundleError(
                            f"routes {left.id} and {right.id} have ambiguous path templates {left_path} and {right_path}"
                        )
    routes.sort(key=lambda route: route.id)
    if not validate_schema:
        validate_policy_schema(raw)
    frozen_principals = FrozenDict(
        {
            principal_id: PrincipalPolicy(
                id=principal.id,
                source_cidrs=principal.source_cidrs,
                required_headers=_deep_freeze(principal.required_headers),
                proxy_authorization=principal.proxy_authorization,
                mtls=principal.mtls,
            )
            for principal_id, principal in principals.items()
        }
    )
    frozen_credentials = FrozenDict(
        {
            credential_id: CredentialPolicy(
                id=credential.id,
                kind=credential.kind,
                provider=credential.provider,
                provider_subject=credential.provider_subject,
                oauth_client_id=credential.oauth_client_id,
                scopes=credential.scopes,
                injection=_deep_freeze(credential.injection),
            )
            for credential_id, credential in credentials.items()
        }
    )
    frozen_routes = tuple(
        RoutePolicy(
            id=route.id,
            principals=route.principals,
            host=route.host,
            port=route.port,
            scheme=route.scheme,
            methods=route.methods,
            path_templates=route.path_templates,
            path_regexes=route.path_regexes,
            credential_ref=route.credential_ref,
            adapter_type=route.adapter_type,
            adapter_config=_deep_freeze(route.adapter_config),
            resolved_cidrs=route.resolved_cidrs,
            constraints=tuple(
                _deep_freeze(constraint) for constraint in route.constraints
            ),
            jit=_deep_freeze(route.jit),
        )
        for route in routes
    )
    from serverware.policy_route_authority import admit as admit_route_authority
    compiled_route_authority = admit_route_authority(raw)
    return PolicySnapshot(
        raw=_deep_freeze(raw),
        hash=policy_hash(raw),
        principals=frozen_principals,
        credentials=frozen_credentials,
        routes=frozen_routes,
        compiled_route_authority=_deep_freeze(compiled_route_authority),
    )


def get_policy_snapshot() -> PolicySnapshot | None:
    global _POLICY_BUNDLE_LOADER, _SNAPSHOT_CACHE
    with _SNAPSHOT_CACHE_LOCK:
        if _POLICY_BUNDLE_LOADER.path != POLICY_BUNDLE_PATH:
            _POLICY_BUNDLE_LOADER = PolicyBundleLoader(POLICY_BUNDLE_PATH)
        elif _SNAPSHOT_CACHE is None:
            _POLICY_BUNDLE_LOADER.cache = None
        snapshot = _POLICY_BUNDLE_LOADER.load()
        _SNAPSHOT_CACHE = _POLICY_BUNDLE_LOADER.cache
        return snapshot


def policy_uses_atomic_release_authorization(snapshot: PolicySnapshot) -> bool:
    return any(
        route.jit.get("required") is True
        or any(
            constraint.get("type") == "rateLimit"
            and constraint.get("store", "local") == "shared"
            and constraint.get("phase", "request") == "request"
            for constraint in route.constraints
        )
        for route in snapshot.routes
    )


def _policy_snapshot_authority(
    snapshot: PolicySnapshot,
) -> tuple[str, int, int, str]:
    metadata = snapshot.raw.get("metadata")
    if not isinstance(metadata, dict):
        raise PolicyBundleError("policy metadata is missing")
    policy_id = metadata.get("id")
    sequence = metadata.get("sequence")
    rollback_epoch = metadata.get("rollbackEpoch")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyBundleError("policy metadata id is invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise PolicyBundleError("policy metadata sequence is invalid")
    if not isinstance(rollback_epoch, int) or isinstance(rollback_epoch, bool):
        raise PolicyBundleError("policy metadata rollbackEpoch is invalid")
    if sequence < POLICY_MIN_SEQUENCE:
        raise PolicyBundleError(
            f"policy sequence {sequence} is below configured floor {POLICY_MIN_SEQUENCE}"
        )
    if rollback_epoch < POLICY_MIN_ROLLBACK_EPOCH:
        raise PolicyBundleError(
            "policy rollbackEpoch "
            f"{rollback_epoch} is below configured floor {POLICY_MIN_ROLLBACK_EPOCH}"
        )
    return policy_id, sequence, rollback_epoch, snapshot.hash


def verify_policy_high_water(
    snapshot: PolicySnapshot,
    *,
    _connection: Any | None = None,
    _allow_pending: bool = False,
) -> dict[str, Any]:
    """Verify independently protected rollback state without changing it.

    The metadata store is the monotonic authority. If it shares a rollback
    domain with the policy file, coherent rollback protection remains an
    external deployment boundary described by POLICY_HIGH_WATER_TRUST_BOUNDARY.
    """
    policy_id, sequence, rollback_epoch, snapshot_hash = (
        _policy_snapshot_authority(snapshot)
    )
    from serverware import db

    try:
        return db.verify_policy_high_water(
            policy_id=policy_id,
            sequence=sequence,
            rollback_epoch=rollback_epoch,
            policy_hash=snapshot_hash,
            _connection=_connection,
            _allow_pending=_allow_pending,
        )
    except db.MetadataStoreError as exc:
        raise PolicyBundleError(f"policy rollback protection rejected bundle: {exc}") from exc
    except Exception as exc:
        raise PolicyBundleError(
            "policy rollback protection state is unavailable"
        ) from exc


def enforce_policy_high_water(snapshot: PolicySnapshot) -> dict[str, Any]:
    """Compatibility verifier; publication is the only authority-advance path."""
    return verify_policy_high_water(snapshot)


def _atomic_write_policy(path: Path, payload: str) -> None:
    payload_bytes = payload.encode("utf-8")
    if not 1 <= len(payload_bytes) <= MAX_POLICY_BUNDLE_BYTES:
        raise PolicyBundleError(
            f"policy bundle must contain 1-{MAX_POLICY_BUNDLE_BYTES} bytes"
        )
    _atomic_write_secure_file(
        path,
        payload_bytes,
        label="policy bundle",
        mode=0o600,
    )


@dataclass(frozen=True)
class PreparedPolicyPublication:
    signed: dict[str, Any]
    snapshot: PolicySnapshot
    payload: str
    payload_bytes: bytes
    signing_trust_identity: PolicySigningTrustIdentity


_POLICY_PUBLICATION_CAPABILITY_GUARD = object()


@dataclass(frozen=True)
class _StagedPolicyPublication:
    prepared: PreparedPolicyPublication
    previous_policy_hash: str | None
    _guard: object


def _prepare_policy_publication(raw: dict[str, Any]) -> PreparedPolicyPublication:
    signed = sign_policy_bundle(raw)
    canonical_payload = canonical_json(signed).encode("utf-8")
    if not 1 <= len(canonical_payload) <= MAX_POLICY_BUNDLE_BYTES:
        raise PolicyBundleError(
            "canonical policy bundle exceeds the publication size bound"
        )
    payload = json.dumps(signed, indent=2, sort_keys=True) + "\n"
    payload_bytes = payload.encode("utf-8")
    if not 1 <= len(payload_bytes) <= MAX_POLICY_BUNDLE_BYTES:
        raise PolicyBundleError(
            "persisted policy bundle exceeds the publication size bound"
        )
    signing_trust = _load_policy_signing_trust()
    snapshot = compile_policy_bundle(
        signed,
        verify_signature=True,
        validate_schema=True,
        signing_trust=signing_trust,
    )
    _recheck_policy_signing_trust(signing_trust.identity)
    return PreparedPolicyPublication(
        signed=signed,
        snapshot=snapshot,
        payload=payload,
        payload_bytes=payload_bytes,
        signing_trust_identity=signing_trust.identity,
    )


def _stage_policy_publication(
    prepared: PreparedPolicyPublication,
    *,
    connection: Any | None = None,
) -> dict[str, Any]:
    policy_id, sequence, rollback_epoch, snapshot_hash = (
        _policy_snapshot_authority(prepared.snapshot)
    )
    from serverware import db

    try:
        return db.stage_policy_publication(
            policy_id=policy_id,
            sequence=sequence,
            rollback_epoch=rollback_epoch,
            policy_hash=snapshot_hash,
            _connection=connection,
        )
    except db.MetadataStoreError as exc:
        raise PolicyBundleError(
            f"policy rollback protection rejected bundle: {exc}"
        ) from exc
    except Exception as exc:
        raise PolicyBundleError(
            "policy rollback protection state is unavailable"
        ) from exc


def _stage_prepared_policy_for_transaction(
    prepared: PreparedPolicyPublication,
    *,
    expected_previous_policy_hash: str | None = None,
    require_expected_predecessor: bool = False,
) -> _StagedPolicyPublication:
    staged = _stage_policy_publication(prepared)
    previous_policy_hash = staged.get("previous_policy_hash")
    if previous_policy_hash is not None and (
        not isinstance(previous_policy_hash, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", previous_policy_hash) is None
    ):
        raise PolicyBundleError("policy publication predecessor is invalid")
    if (
        require_expected_predecessor
        and previous_policy_hash != expected_previous_policy_hash
    ):
        raise PolicyBundleError(
            "policy publication predecessor changed before staging"
        )
    return _StagedPolicyPublication(
        prepared=prepared,
        previous_policy_hash=previous_policy_hash,
        _guard=_POLICY_PUBLICATION_CAPABILITY_GUARD,
    )


def _stage_policy_bundle_for_transaction(
    raw: dict[str, Any],
    *,
    expected_previous_policy_hash: str | None,
) -> _StagedPolicyPublication:
    """Create the only capability accepted by the transactional installer."""
    return _stage_prepared_policy_for_transaction(
        _prepare_policy_publication(raw),
        expected_previous_policy_hash=expected_previous_policy_hash,
        require_expected_predecessor=True,
    )


def _install_staged_policy_in_transaction(
    staged_publication: _StagedPolicyPublication,
    *,
    connection: Any,
) -> tuple[PolicySnapshot, PolicyFileIdentity]:
    if not _policy_publication_lock_held():
        raise PolicyBundleError(
            "policy publication transaction requires the publication lock"
        )
    if (
        not isinstance(staged_publication, _StagedPolicyPublication)
        or staged_publication._guard is not _POLICY_PUBLICATION_CAPABILITY_GUARD
    ):
        raise PolicyBundleError(
            "policy publication transaction requires a private staged capability"
        )
    prepared = staged_publication.prepared
    from serverware import db

    policy_id, sequence, rollback_epoch, snapshot_hash = (
        _policy_snapshot_authority(prepared.snapshot)
    )
    try:
        staged = _stage_policy_publication(prepared, connection=connection)
        previous_policy_hash = staged.get("previous_policy_hash")
        if previous_policy_hash != staged_publication.previous_policy_hash:
            raise PolicyBundleError(
                "policy publication predecessor changed before installation"
            )
        db.advance_policy_high_water(
            policy_id=policy_id,
            sequence=sequence,
            rollback_epoch=rollback_epoch,
            policy_hash=snapshot_hash,
            _connection=connection,
        )
        _atomic_write_policy(POLICY_BUNDLE_PATH, prepared.payload)
        persisted_payload, identity = _read_stable_policy_file(
            POLICY_BUNDLE_PATH
        )
        if persisted_payload != prepared.payload_bytes:
            raise PolicyBundleError(
                "persisted policy bundle did not match the compiled publication"
            )
        persisted_trust = _load_policy_signing_trust()
        persisted_snapshot = compile_policy_bundle(
            _decode_raw_policy(POLICY_BUNDLE_PATH, persisted_payload),
            verify_signature=True,
            validate_schema=True,
            signing_trust=persisted_trust,
        )
        if (
            persisted_snapshot.hash != snapshot_hash
            or canonical_json(persisted_snapshot.raw)
            != canonical_json(prepared.signed)
        ):
            raise PolicyBundleError(
                "persisted policy bundle changed during publication"
            )
        verify_policy_high_water(
            persisted_snapshot,
            _connection=connection,
            _allow_pending=True,
        )
        _recheck_policy_path_identity(POLICY_BUNDLE_PATH, identity)
        _recheck_policy_signing_trust(prepared.signing_trust_identity)
        verify_policy_high_water(
            persisted_snapshot,
            _connection=connection,
            _allow_pending=True,
        )
        db.commit_policy_publication(
            policy_id=policy_id,
            sequence=sequence,
            rollback_epoch=rollback_epoch,
            policy_hash=snapshot_hash,
            previous_policy_hash=previous_policy_hash,
            _connection=connection,
        )
        verify_policy_high_water(
            persisted_snapshot,
            _connection=connection,
        )
        _recheck_policy_path_identity(POLICY_BUNDLE_PATH, identity)
        _recheck_policy_signing_trust(prepared.signing_trust_identity)
        return persisted_snapshot, identity
    except db.MetadataStoreError as exc:
        raise PolicyBundleError(
            f"policy rollback protection rejected bundle: {exc}"
        ) from exc


def _write_policy_bundle_in_transaction(
    staged_publication: _StagedPolicyPublication,
    *,
    connection: Any,
) -> PolicySnapshot:
    """Install a candidate whose DB commit is owned by the caller.

    The shared publication lock keeps cooperative readers out until the caller
    commits or rolls back. If the process dies after replacement, rolled-back
    high-water/publication rows make the on-disk candidate unreadable; retrying
    the exact snapshot can stage and commit it again.
    """
    snapshot, _ = _install_staged_policy_in_transaction(
        staged_publication,
        connection=connection,
    )
    global _POLICY_BUNDLE_LOADER, _SNAPSHOT_CACHE
    with _SNAPSHOT_CACHE_LOCK:
        _SNAPSHOT_CACHE = None
        _POLICY_BUNDLE_LOADER.cache = None
    return snapshot


def _restore_policy_after_failed_publication(
    previous_payload: bytes | None,
) -> None:
    if previous_payload is None:
        _unlink_secure_file(
            POLICY_BUNDLE_PATH,
            label="policy bundle",
            expected_mode=0o600,
            maximum_size=MAX_POLICY_BUNDLE_BYTES,
        )
        return
    try:
        current_payload, _ = _read_stable_policy_file(POLICY_BUNDLE_PATH)
    except PolicyBundleError:
        current_payload = None
    if current_payload == previous_payload:
        return
    _atomic_write_policy(
        POLICY_BUNDLE_PATH,
        previous_payload.decode("utf-8"),
    )


def write_policy_bundle(
    raw: dict[str, Any],
    path: Path = POLICY_BUNDLE_PATH,
) -> PolicySnapshot:
    """Durably publish one signed active policy through monotonic authority."""
    if Path(path) != Path(POLICY_BUNDLE_PATH):
        raise PolicyBundleError(
            "active policy publication path is fixed by configuration"
        )
    global _POLICY_BUNDLE_LOADER, _SNAPSHOT_CACHE
    with _policy_publication_lock():
        prepared = _prepare_policy_publication(raw)
        try:
            previous_payload, _ = _read_stable_policy_file(POLICY_BUNDLE_PATH)
        except PolicyBundleError:
            if not _secure_path_exists(
                POLICY_BUNDLE_PATH,
                label="policy bundle",
            ):
                previous_payload = None
            else:
                raise
        with _SNAPSHOT_CACHE_LOCK:
            _SNAPSHOT_CACHE = None
            _POLICY_BUNDLE_LOADER.cache = None
        # This commit is deliberately separate: a crash leaves durable pending
        # intent, never reader authority. The transaction below revalidates the
        # same digest after acquiring the metadata publication lock.
        staged_publication = _stage_prepared_policy_for_transaction(prepared)
        try:
            from serverware import db

            with db.connect() as connection:
                db.lock_policy_publication(connection)
                snapshot, _ = _install_staged_policy_in_transaction(
                    staged_publication,
                    connection=connection,
                )
        except Exception:
            authoritative = get_policy_snapshot()
            if authoritative is not None:
                if authoritative.hash != prepared.snapshot.hash:
                    raise
            else:
                try:
                    verify_policy_high_water(prepared.snapshot)
                except PolicyBundleError:
                    _restore_policy_after_failed_publication(previous_payload)
                raise
        loaded = get_policy_snapshot()
        if loaded is None or loaded.hash != prepared.snapshot.hash:
            raise PolicyBundleError(
                "committed policy publication could not be reloaded exactly"
            )
        return loaded


def demo_policy_bundle(credential_id: str = "cred-demo-bearer") -> dict[str, Any]:
    proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-agent-proxy-token").hexdigest()
    bound_proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-bound-proxy-token").hexdigest()
    trusted_source_cidrs = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]

    def structured_proof_route(
        slug: str,
        response_mode: str,
        allowed_fields: list[str],
        response_limits: dict[str, int],
    ) -> dict[str, Any]:
        return {
            "id": f"demo.proof.stream.{slug}",
            "principals": ["agent:demo"],
            "match": {
                "scheme": "https",
                "host": "demo-upstream",
                "port": 8443,
                "methods": ["GET"],
                "paths": [f"/proof-stream/{slug}"],
            },
            "adapter": {
                "type": "generic.rest",
                "config": {
                    "request": {
                        "allowedQueryKeys": [],
                        "allowedHeaders": ["accept", "user-agent"],
                        "allowedMediaTypes": [],
                        "bodyMode": "none",
                        "maxBodyBytes": 0,
                    },
                    "response": {
                        "mode": response_mode,
                        "maxBodyBytes": 1048576,
                        **response_limits,
                        "allowedFields": allowed_fields,
                    },
                },
            },
        }

    bundle = {
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
                "sourceCidrs": list(trusted_source_cidrs),
                "requiredHeaders": {"X-Serverware-Agent": "demo-agent"},
            },
            {
                "id": "agent:demo-proxy-token",
                "sourceCidrs": list(trusted_source_cidrs),
                "requiredHeaders": {"X-Serverware-Agent": "demo-token-agent"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "demo-sidecar-token",
                    "tokenSha256": proxy_token_sha256,
                    "sourceCidrs": list(trusted_source_cidrs),
                    "expiresAtEpochMs": 4102444800000,
                },
            },
            {
                "id": "agent:demo-source-bound-proxy-token",
                "sourceCidrs": list(trusted_source_cidrs),
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
                "credentialType": "static",
                "provider": "demo",
                "providerSubject": "demo-service-account",
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
                            "allowedQueryKeys": ["reflectCredential"],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["application/json"],
                            "bodyMode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": ["audit_marker"],
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
                                "credential_marker",
                                "credential_reflection",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "demo-echo-json-body",
                        "type": "jsonBody",
                        "contentTypes": ["application/json"],
                        "allowedFields": ["audit_marker"],
                        "fields": {
                            "audit_marker": {
                                "type": "string",
                                "maxLength": 256,
                            }
                        },
                    }
                ],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": ["chunks", "chunkSize", "reflectCredential"],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": [],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["application/octet-stream"],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["application/x-ndjson"],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["application/json"],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["text/event-stream"],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["application/json"],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": [
                                "application/x-www-form-urlencoded"
                            ],
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
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedMediaTypes": ["text/csv"],
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
                            ],
                        },
                    },
                },
            },
            structured_proof_route(
                "jsonl",
                "jsonlStream",
                ["index", "kept", "nested.safe", "sawSecret"],
                {"maxLineBytes": 8192},
            ),
            structured_proof_route(
                "json-array",
                "jsonArrayStream",
                ["index", "kept", "nested.safe", "sawSecret"],
                {"maxItemBytes": 8192},
            ),
            structured_proof_route(
                "json-sse",
                "jsonSseStream",
                ["index", "kept", "nested.safe", "sawSecret"],
                {"maxEventBytes": 8192, "maxLineBytes": 8192},
            ),
            structured_proof_route(
                "json-nested",
                "jsonNestedStream",
                [
                    "requestId",
                    "profile.email",
                    "profile.settings.theme",
                    "items.id",
                    "items.details.safe",
                    "audit.trace",
                    "sawSecret",
                ],
                {"maxNestedBytes": 262144},
            ),
            structured_proof_route(
                "form",
                "formUrlencodedStream",
                ["kept", "safe", "sawSecret"],
                {"maxPairBytes": 8192},
            ),
            structured_proof_route(
                "csv",
                "csvStream",
                ["id", "public", "safe_note", "sawSecret"],
                {"maxRecordBytes": 8192},
            ),
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
                        "request": provider_request_profile("gmail.v1"),
                        "maxAgeDays": 30,
                        "maxResults": 10,
                        "forceQuery": True,
                        "allowMessageGetOnlyFromPriorSearch": True,
                        "cacheTtlSeconds": 1800,
                        "denyEquivalentEndpoints": ["threads", "history", "attachments", "imap"],
                        "response": {
                            "validateInternalDate": True,
                            "validateListByMetadataFetch": True,
                            "metadataFetch": {
                                "maxMessages": 10,
                                "perRequestTimeoutMs": 1500,
                                "totalTimeoutMs": 8000,
                                "maxBodyBytes": 4096,
                            },
                            "maxBodyBytes": 1048576,
                            "allowedFields": [
                                "id",
                                "threadId",
                                "labelIds",
                                "snippet",
                                "internalDate",
                                "payload.headers",
                                "nextPageToken",
                            ],
                            "allowedHeaders": [],
                            "allowedMessageHeaderNames": ["From", "Subject", "Date"],
                            "error": {
                                "mode": "json",
                                "maxBodyBytes": 65536,
                                "allowedFields": [
                                    "error.code",
                                    "error.status",
                                    "error.message",
                                    "error.errors.reason",
                                    "error.errors.domain",
                                ],
                                "allowedHeaders": ["retry-after", "www-authenticate"],
                                "onInvalid": "block",
                            },
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
                        "operations": ["gmail.messages.list"],
                        "items": ["messages"],
                        "dateFields": ["internalDate"],
                        "formats": ["epochMillis"],
                        "maxAgeDays": 30,
                        "required": True,
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
                        "request": provider_request_profile("x.v2", "controlledWrite"),
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
                        "description": "The Docker fixture can publish at most one tweet per UTC calendar day for its single simulated X account; the quota resets at 00:00 UTC.",
                        "max": 1,
                        "calendarWindow": "utcDay",
                        "store": "shared",
                        "key": {
                            "scope": ["route", "operation"],
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
                        "request": provider_request_profile("x.v2", "recentSearchOnly"),
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
                                "meta.next_token",
                                "authorization_present",
                                "authorization_scheme",
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
                        "formats": ["rfc3339"],
                        "required": True,
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
                        "items": ["data"],
                        "dateFields": ["created_at"],
                        "formats": ["rfc3339"],
                        "maxAgeDays": 7,
                        "required": True,
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
                    "methods": ["GET"],
                    "paths": ["/2/**"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "request": provider_request_profile("x.v2", "readOnly"),
                        "mode": "readOnly",
                        "blockWrites": True,
                        "appIds": ["demo-x-app"],
                        "allowedReadOperations": ["tweets.read", "users.read"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 1048576,
                            "allowedFields": [
                                "data",
                                "includes",
                                "meta",
                                "errors",
                                "title",
                                "detail",
                                "type",
                                "status",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-readonly-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "Only tweet and user reads are admitted; search, private-data families, unknown operations, and streaming endpoints remain blocked.",
                        "allowedOperations": ["tweets.read", "users.read"],
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
                        "request": provider_request_profile("npm.registry"),
                        "operations": ["publish", "distTagWrite"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "package",
                                "version",
                                "published",
                                "tag",
                                "dist_tag_written",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                            "allowedHeaders": [],
                            "error": {
                                "mode": "json",
                                "maxBodyBytes": 65536,
                                "allowedFields": ["error", "reason", "code"],
                                "allowedHeaders": ["retry-after", "www-authenticate"],
                                "onInvalid": "block",
                            },
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "npm-sensitive-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "Only publish and dist-tag writes may reach this JIT-protected npm route.",
                        "allowedOperations": ["npm.publish", "npm.distTagWrite"],
                    },
                    {
                        "id": "npm-publish-identity-binding",
                        "type": "responseBinding",
                        "phase": "response",
                        "operations": ["npm.publish"],
                        "successStatusCodes": [200],
                        "contentTypes": ["application/json"],
                        "bindings": [
                            {
                                "id": "package-name",
                                "operationField": "packageName",
                                "responseField": "package",
                                "comparison": "exactString",
                            },
                            {
                                "id": "package-version",
                                "operationField": "packageVersion",
                                "responseField": "version",
                                "comparison": "exactString",
                            },
                        ],
                    },
                    {
                        "id": "npm-publish-success",
                        "type": "responseJson",
                        "phase": "response",
                        "operations": ["npm.publish"],
                        "required": True,
                        "fields": {
                            "published": {
                                "required": True,
                                "type": "boolean",
                                "equals": True,
                            }
                        },
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
                            "query",
                            "selectedHeaders",
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
                            "userVerification": "required",
                            "allowedAuthenticatorClasses": ["yubikey", "hardware"],
                            "requireHardwareAttestation": True,
                        },
                    },
                },
            },
        ],
    }
    bundle["credentials"] = [
        {
            "id": credential_id,
            "credentialType": "static",
            "provider": "demo",
            "providerSubject": "demo-service-account",
            "injection": {"type": "bearer", "header": "Authorization"},
        },
        {
            "id": "cred-demo-google-oauth",
            "credentialType": "oauth2",
            "provider": "google",
            "providerSubject": "demo-google-subject",
            "oauthClientId": "demo-google-client.apps.googleusercontent.com",
            "scopes": [
                "https://www.googleapis.com/auth/gmail.readonly",
            ],
            "injection": {
                "type": "bearer",
                "header": "Authorization",
                "field": "access_token",
            },
        },
        {
            "id": "cred-demo-x-oauth",
            "credentialType": "oauth2",
            "provider": "x",
            "providerSubject": "demo-x-user-id",
            "oauthClientId": "demo-x-app",
            "scopes": ["tweet.read", "tweet.write", "users.read"],
            "injection": {
                "type": "bearer",
                "header": "Authorization",
                "field": "access_token",
            },
        },
        {
            "id": "cred-demo-npm-token",
            "credentialType": "static",
            "provider": "npm",
            "providerSubject": "demo-npm-account",
            "injection": {"type": "bearer", "header": "Authorization"},
        },
    ]

    response_content_types = {
        "headersOnly": [],
        "json": ["application/json"],
        "any": ["application/octet-stream"],
        "stream": ["application/octet-stream"],
        "jsonlStream": ["application/x-ndjson"],
        "jsonArrayStream": ["application/json"],
        "jsonSseStream": ["text/event-stream"],
        "jsonNestedStream": ["application/json"],
        "formUrlencodedStream": ["application/x-www-form-urlencoded"],
        "csvStream": ["text/csv"],
    }
    error_profile = {
        "mode": "json",
        "maxBodyBytes": 65536,
        "allowedFields": ["error", "code", "message"],
        "allowedHeaders": ["retry-after", "www-authenticate"],
        "onInvalid": "block",
    }
    provider_bindings = {
        "gmail.v1": {
            "credentialRef": "cred-demo-google-oauth",
            "credentialBinding": {
                "credentialType": "oauth2",
                "provider": "google",
                "subjects": ["demo-google-subject"],
                "clientIds": [
                    "demo-google-client.apps.googleusercontent.com"
                ],
                "requiredScopes": [
                    "https://www.googleapis.com/auth/gmail.readonly",
                ],
            },
        },
        "x.v2": {
            "credentialRef": "cred-demo-x-oauth",
            "credentialBinding": {
                "credentialType": "oauth2",
                "provider": "x",
                "subjects": ["demo-x-user-id"],
                "clientIds": ["demo-x-app"],
                "requiredScopes": ["tweet.read", "users.read"],
            },
        },
        "npm.registry": {
            "credentialRef": "cred-demo-npm-token",
            "credentialBinding": {
                "credentialType": "static",
                "provider": "npm",
                "subjects": ["demo-npm-account"],
                "secretClass": "automationToken",
            },
        },
    }
    envelope_ids = {
        "demo.echo": "demo-echo-response-envelope",
        "demo.stream": "demo-stream-response-envelope",
        "demo.upload.stream": "demo-upload-stream-response-envelope",
        "demo.jsonl.redact.stream": "demo-jsonl-redact-response-envelope",
        "demo.json.array.redact.stream": "demo-json-array-redact-response-envelope",
        "demo.json.sse.redact.stream": "demo-json-sse-redact-response-envelope",
        "demo.json.nested.redact.stream": "demo-json-nested-redact-response-envelope",
        "demo.form.urlencoded.redact.stream": "demo-form-redact-response-envelope",
        "demo.csv.redact.stream": "demo-csv-redact-response-envelope",
        "demo.proof.stream.jsonl": "demo-proof-jsonl-response-envelope",
        "demo.proof.stream.json-array": "demo-proof-json-array-response-envelope",
        "demo.proof.stream.json-sse": "demo-proof-json-sse-response-envelope",
        "demo.proof.stream.json-nested": "demo-proof-json-nested-response-envelope",
        "demo.proof.stream.form": "demo-proof-form-response-envelope",
        "demo.proof.stream.csv": "demo-proof-csv-response-envelope",
        "demo.gmail.recent": "gmail-response-envelope",
        "demo.x.tweet.one_per_day": "x-tweet-response-envelope",
        "demo.x.search.recent": "x-search-response-envelope",
        "demo.x.readonly": "x-readonly-response-envelope",
        "demo.npm.publish.jit": "npm-write-response-envelope",
    }
    provider_route_ids = {
        "demo.gmail.recent",
        "demo.x.tweet.one_per_day",
        "demo.x.search.recent",
        "demo.x.readonly",
        "demo.npm.publish.jit",
    }
    provider_envelope_operations = {
        "demo.gmail.recent": [
            "gmail.messages.list",
            "gmail.message.get",
        ],
        "demo.x.tweet.one_per_day": ["tweets.write"],
        "demo.x.search.recent": ["search.read"],
        "demo.npm.publish.jit": ["npm.publish", "npm.distTagWrite"],
    }
    for route in bundle["routes"]:
        adapter_type = route["adapter"]["type"]
        adapter_config = route["adapter"]["config"]
        request_profile = adapter_config["request"]
        request_profile.setdefault("valueRules", [])
        response_profile = adapter_config["response"]
        response_mode = response_profile.get("mode", "json")
        success_content_types = response_content_types[response_mode]
        response_profile.setdefault("contentTypes", list(success_content_types))
        response_profile.setdefault("allowedHeaders", [])
        response_profile.setdefault("error", copy.deepcopy(error_profile))

        if adapter_type == "generic.rest":
            request_profile.setdefault(
                "operation",
                {"name": route["id"]},
            )
            if route.get("credentialRef"):
                adapter_config["credentialMode"] = "required"
                adapter_config["credentialBinding"] = {
                    "credentialType": "static",
                    "provider": "demo",
                    "subjects": ["demo-service-account"],
                    "secretClass": "bearerToken",
                }
            else:
                adapter_config["credentialMode"] = "none"
                adapter_config["noCredentialProof"] = {
                    "credentialRefAbsent": True,
                    "secretInjectionDisabled": True,
                    "sensitiveHeadersForwarded": False,
                    "authorizationForwarded": False,
                }
        else:
            binding = provider_bindings[adapter_type]
            route["credentialRef"] = binding["credentialRef"]
            adapter_config["credentialBinding"] = copy.deepcopy(
                binding["credentialBinding"]
            )
            if (
                adapter_type == "x.v2"
                and adapter_config.get("mode") == "controlledWrite"
            ):
                adapter_config["credentialBinding"]["requiredScopes"] = [
                    "tweet.read",
                    "tweet.write",
                    "users.read",
                ]
            if adapter_type == "gmail.v1":
                adapter_config["denyEquivalentEndpoints"] = [
                    f"/{endpoint.lstrip('/')}"
                    for endpoint in adapter_config.get(
                        "denyEquivalentEndpoints", []
                    )
                ]

        constraints = route.setdefault("constraints", [])
        for constraint in constraints:
            if constraint.get("type") != "rateLimit":
                continue
            constraint["windowSemantics"] = (
                "calendarUTC"
                if "calendarWindow" in constraint
                else "fixedFromFirstUse"
            )
        envelope_content_types = list(success_content_types)
        if (
            response_mode != "headersOnly"
            and "application/json" not in envelope_content_types
        ):
            envelope_content_types.append("application/json")
        constraints.append(
            {
                "id": envelope_ids[route["id"]],
                "type": "responseEnvelope",
                "phase": "response",
                "statusCodes": (
                    [200, 201]
                    if route["id"] == "demo.npm.publish.jit"
                    else [200]
                    if route["id"] in provider_route_ids
                    else [
                        200,
                        201,
                        400,
                        401,
                        403,
                        404,
                        409,
                        429,
                        500,
                        502,
                        503,
                        504,
                    ]
                ),
                "bodyPresence": (
                    "forbidden" if response_mode == "headersOnly" else "required"
                ),
                "contentTypes": envelope_content_types,
                "allowedResponseHeaderNames": [],
                "responseHeaderRules": [],
                **(
                    {
                        "operations": provider_envelope_operations[
                            route["id"]
                        ]
                    }
                    if route["id"] in provider_envelope_operations
                    else {}
                ),
            }
        )
        if route["id"] == "demo.gmail.recent":
            constraints.append(
                {
                    "id": "gmail-traversal-budget",
                    "type": "traversalBudget",
                    "operations": ["gmail.messages.list"],
                    "traversal": {
                        "store": "shared",
                        "phases": ["request", "response"],
                        "cursor": {
                            "requestSource": "query",
                            "requestField": "pageToken",
                            "responseField": "nextPageToken",
                            "digest": "sha256",
                            "firstPageMayOmit": True,
                        },
                        "lineage": {
                            "scope": [
                                "principal",
                                "route",
                                "credential",
                                "credentialVersion",
                            ],
                            "queryFields": sorted(
                                set(GMAIL_V1_REQUEST_QUERY_KEYS) - {"pageToken"}
                            ),
                            "queryDigest": "sha256",
                        },
                        "limits": {
                            "maxPages": 3,
                            "maxLifetimeSeconds": 300,
                            "maxRecords": 30,
                            "maxDecodedBytes": 3145728,
                        },
                        "accounting": {
                            "recordCountField": "messages",
                            "byteSource": "validatedDecodedResponseBytes",
                            "commit": "atomicAfterResponseValidation",
                        },
                        "onReplay": "deny",
                        "onCrossLineage": "deny",
                        "onMissingEvidence": "deny",
                    },
                }
            )
        if route["id"] == "demo.x.search.recent":
            constraints.append(
                {
                    "id": "x-search-traversal-budget",
                    "type": "traversalBudget",
                    "operations": ["search.read"],
                    "traversal": {
                        "store": "shared",
                        "phases": ["request", "response"],
                        "cursor": {
                            "requestSource": "query",
                            "requestField": "next_token",
                            "responseField": "meta.next_token",
                            "digest": "sha256",
                            "firstPageMayOmit": True,
                        },
                        "lineage": {
                            "scope": [
                                "principal",
                                "route",
                                "credential",
                                "credentialVersion",
                            ],
                            "queryFields": sorted(
                                set(X_V2_RECENT_SEARCH_QUERY_KEYS)
                                - {"next_token"}
                            ),
                            "queryDigest": "sha256",
                        },
                        "limits": {
                            "maxPages": 3,
                            "maxLifetimeSeconds": 300,
                            "maxRecords": 300,
                            "maxDecodedBytes": 196608,
                        },
                        "accounting": {
                            "recordCountField": "data",
                            "byteSource": "validatedDecodedResponseBytes",
                            "commit": "atomicAfterResponseValidation",
                        },
                        "onReplay": "deny",
                        "onCrossLineage": "deny",
                        "onMissingEvidence": "deny",
                    },
                }
            )
    for route in bundle["routes"]:
        if route["match"]["host"] == "demo-upstream":
            route["match"]["resolvedCidrs"] = list(DEMO_UPSTREAM_RESOLVED_CIDRS)
    return bundle


def _canonical_decimal_port(value: str, context: str) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or len(value) > 5
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise ValueError(f"{context} port must be canonical decimal")
    port = int(value)
    if not 1 <= port <= 65535 or str(port) != value:
        raise ValueError(f"{context} port is zero, out of range, or noncanonical")
    return port


def _validate_raw_absolute_authority(authority: str) -> tuple[str, int | None]:
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise ValueError("request target IPv6 authority has invalid brackets")
        host = authority[1:close]
        suffix = authority[close + 1 :]
        if not host or "[" in host or "]" in host:
            raise ValueError("request target IPv6 authority has invalid brackets")
        try:
            canonical_host = _canonical_network_host(
                host,
                "request target",
                normalize_dns_case=False,
                allow_ipv6=True,
            )
        except PolicyBundleError as exc:
            raise ValueError(str(exc)) from exc
        if ":" not in canonical_host:
            raise ValueError("bracketed request target host must be canonical IPv6")
        port = None
        if suffix:
            if not suffix.startswith(":"):
                raise ValueError("request target IPv6 authority has an invalid suffix")
            port = _canonical_decimal_port(suffix[1:], "request target")
        return canonical_host, port
    if "[" in authority or "]" in authority:
        raise ValueError("request target authority has invalid brackets")
    if authority.count(":") > 1:
        raise ValueError("request target IPv6 host must use brackets")
    host, separator, port_text = authority.partition(":")
    try:
        canonical_host = _canonical_network_host(
            host,
            "request target",
            normalize_dns_case=False,
            allow_ipv6=False,
        )
    except PolicyBundleError as exc:
        raise ValueError(str(exc)) from exc
    port = _canonical_decimal_port(port_text, "request target") if separator else None
    return canonical_host, port


def validate_raw_connect_authority(authority: str) -> tuple[str, int]:
    if (
        not isinstance(authority, str)
        or not authority
        or len(authority) > 512
        or any(
            ord(character) <= 32
            or ord(character) == 127
            or ord(character) > 127
            or character in "\\%@/?#"
            for character in authority
        )
    ):
        raise ValueError("CONNECT target must be canonical host:port authority")
    host, port = _validate_raw_absolute_authority(authority)
    if port is None:
        raise ValueError("CONNECT target must include an explicit canonical port")
    return host, port


def validate_raw_absolute_target(
    pretty_url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
) -> SplitResult:
    """Reject parser-normalizable absolute targets before any URL parser sees them."""
    if not isinstance(pretty_url, str):
        raise TypeError("request target must be text")
    if len(pretty_url) > MAX_RAW_ABSOLUTE_TARGET_BYTES:
        raise ValueError("request target exceeds 64 KiB")
    scheme_separator = pretty_url.find("://")
    if scheme_separator < 0:
        raise ValueError("request target must be absolute-form")
    scheme = pretty_url[:scheme_separator]
    if scheme not in allowed_schemes:
        raise ValueError("request target scheme must be canonical lowercase HTTP(S)")
    authority_start = scheme_separator + 3
    authority_end = len(pretty_url)
    for delimiter in ("/", "?"):
        position = pretty_url.find(delimiter, authority_start)
        if position >= 0:
            authority_end = min(authority_end, position)
    if authority_start == authority_end:
        raise ValueError("request target authority is empty")
    authority = pretty_url[authority_start:authority_end]
    if "@" in authority:
        raise ValueError("request target userinfo is not allowed")
    canonical_host, explicit_port = _validate_raw_absolute_authority(authority)
    default_port = 443 if scheme == "https" else 80
    if explicit_port == default_port:
        raise ValueError("request target must omit the default scheme port")
    if authority_end == len(pretty_url) or pretty_url[authority_end] != "/":
        raise ValueError("request target must contain an explicit absolute path")
    if "#" in pretty_url:
        raise ValueError("request target fragments are not allowed")
    if "\\" in pretty_url:
        raise ValueError("request target contains a forbidden backslash")

    query_marker = pretty_url.find("?", authority_end)
    query_start = query_marker + 1 if query_marker >= 0 else None
    if query_start == len(pretty_url):
        raise ValueError("request target query must not be empty")
    path_end = query_marker if query_marker >= 0 else len(pretty_url)
    try:
        raw = pretty_url.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("request target contains raw non-ASCII") from exc
    path_decoded = bytearray()
    query_decoded = bytearray()
    unreserved = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    index = 0
    while index < len(raw):
        value = raw[index]
        if value <= 0x20 or value == 0x7F:
            raise ValueError("request target contains whitespace or a control byte")
        in_authority = authority_start <= index < authority_end
        in_query = query_start is not None and index >= query_start
        in_path = authority_end <= index < path_end
        if value != 0x25:
            if in_query:
                if value == 0x2B:
                    raise ValueError(
                        "request query must encode space as %20 and literal plus as %2B"
                    )
                if value not in unreserved and value not in b"&=":
                    raise ValueError(
                        "request query contains a raw reserved delimiter or separator"
                    )
                query_decoded.append(value)
            elif in_path:
                path_decoded.append(value)
            index += 1
            continue
        if (
            index + 2 >= len(raw)
            or chr(raw[index + 1]) not in "0123456789abcdefABCDEF"
            or chr(raw[index + 2]) not in "0123456789abcdefABCDEF"
        ):
            raise ValueError("request target contains an invalid percent encoding")
        if in_authority:
            raise ValueError("request target authority must not contain percent encoding")
        hex_pair = raw[index + 1 : index + 3].decode("ascii")
        decoded = int(hex_pair, 16)
        if decoded == 0x25:
            raise ValueError("request target contains a double encoding")
        if decoded == 0x5C or decoded < 0x20 or decoded == 0x7F:
            raise ValueError(
                "request target percent-encodes a forbidden separator or control"
            )
        if decoded == 0x2F and in_path:
            if hex_pair != "2f":
                raise ValueError(
                    "npm scoped-package separators must use canonical %2f"
                )
        else:
            if decoded in unreserved:
                raise ValueError("request target percent-encodes an unreserved byte")
            if any(character in b"abcdef" for character in raw[index + 1 : index + 3]):
                raise ValueError("request target uses a non-canonical percent encoding")
        if in_query:
            query_decoded.append(decoded)
        elif in_path:
            path_decoded.append(decoded)
        index += 3
    try:
        decoded_path = path_decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("request path is not valid UTF-8 after decoding") from exc
    if any(segment in {".", ".."} for segment in decoded_path.split("/")):
        raise ValueError("request path contains a dot segment")
    try:
        query_decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("request query is not valid UTF-8 after decoding") from exc
    if query_start is not None:
        raw_query = pretty_url[query_start:]
        for pair in raw_query.split("&"):
            if pair.count("=") != 1:
                raise ValueError(
                    "request query pairs must contain exactly one equals delimiter"
                )
            key, _ = pair.split("=", 1)
            if not key:
                raise ValueError("request query contains an empty key")
        try:
            query_pairs = parse_qsl(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=MAX_RAW_QUERY_FIELDS,
                separator="&",
            )
        except (UnicodeError, ValueError) as exc:
            raise ValueError("request query is malformed") from exc
        query_keys = [key for key, _ in query_pairs]
        if len(query_keys) != len(set(query_keys)):
            raise ValueError("request query contains a duplicate decoded key")
        if query_pairs != sorted(query_pairs):
            raise ValueError("request query pairs are not in canonical order")
        canonical_query = urlencode(
            query_pairs,
            doseq=False,
            safe="",
            encoding="utf-8",
            errors="strict",
            quote_via=quote,
        )
        if canonical_query != raw_query:
            raise ValueError(
                "request query is not in exact canonical wire form"
            )

    parts = urlsplit(pretty_url)
    expected_remainder = pretty_url[authority_end:]
    expected_path, query_separator, expected_query = expected_remainder.partition("?")
    # urlsplit must preserve the complete admitted wire form. The authority
    # validator has already rejected any DNS spelling that requires case-folding.
    if (
        parts.scheme != scheme
        or parts.netloc != authority
        or parts.path != expected_path
        or parts.query != (expected_query if query_separator else "")
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
        or parts.hostname != canonical_host
    ):
        raise ValueError("URL parser normalized request target outside the explicit contract")
    try:
        parsed_port = parts.port
    except ValueError as exc:
        raise ValueError("request target port is invalid") from exc
    if parsed_port != explicit_port:
        raise ValueError("URL parser changed the explicit request target port")
    return parts


def validated_request_urlsplit(pretty_url: str) -> SplitResult:
    return validate_raw_absolute_target(pretty_url)


def validate_request_target_path(
    pretty_url: str,
    *,
    _validated_parts: SplitResult | None = None,
) -> bool:
    """Validate a provider path and report canonical npm scoped-name encoding."""
    parts = _validated_parts or validated_request_urlsplit(pretty_url)
    raw_path = parts.path or "/"
    if not raw_path.startswith("/") or len(raw_path.encode("utf-8")) > 16 * 1024:
        raise ValueError("request path must be a bounded absolute path")
    if "//" in raw_path:
        raise ValueError("request path contains an empty segment")

    raw = raw_path.encode("utf-8")
    decoded = bytearray()
    encoded_slashes = 0
    index = 0
    unreserved = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    while index < len(raw):
        value = raw[index]
        if value == 0x5C or value < 0x20 or value == 0x7F:
            raise ValueError("request path contains a forbidden separator or control")
        if value != 0x25:
            decoded.append(value)
            index += 1
            continue
        if (
            index + 2 >= len(raw)
            or chr(raw[index + 1]) not in "0123456789abcdefABCDEF"
            or chr(raw[index + 2]) not in "0123456789abcdefABCDEF"
        ):
            raise ValueError("request path contains an invalid percent encoding")
        hex_pair = raw[index + 1 : index + 3].decode("ascii")
        decoded_value = int(hex_pair, 16)
        if decoded_value == 0x2F:
            if hex_pair != "2f":
                raise ValueError(
                    "npm scoped-package separators must use canonical %2f"
                )
            encoded_slashes += 1
        elif (
            decoded_value == 0x5C
            or decoded_value < 0x20
            or decoded_value == 0x7F
        ):
            raise ValueError(
                "request path encodes a forbidden separator or control"
            )
        else:
            if decoded_value == 0x25:
                raise ValueError("request path contains a double encoding")
            if decoded_value in unreserved:
                raise ValueError("request path percent-encodes an unreserved byte")
            if any(character in b"abcdef" for character in raw[index + 1 : index + 3]):
                raise ValueError("request path uses a non-canonical percent encoding")
        decoded.append(decoded_value)
        index += 3

    try:
        decoded_path = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("request path is not valid UTF-8 after decoding") from exc
    if any(segment in {".", ".."} for segment in decoded_path.split("/")):
        raise ValueError("request path contains a dot segment")

    if encoded_slashes:
        scoped_segments = [
            segment for segment in raw_path.split("/") if "%2f" in segment
        ]
        valid_scoped_segment = False
        if encoded_slashes == 1 and len(scoped_segments) == 1:
            scope, separator, package = scoped_segments[0].partition("%2f")
            npm_part = re.compile(r"^[A-Za-z0-9._~-]+$")
            valid_scoped_segment = bool(
                separator
                and scope.startswith("@")
                and npm_part.fullmatch(scope[1:])
                and npm_part.fullmatch(package)
                and "%" not in scope
                and "%" not in package
            )
        if not valid_scoped_segment:
            raise ValueError("encoded slash is not a canonical npm scoped package")
    return encoded_slashes == 1


def validated_request_url_parts(
    pretty_url: str,
) -> tuple[bool, str, str, int, str]:
    parts = validated_request_urlsplit(pretty_url)
    path_has_encoded_slash = validate_request_target_path(
        pretty_url,
        _validated_parts=parts,
    )
    scheme = parts.scheme
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    return path_has_encoded_slash, scheme, host, port, parts.path or "/"


def request_url_parts(pretty_url: str) -> tuple[str, str, int, str]:
    _, scheme, host, port, path = validated_request_url_parts(pretty_url)
    return scheme, host, port, path
