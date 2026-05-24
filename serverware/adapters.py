from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from serverware import runtime
from serverware.policies import PolicyDecision


OLDER_THAN_RE = re.compile(r"\bolder_than:(\d+)([dmy])\b", re.IGNORECASE)
NEWER_THAN_RE = re.compile(r"\bnewer_than:(\d+)([dmy])\b", re.IGNORECASE)


class ApiAdapter:
    id = "generic.rest"

    def validate_credential(self, route: Any, credential: dict[str, Any] | None) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        request_cfg = route.adapter_config.get("request") or {}
        if request_cfg.get("bodyMode") in {"jsonlStream", "jsonArrayStream", "jsonSseStream", "jsonNestedStream", "formUrlencodedStream", "csvStream"}:
            allowed_fields = self._allowed_field_paths(request_cfg)
            if not allowed_fields:
                return PolicyDecision(
                    allowed=False,
                    status_code=500,
                    reason="streaming redaction request policy missing allowedFields",
                    payload={"error": "streaming_redaction_request_allowed_fields_missing"},
            )
            try:
                if request_cfg.get("bodyMode") == "jsonArrayStream":
                    flow.request.content = self._redact_json_array(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "jsonSseStream":
                    flow.request.content = self._redact_json_sse(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "jsonNestedStream":
                    flow.request.content = self._redact_json_nested(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "formUrlencodedStream":
                    flow.request.content = self._redact_form_urlencoded(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "csvStream":
                    flow.request.content = self._redact_csv(flow.request.raw_content or b"", allowed_fields)
                else:
                    flow.request.content = self._redact_json_lines(flow.request.raw_content or b"", allowed_fields)
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason=str(exc),
                    payload={"error": "streaming_redaction_request_invalid", "detail": str(exc)},
                )
        return PolicyDecision(allowed=True)

    def validate_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if not flow.response:
            return PolicyDecision(allowed=True)
        response_cfg = route.adapter_config.get("response") or {}
        if not response_cfg:
            return PolicyDecision(allowed=True)
        max_body = response_cfg.get("maxBodyBytes")
        if max_body is not None and len(flow.response.raw_content or b"") > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="generic response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": int(max_body)},
            )
        mode = response_cfg.get("mode", "any")
        if mode == "headersOnly":
            flow.response.content = b""
            flow.response.headers["Content-Length"] = "0"
            return PolicyDecision(allowed=True)
        allowed_fields = self._allowed_field_paths(response_cfg)
        if mode in {"jsonlStream", "jsonArrayStream", "jsonSseStream", "jsonNestedStream", "formUrlencodedStream", "csvStream"}:
            if not allowed_fields:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="streaming redaction response policy missing allowedFields",
                    payload={"error": "streaming_redaction_response_allowed_fields_missing"},
                )
            try:
                if mode == "jsonArrayStream":
                    flow.response.content = self._redact_json_array(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/json"
                elif mode == "jsonSseStream":
                    flow.response.content = self._redact_json_sse(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "text/event-stream"
                elif mode == "jsonNestedStream":
                    flow.response.content = self._redact_json_nested(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/json"
                elif mode == "formUrlencodedStream":
                    flow.response.content = self._redact_form_urlencoded(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/x-www-form-urlencoded"
                elif mode == "csvStream":
                    flow.response.content = self._redact_csv(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "text/csv"
                else:
                    flow.response.content = self._redact_json_lines(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/x-ndjson"
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason=str(exc),
                    payload={"error": "streaming_redaction_response_invalid", "detail": str(exc)},
                )
            return PolicyDecision(allowed=True)
        if mode == "json" or allowed_fields:
            try:
                payload = json.loads(flow.response.get_text(strict=False))
            except Exception:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="response is not valid JSON",
                    payload={"error": "response_invalid_json"},
                )
            if allowed_fields:
                payload = self._redact_json(payload, allowed_fields)
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return PolicyDecision(allowed=True)

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        return {}

    def _allowed_field_paths(self, response_cfg: dict[str, Any]) -> list[tuple[str, ...]]:
        paths = [
            tuple(segment for segment in str(field).split(".") if segment)
            for field in (response_cfg.get("allowedFields") or [])
        ]
        return [path for path in paths if path]

    def _redact_json(self, source: Any, paths: list[tuple[str, ...]]) -> Any:
        if not paths:
            return source
        if isinstance(source, list):
            return [self._redact_json(item, paths) for item in source]
        if not isinstance(source, dict):
            return None
        grouped: dict[str, list[tuple[str, ...]]] = {}
        for path in paths:
            grouped.setdefault(path[0], []).append(path[1:])
        redacted: dict[str, Any] = {}
        for key, tails in grouped.items():
            if key not in source:
                continue
            if any(not tail for tail in tails):
                redacted[key] = source[key]
                continue
            value = self._redact_json(source[key], [tail for tail in tails if tail])
            if value not in ({}, None):
                redacted[key] = value
        return redacted

    def _redact_json_lines(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        output: list[bytes] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except Exception as exc:
                raise ValueError("json lines body contains invalid JSON") from exc
            redacted = self._redact_json(item, paths)
            output.append(json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        return b"\n".join(output) + (b"\n" if output else b"")

    def _redact_json_array(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        try:
            payload = json.loads(raw)
        except Exception as exc:
            raise ValueError("json array body contains invalid JSON") from exc
        if not isinstance(payload, list):
            raise ValueError("json array body must be a top-level array")
        redacted = [self._redact_json(item, paths) for item in payload]
        return json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _redact_json_nested(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        try:
            payload = json.loads(raw)
        except Exception as exc:
            raise ValueError("json nested body contains invalid JSON") from exc
        redacted = self._redact_json(payload, paths)
        return json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _redact_json_sse(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        output: list[bytes] = []
        event_lines: list[bytes] = []
        for raw_line in raw.splitlines():
            line = raw_line.rstrip(b"\r")
            if not line:
                output.extend(self._redact_json_sse_event(event_lines, paths))
                event_lines = []
                continue
            event_lines.append(line)
        if event_lines:
            output.extend(self._redact_json_sse_event(event_lines, paths))
        return b"".join(output)

    def _redact_json_sse_event(self, event_lines: list[bytes], paths: list[tuple[str, ...]]) -> list[bytes]:
        data_parts: list[bytes] = []
        for line in event_lines:
            if line.startswith(b"data:"):
                value = line[5:]
                if value.startswith(b" "):
                    value = value[1:]
                data_parts.append(value)
        if not data_parts:
            return []
        data = b"\n".join(data_parts).strip()
        if data == b"[DONE]":
            return [b"data: [DONE]\n\n"]
        try:
            payload = json.loads(data)
        except Exception as exc:
            raise ValueError("json sse event contains invalid JSON") from exc
        redacted = self._redact_json(payload, paths)
        return [b"data: " + json.dumps(redacted, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n\n"]

    def _redact_form_urlencoded(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        allowed = {".".join(path) for path in paths if path}
        pairs = parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        redacted = [(key, value) for key, value in pairs if key in allowed]
        return urlencode(redacted, doseq=True).encode("utf-8")

    def _redact_csv(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        allowed = {".".join(path) for path in paths if path}
        reader = csv.reader(io.StringIO(raw.decode("utf-8"), newline=""))
        try:
            headers = next(reader)
        except StopIteration as exc:
            raise ValueError("csv body missing header row") from exc
        if not headers:
            raise ValueError("csv body missing header row")
        if len(set(headers)) != len(headers):
            raise ValueError("csv body contains duplicate headers")
        indexes = [index for index, name in enumerate(headers) if name in allowed]
        if not indexes:
            raise ValueError("csv allowedFields did not match the header row")
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow([headers[index] for index in indexes])
        for row in reader:
            if len(row) != len(headers):
                raise ValueError("csv record does not match header width")
            writer.writerow([row[index] for index in indexes])
        return output.getvalue().encode("utf-8")


class GmailV1Adapter(ApiAdapter):
    id = "gmail.v1"

    def _days(self, route: Any) -> int:
        return int(route.adapter_config.get("maxAgeDays", 30))

    def _max_results(self, route: Any) -> int | None:
        value = route.adapter_config.get("maxResults")
        return int(value) if value is not None else None

    def _is_list(self, params: dict[str, str]) -> bool:
        return "message_id" not in params

    def _older_than_days(self, value: str) -> int | None:
        match = OLDER_THAN_RE.search(value or "")
        if not match:
            return None
        count = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "d":
            return count
        if unit == "m":
            return count * 30
        return count * 365

    def _newer_than_days(self, match: re.Match[str]) -> int:
        count = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "d":
            return count
        if unit == "m":
            return count * 30
        return count * 365

    def _append_recent_query(self, query: str, days: int) -> str:
        guard = f"newer_than:{days}d"
        query = query or ""
        if NEWER_THAN_RE.search(query):
            return NEWER_THAN_RE.sub(
                lambda match: match.group(0) if self._newer_than_days(match) <= days else guard,
                query,
            )
        if not query.strip():
            return guard
        return f"({query}) {guard}"

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        denied_equivalents = {str(item).lower() for item in route.adapter_config.get("denyEquivalentEndpoints") or []}
        if denied_equivalents:
            path_segments = {segment.lower() for segment in (urlsplit(flow.request.pretty_url).path or "").split("/") if segment}
            blocked = sorted(denied_equivalents.intersection(path_segments))
            if blocked:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"gmail equivalent endpoint blocked by policy: {blocked[0]}",
                    payload={"error": "gmail_equivalent_endpoint_blocked", "endpoint": blocked[0]},
                )

        if self._is_list(params):
            query = flow.request.query.get("q", "")
            older_than = self._older_than_days(query)
            days = self._days(route)
            if older_than and older_than > days:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"gmail query asks for mail older than {days} days",
                    payload={"error": "gmail_recent_policy", "max_days": days},
                )
            return PolicyDecision(allowed=True)

        message_id = params["message_id"]
        if route.adapter_config.get("allowMessageGetOnlyFromPriorSearch", True):
            if not runtime.gmail_message_allowed(self._proof_context(flow, route, params), message_id):
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason="gmail message id was not observed in a validated recent list response for this principal, credential version, policy, user, and cutoff",
                    payload={"error": "gmail_message_age_not_proven", "message_id": message_id},
                )
        return PolicyDecision(allowed=True)

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if self._is_list(params) and route.adapter_config.get("forceQuery", True):
            days = self._days(route)
            flow.request.query["q"] = self._append_recent_query(flow.request.query.get("q", ""), days)
            max_results = self._max_results(route)
            if max_results and int(flow.request.query.get("maxResults", max_results)) > max_results:
                flow.request.query["maxResults"] = str(max_results)
        return PolicyDecision(allowed=True)

    def _cutoff_ms(self, route: Any) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._days(route))
        return int(cutoff.timestamp() * 1000)

    def _cache_cutoff_epoch_ms(self, route: Any) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._days(route))
        day_start = datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=timezone.utc)
        return int(day_start.timestamp() * 1000)

    def _proof_context(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, Any]:
        return {
            "route_id": route.id,
            "principal_id": flow.metadata.get("serverware_principal_id"),
            "credential_id": flow.metadata.get("serverware_credential_id") or route.credential_ref,
            "credential_version": flow.metadata.get("serverware_credential_version") or 0,
            "policy_hash": flow.metadata.get("serverware_policy_hash"),
            "gmail_user": params.get("user", "me"),
            "cutoff_epoch_ms": self._cache_cutoff_epoch_ms(route),
        }

    def _validate_internal_date(self, route: Any, item: dict[str, Any]) -> PolicyDecision:
        raw_value = item.get("internalDate")
        if raw_value is None:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response missing internalDate required by policy",
                payload={"error": "gmail_response_missing_internal_date"},
            )
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response internalDate is not an epoch-ms integer",
                payload={"error": "gmail_response_invalid_internal_date"},
            )
        if value < self._cutoff_ms(route):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason=f"gmail response contains mail older than {self._days(route)} days",
                payload={"error": "gmail_response_too_old", "max_days": self._days(route)},
            )
        return PolicyDecision(allowed=True)

    def validate_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if not flow.response or flow.response.status_code >= 400:
            return PolicyDecision(allowed=True)
        response_cfg = route.adapter_config.get("response") or {}
        validate_internal_date = response_cfg.get("validateInternalDate", True)
        allowed_fields = response_cfg.get("allowedFields") or []
        if not validate_internal_date and not allowed_fields:
            return PolicyDecision(allowed=True)
        try:
            payload = json.loads(flow.response.get_text(strict=False))
        except Exception:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response is not valid JSON",
                payload={"error": "gmail_response_invalid_json"},
            )

        if self._is_list(params):
            if validate_internal_date:
                messages = payload.get("messages") or []
                allowed_ids: list[str] = []
                pending_ids: list[str] = []
                for item in messages:
                    if not isinstance(item, dict) or not item.get("id"):
                        continue
                    if item.get("internalDate") is None and response_cfg.get("validateListByMetadataFetch", False):
                        item["serverwareAgeProof"] = "pending"
                        pending_ids.append(str(item["id"]))
                        continue
                    decision = self._validate_internal_date(route, item)
                    if not decision.allowed:
                        return decision
                    item["serverwareAgeProof"] = "validated"
                    allowed_ids.append(str(item["id"]))
                runtime.cache_gmail_message_ids(
                    self._proof_context(flow, route, params),
                    allowed_ids,
                    ttl_seconds=int(route.adapter_config.get("cacheTtlSeconds", 1800)),
                )
                if pending_ids:
                    payload["serverwarePendingAgeProof"] = pending_ids
            self._apply_allowed_fields(flow, route, payload)
            return PolicyDecision(allowed=True)

        decision = PolicyDecision(allowed=True)
        if validate_internal_date:
            decision = self._validate_internal_date(route, payload)
            if decision.allowed and payload.get("id"):
                runtime.cache_gmail_message_ids(
                    self._proof_context(flow, route, params),
                    [payload["id"]],
                    ttl_seconds=int(route.adapter_config.get("cacheTtlSeconds", 1800)),
                )
        self._apply_allowed_fields(flow, route, payload)
        return decision

    def _apply_allowed_fields(self, flow: Any, route: Any, payload: dict[str, Any]) -> None:
        response_cfg = route.adapter_config.get("response") or {}
        allowed_fields = [
            tuple(segment for segment in str(field).split(".") if segment)
            for field in (response_cfg.get("allowedFields") or [])
        ]
        allowed_fields = [field for field in allowed_fields if field]
        if not allowed_fields:
            flow.response.set_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
            return

        def copy_path(source: dict[str, Any], target: dict[str, Any], path: tuple[str, ...]) -> None:
            if not path:
                return
            key = path[0]
            if key not in source:
                return
            if len(path) == 1:
                target[key] = source[key]
                return
            child = source.get(key)
            if isinstance(child, dict):
                nested = target.setdefault(key, {})
                if isinstance(nested, dict):
                    copy_path(child, nested, path[1:])

        def filter_message(item: dict[str, Any]) -> dict[str, Any]:
            filtered: dict[str, Any] = {}
            for path in allowed_fields:
                copy_path(item, filtered, path)
            if "serverwareAgeProof" in item:
                filtered["serverwareAgeProof"] = item["serverwareAgeProof"]
            return filtered

        if "messages" in payload and isinstance(payload["messages"], list):
            filtered_payload: dict[str, Any] = {
                "messages": [
                    filter_message(item) if isinstance(item, dict) else item
                    for item in payload["messages"]
                ]
            }
            if "serverwarePendingAgeProof" in payload:
                filtered_payload["serverwarePendingAgeProof"] = payload["serverwarePendingAgeProof"]
            flow.response.set_text(json.dumps(filtered_payload, separators=(",", ":"), sort_keys=True))
            return

        filtered = filter_message(payload)
        flow.response.set_text(json.dumps(filtered, separators=(",", ":"), sort_keys=True))


class XV2Adapter(ApiAdapter):
    id = "x.v2"

    def validate_credential(self, route: Any, credential: dict[str, Any] | None) -> PolicyDecision:
        allowed_app_ids = set(route.adapter_config.get("appIds") or [])
        if not allowed_app_ids:
            return PolicyDecision(allowed=True)
        metadata = (credential or {}).get("metadata") or {}
        credential_app_id = metadata.get("x_app_id") or metadata.get("app_id")
        if credential_app_id not in allowed_app_ids:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 credential app id is not allowed by route policy",
                payload={"error": "x_app_id_denied"},
            )
        return PolicyDecision(allowed=True)

    def _operation(self, flow: Any) -> str | None:
        path = (urlsplit(flow.request.pretty_url).path or "").rstrip("/")
        method = flow.request.method.upper()
        if path.startswith("/2/tweets/search"):
            return "search.read" if method == "GET" else "search.write"
        if path == "/2/tweets" or path.startswith("/2/tweets/"):
            return "tweets.read" if method == "GET" else "tweets.write"
        if path == "/2/users" or path.startswith("/2/users/"):
            return "users.read" if method == "GET" else "users.write"
        return None

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        operation = self._operation(flow)
        if operation is None:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 unknown provider operation blocked by policy",
                payload={"error": "x_unknown_operation_blocked"},
            )
        if route.adapter_config.get("blockWrites", True) and not operation.endswith(".read"):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 write operation blocked by read-only policy",
                payload={"error": "x_write_blocked", "mode": route.adapter_config.get("mode", "readOnly")},
            )
        allowed_reads = set(route.adapter_config.get("allowedReadOperations") or [])
        if operation.endswith(".read") and operation not in allowed_reads:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"x.v2 read operation {operation} is not allowed by route policy",
                payload={"error": "x_read_operation_not_allowed", "operation": operation},
            )
        return PolicyDecision(allowed=True)


class NpmRegistryAdapter(ApiAdapter):
    id = "npm.registry"

    def _registry_path(self, flow: Any) -> str:
        path = (urlsplit(flow.request.pretty_url).path or "/").rstrip("/") or "/"
        if path.startswith("/npm/"):
            return path[4:] or "/"
        if path == "/npm":
            return "/"
        return path

    def _operation_name(self, flow: Any, params: dict[str, str]) -> str:
        method = flow.request.method.upper()
        path = self._registry_path(flow)
        if method in {"GET", "HEAD"}:
            return "read"
        if path.startswith("/-/package/") and "/dist-tags/" in path:
            return "distTagWrite"
        if path.startswith("/-/npm/v1/tokens") or path.startswith("/-/user/token"):
            return "tokenWrite"
        if method in {"PATCH"}:
            return "metadataWrite"
        if method in {"PUT", "POST"}:
            return "publish"
        return "metadataWrite"

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = self._operation_name(flow, params)
        fields: dict[str, str] = {
            "operation": f"npm.{operation}",
        }
        package = params.get("package")
        if package:
            fields["packageName"] = unquote(package)
        try:
            body = json.loads((flow.request.raw_content or b"{}").decode("utf-8"))
        except Exception:
            body = {}
        if isinstance(body, dict):
            if body.get("name"):
                fields["packageName"] = str(body["name"])
            if body.get("version"):
                fields["packageVersion"] = str(body["version"])
            if body.get("tarball_integrity"):
                fields["tarballIntegrity"] = str(body["tarball_integrity"])
        return fields

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        operation = self._operation_name(flow, params)
        allowed_operations = set(route.adapter_config.get("operations") or [])
        if operation not in allowed_operations:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"npm operation {operation} is not allowed by route policy",
                payload={"error": "npm_operation_not_allowed", "operation": operation},
            )
        if operation == "publish":
            fields = self.operation_fields(flow, route, params)
            missing = [
                field
                for field in ("packageName", "packageVersion", "tarballIntegrity")
                if not fields.get(field)
            ]
            if missing:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"npm publish request missing required operation fields: {', '.join(missing)}",
                    payload={"error": "npm_publish_missing_fields", "missing": missing},
                )
        return PolicyDecision(allowed=True)


ADAPTERS: dict[str, ApiAdapter] = {
    "generic.rest": ApiAdapter(),
    "gmail.v1": GmailV1Adapter(),
    "x.v2": XV2Adapter(),
    "npm.registry": NpmRegistryAdapter(),
}


def get_adapter(adapter_type: str) -> ApiAdapter:
    if adapter_type not in ADAPTERS:
        raise KeyError(f"unsupported adapter: {adapter_type}")
    return ADAPTERS[adapter_type]
