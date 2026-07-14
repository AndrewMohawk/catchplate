from __future__ import annotations

import csv
import base64
import hashlib
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
_GENERIC_NON_FORWARDED_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-serverware-agent",
    "x-serverware-data-plane-token",
}
_STREAMING_RESPONSE_MODES = {
    "stream",
    "jsonlStream",
    "jsonArrayStream",
    "jsonSseStream",
    "jsonNestedStream",
    "formUrlencodedStream",
    "csvStream",
}
_SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "content-language",
    "etag",
    "last-modified",
    "retry-after",
    "www-authenticate",
}
_RESPONSE_CONTENT_TYPES = {
    "json": "application/json",
    "jsonlStream": "application/x-ndjson",
    "jsonArrayStream": "application/json",
    "jsonSseStream": "text/event-stream",
    "jsonNestedStream": "application/json",
    "formUrlencodedStream": "application/x-www-form-urlencoded",
    "csvStream": "text/csv",
}
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


class ApiAdapter:
    id = "generic.rest"

    def validate_credential(self, route: Any, credential: dict[str, Any] | None) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        request_cfg = route.adapter_config.get("request") or {}
        if not request_cfg:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic request policy is missing",
                payload={"error": "generic_request_policy_missing"},
            )

        allowed_headers = {str(item).strip().lower() for item in request_cfg.get("allowedHeaders") or []}
        for raw_name in getattr(flow.request, "headers", {}):
            name = str(raw_name).strip().lower()
            if name in _GENERIC_NON_FORWARDED_HEADERS:
                continue
            if name not in allowed_headers:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"generic request header is not allowed by policy: {name}",
                    payload={"error": "request_header_not_allowed", "header": name},
                )

        allowed_query_keys = {str(item) for item in request_cfg.get("allowedQueryKeys") or []}
        for key, _ in parse_qsl(urlsplit(flow.request.pretty_url).query, keep_blank_values=True):
            if key not in allowed_query_keys:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"generic request query key is not allowed by policy: {key}",
                    payload={"error": "request_query_key_not_allowed", "queryKey": key},
                )

        body = flow.request.raw_content or b""
        max_body = request_cfg.get("maxBodyBytes")
        if max_body is None:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic request body limit is missing",
                payload={"error": "generic_request_body_limit_missing"},
            )
        if len(body) > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=413,
                reason="generic request body exceeded policy limit",
                payload={"error": "request_body_too_large", "maxBodyBytes": int(max_body)},
            )

        body_mode = request_cfg.get("bodyMode")
        if body_mode == "none" and body:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="generic request body is forbidden by policy",
                payload={"error": "request_body_not_allowed"},
            )
        if body_mode == "json" and body:
            content_type = str(flow.request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic JSON request has an unsupported content type",
                    payload={"error": "request_json_content_type_denied", "contentType": content_type},
                )
            try:
                json.loads(body.decode("utf-8"))
            except Exception:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason="generic JSON request body is invalid",
                    payload={"error": "request_json_invalid"},
                )
        if body_mode == "formUrlencoded" and body:
            content_type = str(flow.request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/x-www-form-urlencoded":
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic form request has an unsupported content type",
                    payload={"error": "request_form_content_type_denied", "contentType": content_type},
                )
            try:
                self._parse_form_urlencoded(body)
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason=str(exc),
                    payload={"error": "request_form_invalid"},
                )
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
        response_cfg, profile_error = self._response_profile(flow, route)
        if profile_error is not None:
            return profile_error
        assert response_cfg is not None
        max_body = response_cfg.get("maxBodyBytes")
        if max_body is None:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="response body limit is missing",
                payload={"error": "response_body_limit_missing"},
            )
        if len(flow.response.raw_content or b"") > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="generic response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": int(max_body)},
            )
        mode = response_cfg.get("mode")
        supported_modes = {"any", "headersOnly", "json"} | _STREAMING_RESPONSE_MODES
        if mode not in supported_modes:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="unsupported response mode",
                payload={"error": "response_mode_unsupported", "mode": mode},
            )
        if route.credential_ref and mode in {"any", "stream"}:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="credential-bearing response requires structured projection",
                payload={"error": "credential_response_projection_required", "mode": mode},
            )
        if mode == "headersOnly":
            flow.response.content = b""
            self._normalize_response_headers(flow, response_cfg, mode)
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
            self._normalize_response_headers(flow, response_cfg, mode)
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
        self._normalize_response_headers(flow, response_cfg, mode)
        return PolicyDecision(allowed=True)

    def _response_profile(
        self, flow: Any, route: Any
    ) -> tuple[dict[str, Any] | None, PolicyDecision | None]:
        status_code = int(flow.response.status_code)
        response_cfg = route.adapter_config.get("response") or {}
        if 200 <= status_code < 300:
            if response_cfg:
                return response_cfg, None
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="response policy is missing",
                payload={"error": "response_policy_missing"},
            )
        if 300 <= status_code < 400:
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="provider redirects are not allowed by policy",
                payload={"error": "response_redirect_not_allowed", "upstreamStatus": status_code},
            )
        if 400 <= status_code < 600:
            error_cfg = response_cfg.get("error")
            if isinstance(error_cfg, dict) and error_cfg:
                return error_cfg, None
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="provider error response policy is missing",
                payload={"error": "response_error_policy_missing", "upstreamStatus": status_code},
            )
        return None, PolicyDecision(
            allowed=False,
            status_code=502,
            reason="provider returned an invalid response status",
            payload={"error": "response_status_invalid", "upstreamStatus": status_code},
        )

    def _normalize_response_headers(
        self, flow: Any, response_cfg: dict[str, Any], mode: str
    ) -> None:
        released: dict[str, str] = {}
        configured = {
            str(name).strip().lower() for name in (response_cfg.get("allowedHeaders") or [])
        }
        for name in sorted(configured & _SAFE_RESPONSE_HEADERS):
            value = flow.response.headers.get(name)
            if value is None:
                continue
            text = str(value)
            if len(text.encode("utf-8")) <= 8192 and "\r" not in text and "\n" not in text:
                released[name] = text

        content_type = _RESPONSE_CONTENT_TYPES.get(mode)
        if content_type is None and mode in {"any", "stream"}:
            upstream_type = str(flow.response.headers.get("content-type") or "")
            media_type = upstream_type.split(";", 1)[0].strip().lower()
            content_type = media_type if _MEDIA_TYPE_RE.fullmatch(media_type) else "application/octet-stream"

        flow.response.headers.clear()
        if content_type and mode != "headersOnly":
            flow.response.headers["Content-Type"] = content_type
        for name, value in released.items():
            flow.response.headers[name] = value
        flow.response.headers["Content-Length"] = str(len(flow.response.raw_content or b""))

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = ((route.adapter_config.get("request") or {}).get("operation") or {})
        name = operation.get("name")
        fields: dict[str, str] = {"operation": str(name)} if name else {}
        configured_form_fields = {str(item) for item in operation.get("formFields") or []}
        if not configured_form_fields:
            return fields
        try:
            pairs = self._parse_form_urlencoded(flow.request.raw_content or b"")
        except ValueError:
            return fields
        values: dict[str, list[str]] = {}
        for key, value in pairs:
            normalized = self._normalized_form_key(key)
            if normalized in configured_form_fields:
                values.setdefault(normalized, []).append(value)
        for field, found in values.items():
            if len(found) == 1:
                fields[field] = found[0]
        return fields

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
        pairs = self._parse_form_urlencoded(raw)
        redacted = [
            (key, value)
            for key, value in pairs
            if self._normalized_form_key(key) in allowed
        ]
        return urlencode(redacted, doseq=True).encode("utf-8")

    def _parse_form_urlencoded(self, raw: bytes) -> list[tuple[str, str]]:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("form request is not valid UTF-8") from exc
        if re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError("form request contains invalid percent encoding")
        try:
            pairs = parse_qsl(
                text,
                keep_blank_values=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=256,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("form request is invalid") from exc
        if any(not self._normalized_form_key(key) for key, _ in pairs):
            raise ValueError("form request contains an invalid field name")
        return pairs

    def _normalized_form_key(self, key: str) -> str:
        parts = [part for part in re.split(r"\[([^\]]*)\]", key) if part and not part.isdigit()]
        return ".".join(parts)

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

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = "gmail.messages.list" if self._is_list(params) else "gmail.message.get"
        return {"operation": operation}

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
        if not flow.response:
            return PolicyDecision(allowed=True)
        if not 200 <= int(flow.response.status_code) < 300:
            return super().validate_response(flow, route, params)
        response_cfg = route.adapter_config.get("response") or {}
        max_body = response_cfg.get("maxBodyBytes")
        if max_body is None or len(flow.response.raw_content or b"") > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": max_body},
            )
        validate_internal_date = response_cfg.get("validateInternalDate", True)
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
                validated_messages: list[dict[str, Any]] = []
                for item in messages:
                    if not isinstance(item, dict) or not item.get("id"):
                        continue
                    if item.get("internalDate") is None and response_cfg.get("validateListByMetadataFetch", False):
                        # The prototype cannot perform the gate's bounded metadata fetch.
                        # Do not release an identifier until its age is proven.
                        continue
                    decision = self._validate_internal_date(route, item)
                    if not decision.allowed:
                        return decision
                    item["serverwareAgeProof"] = "validated"
                    allowed_ids.append(str(item["id"]))
                    validated_messages.append(item)
                payload["messages"] = validated_messages
                runtime.cache_gmail_message_ids(
                    self._proof_context(flow, route, params),
                    allowed_ids,
                    ttl_seconds=int(route.adapter_config.get("cacheTtlSeconds", 1800)),
                )
            self._apply_allowed_fields(flow, route, payload)
            self._normalize_response_headers(flow, response_cfg, "json")
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
        if decision.allowed:
            self._normalize_response_headers(flow, response_cfg, "json")
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
            payload_value = filtered.get("payload")
            if isinstance(payload_value, dict) and isinstance(payload_value.get("headers"), list):
                allowed_header_names = {
                    str(name).casefold()
                    for name in (response_cfg.get("allowedMessageHeaderNames") or [])
                }
                payload_value["headers"] = [
                    {"name": str(header["name"]), "value": str(header.get("value", ""))}
                    for header in payload_value["headers"]
                    if isinstance(header, dict)
                    and isinstance(header.get("name"), str)
                    and header["name"].casefold() in allowed_header_names
                ]
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


X_V2_READ_OPERATION_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "accountActivity.read",
        (
            "/2/account_activity/subscriptions/count",
            "/2/account_activity/webhooks/{webhook_id}/subscriptions/all",
            "/2/account_activity/webhooks/{webhook_id}/subscriptions/all/list",
        ),
    ),
    ("activity.read", ("/2/activity/subscriptions",)),
    ("analytics.read", ("/2/media/analytics", "/2/tweets/analytics")),
    (
        "bookmarks.read",
        (
            "/2/users/{id}/bookmarks",
            "/2/users/{id}/bookmarks/folders",
            "/2/users/{id}/bookmarks/folders/{folder_id}",
        ),
    ),
    (
        "chat.read",
        (
            "/2/chat/conversations",
            "/2/chat/conversations/{id}",
            "/2/chat/conversations/{id}/events",
            "/2/chat/media/{id}/{media_hash_key}",
        ),
    ),
    ("communities.read", ("/2/communities/search", "/2/communities/{id}")),
    ("compliance.read", ("/2/compliance/jobs", "/2/compliance/jobs/{id}")),
    ("connections.read", ("/2/connections",)),
    (
        "directMessages.read",
        (
            "/2/dm_conversations/media/{dm_id}/{media_id}/{resource_id}",
            "/2/dm_conversations/with/{participant_id}/dm_events",
            "/2/dm_conversations/{id}/dm_events",
            "/2/dm_events",
            "/2/dm_events/{event_id}",
        ),
    ),
    ("insights.read", ("/2/insights/28hr", "/2/insights/historical")),
    (
        "lists.read",
        (
            "/2/lists/{id}",
            "/2/lists/{id}/followers",
            "/2/lists/{id}/members",
            "/2/lists/{id}/tweets",
            "/2/users/{id}/followed_lists",
            "/2/users/{id}/list_memberships",
            "/2/users/{id}/owned_lists",
            "/2/users/{id}/pinned_lists",
        ),
    ),
    (
        "media.read",
        (
            "/2/media",
            "/2/media/upload",
            "/2/media/{media_key}",
        ),
    ),
    ("news.read", ("/2/news/search", "/2/news/{id}")),
    (
        "notes.read",
        (
            "/2/notes/search/notes_written",
            "/2/notes/search/posts_eligible_for_notes",
        ),
    ),
    ("schema.read", ("/2/openapi.json",)),
    (
        "search.read",
        (
            "/2/tweets/counts/all",
            "/2/tweets/counts/recent",
            "/2/tweets/search/all",
            "/2/tweets/search/recent",
        ),
    ),
    (
        "spaces.read",
        (
            "/2/spaces",
            "/2/spaces/by/creator_ids",
            "/2/spaces/search",
            "/2/spaces/{id}",
            "/2/spaces/{id}/buyers",
            "/2/spaces/{id}/tweets",
        ),
    ),
    (
        "streams.read",
        (
            "/2/activity/stream",
            "/2/likes/compliance/stream",
            "/2/likes/firehose/stream",
            "/2/likes/sample10/stream",
            "/2/tweets/compliance/stream",
            "/2/tweets/firehose/stream",
            "/2/tweets/firehose/stream/lang/en",
            "/2/tweets/firehose/stream/lang/ja",
            "/2/tweets/firehose/stream/lang/ko",
            "/2/tweets/firehose/stream/lang/pt",
            "/2/tweets/label/stream",
            "/2/tweets/sample/stream",
            "/2/tweets/sample10/stream",
            "/2/tweets/search/stream",
            "/2/tweets/search/stream/rules",
            "/2/tweets/search/stream/rules/counts",
            "/2/users/compliance/stream",
        ),
    ),
    (
        "trends.read",
        (
            "/2/trends/by/woeid/{woeid}",
            "/2/users/personalized_trends",
        ),
    ),
    (
        "tweets.read",
        (
            "/2/tweets",
            "/2/tweets/{id}",
            "/2/tweets/{id}/liking_users",
            "/2/tweets/{id}/quote_tweets",
            "/2/tweets/{id}/retweeted_by",
            "/2/tweets/{id}/retweets",
            "/2/users/reposts_of_me",
            "/2/users/{id}/liked_tweets",
            "/2/users/{id}/mentions",
            "/2/users/{id}/timelines/reverse_chronological",
            "/2/users/{id}/tweets",
        ),
    ),
    ("usage.read", ("/2/usage/tweets",)),
    (
        "users.read",
        (
            "/2/users",
            "/2/users/by",
            "/2/users/by/username/{username}",
            "/2/users/me",
            "/2/users/public_keys",
            "/2/users/search",
            "/2/users/{id}",
            "/2/users/{id}/affiliates",
            "/2/users/{id}/blocking",
            "/2/users/{id}/followers",
            "/2/users/{id}/following",
            "/2/users/{id}/muting",
            "/2/users/{id}/public_keys",
        ),
    ),
    (
        "webhooks.read",
        (
            "/2/tweets/search/webhooks",
            "/2/webhooks",
        ),
    ),
)

X_V2_READ_OPERATIONS = frozenset(operation for operation, _ in X_V2_READ_OPERATION_PATHS)


def _x_path_template_matches(path: str, template: str) -> bool:
    path_segments = path.strip("/").split("/")
    template_segments = template.strip("/").split("/")
    if len(path_segments) != len(template_segments):
        return False
    return all(
        bool(path_segment)
        and (template_segment == path_segment or template_segment.startswith("{") and template_segment.endswith("}"))
        for path_segment, template_segment in zip(path_segments, template_segments, strict=True)
    )


def _x_read_operation(path: str) -> str | None:
    matches: list[tuple[int, str]] = []
    for operation, templates in X_V2_READ_OPERATION_PATHS:
        for template in templates:
            if _x_path_template_matches(path, template):
                specificity = sum(
                    not (segment.startswith("{") and segment.endswith("}"))
                    for segment in template.strip("/").split("/")
                )
                matches.append((specificity, operation))
    if not matches:
        return None
    matches.sort(reverse=True)
    if len(matches) > 1 and matches[0][0] == matches[1][0] and matches[0][1] != matches[1][1]:
        return None
    return matches[0][1]


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
        path = (urlsplit(flow.request.pretty_url).path or "/").rstrip("/") or "/"
        method = flow.request.method.upper()
        if method == "POST" and path == "/2/tweets":
            return "tweets.write"
        return _x_read_operation(path) if method == "GET" else None

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

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if self._operation(flow) == "search.read" and any(
            constraint.get("type") == "responseDateWindow" for constraint in route.constraints
        ):
            fields = {
                item.strip()
                for item in str(flow.request.query.get("tweet.fields") or "").split(",")
                if item.strip()
            }
            fields.add("created_at")
            flow.request.query["tweet.fields"] = ",".join(sorted(fields))
        return PolicyDecision(allowed=True)

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = self._operation(flow)
        return {"operation": operation or ""}


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
            selected_version = body.get("version")
            dist_tags = body.get("dist-tags")
            if not selected_version and isinstance(dist_tags, dict):
                selected_version = dist_tags.get("latest")
            versions = body.get("versions")
            version_doc: dict[str, Any] = {}
            if isinstance(versions, dict):
                if not selected_version and len(versions) == 1:
                    selected_version = next(iter(versions))
                candidate = versions.get(str(selected_version)) if selected_version else None
                if isinstance(candidate, dict):
                    version_doc = candidate
            if selected_version or version_doc.get("version"):
                fields["packageVersion"] = str(version_doc.get("version") or selected_version)
            integrity = body.get("tarball_integrity")
            dist = version_doc.get("dist")
            if not integrity and isinstance(dist, dict):
                integrity = dist.get("integrity")
            if not integrity:
                integrity = version_doc.get("_integrity")
            if not integrity:
                attachments = body.get("_attachments")
                if isinstance(attachments, dict) and len(attachments) == 1:
                    attachment = next(iter(attachments.values()))
                    encoded = attachment.get("data") if isinstance(attachment, dict) else None
                    if isinstance(encoded, str):
                        try:
                            tarball = base64.b64decode(encoded, validate=True)
                        except Exception:
                            tarball = b""
                        if tarball:
                            integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
            if integrity:
                fields["tarballIntegrity"] = str(integrity)
        return fields

    def _validate_publish_document(self, flow: Any, params: dict[str, str]) -> PolicyDecision:
        try:
            body = json.loads((flow.request.raw_content or b"").decode("utf-8"))
        except Exception:
            body = None
        if not isinstance(body, dict):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish body must be a JSON object",
                payload={"error": "npm_publish_invalid_json"},
            )
        route_package = unquote(params.get("package") or "")
        document_package = body.get("name")
        if not isinstance(document_package, str) or not document_package:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish body must declare the package name",
                payload={"error": "npm_publish_package_missing"},
            )
        if route_package and route_package != document_package:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish package does not match the authorized route",
                payload={
                    "error": "npm_publish_package_mismatch",
                    "route_package": route_package,
                    "document_package": document_package,
                },
            )
        versions = body.get("versions")
        if not isinstance(versions, dict) or len(versions) != 1:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish must contain exactly one package version",
                payload={
                    "error": "npm_publish_requires_exactly_one_version",
                    "version_count": len(versions) if isinstance(versions, dict) else 0,
                },
            )
        version, version_document = next(iter(versions.items()))
        latest = (body.get("dist-tags") or {}).get("latest") if isinstance(body.get("dist-tags"), dict) else None
        if latest != version:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish latest tag must reference the sole authorized version",
                payload={"error": "npm_publish_latest_tag_mismatch", "latest": latest, "version": version},
            )
        if not isinstance(version_document, dict) or version_document.get("version") != version:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish version document does not match its version key",
                payload={"error": "npm_publish_version_mismatch", "version": version},
            )
        return PolicyDecision(allowed=True)

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
            document_decision = self._validate_publish_document(flow, params)
            if not document_decision.allowed:
                return document_decision
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
