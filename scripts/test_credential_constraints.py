from __future__ import annotations

# ruff: noqa: E402

import base64
import copy
import contextlib
import hashlib
import json
import os
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROXY_TRANSPORT_ONLY = "--proxy-transport-only" in sys.argv

REQUEST_VALUE_PARITY_VECTORS = (
    ("equals-allow", {"kind": "equals", "value": "approved"}, "approved", True),
    ("equals-deny", {"kind": "equals", "value": "approved"}, "other", False),
    ("enum-allow", {"kind": "enum", "values": ["open", "closed"]}, "open", True),
    ("enum-deny", {"kind": "enum", "values": ["open", "closed"]}, "all", False),
    (
        "pattern-allow",
        {"kind": "pattern", "pattern": "^[A-Za-z0-9._-]{1,16}$", "maxLength": 16},
        "repo-1",
        True,
    ),
    (
        "pattern-deny",
        {"kind": "pattern", "pattern": "^[A-Za-z0-9._-]{1,16}$", "maxLength": 16},
        "repo/1",
        False,
    ),
    ("length-byte-allow", {"kind": "stringLength", "minLength": 2, "maxLength": 2}, "é", True),
    ("length-byte-deny", {"kind": "stringLength", "maxLength": 1}, "é", False),
    ("integer-allow", {"kind": "numeric", "min": 1, "max": 50, "integer": True}, "42", True),
    ("integer-canonical-deny", {"kind": "numeric", "min": 1, "max": 50, "integer": True}, "+42", False),
    (
        "integer-above-f64-precision-deny",
        {"kind": "numeric", "max": 9007199254740992, "integer": True},
        "9007199254740993",
        False,
    ),
    (
        "integer-i64-maximum-allow",
        {"kind": "numeric", "min": 9223372036854775807, "integer": True},
        "9223372036854775807",
        True,
    ),
    (
        "integer-outside-i64-deny",
        {"kind": "numeric", "max": 9223372036854775807, "integer": True},
        "9223372036854775808",
        False,
    ),
    ("number-allow", {"kind": "numeric", "min": 1.25, "max": 2.5}, "1.5", True),
    ("number-whitespace-deny", {"kind": "numeric", "min": 1.25, "max": 2.5}, " 1.5", False),
    ("number-finite-deny", {"kind": "numeric", "min": 0}, "NaN", False),
)

tmpdir = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = tmpdir.name
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
for name in (
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
):
    os.environ.pop(name, None)

from serverware import constraints, db, http_client, runtime
from serverware.adapters import (
    X_V2_READ_OPERATION_PATHS,
    X_V2_READ_OPERATIONS,
    _x_read_operation,
    get_adapter,
    preflight_request_admission,
)
from serverware.constraints import (
    _enforce_request_time_window,
    evaluate_request_constraints,
    evaluate_response_binding_sources,
    evaluate_response_constraints,
    reset_local_constraint_state,
)
from serverware.policy_bundle import (
    GMAIL_V1_REQUEST_HEADERS,
    GMAIL_V1_REQUEST_QUERY_KEYS,
    NPM_REGISTRY_REQUEST_HEADERS,
    X_V2_BOUNDED_READ_QUERY_KEYS,
    X_V2_BOUNDED_READ_OPERATIONS,
    X_V2_RECENT_SEARCH_QUERY_KEYS,
    X_V2_RECENT_SEARCH_PATHS,
    X_V2_REQUEST_HEADERS,
    CredentialPolicy,
    PolicyBundleError,
    _validate_generic_required_headers,
    _load_raw_policy,
    bounded_pattern_matches,
    canonical_json,
    compile_policy_bundle,
    demo_policy_bundle,
    provider_request_profile,
    provider_account_scope_value,
    sign_policy_bundle,
    strict_json_loads,
    validate_discard_headers,
    validate_policy_schema,
    validate_raw_absolute_target,
    validate_request_target_path,
)
try:
    from mitmproxy import http as mitm_http
    from serverware import policy_engine
    from serverware.policy_engine import (
        LEGACY_MITM_TRANSPORT_METADATA_KEY,
        _canonical_credential_version,
        _canonical_forwarded_request_headers,
        _canonical_query_wire,
        _canonical_request,
        _canonicalize_provider_query,
        _bind_provider_account_scope,
        _credential_policy_binding_decision,
        _credential_injection_collision,
        _discard_declared_request_headers,
        _digest,
        _inject_credential,
        _legacy_mitm_route_admission,
        _normalized_request_headers,
        _operation_digest,
        _evaluate_response_envelope,
        _provider_request_matches_canonical,
        _validated_successful_release_reserve,
        _verified_mtls_evidence,
        evaluate_request,
        evaluate_response,
    )
    from serverware.mitm_addon import ServerwareAddon
except ModuleNotFoundError as exc:
    if exc.name != "mitmproxy":
        raise
    if PROXY_TRANSPORT_ONLY:
        raise AssertionError(
            "proxy transport assertions require mitmproxy==11.0.2"
        ) from exc
    _inject_credential = None
    _bind_provider_account_scope = None
    _operation_digest = None
    _validated_successful_release_reserve = None
    _canonical_credential_version = None
    _canonical_forwarded_request_headers = None
    _canonical_query_wire = None
    _canonical_request = None
    _canonicalize_provider_query = None
    _credential_injection_collision = None
    _discard_declared_request_headers = None
    _digest = None
    _normalized_request_headers = None
    _provider_request_matches_canonical = None
    _legacy_mitm_route_admission = None
    LEGACY_MITM_TRANSPORT_METADATA_KEY = None
    policy_engine = None
    mitm_http = None
    evaluate_response = None
    evaluate_request = None
    ServerwareAddon = None


def require_consolidated_policy_runtime() -> None:
    missing = [
        name
        for name, value in {
            "mitmproxy.http": mitm_http,
            "ServerwareAddon": ServerwareAddon,
            "_canonical_forwarded_request_headers": _canonical_forwarded_request_headers,
            "_canonical_query_wire": _canonical_query_wire,
            "_canonical_request": _canonical_request,
            "_canonicalize_provider_query": _canonicalize_provider_query,
            "_discard_declared_request_headers": _discard_declared_request_headers,
            "_normalized_request_headers": _normalized_request_headers,
            "_digest": _digest,
            "_operation_digest": _operation_digest,
            "_provider_request_matches_canonical": _provider_request_matches_canonical,
            "_legacy_mitm_route_admission": _legacy_mitm_route_admission,
            "LEGACY_MITM_TRANSPORT_METADATA_KEY": LEGACY_MITM_TRANSPORT_METADATA_KEY,
            "evaluate_request": evaluate_request,
            "policy_engine": policy_engine,
        }.items()
        if value is None
    ]
    if missing:
        raise AssertionError(
            "consolidated credential-constraint lane requires the locked "
            f"mitmproxy/policy runtime; missing: {', '.join(missing)}"
        )


class RawHeaders(dict):
    def __init__(self, entries: list[tuple[str, str]]) -> None:
        super().__init__(entries)
        self.fields = tuple(
            (name.encode("ascii"), value.encode("ascii"))
            for name, value in entries
        )


class Request:
    def __init__(self, method: str, url: str, body: dict | None = None, content_type: str = "application/json") -> None:
        parts = urlsplit(url)
        authority = parts.netloc
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        self.method = method
        self.pretty_url = url
        self.headers = {"content-type": content_type}
        self.raw_content = json.dumps(body or {}).encode("utf-8") if body is not None else b""
        self.query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        self.host = parts.hostname or ""
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.scheme = parts.scheme
        self.path = authority if method == "CONNECT" else path
        self.first_line_format = "authority" if method == "CONNECT" else "absolute"
        self.http_version = "HTTP/1.1"
        raw_headers = RawHeaders(
            [("Host", authority)]
        )
        self.data = SimpleNamespace(
            method=method.encode("ascii"),
            scheme=b"" if method == "CONNECT" else parts.scheme.encode("ascii"),
            authority=authority.encode("ascii"),
            path=(authority if method == "CONNECT" else path).encode("ascii"),
            host=self.host,
            port=self.port,
            headers=raw_headers,
            http_version=b"HTTP/1.1",
        )

    @property
    def url(self) -> str:
        return self.pretty_url

    @url.setter
    def url(self, value: str) -> None:
        self.pretty_url = value
        self.query = dict(
            parse_qsl(urlsplit(value).query, keep_blank_values=True)
        )

    def get_content(self, strict: bool = True) -> bytes:
        del strict
        if not isinstance(self.raw_content, bytes):
            raise ValueError("request body is not bytes")
        return self.raw_content


class Response:
    def __init__(self, payload: dict, *, status_code: int = 200, headers: dict | None = None) -> None:
        self.raw_content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.status_code = status_code

    @property
    def content(self) -> bytes:
        return self.raw_content

    @content.setter
    def content(self, value: bytes) -> None:
        self.raw_content = value

    def get_text(self, strict: bool = False) -> str:
        return self.raw_content.decode("utf-8", errors="strict" if strict else "replace")

    def set_text(self, value: str) -> None:
        self.raw_content = value.encode("utf-8")


def flow(method: str, url: str, body: dict | None = None, response: dict | None = None) -> SimpleNamespace:
    request = Request(method, url, body)
    item = SimpleNamespace(
        id=f"flow:{id(request)}",
        request=request,
        client_conn=SimpleNamespace(
            id=f"client:{id(request)}",
            peername=("127.0.0.1", 12345),
        ),
        server_conn=SimpleNamespace(
            id=f"server:{id(request)}",
            address=(request.host, request.port),
            peername=("172.16.0.2", request.port),
            sni=request.host if request.scheme == "https" else None,
            tls_established=request.scheme == "https",
        ),
        metadata={},
    )
    if response is not None:
        item.response = Response(response)
    return item


def route(snapshot, route_id: str):
    for item in snapshot.routes:
        if item.id == route_id:
            return item
    raise AssertionError(f"missing route {route_id}")


def request_decision(
    route_policy,
    item,
    operation: str,
    *,
    consume: bool = False,
    principal_id: str = "agent:demo",
    credential_ref: str | None = None,
    operation_fields: dict[str, str] | None = None,
):
    return evaluate_request_constraints(
        item,
        route_policy,
        principal_id=principal_id,
        credential_ref=credential_ref or route_policy.credential_ref,
        credential_version=1,
        operation_fields=operation_fields or {"operation": operation},
        consume_rate_limits=consume,
        policy_hash="sha256:" + "1" * 64,
        rate_limits_only=consume,
    )


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def epoch_ms_days_ago(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)


def assert_denied(decision, error: str) -> None:
    assert not decision.allowed, decision
    assert decision.payload.get("error") == error, decision.payload


def assert_response_binding_denied(
    decision,
    error: str,
    *,
    binding_id: str | None,
    evidence: bool = True,
    sensitive_values: tuple[str, ...] = (),
) -> None:
    assert_denied(decision, error)
    expected_keys = {
        "error",
        "constraint_id",
        "constraint_type",
    }
    if evidence:
        expected_keys.add("evidence_digest")
        evidence_digest = decision.payload["evidence_digest"]
        assert evidence_digest.startswith("sha256:") and len(evidence_digest) == 71
        assert set(evidence_digest.removeprefix("sha256:")) <= set("0123456789abcdef")
    else:
        assert "evidence_digest" not in decision.payload
    if binding_id is None:
        assert "binding_id" not in decision.payload
    else:
        expected_keys.add("binding_id")
        assert decision.payload["binding_id"] == binding_id
    assert set(decision.payload) == expected_keys, decision.payload
    rendered_denial = json.dumps(
        {"reason": decision.reason, "payload": decision.payload},
        sort_keys=True,
    )
    for value in sensitive_values:
        assert value not in rendered_denial, rendered_denial


def assert_runtime_constraint_vocabulary_fails_closed() -> None:
    item = flow("GET", "https://example.test/resource", response={"ok": True})
    for malformed in (
        {"id": "unknown", "type": "futureConstraint", "phase": "request"},
        {"id": "missing-type", "phase": "request"},
        {"id": "non-string", "type": 7, "phase": "request"},
        {"id": "non-string-phase", "type": "operationPolicy", "phase": 7},
        {"id": "response-as-request", "type": "responseJson", "phase": "request"},
        {"id": "request-as-response", "type": "operationPolicy", "phase": "response"},
    ):
        malformed_route = SimpleNamespace(
            id="route:malformed",
            credential_ref=None,
            constraints=[malformed],
        )
        request = evaluate_request_constraints(
            item,
            malformed_route,
            principal_id="agent:test",
            credential_ref=None,
            credential_version=0,
            operation_fields={"operation": "generic.request"},
            consume_rate_limits=False,
        )
        assert_denied(request, "constraint_type_unsupported_at_runtime")
        assert request.status_code == 503

        response = evaluate_response_constraints(item, malformed_route)
        assert_denied(response, "constraint_type_unsupported_at_runtime")
        assert response.status_code == 502

        source = evaluate_response_binding_sources(
            malformed_route,
            {"operation": "generic.request"},
        )
        assert_denied(source, "constraint_type_unsupported_at_runtime")
        assert source.status_code == 503


def schema_validation_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except Exception as exc:
        raise AssertionError("jsonschema is required; policy tests must not downgrade semantic coverage") from exc
    return True


def assert_policy_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(bundle, validate_schema=use_schema)
        except PolicyBundleError:
            continue
        raise AssertionError(f"{message}; validate_schema={use_schema}")


def assert_signed_policy_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    signed = sign_policy_bundle(bundle)
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(
                signed,
                verify_signature=True,
                validate_schema=use_schema,
            )
        except PolicyBundleError:
            continue
        raise AssertionError(f"{message}; validate_schema={use_schema}")


def assert_signed_policy_and_schema_rejected(
    bundle: dict,
    message: str,
    *,
    validate_schema: bool,
) -> None:
    signed = sign_policy_bundle(bundle)
    try:
        compile_policy_bundle(
            signed,
            verify_signature=True,
            validate_schema=False,
        )
    except PolicyBundleError:
        pass
    else:
        raise AssertionError(f"compiler accepted {message}")

    if not validate_schema:
        return
    try:
        validate_policy_schema(signed)
    except PolicyBundleError:
        return
    raise AssertionError(f"policy schema accepted {message}")


def assert_signed_policy_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    signed = sign_policy_bundle(bundle)
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(
                signed,
                verify_signature=True,
                validate_schema=use_schema,
            )
        except PolicyBundleError as exc:
            assert str(exc) == expected_reason, str(exc)
            continue
        raise AssertionError(
            f"compiler accepted signed policy expected to fail with: {expected_reason}; "
            f"validate_schema={use_schema}"
        )


def assert_policy_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    try:
        compile_policy_bundle(bundle, validate_schema=False)
    except PolicyBundleError as exc:
        assert str(exc) == expected_reason, str(exc)
    else:
        raise AssertionError(f"compiler accepted policy expected to fail with: {expected_reason}")
    if not validate_schema:
        return
    try:
        validate_policy_schema(bundle)
    except PolicyBundleError:
        return
    raise AssertionError(f"policy schema accepted policy expected to fail with: {expected_reason}")


def assert_compiler_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(bundle, validate_schema=use_schema)
        except PolicyBundleError as exc:
            assert str(exc) == expected_reason, str(exc)
            continue
        raise AssertionError(
            f"compiler accepted policy expected to fail with: {expected_reason}; "
            f"validate_schema={use_schema}"
        )


def assert_injection_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    assert_policy_rejected(bundle, message, validate_schema=validate_schema)
    if not validate_schema:
        return
    try:
        validate_policy_schema(bundle)
    except PolicyBundleError:
        return
    raise AssertionError(f"policy schema accepted {message}")


_LIVE_PROXY_TIMEOUT_SECONDS = 20.0
_MITMDUMP_OUTPUT_LIMIT_BYTES = 1024 * 1024
_MITMDUMP_DIAGNOSTIC_TAIL_BYTES = 32 * 1024
_MITMDUMP_TEARDOWN_RESERVE_SECONDS = 2.0
_MITMDUMP_TERM_GRACE_SECONDS = 0.75
_MITMDUMP_FINAL_REAP_RESERVE_SECONDS = 0.25


class _MitmdumpSupervisor:
    def __init__(self, process: subprocess.Popen[bytes], deadline: float) -> None:
        if process.stdout is None or process.stderr is None:
            raise AssertionError("mitmdump supervisor requires stdout and stderr pipes")
        self.process = process
        self.deadline = deadline
        self.assertion_cutoff = deadline - _MITMDUMP_TEARDOWN_RESERVE_SECONDS
        self._lock = threading.Lock()
        self._shutdown_requested = threading.Event()
        self._done = threading.Event()
        self._failure: str | None = None
        self._observed_bytes = 0
        self._tails = {
            "stdout": bytearray(),
            "stderr": bytearray(),
        }
        self._thread = threading.Thread(
            target=self._supervise,
            name="mitmdump-output-supervisor",
            daemon=False,
        )
        self._thread.start()

    def _record_failure(self, message: str) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = message

    def _capture(self, stream_name: str, chunk: bytes) -> None:
        with self._lock:
            self._observed_bytes += len(chunk)
            tail = self._tails[stream_name]
            tail.extend(chunk)
            if len(tail) > _MITMDUMP_DIAGNOSTIC_TAIL_BYTES:
                del tail[:-_MITMDUMP_DIAGNOSTIC_TAIL_BYTES]
            if (
                self._observed_bytes > _MITMDUMP_OUTPUT_LIMIT_BYTES
                and self._failure is None
            ):
                self._failure = (
                    "mitmdump exceeded the "
                    f"{_MITMDUMP_OUTPUT_LIMIT_BYTES}-byte combined output cap"
                )

    def _diagnostics(self) -> str:
        with self._lock:
            observed_bytes = self._observed_bytes
            tails = {
                name: bytes(value).decode("utf-8", errors="replace")
                for name, value in self._tails.items()
            }
        sections = [
            "mitmdump output "
            f"({observed_bytes} bytes observed; bounded tails follow)"
        ]
        for stream_name in ("stdout", "stderr"):
            content = tails[stream_name]
            sections.append(f"--- {stream_name} tail ---\n{content or '<empty>'}")
        return "\n".join(sections)

    def _failure_message(self) -> str | None:
        with self._lock:
            failure = self._failure
        if failure is None:
            return None
        return f"{failure}\n{self._diagnostics()}"

    def _group_exists(self) -> bool:
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _signal_group(self, sig: signal.Signals) -> None:
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    @staticmethod
    def _close_stream(
        selector: selectors.BaseSelector,
        stream,
    ) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass

    def _drain_ready(
        self,
        selector: selectors.BaseSelector,
        timeout: float,
    ) -> None:
        try:
            events = selector.select(timeout)
        except (OSError, ValueError):
            return
        for key, _mask in events:
            stream = key.fileobj
            stream_name = key.data
            for _ in range(64):
                try:
                    chunk = os.read(stream.fileno(), 16 * 1024)
                except BlockingIOError:
                    break
                except (OSError, ValueError):
                    self._close_stream(selector, stream)
                    break
                if not chunk:
                    self._close_stream(selector, stream)
                    break
                self._capture(stream_name, chunk)

    def _supervise(self) -> None:
        selector = selectors.DefaultSelector()
        streams = (
            (self.process.stdout, "stdout"),
            (self.process.stderr, "stderr"),
        )
        shutting_down = False
        term_sent_at: float | None = None
        kill_sent = False
        try:
            for stream, stream_name in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, stream_name)

            while True:
                now = time.monotonic()
                if shutting_down:
                    next_transition = self.deadline
                    if term_sent_at is not None and not kill_sent:
                        next_transition = min(
                            next_transition,
                            term_sent_at + _MITMDUMP_TERM_GRACE_SECONDS,
                        )
                else:
                    next_transition = self.assertion_cutoff
                self._drain_ready(
                    selector,
                    max(0.0, min(0.05, next_transition - now)),
                )
                now = time.monotonic()

                with self._lock:
                    output_failed = (
                        self._failure is not None
                        and self._observed_bytes > _MITMDUMP_OUTPUT_LIMIT_BYTES
                    )

                if not shutting_down:
                    if self._shutdown_requested.is_set():
                        shutting_down = True
                    elif output_failed:
                        shutting_down = True
                    elif now >= self.assertion_cutoff:
                        self._record_failure(
                            "live proxy assertions exceeded the single "
                            f"{_LIVE_PROXY_TIMEOUT_SECONDS:g}-second deadline"
                        )
                        shutting_down = True
                    elif self.process.poll() is not None:
                        self._record_failure(
                            "mitmdump exited before live assertions completed "
                            f"with status {self.process.returncode}"
                        )
                        shutting_down = True

                if shutting_down and term_sent_at is None:
                    self._signal_group(signal.SIGTERM)
                    term_sent_at = now

                if (
                    shutting_down
                    and term_sent_at is not None
                    and not kill_sent
                    and now >= term_sent_at + _MITMDUMP_TERM_GRACE_SECONDS
                    and self._group_exists()
                ):
                    self._signal_group(signal.SIGKILL)
                    kill_sent = True

                group_exists = self._group_exists()
                leader_exited = self.process.poll() is not None
                if shutting_down and not group_exists and leader_exited:
                    self._drain_ready(selector, 0.0)
                    if not selector.get_map():
                        break

                if now >= self.deadline - _MITMDUMP_FINAL_REAP_RESERVE_SECONDS:
                    if group_exists:
                        self._signal_group(signal.SIGKILL)
                        kill_sent = True
                    if now >= self.deadline:
                        if self._group_exists() or self.process.poll() is None:
                            self._record_failure(
                                "mitmdump process group was not reaped before "
                                "the live proxy deadline"
                            )
                        break
        except BaseException as exc:
            self._record_failure(
                "mitmdump supervision failed: "
                f"{type(exc).__name__}: {exc}"
            )
        finally:
            if self._group_exists():
                self._signal_group(signal.SIGKILL)
            remaining = max(0.0, self.deadline - time.monotonic())
            if self.process.poll() is None and remaining > 0:
                try:
                    self.process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    self._record_failure(
                        "mitmdump leader was not reaped before the live proxy deadline"
                    )
            self._drain_ready(selector, 0.0)
            for stream, _stream_name in streams:
                self._close_stream(selector, stream)
            selector.close()
            self._done.set()

    def check(self, context: str) -> None:
        failure = self._failure_message()
        if failure is not None:
            raise AssertionError(f"{context}: {failure}")
        if self.process.poll() is not None and not self._shutdown_requested.is_set():
            self._record_failure(
                "mitmdump exited before live assertions completed "
                f"with status {self.process.returncode}"
            )
            raise AssertionError(f"{context}: {self._failure_message()}")
        if time.monotonic() >= self.assertion_cutoff:
            self._record_failure(
                "live proxy assertions exceeded the single "
                f"{_LIVE_PROXY_TIMEOUT_SECONDS:g}-second deadline"
            )
            raise AssertionError(f"{context}: {self._failure_message()}")

    def io_timeout(self, maximum: float, context: str) -> float:
        self.check(context)
        remaining = self.assertion_cutoff - time.monotonic()
        if remaining <= 0:
            self.check(context)
        return max(0.001, min(maximum, remaining))

    def pause(self, duration: float, context: str) -> None:
        self.check(context)
        self._shutdown_requested.wait(self.io_timeout(duration, context))
        self.check(context)

    def finish(self) -> str | None:
        self._shutdown_requested.set()
        force_at = self.deadline - _MITMDUMP_FINAL_REAP_RESERVE_SECONDS
        self._done.wait(max(0.0, force_at - time.monotonic()))
        if not self._done.is_set():
            self._signal_group(signal.SIGKILL)
            for stream in (self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            self._done.wait(max(0.0, self.deadline - time.monotonic()))
        self._thread.join(timeout=max(0.0, self.deadline - time.monotonic()))
        if self._thread.is_alive():
            self._record_failure(
                "mitmdump output supervisor did not stop before the live proxy deadline"
            )
        if self.process.poll() is None or self._group_exists():
            self._record_failure(
                "mitmdump process group remained after bounded teardown"
            )
        return self._failure_message()


def _proxy_http_headers(
    sock: socket.socket,
    supervisor: _MitmdumpSupervisor,
) -> bytes:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        sock.settimeout(
            supervisor.io_timeout(2.0, "waiting for proxy CONNECT response")
        )
        chunk = sock.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
        if len(received) > 65536:
            raise AssertionError("proxy returned oversized CONNECT response headers")
        supervisor.check("reading proxy CONNECT response")
    return bytes(received)


def _assert_no_upstream_connection(
    listener: socket.socket,
    label: str,
    supervisor: _MitmdumpSupervisor,
) -> None:
    listener.settimeout(
        supervisor.io_timeout(0.5, f"checking {label} upstream isolation")
    )
    try:
        upstream, _address = listener.accept()
    except TimeoutError:
        supervisor.check(f"checking {label} upstream isolation")
        return
    try:
        upstream.settimeout(
            supervisor.io_timeout(0.1, f"reading unexpected {label} connection")
        )
        try:
            payload = upstream.recv(4096)
        except TimeoutError:
            payload = b""
    finally:
        upstream.close()
    raise AssertionError(f"{label} reached the upstream TCP listener: {payload!r}")


def _live_proxy_transport_assertions(runner_module) -> None:
    from serverware.config import POLICY_BUNDLE_PATH

    deadline = time.monotonic() + _LIVE_PROXY_TIMEOUT_SECONDS
    bundle = demo_policy_bundle("cred-demo-bearer")
    echo_route = next(item for item in bundle["routes"] if item["id"] == "demo.echo")

    upstream_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream_listener.bind(("127.0.0.1", 0))
    upstream_listener.listen(8)
    upstream_port = upstream_listener.getsockname()[1]
    echo_route["match"]["host"] = "localhost"
    echo_route["match"]["port"] = upstream_port
    echo_route["match"]["resolvedCidrs"] = ["127.0.0.1/32"]
    signed_bundle = sign_policy_bundle(bundle)
    compile_policy_bundle(signed_bundle, verify_signature=True, validate_schema=True)
    POLICY_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_BUNDLE_PATH.write_text(canonical_json(signed_bundle), encoding="utf-8")

    port_reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_reservation.bind(("127.0.0.1", 0))
    proxy_port = port_reservation.getsockname()[1]
    port_reservation.close()

    command = runner_module._mitmdump_command()
    command[command.index("--listen-host") + 1] = "127.0.0.1"
    command[command.index("--listen-port") + 1] = str(proxy_port)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(ROOT), env.get("PYTHONPATH", "")) if item
    )
    process: subprocess.Popen[bytes] | None = None
    supervisor: _MitmdumpSupervisor | None = None
    primary_error: BaseException | None = None
    cleanup_error: str | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=True,
        )
        supervisor = _MitmdumpSupervisor(process, deadline)

        def open_connect(agent: str) -> tuple[socket.socket, bytes]:
            supervisor.check(f"opening CONNECT tunnel for {agent}")
            tunnel = socket.create_connection(
                ("127.0.0.1", proxy_port),
                timeout=supervisor.io_timeout(
                    2.0,
                    f"opening CONNECT tunnel for {agent}",
                ),
            )
            tunnel.settimeout(
                supervisor.io_timeout(
                    2.0,
                    f"sending CONNECT request for {agent}",
                )
            )
            tunnel.sendall(
                (
                    f"CONNECT localhost:{upstream_port} HTTP/1.1\r\n"
                    f"Host: localhost:{upstream_port}\r\n"
                    f"X-Serverware-Agent: {agent}\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            return tunnel, _proxy_http_headers(tunnel, supervisor)

        while True:
            supervisor.check("waiting for mitmdump listener")
            try:
                with socket.create_connection(
                    ("127.0.0.1", proxy_port),
                    timeout=supervisor.io_timeout(
                        0.1,
                        "waiting for mitmdump listener",
                    ),
                ):
                    break
            except OSError:
                supervisor.pause(0.05, "waiting for mitmdump listener")

        denied_tunnel, denied_headers = open_connect("not-admitted")
        denied_tunnel.close()
        assert denied_headers.startswith(b"HTTP/1.1 403"), denied_headers
        _assert_no_upstream_connection(
            upstream_listener,
            "unadmitted CONNECT",
            supervisor,
        )

        admitted_tunnel, admitted_headers = open_connect("demo-agent")
        assert admitted_headers.startswith(b"HTTP/1.1 200"), admitted_headers
        admitted_tunnel.sendall(b"SERVERWARE-UNKNOWN-RAW-TCP\x00\x01\x02")
        admitted_tunnel.close()
        _assert_no_upstream_connection(
            upstream_listener,
            "raw TCP after admitted CONNECT",
            supervisor,
        )

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE

        matching_tunnel, matching_headers = open_connect("demo-agent")
        assert matching_headers.startswith(b"HTTP/1.1 200"), matching_headers
        matching_tunnel.settimeout(
            supervisor.io_timeout(2.0, "performing matching SNI handshake")
        )
        matching_tls = tls_context.wrap_socket(
            matching_tunnel,
            server_hostname="localhost",
        )
        matching_tls.sendall(
            (
                "GET /echo HTTP/1.1\r\n"
                f"Host: localhost:{upstream_port}\r\n"
                "X-Serverware-Agent: demo-agent\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
        )
        denied_request_headers = _proxy_http_headers(
            matching_tls,
            supervisor,
        )
        matching_tls.close()
        assert denied_request_headers.startswith(
            b"HTTP/1.1 503"
        ), denied_request_headers
        assert (
            b"legacy_mitm_credential_transport_denied"
            in denied_request_headers
            or b"content-type: application/json"
            in denied_request_headers.lower()
        ), denied_request_headers
        _assert_no_upstream_connection(
            upstream_listener,
            "credential-bearing HTTPS request",
            supervisor,
        )

        for server_hostname, label in (
            ("mismatch.example.test", "mismatched SNI"),
            (None, "absent SNI for DNS CONNECT authority"),
        ):
            invalid_tunnel, invalid_headers = open_connect("demo-agent")
            assert invalid_headers.startswith(b"HTTP/1.1 200"), invalid_headers
            invalid_tunnel.settimeout(
                supervisor.io_timeout(2.0, f"performing {label} handshake")
            )
            try:
                invalid_tls = tls_context.wrap_socket(
                    invalid_tunnel,
                    server_hostname=server_hostname,
                )
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            else:
                invalid_tls.close()
                raise AssertionError(f"{label} completed a TLS handshake")
            _assert_no_upstream_connection(
                upstream_listener,
                label,
                supervisor,
            )
        supervisor.check("completing live proxy assertions")
    except BaseException as exc:
        primary_error = exc
    finally:
        upstream_listener.close()
        if supervisor is not None:
            cleanup_error = supervisor.finish()
        elif process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=min(_MITMDUMP_TERM_GRACE_SECONDS, remaining))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    cleanup_error = "mitmdump launch failure left an unreaped process group"

    if primary_error is not None:
        if cleanup_error is not None:
            primary_error.add_note(f"mitmdump supervision: {cleanup_error}")
        raise primary_error.with_traceback(primary_error.__traceback__)
    if cleanup_error is not None:
        raise AssertionError(cleanup_error)


def run_proxy_transport_assertions() -> None:
    if ServerwareAddon is None:
        raise AssertionError("proxy transport assertions did not import the mitmproxy addon")
    assert version("mitmproxy") == "11.0.2"

    from mitmproxy import connection, http, tls
    from mitmproxy.options import Options
    from mitmproxy.proxy.context import Context
    from serverware import mitm_addon, policy_engine, runner

    expected_command = [
        "mitmdump",
        "--listen-host",
        runner.PROXY_HOST,
        "--listen-port",
        str(runner.PROXY_PORT),
        "--set",
        f"confdir={runner.MITMPROXY_CONF_DIR}",
        "--set",
        "rawtcp=false",
        "--set",
        "connection_strategy=lazy",
        "--set",
        "ssl_insecure=false",
        "--set",
        "block_global=false",
        "-s",
        str(Path(runner.__file__).with_name("mitm_addon.py")),
    ]
    assert runner._mitmdump_command() == expected_command
    assert "connection_strategy=eager" not in runner._mitmdump_command()
    assert "ssl_insecure=true" not in runner._mitmdump_command()

    addon_source = Path(mitm_addon.__file__).read_text(encoding="utf-8")
    marker_offset = addon_source.index(
        "flow.metadata[LEGACY_MITM_TRANSPORT_METADATA_KEY] = True"
    )
    evaluation_offset = addon_source.index("evaluation = evaluate_request(flow)")
    route_guard_offset = addon_source.index(
        "if route.credential_ref:",
        evaluation_offset,
    )
    dispatch_offset = addon_source.index(
        "dispatch = dispatch_release_authorization(flow)",
        route_guard_offset,
    )
    assert marker_offset < evaluation_offset < route_guard_offset < dispatch_offset
    assert "verify_connected_provider_peer" not in addon_source

    policy_source = Path(policy_engine.__file__).read_text(encoding="utf-8")
    request_evaluation_offset = policy_source.index(
        "def evaluate_request(flow: http.HTTPFlow)"
    )
    admission_offset = policy_source.index(
        "transport_denial = _legacy_mitm_route_admission(flow, route)",
        request_evaluation_offset,
    )
    adapter_offset = policy_source.index(
        "adapter = get_adapter(route.adapter_type)",
        admission_offset,
    )
    credential_generation_offset = policy_source.index(
        "credential_generation = runtime.get_credential_generation(",
        adapter_offset,
    )
    assert admission_offset < adapter_offset < credential_generation_offset

    http_client_source = Path(http_client.__file__).read_text(encoding="utf-8")
    assert "class PinnedProviderConnection" not in http_client_source
    assert "def open_pinned_provider_connection" not in http_client_source

    production_env = os.environ.copy()
    production_env["SERVERWARE_RELEASE_CHANNEL"] = "production"
    production_env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(ROOT), production_env.get("PYTHONPATH", "")) if item
    )
    for module_name, expected_error in (
        ("serverware.runner", "legacy Python mitmproxy transport is development-only"),
        ("serverware.mitm_addon", "legacy Python mitmproxy addon is development-only"),
    ):
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}"],
            cwd=ROOT,
            env=production_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode != 0, module_name
        assert expected_error in result.stderr, result.stderr

    addon = ServerwareAddon()
    original_snapshot = mitm_addon.get_policy_snapshot
    original_log_request = runtime.log_request
    route_policy = SimpleNamespace(
        scheme="https",
        host="connect.example.test",
        port=443,
        principals=("agent:connect-assigned",),
    )

    def identify_principal(_client_ip, headers):
        if headers.get("X-Serverware-Agent") == "connect-agent":
            return SimpleNamespace(id="agent:connect-assigned")
        return None

    snapshot = SimpleNamespace(
        routes=(route_policy,),
        identify_principal=identify_principal,
    )

    def connect_flow(agent: str):
        client = connection.Client(
            peername=("127.0.0.1", 51234),
            sockname=("127.0.0.1", 8080),
            state=connection.ConnectionState.OPEN,
        )
        server = connection.Server(
            address=("connect.example.test", 443),
            state=connection.ConnectionState.CLOSED,
        )
        item = http.HTTPFlow(client, server)
        item.request = http.Request.make(
            "CONNECT",
            "https://connect.example.test:443",
            headers={
                "Host": "connect.example.test:443",
                "X-Serverware-Agent": agent,
            },
        )
        item.request.data.scheme = b""
        item.request.data.authority = b"connect.example.test:443"
        item.request.data.path = b"connect.example.test:443"
        return item

    def client_hello_data(item, sni):
        context = Context(item.client_conn, Options())
        context.server = item.server_conn
        return tls.ClientHelloData(context, SimpleNamespace(sni=sni))

    mitm_addon.get_policy_snapshot = lambda: snapshot
    runtime.log_request = lambda *_args, **_kwargs: None
    try:
        denied = connect_flow("not-admitted")
        addon.http_connect(denied)
        assert denied.response.status_code == 403
        assert denied.metadata["serverware_blocked_response"] is True

        admitted = connect_flow("connect-agent")
        addon.http_connect(admitted)
        assert admitted.response is None
        noncanonical_sni = client_hello_data(admitted, "CONNECT.EXAMPLE.TEST.")
        addon.tls_clienthello(noncanonical_sni)
        assert (
            noncanonical_sni.context.client.state
            is connection.ConnectionState.CLOSED
        )
        assert "SNI does not match" in noncanonical_sni.context.client.error

        canonical_sni = connect_flow("connect-agent")
        addon.http_connect(canonical_sni)
        matching = client_hello_data(canonical_sni, "connect.example.test")
        addon.tls_clienthello(matching)
        assert matching.context.client.state is connection.ConnectionState.OPEN
        assert matching.context.client.error is None

        absent = connect_flow("connect-agent")
        addon.http_connect(absent)
        absent_data = client_hello_data(absent, None)
        addon.tls_clienthello(absent_data)
        assert absent_data.context.client.state is connection.ConnectionState.CLOSED
        assert "SNI is required" in absent_data.context.client.error

        mismatched = connect_flow("connect-agent")
        addon.http_connect(mismatched)
        mismatched_data = client_hello_data(mismatched, "other.example.test")
        addon.tls_clienthello(mismatched_data)
        assert mismatched_data.context.client.state is connection.ConnectionState.CLOSED
        assert "does not match" in mismatched_data.context.client.error

        wrong_authority = connect_flow("connect-agent")
        addon.http_connect(wrong_authority)
        wrong_authority.server_conn.address = ("connect.example.test", 444)
        wrong_authority_data = client_hello_data(
            wrong_authority,
            "connect.example.test",
        )
        addon.tls_clienthello(wrong_authority_data)
        assert wrong_authority_data.context.client.state is connection.ConnectionState.CLOSED
        assert "tunnel authority does not match" in wrong_authority_data.context.client.error

        unadmitted = connect_flow("not-admitted")
        unadmitted_data = client_hello_data(unadmitted, "connect.example.test")
        addon.tls_clienthello(unadmitted_data)
        assert unadmitted_data.context.client.state is connection.ConnectionState.CLOSED
        assert "without an admitted CONNECT" in unadmitted_data.context.client.error

        addon.client_disconnected(admitted.client_conn)
        assert (
            mitm_addon._connection_key(admitted.client_conn)
            not in addon._admitted_connect_authorities
        )
        assert (
            mitm_addon._connection_key(admitted.server_conn)
            in addon._admitted_server_connections
        )
        disconnected_data = client_hello_data(admitted, "connect.example.test")
        addon.tls_clienthello(disconnected_data)
        assert disconnected_data.context.client.state is connection.ConnectionState.CLOSED
        addon.server_disconnected(admitted.server_conn)
        assert (
            mitm_addon._connection_key(admitted.server_conn)
            not in addon._admitted_server_connections
        )
    finally:
        runtime.log_request = original_log_request
        mitm_addon.get_policy_snapshot = original_snapshot

    _live_proxy_transport_assertions(runner)
    print("proxy transport assertions passed; mitmproxy=11.0.2")


def main() -> None:
    require_consolidated_policy_runtime()
    assert_runtime_constraint_vocabulary_fails_closed()
    if PROXY_TRANSPORT_ONLY:
        run_proxy_transport_assertions()
        return
    db.init_db()
    validate_schema = schema_validation_available()
    demo_bundle = demo_policy_bundle("cred-demo-bearer")
    internal_demo_routes = [
        item for item in demo_bundle["routes"] if item["match"]["host"] == "demo-upstream"
    ]
    assert internal_demo_routes
    assert all(
        item["match"]["resolvedCidrs"] == ["172.16.0.0/12"]
        for item in internal_demo_routes
    )

    for canonical_host in ("example.test", "192.0.2.1"):
        valid_host = copy.deepcopy(demo_bundle)
        next(item for item in valid_host["routes"] if item["id"] == "demo.echo")[
            "match"
        ]["host"] = canonical_host
        compiled_host = compile_policy_bundle(
            valid_host,
            validate_schema=validate_schema,
        )
        assert route(compiled_host, "demo.echo").host == canonical_host

    for label, invalid_host in (
        ("upper-case DNS", "EXAMPLE.test"),
        ("trailing DNS dot", "example.test."),
        ("empty DNS label", "example..test"),
        ("userinfo", "user@example.test"),
        ("path separator", "example.test/path"),
        ("percent escape", "example%2etest"),
        ("noncanonical IPv4", "0127.0.0.1"),
        ("short IPv4", "127.1"),
        ("integer IPv4", "2130706433"),
        ("expanded IPv6", "2001:0db8::1"),
        ("upper-case IPv6", "2001:DB8::1"),
        ("v1 policy IPv6 extension unavailable", "2001:db8::1"),
        ("bracketed IPv6", "[2001:db8::1]"),
        ("IPv6 zone", "fe80::1%eth0"),
        ("IPv4-mapped IPv6", "::ffff:c000:201"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        next(item for item in invalid["routes"] if item["id"] == "demo.echo")[
            "match"
        ]["host"] = invalid_host
        assert_signed_policy_and_schema_rejected(
            invalid,
            f"noncanonical route host with {label}",
            validate_schema=validate_schema,
        )

    valid_resolved_cidrs = [
        "10.0.0.0/8",
        "127.0.0.0/8",
        "fd12:3456:789a::/48",
        "::1/128",
    ]
    explicit_resolution = copy.deepcopy(demo_bundle)
    next(
        item for item in explicit_resolution["routes"] if item["id"] == "demo.echo"
    )["match"]["resolvedCidrs"] = valid_resolved_cidrs
    signed_explicit_resolution = sign_policy_bundle(explicit_resolution)
    explicit_snapshot = compile_policy_bundle(
        signed_explicit_resolution,
        verify_signature=True,
        validate_schema=validate_schema,
    )
    assert route(explicit_snapshot, "demo.echo").resolved_cidrs == tuple(
        valid_resolved_cidrs
    )
    assert next(
        item for item in explicit_snapshot.raw["routes"] if item["id"] == "demo.echo"
    )["match"]["resolvedCidrs"] == valid_resolved_cidrs

    peer_bound_route = route(explicit_snapshot, "demo.echo")
    legacy_credential_flow = flow(
        "POST",
        "https://demo-upstream:8443/echo",
    )
    legacy_credential_flow.metadata[
        LEGACY_MITM_TRANSPORT_METADATA_KEY
    ] = True
    assert_denied(
        _legacy_mitm_route_admission(
            legacy_credential_flow,
            peer_bound_route,
        ),
        "legacy_mitm_credential_transport_denied",
    )

    admission_side_effects: list[str] = []

    def forbidden_admission_side_effect(*_args, **_kwargs):
        admission_side_effects.append("credential_or_adapter")
        raise AssertionError(
            "legacy credential route reached credential or adapter work"
        )

    original_snapshot_lookup = policy_engine.get_policy_snapshot
    original_adapter_lookup = policy_engine.get_adapter
    original_generation_lookup = runtime.get_credential_generation
    original_request_log = runtime.log_request
    legacy_credential_flow.request.headers[
        "X-Serverware-Agent"
    ] = "demo-agent"
    policy_engine.get_policy_snapshot = lambda: explicit_snapshot
    policy_engine.get_adapter = forbidden_admission_side_effect
    runtime.get_credential_generation = forbidden_admission_side_effect
    runtime.log_request = lambda *_args, **_kwargs: None
    try:
        legacy_evaluation = evaluate_request(legacy_credential_flow)
    finally:
        runtime.log_request = original_request_log
        runtime.get_credential_generation = original_generation_lookup
        policy_engine.get_adapter = original_adapter_lookup
        policy_engine.get_policy_snapshot = original_snapshot_lookup
    assert_denied(
        legacy_evaluation.decision,
        "legacy_mitm_credential_transport_denied",
    )
    assert admission_side_effects == []

    missing_resolution_flow = flow(
        "POST",
        "https://demo-upstream:8443/echo",
    )
    assert_denied(
        _legacy_mitm_route_admission(
            missing_resolution_flow,
            SimpleNamespace(
                credential_ref="cred-demo-bearer",
                resolved_cidrs=None,
            ),
        ),
        "provider_resolved_cidrs_required",
    )

    credentialless_dev_flow = flow(
        "GET",
        "https://demo-upstream:8443/stream-bytes",
    )
    credentialless_dev_flow.metadata[
        LEGACY_MITM_TRANSPORT_METADATA_KEY
    ] = True
    assert (
        _legacy_mitm_route_admission(
            credentialless_dev_flow,
            SimpleNamespace(
                credential_ref=None,
                resolved_cidrs=None,
            ),
        )
        is None
    )
    assert_denied(
        _legacy_mitm_route_admission(
            credentialless_dev_flow,
            SimpleNamespace(
                credential_ref=None,
                resolved_cidrs=("127.0.0.1/32",),
            ),
        ),
        "legacy_mitm_resolved_cidrs_unsupported",
    )

    public_only_resolution = copy.deepcopy(demo_bundle)
    next(
        item for item in public_only_resolution["routes"] if item["id"] == "demo.echo"
    )["match"].pop("resolvedCidrs")
    public_only_snapshot = compile_policy_bundle(
        public_only_resolution,
        validate_schema=validate_schema,
    )
    assert route(public_only_snapshot, "demo.echo").resolved_cidrs is None
    missing_resolution_request = flow(
        "POST",
        "https://demo-upstream:8443/echo",
    )
    missing_resolution_request.request.headers[
        "X-Serverware-Agent"
    ] = "demo-agent"
    admission_side_effects.clear()
    original_snapshot_lookup = policy_engine.get_policy_snapshot
    original_adapter_lookup = policy_engine.get_adapter
    original_generation_lookup = runtime.get_credential_generation
    original_request_log = runtime.log_request
    policy_engine.get_policy_snapshot = lambda: public_only_snapshot
    policy_engine.get_adapter = forbidden_admission_side_effect
    runtime.get_credential_generation = forbidden_admission_side_effect
    runtime.log_request = lambda *_args, **_kwargs: None
    try:
        missing_resolution_evaluation = evaluate_request(
            missing_resolution_request
        )
    finally:
        runtime.log_request = original_request_log
        runtime.get_credential_generation = original_generation_lookup
        policy_engine.get_adapter = original_adapter_lookup
        policy_engine.get_policy_snapshot = original_snapshot_lookup
    assert_denied(
        missing_resolution_evaluation.decision,
        "provider_resolved_cidrs_required",
    )
    assert admission_side_effects == []

    invalid_resolved_cidr_sets = (
        ("empty list", []),
        ("more than 32 entries", [f"10.{index}.0.0/16" for index in range(33)]),
        ("non-string entry", [123]),
        ("host bits", ["10.0.0.1/8"]),
        ("noncanonical IPv6", ["FD12:3456:789A::/48"]),
        ("zone ID", ["fe80::%eth0/64"]),
        ("invalid CIDR", ["not-a-cidr"]),
        ("IPv4-mapped IPv6", ["::ffff:192.0.2.0/120"]),
        (
            "duplicate after normalization",
            ["2001:db8::/32", "2001:0db8::/32"],
        ),
    )
    for label, cidrs in invalid_resolved_cidr_sets:
        invalid = copy.deepcopy(demo_bundle)
        next(item for item in invalid["routes"] if item["id"] == "demo.echo")[
            "match"
        ]["resolvedCidrs"] = cidrs
        assert_policy_rejected(
            invalid,
            f"compiler accepted resolvedCidrs with {label}",
            validate_schema=validate_schema,
        )

    for metadata_overlap in (
        "169.254.169.254/32",
        "169.254.170.0/24",
        "169.254.0.0/16",
        "100.100.100.200/32",
        "192.0.0.192/32",
        "fd00:ec2::/64",
        "fd00::/8",
        "fd20:ce::/64",
    ):
        invalid = copy.deepcopy(demo_bundle)
        next(item for item in invalid["routes"] if item["id"] == "demo.echo")[
            "match"
        ]["resolvedCidrs"] = [metadata_overlap]
        assert_policy_rejected(
            invalid,
            f"compiler accepted metadata-overlapping CIDR {metadata_overlap}",
            validate_schema=validate_schema,
        )

    for encoded in (
        '{"duplicate":1,"duplicate":1}',
        '{"number":NaN}',
        '{"number":Infinity}',
        '{"number":-Infinity}',
        '{"number":1e400}',
        '{"number":' + "1" + "0" * 400 + "}",
    ):
        try:
            strict_json_loads(encoded)
        except ValueError:
            pass
        else:
            raise AssertionError(f"strict JSON decoder accepted invalid input: {encoded[:80]}")

    for value in (float("nan"), float("inf"), float("-inf"), 10**400):
        try:
            canonical_json({"number": value})
        except ValueError:
            pass
        else:
            raise AssertionError(f"canonical JSON accepted an invalid number: {value!r}")

        invalid = copy.deepcopy(demo_bundle)
        invalid["metadata"]["sequence"] = value
        try:
            sign_policy_bundle(invalid)
        except PolicyBundleError:
            pass
        else:
            raise AssertionError(f"policy signer accepted an invalid number: {value!r}")

    signed_demo = sign_policy_bundle(demo_bundle)
    compile_policy_bundle(signed_demo, verify_signature=True, validate_schema=validate_schema)
    duplicate_signed_json = json.dumps(signed_demo, sort_keys=True).replace(
        '"kind": "PolicyBundle"',
        '"kind": "PolicyBundle", "kind": "PolicyBundle"',
        1,
    )
    duplicate_signed_path = Path(tmpdir.name) / "duplicate-signed-policy.json"
    duplicate_signed_path.write_text(duplicate_signed_json)
    try:
        _load_raw_policy(duplicate_signed_path)
    except ValueError:
        pass
    else:
        raise AssertionError("strict policy loading accepted duplicate keys in a validly signed policy")

    checked_in_demo = json.loads((ROOT / "policies" / "demo.policy.json").read_text())
    expected_checked_demo = copy.deepcopy(demo_bundle)
    explicit_provider_statuses = {
        "demo.gmail.recent": [200, 400, 401, 403, 404, 429, 500, 502, 503],
        "demo.x.tweet.one_per_day": [
            200,
            400,
            401,
            403,
            409,
            422,
            429,
            500,
            502,
            503,
        ],
        "demo.x.search.recent": [200, 400, 401, 403, 404, 429, 500, 502, 503],
        "demo.x.readonly": [200, 400, 401, 403, 404, 429, 500, 502, 503],
        "demo.npm.publish.jit": [
            200,
            201,
            400,
            401,
            403,
            404,
            409,
            422,
            429,
            500,
            502,
            503,
        ],
    }
    retry_after_rule = {
        "name": "retry-after",
        "required": False,
        "predicate": {
            "kind": "pattern",
            "pattern": "^[0-9]{1,6}$",
            "maxLength": 6,
        },
    }
    authenticate_rule = {
        "name": "www-authenticate",
        "required": False,
        "predicate": {
            "kind": "stringLength",
            "minLength": 1,
            "maxLength": 512,
        },
    }
    for route_id, statuses in explicit_provider_statuses.items():
        expected_route = next(
            item
            for item in expected_checked_demo["routes"]
            if item["id"] == route_id
        )
        envelope = next(
            constraint
            for constraint in expected_route["constraints"]
            if constraint["type"] == "responseEnvelope"
        )
        envelope["statusCodes"] = statuses
        envelope["allowedResponseHeaderNames"] = ["retry-after"]
        envelope["responseHeaderRules"] = [copy.deepcopy(retry_after_rule)]
        if route_id in {"demo.gmail.recent", "demo.npm.publish.jit"}:
            envelope["allowedResponseHeaderNames"].append("www-authenticate")
            envelope["responseHeaderRules"].append(
                copy.deepcopy(authenticate_rule)
            )
    expected_gmail = next(
        item
        for item in expected_checked_demo["routes"]
        if item["id"] == "demo.gmail.recent"
    )
    gmail_date_window = next(
        constraint
        for constraint in expected_gmail["constraints"]
        if constraint["type"] == "responseDateWindow"
    )
    gmail_date_window["allowFutureSkewSeconds"] = 300
    gmail_envelope = next(
        constraint
        for constraint in expected_gmail["constraints"]
        if constraint["type"] == "responseEnvelope"
    )
    gmail_envelope["description"] = (
        "The gmail.v1 adapter additionally requires a successful detail response "
        "id to exactly equal the requested message_id and rejects internalDate "
        "values more than 300 seconds in the future."
    )
    assert checked_in_demo == expected_checked_demo, (
        "policies/demo.policy.json drifted from its explicit security overlay"
    )
    demo = compile_policy_bundle(checked_in_demo, validate_schema=validate_schema)
    examples = json.loads((ROOT / "policies" / "credential-limits.examples.json").read_text())
    example_snapshot = compile_policy_bundle(examples, validate_schema=validate_schema)
    credential_example_routes = [
        item for item in examples["routes"] if item.get("credentialRef")
    ]
    assert credential_example_routes
    assert all(
        item["match"].get("resolvedCidrs")
        for item in credential_example_routes
    )
    assert all(
        item.resolved_cidrs is not None
        for item in example_snapshot.routes
        if item.credential_ref
    )

    for label, predicate, value, expected_allowed in REQUEST_VALUE_PARITY_VECTORS:
        vector_flow = flow("GET", f"https://example.test/items?scope={quote(value, safe='')}")
        vector_route = SimpleNamespace(
            id=f"request-value-{label}",
            credential_ref=None,
            constraints=(
                {
                    "id": label,
                    "type": "requestValue",
                    "rules": [
                        {
                            "source": "query",
                            "name": "scope",
                            "predicate": predicate,
                            "capture": "validatedScope",
                        }
                    ],
                },
            ),
        )
        operation_fields = {"operation": "vectors.read"}
        decision = evaluate_request_constraints(
            vector_flow,
            vector_route,
            principal_id="agent:example",
            credential_ref=None,
            credential_version=0,
            operation_fields=operation_fields,
            consume_rate_limits=False,
        )
        assert decision.allowed is expected_allowed, (label, decision)
        assert (operation_fields.get("validatedScope") == value) is expected_allowed, label

    oversized_value_flow = flow(
        "GET",
        f"https://example.test/items?scope={quote('x' * 4097, safe='')}",
    )
    oversized_value_route = SimpleNamespace(
        id="request-value-oversized",
        credential_ref=None,
        constraints=(
            {
                "id": "bounded-input",
                "type": "requestValue",
                "rules": [
                    {
                        "source": "query",
                        "name": "scope",
                        "predicate": {"kind": "stringLength", "minLength": 1},
                    }
                ],
            },
        ),
    )
    assert_denied(
        request_decision(oversized_value_route, oversized_value_flow, "vectors.read"),
        "request_value_predicate_denied",
    )

    ambiguous_flow = flow(
        "GET",
        "https://example.test/items?scope=approved&scope=approved",
    )
    ambiguous_route = SimpleNamespace(
        id="request-value-ambiguous",
        credential_ref=None,
        constraints=(
            {
                "id": "single-query-value",
                "type": "requestValue",
                "rules": [
                    {
                        "source": "query",
                        "name": "scope",
                        "predicate": {"kind": "equals", "value": "approved"},
                    }
                ],
            },
        ),
    )
    assert_denied(
        request_decision(ambiguous_route, ambiguous_flow, "vectors.read"),
        "request_value_ambiguous",
    )

    header_flow = flow("GET", "https://example.test/items")
    header_flow.request.headers["x-tenant-id"] = "tenant-a"
    header_route = SimpleNamespace(
        id="request-value-header",
        credential_ref=None,
        constraints=(
            {
                "id": "tenant-header",
                "type": "requestValue",
                "rules": [
                    {
                        "source": "header",
                        "name": "x-tenant-id",
                        "predicate": {"kind": "enum", "values": ["tenant-a"]},
                    }
                ],
            },
        ),
    )
    assert request_decision(header_route, header_flow, "vectors.read").allowed

    path_flow = flow("GET", "https://example.test/repos/approved-owner")
    path_flow.metadata["serverware_request_value_path_params"] = {"owner": "approved-owner"}
    path_route = SimpleNamespace(
        id="request-value-path",
        credential_ref=None,
        constraints=(
            {
                "id": "owner-path",
                "type": "requestValue",
                "rules": [
                    {
                        "source": "pathParam",
                        "name": "owner",
                        "predicate": {"kind": "equals", "value": "approved-owner"},
                    }
                ],
            },
        ),
    )
    assert request_decision(path_route, path_flow, "vectors.read").allowed

    github_raw = next(
        route for route in examples["routes"] if route["id"] == "example.github.issues_since_30_days"
    )
    for mutate, message in (
        (
            lambda route: route["constraints"][0]["rules"][0].update({"unknown": True}),
            "unknown requestValue rule field",
        ),
        (
            lambda route: route["constraints"][0]["rules"][0]["predicate"].update(
                {"values": ["mixed"]}
            ),
            "mixed requestValue predicate families",
        ),
        (
            lambda route: route["constraints"][0]["rules"][0].update({"name": "missing"}),
            "requestValue path parameter absent from the path",
        ),
        (
            lambda route: route["constraints"][0]["rules"][1].update({"capture": "githubOwner"}),
            "duplicate requestValue capture",
        ),
        (
            lambda route: route["constraints"][0]["rules"][1].update(
                {"capture": "providerAccount"}
            ),
            "reserved provider-account requestValue capture",
        ),
        (
            lambda route: route["constraints"][0].update(
                {"rules": route["constraints"][0]["rules"] * 9}
            ),
            "more than 16 requestValue rules",
        ),
    ):
        invalid = copy.deepcopy(examples)
        invalid_route = next(route for route in invalid["routes"] if route["id"] == github_raw["id"])
        mutate(invalid_route)
        assert_policy_rejected(
            invalid,
            f"compiler accepted {message}",
            validate_schema=validate_schema,
        )

    invalid = copy.deepcopy(examples)
    invalid_route = next(route for route in invalid["routes"] if route["id"] == github_raw["id"])
    invalid_route["constraints"][0]["rules"][0] = {
        "source": "query",
        "name": "visibility",
        "predicate": {"kind": "equals", "value": "public"},
    }
    assert_policy_rejected(
        invalid,
        "compiler accepted requestValue query outside generic allowlist",
        validate_schema=validate_schema,
    )

    github_route = route(example_snapshot, "example.github.issues_since_30_days")
    github_adapter = get_adapter(github_route.adapter_type)
    github_since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    github_flow = flow(
        "GET",
        "https://api.github.com/repos/approved-owner/approved-api/issues"
        f"?state=open&since={github_since}&per_page=10",
    )
    github_operation = github_adapter.operation_fields(
        github_flow,
        github_route,
        {"owner": "approved-owner", "repo": "approved-api"},
    )
    github_decision = evaluate_request_constraints(
        github_flow,
        github_route,
        principal_id="agent:example",
        credential_ref=github_route.credential_ref,
        credential_version=1,
        operation_fields=github_operation,
        consume_rate_limits=False,
        skip_rate_limits=True,
    )
    assert github_decision.allowed
    assert github_operation == {
        "githubOwner": "approved-owner",
        "githubRepository": "approved-api",
    }
    denied_github = flow(
        "GET",
        "https://api.github.com/repos/other/approved-api/issues"
        f"?state=open&since={github_since}&per_page=10",
    )
    denied_github_operation = github_adapter.operation_fields(
        denied_github,
        github_route,
        {"owner": "other", "repo": "approved-api"},
    )
    assert_denied(
        evaluate_request_constraints(
            denied_github,
            github_route,
            principal_id="agent:example",
            credential_ref=github_route.credential_ref,
            credential_version=1,
            operation_fields=denied_github_operation,
            consume_rate_limits=False,
            skip_rate_limits=True,
        ),
        "request_value_predicate_denied",
    )

    stripe_customer_route = route(example_snapshot, "example.stripe.customers.get")
    stripe_customer_flow = flow(
        "GET",
        "https://api.stripe.com/v1/customers/cus_replace_with_approved_customer",
    )
    stripe_customer_operation = get_adapter(stripe_customer_route.adapter_type).operation_fields(
        stripe_customer_flow,
        stripe_customer_route,
        {"customer_id": "cus_replace_with_approved_customer"},
    )
    assert request_decision(
        stripe_customer_route,
        stripe_customer_flow,
        "stripe.customers.get",
        operation_fields=stripe_customer_operation,
    ).allowed
    assert stripe_customer_operation["approvedCustomerId"] == (
        "cus_replace_with_approved_customer"
    )
    assert evaluate_response_binding_sources(
        stripe_customer_route,
        stripe_customer_operation,
    ).allowed

    unknown_field_mutations: list[tuple[str, dict]] = []

    unknown_top = copy.deepcopy(examples)
    unknown_top["unknownPolicyField"] = True
    unknown_field_mutations.append(("top-level", unknown_top))

    unknown_default = copy.deepcopy(examples)
    unknown_default["defaults"]["unknownDefaultField"] = True
    unknown_field_mutations.append(("defaults", unknown_default))

    unknown_route = copy.deepcopy(examples)
    unknown_route["routes"][0]["unknownRouteField"] = True
    unknown_field_mutations.append(("route", unknown_route))

    unknown_jit = copy.deepcopy(examples)
    jit_route = next(item for item in unknown_jit["routes"] if "jit" in item)
    jit_route["jit"]["unknownJitField"] = True
    unknown_field_mutations.append(("JIT", unknown_jit))

    unknown_generic_request = copy.deepcopy(examples)
    generic_route = next(
        item for item in unknown_generic_request["routes"] if item["adapter"]["type"] == "generic.rest"
    )
    generic_route["adapter"]["config"]["request"]["unknownRequestField"] = True
    unknown_field_mutations.append(("generic request", unknown_generic_request))

    for layer, mutation in unknown_field_mutations:
        assert_policy_rejected(
            mutation,
            f"compiler accepted an unknown {layer} policy field",
            validate_schema=validate_schema,
        )
        assert_signed_policy_rejected(
            mutation,
            f"signed compiler path accepted an unknown {layer} policy field",
            validate_schema=validate_schema,
        )

    for aliases, subject in (
        (("x", "twitter", "x.oauth", "x.oauth2", " X.OAUTH2 "), "verified-x-user-id"),
        (("google", "google.oauth", "google.oauth2", " GOOGLE.OAUTH2 "), "verified-google-sub"),
    ):
        alias_scopes = {provider_account_scope_value(alias, subject) for alias in aliases}
        assert len(alias_scopes) == 1, (aliases, alias_scopes)
        assert None not in alias_scopes
        assert provider_account_scope_value(aliases[0], f"{subject}-other") not in alias_scopes

    object_store_example = next(
        item for item in examples["routes"] if item["id"] == "example.object_store.small_puts"
    )
    object_store_operation = object_store_example["adapter"]["config"]["request"]["operation"]
    object_store_body_constraint = next(
        constraint
        for constraint in object_store_example["constraints"]
        if constraint["type"] == "jsonBody"
    )
    assert object_store_operation["bodySha256Field"] == "requestBodySha256"
    assert "sha256" not in object_store_operation.get("jsonFields", [])
    assert "sha256" not in object_store_body_constraint["allowedFields"]
    assert "sha256" not in object_store_body_constraint["requiredFields"]
    assert list(example_snapshot.credentials["cred-gmail"].scopes) == [
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.readonly",
    ]
    for credential_id in ("cred-gmail", "cred-x"):
        assert example_snapshot.credentials[credential_id].injection == {
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
        }
    assert example_snapshot.credentials["cred-object-store"].injection == {
        "type": "header",
        "name": "X-Api-Key",
    }
    assert example_snapshot.credentials["cred-basic-structured"].injection == {
        "type": "basic",
        "username": "service-account",
        "field": "password",
    }
    assert example_snapshot.credentials["cred-query-structured"].injection == {
        "type": "query",
        "name": "api_key",
        "field": "credentials.api_key",
    }
    assert example_snapshot.credentials["cred-cookie-structured"].injection == {
        "type": "cookie",
        "name": "session_token",
        "field": "session.token",
    }
    example_route_ids = {route.id for route in example_snapshot.routes}
    for route_id in (
        "example.basic.structured_secret_read",
        "example.query.structured_secret_read",
        "example.cookie.structured_secret_read",
    ):
        assert route_id in example_route_ids
    valid_injections = (
        {"type": "bearer"},
        {"type": "bearer", "header": "Authorization", "field": "access_token", "prefix": "Bearer "},
        {"type": "basic", "username": "service-account", "header": "Authorization", "field": "password"},
        {"type": "header", "name": "X-Api-Key", "field": "api.key", "prefix": "Token "},
        {"type": "query", "name": "api_key", "field": "token"},
        {"type": "cookie", "name": "session_token", "field": "token"},
    )
    for injection in valid_injections:
        valid = copy.deepcopy(demo_bundle)
        valid["credentials"][0]["injection"] = injection
        compiled = compile_policy_bundle(valid, validate_schema=validate_schema)
        assert compiled.credentials["cred-demo-bearer"].injection == injection

    invalid_injections = (
        ({}, "an injection without a type"),
        ({"type": "basic"}, "Basic injection without a username"),
        ({"type": "basic", "username": ""}, "Basic injection with an empty username"),
        ({"type": "basic", "username": 7}, "Basic injection with a non-string username"),
        ({"type": "basic", "username": "user:name"}, "Basic injection with a colon in its username"),
        ({"type": "basic", "username": "user name"}, "Basic injection with whitespace in its username"),
        ({"type": "basic", "username": "a" * 257}, "Basic injection with an oversized username"),
        ({"type": "header"}, "header injection without a name"),
        ({"type": "query"}, "query injection without a name"),
        ({"type": "cookie"}, "cookie injection without a name"),
        ({"type": "header", "name": ""}, "header injection with an empty name"),
        ({"type": "query", "name": ""}, "query injection with an empty name"),
        ({"type": "cookie", "name": ""}, "cookie injection with an empty name"),
        ({"type": "header", "name": "Bad Header"}, "header injection with an invalid name"),
        ({"type": "query", "name": "api key"}, "query injection with an invalid name"),
        ({"type": "cookie", "name": "session;token"}, "cookie injection with an invalid name"),
        ({"type": "query", "name": "a" * 129}, "query injection with an oversized name"),
        ({"type": "header", "name": "Authorization"}, "custom header injection into Authorization"),
        ({"type": "bearer", "header": "Host"}, "bearer injection into Host"),
        ({"type": "basic", "username": "service", "header": "Cookie"}, "Basic injection into Cookie"),
        ({"type": "header", "name": "X-Serverware-Admin-Token"}, "header injection into service auth"),
        ({"type": "bearer", "name": "X-Api-Key"}, "bearer injection with a header-only name field"),
        ({"type": "basic", "username": "service", "prefix": "Basic "}, "Basic injection with a prefix"),
        ({"type": "header", "name": "X-Api-Key", "username": "service"}, "header injection with a username"),
        ({"type": "query", "name": "api_key", "prefix": "Token "}, "query injection with a prefix"),
        ({"type": "cookie", "name": "session_token", "header": "Cookie"}, "cookie injection with a header"),
        ({"type": "bearer", "header": 7}, "bearer injection with a non-string header"),
        ({"type": "header", "name": 7}, "header injection with a non-string name"),
        ({"type": "bearer", "field": ["access_token"]}, "bearer injection with a non-string field"),
        ({"type": "bearer", "prefix": "Bearer\r\nX-Evil: 1"}, "bearer injection with a multiline prefix"),
        ({"type": "bearer", "unknown": True}, "bearer injection with an unknown field"),
        ({"type": "unsupported"}, "unsupported injection type"),
    )
    for injection, description in invalid_injections:
        invalid = copy.deepcopy(demo_bundle)
        invalid["credentials"][0]["injection"] = injection
        assert_injection_rejected(
            invalid,
            f"compiler accepted {description}",
            validate_schema=validate_schema,
        )
    missing_injection = copy.deepcopy(demo_bundle)
    missing_injection["credentials"][0].pop("injection")
    assert_injection_rejected(
        missing_injection,
        "compiler accepted a credential without an injection declaration",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    stripe = next(
        item for item in invalid["routes"] if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe["adapter"]["config"]["request"]["requiredHeaders"]["idempotency-key"]["type"] = "integer"
    assert_policy_rejected(
        invalid,
        "compiler accepted a non-string generic required header",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    stripe = next(
        item for item in invalid["routes"] if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe["adapter"]["config"]["request"]["requiredHeaders"]["idempotency-key"]["maxLength"] = 9000
    assert_policy_rejected(
        invalid,
        "compiler accepted an unbounded generic required header",
        validate_schema=validate_schema,
    )

    def response_binding_candidate() -> tuple[dict, dict]:
        candidate = copy.deepcopy(examples)
        stripe_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.stripe.payment_intent.tokenized_jit"
        )
        binding_constraint = next(
            constraint
            for constraint in stripe_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        return candidate, binding_constraint

    def json_path_response_binding_candidate() -> tuple[dict, dict, dict]:
        candidate, binding_constraint = response_binding_candidate()
        route_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.stripe.payment_intent.tokenized_jit"
        )
        route_candidate["match"]["paths"] = ["/v1/payment_intents/{payment_intent_id}"]
        request = route_candidate["adapter"]["config"]["request"]
        request["bodyMode"] = "json"
        request["allowedMediaTypes"] = ["application/json"]
        request["operation"] = {
            "name": "stripe.payment_intents.create",
            "jsonFields": ["amount", "currency", "payment_method"],
            "pathParams": ["payment_intent_id"],
        }
        form_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "formBody"
        )
        form_constraint.clear()
        form_constraint.update(
            {
                "id": "payment-intent-json",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["amount", "currency", "payment_method"],
                "requiredFields": ["amount", "currency", "payment_method"],
                "fields": {
                    "amount": {"type": "integer", "min": 50, "max": 50000},
                    "currency": {"type": "string", "equals": "usd"},
                    "payment_method": {
                        "type": "string",
                        "pattern": "^pm_[A-Za-z0-9]{8,64}$",
                        "maxLength": 67,
                    },
                },
            }
        )
        binding_constraint["bindings"].append(
            {
                "id": "payment-intent-id",
                "operationField": "payment_intent_id",
                "responseField": "id",
                "comparison": "exactString",
            }
        )
        return candidate, route_candidate, binding_constraint

    def generated_response_bindings(count: int) -> list[dict]:
        return [
            {
                "id": f"binding-{index}",
                "operationField": "amount",
                "responseField": f"field_{index}",
                "comparison": "canonicalInteger",
            }
            for index in range(count)
        ]

    def body_sha256_candidate() -> tuple[dict, dict, dict]:
        candidate = copy.deepcopy(examples)
        route_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.object_store.small_puts"
        )
        binding_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        return candidate, route_candidate, binding_constraint

    for binding_count in (1, 8):
        valid, response_binding = response_binding_candidate()
        response_binding["bindings"] = generated_response_bindings(binding_count)
        compile_policy_bundle(valid, validate_schema=validate_schema)
    for binding_count in (0, 9):
        invalid, response_binding = response_binding_candidate()
        response_binding["bindings"] = generated_response_bindings(binding_count)
        assert_policy_rejected(
            invalid,
            f"compiler accepted {binding_count} response bindings",
            validate_schema=validate_schema,
        )

    valid_json_path, _, _ = json_path_response_binding_candidate()
    json_path_snapshot = compile_policy_bundle(valid_json_path, validate_schema=validate_schema)

    valid_body_sha256, _, _ = body_sha256_candidate()
    compile_policy_bundle(valid_body_sha256, validate_schema=validate_schema)

    valid_form_body_sha256, form_binding = response_binding_candidate()
    form_route = next(
        item
        for item in valid_form_body_sha256["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_route["adapter"]["config"]["request"]["operation"]["bodySha256Field"] = (
        "requestBodySha256"
    )
    form_binding["bindings"].append(
        {
            "id": "request-body-sha256",
            "operationField": "requestBodySha256",
            "responseField": "request_body_sha256",
            "comparison": "exactString",
        }
    )
    compile_policy_bundle(valid_form_body_sha256, validate_schema=validate_schema)

    for invalid_mode in (
        "none",
        "any",
        "stream",
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        invalid, route_candidate, binding_constraint = body_sha256_candidate()
        route_candidate.pop("credentialRef")
        route_candidate["adapter"]["config"]["request"]["bodyMode"] = invalid_mode
        route_candidate["constraints"] = [
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] != "jsonBody"
        ]
        binding_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        binding_constraint["bindings"] = [binding_constraint["bindings"][-1]]
        assert_policy_rejected(
            invalid,
            f"compiler accepted bodySha256Field with non-buffered body mode {invalid_mode}",
            validate_schema=validate_schema,
        )

    for invalid_name in (None, "operation", "1digest", "digest/value", "a" * 129):
        invalid, route_candidate, _ = body_sha256_candidate()
        route_candidate["adapter"]["config"]["request"]["operation"]["bodySha256Field"] = (
            invalid_name
        )
        assert_policy_rejected(
            invalid,
            f"compiler accepted invalid bodySha256Field name {invalid_name!r}",
            validate_schema=validate_schema,
        )

    for source_key, source_value in (
        ("jsonFields", ["requestBodySha256"]),
        ("pathParams", ["requestBodySha256"]),
        ("formFields", ["requestBodySha256"]),
    ):
        invalid, route_candidate, _ = body_sha256_candidate()
        request = route_candidate["adapter"]["config"]["request"]
        if source_key == "formFields":
            route_candidate.pop("credentialRef")
            request["bodyMode"] = "formUrlencoded"
            request["allowedMediaTypes"] = [
                "application/x-www-form-urlencoded"
            ]
            route_candidate["constraints"] = [
                constraint
                for constraint in route_candidate["constraints"]
                if constraint["type"] != "jsonBody"
            ]
        request["operation"][source_key] = source_value
        assert_policy_rejected(
            invalid,
            f"compiler accepted bodySha256Field duplicated by {source_key}",
            validate_schema=validate_schema,
        )

    invalid, _, binding_constraint = body_sha256_candidate()
    digest_binding = next(
        binding
        for binding in binding_constraint["bindings"]
        if binding["operationField"] == "requestBodySha256"
    )
    digest_binding["comparison"] = "canonicalInteger"
    assert_policy_rejected(
        invalid,
        "compiler accepted canonicalInteger for a bodySha256Field response binding",
        validate_schema=validate_schema,
    )

    valid_path_only, path_only_route, path_only_binding = json_path_response_binding_candidate()
    path_only_request = path_only_route["adapter"]["config"]["request"]
    path_only_request["bodyMode"] = "none"
    path_only_request["allowedMediaTypes"] = []
    path_only_request["maxBodyBytes"] = 0
    path_only_request["operation"].pop("jsonFields")
    path_only_route["constraints"] = [
        constraint
        for constraint in path_only_route["constraints"]
        if constraint["type"] != "jsonBody"
    ]
    path_only_binding["bindings"] = [
        {
            "id": "payment-intent-id",
            "operationField": "payment_intent_id",
            "responseField": "id",
            "comparison": "exactString",
        }
    ]
    compile_policy_bundle(valid_path_only, validate_schema=validate_schema)

    valid_stable_path_source, stable_path_route, _ = json_path_response_binding_candidate()
    stable_path_route["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{left}",
        "/v1/payment_intents/{payment_intent_id}/{right}",
    ]
    compile_policy_bundle(valid_stable_path_source, validate_schema=validate_schema)

    for operation_update, description in (
        ({"jsonFields": ["operation"]}, "the reserved operation field as a JSON source"),
        ({"formFields": ["currency"]}, "mixed form and JSON source kinds"),
        ({"pathParams": ["currency"]}, "a source duplicated across JSON and path sources"),
        ({"jsonFields": ["amount", "amount"]}, "duplicate JSON sources"),
        ({"jsonFields": ["metadata.id"]}, "a dotted JSON source"),
        ({"jsonFields": None}, "a null JSON source declaration"),
        ({"jsonFields": ["amount", []]}, "a non-string JSON source"),
        ({"jsonFields": [f"field_{index}" for index in range(17)]}, "more than 16 JSON sources"),
    ):
        invalid, route_candidate, _ = json_path_response_binding_candidate()
        route_candidate["adapter"]["config"]["request"]["operation"].update(operation_update)
        assert_policy_rejected(
            invalid,
            f"compiler accepted {description}",
            validate_schema=validate_schema,
        )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["adapter"]["config"]["request"]["bodyMode"] = "formUrlencoded"
    assert_policy_rejected(
        invalid,
        "compiler accepted JSON operation sources for a form request",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["adapter"]["config"]["request"]["operation"]["pathParams"] = ["missing_id"]
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source absent from the matched path",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"].append("/v1/payment_intents/static")
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source absent from one matched path",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{other}",
        "/v1/payment_intents/{other}/{payment_intent_id}",
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source mapped to different positions in ambiguous templates",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{payment_intent_id}"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted a repeated path placeholder",
        validate_schema=validate_schema,
    )

    invalid, _, binding_constraint = json_path_response_binding_candidate()
    binding_constraint["bindings"][-1]["comparison"] = "canonicalInteger"
    assert_policy_rejected(
        invalid,
        "compiler accepted canonicalInteger for a path source",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    json_constraint = next(
        constraint for constraint in route_candidate["constraints"] if constraint["type"] == "jsonBody"
    )
    json_constraint["requiredFields"].remove("amount")
    assert_policy_rejected(
        invalid,
        "compiler accepted an optional JSON response binding source",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    json_constraint = next(
        constraint for constraint in route_candidate["constraints"] if constraint["type"] == "jsonBody"
    )
    json_constraint["fields"]["amount"] = {"type": "string", "maxLength": 20}
    assert_policy_rejected(
        invalid,
        "compiler accepted a mistyped JSON response binding source",
        validate_schema=validate_schema,
    )

    invalid, response_binding = response_binding_candidate()
    response_binding["phase"] = "request"
    assert_policy_rejected(
        invalid,
        "compiler accepted a response binding in the request phase",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["unexpected"] = True
    assert_policy_rejected(
        invalid,
        "compiler accepted an extra response binding constraint field",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["unexpected"] = True
    assert_policy_rejected(
        invalid,
        "compiler accepted an extra response binding field",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][1]["id"] = response_binding["bindings"][0]["id"]
    assert_policy_rejected(
        invalid,
        "compiler accepted duplicate response binding ids",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][1]["responseField"] = response_binding["bindings"][0][
        "responseField"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted duplicate response binding paths",
        validate_schema=validate_schema,
    )
    for malformed_path in (".amount", "amount.", "amount..value", "amount[*]"):
        invalid, response_binding = response_binding_candidate()
        response_binding["bindings"][0]["responseField"] = malformed_path
        assert_policy_rejected(
            invalid,
            f"compiler accepted malformed response binding path {malformed_path!r}",
            validate_schema=validate_schema,
        )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["comparison"] = "caseInsensitive"
    assert_policy_rejected(
        invalid,
        "compiler accepted an unsupported response binding comparison",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["operationField"] = "uncaptured"
    assert_policy_rejected(
        invalid,
        "compiler accepted a response binding source not captured by the operation classifier",
        validate_schema=validate_schema,
    )
    for missing_field in ("successStatusCodes", "contentTypes"):
        invalid, response_binding = response_binding_candidate()
        response_binding.pop(missing_field)
        assert_policy_rejected(
            invalid,
            f"compiler accepted response binding without {missing_field}",
            validate_schema=validate_schema,
        )
    for field, value in (
        ("successStatusCodes", [199]),
        ("successStatusCodes", [200, 200]),
        ("contentTypes", ["Application/JSON"]),
        ("contentTypes", ["application/json", "application/json"]),
    ):
        invalid, response_binding = response_binding_candidate()
        response_binding[field] = value
        assert_policy_rejected(
            invalid,
            f"compiler accepted invalid response binding {field}",
            validate_schema=validate_schema,
        )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_constraint = next(
        constraint
        for constraint in stripe_candidate["constraints"]
        if constraint["type"] == "formBody"
    )
    form_constraint["requiredFields"].remove("amount")
    assert_policy_rejected(
        invalid,
        "compiler accepted an optional response binding source",
        validate_schema=validate_schema,
    )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_constraint = next(
        constraint
        for constraint in stripe_candidate["constraints"]
        if constraint["type"] == "formBody"
    )
    form_constraint["fields"]["amount"]["type"] = "string"
    form_constraint["fields"]["amount"].pop("min")
    form_constraint["fields"]["amount"].pop("max")
    assert_policy_rejected(
        invalid,
        "compiler accepted a mistyped response binding source",
        validate_schema=validate_schema,
    )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe_candidate["adapter"]["config"]["response"]["mode"] = "stream"
    assert_policy_rejected(
        invalid,
        "compiler accepted a streaming response binding",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    gmail_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.gmail.last_30_days"
    )
    gmail_candidate["constraints"].append(copy.deepcopy(response_binding))
    assert_policy_rejected(
        invalid,
        "compiler accepted response binding on a non-generic adapter",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    object_store = next(item for item in invalid["routes"] if item["id"] == "example.object_store.small_puts")
    object_store["adapter"]["config"]["request"]["allowedHeaders"].append("x-api-key")
    assert_policy_rejected(
        invalid,
        "compiler accepted an agent header collision with credential injection",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    object_store_credential = next(item for item in invalid["credentials"] if item["id"] == "cred-object-store")
    object_store_credential["injection"] = {"type": "query", "name": "api_key"}
    object_store = next(item for item in invalid["routes"] if item["id"] == "example.object_store.small_puts")
    object_store["adapter"]["config"]["request"]["allowedQueryKeys"].append("api_key")
    assert_policy_rejected(
        invalid,
        "compiler accepted an agent query collision with credential injection",
        validate_schema=validate_schema,
    )
    for provider, subject in (
        ("generic", "verified-subject"),
        ("", "verified-subject"),
        (None, "verified-subject"),
        ("google", " leading-space"),
        ("google", "control\x00character"),
    ):
        invalid_subject = copy.deepcopy(examples)
        credential = invalid_subject["credentials"][1]
        if provider is None:
            credential.pop("provider", None)
        else:
            credential["provider"] = provider
        credential["providerSubject"] = subject
        assert_policy_rejected(
            invalid_subject,
            f"compiler accepted invalid provider subject binding {provider!r} {subject!r}",
            validate_schema=validate_schema,
        )
    x_write_example = next(
        item for item in examples["routes"] if item["id"] == "example.x.tweet.one_per_day"
    )
    account_quota = next(
        item for item in x_write_example["constraints"] if item["type"] == "rateLimit"
    )
    assert account_quota["key"] == {
        "scope": ["route", "operation"],
        "operationFields": ["providerAccount"],
    }
    calendar_policy = copy.deepcopy(examples)
    calendar_route = next(
        item
        for item in calendar_policy["routes"]
        if item["id"] == "example.x.tweet.one_per_day"
    )
    calendar_quota = next(
        item for item in calendar_route["constraints"] if item["type"] == "rateLimit"
    )
    calendar_quota.pop("windowSeconds", None)
    calendar_quota["calendarWindow"] = "utcMonth"
    calendar_snapshot = compile_policy_bundle(
        calendar_policy, validate_schema=validate_schema
    )
    compiled_calendar_route = route(calendar_snapshot, calendar_route["id"])
    compiled_calendar_quota = next(
        item
        for item in compiled_calendar_route.constraints
        if item["type"] == "rateLimit"
    )
    assert compiled_calendar_quota["calendarWindow"] == "utcMonth"

    numeric_bounds_policy = copy.deepcopy(examples)
    numeric_bounds_constraint = next(
        constraint
        for candidate_route in numeric_bounds_policy["routes"]
        for constraint in candidate_route.get("constraints", [])
        if constraint.get("type") == "queryNumericBounds"
    )
    numeric_bounds_constraint["min"] = -2.25
    numeric_bounds_constraint["max"] = -1.5
    numeric_bounds_constraint["integer"] = False
    compile_policy_bundle(
        numeric_bounds_policy, validate_schema=validate_schema
    )

    for label, mutate in (
        (
            "missing rate-limit window",
            lambda quota: (
                quota.pop("windowSeconds", None),
                quota.pop("calendarWindow", None),
            ),
        ),
        (
            "ambiguous rate-limit windows",
            lambda quota: (
                quota.__setitem__("windowSeconds", 60),
                quota.__setitem__("calendarWindow", "utcDay"),
            ),
        ),
        (
            "fractional rate-limit maximum",
            lambda quota: quota.__setitem__("max", 1.5),
        ),
    ):
        invalid_window = copy.deepcopy(examples)
        invalid_route = next(
            item
            for item in invalid_window["routes"]
            if item["id"] == "example.x.tweet.one_per_day"
        )
        invalid_quota = next(
            item for item in invalid_route["constraints"] if item["type"] == "rateLimit"
        )
        mutate(invalid_quota)
        assert_policy_rejected(
            invalid_window,
            f"compiler accepted {label}",
            validate_schema=validate_schema,
        )

    local_calendar = copy.deepcopy(calendar_policy)
    local_calendar_route = next(
        item
        for item in local_calendar["routes"]
        if item["id"] == "example.x.tweet.one_per_day"
    )
    local_calendar_quota = next(
        item
        for item in local_calendar_route["constraints"]
        if item["type"] == "rateLimit"
    )
    local_calendar_quota["store"] = "local"
    assert_policy_rejected(
        local_calendar,
        "compiler accepted a local calendar quota",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    x_credential = next(item for item in invalid["credentials"] if item["id"] == "cred-x")
    x_credential["provider"] = "custom-x"
    x_credential.pop("providerSubject")
    assert_policy_rejected(
        invalid,
        "compiler accepted a provider-account quota without account identity",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    invalid_x_write = next(
        item for item in invalid["routes"] if item["id"] == "example.x.tweet.one_per_day"
    )
    invalid_quota = next(
        item for item in invalid_x_write["constraints"] if item["type"] == "rateLimit"
    )
    invalid_quota["key"]["scope"].append("principal")
    assert_policy_rejected(
        invalid,
        "compiler accepted a provider-account quota partitioned by principal",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    invalid_recent = next(
        item for item in invalid["routes"] if item["id"] == "example.x.search.seven_days"
    )
    invalid_recent["match"]["paths"] = ["/2/tweets/search/all"]
    assert_policy_rejected(
        invalid,
        "compiler accepted an X historical endpoint in recent-search mode",
        validate_schema=validate_schema,
    )
    x_schema = json.loads((ROOT / "schemas" / "adapters" / "x.v2.schema.json").read_text())
    x_schema_operations = set(x_schema["properties"]["allowedReadOperations"]["items"]["enum"])
    assert x_schema_operations == X_V2_READ_OPERATIONS
    assert X_V2_BOUNDED_READ_OPERATIONS == X_V2_READ_OPERATIONS
    assert X_V2_RECENT_SEARCH_PATHS == {
        "/2/tweets/counts/recent",
        "/2/tweets/search/recent",
    }
    assert len(X_V2_RECENT_SEARCH_QUERY_KEYS) == 16
    assert len(X_V2_BOUNDED_READ_QUERY_KEYS) == 55
    assert len(GMAIL_V1_REQUEST_QUERY_KEYS) == 12
    assert len(GMAIL_V1_REQUEST_HEADERS) == 7
    assert len(X_V2_REQUEST_HEADERS) == 4
    assert len(NPM_REGISTRY_REQUEST_HEADERS) == 9
    assert validate_request_target_path(
        "https://registry.npmjs.org/@scope%2fexample"
    )
    assert not validate_request_target_path(
        "https://api.example.test/public/resource"
    )
    for ambiguous_path in (
        "/public/../admin",
        "/public/./resource",
        "/public/%2E%2E/admin",
        "/public/%2e/admin",
        "/public/%5Cadmin",
        "/public\\admin",
        "/public/%252e%252e/admin",
        "/public/%zz/admin",
        "/public//admin",
        "/public/%2Fadmin",
        "/public/value%2fadmin",
    ):
        try:
            validate_request_target_path(
                "https://api.example.test" + ambiguous_path
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"ambiguous provider path was admitted: {ambiguous_path}"
            )
    for canonical_target in (
        "https://api.example.test/resource?data=a%26b%3Dc&literal=%2B&space=%20",
        "https://api.example.test/caf%C3%A9",
        "https://[2001:db8::1]:8443/resource?value=ok",
    ):
        validate_raw_absolute_target(canonical_target)
    for ambiguous_target in (
        "HTTPS://api.example.test/resource?value=ok",
        "https://EXAMPLE.test:443/resource?value=ok",
        "https://user@api.example.test/resource?value=ok",
        "https://api.example.test:443/resource?value=ok",
        "https://api.example.test:0443/resource?value=ok",
        "https://api.example.test/resource#fragment",
        "https://api.example.test\\attacker/resource?value=ok",
        "https://api.example.test/resource?value=customer+name",
        "https://api.example.test/resource?value=%2b",
        "https://api.example.test/resource?value=a%26b%3dc",
        "https://api.example.test/resource?value=a=b",
        "https://api.example.test/resource?value",
        "https://api.example.test/resource?=value",
        "https://api.example.test/resource?value=1&&other=2",
        "https://api.example.test/resource?value=%",
        "https://api.example.test/resource?value=%25",
        "https://api.example.test/resource?value=%252B",
        "https://api.example.test/resource?value=%41",
        "https://api.example.test/resource?value=%C0%AF",
        "https://api.example.test/resource?value=%ED%A0%80",
        "https://api.example.test/resource?value=a/b",
        "https://api.example.test/resource?value=a;b",
        "https://api.example.test/resource?",
        "https://api.example.test",
        "https://api.example.test?value=ok",
    ):
        try:
            validate_raw_absolute_target(ambiguous_target)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"ambiguous absolute target was admitted: {ambiguous_target}"
            )
    for operation, templates in X_V2_READ_OPERATION_PATHS:
        for template in templates:
            concrete_path = "/".join(
                "catalog-value" if segment.startswith("{") and segment.endswith("}") else segment
                for segment in template.split("/")
            )
            assert _x_read_operation(concrete_path) == operation, (concrete_path, operation)

    provider_profile_routes = (
        ("example.gmail.last_30_days", "gmail.v1", None),
        ("example.x.search.seven_days", "x.v2", "recentSearchOnly"),
        ("example.x.full_bounded_read", "x.v2", "readOnly"),
        ("example.x.tweet.one_per_day", "x.v2", "controlledWrite"),
        ("example.npm.publish.yubikey_jit", "npm.registry", None),
    )
    for route_id, adapter_type, mode in provider_profile_routes:
        expected_profile = provider_request_profile(adapter_type, mode)
        configured_route = next(item for item in examples["routes"] if item["id"] == route_id)
        assert configured_route["adapter"]["config"]["request"] == expected_profile

        for field_name, widened_value in (
            ("allowedHeaders", "x-provider-profile-widening"),
            ("allowedQueryKeys", "serverware_unknown_query"),
            ("allowedMediaTypes", "text/plain"),
        ):
            invalid = copy.deepcopy(examples)
            request_profile = next(
                item for item in invalid["routes"] if item["id"] == route_id
            )["adapter"]["config"]["request"]
            request_profile[field_name].append(widened_value)
            assert_policy_rejected(
                invalid,
                f"compiler accepted widened {adapter_type} {field_name}",
                validate_schema=validate_schema,
            )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile["allowedHeaders"].pop()
        assert_policy_rejected(
            invalid,
            f"compiler accepted narrowed {adapter_type} allowedHeaders",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile.pop("discardHeaders")
        if adapter_type == "npm.registry":
            assert_policy_rejected(
                invalid,
                "compiler accepted an npm provider profile without its explicit discard preset",
                validate_schema=validate_schema,
            )
        else:
            compile_policy_bundle(
                invalid,
                validate_schema=validate_schema,
            )
            legacy_empty_discard_signed_policy = sign_policy_bundle(
                copy.deepcopy(invalid)
            )
            compile_policy_bundle(
                legacy_empty_discard_signed_policy,
                verify_signature=True,
                validate_schema=validate_schema,
            )

        customized = copy.deepcopy(examples)
        request_profile = next(
            item for item in customized["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile["discardHeaders"] = sorted(
            set(expected_profile["discardHeaders"]) | {"x-client-retry"}
        )
        compile_policy_bundle(
            customized,
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile["allowedHeaders"].append(request_profile["allowedHeaders"][0])
        assert_policy_rejected(
            invalid,
            f"compiler accepted duplicate {adapter_type} allowedHeaders",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile["allowedHeaders"][0] = request_profile["allowedHeaders"][0].upper()
        assert_policy_rejected(
            invalid,
            f"compiler accepted non-lowercase {adapter_type} allowedHeaders",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile.pop("maxBodyBytes")
        assert_policy_rejected(
            invalid,
            f"compiler accepted incomplete {adapter_type} request profile",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(examples)
        request_profile = next(
            item for item in invalid["routes"] if item["id"] == route_id
        )["adapter"]["config"]["request"]
        request_profile["maxBodyBytes"] = max(0, expected_profile["maxBodyBytes"] - 1)
        if request_profile["maxBodyBytes"] == expected_profile["maxBodyBytes"]:
            request_profile["maxBodyBytes"] = expected_profile["maxBodyBytes"] + 1
        assert_policy_rejected(
            invalid,
            f"compiler accepted altered {adapter_type} maxBodyBytes",
            validate_schema=validate_schema,
        )

    generic_empty_body_route = SimpleNamespace(
        adapter_config={
            "request": {
                "allowedHeaders": ["content-type"],
                "allowedMediaTypes": ["application/json"],
                "allowedQueryKeys": [],
                "bodyMode": "json",
                "discardHeaders": [],
                "maxBodyBytes": 1024,
                "requiredHeaders": {},
            }
        },
        credential_ref=None,
        constraints=(),
    )
    typed_empty_body_route = SimpleNamespace(
        adapter_config={
            "request": provider_request_profile("npm.registry"),
        }
    )
    generic_empty_allowlist_route = SimpleNamespace(
        adapter_config={
            "request": {
                "allowedHeaders": ["content-type"],
                "allowedMediaTypes": [],
                "allowedQueryKeys": [],
                "bodyMode": "none",
                "discardHeaders": [],
                "maxBodyBytes": 0,
                "requiredHeaders": {},
            }
        },
        credential_ref=None,
        constraints=(),
    )

    def empty_body_flow(content_type: str | None) -> SimpleNamespace:
        headers = {}
        if content_type is not None:
            headers["content-type"] = content_type
        request = SimpleNamespace(
            headers=headers,
            pretty_url="https://registry.npmjs.org/example",
            raw_content=b"",
            get_content=lambda strict=True: b"",
        )
        return SimpleNamespace(request=request)

    for label, content_type, allowed in (
        ("present wrong", "text/plain", False),
        ("present valid", "application/json", True),
        ("absent", None, True),
    ):
        preflight_flow = empty_body_flow(content_type)
        preflight_decision = preflight_request_admission(
            preflight_flow,
            generic_empty_body_route,
            {
                str(name).lower(): str(value)
                for name, value in preflight_flow.request.headers.items()
            },
        )
        if preflight_decision.allowed is not allowed:
            raise AssertionError(
                f"raw preflight empty-body media fixture {label} produced "
                f"{preflight_decision}"
            )

        generic_decision = get_adapter("generic.rest").validate_request(
            empty_body_flow(content_type),
            generic_empty_body_route,
            {},
        )
        if generic_decision.allowed is not allowed:
            raise AssertionError(
                f"generic adapter empty-body media fixture {label} produced "
                f"{generic_decision}"
            )

        typed_decision = get_adapter(
            "npm.registry"
        )._validate_provider_request_profile(
            empty_body_flow(content_type),
            typed_empty_body_route,
        )
        if typed_decision.allowed is not allowed:
            raise AssertionError(
                f"typed provider empty-body media fixture {label} produced "
                f"{typed_decision}"
            )

    empty_allowlist_flow = empty_body_flow("application/json")
    assert_denied(
        preflight_request_admission(
            empty_allowlist_flow,
            generic_empty_allowlist_route,
            {"content-type": "application/json"},
        ),
        "request_content_type_denied",
    )
    assert_denied(
        get_adapter("generic.rest").validate_request(
            empty_body_flow("application/json"),
            generic_empty_allowlist_route,
            {},
        ),
        "request_content_type_denied",
    )

    def generic_discard_bundle(headers: list[str]) -> tuple[dict, dict]:
        candidate = copy.deepcopy(examples)
        candidate_route = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.slack.chat_post.hourly"
        )
        candidate_route["adapter"]["config"]["request"]["discardHeaders"] = headers
        return candidate, candidate_route

    valid_generic_discard, _ = generic_discard_bundle(["x-client-retry"])
    compile_policy_bundle(
        valid_generic_discard,
        validate_schema=validate_schema,
    )

    invalid_content_encoding, invalid_content_encoding_route = (
        generic_discard_bundle([])
    )
    invalid_content_encoding_request = invalid_content_encoding_route[
        "adapter"
    ]["config"]["request"]
    invalid_content_encoding_request["allowedHeaders"].append(
        "content-encoding"
    )
    invalid_content_encoding_request["allowedHeaders"].sort()
    assert_policy_rejected(
        invalid_content_encoding,
        "compiler accepted unbounded request content-encoding forwarding",
        validate_schema=validate_schema,
    )
    for identity_header in (
        "content-encoding",
        "content-length",
        "transfer-encoding",
    ):
        invalid_identity = copy.deepcopy(examples)
        invalid_identity["principals"][0]["requiredHeaders"][
            identity_header
        ] = "selector-value"
        assert_policy_rejected(
            invalid_identity,
            f"compiler accepted raw admission header {identity_header} "
            "as a principal selector",
            validate_schema=validate_schema,
        )
        try:
            _validate_generic_required_headers(
                "route:raw-admission-selector-negative",
                {
                    "requiredHeaders": {
                        identity_header: {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                        }
                    }
                },
                {identity_header},
            )
        except PolicyBundleError:
            pass
        else:
            raise AssertionError(
                f"generic requiredHeaders accepted raw admission selector "
                f"{identity_header}"
            )

    discard_admission_negatives = (
        (
            ["x-discard-01", "x-discard-00"],
            "compiler accepted unsorted discardHeaders",
        ),
        (
            ["X-Client-Retry"],
            "compiler accepted a discardHeaders case variant",
        ),
        (
            ["x-client-retry", "x-client-retry"],
            "compiler accepted duplicate discardHeaders",
        ),
        (
            ["x-client-retry", "x_client_retry"],
            "compiler accepted underscore-equivalent discardHeaders aliases",
        ),
        (
            [f"x-discard-{index:02d}" for index in range(17)],
            "compiler accepted more than 16 discardHeaders",
        ),
    )
    for discard_headers, label in discard_admission_negatives:
        invalid, _ = generic_discard_bundle(discard_headers)
        assert_policy_rejected(
            invalid,
            label,
            validate_schema=validate_schema,
        )

    for reserved_name in (
        "authorization",
        "connection",
        "content-length",
        "content_type",
        "cookie",
        "host",
        "idempotency-key",
        "if-match",
        "npm-command",
        "proxy_authorization",
        "sec-fetch-site",
        "signature",
        "traceparent",
        "x-api-key",
        "x-goog-user-project",
        "x-custom-token",
        "x-forwarded-for",
        "x_serverware_agent",
    ):
        invalid, _ = generic_discard_bundle([reserved_name])
        assert_policy_rejected(
            invalid,
            f"compiler accepted reserved discard header {reserved_name}",
            validate_schema=validate_schema,
        )

    valid_npm_session_discard, _ = generic_discard_bundle(["npm-session"])
    compile_policy_bundle(
        valid_npm_session_discard,
        validate_schema=validate_schema,
    )

    invalid, _ = generic_discard_bundle(["user-agent"])
    assert_policy_rejected(
        invalid,
        "compiler accepted discardHeaders overlap with allowedHeaders",
        validate_schema=validate_schema,
    )

    invalid, invalid_route = generic_discard_bundle(["x-request-marker"])
    invalid_request = invalid_route["adapter"]["config"]["request"]
    invalid_request["allowedHeaders"].append("x-request-marker")
    invalid_request["allowedHeaders"].sort()
    invalid_request["requiredHeaders"] = {
        "x-request-marker": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
        }
    }
    assert_policy_rejected(
        invalid,
        "compiler accepted discardHeaders overlap with requiredHeaders",
        validate_schema=validate_schema,
    )
    try:
        validate_discard_headers(
            "route:direct-required-overlap",
            {"discardHeaders": ["x-request-marker"]},
            required_headers={"x-request-marker"},
        )
    except PolicyBundleError as exc:
        assert "requiredHeaders" in str(exc), exc
    else:
        raise AssertionError(
            "typed discard validator accepted direct requiredHeaders overlap"
        )

    invalid, invalid_route = generic_discard_bundle(["x-provider-value"])
    invalid_route["credentialRef"] = "cred-slack"
    next(
        item for item in invalid["credentials"] if item["id"] == "cred-slack"
    )["injection"] = {
        "type": "header",
        "name": "x-provider-value",
    }
    assert_policy_rejected(
        invalid,
        "compiler accepted discardHeaders overlap with credential injection",
        validate_schema=validate_schema,
    )

    invalid, _ = generic_discard_bundle(["x-agent-selector"])
    invalid["principals"][0]["requiredHeaders"]["x-agent-selector"] = "bound-agent"
    assert_policy_rejected(
        invalid,
        "compiler accepted discardHeaders overlap with principal identity",
        validate_schema=validate_schema,
    )

    invalid, invalid_route = generic_discard_bundle([])
    invalid["principals"][0]["requiredHeaders"]["x-agent-selector"] = "bound-agent"
    invalid_request = invalid_route["adapter"]["config"]["request"]
    invalid_request["allowedHeaders"].append("x-agent-selector")
    invalid_request["allowedHeaders"].sort()
    invalid_request["requiredHeaders"] = {
        "x-agent-selector": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
        }
    }
    assert_policy_rejected(
        invalid,
        "compiler accepted provider requiredHeaders overlap with principal identity",
        validate_schema=validate_schema,
    )

    if validate_schema:
        invalid_field = json.loads(json.dumps(examples))
        invalid_field["credentials"][0]["injection"]["field"] = "*.access_token"
        try:
            compile_policy_bundle(invalid_field, validate_schema=True)
        except Exception:
            pass
        else:
            raise AssertionError("schema accepted wildcard credential injection field")

    for invalid_mode in ("bogus", 7, None):
        invalid = copy.deepcopy(demo_bundle)
        invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = invalid_mode
        assert_policy_rejected(
            invalid,
            f"compiler accepted unsupported response mode {invalid_mode!r}",
            validate_schema=validate_schema,
        )
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"].pop("mode")
    assert_policy_rejected(invalid, "compiler accepted a missing response mode", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = "any"
    assert_policy_rejected(
        invalid,
        "compiler accepted an opaque credential-bearing response",
        validate_schema=validate_schema,
    )
    explicit_opaque = copy.deepcopy(demo_bundle)
    explicit_opaque_route = explicit_opaque["routes"][0]
    explicit_opaque_route.pop("credentialRef")
    explicit_opaque_route.pop("constraints", None)
    explicit_opaque_route["adapter"]["config"]["request"]["bodyMode"] = "any"
    explicit_opaque_response = explicit_opaque_route["adapter"]["config"]["response"]
    explicit_opaque_response["mode"] = "any"
    explicit_opaque_response.pop("allowedFields")
    explicit_opaque_snapshot = compile_policy_bundle(
        explicit_opaque,
        validate_schema=validate_schema,
    )
    assert route(explicit_opaque_snapshot, "demo.echo").credential_ref is None
    for projection_value, failure in (
        (None, "is missing allowedFields"),
        ([], "allowedFields must not be empty"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        generic_response = invalid["routes"][0]["adapter"]["config"]["response"]
        if projection_value is None:
            generic_response.pop("allowedFields")
        else:
            generic_response["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.echo credential-bearing JSON success response {failure}",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(demo_bundle)
        x_write = next(item for item in invalid["routes"] if item["id"] == "demo.x.tweet.one_per_day")
        if projection_value is None:
            x_write["adapter"]["config"]["response"].pop("allowedFields")
        else:
            x_write["adapter"]["config"]["response"]["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.x.tweet.one_per_day credential-bearing JSON success response {failure}",
            validate_schema=validate_schema,
        )

    for response_mode in (
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        for projection_value, failure in (
            (None, "is missing allowedFields"),
            ([], "allowedFields must not be empty"),
        ):
            invalid = copy.deepcopy(demo_bundle)
            response = invalid["routes"][0]["adapter"]["config"]["response"]
            response["mode"] = response_mode
            if projection_value is None:
                response.pop("allowedFields")
            else:
                response["allowedFields"] = projection_value
            assert_policy_rejected_reason(
                invalid,
                f"route demo.echo credential-bearing {response_mode} success response {failure}",
                validate_schema=validate_schema,
            )
    for projection_value, failure in (
        (None, "is missing allowedFields"),
        ([], "allowedFields must not be empty"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        error_response = {
            "mode": "json",
            "maxBodyBytes": 4096,
            "allowedFields": ["error", "code"],
            "allowedHeaders": [],
            "onInvalid": "block",
        }
        invalid["routes"][0]["adapter"]["config"]["response"]["error"] = error_response
        if projection_value is None:
            error_response.pop("allowedFields")
        else:
            error_response["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.echo credential-bearing JSON error response {failure}",
            validate_schema=validate_schema,
        )

    missing_json_body_policy = copy.deepcopy(demo_bundle)
    missing_json_route = missing_json_body_policy["routes"][0]
    missing_json_route["adapter"]["config"]["request"]["bodyMode"] = "json"
    missing_json_route.pop("constraints", None)
    assert_compiler_rejected_reason(
        missing_json_body_policy,
        "route demo.echo credential-bearing generic.rest bodyMode json requires "
        "a jsonBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    wrong_json_body_policy = copy.deepcopy(missing_json_body_policy)
    wrong_json_body_policy["routes"][0]["constraints"] = [
        {
            "id": "wrong-form-body-policy",
            "type": "formBody",
            "allowedFields": ["safe"],
        }
    ]
    assert_compiler_rejected_reason(
        wrong_json_body_policy,
        "route demo.echo credential-bearing generic.rest bodyMode json requires "
        "a jsonBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    credential_json_bundle = copy.deepcopy(missing_json_body_policy)
    credential_json_bundle["routes"][0]["constraints"] = [
        {
            "id": "echo-json-body",
            "type": "jsonBody",
            "contentTypes": ["application/json"],
            "allowedFields": ["safe", "nested.value"],
        }
    ]
    credential_json_snapshot = compile_policy_bundle(
        credential_json_bundle,
        validate_schema=validate_schema,
    )
    opaque_credential_body = copy.deepcopy(demo_bundle)
    opaque_credential_body["routes"][0]["adapter"]["config"]["request"]["bodyMode"] = "any"
    assert_compiler_rejected_reason(
        opaque_credential_body,
        "route demo.echo credential-bearing generic.rest routes cannot use opaque bodyMode any",
        validate_schema=validate_schema,
    )
    empty_json_allowlist = copy.deepcopy(credential_json_bundle)
    empty_json_allowlist["routes"][0]["constraints"][0]["allowedFields"] = []
    assert_policy_rejected(
        empty_json_allowlist,
        "compiler accepted a credential-bearing JSON body policy with an empty allowlist",
        validate_schema=validate_schema,
    )

    missing_form_body_policy = copy.deepcopy(examples)
    missing_form_route = next(
        item
        for item in missing_form_body_policy["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    missing_form_route["constraints"] = [
        constraint
        for constraint in missing_form_route["constraints"]
        if constraint["type"] != "formBody"
    ]
    assert_compiler_rejected_reason(
        missing_form_body_policy,
        "route example.stripe.payment_intent.tokenized_jit credential-bearing generic.rest "
        "bodyMode formUrlencoded requires a formBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    for request_mode in (
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        valid_stream_request = copy.deepcopy(demo_bundle)
        valid_stream_route = valid_stream_request["routes"][0]
        valid_stream_route.pop("credentialRef")
        stream_request = valid_stream_route["adapter"]["config"]["request"]
        stream_request["bodyMode"] = request_mode
        stream_request["allowedMediaTypes"] = [
            {
                "jsonlStream": "application/x-ndjson",
                "jsonArrayStream": "application/json",
                "jsonSseStream": "text/event-stream",
                "jsonNestedStream": "application/json",
                "formUrlencodedStream": "application/x-www-form-urlencoded",
                "csvStream": "text/csv",
            }[request_mode]
        ]
        stream_request["allowedFields"] = ["safe", "nested.value"]
        compile_policy_bundle(valid_stream_request, validate_schema=validate_schema)

        missing_stream_media = copy.deepcopy(valid_stream_request)
        missing_stream_media["routes"][0]["adapter"]["config"]["request"].pop(
            "allowedMediaTypes"
        )
        assert_policy_rejected(
            missing_stream_media,
            f"compiler accepted {request_mode} request without allowedMediaTypes",
            validate_schema=validate_schema,
        )

        missing_stream_fields = copy.deepcopy(valid_stream_request)
        missing_stream_fields["routes"][0]["adapter"]["config"]["request"].pop("allowedFields")
        assert_policy_rejected(
            missing_stream_fields,
            f"compiler accepted {request_mode} request without allowedFields",
            validate_schema=validate_schema,
        )

    invalid_stream_fields = (
        ([], "empty"),
        (["safe", "safe"], "duplicate"),
        (["safe.*"], "non-dotted-path"),
        (["a" * 257], "overlong"),
        ([f"field{index}" for index in range(65)], "oversized"),
    )
    for allowed_fields, description in invalid_stream_fields:
        invalid_stream_request = copy.deepcopy(demo_bundle)
        invalid_stream_route = invalid_stream_request["routes"][0]
        invalid_stream_route.pop("credentialRef")
        request = invalid_stream_route["adapter"]["config"]["request"]
        request["bodyMode"] = "jsonlStream"
        request["allowedMediaTypes"] = ["application/x-ndjson"]
        request["allowedFields"] = allowed_fields
        assert_policy_rejected(
            invalid_stream_request,
            f"compiler accepted {description} structured stream request allowedFields",
            validate_schema=validate_schema,
        )

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["request"]["bodyMode"] = "stream"
    assert_compiler_rejected_reason(
        invalid,
        "route demo.echo credential-bearing generic.rest routes cannot use "
        "opaque bodyMode stream",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["adapter"]["config"]["response"]["allowedHeaders"] = ["etag"]
    assert_policy_rejected(
        invalid,
        "compiler accepted released upstream headers on a streaming response",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    npm_route = next(item for item in invalid["routes"] if item["adapter"]["type"] == "npm.registry")
    npm_route["adapter"]["config"].pop("response")
    assert_policy_rejected(invalid, "compiler accepted npm without a response policy", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["metadata"]["validFrom"] = "2030-01-01T00:00:00Z"
    assert_policy_rejected(invalid, "compiler accepted unenforced validFrom", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["defaults"]["validationFailure"] = "allowWithAudit"
    assert_policy_rejected(invalid, "compiler accepted fail-open validation", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid.pop("defaults")
    assert_policy_rejected(invalid, "compiler accepted implicit policy defaults", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:spiffe", "spiffeIds": ["spiffe://example.test/agent"]}
    assert_policy_rejected(invalid, "compiler accepted unsupported SPIFFE identity", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:unconstrained"}
    assert_policy_rejected(invalid, "compiler accepted unconstrained principal", validate_schema=validate_schema)

    jit_route = next(item for item in demo_bundle["routes"] if item.get("jit"))
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["approvers"]["quorum"] = 2
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT quorum", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["approvers"]["users"] = ["*"]
    assert_policy_rejected(invalid, "compiler accepted wildcard JIT approver authority", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    approver_users = next(
        item for item in invalid["routes"] if item["id"] == jit_route["id"]
    )["jit"]["approvers"]["users"]
    approver_users.append(approver_users[0])
    assert_policy_rejected(invalid, "compiler accepted duplicate JIT approvers", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["consumeOn"] = "successfulResponse"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT consumption", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["mode"] = "perRequest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT mode", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["binding"]["type"] = "unknownDigest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT binding", validate_schema=validate_schema)

    gmail_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "gmail.v1")
    canonical_metadata_fetch = {
        "maxMessages": 10,
        "perRequestTimeoutMs": 1500,
        "totalTimeoutMs": 8000,
        "maxBodyBytes": 4096,
    }
    assert gmail_route_raw["adapter"]["config"]["response"]["metadataFetch"] == (
        canonical_metadata_fetch
    )
    compile_policy_bundle(
        sign_policy_bundle(copy.deepcopy(demo_bundle)),
        verify_signature=True,
        validate_schema=validate_schema,
    )

    for mutation, message in (
        (lambda item: item["adapter"]["config"].__setitem__("forceQuery", False), "disabled Gmail query bounding"),
        (
            lambda item: item["adapter"]["config"]["response"].__setitem__("validateInternalDate", False),
            "disabled Gmail response age validation",
        ),
        (lambda item: item.pop("credentialRef"), "credentialless Gmail route"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
        mutation(target)
        assert_policy_rejected(invalid, f"compiler accepted {message}", validate_schema=validate_schema)

    schema_rejected_gmail_mutations = (
        (
            lambda response: response.pop("metadataFetch"),
            "signed Gmail metadata hydration without metadataFetch",
        ),
        (
            lambda response: response["metadataFetch"].__setitem__("maxMessages", 33),
            "signed Gmail metadata hydration with excessive maxMessages",
        ),
        (
            lambda response: response["metadataFetch"].__setitem__("perRequestTimeoutMs", 3001),
            "signed Gmail metadata hydration with excessive perRequestTimeoutMs",
        ),
        (
            lambda response: response["metadataFetch"].__setitem__("totalTimeoutMs", 10001),
            "signed Gmail metadata hydration with excessive totalTimeoutMs",
        ),
        (
            lambda response: response["metadataFetch"].__setitem__("maxBodyBytes", 8193),
            "signed Gmail metadata hydration with excessive maxBodyBytes",
        ),
        (
            lambda response: response["metadataFetch"].update(
                {"perRequestTimeoutMs": 1001, "totalTimeoutMs": 1000}
            ),
            "signed Gmail metadata hydration with per-request timeout above total timeout",
        ),
        (
            lambda response: response["allowedFields"].remove("id"),
            "signed Gmail metadata hydration without id projection",
        ),
        (
            lambda response: response["metadataFetch"].pop("maxBodyBytes"),
            "signed Gmail metadata hydration with an incomplete metadataFetch object",
        ),
        (
            lambda response: response["metadataFetch"].__setitem__("unexpected", 1),
            "signed Gmail metadata hydration with an unknown metadataFetch field",
        ),
    )
    for mutation, message in schema_rejected_gmail_mutations:
        invalid = copy.deepcopy(demo_bundle)
        target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
        mutation(target["adapter"]["config"]["response"])
        assert_signed_policy_and_schema_rejected(
            invalid,
            message,
            validate_schema=validate_schema,
        )

    for field_name in canonical_metadata_fetch:
        for invalid_value in (0, True, str(canonical_metadata_fetch[field_name])):
            invalid = copy.deepcopy(demo_bundle)
            target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
            target["adapter"]["config"]["response"]["metadataFetch"][field_name] = invalid_value
            assert_signed_policy_and_schema_rejected(
                invalid,
                f"signed Gmail metadata hydration with coerced {field_name}={invalid_value!r}",
                validate_schema=validate_schema,
            )

        invalid = copy.deepcopy(demo_bundle)
        target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
        integral_float = float(canonical_metadata_fetch[field_name])
        target["adapter"]["config"]["response"]["metadataFetch"][field_name] = integral_float
        assert_signed_policy_rejected(
            invalid,
            f"compiler accepted Gmail metadata hydration with {field_name}={integral_float!r}",
            validate_schema=validate_schema,
        )

    invalid = copy.deepcopy(demo_bundle)
    target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
    target["adapter"]["config"]["maxResults"] = 9
    assert_signed_policy_rejected(
        invalid,
        "compiler accepted Gmail metadataFetch maxMessages greater than maxResults",
        validate_schema=validate_schema,
    )

    metadata_fetch_disabled = copy.deepcopy(demo_bundle)
    target = next(
        item for item in metadata_fetch_disabled["routes"] if item["id"] == gmail_route_raw["id"]
    )
    response = target["adapter"]["config"]["response"]
    response["validateListByMetadataFetch"] = False
    response.pop("metadataFetch")
    response["allowedFields"].remove("id")
    compile_policy_bundle(
        sign_policy_bundle(metadata_fetch_disabled),
        verify_signature=True,
        validate_schema=validate_schema,
    )

    npm_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "npm.registry")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"]).pop("jit")
    assert_policy_rejected(invalid, "compiler accepted npm writes without JIT", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])["jit"]["approvers"]["authn"][
        "requireHardwareAttestation"
    ] = False
    assert_policy_rejected(invalid, "compiler accepted npm writes without hardware attestation", validate_schema=validate_schema)

    public_npm = copy.deepcopy(demo_bundle)
    public_npm_route = next(
        item for item in public_npm["routes"] if item["id"] == npm_route_raw["id"]
    )
    public_npm_route["match"]["host"] = "registry.npmjs.org"
    public_npm_route["adapter"]["config"][
        "publishResponseContract"
    ] = "npm-public-registry-receipt-v1"
    public_npm_route["adapter"]["config"]["response"]["allowedFields"] = [
        "ok",
        "published",
    ]
    public_npm_route["adapter"]["config"]["response"]["allowedHeaders"] = []
    public_npm_route["constraints"] = [
        constraint
        for constraint in public_npm_route["constraints"]
        if constraint["type"] not in {"responseBinding", "responseJson"}
    ]
    public_npm_snapshot = compile_policy_bundle(
        sign_policy_bundle(public_npm),
        verify_signature=True,
        validate_schema=validate_schema,
    )

    for mutation, expected_reason, schema_rejects in (
        (
            lambda item: item["adapter"]["config"].pop("publishResponseContract"),
            f"route {npm_route_raw['id']} public npm.publish requires "
            "publishResponseContract npm-public-registry-receipt-v1",
            False,
        ),
        (
            lambda item: item["adapter"]["config"]["response"].__setitem__(
                "allowedFields", ["package", "version", "published"]
            ),
            f"route {npm_route_raw['id']} public npm.publish response must project exactly ok and published",
            True,
        ),
        (
            lambda item: item["adapter"]["config"]["response"].__setitem__(
                "allowedHeaders", ["etag"]
            ),
            f"route {npm_route_raw['id']} public npm.publish response must not release upstream headers",
            True,
        ),
    ):
        invalid_public = copy.deepcopy(public_npm)
        mutation(
            next(
                item
                for item in invalid_public["routes"]
                if item["id"] == npm_route_raw["id"]
            )
        )
        assert_signed_policy_rejected_reason(
            invalid_public,
            expected_reason,
            validate_schema=False,
        )
        if validate_schema and schema_rejects:
            assert_signed_policy_and_schema_rejected(
                invalid_public,
                "an invalid public npm publish receipt projection",
                validate_schema=True,
            )

    constrained_public = copy.deepcopy(public_npm)
    constrained_public_route = next(
        item
        for item in constrained_public["routes"]
        if item["id"] == npm_route_raw["id"]
    )
    constrained_public_route["constraints"].append(
        {
            "id": "untrusted-public-publish-identity",
            "type": "responseJson",
            "phase": "response",
            "fields": {"published": {"type": "boolean", "equals": True}},
        }
    )
    assert_signed_policy_rejected_reason(
        constrained_public,
        f"route {npm_route_raw['id']} public npm.publish receipt must not use responseBinding or responseJson",
        validate_schema=validate_schema,
    )

    non_public_without_response_identity = copy.deepcopy(public_npm)
    non_public_route = next(
        item
        for item in non_public_without_response_identity["routes"]
        if item["id"] == npm_route_raw["id"]
    )
    non_public_route["match"]["host"] = "registry.example.test"
    non_public_route["adapter"]["config"].pop("publishResponseContract")
    assert_signed_policy_rejected_reason(
        non_public_without_response_identity,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseBinding scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["constraints"] = [
        constraint
        for constraint in invalid_npm["constraints"]
        if constraint["type"] != "responseBinding"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseBinding scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["constraints"] = [
        constraint
        for constraint in invalid_npm["constraints"]
        if constraint["type"] != "responseJson"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseJson success constraint scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_json = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseJson"
    )
    response_json["fields"]["published"]["equals"] = False
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish responseJson success constraint must require published to equal true",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["bindings"] = [
        binding for binding in response_binding["bindings"] if binding["operationField"] != "packageVersion"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} must bind npm.publish packageName and packageVersion",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["operations"] = ["npm.distTagWrite"]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} must be scoped only to configured npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["successStatusCodes"] = [202]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} npm.publish successStatusCodes may contain only 200 or 201",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["contentTypes"] = ["application/problem+json"]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} npm.publish contentTypes must be exactly application/json",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["adapter"]["config"]["response"]["maxBodyBytes"] = 65537
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding requires a buffered JSON response capped at 65536 bytes",
        validate_schema=validate_schema,
    )

    x_read_route_raw = next(item for item in demo_bundle["routes"] if item["id"] == "demo.x.readonly")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])["match"]["methods"].append(
        "POST"
    )
    assert_policy_rejected(invalid, "compiler accepted writes on an X read route", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_read = next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])
    invalid_x_read["adapter"]["config"]["allowedReadOperations"].append("streams.read")
    assert_policy_rejected(
        invalid,
        "compiler accepted streams mixed with bounded X reads",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_write = next(item for item in invalid["routes"] if item["id"] == "demo.x.tweet.one_per_day")
    invalid_x_write["constraints"] = [
        constraint for constraint in invalid_x_write["constraints"] if constraint["type"] != "jsonBody"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted an unconstrained X post body",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {"id": "empty-schedule", "type": "requestTimeWindow", "timezone": "UTC"}
    ]
    assert_policy_rejected(invalid, "compiler accepted an empty request schedule", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "overlapping-schedule",
            "type": "requestTimeWindow",
            "timezone": "UTC",
            "dailyWindows": [
                {"start": "09:00", "end": "12:00"},
                {"start": "11:00", "end": "13:00"},
            ],
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted overlapping request windows", validate_schema=validate_schema)

    schedule = {
        "id": "weekday-hours",
        "type": "requestTimeWindow",
        "timezone": "UTC",
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2027-01-01T00:00:00Z",
        "weekdays": ["mon", "tue", "wed", "thu", "fri"],
        "dailyWindows": [{"start": "13:00", "end": "15:00"}],
    }
    assert _enforce_request_time_window(
        schedule,
        now=datetime(2026, 7, 14, 14, 0, tzinfo=timezone.utc),
    ).allowed
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc),
        ),
        "request_time_daily_window_denied",
    )
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc),
        ),
        "request_time_weekday_denied",
    )

    numeric_route_raw = next(
        item
        for item in demo_bundle["routes"]
        if any(constraint.get("type") == "queryNumericBounds" for constraint in item.get("constraints") or [])
    )
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint.pop("min", None)
    numeric_constraint.pop("max", None)
    assert_policy_rejected(invalid, "compiler accepted a no-op numeric bound", validate_schema=validate_schema)
    for bound in ("min", "max"):
        for value in (float("nan"), float("inf"), float("-inf"), 10**400):
            invalid = copy.deepcopy(demo_bundle)
            numeric_constraint = next(
                constraint
                for constraint in next(
                    item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"]
                )["constraints"]
                if constraint["type"] == "queryNumericBounds"
            )
            numeric_constraint[bound] = value
            assert_policy_rejected(
                invalid,
                f"compiler accepted invalid query numeric {bound}: {value!r}",
                validate_schema=validate_schema,
            )
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint["allowedOperations"] = ["silently.ignored"]
    assert_policy_rejected(invalid, "compiler accepted a cross-type constraint field", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    body_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] in {"jsonBody", "formBody"}
    )
    body_constraint.pop("allowedFields", None)
    assert_policy_rejected(
        invalid,
        "compiler accepted a body policy that could not reject unknown fields",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["phase"] = "request"
    assert_policy_rejected(invalid, "compiler accepted request-phase response constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["operations"] = []
    assert_policy_rejected(invalid, "compiler accepted an empty response operation selector", validate_schema=validate_schema)

    invalid = copy.deepcopy(examples)
    response_json = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseJson"
    )
    response_json["fields"] = {}
    assert_policy_rejected(invalid, "compiler accepted responseJson without field assertions", validate_schema=validate_schema)

    invalid = copy.deepcopy(examples)
    response_json = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseJson"
    )
    response_json["items"] = ["bad.*.path"]
    assert_policy_rejected(invalid, "compiler accepted wildcard responseJson items", validate_schema=validate_schema)

    for field, value, label in (
        ("required", "yes", "non-boolean responseJson required flag"),
        ("items", [{"path": "data"}], "non-string responseJson item path"),
        ("operations", [{"operation": "widgets.read"}], "non-string responseJson operation"),
    ):
        invalid = copy.deepcopy(examples)
        response_json = next(
            constraint
            for item in invalid["routes"]
            for constraint in item.get("constraints", [])
            if constraint["type"] == "responseJson"
        )
        response_json[field] = value
        assert_policy_rejected(invalid, f"compiler accepted {label}", validate_schema=validate_schema)

    invalid_response_rules = (
        ({"type": "string", "unknown": True}, "unknown responseJson field rule"),
        ({"required": "yes"}, "non-boolean responseJson required rule"),
        ({"enum": []}, "empty responseJson enum"),
        ({"enum": ["same", "same"]}, "duplicate responseJson enum"),
        ({"minLength": 1}, "string length rule without an explicit type"),
        ({"type": "number", "maxLength": 10}, "string length rule on a numeric field"),
        ({"type": "string", "min": 0}, "numeric rule on a string field"),
        ({"max": 10}, "numeric rule without an explicit type"),
        ({"type": "string", "minItems": 0}, "array item rule on a string field"),
        ({"maxItems": 10}, "array item rule without an explicit type"),
        ({"minLength": 5, "maxLength": 4}, "inverted responseJson length range"),
        ({"min": 5, "max": 4}, "inverted responseJson numeric range"),
        ({"pattern": "^[0-9]{1,4}$"}, "unbounded responseJson pattern input"),
        (
            {"pattern": "^[0-9]{1,4}$", "maxLength": 4097},
            "oversized responseJson pattern input",
        ),
        (
            {"pattern": "^[0-9]+$", "maxLength": 64},
            "responseJson pattern outside bounded runtime grammar",
        ),
    )
    for rule, label in invalid_response_rules:
        invalid = copy.deepcopy(examples)
        response_json = next(
            constraint
            for item in invalid["routes"]
            for constraint in item.get("constraints", [])
            if constraint["type"] == "responseJson"
        )
        response_json["fields"]["id"] = rule
        assert_policy_rejected(invalid, f"compiler accepted {label}", validate_schema=validate_schema)

    assert bounded_pattern_matches("^v1.:[0-9]{1,2}$", "v1.:12") is True
    assert bounded_pattern_matches("^v1.:[0-9]{1,2}$", "v1X:12") is False

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["phase"] = "both"
    assert_policy_rejected(invalid, "compiler accepted ambiguous constraint phase", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["operations"] = ["unsupported.request.selector"]
    assert_policy_rejected(invalid, "compiler accepted response-only operation selectors on a request constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["match"]["paths"] = ["/allowed/**/suffix"]
    assert_policy_rejected(invalid, "compiler accepted a non-terminal recursive wildcard", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsupported-extension",
            "type": "operationPolicy",
            "allowedOperations": ["read"],
            "extensions": {"runtime": "not-attested"},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unattested policy extension", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsafe-pattern",
            "type": "jsonBody",
            "allowedFields": ["name"],
            "fields": {"name": {"type": "string", "pattern": "(a+)+$", "maxLength": 100}},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unsafe regex policy", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["constraints"] = [
        {
            "id": "stream-response-window",
            "type": "responseDateWindow",
            "phase": "response",
            "dateFields": ["created_at"],
            "formats": ["rfc3339"],
            "maxAgeDays": 1,
            "required": True,
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted whole-response validation on a stream", validate_schema=validate_schema)

    generic_route = route(example_snapshot, "example.stripe.customers.list")
    generic_adapter = get_adapter(generic_route.adapter_type)
    generic_request = flow("GET", "https://api.stripe.com/v1/customers?limit=5")
    assert generic_adapter.validate_request(generic_request, generic_route, {}).allowed
    generic_request.request.headers["x-http-method-override"] = "POST"
    assert_denied(generic_adapter.validate_request(generic_request, generic_route, {}), "request_header_not_allowed")
    generic_with_body = flow("GET", "https://api.stripe.com/v1/customers", {"unexpected": True})
    assert_denied(generic_adapter.validate_request(generic_with_body, generic_route, {}), "request_body_too_large")

    credential_json_route = route(credential_json_snapshot, "demo.echo")
    credential_json_adapter = get_adapter(credential_json_route.adapter_type)
    credential_json_bypass = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {
            "safe": "expected",
            "admin": True,
            "callback_url": "https://attacker.example",
        },
    )
    original_json_body = credential_json_bypass.request.raw_content
    assert credential_json_adapter.validate_request(
        credential_json_bypass,
        credential_json_route,
        {},
    ).allowed
    assert_denied(
        request_decision(credential_json_route, credential_json_bypass, "echo"),
        "json_body_field_not_allowed",
    )
    assert credential_json_bypass.request.raw_content == original_json_body
    assert credential_json_adapter.rewrite_request(
        credential_json_bypass,
        credential_json_route,
        {},
    ).allowed
    assert credential_json_bypass.request.raw_content == original_json_body

    for invalid_json_body in (
        b'{"safe":"first","safe":"second"}',
        b'{"nested":{"value":1,"value":2}}',
        b'{"safe":NaN}',
        b'{"safe":Infinity}',
        b'{"safe":-Infinity}',
        b'{"safe":1e400}',
        b'{"safe":"\xff"}',
    ):
        invalid_json_request = flow(
            "POST",
            "https://demo-upstream:8443/echo",
            {"safe": "placeholder"},
        )
        invalid_json_request.request.raw_content = invalid_json_body
        assert_denied(
            credential_json_adapter.validate_request(
                invalid_json_request,
                credential_json_route,
                {},
            ),
            "request_json_invalid",
        )
        assert_denied(
            request_decision(credential_json_route, invalid_json_request, "echo"),
            "json_body_invalid",
        )

    structured_json_vectors = (
        (
            credential_json_adapter._redact_json_lines,
            b'{"safe":1,"safe":2}\n',
        ),
        (
            credential_json_adapter._redact_json_array,
            b'[{"safe":NaN}]',
        ),
        (
            credential_json_adapter._redact_json_nested,
            b'{"safe":"\xff"}',
        ),
        (
            credential_json_adapter._redact_json_sse,
            b'data: {"safe":Infinity}\n\n',
        ),
    )
    for parser, hostile_body in structured_json_vectors:
        try:
            parser(hostile_body, [("safe",)])
        except ValueError:
            pass
        else:
            raise AssertionError(
                "structured JSON parser accepted duplicate keys, a non-finite "
                "number, or invalid UTF-8"
            )
    assert credential_json_adapter._redact_json_array(
        b'[{"z":0,"safe":{"z":2,"a":1}}]',
        [("safe",)],
    ) == b'[{"safe":{"a":1,"z":2}}]'

    for stale_constraints in (
        (),
        ({"type": "jsonBody", "allowedFields": []},),
        (
            {
                "type": "jsonBody",
                "phase": "response",
                "allowedFields": ["safe"],
            },
        ),
    ):
        stale_json_route = SimpleNamespace(
            credential_ref=credential_json_route.credential_ref,
            adapter_config=credential_json_route.adapter_config,
            constraints=stale_constraints,
        )
        stale_json_decision = credential_json_adapter.validate_request(
            credential_json_bypass,
            stale_json_route,
            {},
        )
        assert_denied(stale_json_decision, "credential_request_body_policy_missing")
        assert stale_json_decision.status_code == 500
        assert stale_json_decision.payload["requiredConstraint"] == "jsonBody"

    stale_opaque_route = SimpleNamespace(
        credential_ref=credential_json_route.credential_ref,
        adapter_config={
            **credential_json_route.adapter_config,
            "request": {
                **credential_json_route.adapter_config["request"],
                "bodyMode": "any",
            },
        },
        constraints=(),
    )
    assert_denied(
        credential_json_adapter.validate_request(
            credential_json_bypass,
            stale_opaque_route,
            {},
        ),
        "credential_opaque_request_body_denied",
    )

    credentialless_json_bundle = copy.deepcopy(missing_json_body_policy)
    credentialless_json_bundle["routes"][0].pop("credentialRef")
    credentialless_json_snapshot = compile_policy_bundle(
        credentialless_json_bundle,
        validate_schema=validate_schema,
    )
    credentialless_json_route = route(credentialless_json_snapshot, "demo.echo")
    credentialless_json_request = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {"safe": "expected", "unrestricted_public_field": True},
    )
    credentialless_json_body = credentialless_json_request.request.raw_content
    assert credential_json_adapter.validate_request(
        credentialless_json_request,
        credentialless_json_route,
        {},
    ).allowed
    assert credential_json_adapter.rewrite_request(
        credentialless_json_request,
        credentialless_json_route,
        {},
    ).allowed
    assert credentialless_json_request.request.raw_content == credentialless_json_body

    explicit_any_route = route(explicit_opaque_snapshot, "demo.echo")
    explicit_any_request = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {"explicitly": "opaque", "admin": True},
    )
    explicit_any_body = explicit_any_request.request.raw_content
    assert generic_adapter.validate_request(explicit_any_request, explicit_any_route, {}).allowed
    assert generic_adapter.rewrite_request(explicit_any_request, explicit_any_route, {}).allowed
    assert explicit_any_request.request.raw_content == explicit_any_body

    slack_route = route(example_snapshot, "example.slack.chat_post.hourly")
    slack_request = flow(
        "POST",
        "https://slack.com/api/chat.postMessage",
        {"channel": "C123", "text": "bounded message"},
    )
    slack_body = slack_request.request.raw_content
    assert generic_adapter.validate_request(slack_request, slack_route, {}).allowed
    assert generic_adapter.rewrite_request(slack_request, slack_route, {}).allowed
    assert slack_request.request.raw_content == slack_body

    for stream_fields, expected_error in (
        (None, "streaming_redaction_request_allowed_fields_missing"),
        (["safe", "safe"], "streaming_redaction_request_allowed_fields_invalid"),
    ):
        stream_request_config = {
            "allowedHeaders": ["content-type"],
            "allowedMediaTypes": ["application/x-ndjson"],
            "allowedQueryKeys": [],
            "bodyMode": "jsonlStream",
            "maxBodyBytes": 4096,
        }
        if stream_fields is not None:
            stream_request_config["allowedFields"] = stream_fields
        stale_stream_route = SimpleNamespace(
            credential_ref=None,
            adapter_config={"request": stream_request_config},
            constraints=(),
        )
        stale_stream_request = flow(
            "POST",
            "https://api.example.test/events",
            {"safe": "value"},
        )
        assert_denied(
            generic_adapter.validate_request(stale_stream_request, stale_stream_route, {}),
            expected_error,
        )

    for projection in (None, []):
        response_config = {"mode": "json", "maxBodyBytes": 4096, "allowedHeaders": []}
        if projection is not None:
            response_config["allowedFields"] = projection
        unprojected_route = SimpleNamespace(
            credential_ref="cred-generic",
            adapter_config={"response": response_config},
        )
        unprojected = flow(
            "GET",
            "https://api.example.test/data",
            response={"id": "safe", "provider_internal_secret": "must-not-release"},
        )
        decision = generic_adapter.validate_response(unprojected, unprojected_route, {})
        assert_denied(decision, "credential_response_projection_required")
        assert decision.status_code == 502
        assert decision.reason == "credential-bearing response requires a non-empty allowedFields projection"
        assert decision.payload == {
            "error": "credential_response_projection_required",
            "adapter": "generic.rest",
            "mode": "json",
        }

    source_with_siblings = {
        "data": {"id": "safe", "provider_internal_secret": "nested-secret"},
        "provider_internal_secret": "top-level-secret",
    }
    assert generic_adapter._redact_json(source_with_siblings, []) == {}
    assert generic_adapter._redact_json([source_with_siblings], []) == []
    projected_route = SimpleNamespace(
        credential_ref="cred-generic",
        adapter_config={
            "response": {
                "mode": "json",
                "maxBodyBytes": 4096,
                "allowedFields": ["data.id"],
                "allowedHeaders": [],
            }
        },
    )
    projected = flow(
        "GET",
        "https://api.example.test/data",
        response=source_with_siblings,
    )
    projected.response.headers["content-type"] = ' Application/JSON ; charset="utf-8" '
    assert generic_adapter.prepare_response(projected, projected_route, {}).allowed
    assert generic_adapter.validate_response(projected, projected_route, {}).allowed
    assert json.loads(projected.response.get_text()) == {"data": {"id": "safe"}}
    assert projected.response.headers == {
        "Content-Type": "application/json",
        "Content-Length": str(len(projected.response.raw_content)),
    }
    for hostile_json_response in (
        b'{"data":{"id":"first","id":"second"}}',
        b'{"data":{"id":NaN}}',
        b'{"data":{"id":"\xff"}}',
    ):
        hostile_projected = flow(
            "GET",
            "https://api.example.test/data",
            response=source_with_siblings,
        )
        hostile_projected.response.raw_content = hostile_json_response
        assert_denied(
            generic_adapter.validate_response(
                hostile_projected,
                projected_route,
                {},
            ),
            "response_invalid_json",
        )

    for label, response_headers in (
        ("missing", {}),
        (
            "duplicate",
            {"content-type": "application/json", "Content-Type": "application/json"},
        ),
        ("malformed", {"content-type": "application/json; charset"}),
        ("different", {"content-type": "application/problem+json"}),
    ):
        denied_media_type = flow(
            "GET",
            "https://api.example.test/data",
            response={"data": {"id": "must-not-release"}},
        )
        denied_media_type.response.headers = response_headers
        denied_media_type.response.raw_content = b"not-json-and-must-not-release"
        original_body = denied_media_type.response.raw_content
        for decision in (
            generic_adapter.prepare_response(denied_media_type, projected_route, {}),
            generic_adapter.validate_response(denied_media_type, projected_route, {}),
        ):
            assert_denied(decision, "response_json_content_type_denied")
            assert decision.status_code == 502, (label, decision)
        assert denied_media_type.response.raw_content == original_body, label

    explicit_opaque_route = SimpleNamespace(
        credential_ref=None,
        adapter_config={
            "response": {"mode": "any", "maxBodyBytes": 4096, "allowedHeaders": []}
        },
    )
    explicit_opaque_response = flow(
        "GET",
        "https://public.example.test/data",
        response=source_with_siblings,
    )
    original_opaque_body = explicit_opaque_response.response.raw_content
    assert generic_adapter.validate_response(
        explicit_opaque_response,
        explicit_opaque_route,
        {},
    ).allowed
    assert explicit_opaque_response.response.raw_content == original_opaque_body

    x_projection_route = route(demo, "demo.x.tweet.one_per_day")
    x_projection = flow(
        "POST",
        "https://demo-upstream:8443/2/tweets",
        response=source_with_siblings,
    )
    x_projection.response.headers["content-type"] = "application/json;charset=utf-8"
    assert get_adapter("x.v2").prepare_response(x_projection, x_projection_route, {}).allowed
    assert get_adapter("x.v2").validate_response(x_projection, x_projection_route, {}).allowed
    assert json.loads(x_projection.response.get_text()) == {"data": {"id": "safe"}}

    x_wrong_media_type = flow(
        "POST",
        "https://demo-upstream:8443/2/tweets",
        response=source_with_siblings,
    )
    x_wrong_media_type.response.headers["content-type"] = "text/json"
    assert_denied(
        get_adapter("x.v2").prepare_response(
            x_wrong_media_type,
            x_projection_route,
            {},
        ),
        "response_json_content_type_denied",
    )
    assert_denied(
        get_adapter("x.v2").validate_response(
            x_wrong_media_type,
            x_projection_route,
            {},
        ),
        "response_json_content_type_denied",
    )

    object_store_route = route(example_snapshot, "example.object_store.small_puts")
    object_store_adapter = get_adapter(object_store_route.adapter_type)
    object_store_body = b'{"content":"hello","contentType":"text/plain"}'
    expected_object_store_digest = (
        "sha256:292df0fecc76d806319901d8e74c1f5de3cd776d05d4e4e72bdc44e83492d010"
    )
    assert expected_object_store_digest == f"sha256:{hashlib.sha256(object_store_body).hexdigest()}"
    object_store_request = flow(
        "PUT",
        "https://objects.example.com/v1/buckets/agent-artifacts/objects/report-1",
    )
    object_store_request.request.raw_content = object_store_body
    object_store_operation = object_store_adapter.operation_fields(
        object_store_request,
        object_store_route,
        {"bucket": "agent-artifacts", "artifact_id": "report-1"},
    )
    assert object_store_operation == {
        "operation": "object_store.objects.put",
        "artifact_id": "report-1",
        "requestBodySha256": expected_object_store_digest,
    }
    assert request_decision(
        object_store_route,
        object_store_request,
        "object_store.objects.put",
        operation_fields=object_store_operation,
    ).allowed
    assert object_store_operation["validatedBucket"] == "agent-artifacts"
    assert object_store_operation["validatedObjectKey"] == "report-1"

    caller_digest = "sha256:" + "0" * 64
    caller_digest_request = copy.deepcopy(object_store_request)
    caller_digest_request.request.raw_content = json.dumps(
        {"content": "hello", "requestBodySha256": caller_digest},
        separators=(",", ":"),
    ).encode("utf-8")
    caller_digest_operation = object_store_adapter.operation_fields(
        caller_digest_request,
        object_store_route,
        {"bucket": "agent-artifacts", "artifact_id": "report-1"},
    )
    assert caller_digest_operation["requestBodySha256"] == (
        f"sha256:{hashlib.sha256(caller_digest_request.request.raw_content).hexdigest()}"
    )
    assert caller_digest_operation["requestBodySha256"] != caller_digest

    object_store_response = flow(
        "PUT",
        "https://objects.example.com/v1/buckets/agent-artifacts/objects/report-1",
        response={"ok": True, "id": "report-1", "sha256": expected_object_store_digest},
    )
    object_store_response.metadata["serverware_operation"] = object_store_operation
    assert evaluate_response_constraints(object_store_response, object_store_route).allowed
    mismatched_object_store_digest = copy.deepcopy(object_store_response)
    mismatched_object_store_digest.response.raw_content = json.dumps(
        {"ok": True, "id": "report-1", "sha256": "sha256:" + "a" * 64}
    ).encode("utf-8")
    assert_response_binding_denied(
        evaluate_response_constraints(mismatched_object_store_digest, object_store_route),
        "response_binding_mismatch",
        binding_id="sha256",
    )
    wrong_object_store_status = copy.deepcopy(object_store_response)
    wrong_object_store_status.response.raw_content = json.dumps(
        {"ok": False, "id": "report-1", "sha256": expected_object_store_digest}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(wrong_object_store_status, object_store_route),
        "response_json_field_equals_denied",
    )
    malformed_object_store_digest = copy.deepcopy(object_store_response)
    malformed_object_store_digest.response.raw_content = json.dumps(
        {"ok": True, "id": "report-1", "sha256": "not-a-digest"}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(malformed_object_store_digest, object_store_route),
        "response_json_field_pattern_denied",
    )
    missing_object_store_id = copy.deepcopy(object_store_response)
    missing_object_store_id.response.raw_content = json.dumps(
        {"ok": True, "sha256": "sha256:" + "a" * 64}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(missing_object_store_id, object_store_route),
        "response_json_required_field_missing",
    )
    response_items_route = SimpleNamespace(
        constraints=[
            {
                "id": "typed-results",
                "type": "responseJson",
                "phase": "response",
                "items": ["data"],
                "required": True,
                "fields": {
                    "status": {"required": True, "type": "string", "enum": ["ready", "done"]},
                    "score": {"required": True, "type": "number", "min": 0, "max": 1},
                    "tags": {"type": "array", "maxItems": 3},
                },
            }
        ]
    )
    typed_results = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "ready", "score": 0.8, "tags": ["safe"]}]},
    )
    assert evaluate_response_constraints(typed_results, response_items_route).allowed
    bad_result = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "unknown", "score": 0.8}]},
    )
    assert_denied(
        evaluate_response_constraints(bad_result, response_items_route),
        "response_json_field_enum_denied",
    )
    high_score = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "ready", "score": 1.1}]},
    )
    assert_denied(
        evaluate_response_constraints(high_score, response_items_route),
        "response_json_field_max",
    )
    for invalid_response_body in (
        b'{"data":[{"status":"ready","status":"done","score":0.8}]}',
        b'{"data":[{"status":"ready","score":NaN}]}',
        b'{"data":[{"status":"ready","score":Infinity}]}',
        b'{"data":[{"status":"ready","score":-Infinity}]}',
        b'{"data":[{"status":"ready","score":1e400}]}',
    ):
        invalid_result = flow(
            "GET",
            "https://api.example.test/results",
            response={"data": []},
        )
        invalid_result.response.raw_content = invalid_response_body
        assert_denied(
            evaluate_response_constraints(invalid_result, response_items_route),
            "response_json_invalid",
        )
    missing_results = flow("GET", "https://api.example.test/results", response={"meta": {}})
    assert_denied(
        evaluate_response_constraints(missing_results, response_items_route),
        "response_json_items_missing",
    )

    stripe_route = route(example_snapshot, "example.stripe.payment_intent.tokenized_jit")
    stripe_adapter = get_adapter(stripe_route.adapter_type)
    stripe_request = flow("POST", "https://api.stripe.com/v1/payment_intents")
    stripe_request.request.headers["content-type"] = "application/x-www-form-urlencoded"
    stripe_request.request.raw_content = (
        b"amount=5000&currency=usd&payment_method=pm_12345678&confirm=true&"
        b"metadata%5Bagent_request_id%5D=req-123"
    )
    assert_denied(
        stripe_adapter.validate_request(stripe_request, stripe_route, {}),
        "required_header_missing",
    )
    stripe_request.request.headers["idempotency-key"] = "agent-payment:req-123"
    assert stripe_adapter.validate_request(stripe_request, stripe_route, {}).allowed
    invalid_idempotency_key = copy.deepcopy(stripe_request)
    invalid_idempotency_key.request.headers["idempotency-key"] = "invalid key with spaces"
    assert_denied(
        stripe_adapter.validate_request(invalid_idempotency_key, stripe_route, {}),
        "required_header_invalid",
    )
    stripe_operation = stripe_adapter.operation_fields(stripe_request, stripe_route, {})
    assert stripe_operation == {
        "operation": "stripe.payment_intents.create",
        "amount": "5000",
        "currency": "usd",
        "payment_method": "pm_12345678",
        "confirm": "true",
        "metadata.agent_request_id": "req-123",
    }, stripe_operation
    stripe_digest_route = copy.deepcopy(stripe_route)
    stripe_digest_route.adapter_config["request"]["operation"]["bodySha256Field"] = (
        "requestBodySha256"
    )
    stripe_digest_operation = stripe_adapter.operation_fields(
        stripe_request,
        stripe_digest_route,
        {},
    )
    assert stripe_digest_operation["requestBodySha256"] == (
        f"sha256:{hashlib.sha256(stripe_request.request.raw_content).hexdigest()}"
    )
    assert evaluate_response_binding_sources(stripe_route, stripe_operation).allowed
    assert request_decision(stripe_route, stripe_request, "stripe.payment_intents.create").allowed

    json_source_route = SimpleNamespace(
        adapter_config={
            "request": {
                "bodyMode": "json",
                "operation": {
                    "name": "example.json.capture",
                    "jsonFields": [
                        "text",
                        "minimum",
                        "maximum",
                        "boolean",
                        "floating",
                        "null_value",
                        "array_value",
                        "object_value",
                        "too_large",
                        "lone_surrogate",
                    ],
                    "pathParams": ["artifact_id"],
                },
            }
        }
    )
    json_source_request = flow(
        "PUT",
        "https://api.example.test/artifacts/artifact-123",
        body={
            "text": "Gr\u00fc\u00dfe",
            "minimum": -(2**63),
            "maximum": 2**63 - 1,
            "metadata.id": "literal-top-level",
            "metadata": {"id": "must-not-traverse"},
            "boolean": True,
            "floating": 1.0,
            "null_value": None,
            "array_value": ["value"],
            "object_value": {"value": "nested"},
            "too_large": 2**63,
        },
    )
    json_source_fields = stripe_adapter.operation_fields(
        json_source_request,
        json_source_route,
        {"artifact_id": "artifact-123"},
    )
    assert json_source_fields == {
        "operation": "example.json.capture",
        "artifact_id": "artifact-123",
        "text": "Gr\u00fc\u00dfe",
        "minimum": str(-(2**63)),
        "maximum": str(2**63 - 1),
    }, json_source_fields

    dotted_json_source_route = copy.deepcopy(json_source_route)
    dotted_json_source_route.adapter_config["request"]["operation"]["jsonFields"] = ["metadata.id"]
    assert stripe_adapter.operation_fields(
        json_source_request,
        dotted_json_source_route,
        {"artifact_id": "artifact-123"},
    ) == {
        "operation": "example.json.capture",
        "artifact_id": "artifact-123",
    }

    invalid_json_source_bodies = (
        b'{"text":"first-secret","text":"second-secret"}',
        b'{"text":',
        b'["not-an-object"]',
        b'{"text":"\\ud800"}',
        b'{"minimum":-0}',
    )
    for invalid_body in invalid_json_source_bodies:
        invalid_json_source = copy.deepcopy(json_source_request)
        invalid_json_source.request.raw_content = invalid_body
        assert stripe_adapter.operation_fields(
            invalid_json_source,
            json_source_route,
            {"artifact_id": "artifact-123"},
        ) == {
            "operation": "example.json.capture",
            "artifact_id": "artifact-123",
        }

    json_binding_route = route(
        json_path_snapshot,
        "example.stripe.payment_intent.tokenized_jit",
    )
    malformed_bound_json = flow(
        "POST",
        "https://api.stripe.com/v1/payment_intents/pi_12345678",
        body={"amount": 5000, "currency": "usd", "payment_method": "pm_12345678"},
    )
    malformed_bound_json.request.headers["idempotency-key"] = "agent-payment:req-json"
    malformed_bound_json.request.raw_content = (
        b'{"amount":5000,"amount":5001,"currency":"usd",'
        b'"payment_method":"pm_12345678"}'
    )
    malformed_operation_fields = stripe_adapter.operation_fields(
        malformed_bound_json,
        json_binding_route,
        {"payment_intent_id": "pi_12345678"},
    )
    assert malformed_operation_fields == {
        "operation": "stripe.payment_intents.create",
        "payment_intent_id": "pi_12345678",
    }
    assert_denied(
        request_decision(
            json_binding_route,
            malformed_bound_json,
            "stripe.payment_intents.create",
            operation_fields=malformed_operation_fields,
        ),
        "json_body_invalid",
    )
    assert_response_binding_denied(
        evaluate_response_binding_sources(json_binding_route, malformed_operation_fields),
        "response_binding_source_missing",
        binding_id="amount",
        evidence=False,
    )

    secret_path_source = "path-source-canary-never-disclose"
    path_source_route = SimpleNamespace(
        constraints=(
            {
                "id": "path-source-binding",
                "type": "responseBinding",
                "phase": "response",
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "artifact-id",
                        "operationField": "artifact_id",
                        "responseField": "id",
                        "comparison": "exactString",
                    }
                ],
            },
        )
    )
    path_source_denial = evaluate_response_binding_sources(
        path_source_route,
        {"artifact_id": secret_path_source + "x" * 4096},
    )
    assert_response_binding_denied(
        path_source_denial,
        "response_binding_source_missing",
        binding_id="artifact-id",
        evidence=False,
        sensitive_values=(secret_path_source,),
    )

    matching_stripe_response = flow(
        "POST",
        "https://api.stripe.com/v1/payment_intents",
        response={
            "id": "pi_12345678",
            "object": "payment_intent",
            "amount": 5000,
            "currency": "usd",
            "payment_method": "pm_12345678",
            "status": "succeeded",
        },
    )
    matching_stripe_response.metadata.update(
        {
            "serverware_operation": stripe_operation,
            "serverware_policy_hash": "sha256:" + "1" * 64,
            "serverware_request_digest": "sha256:" + "2" * 64,
            "serverware_operation_digest": "sha256:" + "3" * 64,
        }
    )
    matching_binding_decision = evaluate_response_constraints(
        matching_stripe_response,
        stripe_route,
        constraint_types={"responseBinding"},
    )
    assert matching_binding_decision.allowed
    assert len(matching_binding_decision.payload["bindings"]) == 3
    assert "pm_12345678" not in json.dumps(matching_binding_decision.payload)
    assert evaluate_response_constraints(matching_stripe_response, stripe_route).allowed
    wrong_stripe_object = copy.deepcopy(matching_stripe_response)
    wrong_stripe_object.response.raw_content = json.dumps(
        {
            "id": "obj_12345678",
            "object": "arbitrary",
            "amount": 5000,
            "currency": "usd",
            "payment_method": "pm_12345678",
        }
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(wrong_stripe_object, stripe_route),
        "response_json_field_pattern_denied",
    )
    if evaluate_response is not None:
        original_response_log = runtime.log_request
        response_logs: list[tuple] = []
        runtime.log_request = lambda *args, **_kwargs: response_logs.append(args)
        try:
            audited_response = copy.deepcopy(matching_stripe_response)
            audited_response.metadata.update(
                {
                    "serverware_route": stripe_route,
                    "serverware_route_id": stripe_route.id,
                    "serverware_params": {},
                    "serverware_principal_id": "agent:example",
                    "serverware_credential_id": stripe_route.credential_ref,
                    "serverware_credential_version": 1,
                }
            )
            assert evaluate_response(audited_response).allowed
            released_event = response_logs[-1][6]
            assert released_event["response_validation"]["ok"] is True
            assert len(released_event["response_validation"]["bindings"]) == 3
            assert "serverware_operation" not in released_event
            assert "pm_12345678" not in json.dumps(released_event)

            response_logs.clear()
            denied_response = copy.deepcopy(audited_response)
            denied_response.response.raw_content = json.dumps(
                {
                    "id": "pi_12345678",
                    "object": "payment_intent",
                    "amount": 5001,
                    "currency": "usd",
                    "payment_method": "pm_12345678",
                }
            ).encode("utf-8")
            assert_denied(evaluate_response(denied_response), "response_binding_mismatch")
            blocked_event = response_logs[-1][6]
            assert blocked_event["response_validation"]["ok"] is False
            assert blocked_event["response_validation"]["binding_id"] == "amount"
            assert blocked_event["response_validation"]["evidence_digest"].startswith("sha256:")
            assert "pm_12345678" not in json.dumps(blocked_event)
            assert "5001" not in json.dumps(blocked_event)
        finally:
            runtime.log_request = original_response_log

    for status_code, headers, expected_error in (
        (201, {"content-type": "application/json"}, "response_binding_status_denied"),
        (200, {"content-type": "text/plain"}, "response_binding_content_type_denied"),
        (200, {"content-type": "application/json", "content-encoding": "gzip"}, "response_binding_content_encoding_denied"),
    ):
        denied_envelope = copy.deepcopy(matching_stripe_response)
        denied_envelope.response.status_code = status_code
        denied_envelope.response.headers = headers
        assert_response_binding_denied(
            evaluate_response_constraints(
                denied_envelope,
                stripe_route,
                constraint_types={"responseBinding"},
            ),
            expected_error,
            binding_id=None,
        )

    ordered_envelope_denial = copy.deepcopy(matching_stripe_response)
    ordered_envelope_denial.response.status_code = 201
    ordered_envelope_denial.response.raw_content = b"not-json"
    assert_response_binding_denied(
        evaluate_response_constraints(ordered_envelope_denial, stripe_route),
        "response_binding_status_denied",
        binding_id=None,
    )

    for array_body in (
        b'[{"amount":5000,"currency":"usd","payment_method":"pm_12345678"}]',
        b'[{"amount":5000},{"currency":"usd"},{"payment_method":"pm_12345678"}]',
    ):
        array_response = copy.deepcopy(matching_stripe_response)
        array_response.response.raw_content = array_body
        assert_response_binding_denied(
            evaluate_response_constraints(
                array_response,
                stripe_route,
                constraint_types={"responseBinding"},
            ),
            "response_binding_object_required",
            binding_id=None,
        )
    nested_array_route = copy.deepcopy(stripe_route)
    nested_binding = next(
        constraint
        for constraint in nested_array_route.constraints
        if constraint.get("type") == "responseBinding"
    )
    nested_binding["bindings"][0]["responseField"] = "data.amount"
    nested_array_response = copy.deepcopy(matching_stripe_response)
    nested_array_response.response.raw_content = (
        b'{"data":[{"amount":5000}],"currency":"usd","payment_method":"pm_12345678"}'
    )
    assert_response_binding_denied(
        evaluate_response_constraints(
            nested_array_response,
            nested_array_route,
            constraint_types={"responseBinding"},
        ),
        "response_binding_field_ambiguous",
        binding_id="amount",
    )
    for invalid_body, sensitive_values in (
        (
            b'{"amount":5000,"currency":"response-json-canary-a","currency":"usd"}',
            ("response-json-canary-a",),
        ),
        (b'{"amount":NaN,"currency":"usd"}', ()),
    ):
        invalid_json_response = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response={},
        )
        invalid_json_response.response.raw_content = invalid_body
        invalid_json_response.metadata["serverware_operation"] = stripe_operation
        decision = evaluate_response_constraints(
            invalid_json_response,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            "response_binding_json_invalid",
            binding_id=None,
            sensitive_values=sensitive_values,
        )

    for response, binding_id, expected_error in (
        (
            {"amount": 5001, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": "eur", "payment_method": "pm_12345678"},
            "currency",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": "usd"},
            "payment-method",
            "response_binding_field_ambiguous",
        ),
        (
            {"currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_field_ambiguous",
        ),
        (
            {"amount": "5000", "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000.0, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": True, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": 7, "payment_method": "pm_12345678"},
            "currency",
            "response_binding_mismatch",
        ),
    ):
        mismatched = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response=response,
        )
        mismatched.metadata["serverware_operation"] = stripe_operation
        decision = evaluate_response_constraints(
            mismatched,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            expected_error,
            binding_id=binding_id,
        )
        assert decision.status_code == 502

    missing_binding_source = dict(stripe_operation)
    missing_binding_source.pop("amount")
    decision = evaluate_response_binding_sources(stripe_route, missing_binding_source)
    assert_response_binding_denied(
        decision,
        "response_binding_source_missing",
        binding_id="amount",
        evidence=False,
    )
    noncanonical_binding_source = {**stripe_operation, "amount": "05000"}
    assert_response_binding_denied(
        evaluate_response_binding_sources(stripe_route, noncanonical_binding_source),
        "response_binding_source_invalid",
        binding_id="amount",
        evidence=False,
    )

    source_canary = "request-source-canary-never-disclose"
    assert_response_binding_denied(
        evaluate_response_binding_sources(
            stripe_route,
            {**stripe_operation, "amount": source_canary},
        ),
        "response_binding_source_invalid",
        binding_id="amount",
        evidence=False,
        sensitive_values=(source_canary,),
    )

    i64_route = SimpleNamespace(
        constraints=(
            {
                "id": "signed-i64-response-binding",
                "type": "responseBinding",
                "phase": "response",
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "signed-i64",
                        "operationField": "authorized_value",
                        "responseField": "value",
                        "comparison": "canonicalInteger",
                    }
                ],
            },
        )
    )
    min_i64 = -(2**63)
    max_i64 = 2**63 - 1
    for boundary in (min_i64, max_i64):
        boundary_operation = {"authorized_value": str(boundary)}
        assert evaluate_response_binding_sources(i64_route, boundary_operation).allowed
        boundary_response = flow(
            "POST",
            "https://api.example.test/i64",
            response={"value": boundary},
        )
        boundary_response.metadata["serverware_operation"] = boundary_operation
        assert evaluate_response_constraints(
            boundary_response,
            i64_route,
            constraint_types={"responseBinding"},
        ).allowed

    for out_of_range in (min_i64 - 1, max_i64 + 1):
        assert_response_binding_denied(
            evaluate_response_binding_sources(
                i64_route,
                {"authorized_value": str(out_of_range)},
            ),
            "response_binding_source_invalid",
            binding_id="signed-i64",
            evidence=False,
        )
        out_of_range_response = flow(
            "POST",
            "https://api.example.test/i64",
            response={"value": out_of_range},
        )
        out_of_range_response.metadata["serverware_operation"] = {
            "authorized_value": str(max_i64 if out_of_range > 0 else min_i64)
        }
        assert_response_binding_denied(
            evaluate_response_constraints(
                out_of_range_response,
                i64_route,
                constraint_types={"responseBinding"},
            ),
            "response_binding_mismatch",
            binding_id="signed-i64",
        )

    for suffix in ("a", "b"):
        request_canary = f"request-binding-canary-{suffix}-never-disclose"
        response_canary = f"response-binding-canary-{suffix}-never-disclose"
        canary_operation = {**stripe_operation, "currency": request_canary}
        canary_response = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response={
                "amount": 5000,
                "currency": response_canary,
                "payment_method": "pm_12345678",
            },
        )
        canary_response.metadata["serverware_operation"] = canary_operation
        decision = evaluate_response_constraints(
            canary_response,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            "response_binding_mismatch",
            binding_id="currency",
            sensitive_values=(request_canary, response_canary),
        )

    stale_stripe_route = SimpleNamespace(
        credential_ref=stripe_route.credential_ref,
        adapter_config=stripe_route.adapter_config,
        constraints=(),
    )
    stale_stripe_decision = stripe_adapter.validate_request(
        stripe_request,
        stale_stripe_route,
        {},
    )
    assert_denied(stale_stripe_decision, "credential_request_body_policy_missing")
    assert stale_stripe_decision.status_code == 500
    assert stale_stripe_decision.payload["requiredConstraint"] == "formBody"

    sibling_form_field = copy.deepcopy(stripe_request)
    sibling_form_field.request.raw_content += (
        b"&transfer_data%5Bdestination%5D=acct_attacker"
    )
    original_form_body = sibling_form_field.request.raw_content
    assert stripe_adapter.validate_request(sibling_form_field, stripe_route, {}).allowed
    assert_denied(
        request_decision(
            stripe_route,
            sibling_form_field,
            "stripe.payment_intents.create",
        ),
        "form_body_field_not_allowed",
    )
    assert stripe_adapter.rewrite_request(sibling_form_field, stripe_route, {}).allowed
    assert sibling_form_field.request.raw_content == original_form_body

    if _canonical_forwarded_request_headers is not None:
        stripe_credential = example_snapshot.credentials[stripe_route.credential_ref]
        principal = example_snapshot.principals["agent:example"]
        forwarded_headers = _canonical_forwarded_request_headers(stripe_request, stripe_credential)
        assert forwarded_headers == {
            "content-length": str(len(stripe_request.request.raw_content)),
            "content-type": "application/x-www-form-urlencoded",
            "host": "api.stripe.com",
            "idempotency-key": "agent-payment:req-123",
        }
        canonical = _canonical_request(
            stripe_request,
            principal=principal,
            route=stripe_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=stripe_operation,
            forwarded_headers=forwarded_headers,
            discard_headers=(),
        )
        changed_idempotency_key = copy.deepcopy(stripe_request)
        changed_idempotency_key.request.headers["idempotency-key"] = "agent-payment:req-124"
        changed_forwarded_headers = _canonical_forwarded_request_headers(
            changed_idempotency_key,
            stripe_credential,
        )
        changed_canonical = _canonical_request(
            changed_idempotency_key,
            principal=principal,
            route=stripe_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=stripe_operation,
            forwarded_headers=changed_forwarded_headers,
            discard_headers=(),
        )
        assert _digest(canonical) != _digest(changed_canonical)
        assert _operation_digest(canonical) != _operation_digest(changed_canonical)

        raw_plus_query = flow(
            "GET",
            "https://api.stripe.com/v1/customers?"
            "starting_after=customer+name&limit=5",
        )
        try:
            _canonicalize_provider_query(raw_plus_query)
        except ValueError:
            pass
        else:
            raise AssertionError("raw query plus was normalized instead of rejected")

        unsorted_query = flow(
            "GET",
            "https://api.stripe.com/v1/customers?"
            "starting_after=customer%20name&limit=5",
        )
        try:
            _canonicalize_provider_query(unsorted_query)
        except ValueError:
            pass
        else:
            raise AssertionError("unsorted raw query was reordered instead of rejected")
        canonical_query = flow(
            "GET",
            "https://api.stripe.com/v1/customers?"
            "limit=5&starting_after=customer%20name",
        )
        assert _canonicalize_provider_query(canonical_query) == [
            ("limit", "5"),
            ("starting_after", "customer name"),
        ]
        assert canonical_query.request.pretty_url == (
            "https://api.stripe.com/v1/customers?"
            "limit=5&starting_after=customer%20name"
        )
        assert _canonical_query_wire(
            [("limit", "5"), ("starting_after", "customer name")]
        ) == "limit=5&starting_after=customer%20name"
        encoded_delimiters = flow(
            "GET",
            "https://api.stripe.com/v1/customers?"
            "data=a%26b%3Dc&literal=%2B",
        )
        assert _canonicalize_provider_query(encoded_delimiters) == [
            ("data", "a&b=c"),
            ("literal", "+"),
        ]
        assert encoded_delimiters.request.pretty_url == (
            "https://api.stripe.com/v1/customers?"
            "data=a%26b%3Dc&literal=%2B"
        )

        list_route = route(
            example_snapshot,
            "example.stripe.customers.list",
        )
        list_forwarded = _canonical_forwarded_request_headers(
            canonical_query,
            stripe_credential,
        )
        list_canonical = _canonical_request(
            canonical_query,
            principal=principal,
            route=list_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields={"operation": "stripe.customers.list"},
            forwarded_headers=list_forwarded,
            discard_headers=(),
        )
        assert list_canonical["request"]["query"] == [
            ("limit", "5"),
            ("starting_after", "customer name"),
        ]
        assert _provider_request_matches_canonical(
            query_variants[0],
            list_canonical,
            stripe_credential,
        )
        raw_query_tamper = copy.deepcopy(query_variants[0])
        raw_query_tamper.request.pretty_url = (
            "https://api.stripe.com/v1/customers?"
            "starting_after=customer+name&limit=5"
        )
        assert not _provider_request_matches_canonical(
            raw_query_tamper,
            list_canonical,
            stripe_credential,
        )

        query_credential_policy = CredentialPolicy(
            id="cred-query-binding",
            injection={"type": "query", "name": "api_key"},
        )
        query_credential_request = flow(
            "GET",
            "https://api.stripe.com/v1/customers?"
            "limit=5&starting_after=customer%20name",
        )
        _canonicalize_provider_query(query_credential_request)
        query_credential_canonical = _canonical_request(
            query_credential_request,
            principal=principal,
            route=list_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields={"operation": "stripe.customers.list"},
            forwarded_headers=_canonical_forwarded_request_headers(
                query_credential_request,
                query_credential_policy,
            ),
            discard_headers=(),
        )
        query_credential = {
            "kind": "query",
            "secret": "provider key/+%",
        }
        _inject_credential(
            query_credential_request,
            query_credential_policy,
            query_credential,
        )
        assert query_credential_request.request.pretty_url == (
            "https://api.stripe.com/v1/customers?"
            "api_key=provider%20key%2F%2B%25&limit=5&"
            "starting_after=customer%20name"
        )
        assert _provider_request_matches_canonical(
            query_credential_request,
            query_credential_canonical,
            query_credential_policy,
            query_credential,
        )
        changed_query_credential = copy.deepcopy(query_credential_request)
        changed_query_credential.request.pretty_url = (
            "https://api.stripe.com/v1/customers?"
            "api_key=different&limit=5&starting_after=customer%20name"
        )
        assert not _provider_request_matches_canonical(
            changed_query_credential,
            query_credential_canonical,
            query_credential_policy,
            query_credential,
        )

        header_collision = copy.deepcopy(stripe_request)
        header_collision.request.headers["Authorization"] = "Bearer agent-controlled"
        assert_denied(
            _credential_injection_collision(header_collision, stripe_credential),
            "credential_injection_header_collision",
        )
        query_collision = flow(
            "PUT",
            "https://objects.example.com/agent-artifacts/report-1?api_key=agent-controlled",
        )
        assert_denied(
            _credential_injection_collision(
                query_collision,
                SimpleNamespace(injection={"type": "query", "name": "api_key"}),
            ),
            "credential_injection_query_collision",
        )

    excessive_amount = copy.deepcopy(stripe_request)
    excessive_amount.request.raw_content = b"amount=50001&currency=usd&payment_method=pm_12345678&confirm=true"
    assert_denied(
        request_decision(stripe_route, excessive_amount, "stripe.payment_intents.create"),
        "form_body_field_max",
    )
    duplicate_amount = copy.deepcopy(stripe_request)
    duplicate_amount.request.raw_content = (
        b"amount=50&amount=50000&currency=usd&payment_method=pm_12345678&confirm=true"
    )
    assert_denied(
        request_decision(stripe_route, duplicate_amount, "stripe.payment_intents.create"),
        "form_body_duplicate_field_denied",
    )
    raw_card = copy.deepcopy(stripe_request)
    raw_card.request.raw_content = (
        b"amount=5000&currency=usd&confirm=true&payment_method_data%5Bcard%5D%5Bnumber%5D=4242424242424242"
    )
    assert_denied(
        request_decision(stripe_route, raw_card, "stripe.payment_intents.create"),
        "form_body_field_not_allowed",
    )

    gmail_request_route = route(example_snapshot, "example.gmail.last_30_days")
    gmail_request_adapter = get_adapter(gmail_request_route.adapter_type)
    gmail_bodyless_content_type = flow(
        "GET",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=serverware",
    )
    gmail_bodyless_content_type.request.headers["content-type"] = (
        ' Application/JSON ; charset="utf-8" '
    )
    assert_denied(
        gmail_request_adapter.validate_request(
            gmail_bodyless_content_type,
            gmail_request_route,
            {"user": "me"},
        ),
        "request_content_type_denied",
    )
    for denied_request, expected_error in (
        (
            flow(
                "GET",
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?unknown=1",
            ),
            "request_query_key_not_allowed",
        ),
        (
            flow(
                "GET",
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                {"forbidden": True},
            ),
            "request_body_not_allowed",
        ),
    ):
        assert_denied(
            gmail_request_adapter.validate_request(
                denied_request,
                gmail_request_route,
                {"user": "me"},
            ),
            expected_error,
        )
    gmail_unknown_header = flow(
        "GET",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
    )
    gmail_unknown_header.request.headers["x-agent-widening"] = "1"
    assert_denied(
        gmail_request_adapter.validate_request(
            gmail_unknown_header,
            gmail_request_route,
            {"user": "me"},
        ),
        "request_header_not_allowed",
    )
    gmail_duplicate_content_type = flow(
        "GET",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
    )
    gmail_duplicate_content_type.request.headers = {
        "content-type": "application/json",
        "Content-Type": "application/json",
    }
    assert_denied(
        gmail_request_adapter.validate_request(
            gmail_duplicate_content_type,
            gmail_request_route,
            {"user": "me"},
        ),
        "request_content_type_ambiguous",
    )

    x_route = route(example_snapshot, "example.x.search.seven_days")
    x_request = flow("GET", "https://api.x.com/2/tweets/search/recent?query=serverware&tweet.fields=author_id")
    x_adapter = get_adapter(x_route.adapter_type)
    x_bodyless_content_type = flow(
        "GET",
        "https://api.x.com/2/tweets/search/recent?query=serverware",
    )
    x_bodyless_content_type.request.headers["content-type"] = "application/json"
    assert_denied(
        x_adapter.validate_request(x_bodyless_content_type, x_route, {}),
        "request_content_type_denied",
    )
    x_recent_unknown_header = flow(
        "GET",
        "https://api.x.com/2/tweets/search/recent?query=serverware",
    )
    x_recent_unknown_header.request.headers["x-agent-widening"] = "1"
    assert_denied(
        x_adapter.validate_request(x_recent_unknown_header, x_route, {}),
        "request_header_not_allowed",
    )
    assert_denied(
        x_adapter.validate_request(
            flow(
                "GET",
                "https://api.x.com/2/tweets/search/recent?query=serverware&unknown=1",
            ),
            x_route,
            {},
        ),
        "request_query_key_not_allowed",
    )
    assert_denied(
        x_adapter.validate_request(
            flow(
                "GET",
                "https://api.x.com/2/tweets/search/recent?query=serverware",
                {"forbidden": True},
            ),
            x_route,
            {},
        ),
        "request_body_not_allowed",
    )
    assert x_adapter.rewrite_request(x_request, x_route, {}).allowed
    assert set(x_request.request.query["tweet.fields"].split(",")) == {"author_id", "created_at"}
    for historical_path in ("/2/tweets/search/all", "/2/tweets/counts/all"):
        assert_denied(
            x_adapter.validate_request(
                flow("GET", f"https://api.x.com{historical_path}?query=serverware"),
                x_route,
                {},
            ),
            "x_recent_search_endpoint_denied",
        )
    assert x_adapter.validate_request(
        flow("GET", "https://api.x.com/2/tweets/counts/recent?query=serverware"),
        x_route,
        {},
    ).allowed

    full_x_route = route(example_snapshot, "example.x.full_bounded_read")
    full_x_adapter = get_adapter(full_x_route.adapter_type)
    assert full_x_adapter.validate_credential_metadata(
        full_x_route,
        {"x_app_id": "approved-x-app-id"},
    ).allowed
    assert_denied(
        full_x_adapter.validate_credential_metadata(
            full_x_route,
            {"x_app_id": "unapproved-x-app-id"},
        ),
        "x_app_id_denied",
    )
    full_x_bodyless_content_type = flow("GET", "https://api.x.com/2/users/me")
    full_x_bodyless_content_type.request.headers["content-type"] = "application/json"
    assert_denied(
        full_x_adapter.validate_request(
            full_x_bodyless_content_type,
            full_x_route,
            {},
        ),
        "request_content_type_denied",
    )
    assert_denied(
        full_x_adapter.validate_request(
            flow("GET", "https://api.x.com/2/users/me?unknown=1"),
            full_x_route,
            {},
        ),
        "request_query_key_not_allowed",
    )
    expected_x_reads = {
        "https://api.x.com/2/tweets/123": "tweets.read",
        "https://api.x.com/2/tweets/analytics": "analytics.read",
        "https://api.x.com/2/tweets/search/recent?query=serverware": "search.read",
        "https://api.x.com/2/tweets/search/all?query=serverware": "search.read",
        "https://api.x.com/2/users/me": "users.read",
        "https://api.x.com/2/users/123/bookmarks/folders/456": "bookmarks.read",
        "https://api.x.com/2/users/123/owned_lists": "lists.read",
        "https://api.x.com/2/dm_events": "directMessages.read",
        "https://api.x.com/2/media/upload?media_id=123": "media.read",
        "https://api.x.com/2/spaces/search?query=security": "spaces.read",
    }
    for url, operation in expected_x_reads.items():
        x_read = flow("GET", url)
        assert full_x_adapter.operation_fields(x_read, full_x_route, {}) == {"operation": operation}
        assert full_x_adapter.validate_request(x_read, full_x_route, {}).allowed
    assert_denied(
        full_x_adapter.validate_request(
            flow("GET", "https://api.x.com/2/future/unknown_endpoint"),
            full_x_route,
            {},
        ),
        "x_unknown_operation_blocked",
    )
    assert_denied(
        full_x_adapter.validate_request(
            flow("POST", "https://api.x.com/2/tweets"),
            full_x_route,
            {},
        ),
        "x_write_blocked",
    )

    x_write_route = route(example_snapshot, "example.x.tweet.one_per_day")
    x_write_adapter = get_adapter(x_write_route.adapter_type)
    assert x_write_adapter.validate_request(
        flow("POST", "https://api.x.com/2/tweets", {"text": "bounded post"}),
        x_write_route,
        {},
    ).allowed
    x_write_unknown_header = flow(
        "POST",
        "https://api.x.com/2/tweets",
        {"text": "bounded post"},
    )
    x_write_unknown_header.request.headers["x-agent-widening"] = "1"
    assert_denied(
        x_write_adapter.validate_request(x_write_unknown_header, x_write_route, {}),
        "request_header_not_allowed",
    )
    assert_denied(
        x_write_adapter.validate_request(
            flow(
                "POST",
                "https://api.x.com/2/tweets?unknown=1",
                {"text": "bounded post"},
            ),
            x_write_route,
            {},
        ),
        "request_query_key_not_allowed",
    )
    for label, headers, expected_error in (
        ("missing", {}, "request_content_type_required"),
        ("wrong", {"content-type": "text/plain"}, "request_content_type_denied"),
        (
            "duplicate",
            {
                "content-type": "application/json",
                "Content-Type": "application/json",
            },
            "request_content_type_ambiguous",
        ),
        (
            "duplicate parameter",
            {
                "content-type": (
                    "application/json; charset=utf-8; CHARSET=utf-8"
                )
            },
            "request_content_type_denied",
        ),
    ):
        denied_x_write = flow(
            "POST",
            "https://api.x.com/2/tweets",
            {"text": "bounded post"},
        )
        denied_x_write.request.headers = headers
        decision = x_write_adapter.validate_request(denied_x_write, x_write_route, {})
        assert_denied(decision, expected_error)
        assert decision.status_code == 415, label
    oversized_x_write = flow("POST", "https://api.x.com/2/tweets")
    oversized_x_write.request.headers["content-type"] = "application/json"
    oversized_x_write.request.raw_content = b"x" * 65537
    assert_denied(
        x_write_adapter.validate_request(oversized_x_write, x_write_route, {}),
        "request_body_too_large",
    )

    npm_route = route(example_snapshot, "example.npm.publish.yubikey_jit")
    tarball = b"captured npm package tarball bytes"
    npm_document = {
        "_id": "@scope/example",
        "name": "@scope/example",
        "dist-tags": {"latest": "1.2.3"},
        "versions": {
            "1.2.3": {
                "name": "@scope/example",
                "version": "1.2.3",
                "dist": {},
            }
        },
        "_attachments": {
            "example-1.2.3.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }
    npm_request = flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_document)
    npm_adapter = get_adapter(npm_route.adapter_type)
    assert set(npm_route.adapter_config["operations"]) == {
        "publish",
        "unpublish",
        "distTagWrite",
        "tokenWrite",
        "metadataWrite",
    }
    assert "operation" in npm_route.jit["binding"]["fields"]
    npm_fields = npm_adapter.operation_fields(npm_request, npm_route, {"package": "@scope%2fexample"})
    assert npm_fields["packageName"] == "@scope/example", npm_fields
    assert npm_fields["packageVersion"] == "1.2.3", npm_fields
    npm_integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
    assert npm_fields["tarballIntegrity"] == npm_integrity, npm_fields
    assert npm_fields["attachmentName"] == "example-1.2.3.tgz", npm_fields
    assert npm_fields["attachmentBytes"] == str(len(tarball)), npm_fields
    assert npm_adapter.validate_request(npm_request, npm_route, {"package": "@scope%2fexample"}).allowed

    if (
        _discard_declared_request_headers is not None
        and _canonical_credential_version is not None
        and _canonical_forwarded_request_headers is not None
        and _canonical_request is not None
        and _normalized_request_headers is not None
        and _digest is not None
        and _operation_digest is not None
    ):
        parity_vector = json.loads(
            (ROOT / "scripts" / "discard_headers_parity.v1.json").read_text(
                encoding="utf-8"
            )
        )
        assert parity_vector["apiVersion"] == "serverware.discardHeadersParity/v2"
        raw_target_vector = parity_vector["rawAbsoluteTarget"]
        for target in raw_target_vector["valid"]:
            parts = validate_raw_absolute_target(target)
            validate_request_target_path(target)
            assert parts.geturl() == target
        for target in raw_target_vector["invalid"]:
            try:
                validate_request_target_path(target)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"shared invalid absolute target was admitted: {target}"
                )
        canonical_query_vector = raw_target_vector["canonicalQuery"]
        canonical_query_flow = flow(
            "GET",
            canonical_query_vector["input"],
        )
        expected_query_pairs = [
            tuple(pair) for pair in canonical_query_vector["pairs"]
        ]
        assert (
            _canonicalize_provider_query(canonical_query_flow)
            == expected_query_pairs
        )
        assert canonical_query_flow.request.pretty_url == (
            "https://api.example.test/resource?"
            + canonical_query_vector["wire"]
        )
        for vector_name in ("legacyV1", "discardV2"):
            vector = parity_vector[vector_name]
            parity_canonical = vector["canonicalRequest"]
            parity_operation_view = {
                "principal": parity_canonical["principal"],
                "route_id": parity_canonical["route_id"],
                "credential_ref": parity_canonical["credential_ref"],
                "credential_version": parity_canonical["credential_version"],
                "policy_hash": parity_canonical["policy_hash"],
                "request": parity_canonical["request"],
                "operation": parity_canonical["operation"],
            }
            assert canonical_json(parity_canonical) == vector["canonicalJson"]
            assert canonical_json(parity_operation_view) == vector["operationJson"]
            assert _digest(parity_canonical) == (
                "sha256:"
                + hashlib.sha256(vector["canonicalJson"].encode("utf-8")).hexdigest()
            )
            assert _operation_digest(parity_canonical) == (
                "sha256:"
                + hashlib.sha256(vector["operationJson"].encode("utf-8")).hexdigest()
            )
        legacy_vector = parity_vector["legacyV1"]["canonicalRequest"]
        legacy_vector_flow = flow(
            "GET",
            "https://api.example.test/resource",
        )
        legacy_vector_flow.client_conn.peername = ("192.0.2.44", 12345)
        legacy_vector_flow.request.headers = {
            "accept": "application/json"
        }
        legacy_vector_route = SimpleNamespace(
            id="route:legacy-parity",
            credential_ref=None,
        )
        actual_legacy_canonical = _canonical_request(
            legacy_vector_flow,
            principal=SimpleNamespace(id="agent:parity"),
            route=legacy_vector_route,
            credential_version=_canonical_credential_version(0),
            policy_hash=legacy_vector["policy_hash"],
            operation_fields={"operation": "test.read"},
            forwarded_headers=_canonical_forwarded_request_headers(
                legacy_vector_flow,
                None,
            ),
            discard_headers=(),
        )
        assert actual_legacy_canonical == legacy_vector
        assert (
            actual_legacy_canonical["credential_version"]
            == _canonical_credential_version(0)
            == "none"
        )
        assert "discard_headers" not in parity_vector["legacyV1"]["canonicalRequest"]["request"]
        discard_vector = parity_vector["discardV2"]
        discard_vector_canonical = discard_vector["canonicalRequest"]
        discard_vector_flow = flow(
            "PUT",
            "https://registry.npmjs.org/package",
        )
        discard_vector_flow.client_conn.peername = ("192.0.2.44", 12345)
        discard_vector_flow.request.headers = {
            "content-length": "0",
            "content-type": "application/json",
            "npm-command": "publish",
            "user-agent": "npm/10.8.2 node/v22.5.1",
        }
        actual_discard_canonical = _canonical_request(
            discard_vector_flow,
            principal=SimpleNamespace(id="agent:parity"),
            route=SimpleNamespace(
                id="route:npm-parity",
                credential_ref="credential:npm-parity",
            ),
            credential_version=_canonical_credential_version(7),
            policy_hash=discard_vector_canonical["policy_hash"],
            operation_fields={
                "operation": "npm.publish",
                "packageName": "package",
                "packageVersion": "1.2.3",
            },
            forwarded_headers=_canonical_forwarded_request_headers(
                discard_vector_flow,
                None,
            ),
            discard_headers=("npm-session",),
        )
        assert actual_discard_canonical == discard_vector_canonical
        assert discard_vector["canonicalRequest"]["request"]["discard_headers"] == [
            "npm-session"
        ]
        for discarded_value in discard_vector["discardedValues"]:
            assert discarded_value not in discard_vector["canonicalJson"]
            assert discarded_value not in discard_vector["operationJson"]

        npm_principal = example_snapshot.principals["agent:example"]
        retry_requests = []
        for session_value in ("npm-session-attempt-a", "npm-session-attempt-b"):
            retry_request = copy.deepcopy(npm_request)
            retry_request.request.headers.update(
                {
                    "npm-command": "publish",
                    "npm-session": session_value,
                    "user-agent": "npm/10.8.2 node/v22.5.1",
                }
            )
            declared_discard = _discard_declared_request_headers(
                retry_request,
                npm_route,
                npm_principal,
                example_snapshot.credentials[npm_route.credential_ref],
            )
            assert declared_discard == ("npm-session",)
            discarded_evidence = retry_request.metadata.get(
                "serverware_discarded_request_headers"
            )
            assert discarded_evidence == discard_vector["discardedEvidence"]
            assert session_value not in canonical_json(discarded_evidence)
            assert "npm-session" not in {
                str(name).lower() for name in retry_request.request.headers
            }
            assert npm_adapter.validate_request(
                retry_request,
                npm_route,
                {"package": "@scope%2fexample"},
            ).allowed
            forwarded = _canonical_forwarded_request_headers(
                retry_request,
                example_snapshot.credentials[npm_route.credential_ref],
            )
            assert forwarded["npm-command"] == "publish"
            assert forwarded["user-agent"] == "npm/10.8.2 node/v22.5.1"
            assert "npm-session" not in forwarded
            retry_fields = npm_adapter.operation_fields(
                retry_request,
                npm_route,
                {"package": "@scope%2fexample"},
            )
            canonical_retry = _canonical_request(
                retry_request,
                principal=npm_principal,
                route=npm_route,
                credential_version="1",
                policy_hash=example_snapshot.hash,
                operation_fields=retry_fields,
                forwarded_headers=forwarded,
                discard_headers=declared_discard,
            )
            assert canonical_retry["v"] == 2
            assert canonical_retry["request"]["discard_headers"] == ["npm-session"]
            assert session_value not in canonical_json(canonical_retry)
            retry_requests.append((retry_request, canonical_retry))

        first_retry = retry_requests[0][1]
        second_retry = retry_requests[1][1]
        assert _digest(first_retry) == _digest(second_retry)
        assert _operation_digest(first_retry) == _operation_digest(second_retry)
        changed_discard_policy = copy.deepcopy(first_retry)
        changed_discard_policy["request"]["discard_headers"] = []
        assert _digest(changed_discard_policy) != _digest(first_retry)
        assert _operation_digest(changed_discard_policy) != _operation_digest(first_retry)

        legacy_route = generic_route
        legacy_request = flow(
            "GET",
            "https://api.stripe.com/v1/customers?limit=5",
        )
        legacy_credential = example_snapshot.credentials[legacy_route.credential_ref]
        legacy_discard = _discard_declared_request_headers(
            legacy_request,
            legacy_route,
            npm_principal,
            legacy_credential,
        )
        assert legacy_discard == ()
        legacy_forwarded = _canonical_forwarded_request_headers(
            legacy_request,
            legacy_credential,
        )
        legacy_fields = get_adapter(legacy_route.adapter_type).operation_fields(
            legacy_request,
            legacy_route,
            {},
        )
        legacy_canonical = _canonical_request(
            legacy_request,
            principal=npm_principal,
            route=legacy_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=legacy_fields,
            forwarded_headers=legacy_forwarded,
            discard_headers=legacy_discard,
        )
        assert legacy_canonical["v"] == 1
        assert "discard_headers" not in legacy_canonical["request"]

        if mitm_http is None:
            raise AssertionError(
                "consolidated discard-header parity requires mitmproxy physical headers"
            )
        duplicate_physical = copy.deepcopy(npm_request)
        duplicate_fields = [
            (b"Host", b"registry.npmjs.org"),
            *[
                (name.encode("ascii"), value.encode("ascii"))
                for name, value in discard_vector["duplicatePhysicalHeaders"]
            ],
        ]
        duplicate_physical.request.headers = mitm_http.Headers(
            fields=duplicate_fields
        )
        try:
            _normalized_request_headers(duplicate_physical)
        except ValueError as exc:
            assert "repeats header npm-session" in str(exc)
        else:
            raise AssertionError(
                "Python merged duplicate physical npm-session fields"
            )

        for malformed_headers in (
            {"bad\nname": "value"},
            {"x" * 129: "value"},
            {"x-test": "bad\nvalue"},
            {"x-test": "x" * (16 * 1024 + 1)},
            {
                "Npm-Session": "one",
                "npm-session": "two",
            },
        ):
            malformed_request = copy.deepcopy(npm_request)
            malformed_request.request.headers = malformed_headers
            try:
                _normalized_request_headers(malformed_request)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"malformed request headers normalized: {list(malformed_headers)}"
                )

        malformed_policy_route = copy.deepcopy(npm_route)
        malformed_policy_route.adapter_config["request"]["allowedHeaders"] = "user-agent"
        try:
            _discard_declared_request_headers(
                copy.deepcopy(npm_request),
                malformed_policy_route,
                npm_principal,
                example_snapshot.credentials[npm_route.credential_ref],
            )
        except PolicyBundleError:
            pass
        else:
            raise AssertionError(
                "Python runtime accepted malformed request-header policy state"
            )

        retained_header_change = copy.deepcopy(retry_requests[0][0])
        retained_header_change.request.headers["user-agent"] = "npm/10.9.0 node/v22.5.1"
        changed_forwarded = _canonical_forwarded_request_headers(
            retained_header_change,
            example_snapshot.credentials[npm_route.credential_ref],
        )
        changed_header_canonical = _canonical_request(
            retained_header_change,
            principal=npm_principal,
            route=npm_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=npm_fields,
            forwarded_headers=changed_forwarded,
            discard_headers=("npm-session",),
        )
        assert _digest(changed_header_canonical) != _digest(first_retry)
        assert _operation_digest(changed_header_canonical) != _operation_digest(first_retry)

        body_change = copy.deepcopy(retry_requests[0][0])
        body_change.request.raw_content += b" "
        changed_body_forwarded = _canonical_forwarded_request_headers(
            body_change,
            example_snapshot.credentials[npm_route.credential_ref],
        )
        changed_body_canonical = _canonical_request(
            body_change,
            principal=npm_principal,
            route=npm_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=npm_fields,
            forwarded_headers=changed_body_forwarded,
            discard_headers=("npm-session",),
        )
        assert _digest(changed_body_canonical) != _digest(first_retry)
        assert _operation_digest(changed_body_canonical) != _operation_digest(first_retry)

        path_change = copy.deepcopy(retry_requests[0][0])
        path_change.request.pretty_url = "https://registry.npmjs.org/@scope%2fother"
        path_decision = npm_adapter.validate_request(
            path_change,
            npm_route,
            {"package": "@scope%2fother"},
        )
        assert not path_decision.allowed
        changed_path_canonical = _canonical_request(
            path_change,
            principal=npm_principal,
            route=npm_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=npm_fields,
            forwarded_headers=_canonical_forwarded_request_headers(
                path_change,
                example_snapshot.credentials[npm_route.credential_ref],
            ),
            discard_headers=("npm-session",),
        )
        assert _digest(changed_path_canonical) != _digest(first_retry)
        assert _operation_digest(changed_path_canonical) != _operation_digest(first_retry)

        changed_package_document = copy.deepcopy(npm_document)
        changed_package_document["name"] = "@scope/other"
        changed_package_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            changed_package_document,
        )
        assert not npm_adapter.validate_request(
            changed_package_request,
            npm_route,
            {"package": "@scope%2fexample"},
        ).allowed

        changed_version_document = copy.deepcopy(npm_document)
        changed_version_document["versions"]["1.2.3"]["version"] = "1.2.4"
        changed_version_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            changed_version_document,
        )
        assert not npm_adapter.validate_request(
            changed_version_request,
            npm_route,
            {"package": "@scope%2fexample"},
        ).allowed

    existing_publish_document = copy.deepcopy(npm_document)
    existing_publish_document["_rev"] = "42-deadbeef"
    existing_publish_request = flow(
        "PUT",
        "https://registry.npmjs.org/@scope%2fexample",
        existing_publish_document,
    )
    existing_publish_fields = npm_adapter.operation_fields(
        existing_publish_request,
        npm_route,
        {"package": "@scope%2fexample"},
    )
    assert existing_publish_fields["operation"] == "npm.publish", existing_publish_fields
    assert existing_publish_fields["tarballIntegrity"] == npm_integrity, existing_publish_fields
    assert npm_adapter.validate_request(
        existing_publish_request,
        npm_route,
        {"package": "@scope%2fexample"},
    ).allowed

    incomplete_existing_publish_documents = []
    for publish_key in ("versions", "dist-tags", "_attachments", "tarball_integrity"):
        incomplete_document = {
            "_rev": "42-deadbeef",
            "name": "@scope/example",
            publish_key: copy.deepcopy(npm_document.get(publish_key, npm_integrity)),
        }
        incomplete_existing_publish_documents.append((publish_key, incomplete_document))
    for publish_key, incomplete_document in incomplete_existing_publish_documents:
        incomplete_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            incomplete_document,
        )
        incomplete_decision = npm_adapter.validate_request(
            incomplete_request,
            npm_route,
            {"package": "@scope%2fexample"},
        )
        assert not incomplete_decision.allowed, (publish_key, incomplete_decision)
        expected_prefix = (
            "npm_publish_"
            if publish_key in {"_attachments", "tarball_integrity"}
            else "npm_metadata_"
        )
        assert incomplete_decision.payload.get("error", "").startswith(expected_prefix), (
            publish_key,
            incomplete_decision.payload,
        )
        try:
            incomplete_fields = npm_adapter.operation_fields(
                incomplete_request,
                npm_route,
                {"package": "@scope%2fexample"},
            )
        except ValueError as exc:
            assert str(exc).startswith(expected_prefix), (publish_key, exc)
        else:
            assert incomplete_fields["operation"] == "npm.publish", (
                publish_key,
                incomplete_fields,
            )

    declared_npm_document = copy.deepcopy(npm_document)
    declared_npm_document["tarball_integrity"] = npm_integrity
    declared_version = declared_npm_document["versions"]["1.2.3"]
    declared_version["dist"]["integrity"] = npm_integrity
    declared_version["_integrity"] = npm_integrity
    declared_npm = flow(
        "PUT",
        "https://registry.npmjs.org/@scope%2fexample",
        declared_npm_document,
    )
    declared_fields = npm_adapter.operation_fields(
        declared_npm,
        npm_route,
        {"package": "@scope%2fexample"},
    )
    assert declared_fields["tarballIntegrity"] == npm_integrity, declared_fields
    assert npm_adapter.validate_request(
        declared_npm,
        npm_route,
        {"package": "@scope%2fexample"},
    ).allowed

    conflicting_top_level_version = copy.deepcopy(npm_document)
    conflicting_top_level_version["version"] = "9.9.9"
    top_level_version_request = flow(
        "PUT",
        "https://registry.npmjs.org/@scope%2fexample",
        conflicting_top_level_version,
    )
    top_level_version_fields = npm_adapter.operation_fields(
        top_level_version_request,
        npm_route,
        {"package": "@scope%2fexample"},
    )
    assert top_level_version_fields["packageVersion"] == "1.2.3", top_level_version_fields

    for invalid_name in (None, 7, "@scope/attacker"):
        invalid_name_document = copy.deepcopy(npm_document)
        invalid_name_document["name"] = invalid_name
        invalid_name_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            invalid_name_document,
        )
        expected_error = (
            "npm_publish_package_mismatch"
            if invalid_name == "@scope/attacker"
            else "npm_publish_package_missing"
        )
        assert_denied(
            npm_adapter.validate_request(
                invalid_name_request,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            expected_error,
        )

    for declaration in ("tarball_integrity", "dist.integrity", "_integrity"):
        conflicting_document = copy.deepcopy(npm_document)
        if declaration == "tarball_integrity":
            conflicting_document["tarball_integrity"] = "sha512-declared-not-uploaded"
        elif declaration == "dist.integrity":
            conflicting_document["versions"]["1.2.3"]["dist"][
                "integrity"
            ] = "sha512-declared-not-uploaded"
        else:
            conflicting_document["versions"]["1.2.3"][
                "_integrity"
            ] = "sha512-declared-not-uploaded"
        conflicting_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            conflicting_document,
        )
        assert_denied(
            npm_adapter.validate_request(
                conflicting_request,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            "npm_publish_integrity_mismatch",
        )
        try:
            npm_adapter.operation_fields(
                conflicting_request,
                npm_route,
                {"package": "@scope%2fexample"},
            )
        except ValueError as exc:
            assert str(exc) == "npm_publish_integrity_mismatch", (declaration, exc)
        else:
            raise AssertionError(f"npm accepted conflicting {declaration}")

    invalid_attachment_documents = []
    missing_attachment = copy.deepcopy(npm_document)
    missing_attachment.pop("_attachments")
    invalid_attachment_documents.append(("npm_publish_attachment_missing", missing_attachment))
    zero_attachments = copy.deepcopy(npm_document)
    zero_attachments["_attachments"] = {}
    invalid_attachment_documents.append(("npm_publish_attachment_ambiguous", zero_attachments))
    multiple_attachments = copy.deepcopy(npm_document)
    multiple_attachments["_attachments"]["other.tgz"] = {
        "data": base64.b64encode(b"other").decode("ascii")
    }
    invalid_attachment_documents.append(("npm_publish_attachment_ambiguous", multiple_attachments))
    invalid_attachment_object = copy.deepcopy(npm_document)
    invalid_attachment_object["_attachments"]["example-1.2.3.tgz"] = []
    invalid_attachment_documents.append(
        ("npm_publish_attachment_invalid", invalid_attachment_object)
    )
    missing_attachment_data = copy.deepcopy(npm_document)
    missing_attachment_data["_attachments"]["example-1.2.3.tgz"].pop("data")
    invalid_attachment_documents.append(
        ("npm_publish_attachment_data_missing", missing_attachment_data)
    )
    invalid_base64 = copy.deepcopy(npm_document)
    invalid_base64["_attachments"]["example-1.2.3.tgz"]["data"] = "***"
    invalid_attachment_documents.append(
        ("npm_publish_attachment_invalid_base64", invalid_base64)
    )
    noncanonical_base64 = copy.deepcopy(npm_document)
    noncanonical_base64["_attachments"]["example-1.2.3.tgz"]["data"] = "YR=="
    invalid_attachment_documents.append(
        ("npm_publish_attachment_invalid_base64", noncanonical_base64)
    )
    empty_attachment = copy.deepcopy(npm_document)
    empty_attachment["_attachments"]["example-1.2.3.tgz"]["data"] = ""
    empty_attachment["_attachments"]["example-1.2.3.tgz"]["length"] = 0
    invalid_attachment_documents.append(("npm_publish_attachment_empty", empty_attachment))
    wrong_attachment_length = copy.deepcopy(npm_document)
    wrong_attachment_length["_attachments"]["example-1.2.3.tgz"]["length"] += 1
    invalid_attachment_documents.append(
        ("npm_publish_attachment_length_mismatch", wrong_attachment_length)
    )
    oversized_attachment = copy.deepcopy(npm_document)
    oversized_attachment["_attachments"]["example-1.2.3.tgz"]["data"] = "A" * (
        (16 * 1024 * 1024 * 4) // 3 + 5
    )
    invalid_attachment_documents.append(
        ("request_body_too_large", oversized_attachment)
    )
    for expected_error, invalid_document in invalid_attachment_documents:
        invalid_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            invalid_document,
        )
        assert_denied(
            npm_adapter.validate_request(
                invalid_request,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            expected_error,
        )

    known_npm_operations = (
        (
            "DELETE",
            "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
            None,
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
            {
                "_rev": "42-deadbeef",
                "name": "@scope/example",
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "2.0.0": {
                        "name": "@scope/example",
                        "version": "2.0.0",
                    }
                },
            },
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            "DELETE",
            "https://registry.npmjs.org/@scope%2fexample/-/example.tgz/-rev/42-deadbeef",
            None,
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            "PUT",
            "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next",
            "1.2.3",
            {"package": "@scope%2fexample", "tag": "next"},
            "npm.distTagWrite",
        ),
        (
            "DELETE",
            "https://registry.npmjs.org/-/npm/v1/tokens/token/token-key",
            None,
            {"token": "token-key"},
            "npm.tokenWrite",
        ),
        (
            "POST",
            "https://registry.npmjs.org/-/package/@scope%2fexample/access",
            {"access": "public"},
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
        (
            "POST",
            "https://registry.npmjs.org/-/npm/v1/user",
            {"email": "owner@example.test"},
            {},
            "npm.metadataWrite",
        ),
        (
            "PUT",
            "https://registry.npmjs.org/-/team/scope/owners/package",
            {"package": "@scope/example"},
            {"scope": "scope", "team": "owners"},
            "npm.metadataWrite",
        ),
        (
            "DELETE",
            "https://registry.npmjs.org/-/team/scope/owners/package",
            {"package": "@scope/example"},
            {"scope": "scope", "team": "owners"},
            "npm.metadataWrite",
        ),
        (
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            {"_rev": "42-deadbeef", "name": "@scope/example", "description": "metadata only"},
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
        (
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            {
                "_id": "@scope/example",
                "_rev": "42-deadbeef",
                "name": "@scope/example",
                "dist-tags": {"latest": "1.2.3"},
                "versions": {
                    "1.2.3": {
                        "name": "@scope/example",
                        "version": "1.2.3",
                        "deprecated": "use 2.x",
                    }
                },
                "_attachments": {
                    "example-1.2.3.tgz": {
                        "stub": True,
                        "length": len(tarball),
                    }
                },
            },
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
    )
    for method, target, body, params, expected_operation in known_npm_operations:
        known_request = flow(method, target, body)
        fields = npm_adapter.operation_fields(known_request, npm_route, params)
        assert fields["operation"] == expected_operation, (target, fields)
        assert npm_adapter.validate_request(known_request, npm_route, params).allowed, (
            target,
            fields,
        )

    malformed_wire_forms = (
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next",
                {"version": "1.2.3"},
            ),
            {"package": "@scope%2fexample", "tag": "next"},
            "npm_dist_tag_version_invalid",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
                {
                    "_rev": "43-attacker",
                    "name": "@scope/example",
                    "dist-tags": {"latest": "2.0.0"},
                    "versions": {
                        "2.0.0": {
                            "name": "@scope/example",
                            "version": "2.0.0",
                        }
                    },
                },
            ),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm_unpublish_revision_mismatch",
        ),
        (
            flow(
                "DELETE",
                "https://registry.npmjs.org/-/team/scope/owners/package",
                {"package": "@other/example"},
            ),
            {"scope": "scope", "team": "owners"},
            "npm_team_access_scope_mismatch",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample",
                {
                    "_rev": "42-deadbeef",
                    "name": "@scope/example",
                    "dist-tags": {"latest": "1.2.3"},
                    "versions": {
                        "1.2.3": {
                            "name": "@scope/example",
                            "version": "1.2.3",
                        }
                    },
                },
            ),
            {"package": "@scope%2fexample"},
            "npm_metadata_deprecation_required",
        ),
        (
            flow(
                "POST",
                "https://registry.npmjs.org/-/npm/v1/tokens",
                {"name": "agent-created", "password": "must-not-be-forwarded"},
            ),
            {},
            "npm_token_creation_denied",
        ),
    )
    for malformed_request, params, expected_error in malformed_wire_forms:
        assert_denied(
            npm_adapter.validate_request(malformed_request, npm_route, params),
            expected_error,
        )
        try:
            npm_adapter.operation_fields(malformed_request, npm_route, params)
        except ValueError as exc:
            assert str(exc) == expected_error, (expected_error, exc)
        else:
            raise AssertionError(
                f"npm accepted malformed wire form {malformed_request.request.pretty_url}"
            )

    for revision in (None, False, 0, "", {}):
        invalid_revision_document = {
            "_rev": revision,
            "name": "@scope/example",
            "description": "metadata only",
        }
        invalid_revision_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            invalid_revision_document,
        )
        assert_denied(
            npm_adapter.validate_request(
                invalid_revision_request,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            "npm_metadata_revision_invalid",
        )
        try:
            npm_adapter.operation_fields(
                invalid_revision_request,
                npm_route,
                {"package": "@scope%2fexample"},
            )
        except ValueError as exc:
            assert str(exc) == "npm_metadata_revision_invalid", (revision, exc)
        else:
            raise AssertionError(f"npm accepted invalid _rev value {revision!r}")

        invalid_publish_revision_document = copy.deepcopy(npm_document)
        invalid_publish_revision_document["_rev"] = revision
        invalid_publish_revision_request = flow(
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample",
            invalid_publish_revision_document,
        )
        invalid_publish_revision_decision = npm_adapter.validate_request(
            invalid_publish_revision_request,
            npm_route,
            {"package": "@scope%2fexample"},
        )
        assert not invalid_publish_revision_decision.allowed, (
            revision,
            invalid_publish_revision_decision,
        )
        assert invalid_publish_revision_decision.payload.get("error"), (
            revision,
            invalid_publish_revision_decision.payload,
        )

    unknown_npm_requests = (
        ("GET", "https://registry.npmjs.org/@scope%2fexample", None),
        ("HEAD", "https://registry.npmjs.org/@scope%2fexample/-/example-1.2.3.tgz", None),
        ("POST", "https://registry.npmjs.org/@scope%2fexample", npm_document),
        ("PATCH", "https://registry.npmjs.org/@scope%2fexample", npm_document),
        ("PUT", "https://registry.npmjs.org/arbitrary/path", {}),
        ("POST", "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next", {}),
        ("PUT", "https://registry.npmjs.org/-/npm/v1/tokens", {}),
        ("DELETE", "https://registry.npmjs.org/-/package/@scope%2fexample/access", {}),
        ("PUT", "https://registry.npmjs.org/-/npm/v1/tokens-evil", {}),
        (
            "PUT",
            "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next/extra",
            {},
        ),
        (
            "PUT",
            "https://registry.npmjs.org/@scope%2fexample/",
            npm_document,
        ),
        ("DELETE", "https://registry.npmjs.org/-/user/token/token-key", {}),
    )
    for method, target, body in unknown_npm_requests:
        unknown_request = flow(method, target, body)
        assert_denied(
            npm_adapter.validate_request(unknown_request, npm_route, {}),
            "npm_operation_unclassified",
        )
        try:
            npm_adapter.operation_fields(unknown_request, npm_route, {})
        except ValueError:
            pass
        else:
            raise AssertionError(f"npm classified unknown request {method} {target}")

    for invalid_request, expected_error in (
        (
            flow("POST", "https://registry.npmjs.org/-/npm/v1/tokens"),
            "npm_token_creation_denied",
        ),
        (
            flow(
                "DELETE",
                "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
                {"unexpected": True},
            ),
            "npm_delete_body_denied",
        ),
    ):
        assert_denied(
            npm_adapter.validate_request(invalid_request, npm_route, {}),
            expected_error,
        )
        try:
            npm_adapter.operation_fields(invalid_request, npm_route, {})
        except ValueError as exc:
            assert str(exc) == expected_error, exc
        else:
            raise AssertionError(f"npm accepted invalid body for {invalid_request.request.pretty_url}")

    npm_unknown_header = copy.deepcopy(npm_request)
    npm_unknown_header.request.headers["x-agent-widening"] = "1"
    assert_denied(
        npm_adapter.validate_request(
            npm_unknown_header,
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "request_header_not_allowed",
    )
    npm_unknown_query = copy.deepcopy(npm_request)
    npm_unknown_query.request.pretty_url += "?unknown=1"
    assert_denied(
        npm_adapter.validate_request(
            npm_unknown_query,
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "request_query_key_not_allowed",
    )
    for label, headers, expected_error in (
        ("missing", {}, "request_content_type_required"),
        ("wrong", {"content-type": "text/plain"}, "request_content_type_denied"),
        (
            "duplicate",
            {
                "content-type": "application/json",
                "Content-Type": "application/json",
            },
            "request_content_type_ambiguous",
        ),
    ):
        denied_npm = copy.deepcopy(npm_request)
        denied_npm.request.headers = headers
        decision = npm_adapter.validate_request(
            denied_npm,
            npm_route,
            {"package": "@scope%2fexample"},
        )
        assert_denied(decision, expected_error)
        assert decision.status_code == 415, label
    oversized_npm = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
    oversized_npm.request.headers["content-type"] = "application/json"
    oversized_npm.request.raw_content = b"x" * (16777216 + 1)
    assert_denied(
        npm_adapter.validate_request(
            oversized_npm,
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "request_body_too_large",
    )

    valid_npm_json = npm_request.request.raw_content.decode("utf-8")
    invalid_npm_publish_bodies = (
        valid_npm_json.replace(
            '"name": "@scope/example"',
            '"name": "@scope/example", "name": "@scope/attacker"',
            1,
        ).encode("utf-8"),
        (valid_npm_json[:-1] + ', "nonFinite": NaN}').encode("utf-8"),
        (valid_npm_json[:-1] + ', "overflow": 1e400}').encode("utf-8"),
    )
    for invalid_body in invalid_npm_publish_bodies:
        invalid_publish = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
        invalid_publish.request.headers["content-type"] = "application/json"
        invalid_publish.request.raw_content = invalid_body
        assert_denied(
            npm_adapter.validate_request(
                invalid_publish,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            "npm_write_invalid_json",
        )
        try:
            npm_adapter.operation_fields(
                invalid_publish,
                npm_route,
                {"package": "@scope%2fexample"},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("npm JIT operation fields accepted an invalid publish body")

    invalid_metadata = flow("POST", "https://registry.npmjs.org/-/npm/v1/user")
    invalid_metadata.request.headers["content-type"] = "application/json"
    invalid_metadata.request.raw_content = b'{"email":"owner@example.test","email":"attacker@example.test"}'
    assert_denied(
        npm_adapter.validate_request(invalid_metadata, npm_route, {}),
        "npm_write_invalid_json",
    )

    invalid_revision = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
    invalid_revision.request.headers["content-type"] = "application/json"
    invalid_revision.request.raw_content = b'{"_rev":"1-safe","_rev":"2-attacker"}'
    credential_accesses: list[str] = []
    upstream_contacts: list[str] = []
    invalid_revision_decision = npm_adapter.validate_request(
        invalid_revision,
        npm_route,
        {"package": "@scope%2fexample"},
    )
    if invalid_revision_decision.allowed:
        credential_accesses.append("cred-npm")
        upstream_contacts.append(invalid_revision.request.pretty_url)
    assert_denied(invalid_revision_decision, "npm_write_invalid_json")
    assert credential_accesses == []
    assert upstream_contacts == []

    original_runtime_claim = runtime._claim_release_controlled_credential
    original_runtime_start_workers = runtime.start_runtime_workers
    original_runtime_db_get_credential = db.get_credential
    with runtime._credential_lock:
        original_runtime_cache = copy.deepcopy(runtime._credential_cache)
    release_cache_events: list[tuple[str, str]] = []
    claimed_attempts: set[str] = set()

    def fixture_release_claim(
        credential_id: str,
        request_authority: dict[str, Any],
        release_authorization: dict[str, Any] | None,
        *,
        expected: runtime.ReleaseAuthorizationExpectedIdentity,
        jit_policy: dict[str, Any] | None,
    ) -> None:
        del expected, jit_policy, release_authorization
        attempt_id = str(request_authority["attemptId"])
        release_cache_events.append(("claim", attempt_id))
        if int(request_authority["reservationExpiresAtEpochMs"]) <= int(
            time.time() * 1000
        ):
            raise runtime.ReleaseAuthorizationClientError(
                "fixture authority expired"
            )
        if attempt_id in claimed_attempts:
            raise runtime.ReleaseAuthorizationClientError(
                "fixture authority replayed"
            )
        claimed_attempts.add(attempt_id)
        assert credential_id == "credential:release-cache"

    def fixture_release_secret(
        credential_id: str,
        *,
        include_secret: bool = False,
    ) -> dict[str, Any]:
        assert include_secret is True
        release_cache_events.append(("secret", credential_id))
        return {
            "id": credential_id,
            "kind": "bearer",
            "credential_version": 7,
            "lifecycle_status": "active",
            "metadata": {},
            "secret": "reservation-scoped-secret",
        }

    runtime._claim_release_controlled_credential = fixture_release_claim
    runtime.start_runtime_workers = lambda: release_cache_events.append(
        ("workers", "started")
    )
    db.get_credential = fixture_release_secret
    try:
        authority_a = {
            "attemptId": "attempt:release-cache:a",
            "reservationExpiresAtEpochMs": int(time.time() * 1000) + 30_000,
        }
        authority_b = {
            "attemptId": "attempt:release-cache:b",
            "reservationExpiresAtEpochMs": int(time.time() * 1000) + 30_000,
        }
        assert runtime.get_credential(
            "credential:release-cache",
            request_authority=authority_a,
            expected_release_identity=object(),
            jit_policy={"required": False},
        )["secret"] == "reservation-scoped-secret"
        assert runtime.get_credential(
            "credential:release-cache",
            request_authority=authority_b,
            expected_release_identity=object(),
            jit_policy={"required": False},
        )["secret"] == "reservation-scoped-secret"
        secret_events_before_denials = [
            event for event in release_cache_events if event[0] == "secret"
        ]
        for rejected_authority in (
            authority_a,
            {
                "attemptId": "attempt:release-cache:expired",
                "reservationExpiresAtEpochMs": int(time.time() * 1000) - 1,
            },
        ):
            try:
                runtime.get_credential(
                    "credential:release-cache",
                    request_authority=rejected_authority,
                    expected_release_identity=object(),
                    jit_policy={"required": False},
                )
            except runtime.ReleaseAuthorizationClientError:
                pass
            else:
                raise AssertionError(
                    "replayed or expired release authority reached credential material"
                )
        assert [
            event for event in release_cache_events if event[0] == "secret"
        ] == secret_events_before_denials
        assert release_cache_events[:3] == [
            ("claim", "attempt:release-cache:a"),
            ("workers", "started"),
            ("secret", "credential:release-cache"),
        ]
        assert release_cache_events[3:6] == [
            ("claim", "attempt:release-cache:b"),
            ("workers", "started"),
            ("secret", "credential:release-cache"),
        ]
        with runtime._credential_lock:
            assert runtime._credential_cache == original_runtime_cache
    finally:
        runtime._claim_release_controlled_credential = original_runtime_claim
        runtime.start_runtime_workers = original_runtime_start_workers
        db.get_credential = original_runtime_db_get_credential
        with runtime._credential_lock:
            runtime._credential_cache.clear()
            runtime._credential_cache.update(original_runtime_cache)

    if ServerwareAddon is not None:
        from serverware import policy_engine

        original_get_policy_snapshot = policy_engine.get_policy_snapshot
        original_get_credential = runtime.get_credential
        original_get_credential_version = runtime.get_credential_version
        original_get_credential_generation = runtime.get_credential_generation
        original_generation_snapshot = db.credential_generation_snapshot
        original_atomic_mode = runtime.atomic_release_authorization_enabled
        original_expected_reserve = runtime.reserve_expected_release_authorization
        original_dispatch = runtime.dispatch_release_authorization
        credential_reads: list[str | None] = []
        authorization_calls: list[str] = []

        x_admission_events: list[str] = []

        @contextlib.contextmanager
        def x_generation_snapshot(credential_id: str):
            x_admission_events.append(f"metadata:{credential_id}")
            credential_policy = example_snapshot.credentials[credential_id]
            yield {
                "id": credential_id,
                "kind": "oauth2",
                "credential_version": 7,
                "lifecycle_status": "active",
                "metadata": {
                    "oauth": True,
                    "provider_identity_verified": True,
                    "provider_id": "x",
                    "provider_subject": credential_policy.provider_subject,
                    "scopes": list(credential_policy.scopes),
                    "x_app_id": "approved-x-app-id",
                },
            }

        def reject_x_secret_read(credential_id: str | None):
            x_admission_events.append(f"secret:{credential_id}")
            raise RuntimeError("fixture stops after secret lease ordering")

        def reject_x_version_read(credential_id: str | None):
            x_admission_events.append(f"version:{credential_id}")
            raise AssertionError("X generation admission reparsed credential version")

        policy_engine.get_policy_snapshot = lambda: example_snapshot
        db.credential_generation_snapshot = x_generation_snapshot
        runtime.get_credential = reject_x_secret_read
        runtime.get_credential_version = reject_x_version_read
        runtime.atomic_release_authorization_enabled = lambda: False
        try:
            admitted_x = flow("GET", "https://api.x.com/2/users/me")
            admitted_x.request.headers["X-Serverware-Agent"] = "example-agent"
            admitted_x_decision = policy_engine.evaluate_request(
                admitted_x
            ).decision
            assert_denied(admitted_x_decision, "credential_unavailable")
            assert x_admission_events == [
                "metadata:cred-x",
                "secret:cred-x",
            ], x_admission_events
        finally:
            runtime.atomic_release_authorization_enabled = original_atomic_mode
            runtime.get_credential_version = original_get_credential_version
            runtime.get_credential_generation = original_get_credential_generation
            runtime.get_credential = original_get_credential
            db.credential_generation_snapshot = original_generation_snapshot
            policy_engine.get_policy_snapshot = original_get_policy_snapshot

        def reject_credential_read(credential_id: str | None):
            credential_reads.append(credential_id)
            raise AssertionError("invalid npm body reached credential access")

        policy_engine.get_policy_snapshot = lambda: example_snapshot
        runtime.get_credential = reject_credential_read
        runtime.get_credential_version = reject_credential_read
        runtime.get_credential_generation = reject_credential_read
        runtime.atomic_release_authorization_enabled = lambda: True
        runtime.reserve_expected_release_authorization = (
            lambda **_kwargs: authorization_calls.append("reserve")
        )
        runtime.dispatch_release_authorization = lambda **_kwargs: authorization_calls.append("dispatch")
        try:
            blocked_npm = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
            blocked_npm.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_npm.request.headers["content-type"] = "application/json"
            blocked_npm.request.raw_content = invalid_npm_publish_bodies[0]
            blocked_unknown_npm = flow(
                "POST",
                "https://registry.npmjs.org/@scope%2fexample",
                npm_document,
            )
            blocked_unknown_npm.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_dist_tag = flow(
                "PUT",
                "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next",
                {"version": "1.2.3"},
            )
            blocked_unpublish = flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
                {
                    "_rev": "43-attacker",
                    "name": "@scope/example",
                    "dist-tags": {"latest": "2.0.0"},
                    "versions": {
                        "2.0.0": {
                            "name": "@scope/example",
                            "version": "2.0.0",
                        }
                    },
                },
            )
            blocked_team_delete = flow(
                "DELETE",
                "https://registry.npmjs.org/-/team/scope/owners/package",
                {"package": "@other/example"},
            )
            blocked_deprecation = flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample",
                {
                    "_rev": "42-deadbeef",
                    "name": "@scope/example",
                    "dist-tags": {"latest": "1.2.3"},
                    "versions": {
                        "1.2.3": {
                            "name": "@scope/example",
                            "version": "1.2.3",
                        }
                    },
                },
            )
            blocked_token_create = flow(
                "POST",
                "https://registry.npmjs.org/-/npm/v1/tokens",
                {"name": "agent-created", "password": "must-not-be-forwarded"},
            )
            for blocked_npm_request in (
                blocked_dist_tag,
                blocked_unpublish,
                blocked_team_delete,
                blocked_deprecation,
                blocked_token_create,
            ):
                blocked_npm_request.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_gmail = flow(
                "GET",
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?unknown=1",
            )
            blocked_gmail.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_x_read = flow(
                "GET",
                "https://api.x.com/2/tweets/search/recent?query=serverware&unknown=1",
            )
            blocked_x_read.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_x_write = flow(
                "POST",
                "https://api.x.com/2/tweets",
                {"text": "must not reserve"},
            )
            blocked_x_write.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_x_write.request.headers["content-type"] = "text/plain"
            for blocked_request, expected_error, expected_status in (
                (blocked_gmail, "request_query_key_not_allowed", 403),
                (blocked_x_read, "request_query_key_not_allowed", 403),
                (blocked_x_write, "request_content_type_denied", 415),
                (blocked_npm, "npm_write_invalid_json", 403),
                (blocked_unknown_npm, "npm_operation_unclassified", 403),
                (blocked_dist_tag, "npm_dist_tag_version_invalid", 403),
                (blocked_unpublish, "npm_unpublish_revision_mismatch", 403),
                (blocked_team_delete, "npm_team_access_scope_mismatch", 403),
                (blocked_deprecation, "npm_metadata_deprecation_required", 403),
                (blocked_token_create, "npm_token_creation_denied", 403),
            ):
                ServerwareAddon().request(blocked_request)
                assert credential_reads == [], credential_reads
                assert authorization_calls == [], authorization_calls
                assert blocked_request.metadata.get("serverware_blocked_response") is True
                assert blocked_request.response.status_code == expected_status
                assert json.loads(blocked_request.response.raw_content)["error"] == expected_error
        finally:
            runtime.dispatch_release_authorization = original_dispatch
            runtime.reserve_expected_release_authorization = original_expected_reserve
            runtime.atomic_release_authorization_enabled = original_atomic_mode
            runtime.get_credential_version = original_get_credential_version
            runtime.get_credential_generation = original_get_credential_generation
            runtime.get_credential = original_get_credential
            policy_engine.get_policy_snapshot = original_get_policy_snapshot

        missing_lifecycle = flow("POST", "https://demo-upstream:8443/echo")
        runtime.atomic_release_authorization_enabled = lambda: True
        try:
            assert_denied(
                policy_engine.dispatch_release_authorization(missing_lifecycle),
                "release_authorization_lifecycle_missing",
            )
            runtime.atomic_release_authorization_enabled = lambda: False
            assert policy_engine.dispatch_release_authorization(missing_lifecycle).allowed
        finally:
            runtime.atomic_release_authorization_enabled = original_atomic_mode

        successful_reserve = {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": "attempt:successful-reserve",
            "binding_digest": "sha256:" + "9" * 64,
            "idempotent_replay": False,
            "grant_id": "grant:successful-reserve",
            "approval_request_id": "approval:successful-reserve",
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": 123456,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
        }
        validated_jit_reserve = _validated_successful_release_reserve(
            successful_reserve,
            attempt_id="attempt:successful-reserve",
            jit_required=True,
        )
        assert validated_jit_reserve == {
            "binding_digest": "sha256:" + "9" * 64,
            "reservation_expires_at_epoch_ms": 123456,
            "grant_id": "grant:successful-reserve",
            "approval_request_id": "approval:successful-reserve",
        }
        for field, invalid_value in (
            ("grant_id", None),
            ("grant_id", ""),
            ("grant_id", " grant:whitespace"),
            ("grant_id", "g" * 257),
            ("grant_id", "grant:invalid\nidentity"),
            ("approval_request_id", None),
            ("approval_request_id", ""),
            ("approval_request_id", "approval:whitespace "),
            ("approval_request_id", "a" * 257),
            ("approval_request_id", "approval:invalid\nidentity"),
        ):
            invalid_identity = {**successful_reserve, field: invalid_value}
            assert (
                _validated_successful_release_reserve(
                    invalid_identity,
                    attempt_id="attempt:successful-reserve",
                    jit_required=True,
                )
                is None
            ), (field, invalid_value)
        for field, invalid_value in (
            ("state", "dispatching"),
            ("reason", "authorized"),
            ("reservation_expires_at_epoch_ms", None),
            ("dispatch_started_at_epoch_ms", 123),
            ("completion_outcome", "forwarded"),
            ("retry_after_seconds", 1),
            ("approval_status", "pending"),
        ):
            invalid_lifecycle = {**successful_reserve, field: invalid_value}
            assert (
                _validated_successful_release_reserve(
                    invalid_lifecycle,
                    attempt_id="attempt:successful-reserve",
                    jit_required=True,
                )
                is None
            ), (field, invalid_value)
        non_jit_reserve = {
            **successful_reserve,
            "grant_id": None,
            "approval_request_id": None,
        }
        assert _validated_successful_release_reserve(
            non_jit_reserve,
            attempt_id="attempt:successful-reserve",
            jit_required=False,
        ) is not None
        for unexpected_identity in (
            {"grant_id": "grant:unexpected"},
            {"approval_request_id": "approval:unexpected"},
        ):
            assert (
                _validated_successful_release_reserve(
                    {**non_jit_reserve, **unexpected_identity},
                    attempt_id="attempt:successful-reserve",
                    jit_required=False,
                )
                is None
            )

        lifecycle_metadata = flow("POST", "https://demo-upstream:8443/echo")
        stored_lifecycle = policy_engine._store_release_lifecycle(
            lifecycle_metadata,
            attempt_id="attempt:successful-reserve",
            binding_digest="sha256:" + "9" * 64,
            state="reserved",
            grant_id="grant:successful-reserve",
            approval_request_id="approval:successful-reserve",
            reservation_expires_at_epoch_ms=123456,
        )
        assert stored_lifecycle["grant_id"] == "grant:successful-reserve"
        assert (
            stored_lifecycle["approval_request_id"]
            == "approval:successful-reserve"
        )
        assert (
            lifecycle_metadata.metadata["serverware_release_grant_id"]
            == "grant:successful-reserve"
        )
        assert (
            lifecycle_metadata.metadata["serverware_release_approval_request_id"]
            == "approval:successful-reserve"
        )

        original_atomic_snapshot = policy_engine.get_policy_snapshot
        original_atomic_get_version = runtime.get_credential_version
        original_atomic_get_generation = runtime.get_credential_generation
        original_atomic_get_credential = runtime.get_credential
        original_atomic_expected_reserve = (
            runtime.reserve_expected_release_authorization
        )
        original_atomic_complete = runtime.complete_release_authorization
        original_atomic_cancel_expected = (
            runtime.cancel_expected_release_authorization
        )
        invalid_reserve_credential_reads: list[str | None] = []
        invalid_reserve_completions: list[str] = []

        def invalid_successful_reserve(**kwargs):
            expected = kwargs["guard"].expected
            return {
                **successful_reserve,
                "attempt_id": expected.attempt_id,
                "binding_digest": expected.binding_digest,
                "grant_id": None,
            }

        def reject_invalid_reserve_credential_read(credential_id):
            invalid_reserve_credential_reads.append(credential_id)
            raise AssertionError("invalid atomic reserve reached credential access")

        def cancel_invalid_successful_reserve(expected):
            invalid_reserve_completions.append("not_forwarded")
            return {
                "authorized": False,
                "state": "absent",
                "reason": "reservation_absent",
                "attempt_id": expected.attempt_id,
                "binding_digest": expected.binding_digest,
                "idempotent_replay": True,
                "grant_id": None,
                "approval_request_id": None,
                "reservation_expires_at_epoch_ms": None,
                "dispatch_started_at_epoch_ms": None,
                "dispatch_expires_at_epoch_ms": None,
                "completion_outcome": None,
                "retry_after_seconds": 0,
                "quotas": [],
            }

        policy_engine.get_policy_snapshot = lambda: example_snapshot
        runtime.atomic_release_authorization_enabled = lambda: True
        runtime.get_credential_version = lambda _credential_id: 1
        runtime.get_credential_generation = lambda credential_id: {
            "id": credential_id,
            "kind": "bearer",
            "credential_version": 1,
            "lifecycle_status": "active",
            "metadata": {
                "provider_id": "npm",
                "scopes": ["automation"],
            },
        }
        runtime.get_credential = reject_invalid_reserve_credential_read
        runtime.reserve_expected_release_authorization = invalid_successful_reserve
        runtime.cancel_expected_release_authorization = (
            cancel_invalid_successful_reserve
        )
        try:
            invalid_success = copy.deepcopy(npm_request)
            invalid_success.request.headers["X-Serverware-Agent"] = "example-agent"
            invalid_success_decision = policy_engine.evaluate_request(
                invalid_success
            ).decision
            assert_denied(
                invalid_success_decision,
                "release_authorization_reserve_invalid",
            )
            assert invalid_reserve_credential_reads == []
            assert invalid_reserve_completions == ["not_forwarded"]
            invalid_guard = invalid_success.metadata.get(
                "serverware_release_authorization_guard"
            )
            assert invalid_guard is not None
            assert invalid_guard.cleanup_emitted is True
            assert invalid_guard.phase == "terminal"
        finally:
            runtime.cancel_expected_release_authorization = (
                original_atomic_cancel_expected
            )
            runtime.complete_release_authorization = original_atomic_complete
            runtime.reserve_expected_release_authorization = (
                original_atomic_expected_reserve
            )
            runtime.get_credential = original_atomic_get_credential
            runtime.get_credential_version = original_atomic_get_version
            runtime.get_credential_generation = original_atomic_get_generation
            runtime.atomic_release_authorization_enabled = original_atomic_mode
            policy_engine.get_policy_snapshot = original_atomic_snapshot

        from serverware import mitm_addon

        addon = ServerwareAddon()
        original_connect_snapshot = mitm_addon.get_policy_snapshot
        original_connect_log = runtime.log_request
        connect_routes = (
            SimpleNamespace(
                scheme="https",
                host="connect.example.test",
                port=443,
                principals=("agent:connect-assigned",),
            ),
            SimpleNamespace(
                scheme="http",
                host="connect.example.test",
                port=443,
                principals=("agent:http-only",),
            ),
        )
        identified_inputs: list[tuple[str | None, object]] = []

        def connect_flow():
            item = flow("CONNECT", "https://connect.example.test:443")
            item.request.host = "connect.example.test"
            item.request.port = 443
            item.request.headers = RawHeaders(
                [
                    ("Host", "connect.example.test:443"),
                    (
                        "Proxy-Authorization",
                        "Basic must-not-enter-audit",
                    ),
                    ("X-Serverware-Agent", "connect-agent"),
                ]
            )
            item.request.data.headers = item.request.headers
            item.client_conn.peername = ("10.42.0.9", 51234)
            return item

        def connect_snapshot(principal):
            def identify(client_ip, headers):
                identified_inputs.append((client_ip, headers))
                return principal

            return SimpleNamespace(
                routes=connect_routes,
                identify_principal=identify,
            )

        connect_logs: list[tuple[tuple, dict]] = []
        runtime.log_request = lambda *args, **kwargs: connect_logs.append((args, kwargs))
        try:
            uppercase_wire = connect_flow()
            uppercase_wire.request.data.authority = b"CONNECT.example.test:443"
            uppercase_wire.request.data.path = b"CONNECT.example.test:443"
            uppercase_wire.request.headers = RawHeaders(
                [("Host", "CONNECT.example.test:443")]
            )
            uppercase_wire.request.data.headers = uppercase_wire.request.headers
            mitm_addon.get_policy_snapshot = lambda: (_ for _ in ()).throw(
                AssertionError("invalid CONNECT target reached policy snapshot")
            )
            addon.http_connect(uppercase_wire)
            assert uppercase_wire.response.status_code == 400
            assert json.loads(uppercase_wire.response.raw_content) == {
                "error": "invalid_connect_target"
            }

            unknown_principal = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(None)
            addon.http_connect(unknown_principal)
            assert unknown_principal.response.status_code == 403
            assert unknown_principal.metadata["serverware_blocked_response"] is True
            assert json.loads(unknown_principal.response.raw_content)["error"] == "unknown_connect_denied"

            unassigned_principal = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(
                SimpleNamespace(id="agent:connect-unassigned")
            )
            addon.http_connect(unassigned_principal)
            assert unassigned_principal.response.status_code == 403
            assert unassigned_principal.metadata["serverware_blocked_response"] is True

            snapshot_failure = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: (_ for _ in ()).throw(
                RuntimeError("forced CONNECT snapshot failure")
            )
            addon.http_connect(snapshot_failure)
            assert snapshot_failure.response.status_code == 503
            assert json.loads(snapshot_failure.response.raw_content) == {
                "error": "connect_hook_failed_closed"
            }

            log_failure = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(None)
            runtime.log_request = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("forced CONNECT audit failure")
            )
            addon.http_connect(log_failure)
            assert log_failure.response.status_code == 503
            assert log_failure.metadata["serverware_blocked_response"] is True
            assert json.loads(log_failure.response.raw_content) == {
                "error": "connect_hook_failed_closed"
            }

            assigned = connect_flow()
            assigned_principal = SimpleNamespace(id="agent:connect-assigned")
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(assigned_principal)
            runtime.log_request = lambda *args, **kwargs: connect_logs.append((args, kwargs))
            addon.http_connect(assigned)
            assert getattr(assigned, "response", None) is None
            assert assigned.metadata.get("serverware_blocked_response") is not True
            assert identified_inputs[-1] == ("10.42.0.9", assigned.request.headers)
            assert "must-not-enter-audit" not in repr(connect_logs)
            reused_tunnel = connect_flow()
            reused_tunnel.client_conn = assigned.client_conn
            reused_tunnel.server_conn = assigned.server_conn
            addon.http_connect(reused_tunnel)
            assert reused_tunnel.response.status_code == 400
            assert json.loads(reused_tunnel.response.raw_content) == {
                "error": "invalid_connect_target"
            }
        finally:
            runtime.log_request = original_connect_log
            mitm_addon.get_policy_snapshot = original_connect_snapshot

        original_addon_evaluate_request = mitm_addon.evaluate_request
        original_addon_dispatch = mitm_addon.dispatch_release_authorization
        original_addon_dispatch_marker = (
            mitm_addon.mark_provider_dispatch_uncertain
        )
        original_complete = runtime.complete_release_authorization
        original_cancel_expected = runtime.cancel_expected_release_authorization
        completion_outcomes: list[str] = []
        dispatch_calls: list[str] = []

        def complete_failed_hook(**kwargs):
            completion_outcomes.append(kwargs["outcome"])
            if kwargs["outcome"] != "unknown":
                raise AssertionError(
                    "untyped addon cleanup bypassed the expected reservation guard"
                )
            previous = kwargs["previous_lifecycle"]
            return {
                "authorized": True,
                "state": "committed_indeterminate",
                "reason": "forward_outcome_indeterminate",
                "attempt_id": kwargs["attempt_id"],
                "binding_digest": kwargs["binding_digest"],
                "idempotent_replay": False,
                "grant_id": None,
                "approval_request_id": None,
                "approval_status": None,
                "approval_expires_at": None,
                "approval_created": None,
                "reservation_expires_at_epoch_ms": previous[
                    "reservation_expires_at_epoch_ms"
                ],
                "dispatch_started_at_epoch_ms": previous.get(
                    "dispatch_started_at_epoch_ms"
                ),
                "dispatch_expires_at_epoch_ms": previous.get(
                    "dispatch_expires_at_epoch_ms"
                ),
                "completion_outcome": "unknown",
                "retry_after_seconds": 0,
                "quotas": [],
            }

        def cancel_expected_hook(expected):
            completion_outcomes.append("not_forwarded")
            return {
                "authorized": False,
                "state": "cancelled",
                "reason": "cancelled",
                "attempt_id": expected.attempt_id,
                "binding_digest": expected.binding_digest,
                "idempotent_replay": False,
                "grant_id": None,
                "approval_request_id": None,
                "approval_status": None,
                "approval_expires_at": None,
                "approval_created": None,
                "reservation_expires_at_epoch_ms": int(time.time() * 1000)
                + 60_000,
                "dispatch_started_at_epoch_ms": None,
                "dispatch_expires_at_epoch_ms": None,
                "completion_outcome": "not_forwarded",
                "retry_after_seconds": 0,
                "quotas": [],
            }

        def install_lifecycle(item, *, dispatch_attempted: bool = False):
            expected = runtime.expected_release_authorization_identity(
                attempt_id="attempt:addon-failure",
                flow_id="attempt:addon-failure",
                principal_id="agent:addon-fixture",
                route_id="route:addon-fixture",
                credential_ref=None,
                credential_version=0,
                policy_hash="sha256:" + "7" * 64,
                request_digest="sha256:" + "6" * 64,
                operation_digest=None,
                operation_context={},
                shared_quotas=[],
                require_jit_grant=False,
            )
            guard = runtime.ReleaseAuthorizationGuard(expected)
            guard.promote_reserved()
            item.metadata["serverware_atomic_reservation_required"] = True
            item.metadata[
                "serverware_release_authorization_guard"
            ] = guard
            item.metadata["serverware_release_authorization"] = {
                "attempt_id": expected.attempt_id,
                "flow_id": expected.flow_id,
                "binding_digest": expected.binding_digest,
                "state": "reserved",
                "dispatch_attempted": dispatch_attempted,
                "reservation_expires_at_epoch_ms": int(time.time() * 1000)
                + 60_000,
                "quotas": [],
            }
            return guard

        def fail_after_reserve(item):
            install_lifecycle(item)
            raise RuntimeError("request evaluation failed after reserve")

        def allow_with_reservation(item):
            install_lifecycle(item)
            return SimpleNamespace(
                decision=policy_engine.PolicyDecision(True),
                route=SimpleNamespace(
                    credential_ref=None,
                    resolved_cidrs=None,
                ),
            )

        def incorrectly_allow_credential(_item):
            return SimpleNamespace(
                decision=policy_engine.PolicyDecision(True),
                route=SimpleNamespace(
                    credential_ref="cred-demo-bearer",
                    resolved_cidrs=("127.0.0.1/32",),
                ),
            )

        def fail_during_dispatch(item):
            dispatch_calls.append("dispatch")
            item.metadata["serverware_release_authorization"]["dispatch_attempted"] = True
            raise RuntimeError("dispatch transport failed unexpectedly")

        runtime.complete_release_authorization = complete_failed_hook
        runtime.cancel_expected_release_authorization = cancel_expected_hook
        try:
            ingress_targets: list[str] = []

            def deny_after_raw_ingress(item):
                ingress_targets.append(
                    item.metadata["serverware_raw_absolute_target"]
                )
                assert (
                    item.metadata["serverware_raw_target_validated"] is True
                )
                assert (
                    item.request.pretty_url
                    == item.metadata["serverware_raw_absolute_target"]
                )
                assert (
                    item.metadata[LEGACY_MITM_TRANSPORT_METADATA_KEY]
                    is True
                )
                return SimpleNamespace(
                    decision=policy_engine.PolicyDecision(
                        False,
                        "fixture denial",
                        403,
                        {"error": "fixture_denied"},
                    )
                )

            mitm_addon.evaluate_request = deny_after_raw_ingress
            canonical_absolute = flow(
                "GET",
                "https://demo-upstream:8443/echo?literal=%2B&space=a%20b",
            )
            addon.request(canonical_absolute)
            assert canonical_absolute.response.status_code == 403
            assert ingress_targets == [
                "https://demo-upstream:8443/echo?literal=%2B&space=a%20b"
            ]

            canonical_origin = flow("GET", "https://demo-upstream:8443/echo")
            canonical_origin.request.first_line_format = "relative"
            canonical_origin.request.data.authority = b""
            canonical_origin.request.headers = RawHeaders(
                [("Host", "demo-upstream:8443")]
            )
            canonical_origin.request.data.headers = canonical_origin.request.headers
            addon.request(canonical_origin)
            assert canonical_origin.response.status_code == 400
            assert json.loads(canonical_origin.response.raw_content) == {
                "error": "invalid_request_target"
            }

            missing_host = flow(
                "GET", "https://demo-upstream:8443/echo"
            )
            missing_host.request.data.headers = RawHeaders([])
            duplicate_host = flow(
                "GET", "https://demo-upstream:8443/echo"
            )
            duplicate_host.request.data.headers = RawHeaders(
                [
                    ("Host", "demo-upstream:8443"),
                    ("host", "demo-upstream:8443"),
                ]
            )
            h2_host_ambiguity = flow(
                "GET", "https://demo-upstream:8443/echo"
            )
            h2_host_ambiguity.request.first_line_format = "relative"
            h2_host_ambiguity.request.http_version = "HTTP/2"
            h2_host_ambiguity.request.data.http_version = b"HTTP/2"
            h2_host_ambiguity.request.data.headers = RawHeaders(
                [("Host", "demo-upstream:8443")]
            )
            for invalid_host in (
                missing_host,
                duplicate_host,
                h2_host_ambiguity,
            ):
                addon.request(invalid_host)
                assert invalid_host.response.status_code == 400
                assert json.loads(invalid_host.response.raw_content) == {
                    "error": "invalid_request_target"
                }

            h2_canonical = flow(
                "GET", "https://demo-upstream:8443/echo"
            )
            h2_canonical.request.first_line_format = "relative"
            h2_canonical.request.http_version = "HTTP/2"
            h2_canonical.request.data.http_version = b"HTTP/2"
            h2_canonical.request.data.headers = RawHeaders([])
            assert mitm_addon._admit_raw_absolute_request_target(
                h2_canonical
            ) == (
                "https://demo-upstream:8443/echo",
                "demo-upstream",
                8443,
            )

            tunnel_a_request = flow(
                "GET", "https://connect.example.test/resource"
            )
            tunnel_a_request.client_conn = assigned.client_conn
            tunnel_a_request.server_conn = assigned.server_conn
            tunnel_a_request.request.first_line_format = "relative"
            tunnel_a_request.request.data.authority = b""
            tunnel_a_request.request.data.headers = RawHeaders(
                [("Host", "connect.example.test")]
            )
            addon.request(tunnel_a_request)
            assert tunnel_a_request.response.status_code == 403
            assert ingress_targets[-1] == (
                "https://connect.example.test/resource"
            )

            admitted_before_cross_authority = len(ingress_targets)
            tunnel_b_request = flow(
                "GET", "https://other.example.test/resource"
            )
            tunnel_b_request.client_conn = assigned.client_conn
            tunnel_b_request.server_conn = assigned.server_conn
            tunnel_b_request.request.first_line_format = "relative"
            tunnel_b_request.request.data.authority = b""
            tunnel_b_request.request.data.headers = RawHeaders(
                [("Host", "other.example.test")]
            )
            addon.request(tunnel_b_request)
            assert tunnel_b_request.response.status_code == 400
            assert json.loads(tunnel_b_request.response.raw_content) == {
                "error": "invalid_request_target"
            }
            assert len(ingress_targets) == admitted_before_cross_authority

            (
                unavailable_raw,
                unavailable_headers,
                uppercase_raw,
                inconsistent_raw,
                raw_plus_query,
                unsorted_query,
                duplicate_query,
            ) = (
                flow("GET", "https://demo-upstream:8443/echo"),
                flow("GET", "https://demo-upstream:8443/echo"),
                flow("GET", "https://demo-upstream:8443/echo"),
                flow("GET", "https://demo-upstream:8443/echo"),
                flow(
                    "GET",
                    "https://demo-upstream:8443/echo?space=a+b",
                ),
                flow(
                    "GET",
                    "https://demo-upstream:8443/echo?space=a%20b&data=a%26b%3Dc",
                ),
                flow(
                    "GET",
                    "https://demo-upstream:8443/echo?data=first&data=second",
                ),
            )
            unavailable_raw.request.data = None
            unavailable_headers.request.data.headers = None
            uppercase_raw.request.data.authority = b"DEMO-upstream:8443"
            inconsistent_raw.request.data.path = b"/different"
            admitted_before_invalid = len(ingress_targets)
            for invalid_ingress in (
                unavailable_raw,
                unavailable_headers,
                uppercase_raw,
                inconsistent_raw,
                raw_plus_query,
                unsorted_query,
                duplicate_query,
            ):
                addon.request(invalid_ingress)
                assert invalid_ingress.response.status_code == 400
                assert json.loads(invalid_ingress.response.raw_content) == {
                    "error": "invalid_request_target"
                }
            assert len(ingress_targets) == admitted_before_invalid

            cleanup_unknown_calls: list[object] = []

            def cleanup_transport_loss(expected):
                cleanup_unknown_calls.append(expected)
                raise runtime.ReleaseAuthorizationClientError(
                    "fixture cleanup transport loss"
                )

            runtime.cancel_expected_release_authorization = (
                cleanup_transport_loss
            )
            cleanup_unknown = flow(
                "POST",
                "https://demo-upstream:8443/echo",
            )
            cleanup_unknown_guard = install_lifecycle(cleanup_unknown)
            first_cleanup = (
                policy_engine.complete_release_authorization_for_error(
                    cleanup_unknown
                )
            )
            second_cleanup = (
                policy_engine.complete_release_authorization_for_error(
                    cleanup_unknown
                )
            )
            assert first_cleanup.allowed is False
            assert second_cleanup.allowed is True
            assert cleanup_unknown_calls == [cleanup_unknown_guard.expected]
            assert cleanup_unknown_guard.phase == "cleanup_unknown"
            assert cleanup_unknown_guard.cleanup_emitted is True
            assert cleanup_unknown_guard.cleanup_error is True
            assert (
                cleanup_unknown.metadata["serverware_release_state"]
                == "cleanup_unknown"
            )
            assert (
                cleanup_unknown.metadata[
                    "serverware_release_authorization"
                ]["cleanup_error"]
                == "fixture cleanup transport loss"
            )
            runtime.cancel_expected_release_authorization = cancel_expected_hook

            mitm_addon.evaluate_request = incorrectly_allow_credential
            mitm_addon.dispatch_release_authorization = (
                lambda _item: dispatch_calls.append("unexpected_dispatch")
            )
            escaped_credential = flow(
                "POST",
                "https://demo-upstream:8443/echo",
            )
            addon.request(escaped_credential)
            assert escaped_credential.response.status_code == 503
            assert json.loads(
                escaped_credential.response.raw_content
            ) == {
                "error": "legacy_mitm_credential_transport_denied"
            }
            assert dispatch_calls == []

            mitm_addon.evaluate_request = fail_after_reserve
            mitm_addon.dispatch_release_authorization = lambda _item: dispatch_calls.append(
                "unexpected_dispatch"
            )
            reserved_failure = flow("POST", "https://demo-upstream:8443/echo")
            addon.request(reserved_failure)
            assert reserved_failure.response is not None
            assert reserved_failure.response.status_code == 503
            assert reserved_failure.metadata["serverware_blocked_response"] is True
            assert json.loads(reserved_failure.response.raw_content) == {
                "error": "request_hook_failed_closed"
            }
            assert dispatch_calls == [], dispatch_calls
            assert completion_outcomes == ["not_forwarded"], completion_outcomes
            assert reserved_failure.metadata["serverware_release_state"] == "cancelled"

            mitm_addon.evaluate_request = allow_with_reservation
            mitm_addon.dispatch_release_authorization = fail_during_dispatch
            dispatch_failure = flow("POST", "https://demo-upstream:8443/echo")
            addon.request(dispatch_failure)
            assert dispatch_failure.response is not None
            assert dispatch_failure.response.status_code == 503
            assert dispatch_failure.metadata["serverware_blocked_response"] is True
            assert completion_outcomes == ["not_forwarded", "unknown"], completion_outcomes
            assert dispatch_failure.metadata["serverware_release_state"] == "committed_indeterminate"

            forward_events: list[str] = []

            def authorize_dispatch(item):
                forward_events.append("dispatch")
                lifecycle = item.metadata["serverware_release_authorization"]
                lifecycle["state"] = "dispatch_authorized"
                item.metadata["serverware_release_state"] = "dispatch_authorized"
                item.metadata[
                    "serverware_release_authorization_guard"
                ].mark_dispatch_authorized()
                return policy_engine.PolicyDecision(True)

            def observe_dispatch_marker(item):
                original_addon_dispatch_marker(item)
                forward_events.append("dispatch_marker")

            mitm_addon.evaluate_request = allow_with_reservation
            mitm_addon.dispatch_release_authorization = authorize_dispatch
            mitm_addon.mark_provider_dispatch_uncertain = (
                observe_dispatch_marker
            )
            forwarded = flow("POST", "https://demo-upstream:8443/echo")
            addon.request(forwarded)
            if (
                forwarded.response is not None
                or forward_events
                != ["dispatch", "dispatch_marker"]
                or forwarded.metadata.get("serverware_release_state")
                != "dispatching"
                or not forwarded.metadata[
                    "serverware_release_authorization_guard"
                ].dispatch_uncertain
            ):
                raise AssertionError(
                    "addon did not retain dispatch ownership through its final "
                    f"pre-provider operation: {forward_events} {forwarded.metadata}"
                )

            mitm_addon.evaluate_request = lambda _item: (_ for _ in ()).throw(
                AssertionError("streamed request reached policy evaluation")
            )
            streamed = flow("POST", "https://demo-upstream:8443/echo")
            streamed.request.stream = True
            addon.requestheaders(streamed)
            addon.request(streamed)
            assert streamed.response.status_code == 503
            assert json.loads(streamed.response.raw_content) == {
                "error": "request_streaming_unsupported"
            }
        finally:
            runtime.cancel_expected_release_authorization = (
                original_cancel_expected
            )
            runtime.complete_release_authorization = original_complete
            mitm_addon.mark_provider_dispatch_uncertain = (
                original_addon_dispatch_marker
            )
            mitm_addon.dispatch_release_authorization = original_addon_dispatch
            mitm_addon.evaluate_request = original_addon_evaluate_request

    npm_extra_version = copy.deepcopy(npm_document)
    npm_extra_version["versions"]["9.9.9"] = {"name": "@scope/example", "version": "9.9.9"}
    assert_denied(
        npm_adapter.validate_request(
            flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_extra_version),
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "npm_publish_requires_exactly_one_version",
    )

    npm_operations = (
        (
            flow("DELETE", "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef"),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
                {
                    "_rev": "42-deadbeef",
                    "name": "@scope/example",
                    "dist-tags": {"latest": "2.0.0"},
                    "versions": {
                        "2.0.0": {
                            "name": "@scope/example",
                            "version": "2.0.0",
                        }
                    },
                },
            ),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            flow(
                "DELETE",
                "https://registry.npmjs.org/@scope%2fexample/-/example.tgz/-rev/42-deadbeef",
            ),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next",
                "1.2.3",
            ),
            {"package": "@scope%2fexample", "tag": "next"},
            "npm.distTagWrite",
        ),
        (
            flow("DELETE", "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next"),
            {"package": "@scope%2fexample", "tag": "next"},
            "npm.distTagWrite",
        ),
        (
            flow("DELETE", "https://registry.npmjs.org/-/npm/v1/tokens/token/token-key"),
            {"token": "token-key"},
            "npm.tokenWrite",
        ),
        (
            flow("POST", "https://registry.npmjs.org/-/package/@scope%2fexample/access", {"access": "public"}),
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
        (
            flow("POST", "https://registry.npmjs.org/-/npm/v1/user", {"email": "owner@example.test"}),
            {},
            "npm.metadataWrite",
        ),
        (
            flow(
                "DELETE",
                "https://registry.npmjs.org/-/team/scope/owners/package",
                {"package": "@scope/example"},
            ),
            {"scope": "scope", "team": "owners"},
            "npm.metadataWrite",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample",
                {
                    "_rev": "42-deadbeef",
                    "name": "@scope/example",
                    "description": "metadata only",
                },
            ),
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
    )
    for npm_write, params, expected_operation in npm_operations:
        fields = npm_adapter.operation_fields(npm_write, npm_route, params)
        assert fields["operation"] == expected_operation, fields
        assert npm_adapter.validate_request(npm_write, npm_route, params).allowed, fields

    if _bind_provider_account_scope is not None:
        db.clear_rate_limit_counters((x_write_example["id"],))
        account_route = route(example_snapshot, x_write_example["id"])
        account_credential = example_snapshot.credentials[account_route.credential_ref]
        first_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, account_credential, first_operation) is None
        assert first_operation["providerAccount"] == (
            "sha256:a807912d32ff627e2bcaeea09bad5a4ba3b43c74e891cdfb13d913f4230b122e"
        )
        account_tweet = flow("POST", "https://api.x.com/2/tweets", {"text": "first"})
        assert request_decision(
            account_route,
            account_tweet,
            "tweets.write",
            consume=True,
            principal_id="agent:first",
            credential_ref="cred-x:first-version",
            operation_fields=first_operation,
        ).allowed

        rotated_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, account_credential, rotated_operation) is None
        assert_denied(
            request_decision(
                account_route,
                account_tweet,
                "tweets.write",
                consume=True,
                principal_id="agent:second",
                credential_ref="cred-x:rotated-version",
                operation_fields=rotated_operation,
            ),
            "credential_rate_limit_exceeded",
        )

        for alias in ("twitter", "x.oauth", "x.oauth2", " X.OAUTH2 "):
            alias_account = CredentialPolicy(
                id=f"cred-x:{alias.strip().lower()}",
                provider=alias,
                provider_subject=account_credential.provider_subject,
            )
            alias_operation = {"operation": "tweets.write"}
            assert _bind_provider_account_scope(account_route, alias_account, alias_operation) is None
            assert alias_operation["providerAccount"] == first_operation["providerAccount"]
            assert_denied(
                request_decision(
                    account_route,
                    account_tweet,
                    "tweets.write",
                    consume=True,
                    principal_id=f"agent:{alias.strip().lower()}",
                    credential_ref=alias_account.id,
                    operation_fields=alias_operation,
                ),
                "credential_rate_limit_exceeded",
            )

        other_account = CredentialPolicy(
            id="cred-x:other-account",
            provider="x",
            provider_subject="different-x-user-id",
        )
        other_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, other_account, other_operation) is None
        assert other_operation["providerAccount"] != first_operation["providerAccount"]
        assert request_decision(
            account_route,
            account_tweet,
            "tweets.write",
            consume=True,
            principal_id="agent:third",
            credential_ref=other_account.id,
            operation_fields=other_operation,
        ).allowed

        missing_account = CredentialPolicy(id="cred-x:missing-account", provider="custom-x")
        missing_decision = _bind_provider_account_scope(
            account_route,
            missing_account,
            {"operation": "tweets.write"},
        )
        assert_denied(missing_decision, "provider_account_identity_unavailable")
        db.clear_rate_limit_counters((x_write_example["id"],))

    reset_local_constraint_state()
    local_rate_route = SimpleNamespace(
        id="local-rate-capacity-test",
        credential_ref="credential:local-rate",
        constraints=[
            {
                "id": "bounded-local-rate",
                "type": "rateLimit",
                "max": 10,
                "windowSeconds": 1,
                "store": "local",
            }
        ],
    )
    local_rate_flow = flow("GET", "https://local-rate.example.test/read")
    original_local_capacity = constraints._MAX_LOCAL_RATE_COUNTER_ENTRIES
    original_constraint_time = constraints.time.time
    constraints._MAX_LOCAL_RATE_COUNTER_ENTRIES = 2
    constraint_now = 100
    constraints.time.time = lambda: constraint_now
    try:
        for operation in ("preview-one", "preview-two", "preview-three"):
            assert request_decision(local_rate_route, local_rate_flow, operation).allowed
        assert constraints._RATE_BUCKETS == {}, constraints._RATE_BUCKETS

        assert request_decision(
            local_rate_route, local_rate_flow, "consume-one", consume=True
        ).allowed
        assert request_decision(
            local_rate_route, local_rate_flow, "consume-two", consume=True
        ).allowed
        assert len(constraints._RATE_BUCKETS) == 2
        assert request_decision(
            local_rate_route, local_rate_flow, "preview-at-capacity"
        ).allowed
        assert len(constraints._RATE_BUCKETS) == 2
        capacity_denial = request_decision(
            local_rate_route, local_rate_flow, "consume-over-capacity", consume=True
        )
        assert_denied(capacity_denial, "local_rate_limit_capacity_exhausted")
        assert capacity_denial.status_code == 503
        assert capacity_denial.payload["capacity"] == 2
        assert len(constraints._RATE_BUCKETS) == 2

        constraint_now = 102
        assert request_decision(
            local_rate_route, local_rate_flow, "consume-after-expiry", consume=True
        ).allowed
        assert len(constraints._RATE_BUCKETS) == 1
        only_bucket = next(iter(constraints._RATE_BUCKETS.values()))
        assert only_bucket.count == 1
        assert only_bucket.expires_at == 103
    finally:
        constraints.time.time = original_constraint_time
        constraints._MAX_LOCAL_RATE_COUNTER_ENTRIES = original_local_capacity
        reset_local_constraint_state()

    tweet_route = route(demo, "demo.x.tweet.one_per_day")
    tweet = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it"})
    assert request_decision(tweet_route, tweet, "tweets.write").allowed
    assert request_decision(tweet_route, tweet, "tweets.write", consume=True).allowed
    assert_denied(
        request_decision(tweet_route, tweet, "tweets.write", consume=True),
        "credential_rate_limit_exceeded",
    )

    db.clear_rate_limit_counters(("demo.x.tweet.one_per_day",))
    reset_local_constraint_state()
    tweet_with_media = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it", "media": {"ids": ["1"]}})
    assert_denied(request_decision(tweet_route, tweet_with_media, "tweets.write"), "json_body_field_not_allowed")

    for unexpected_empty in ({}, [], [{}], {"nested": []}):
        tweet_with_empty_unknown = flow(
            "POST",
            "https://demo-upstream:8443/2/tweets",
            {"text": "ship it", "unexpected": unexpected_empty},
        )
        assert_denied(
            request_decision(tweet_route, tweet_with_empty_unknown, "tweets.write"),
            "json_body_field_not_allowed",
        )

    explicit_container_route = SimpleNamespace(
        id="test.explicit-empty-container",
        credential_ref=None,
        constraints=[
            {
                "id": "explicit-empty-container-body",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["items"],
                "requiredFields": ["items"],
                "fields": {"items": {"type": "array", "minItems": 0, "maxItems": 1}},
            }
        ],
    )
    for allowed_items in ([], [{}]):
        assert request_decision(
            explicit_container_route,
            flow("POST", "https://api.example.test/items", {"items": allowed_items}),
            "items.write",
        ).allowed
    assert_denied(
        request_decision(
            explicit_container_route,
            flow("POST", "https://api.example.test/items", {"items": [{}, {}]}),
            "items.write",
        ),
        "json_body_field_max_items",
    )

    readonly_route = route(demo, "demo.x.readonly")
    readonly_write = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "nope"})
    readonly_adapter = get_adapter(readonly_route.adapter_type)
    assert_denied(readonly_adapter.validate_request(readonly_write, readonly_route, {}), "x_write_blocked")

    search_route = route(demo, "demo.x.search.recent")
    old_search = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(10)}&max_results=10",
    )
    assert_denied(request_decision(search_route, old_search, "search.read"), "query_date_window_exceeded")

    huge_page = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(1)}&max_results=500",
    )
    assert_denied(request_decision(search_route, huge_page, "search.read"), "query_numeric_max_exceeded")

    for non_finite in ("NaN", "Infinity", "-Infinity", "1e400"):
        non_finite_query = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent"
            f"?query=serverware&start_time={iso_days_ago(1)}&max_results={non_finite}",
        )
        assert_denied(
            request_decision(search_route, non_finite_query, "search.read"),
            "query_numeric_parameter_invalid",
        )
        non_finite_date_query = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent"
            f"?query=serverware&start_time={non_finite}&max_results=10",
        )
        assert_denied(
            request_decision(search_route, non_finite_date_query, "search.read"),
            "query_date_parameter_invalid",
        )

    old_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": [{"id": "1", "text": "old", "created_at": iso_days_ago(10)}]},
    )
    assert_denied(evaluate_response_constraints(old_response, search_route), "response_date_window_exceeded")
    for invalid_date_body in (
        b'{"data":[{"created_at":"first","created_at":"second"}]}',
        b'{"data":[{"created_at":NaN}]}',
        b'{"data":[{"created_at":Infinity}]}',
        b'{"data":[{"created_at":-Infinity}]}',
        b'{"data":[{"created_at":1e400}]}',
    ):
        invalid_date_response = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
            response={"data": []},
        )
        invalid_date_response.response.raw_content = invalid_date_body
        assert_denied(
            evaluate_response_constraints(invalid_date_response, search_route),
            "response_json_invalid",
        )
    empty_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": []},
    )
    assert evaluate_response_constraints(empty_response, search_route).allowed

    gmail_route = route(demo, "demo.gmail.recent")
    gmail_old_list = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "msg-old", "internalDate": str(epoch_ms_days_ago(45))}]},
    )
    gmail_old_list.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(gmail_old_list, gmail_route), "response_date_window_exceeded")

    gmail_detail = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent-message-1",
        response={"id": "recent-message-1", "internalDate": str(epoch_ms_days_ago(1))},
    )
    assert_denied(evaluate_response_constraints(gmail_detail, gmail_route), "response_operation_context_missing")
    gmail_detail.metadata["serverware_operation"] = {"operation": "gmail.message.get"}
    assert evaluate_response_constraints(gmail_detail, gmail_route).allowed

    gmail_adapter = get_adapter(gmail_route.adapter_type)
    gmail_wrong_media_type = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"id": "recent"},
    )
    gmail_wrong_media_type.response.headers["content-type"] = "text/plain"
    gmail_wrong_media_type.response.raw_content = b"not-json-and-must-not-release"
    gmail_wrong_media_body = gmail_wrong_media_type.response.raw_content
    for decision in (
        gmail_adapter.prepare_response(
            gmail_wrong_media_type,
            gmail_route,
            {"user": "me", "message_id": "recent"},
        ),
        gmail_adapter.validate_response(
            gmail_wrong_media_type,
            gmail_route,
            {"user": "me", "message_id": "recent"},
        ),
    ):
        assert_denied(decision, "response_json_content_type_denied")
        assert decision.status_code == 502
    assert gmail_wrong_media_type.response.raw_content == gmail_wrong_media_body

    fractional_internal_date = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/fractional",
        response={
            "id": "fractional",
            "internalDate": float(epoch_ms_days_ago(1)) + 0.5,
        },
    )
    fractional_internal_date.response.headers[
        "content-type"
    ] = "application/json; charset=utf-8"
    assert_denied(
        gmail_adapter.validate_response(
            fractional_internal_date,
            gmail_route,
            {"user": "me", "message_id": "fractional"},
        ),
        "gmail_response_invalid_internal_date",
    )
    mismatched_detail = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/requested",
        response={
            "id": "different",
            "internalDate": str(epoch_ms_days_ago(1)),
        },
    )
    assert_denied(
        gmail_adapter.validate_response(
            mismatched_detail,
            gmail_route,
            {"user": "me", "message_id": "requested"},
        ),
        "gmail_response_message_id_mismatch",
    )
    future_detail = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/future",
        response={
            "id": "future",
            "internalDate": str(int(time.time() * 1000) + 360_000),
        },
    )
    assert_denied(
        gmail_adapter.validate_response(
            future_detail,
            gmail_route,
            {"user": "me", "message_id": "future"},
        ),
        "gmail_response_internal_date_in_future",
    )
    for projection in (None, []):
        unprojected_gmail_route = copy.deepcopy(gmail_route)
        response_config = unprojected_gmail_route.adapter_config["response"]
        if projection is None:
            response_config.pop("allowedFields")
        else:
            response_config["allowedFields"] = projection
        unprojected_gmail = flow(
            "GET",
            "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
            response={
                "id": "recent",
                "internalDate": str(epoch_ms_days_ago(1)),
                "provider_internal_secret": "must-not-release",
            },
        )
        decision = gmail_adapter.validate_response(
            unprojected_gmail,
            unprojected_gmail_route,
            {"user": "me", "message_id": "recent"},
        )
        assert_denied(decision, "credential_response_projection_required")
        assert decision.status_code == 502
        assert decision.reason == "credential-bearing response requires a non-empty allowedFields projection"
        assert decision.payload == {
            "error": "credential_response_projection_required",
            "adapter": "gmail.v1",
            "mode": "json",
        }

    gmail_response_config = gmail_route.adapter_config["response"]
    assert gmail_route.adapter_config["forceQuery"] is True
    assert (
        gmail_route.adapter_config["allowMessageGetOnlyFromPriorSearch"]
        is True
    )
    assert gmail_response_config["validateInternalDate"] is True
    assert (
        gmail_response_config["validateListByMetadataFetch"]
        is True
    )
    assert gmail_response_config["metadataFetch"] == {
        "maxMessages": 10,
        "perRequestTimeoutMs": 1500,
        "totalTimeoutMs": 8000,
        "maxBodyBytes": 4096,
    }
    legacy_gmail_flow = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
    )
    legacy_gmail_flow.metadata[
        LEGACY_MITM_TRANSPORT_METADATA_KEY
    ] = True
    assert_denied(
        _legacy_mitm_route_admission(
            legacy_gmail_flow,
            gmail_route,
        ),
        "legacy_mitm_credential_transport_denied",
    )

    gmail_headers = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "id": "recent",
            "internalDate": str(epoch_ms_days_ago(1)),
            "provider_internal_secret": "top-level-secret",
            "payload": {
                "body": {"data": "nested-secret"},
                "headers": [
                    {"name": "From", "value": "sender@example.test"},
                    {"name": "Subject", "value": "allowed"},
                    {"name": "Bcc", "value": "must-not-release@example.test"},
                ]
            },
        },
    )
    gmail_headers.response.headers.update(
        {"set-cookie": "provider_session=secret", "location": "https://evil.test/"}
    )
    gmail_detail_params = {"user": "me", "message_id": "recent"}
    assert gmail_adapter.validate_response(gmail_headers, gmail_route, gmail_detail_params).allowed
    released_gmail = json.loads(gmail_headers.response.get_text())
    released_headers = released_gmail["payload"]["headers"]
    assert [item["name"] for item in released_headers] == ["From", "Subject"], released_headers
    assert "provider_internal_secret" not in released_gmail
    assert "body" not in released_gmail["payload"]
    assert "top-level-secret" not in gmail_headers.response.get_text()
    assert "nested-secret" not in gmail_headers.response.get_text()
    assert set(name.lower() for name in gmail_headers.response.headers) == {
        "content-type",
        "content-length",
    }, gmail_headers.response.headers

    gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "slow down"},
            "providerInternal": "must not release",
        },
    )
    gmail_error.response.status_code = 429
    gmail_error.metadata["serverware_operation"] = {
        "operation": "gmail.message.get"
    }
    assert _evaluate_response_envelope(gmail_error, gmail_route).allowed
    gmail_error.response.headers.update(
        {
            "retry-after": "30",
            "www-authenticate": 'Bearer realm="gmail"',
        }
    )
    assert _evaluate_response_envelope(gmail_error, gmail_route).allowed
    malformed_retry_after = copy.deepcopy(gmail_error)
    malformed_retry_after.response.headers["retry-after"] = "1234567"
    assert_denied(
        _evaluate_response_envelope(malformed_retry_after, gmail_route),
        "response_envelope_header_value_denied",
    )
    gmail_error.response.headers["set-cookie"] = "provider_session=secret"
    assert gmail_adapter.validate_response(gmail_error, gmail_route, gmail_detail_params).allowed
    assert json.loads(gmail_error.response.get_text()) == {
        "error": {"code": 429, "message": "slow down", "status": "RESOURCE_EXHAUSTED"}
    }
    assert gmail_error.response.headers.get("retry-after") == "30"
    assert gmail_error.response.headers.get("www-authenticate") == 'Bearer realm="gmail"'
    assert "set-cookie" not in {name.lower() for name in gmail_error.response.headers}

    unlisted_gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"error": {"code": 418, "message": "not admitted"}},
    )
    unlisted_gmail_error.response.status_code = 418
    unlisted_gmail_error.metadata["serverware_operation"] = {
        "operation": "gmail.message.get"
    }
    assert_denied(
        _evaluate_response_envelope(unlisted_gmail_error, gmail_route),
        "response_envelope_status_denied",
    )
    assert_denied(
        gmail_adapter.validate_response(
            unlisted_gmail_error,
            gmail_route,
            gmail_detail_params,
        ),
        "response_error_profile_status_denied",
    )

    oversized_gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"error": {"code": 429, "message": "placeholder"}},
    )
    oversized_gmail_error.response.status_code = 429
    oversized_gmail_error.response.raw_content = (
        b'{"error":{"code":429,"message":"'
        + b"x" * 65_536
        + b'"}}'
    )
    oversized_gmail_error.metadata["serverware_operation"] = {
        "operation": "gmail.message.get"
    }
    assert _evaluate_response_envelope(
        oversized_gmail_error,
        gmail_route,
    ).allowed
    assert_denied(
        gmail_adapter.validate_response(
            oversized_gmail_error,
            gmail_route,
            gmail_detail_params,
        ),
        "response_body_too_large",
    )

    bodyless_gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={},
    )
    bodyless_gmail_error.response.status_code = 429
    bodyless_gmail_error.response.raw_content = b""
    bodyless_gmail_error.metadata["serverware_operation"] = {
        "operation": "gmail.message.get"
    }
    assert_denied(
        _evaluate_response_envelope(bodyless_gmail_error, gmail_route),
        "response_envelope_body_presence_denied",
    )

    gmail_redirect = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"redirect": True},
    )
    gmail_redirect.response.status_code = 302
    gmail_redirect.response.headers["location"] = "https://evil.test/"
    assert_denied(
        gmail_adapter.validate_response(gmail_redirect, gmail_route, gmail_detail_params),
        "response_redirect_not_allowed",
    )

    npm_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "denied", "reason": "policy", "internal": "must not release"},
    )
    npm_error.response.status_code = 403
    npm_error.metadata["serverware_operation"] = {"operation": "npm.publish"}
    npm_adapter = get_adapter(route(demo, "demo.npm.publish.jit").adapter_type)
    npm_demo_route = route(demo, "demo.npm.publish.jit")
    npm_public_route = route(public_npm_snapshot, "demo.npm.publish.jit")
    npm_public_params = {"package": "@scope%2fexample"}

    def public_npm_receipt(
        payload: dict,
        *,
        status_code: int = 200,
    ) -> SimpleNamespace:
        receipt = flow(
            "PUT",
            "https://registry.npmjs.org/npm/@scope%2fexample",
            npm_document,
            response=payload,
        )
        receipt.response.status_code = status_code
        receipt.metadata["serverware_operation"] = {
            "operation": "npm.publish",
            "packageName": "@scope/example",
            "packageVersion": "1.2.3",
        }
        return receipt

    for status_code in (200, 201):
        empty_public_receipt = public_npm_receipt({}, status_code=status_code)
        assert npm_adapter.prepare_response(
            empty_public_receipt,
            npm_public_route,
            npm_public_params,
        ).allowed
        assert npm_adapter.validate_response(
            empty_public_receipt,
            npm_public_route,
            npm_public_params,
        ).allowed
        assert json.loads(empty_public_receipt.response.get_text()) == {}

    projected_public_receipt = public_npm_receipt(
        {
            "ok": True,
            "published": True,
            "package": "other",
            "version": "9.9.9",
        }
    )
    assert npm_adapter.validate_response(
        projected_public_receipt,
        npm_public_route,
        npm_public_params,
    ).allowed
    assert json.loads(projected_public_receipt.response.get_text()) == {
        "ok": True,
        "published": True,
    }
    assert b"other" not in projected_public_receipt.response.raw_content
    assert b"9.9.9" not in projected_public_receipt.response.raw_content

    wrong_identity_only = public_npm_receipt(
        {"package": "other", "version": "9.9.9"}
    )
    assert npm_adapter.validate_response(
        wrong_identity_only,
        npm_public_route,
        npm_public_params,
    ).allowed
    assert json.loads(wrong_identity_only.response.get_text()) == {}

    denied_public_receipts = (
        {"published": False, "package": "other", "version": "9.9.9"},
        {"ok": False},
        {"ok": True, "published": False},
        {"published": "true"},
    )
    for payload in denied_public_receipts:
        denied_public_receipt = public_npm_receipt(payload)
        original_body = denied_public_receipt.response.raw_content
        assert npm_adapter.prepare_response(
            denied_public_receipt,
            npm_public_route,
            npm_public_params,
        ).allowed
        assert_denied(
            npm_adapter.validate_response(
                denied_public_receipt,
                npm_public_route,
                npm_public_params,
            ),
            "npm_public_publish_receipt_success_denied",
        )
        assert denied_public_receipt.response.raw_content == original_body

    duplicate_boolean_receipt = public_npm_receipt({})
    duplicate_boolean_receipt.response.raw_content = (
        b'{"published":true,"published":false}'
    )
    assert_denied(
        npm_adapter.validate_response(
            duplicate_boolean_receipt,
            npm_public_route,
            npm_public_params,
        ),
        "npm_public_publish_receipt_invalid_json",
    )

    non_object_receipt = public_npm_receipt({})
    non_object_receipt.response.raw_content = b"[]"
    assert_denied(
        npm_adapter.validate_response(
            non_object_receipt,
            npm_public_route,
            npm_public_params,
        ),
        "npm_public_publish_receipt_object_required",
    )

    public_status_202 = public_npm_receipt({}, status_code=202)
    for decision in (
        npm_adapter.prepare_response(
            public_status_202,
            npm_public_route,
            npm_public_params,
        ),
        npm_adapter.validate_response(
            public_status_202,
            npm_public_route,
            npm_public_params,
        ),
    ):
        assert_denied(decision, "npm_public_publish_receipt_status_denied")

    for label, headers in (
        ("missing", {}),
        ("wrong", {"content-type": "text/plain"}),
        (
            "duplicate",
            {"content-type": "application/json", "Content-Type": "application/json"},
        ),
    ):
        denied_public_media = public_npm_receipt({})
        denied_public_media.response.headers = headers
        original_body = denied_public_media.response.raw_content
        for decision in (
            npm_adapter.prepare_response(
                denied_public_media,
                npm_public_route,
                npm_public_params,
            ),
            npm_adapter.validate_response(
                denied_public_media,
                npm_public_route,
                npm_public_params,
            ),
        ):
            assert_denied(decision, "response_json_content_type_denied")
        assert denied_public_media.response.raw_content == original_body, label

    npm_demo_request = flow(
        "PUT",
        "https://demo-upstream:8443/npm/@scope%2fexample",
        npm_document,
    )
    npm_demo_fields = npm_adapter.operation_fields(
        npm_demo_request,
        npm_demo_route,
        {"package": "@scope%2fexample"},
    )
    npm_demo_success = flow(
        "PUT",
        "https://demo-upstream:8443/npm/@scope%2fexample",
        response={
            "package": "@scope/example",
            "version": "1.2.3",
            "published": True,
        },
    )
    npm_demo_success.metadata["serverware_operation"] = npm_demo_fields
    assert evaluate_response_constraints(npm_demo_success, npm_demo_route).allowed
    npm_demo_wrong_version = copy.deepcopy(npm_demo_success)
    npm_demo_wrong_version.response.raw_content = json.dumps(
        {
            "package": "@scope/example",
            "version": "9.9.9",
            "published": True,
        }
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(npm_demo_wrong_version, npm_demo_route),
        "response_binding_mismatch",
    )
    npm_wrong_error_media_type = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "must-not-release"},
    )
    npm_wrong_error_media_type.response.status_code = 403
    npm_wrong_error_media_type.metadata["serverware_operation"] = {
        "operation": "npm.publish"
    }
    npm_wrong_error_media_type.response.headers["content-type"] = "text/plain"
    npm_wrong_error_media_type.response.raw_content = b"not-json-and-must-not-release"
    npm_wrong_error_body = npm_wrong_error_media_type.response.raw_content
    for decision in (
        npm_adapter.prepare_response(
            npm_wrong_error_media_type,
            npm_demo_route,
            {"package": "@scope%2fexample"},
        ),
        npm_adapter.validate_response(
            npm_wrong_error_media_type,
            npm_demo_route,
            {"package": "@scope%2fexample"},
        ),
    ):
        assert_denied(decision, "response_json_content_type_denied")
        assert decision.status_code == 502
    assert npm_wrong_error_media_type.response.raw_content == npm_wrong_error_body

    npm_error.response.headers["content-type"] = "application/json; charset=utf-8"
    assert npm_adapter.prepare_response(
        npm_error,
        npm_demo_route,
        {"package": "@scope%2fexample"},
    ).allowed
    assert npm_adapter.validate_response(
        npm_error,
        npm_demo_route,
        {"package": "@scope%2fexample"},
    ).allowed
    assert json.loads(npm_error.response.get_text()) == {"error": "denied", "reason": "policy"}

    npm_invalid_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "invalid"},
    )
    npm_invalid_error.response.status_code = 500
    npm_invalid_error.metadata["serverware_operation"] = {
        "operation": "npm.publish"
    }
    npm_invalid_error.response.raw_content = b"not-json"
    assert_denied(
        npm_adapter.validate_response(npm_invalid_error, npm_demo_route, {"package": "@scope%2fexample"}),
        "response_invalid_json",
    )

    wrong_epoch_format = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "seconds", "internalDate": int(datetime.now(timezone.utc).timestamp())}]},
    )
    wrong_epoch_format.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(wrong_epoch_format, gmail_route), "response_date_field_invalid")

    if evaluate_response is not None:
        missing_response_context = flow(
            "GET",
            "https://demo-upstream:8443/unknown",
            response={"secret": "must not escape"},
        )
        assert_denied(evaluate_response(missing_response_context), "response_policy_context_missing")
        missing_response_context.metadata["serverware_blocked_response"] = True
        assert evaluate_response(missing_response_context).allowed

        guard_route = SimpleNamespace(
            id="response.credential.guard",
            adapter_type="generic.rest",
            adapter_config={
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 4096,
                    "allowedFields": ["echo", "ok", "authorization_sha256"],
                }
            },
            constraints=[],
            credential_ref="response-guard-credential",
        )

        def guarded_response(secret: str, payload: dict, injection: dict | None = None):
            guarded = flow("GET", "https://demo-upstream:8443/guarded", response=payload)
            guarded.metadata.update(
                {
                    "serverware_route": guard_route,
                    "serverware_route_id": guard_route.id,
                    "serverware_params": {},
                    "serverware_principal_id": "agent:demo",
                    "serverware_credential_id": guard_route.credential_ref,
                    "serverware_credential_version": 1,
                    "serverware_policy_hash": demo.hash,
                }
            )
            _inject_credential(
                guarded,
                SimpleNamespace(injection=injection or {"type": "bearer"}),
                {"secret": secret, "kind": "bearer", "metadata": {}},
            )
            return guarded

        original_response_adapter_lookup = policy_engine.get_adapter
        policy_engine.get_adapter = lambda _adapter_type: (_ for _ in ()).throw(
            AssertionError(
                "invalid response Content-Encoding reached adapter body processing"
            )
        )
        try:
            for adapter_type, status_code in (
                ("generic.rest", 200),
                ("x.v2", 200),
                ("gmail.v1", 200),
                ("npm.registry", 200),
                ("generic.rest", 500),
            ):
                for response_headers in (
                    RawHeaders(
                        [
                            ("Content-Type", "application/json"),
                            ("Content-Encoding", "identity"),
                            ("content-encoding", "identity"),
                        ]
                    ),
                    RawHeaders(
                        [
                            ("Content-Type", "application/json"),
                            ("Content-Encoding", "Identity"),
                        ]
                    ),
                    RawHeaders(
                        [
                            ("Content-Type", "application/json"),
                            ("Content-Encoding", "identity; q=1"),
                        ]
                    ),
                    RawHeaders(
                        [
                            ("Content-Type", "application/json"),
                            ("Content-Encoding", "gzip"),
                        ]
                    ),
                ):
                    encoded_response = flow(
                        "GET",
                        "https://demo-upstream:8443/encoded",
                        response={"must": "remain buffered"},
                    )
                    encoded_response.response.status_code = status_code
                    encoded_response.response.headers = response_headers
                    encoded_response.metadata.update(
                        {
                            "serverware_route": SimpleNamespace(
                                id=f"encoding.{adapter_type}.{status_code}",
                                adapter_type=adapter_type,
                                adapter_config={},
                                constraints=[],
                                credential_ref=None,
                            ),
                            "serverware_route_id": (
                                f"encoding.{adapter_type}.{status_code}"
                            ),
                            "serverware_params": {},
                        }
                    )
                    original_encoded_body = (
                        encoded_response.response.raw_content
                    )
                    decision = policy_engine.prepare_response(
                        encoded_response
                    )
                    assert_denied(
                        decision, "response_content_encoding_denied"
                    )
                    assert (
                        encoded_response.response.raw_content
                        == original_encoded_body
                    )
        finally:
            policy_engine.get_adapter = original_response_adapter_lookup

        audit_calls = []
        original_log_request = runtime.log_request
        runtime.log_request = lambda *args, **kwargs: audit_calls.append((args, kwargs))
        try:
            from serverware import mitm_addon

            lifecycle_order: list[str] = []
            lifecycle_response = guarded_response(
                "prototype-lifecycle-secret",
                {"ok": True},
            )
            lifecycle_response.metadata.update(
                {
                    "serverware_release_authorization": {
                        "attempt_id": "attempt:response-completion",
                        "flow_id": "attempt:response-completion",
                        "binding_digest": "sha256:" + "7" * 64,
                        "state": "dispatching",
                        "dispatch_attempted": True,
                    },
                    "serverware_release_attempt_id": "attempt:response-completion",
                    "serverware_release_binding_digest": "sha256:" + "7" * 64,
                    "serverware_release_state": "dispatching",
                }
            )
            original_complete_release = runtime.complete_release_authorization
            original_validate_complete_release = (
                runtime.validate_complete_release_authorization_response
            )
            original_addon_evaluate_response = mitm_addon.evaluate_response

            def complete_forwarded(**kwargs):
                lifecycle_order.append("complete:forwarded")
                return {
                    "authorized": True,
                    "state": "committed",
                    "attempt_id": kwargs["attempt_id"],
                    "binding_digest": kwargs["binding_digest"],
                    "completion_outcome": kwargs["outcome"],
                    "quotas": [],
                }

            def observe_response_policy(item):
                lifecycle_order.append("response_policy")
                return original_addon_evaluate_response(item)

            runtime.complete_release_authorization = complete_forwarded
            runtime.validate_complete_release_authorization_response = (
                lambda response, **_kwargs: response
            )
            mitm_addon.evaluate_response = observe_response_policy
            try:
                ServerwareAddon().response(lifecycle_response)
            finally:
                mitm_addon.evaluate_response = original_addon_evaluate_response
                runtime.validate_complete_release_authorization_response = (
                    original_validate_complete_release
                )
                runtime.complete_release_authorization = original_complete_release
            assert lifecycle_order == ["response_policy", "complete:forwarded"], lifecycle_order
            assert lifecycle_response.metadata["serverware_release_state"] == "committed"
            lifecycle_actions = [call[0][3] for call in audit_calls]
            assert lifecycle_actions[-2:] == [
                "response_validated",
                "response_release_authorized",
            ], lifecycle_actions

            ordinary_body_flow = guarded_response(
                "ordinary-staged-body-secret",
                {"ok": True},
            )
            assert evaluate_response(ordinary_body_flow).allowed
            ordinary_body_flow.response.raw_content = b'{"ok":false}'
            assert_denied(
                policy_engine.validate_response_completion(
                    ordinary_body_flow
                ),
                "response_changed_after_validation",
            )

            durable_order: list[str] = []
            original_complete_durable = (
                runtime.complete_durable_policy_state
            )
            original_fail_durable = runtime.fail_durable_policy_state
            original_policy_adapter_lookup = policy_engine.get_adapter

            class DurableOrderingAdapter:
                def __init__(self, finalizer):
                    self._finalizer = finalizer

                def validate_response(self, *_args, **_kwargs):
                    return SimpleNamespace(
                        allowed=True,
                        reason=None,
                        status_code=200,
                        payload={},
                    )

                def finalize_response(self, item, *_args, **_kwargs):
                    durable_order.append("finalizer")
                    return self._finalizer(item)

            def durable_flow(secret: str, state: str = "dispatched"):
                item = guarded_response(secret, {"ok": True})
                dispatch_deadline = int(time.time() * 1000) + 30_000
                reservation = {
                    "state": state,
                    "attempt_id": "attempt:durable-order",
                    "claim_digest": "sha256:" + "8" * 64,
                    "reservation_id": "sha256:" + "9" * 64,
                    "dispatch_deadline_at_epoch_ms": dispatch_deadline,
                }
                item.metadata.update(
                    {
                        "serverware_durable_policy_claims": [],
                        "serverware_durable_policy_reservation": reservation,
                        "serverware_release_authorization": {
                            "state": "dispatching",
                            "dispatch_expires_at_epoch_ms": (
                                dispatch_deadline
                            ),
                            "durable_policy": copy.deepcopy(reservation),
                        },
                    }
                )
                return item

            def reject_split_durable_transition(*_args, **_kwargs):
                raise AssertionError(
                    "response path used a split durable policy transition"
                )

            runtime.complete_durable_policy_state = (
                reject_split_durable_transition
            )
            runtime.fail_durable_policy_state = (
                reject_split_durable_transition
            )
            try:
                policy_engine.get_adapter = lambda _adapter_type: (
                    DurableOrderingAdapter(
                        lambda _item: SimpleNamespace(
                            allowed=True,
                            reason=None,
                            status_code=200,
                            payload={},
                        )
                    )
                )
                durable_success_flow = durable_flow(
                    "durable-order-success-secret"
                )
                assert evaluate_response(durable_success_flow).allowed
                assert durable_order == ["finalizer"]
                staged_success = durable_success_flow.metadata[
                    "serverware_durable_policy_completion"
                ]
                assert staged_success["outcome"] == "forwarded"
                assert staged_success["response_body_sha256"] == (
                    "sha256:"
                    + hashlib.sha256(
                        durable_success_flow.response.raw_content
                    ).hexdigest()
                )
                durable_success_flow.metadata[
                    "serverware_durable_policy_reservation"
                ]["state"] = "committed"
                assert policy_engine.validate_response_completion(
                    durable_success_flow
                ).allowed

                durable_order.clear()

                indeterminate_flow = durable_flow(
                    "durable-order-indeterminate-secret"
                )
                assert evaluate_response(indeterminate_flow).allowed
                indeterminate_flow.metadata[
                    "serverware_durable_policy_reservation"
                ]["state"] = "indeterminate"
                indeterminate_decision = (
                    policy_engine.validate_response_completion(
                        indeterminate_flow
                    )
                )
                assert_denied(
                    indeterminate_decision,
                    "durable_policy_response_indeterminate",
                )
                assert durable_order == ["finalizer"]

                durable_order.clear()
                reflected_secret = "durable-order-reflection-secret"

                def reflect_in_finalizer(item):
                    item.response.raw_content = json.dumps(
                        {"echo": reflected_secret}
                    ).encode("utf-8")
                    return SimpleNamespace(
                        allowed=True,
                        reason=None,
                        status_code=200,
                        payload={},
                    )

                policy_engine.get_adapter = lambda _adapter_type: (
                    DurableOrderingAdapter(reflect_in_finalizer)
                )
                reflected_durable_flow = durable_flow(reflected_secret)
                assert_denied(
                    evaluate_response(reflected_durable_flow),
                    "response_credential_reflection",
                )
                assert durable_order == ["finalizer"]
                assert (
                    reflected_durable_flow.metadata[
                        "serverware_durable_policy_completion"
                    ]["outcome"]
                    == "unknown"
                )

                durable_order.clear()
                policy_engine.get_adapter = lambda _adapter_type: (
                    DurableOrderingAdapter(
                        lambda _item: SimpleNamespace(
                            allowed=False,
                            reason="forced finalizer denial",
                            status_code=502,
                            payload={"error": "forced_finalizer_denial"},
                        )
                    )
                )
                finalizer_denial_flow = durable_flow(
                    "durable-order-finalizer-secret"
                )
                assert_denied(
                    evaluate_response(finalizer_denial_flow),
                    "forced_finalizer_denial",
                )
                assert durable_order == ["finalizer"]
                assert (
                    finalizer_denial_flow.metadata[
                        "serverware_durable_policy_completion"
                    ]["outcome"]
                    == "unknown"
                )

                durable_order.clear()
                staged_body_flow = durable_flow(
                    "durable-staged-body-secret",
                )

                def mutate_before_staging(item):
                    item.response.raw_content = b'{"ok":false}'
                    return SimpleNamespace(
                        allowed=True,
                        reason=None,
                        status_code=200,
                        payload={},
                    )

                policy_engine.get_adapter = lambda _adapter_type: (
                    DurableOrderingAdapter(mutate_before_staging)
                )
                assert evaluate_response(staged_body_flow).allowed
                staged_body_digest = staged_body_flow.metadata[
                    "serverware_durable_policy_completion"
                ]["response_body_sha256"]
                assert staged_body_digest == (
                    "sha256:" + hashlib.sha256(b'{"ok":false}').hexdigest()
                )
                staged_body_flow.metadata[
                    "serverware_durable_policy_reservation"
                ]["state"] = "committed"
                staged_body_flow.response.raw_content = b'{"ok":"changed"}'
                assert_denied(
                    policy_engine.validate_response_completion(
                        staged_body_flow
                    ),
                    "response_changed_after_validation",
                )
                assert durable_order == ["finalizer"]

                durable_order.clear()

                class PrepareDenialAdapter:
                    def prepare_response(self, *_args, **_kwargs):
                        return SimpleNamespace(
                            allowed=False,
                            reason="forced response preparation denial",
                            status_code=502,
                            payload={
                                "error": "forced_prepare_response_denial"
                            },
                        )

                policy_engine.get_adapter = lambda _adapter_type: (
                    PrepareDenialAdapter()
                )
                prepare_denial_flow = durable_flow(
                    "durable-prepare-denial-secret"
                )
                assert_denied(
                    policy_engine.prepare_response(prepare_denial_flow),
                    "forced_prepare_response_denial",
                )
                assert durable_order == []
                assert (
                    prepare_denial_flow.metadata[
                        "serverware_durable_policy_completion"
                    ]["outcome"]
                    == "unknown"
                )

                durable_order.clear()
                original_internal_evaluate_response = (
                    policy_engine._evaluate_response
                )
                policy_engine._evaluate_response = (
                    lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        RuntimeError("forced internal response exception")
                    )
                )
                try:
                    evaluator_failure_flow = durable_flow(
                        "durable-evaluator-exception-secret"
                    )
                    assert_denied(
                        evaluate_response(evaluator_failure_flow),
                        "response_evaluation_failed_closed",
                    )
                finally:
                    policy_engine._evaluate_response = (
                        original_internal_evaluate_response
                    )
                assert durable_order == []
                assert (
                    evaluator_failure_flow.metadata[
                        "serverware_durable_policy_completion"
                    ]["outcome"]
                    == "unknown"
                )

                durable_order.clear()
                original_runtime_release_completion = (
                    runtime.complete_release_authorization
                )

                def release_completion_failure(**_kwargs):
                    raise runtime.ReleaseAuthorizationClientError(
                        "forced release completion failure"
                    )

                runtime.complete_release_authorization = (
                    release_completion_failure
                )
                release_cleanup_flow = durable_flow(
                    "durable-release-cleanup-secret"
                )
                release_cleanup_flow.metadata[
                    "serverware_release_authorization"
                ] = {
                    "attempt_id": "attempt:durable-order",
                    "binding_digest": "sha256:" + "7" * 64,
                    "state": "dispatching",
                    "dispatch_attempted": True,
                    "durable_policy": copy.deepcopy(
                        release_cleanup_flow.metadata[
                            "serverware_durable_policy_reservation"
                        ]
                    ),
                }
                try:
                    release_cleanup_decision = (
                        policy_engine.complete_release_authorization_for_error(
                            release_cleanup_flow
                        )
                    )
                finally:
                    runtime.complete_release_authorization = (
                        original_runtime_release_completion
                    )
                assert_denied(
                    release_cleanup_decision,
                    "release_authorization_completion_uncertain",
                )
                assert durable_order == []
                assert (
                    release_cleanup_flow.metadata[
                        "serverware_durable_policy_reservation"
                    ]["state"]
                    == "dispatched"
                )
                assert (
                    release_cleanup_flow.metadata[
                        "serverware_durable_policy_completion"
                    ]["outcome"]
                    == "unknown"
                )

                durable_cleanup_attempts = []

                def fail_durable_cleanup(*_args, **_kwargs):
                    durable_cleanup_attempts.append("fail")
                    raise runtime.DurablePolicyStateError(
                        "forced durable cleanup failure"
                    )

                runtime.fail_durable_policy_state = fail_durable_cleanup
                runtime.complete_release_authorization = (
                    release_completion_failure
                )
                combined_cleanup_flow = durable_flow(
                    "durable-combined-cleanup-secret"
                )
                combined_cleanup_flow.metadata[
                    "serverware_release_authorization"
                ] = {
                    "attempt_id": "attempt:durable-order",
                    "binding_digest": "sha256:" + "7" * 64,
                    "state": "dispatching",
                    "dispatch_attempted": True,
                    "durable_policy": copy.deepcopy(
                        combined_cleanup_flow.metadata[
                            "serverware_durable_policy_reservation"
                        ]
                    ),
                }
                try:
                    combined_cleanup = (
                        policy_engine.complete_release_authorization_for_error(
                            combined_cleanup_flow
                        )
                    )
                finally:
                    runtime.complete_release_authorization = (
                        original_runtime_release_completion
                    )
                    runtime.fail_durable_policy_state = (
                        reject_split_durable_transition
                    )
                assert_denied(
                    combined_cleanup,
                    "release_authorization_completion_uncertain",
                )
                assert durable_cleanup_attempts == []
            finally:
                policy_engine.get_adapter = original_policy_adapter_lookup
                runtime.complete_durable_policy_state = (
                    original_complete_durable
                )
                runtime.fail_durable_policy_state = original_fail_durable

            evaluator_secret = "prototype-evaluator-failure-secret-6bf4"
            evaluator_failure = guarded_response(
                evaluator_secret,
                {"echo": evaluator_secret},
            )
            original_evaluator_response = evaluator_failure.response
            mitm_addon.evaluate_response = lambda _item: (_ for _ in ()).throw(
                RuntimeError("forced response evaluator failure")
            )
            try:
                ServerwareAddon().response(evaluator_failure)
            finally:
                mitm_addon.evaluate_response = original_addon_evaluate_response
            assert evaluator_failure.response is not original_evaluator_response
            assert evaluator_failure.metadata["serverware_blocked_response"] is True
            assert evaluator_failure.response.status_code == 503
            assert json.loads(evaluator_failure.response.get_text()) == {
                "error": "response_hook_failed_closed"
            }
            assert evaluator_secret not in evaluator_failure.response.get_text()

            escaped_secret = 'prototype-"credential /? value'
            reflected = guarded_response(escaped_secret, {"echo": escaped_secret})
            reflected_decision = evaluate_response(reflected)
            assert_denied(reflected_decision, "response_credential_reflection")
            assert reflected_decision.reason == "response credential reflection denied"
            assert escaped_secret not in repr(audit_calls)
            assert not hasattr(reflected, "_serverware_response_credential_guard")

            addon_secret = "prototype-addon-reflection-83e1"
            addon_reflection = guarded_response(addon_secret, {"echo": addon_secret})
            ServerwareAddon().response(addon_reflection)
            assert addon_reflection.response.status_code == 502
            addon_payload = json.loads(addon_reflection.response.get_text())
            assert addon_payload == {"error": "response_credential_reflection"}, addon_payload
            assert addon_secret not in addon_reflection.response.get_text()
            assert addon_secret not in repr(audit_calls)

            basic_secret = "prototype-basic-password-9f4b"
            basic_reflection = guarded_response(
                basic_secret,
                {"ok": True},
                {"type": "basic", "username": "prototype-user"},
            )
            basic_reflection.response.headers["x-upstream-authorization"] = basic_reflection.request.headers["Authorization"]
            assert evaluate_response(basic_reflection).allowed
            assert "x-upstream-authorization" not in {
                name.lower() for name in basic_reflection.response.headers
            }
            assert basic_secret not in repr(audit_calls)

            hash_secret = "prototype-hash-reflection-7d2c"
            hash_reflection = guarded_response(
                hash_secret,
                {
                    "authorization_sha256": "sha256:"
                    + hashlib.sha256(f"Bearer {hash_secret}".encode("utf-8")).hexdigest()
                },
            )
            assert_denied(evaluate_response(hash_reflection), "response_credential_reflection")
            assert hash_secret not in repr(audit_calls)

            exact_secret = "exact-credential-value-123"
            near_match = guarded_response(exact_secret, {"echo": "exact-credential-value-124"})
            assert evaluate_response(near_match).allowed

            redacted_route = SimpleNamespace(
                id="response.credential.guard.redacted",
                adapter_type="generic.rest",
                adapter_config={
                    "response": {
                        "mode": "json",
                        "maxBodyBytes": 4096,
                        "allowedFields": ["safe"],
                    }
                },
                constraints=[
                    {
                        "id": "hidden-provider-status",
                        "type": "responseJson",
                        "phase": "response",
                        "fields": {"provider_status": {"type": "string", "enum": ["ok"]}},
                    }
                ],
                credential_ref=guard_route.credential_ref,
            )
            malformed_hidden = guarded_response(
                exact_secret,
                {"safe": "released", "provider_status": "corrupt"},
            )
            malformed_hidden.metadata["serverware_route"] = redacted_route
            malformed_hidden.metadata["serverware_route_id"] = redacted_route.id
            assert_denied(evaluate_response(malformed_hidden), "response_json_field_enum_denied")

            redacted = guarded_response(
                exact_secret,
                {"safe": "released", "leak": exact_secret, "provider_status": "ok"},
            )
            redacted.metadata["serverware_route"] = redacted_route
            redacted.metadata["serverware_route_id"] = redacted_route.id
            assert evaluate_response(redacted).allowed
            assert exact_secret.encode("utf-8") not in redacted.response.raw_content
            assert json.loads(redacted.response.raw_content) == {"safe": "released"}
        finally:
            runtime.log_request = original_log_request

    source_only_policy_model_fixtures(validate_schema)
    print(f"credential constraint tests passed; schema_validation={validate_schema}")


def source_only_policy_model_fixtures(validate_schema: bool) -> None:
    base = demo_policy_bundle("cred-demo-bearer")

    unknown_adapter = copy.deepcopy(base)
    unknown_adapter["routes"][0]["adapter"]["type"] = "unknown.adapter"
    assert_policy_rejected(
        unknown_adapter,
        "compiler accepted an unknown conditional adapter",
        validate_schema=validate_schema,
    )

    unknown_nested_field = copy.deepcopy(base)
    unknown_nested_field["routes"][0]["adapter"]["config"]["request"][
        "unattestedOption"
    ] = True
    assert_policy_rejected(
        unknown_nested_field,
        "compiler accepted an unknown nested adapter field",
        validate_schema=validate_schema,
    )

    open_generic_profile = copy.deepcopy(base)
    open_generic_profile["routes"][0]["adapter"]["config"]["response"][
        "mode"
    ] = "any"
    assert_policy_rejected(
        open_generic_profile,
        "compiler accepted an opaque credential-bearing generic response",
        validate_schema=validate_schema,
    )

    alternate_x_search = copy.deepcopy(base)
    broad_x = next(
        route
        for route in alternate_x_search["routes"]
        if route["id"] == "demo.x.readonly"
    )
    broad_x["adapter"]["config"]["allowedReadOperations"].append(
        "search.read"
    )
    next(
        constraint
        for constraint in broad_x["constraints"]
        if constraint["type"] == "operationPolicy"
    )["allowedOperations"].append("search.read")
    assert_policy_rejected(
        alternate_x_search,
        "compiler accepted an older X search alternate-route bypass",
        validate_schema=validate_schema,
    )

    oauth_client_mismatch = copy.deepcopy(base)
    gmail_route = next(
        route
        for route in oauth_client_mismatch["routes"]
        if route["id"] == "demo.gmail.recent"
    )
    gmail_route["adapter"]["config"]["credentialBinding"]["clientIds"] = [
        "other-client"
    ]
    assert_policy_rejected(
        oauth_client_mismatch,
        "compiler accepted an OAuth client binding mismatch",
        validate_schema=validate_schema,
    )

    expanded_oauth_clients = copy.deepcopy(base)
    expanded_gmail_route = next(
        route
        for route in expanded_oauth_clients["routes"]
        if route["id"] == "demo.gmail.recent"
    )
    expanded_gmail_route["adapter"]["config"]["credentialBinding"][
        "clientIds"
    ].append("other-client")
    assert_policy_rejected(
        expanded_oauth_clients,
        "compiler accepted an extra OAuth client in an exact route binding",
        validate_schema=validate_schema,
    )

    expanded_credential_subjects = copy.deepcopy(base)
    expanded_subject_route = next(
        route
        for route in expanded_credential_subjects["routes"]
        if route["id"] == "demo.gmail.recent"
    )
    expanded_subject_route["adapter"]["config"]["credentialBinding"][
        "subjects"
    ].append("other-subject")
    assert_policy_rejected(
        expanded_credential_subjects,
        "compiler accepted an extra subject in an exact route binding",
        validate_schema=validate_schema,
    )

    typed_request_values = copy.deepcopy(base)
    typed_request = typed_request_values["routes"][0]["adapter"]["config"][
        "request"
    ]
    typed_request["valueRules"] = [
        {
            "source": "query",
            "name": "reflectCredential",
            "predicate": {"kind": "enum", "values": ["0", "1"]},
        },
        {
            "source": "header",
            "name": "accept",
            "predicate": {
                "kind": "equals",
                "value": "application/json",
            },
        },
        {
            "source": "jsonBody",
            "name": "audit_marker",
            "predicate": {
                "kind": "stringLength",
                "minLength": 1,
                "maxLength": 256,
            },
        },
        {
            "source": "operationField",
            "name": "operation",
            "predicate": {"kind": "equals", "value": "demo.echo"},
        },
    ]
    compile_policy_bundle(
        typed_request_values,
        validate_schema=validate_schema,
    )

    vacuous_response_proof = copy.deepcopy(base)
    vacuous_response_proof["routes"][0]["constraints"].append(
        {
            "id": "empty-response-proof",
            "type": "responseJson",
            "phase": "response",
            "fields": {},
        }
    )
    assert_policy_rejected(
        vacuous_response_proof,
        "compiler accepted a vacuous response JSON proof",
        validate_schema=validate_schema,
    )

    noncanonical_cidr = copy.deepcopy(base)
    noncanonical_cidr["principals"][0]["sourceCidrs"] = [
        "10.0.0.1/8"
    ]
    assert_policy_rejected(
        noncanonical_cidr,
        "compiler accepted a CIDR with host bits",
        validate_schema=validate_schema,
    )

    issuer_only_mtls = copy.deepcopy(base)
    issuer_only_mtls["principals"][0].pop("sourceCidrs", None)
    issuer_only_mtls["principals"][0]["mtls"] = {
        "verifiedByTrustedIngress": True,
        "issuerSpkiSha256": "sha256:" + "1" * 64,
    }
    assert_policy_rejected(
        issuer_only_mtls,
        "compiler accepted issuer-only mTLS identity",
        validate_schema=validate_schema,
    )
    mtls_snapshot = compile_policy_bundle(
        examples, validate_schema=validate_schema
    )
    mtls_flow = flow("GET", "https://example.test/")
    mtls_flow.client_conn.peername = ("10.1.2.3", 443)
    mtls_flow.client_conn.serverware_mtls_verified = True
    mtls_flow.client_conn.serverware_mtls_evidence = {
        "san_spiffe_ids": [
            "spiffe://agents.example.test/agent/example"
        ],
        "san_dns_names": ["example-agent.agents.example.test"],
        "san_uris": ["urn:serverware:agent:example"],
        "certificate_sha256": (
            "sha256:"
            "c2a5140ef6d8a3bc5472798f00b4bd22d33826d0a7d17724e68a4bb86b87c21f"
        ),
        "spki_sha256": (
            "sha256:"
            "1f4d8c8b7a3e90d2c6f547ab16a0be23447b7bb192332eec9b3f76c93ad283fe"
        ),
        "issuer_spki_sha256": (
            "sha256:"
            "5bcf9e3428ea16b49a96a2e8d2ecf2d6557a39219db2b8b53ca99c8f55d844e1"
        ),
    }
    verified_mtls = _verified_mtls_evidence(mtls_flow)
    assert verified_mtls is not None
    assert (
        mtls_snapshot.identify_principal(
            "10.1.2.3",
            RawHeaders([("X-Serverware-Agent", "example-agent-mtls")]),
            verified_mtls,
        ).id
        == "agent:example-mtls"
    )
    mismatched_mtls = dict(mtls_flow.client_conn.serverware_mtls_evidence)
    mismatched_mtls["spki_sha256"] = "sha256:" + "0" * 64
    mtls_flow.client_conn.serverware_mtls_evidence = mismatched_mtls
    assert mtls_snapshot.identify_principal(
        "10.1.2.3",
        RawHeaders([("X-Serverware-Agent", "example-agent-mtls")]),
        _verified_mtls_evidence(mtls_flow),
    ) is None
    contradictory_mtls = dict(mismatched_mtls)
    contradictory_mtls["san_spiffe_ids"] = [
        "spiffe://agents.example.test/agent/example",
        "spiffe://agents.example.test/agent/example",
    ]
    mtls_flow.client_conn.serverware_mtls_evidence = contradictory_mtls
    assert _verified_mtls_evidence(mtls_flow) is None

    contradictory_alias_decision = _credential_policy_binding_decision(
        SimpleNamespace(
            adapter_type="x.v2",
            adapter_config={
                "credentialBinding": {
                    "credentialType": "oauth2",
                    "provider": "x",
                    "subjects": ["x-subject"],
                    "clientIds": ["x-client"],
                    "requiredScopes": [
                        "tweet.read",
                        "users.read",
                    ],
                }
            },
        ),
        CredentialPolicy(
            id="cred-alias-conflict",
            kind="oauth2",
            provider="x",
            provider_subject="x-subject",
            oauth_client_id="x-client",
            scopes=("tweet.read", "users.read"),
        ),
        {
            "kind": "oauth2",
            "metadata": {
                "oauth": True,
                "provider_identity_verified": True,
                "provider_id": "x",
                "provider_subject": "x-subject",
                "oauth_client_id": "x-client",
                "x_app_id": "different-client",
                "scopes": ["tweet.read", "users.read"],
            },
        },
        "search.read",
    )
    assert (
        contradictory_alias_decision is not None
        and not contradictory_alias_decision.allowed
    )

    contradictory_subject_decision = _credential_policy_binding_decision(
        SimpleNamespace(
            adapter_type="x.v2",
            adapter_config={
                "appIds": ["x-client"],
                "credentialBinding": {
                    "credentialType": "oauth2",
                    "provider": "x",
                    "subjects": ["x-subject"],
                    "clientIds": ["x-client"],
                    "requiredScopes": ["tweet.read", "users.read"],
                },
            },
        ),
        CredentialPolicy(
            id="cred-subject-conflict",
            kind="oauth2",
            provider="x",
            provider_subject="x-subject",
            oauth_client_id="x-client",
            scopes=("tweet.read", "users.read"),
            injection={
                "type": "bearer",
                "header": "Authorization",
                "field": "access_token",
                "prefix": "Bearer ",
            },
        ),
        {
            "kind": "oauth2",
            "metadata": {
                "oauth": True,
                "provider_identity_verified": True,
                "provider_id": "x",
                "provider_subject": "x-subject",
                "account_subject": "different-subject",
                "oauth_client_id": "x-client",
                "scopes": ["tweet.read", "users.read"],
            },
        },
        "search.read",
    )
    assert (
        contradictory_subject_decision is not None
        and not contradictory_subject_decision.allowed
        and contradictory_subject_decision.payload.get("binding")
        == "credentialAliases"
    )

    exact_x_route = SimpleNamespace(
        adapter_type="x.v2",
        adapter_config={
            "appIds": ["x-client"],
            "credentialBinding": {
                "credentialType": "oauth2",
                "provider": "x",
                "subjects": ["x-subject"],
                "clientIds": ["x-client"],
                "requiredScopes": ["tweet.read", "users.read"],
            },
        },
    )
    exact_x_policy = CredentialPolicy(
        id="cred-exact-x",
        kind="oauth2",
        provider="x",
        provider_subject="x-subject",
        oauth_client_id="x-client",
        scopes=("tweet.read", "users.read"),
        injection={
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
            "prefix": "Bearer ",
        },
    )
    exact_x_credential = {
        "kind": "oauth2",
        "metadata": {
            "oauth": True,
            "provider_identity_verified": True,
            "provider_id": "x",
            "provider_subject": "x-subject",
            "oauth_client_id": "x-client",
            "scopes": ["tweet.read", "users.read"],
        },
    }
    if (
        _credential_policy_binding_decision(
            exact_x_route,
            exact_x_policy,
            exact_x_credential,
            "search.read",
        )
        is not None
    ):
        raise AssertionError("exact X credential binding was rejected")
    expanded_x_route = SimpleNamespace(
        adapter_type="x.v2",
        adapter_config={
            **exact_x_route.adapter_config,
            "credentialBinding": {
                **exact_x_route.adapter_config["credentialBinding"],
                "clientIds": ["x-client", "other-client"],
            },
        },
    )
    expanded_x_decision = _credential_policy_binding_decision(
        expanded_x_route,
        exact_x_policy,
        exact_x_credential,
        "search.read",
    )
    assert expanded_x_decision is not None and not expanded_x_decision.allowed

    exact_static_route = SimpleNamespace(
        adapter_type="generic.json",
        adapter_config={
            "credentialBinding": {
                "credentialType": "static",
                "provider": "npm",
                "subjects": ["npm-subject"],
                "secretClass": "automationToken",
            }
        },
    )
    exact_static_policy = CredentialPolicy(
        id="cred-exact-static",
        kind="static",
        provider="npm",
        provider_subject="npm-subject",
        scopes=("package.publish",),
        injection={"type": "bearer"},
    )
    exact_static_credential = {
        "kind": "bearer",
        "metadata": {
            "provider": "npm",
            "provider_subject": "npm-subject",
            "secret_class": "automationToken",
            "scopes": ["package.publish"],
        },
    }
    if (
        _credential_policy_binding_decision(
            exact_static_route,
            exact_static_policy,
            exact_static_credential,
            "package.publish",
        )
        is not None
    ):
        raise AssertionError("exact static credential binding was rejected")
    wrong_static_injection = {
        **exact_static_credential,
        "kind": "header",
    }
    static_injection_decision = _credential_policy_binding_decision(
        exact_static_route,
        exact_static_policy,
        wrong_static_injection,
        "package.publish",
    )
    assert (
        static_injection_decision is not None
        and not static_injection_decision.allowed
        and static_injection_decision.payload.get("binding") == "injectionType"
    )

    duplicate_header_flow = flow("GET", "https://example.test/")
    duplicate_header_flow.metadata["serverware_operation"] = {
        "operation": "example.read"
    }
    duplicate_header_flow.response = mitm_http.Response.make(
        200, b"{}", {"Content-Type": "application/json"}
    )
    duplicate_header_flow.response.headers = RawHeaders(
        [
            ("Content-Type", "application/json"),
            ("ETag", '"same"'),
            ("ETag", '"same"'),
        ]
    )
    duplicate_header_flow.response.data.headers = (
        duplicate_header_flow.response.headers
    )
    duplicate_header_decision = _evaluate_response_envelope(
        duplicate_header_flow,
        SimpleNamespace(
            constraints=(
                {
                    "id": "single-etag",
                    "type": "responseEnvelope",
                    "operations": ["example.read"],
                    "statusCodes": [200],
                    "bodyPresence": "required",
                    "contentTypes": ["application/json"],
                    "allowedResponseHeaderNames": ["etag"],
                    "responseHeaderRules": [
                        {
                            "name": "etag",
                            "required": False,
                            "predicate": {
                                "kind": "equals",
                                "value": '"same"',
                            },
                        }
                    ],
                },
            )
        ),
    )
    assert not duplicate_header_decision.allowed
    assert duplicate_header_decision.payload == {
        "error": "response_envelope_header_evidence_invalid",
        "headers": ["etag"],
    }

    for transport_name, transport_value in (
        ("Content-Length", "2"),
        ("Transfer-Encoding", "chunked"),
        ("Connection", "keep-alive"),
        ("Trailer", "x-checksum"),
    ):
        duplicate_transport_flow = flow("GET", "https://example.test/")
        duplicate_transport_flow.metadata["serverware_operation"] = {
            "operation": "example.read"
        }
        duplicate_transport_flow.response = mitm_http.Response.make(
            200, b"{}", {"Content-Type": "application/json"}
        )
        duplicate_transport_flow.response.headers = RawHeaders(
            [
                ("Content-Type", "application/json"),
                (transport_name, transport_value),
                (transport_name.lower(), transport_value),
            ]
        )
        duplicate_transport_flow.response.data.headers = (
            duplicate_transport_flow.response.headers
        )
        duplicate_transport_decision = _evaluate_response_envelope(
            duplicate_transport_flow,
            SimpleNamespace(
                constraints=(
                    {
                        "id": "duplicate-transport-header",
                        "type": "responseEnvelope",
                        "operations": ["example.read"],
                        "statusCodes": [200],
                        "bodyPresence": "required",
                        "contentTypes": ["application/json"],
                        "allowedResponseHeaderNames": [],
                        "responseHeaderRules": [],
                    },
                )
            ),
        )
        assert not duplicate_transport_decision.allowed
        assert duplicate_transport_decision.payload == {
            "error": "response_envelope_header_evidence_invalid",
            "headers": [transport_name.lower()],
        }

    x_pagination_bypass = copy.deepcopy(base)
    recent_search_route = next(
        route
        for route in x_pagination_bypass["routes"]
        if route["id"] == "demo.x.search.recent"
    )
    recent_search_route["adapter"]["config"]["request"][
        "allowedQueryKeys"
    ].append("pagination_token")
    recent_search_route["adapter"]["config"]["request"][
        "allowedQueryKeys"
    ].sort()
    assert_policy_rejected(
        x_pagination_bypass,
        "compiler accepted pagination_token as an alternate recent-search cursor",
        validate_schema=validate_schema,
    )

    universal_header = copy.deepcopy(base)
    universal_header["principals"][0]["sourceCidrs"] = [
        "0.0.0.0/0",
        "::/0",
    ]
    assert_policy_rejected(
        universal_header,
        "compiler accepted requiredHeaders anchored only by universal CIDRs",
        validate_schema=validate_schema,
    )

    unrestricted_bearer_header = copy.deepcopy(universal_header)
    unrestricted_bearer_header["principals"][0][
        "proxyAuthorization"
    ] = {
        "scheme": "Bearer",
        "tokenId": "unrestricted-fixture",
        "tokenSha256": "sha256:" + "2" * 64,
        "sourceCidrs": ["0.0.0.0/0", "::/0"],
        "expiresAtEpochMs": 4102444800000,
    }
    assert_policy_rejected(
        unrestricted_bearer_header,
        "compiler accepted an unrestricted bearer as a trusted-header anchor",
        validate_schema=validate_schema,
    )

    legacy_bearer_header = copy.deepcopy(universal_header)
    legacy_bearer_header["principals"][0][
        "proxyAuthorization"
    ] = "Bearer legacy-is-not-a-source-anchor"
    assert_policy_rejected(
        legacy_bearer_header,
        "compiler accepted a legacy bearer as a trusted-header anchor",
        validate_schema=validate_schema,
    )

    source_bound_bearer_header = copy.deepcopy(universal_header)
    source_bound_bearer_header["principals"][0][
        "proxyAuthorization"
    ] = {
        "scheme": "Bearer",
        "tokenId": "source-bound-fixture",
        "tokenSha256": "sha256:" + "3" * 64,
        "sourceCidrs": ["10.0.0.0/8", "127.0.0.0/8"],
        "expiresAtEpochMs": 4102444800000,
    }
    compile_policy_bundle(
        source_bound_bearer_header,
        validate_schema=validate_schema,
    )

    durable = copy.deepcopy(base)
    durable_route = durable["routes"][0]
    durable_request = durable_route["adapter"]["config"]["request"]
    durable_request["allowedQueryKeys"].extend(
        ["cost", "cursor", "query"]
    )
    durable_request["valueRules"] = [
        {
            "source": "query",
            "name": "cost",
            "capture": "requestCost",
            "predicate": {
                "kind": "numeric",
                "min": 1,
                "max": 1000,
                "integer": True,
            },
        }
    ]
    durable_route["adapter"]["config"]["response"]["allowedFields"].extend(
        ["records", "meta.next"]
    )
    durable_route["constraints"].extend(
        [
            {
                "id": "sliding-operations",
                "type": "slidingWindowLimit",
                "store": "shared",
                "max": 100,
                "windowSeconds": 60,
                "windowSemantics": "sliding",
                "measure": "operationCount",
                "reservationMode": "atomicReserveCommitRelease",
                "onOverflow": "deny",
                "key": {
                    "scope": [
                        "principal",
                        "credential",
                        "credentialVersion",
                        "route",
                    ]
                },
            },
            {
                "id": "weighted-cost",
                "type": "weightedBudget",
                "store": "shared",
                "max": 1000,
                "windowSeconds": 3600,
                "windowSemantics": "sliding",
                "measure": "weightedCanonicalInteger",
                "reservationMode": "atomicReserveCommitRelease",
                "onOverflow": "deny",
                "key": {
                    "scope": [
                        "principal",
                        "credential",
                        "credentialVersion",
                        "route",
                    ]
                },
                "weight": {
                    "source": "requestValue",
                    "field": "requestCost",
                    "representation": "canonicalNonNegativeInteger",
                    "unit": "cost",
                    "minimumPerOperation": 1,
                    "maximumPerOperation": 1000,
                },
            },
            {
                "id": "bounded-traversal",
                "type": "traversalBudget",
                "operations": ["demo.echo"],
                "traversal": {
                    "store": "shared",
                    "phases": ["request", "response"],
                    "cursor": {
                        "requestSource": "query",
                        "requestField": "cursor",
                        "responseField": "meta.next",
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
                        "queryFields": [
                            "cost",
                            "query",
                            "reflectCredential",
                        ],
                        "queryDigest": "sha256",
                    },
                    "limits": {
                        "maxPages": 5,
                        "maxLifetimeSeconds": 300,
                        "maxRecords": 500,
                        "maxDecodedBytes": 1048576,
                    },
                    "accounting": {
                        "recordCountField": "records",
                        "byteSource": "validatedDecodedResponseBytes",
                        "commit": "atomicAfterResponseValidation",
                    },
                    "onReplay": "deny",
                    "onCrossLineage": "deny",
                    "onMissingEvidence": "deny",
                },
            },
        ]
    )
    envelope = next(
        constraint
        for constraint in durable_route["constraints"]
        if constraint["type"] == "responseEnvelope"
    )
    envelope["allowedResponseHeaderNames"] = ["etag"]
    envelope["responseHeaderRules"] = [
        {
            "name": "etag",
            "required": False,
            "predicate": {
                "kind": "pattern",
                "pattern": '^"[A-Za-z0-9._-]{1,64}"$',
                "maxLength": 66,
            },
        }
    ]
    compile_policy_bundle(durable, validate_schema=validate_schema)
    cursor_in_lineage = copy.deepcopy(durable)
    invalid_traversal = next(
        constraint
        for constraint in cursor_in_lineage["routes"][0]["constraints"]
        if constraint["type"] == "traversalBudget"
    )
    invalid_traversal["traversal"]["lineage"]["queryFields"] = [
        "cursor",
        "query",
    ]
    assert_policy_rejected(
        cursor_in_lineage,
        "compiler accepted a query cursor in stable traversal lineage",
        validate_schema=validate_schema,
    )
    omitted_lineage = copy.deepcopy(durable)
    omitted_traversal = next(
        constraint
        for constraint in omitted_lineage["routes"][0]["constraints"]
        if constraint["type"] == "traversalBudget"
    )
    omitted_traversal["traversal"]["lineage"]["queryFields"].remove(
        "reflectCredential"
    )
    assert_policy_rejected(
        omitted_lineage,
        "compiler accepted traversal lineage with an omitted shaping query",
        validate_schema=validate_schema,
    )
    try:
        constraints.traversal_budget_claims(
            SimpleNamespace(
                id="route.invalid-cursor-lineage",
                credential_ref="cred-demo-bearer",
                constraints=[invalid_traversal],
            ),
            principal_id="agent:demo",
            credential_ref="cred-demo-bearer",
            credential_version=1,
            policy_hash="sha256:" + "5" * 64,
            operation_fields={"operation": "demo.echo"},
            canonical_query_fields={
                "cursor": None,
                "query": "bounded",
            },
            request_cursor_values={},
        )
    except ValueError as exc:
        assert "lineage contract" in str(exc), exc
    else:
        raise AssertionError(
            "traversal claim helper accepted its query cursor in lineage"
        )


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
