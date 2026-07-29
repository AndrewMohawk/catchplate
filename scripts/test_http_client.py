#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.http_client import (
    HttpClientError,
    HttpDeadline,
    http_error_body,
    request_bytes,
    request_json_bytes,
)
from serverware import response_identity, runtime


class ParsedHeaders:
    def __init__(self, values: dict[str, list[str]]) -> None:
        self._values = {
            name.lower(): list(header_values)
            for name, header_values in values.items()
        }

    def get_all(self, name: str) -> list[str] | None:
        values = self._values.get(name.lower())
        return None if values is None else list(values)

    def get(self, name: str) -> str | None:
        values = self.get_all(name)
        return values[0] if values else None


class RecordingHttpErrorBody:
    def __init__(
        self,
        *,
        headers: dict[str, list[str]],
        body: bytes,
    ) -> None:
        self.headers = ParsedHeaders(headers)
        self.body = body
        self.offset = 0
        self.closed = False

    def read1(self, amount: int) -> bytes:
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


def exercise_http_error_body_contract() -> None:
    for label, headers in (
        ("absent", {}),
        ("identity", {"Content-Encoding": ["identity"]}),
        ("declared length", {"Content-Length": ["4"]}),
        ("chunked transfer", {"Transfer-Encoding": ["chunked"]}),
    ):
        error = RecordingHttpErrorBody(headers=headers, body=b"test")
        body = http_error_body(error, max_bytes=4)  # type: ignore[arg-type]
        if body != b"test" or error.closed:
            raise AssertionError(
                f"successful {label} parsed Content-Encoding changed caller ownership"
            )

    rejected_content_encodings = {
        "duplicate": ["identity", "identity"],
        "case difference": ["Identity"],
        "trailing whitespace": ["identity "],
        "parameter": ["identity; mode=strict"],
        "other encoding": ["gzip"],
    }
    failures = [
        (
            f"Content-Encoding {label}",
            {"Content-Encoding": values},
            b"test",
            4,
        )
        for label, values in rejected_content_encodings.items()
    ]
    failures.extend(
        (
            (
                "unsupported Transfer-Encoding",
                {"Transfer-Encoding": ["gzip"]},
                b"test",
                4,
            ),
            (
                "Content-Length with Transfer-Encoding",
                {
                    "Content-Length": ["4"],
                    "Transfer-Encoding": ["chunked"],
                },
                b"test",
                4,
            ),
            (
                "duplicate Content-Length",
                {"Content-Length": ["4", "4"]},
                b"test",
                4,
            ),
            (
                "invalid Content-Length",
                {"Content-Length": ["invalid"]},
                b"test",
                4,
            ),
            (
                "oversized declared body",
                {"Content-Length": ["5"]},
                b"",
                4,
            ),
            (
                "oversized bounded read",
                {},
                b"12345",
                4,
            ),
            (
                "truncated declared body",
                {"Content-Length": ["4"]},
                b"123",
                4,
            ),
            (
                "invalid bounded-read limit",
                {},
                b"",
                0,
            ),
        )
    )
    for label, headers, body, max_bytes in failures:
        error = RecordingHttpErrorBody(headers=headers, body=body)
        try:
            http_error_body(error, max_bytes=max_bytes)  # type: ignore[arg-type]
        except HttpClientError:
            if not error.closed:
                raise AssertionError(
                    f"http_error_body left its HTTPError open after {label}"
                )
        else:
            raise AssertionError(f"http_error_body accepted {label}")


class Handler(BaseHTTPRequestHandler):
    redirected_requests = 0
    redirected_secret: str | None = None
    reserve_mode = "declared"
    reserve_payloads: list[dict[str, object]] = []
    cleanup_payloads: list[dict[str, object]] = []

    def do_HEAD(self) -> None:
        if self.path != "/head":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "7")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/signed-error":
            body = b'{"error":"retry_later"}'
            body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
            proof_headers = (
                ("X-Serverware-Response-Key-Id", "sha256:" + "1" * 64),
                ("X-Serverware-Response-Body-SHA256", body_digest),
                ("X-Serverware-Response-Statement-B64", "c2lnbmVkLXN0YXRlbWVudA"),
                ("X-Serverware-Response-Statement-SHA256", "sha256:" + "2" * 64),
                ("X-Serverware-Response-Signature", "ed25519:c2lnbmF0dXJl"),
            )
            self.send_response_only(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Fixture-Order", "first")
            for name, value in proof_headers:
                self.send_header(name, value)
            self.send_header("X-Fixture-Order", "second")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/expected-error-slow-partial":
            self.send_response(429)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "2")
            self.end_headers()
            time.sleep(0.12)
            try:
                self.wfile.write(b"a")
                self.wfile.flush()
            except OSError:
                return
            time.sleep(0.12)
            try:
                self.wfile.write(b"b")
                self.wfile.flush()
            except OSError:
                pass
            return
        if self.path == "/expected-error-malformed-chunked":
            self.send_response(429)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"not-hex\r\n")
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/expected-error-truncated-chunked":
            self.send_response(429)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"5\r\nno")
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/expected-error-oversized-streamed":
            body = b"x" * 33
            self.send_response(429)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/expected-server-error":
            body = b'{"error":"unavailable"}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "3")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/expected-error-oversized":
            body = b"x" * 33
            self.send_response(413)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/duplicate-headers":
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "first=one")
            self.send_header("Set-Cookie", "second=two")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/content-encoding/"):
            _, _, status_kind, variant = self.path.split("/", 3)
            status = 200 if status_kind == "success" else 418
            body = b'{"ok":true}'
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "text/plain" if variant == "precedence" else "application/json",
            )
            if variant == "duplicate":
                self.send_header("Content-Encoding", "identity")
                self.send_header("Content-Encoding", "identity")
            else:
                encoding = {
                    "identity": "identity",
                    "case": "Identity",
                    "trailing-space": "identity ",
                    "parameter": "identity; mode=strict",
                    "gzip": "gzip",
                    "precedence": "gzip",
                }.get(variant)
                if encoding is not None:
                    self.send_header("Content-Encoding", encoding)
            self.send_header(
                "Content-Length",
                str(4097 if variant == "precedence" else len(body)),
            )
            self.end_headers()
            if variant != "precedence":
                self.wfile.write(body)
            return
        if self.path == "/oversized-declared":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "4097")
            self.end_headers()
            return
        if self.path == "/oversized-streamed":
            body = b'{"value":"' + b"x" * 4096 + b'"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/hostile-json/"):
            variant = self.path.rsplit("/", 1)[-1]
            body = {
                "duplicate": b'{"ok":true,"ok":false}',
                "nan": b'{"value":NaN}',
                "infinity": b'{"value":Infinity}',
                "negative-infinity": b'{"value":-Infinity}',
                "overflow": b'{"value":1e400}',
                "negative-zero": b'{"value":-0}',
                "unsafe-positive-integer": b'{"value":9007199254740992}',
                "unsafe-negative-integer": b'{"value":-9007199254740992}',
                "invalid-utf8": b'{"value":"\xff"}',
            }[variant]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/safe-integer-boundaries":
            body = (
                b'{"maximum":9007199254740991,'
                b'"minimum":-9007199254740991}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        if self.path == "/target":
            type(self).redirected_requests += 1
            type(self).redirected_secret = self.headers.get("X-Test-Secret")
            body = b"redirected"
        elif self.path == "/oversized":
            body = b"x" * 33
        else:
            body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length") or "0")
        payload = json.loads(self.rfile.read(content_length))
        if self.path.endswith("/reserve"):
            type(self).reserve_payloads.append(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if type(self).reserve_mode == "declared":
                self.send_header("Content-Length", str(256 * 1024 + 1))
                self.end_headers()
                return
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"oversized":"' + b"x" * (256 * 1024) + b'"}')
            return
        if self.path.endswith("/complete"):
            type(self).cleanup_payloads.append(payload)
            body = json.dumps(
                {
                    "apiVersion": "serverware.releaseAuthorization/v1",
                    "ok": True,
                    "authorized": False,
                    "state": "absent",
                    "reason": "reservation_absent",
                    "attemptId": payload["attemptId"],
                    "bindingDigest": payload["bindingDigest"],
                    "idempotentReplay": True,
                    "grantId": None,
                    "approvalRequestId": None,
                    "approvalStatus": None,
                    "approvalExpiresAt": None,
                    "approvalCreated": None,
                    "reservationExpiresAtEpochMs": None,
                    "dispatchStartedAtEpochMs": None,
                    "dispatchExpiresAtEpochMs": None,
                    "completionOutcome": None,
                    "retryAfterSeconds": 0,
                    "quotas": [],
                    "store": {"backend": "fixture", "ha": False},
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    exercise_http_error_body_contract()
    valid_response_nonce = response_identity.b64e(b"n" * 32)
    response_nonce_alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    final_nonce_index = response_nonce_alphabet.index(valid_response_nonce[-1])
    alias_nonce_index = (
        final_nonce_index + 1
        if final_nonce_index % 4 != 3
        else final_nonce_index - 1
    )
    noncanonical_response_nonce = (
        valid_response_nonce[:-1] + response_nonce_alphabet[alias_nonce_index]
    )
    for label, invalid_nonce in (
        ("missing", None),
        ("short", response_identity.b64e(b"n" * 31)),
        ("padded", valid_response_nonce + "="),
        ("noncanonical", noncanonical_response_nonce),
        ("overlong", response_identity.b64e(b"n" * 33)),
    ):
        try:
            response_identity.response_statement(
                method="POST",
                path="/fixture",
                query="",
                status_code=429,
                body=b"{}",
                response_headers=[],
                nonce=invalid_nonce,  # type: ignore[arg-type]
                context={},
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"responseSignature/v3 producer accepted {label} nonce"
            )
    with patch.object(
        response_identity,
        "response_public_key_info",
        return_value={
            "pem": "fixture",
            "spki_sha256": "sha256:" + "1" * 64,
        },
    ):
        valid_statement = response_identity.response_statement(
            method="POST",
            path="/fixture",
            query="",
            status_code=429,
            body=b"{}",
            response_headers=[],
            nonce=valid_response_nonce,
            context={},
        )
    with patch.object(
        response_identity,
        "sign_statement",
        return_value="ed25519:c2lnbmF0dXJl",
    ):
        response_identity.response_signature_headers(valid_statement)
        for label, invalid_nonce in (
            ("short", response_identity.b64e(b"n" * 31)),
            ("padded", valid_response_nonce + "="),
            ("noncanonical", noncanonical_response_nonce),
            ("overlong", response_identity.b64e(b"n" * 33)),
        ):
            mutated_statement = dict(valid_statement)
            mutated_statement["nonce"] = invalid_nonce
            try:
                response_identity.response_signature_headers(mutated_statement)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"response signature header producer accepted {label} nonce"
                )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        response = request_bytes(f"{base}/ok", timeout=2, max_bytes=32)
        if response.status != 200 or response.body != b'{"ok":true}':
            raise AssertionError(f"bounded request returned the wrong response: {response}")
        duplicate_headers = request_bytes(
            f"{base}/duplicate-headers",
            timeout=2,
            max_bytes=32,
        )
        if [
            value
            for name, value in duplicate_headers.raw_headers
            if name.lower() == "set-cookie"
        ] != ["first=one", "second=two"]:
            raise AssertionError(
                "bounded HTTP client collapsed or reordered repeated headers"
            )
        head_response = request_bytes(
            urllib.request.Request(f"{base}/head", method="HEAD"),
            timeout=2,
            max_bytes=32,
        )
        if (
            head_response.status != 200
            or head_response.body != b""
            or head_response.headers.get("content-length") != "7"
        ):
            raise AssertionError(
                "bounded HTTP client rejected valid HEAD representation length"
            )

        signed_error = request_bytes(
            urllib.request.Request(
                f"{base}/signed-error",
                headers={
                    "X-Serverware-Response-Nonce": valid_response_nonce,
                },
            ),
            timeout=2,
            max_bytes=256,
            expected_statuses=(429,),
            expected_content_types=("application/json",),
        )
        expected_signed_error_raw_headers = (
            ("Content-Type", "application/json"),
            ("X-Fixture-Order", "first"),
            ("X-Serverware-Response-Key-Id", "sha256:" + "1" * 64),
            (
                "X-Serverware-Response-Body-SHA256",
                "sha256:"
                + hashlib.sha256(b'{"error":"retry_later"}').hexdigest(),
            ),
            (
                "X-Serverware-Response-Statement-B64",
                "c2lnbmVkLXN0YXRlbWVudA",
            ),
            (
                "X-Serverware-Response-Statement-SHA256",
                "sha256:" + "2" * 64,
            ),
            ("X-Serverware-Response-Signature", "ed25519:c2lnbmF0dXJl"),
            ("X-Fixture-Order", "second"),
            ("Content-Length", str(len(b'{"error":"retry_later"}'))),
        )
        if (
            signed_error.status != 429
            or signed_error.body != b'{"error":"retry_later"}'
            or signed_error.raw_headers != expected_signed_error_raw_headers
        ):
            raise AssertionError(
                "expected signed HTTP error lost status, body, proof headers, or raw order"
            )
        try:
            request_bytes(
                f"{base}/signed-error",
                timeout=2,
                max_bytes=256,
            )
        except urllib.error.HTTPError as exc:
            try:
                if exc.code != 429:
                    raise AssertionError(
                        f"unexpected signed error returned status {exc.code}"
                    )
            finally:
                exc.close()
        else:
            raise AssertionError(
                "unexpected signed error stopped raising HTTPError"
            )
        try:
            request_bytes(
                f"{base}/expected-error-oversized",
                timeout=2,
                max_bytes=32,
                expected_statuses=(413,),
                expected_content_types=("application/octet-stream",),
            )
        except HttpClientError as exc:
            if "exceeds 32 bytes" not in str(exc):
                raise AssertionError(
                    f"oversized expected HTTP error failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError("oversized expected HTTP error was accepted")

        try:
            request_bytes(
                f"{base}/expected-error-slow-partial",
                timeout=2,
                max_bytes=32,
                deadline=HttpDeadline.after(0.2),
                expected_statuses=(429,),
                expected_content_types=("application/octet-stream",),
            )
        except HttpClientError as exc:
            if "deadline exceeded" not in str(exc):
                raise AssertionError(
                    f"partial expected HTTP error failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "partial expected HTTP error exceeded the total deadline"
            )

        for chunked_path in (
            "/expected-error-malformed-chunked",
            "/expected-error-truncated-chunked",
        ):
            try:
                request_bytes(
                    f"{base}{chunked_path}",
                    timeout=2,
                    max_bytes=32,
                    expected_statuses=(429,),
                    expected_content_types=("application/octet-stream",),
                )
            except HttpClientError as exc:
                if not any(
                    marker in str(exc)
                    for marker in (
                        "body is truncated",
                        "framing is invalid",
                        "body transport failed",
                    )
                ):
                    raise AssertionError(
                        f"{chunked_path} failed ambiguously: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"{chunked_path} expected HTTP error was accepted"
                )

        try:
            request_bytes(
                f"{base}/expected-error-oversized-streamed",
                timeout=2,
                max_bytes=32,
                expected_statuses=(429,),
                expected_content_types=("application/octet-stream",),
            )
        except HttpClientError as exc:
            if "exceeds 32 bytes" not in str(exc):
                raise AssertionError(
                    f"streamed expected HTTP error failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "streamed expected HTTP error bypassed the body limit"
            )

        expected_server_error = request_bytes(
            f"{base}/expected-server-error",
            timeout=2,
            max_bytes=64,
            expected_statuses=(503,),
            expected_content_types=("application/json",),
        )
        if (
            expected_server_error.status != 503
            or expected_server_error.body != b'{"error":"unavailable"}'
            or expected_server_error.headers.get("retry-after") != "3"
        ):
            raise AssertionError(
                "explicitly expected 5xx response was not captured exactly"
            )

        try:
            request_bytes(
                f"{base}/expected-server-error",
                timeout=2,
                max_bytes=64,
                expected_statuses=(502,),
                expected_content_types=("application/json",),
            )
        except urllib.error.HTTPError as exc:
            try:
                if exc.code != 503:
                    raise AssertionError(
                        f"wrong expected-error status became {exc.code}"
                    )
            finally:
                exc.close()
        else:
            raise AssertionError(
                "nonempty expected statuses captured an unlisted status"
            )

        for variant in ("absent", "identity"):
            response = request_json_bytes(
                f"{base}/content-encoding/success/{variant}",
                timeout=2,
                max_bytes=32,
                expected_statuses=(200,),
                expected_content_types=("application/json",),
            )
            if response.value != {"ok": True}:
                raise AssertionError(
                    f"canonical {variant} Content-Encoding response changed"
                )
        for hostile_variant in (
            "duplicate",
            "nan",
            "infinity",
            "negative-infinity",
            "overflow",
            "negative-zero",
            "unsafe-positive-integer",
            "unsafe-negative-integer",
            "invalid-utf8",
        ):
            try:
                request_json_bytes(
                    f"{base}/hostile-json/{hostile_variant}",
                    timeout=2,
                    max_bytes=64,
                    expected_statuses=(200,),
                    expected_content_types=("application/json",),
                )
            except HttpClientError:
                pass
            else:
                raise AssertionError(
                    "strict HTTP JSON parser accepted duplicate keys, a "
                    "noncanonical/unsafe number, or invalid UTF-8: "
                    f"{hostile_variant}"
                )
        safe_integer_boundaries = request_json_bytes(
            f"{base}/safe-integer-boundaries",
            timeout=2,
            max_bytes=128,
            expected_statuses=(200,),
            expected_content_types=("application/json",),
        )
        if safe_integer_boundaries.value != {
            "maximum": 9_007_199_254_740_991,
            "minimum": -9_007_199_254_740_991,
        }:
            raise AssertionError(
                "strict HTTP JSON parser changed safe integer boundaries"
            )

        for status_kind in ("success", "error"):
            for variant in (
                "duplicate",
                "case",
                "trailing-space",
                "parameter",
                "gzip",
                "precedence",
            ):
                try:
                    request_json_bytes(
                        f"{base}/content-encoding/{status_kind}/{variant}",
                        timeout=2,
                        max_bytes=32,
                        expected_statuses=(200,),
                        expected_content_types=("application/json",),
                    )
                except HttpClientError as exc:
                    if "Content-Encoding must be absent or exactly identity" not in str(
                        exc
                    ):
                        raise AssertionError(
                            "Content-Encoding was not rejected before status, media, "
                            f"or body handling for {status_kind}/{variant}: {exc}"
                        ) from exc
                except urllib.error.HTTPError as exc:
                    raise AssertionError(
                        "encoded error response reached status handling before the "
                        f"Content-Encoding gate for {variant}"
                    ) from exc
                else:
                    raise AssertionError(
                        f"forbidden Content-Encoding was accepted: {status_kind}/{variant}"
                    )

        for variant in ("absent", "identity"):
            try:
                request_bytes(
                    f"{base}/content-encoding/error/{variant}",
                    timeout=2,
                    max_bytes=32,
                )
            except urllib.error.HTTPError as exc:
                if exc.code != 418:
                    raise AssertionError(
                        f"canonical encoded error returned wrong status: {exc.code}"
                    ) from exc
            else:
                raise AssertionError(
                    f"canonical {variant} error response bypassed status handling"
                )

        redirect = urllib.request.Request(f"{base}/redirect", headers={"X-Test-Secret": "do-not-forward"})
        try:
            request_bytes(redirect, timeout=2, max_bytes=32)
        except urllib.error.HTTPError as exc:
            if exc.code != 302:
                raise AssertionError(f"redirect failed with the wrong status: {exc.code}") from exc
        else:
            raise AssertionError("HTTP redirect was followed")
        if Handler.redirected_requests or Handler.redirected_secret:
            raise AssertionError("redirect target received a credential-bearing request")

        try:
            request_bytes(f"{base}/oversized", timeout=2, max_bytes=32)
        except HttpClientError as exc:
            if "exceeds 32 bytes" not in str(exc):
                raise AssertionError(f"oversized response failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("oversized HTTP response was accepted")

        for oversized_path in (
            "/oversized-declared",
            "/oversized-streamed",
        ):
            try:
                request_json_bytes(
                    f"{base}{oversized_path}",
                    timeout=2,
                    max_bytes=4096,
                    expected_statuses=(200,),
                    expected_content_types=("application/json",),
                )
            except HttpClientError as exc:
                if "exceeds 4096 bytes" not in str(exc):
                    raise AssertionError(
                        f"{oversized_path} failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"{oversized_path} JSON response was accepted"
                )

        canonical_request = {"operation": {"operation": "fixture.forward"}}
        request_digest = "sha256:" + hashlib.sha256(
            runtime.canonical_json(canonical_request).encode("utf-8")
        ).hexdigest()
        for mode in ("declared", "streamed"):
            Handler.reserve_mode = mode
            expected = runtime.expected_release_authorization_identity(
                attempt_id=f"attempt:http-{mode}-oversize",
                flow_id=f"attempt:http-{mode}-oversize",
                principal_id="agent:http-fixture",
                route_id="route:http-fixture",
                credential_ref=None,
                credential_version=0,
                policy_hash="sha256:" + "a" * 64,
                request_digest=request_digest,
                operation_digest=None,
                operation_context=dict(canonical_request["operation"]),
                shared_quotas=[],
                require_jit_grant=False,
            )
            guard = runtime.ReleaseAuthorizationGuard(expected)
            reserve_count = len(Handler.reserve_payloads)
            cleanup_count = len(Handler.cleanup_payloads)
            with (
                patch.object(
                    runtime,
                    "atomic_release_authorization_enabled",
                    return_value=True,
                ),
                patch.object(
                    runtime,
                    "_release_authorization_base_url",
                    return_value=(
                        f"{base}/api/data-plane/release-authorizations"
                    ),
                ),
                patch.object(
                    runtime,
                    "_release_authorization_token",
                    return_value="fixture-token",
                ),
                patch.object(
                    runtime,
                    "_release_authorization_ssl_context",
                    return_value=None,
                ),
            ):
                try:
                    runtime.reserve_expected_release_authorization(
                        guard=guard,
                        operation_context=dict(canonical_request["operation"]),
                        canonical_request=canonical_request,
                        shared_quotas=[],
                    )
                except runtime.ReleaseAuthorizationClientError:
                    guard.cancel_not_forwarded_once()
                    guard.cancel_not_forwarded_once()
                else:
                    raise AssertionError(
                        f"{mode} oversized reserve response was accepted"
                    )
            if (
                len(Handler.reserve_payloads) != reserve_count + 1
                or len(Handler.cleanup_payloads) != cleanup_count + 1
                or Handler.cleanup_payloads[-1]
                != {
                    "apiVersion": (
                        "serverware.releaseAuthorizationComplete/v1"
                    ),
                    "attemptId": expected.attempt_id,
                    "bindingDigest": expected.binding_digest,
                    "outcome": "not_forwarded",
                }
                or not guard.cleanup_emitted
                or guard.cleanup_error
            ):
                raise AssertionError(
                    f"{mode} oversized reserve did not emit one exact cleanup"
                )

        for invalid in ("file:///etc/passwd", "http://user:password@localhost/", f"{base}/ok#fragment"):
            try:
                request_bytes(invalid, timeout=2, max_bytes=32)
            except HttpClientError:
                pass
            else:
                raise AssertionError(f"unsafe HTTP URL was accepted: {invalid}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print(json.dumps({"http_client": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
