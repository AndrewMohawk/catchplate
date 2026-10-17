from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse


CERT_DIR = Path("/data/demo-upstream")
CA_CERT_PATH = CERT_DIR / "ca.pem"
CERT_PATH = CERT_DIR / "cert.pem"
KEY_PATH = CERT_DIR / "key.pem"

app = FastAPI(title="Catchplate demo upstream")
_REQUEST_COUNTS: dict[tuple[str, str], int] = {}
_REQUEST_COUNTS_BY_RUN: dict[tuple[str, str, str], int] = {}
_STRUCTURED_PROOF_STREAMS: dict[str, tuple[str, bytes]] = {
    "jsonl": (
        "application/x-ndjson",
        b'{"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n'
        b'{"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n',
    ),
    "json-array": (
        "application/json",
        b'[{"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"},'
        b'{"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}]',
    ),
    "json-sse": (
        "text/event-stream",
        b'event: hidden\nid: hidden-0\ndata: {"index":0,"kept":"alpha","nested":{"safe":"one","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n\n'
        b'event: hidden\nid: hidden-1\ndata: {"index":1,"kept":"beta","nested":{"safe":"two","secret":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}\n\n'
        b"data: [DONE]\n\n",
    ),
    "json-nested": (
        "application/json",
        b'{"requestId":"proof-request","profile":{"email":"operator@example.test","settings":{"theme":"dark","token":"hidden"},"secret":"hidden"},'
        b'"items":[{"id":"one","details":{"safe":"kept","secret":"hidden"},"secret":"hidden"}],'
        b'"audit":{"trace":"proof-trace","privateToken":"hidden"},"sawSecret":true,"upstreamSecret":"hidden"}',
    ),
    "form": (
        "application/x-www-form-urlencoded",
        b"kept=alpha&safe=one&sawSecret=true&hidden=hidden&upstreamSecret=hidden",
    ),
    "csv": (
        "text/csv",
        b"id,public,safe_note,sawSecret,hidden,upstreamSecret\n"
        b"one,alpha,kept,true,hidden,hidden\n"
        b"two,beta,kept-too,true,hidden,hidden\n",
    ),
}


def _record_request(request: Request) -> None:
    key = (request.method.upper(), request.url.path)
    _REQUEST_COUNTS[key] = _REQUEST_COUNTS.get(key, 0) + 1
    run_id = request.headers.get("x-catchplate-test-run")
    if run_id is None:
        user_agent = request.headers.get("user-agent", "")
        prefix = "catchplate-test-run/"
        if user_agent.startswith(prefix):
            run_id = user_agent[len(prefix) :]
    if run_id and len(run_id) <= 128 and run_id.isascii():
        run_key = (*key, run_id)
        _REQUEST_COUNTS_BY_RUN[run_key] = _REQUEST_COUNTS_BY_RUN.get(run_key, 0) + 1


def _epoch_millis(value: datetime) -> str:
    return str(int(value.timestamp() * 1000))


def _recent_gmail_internal_date() -> str:
    return _epoch_millis(datetime.now(timezone.utc) - timedelta(days=2))


def _old_gmail_internal_date() -> str:
    return _epoch_millis(datetime.now(timezone.utc) - timedelta(days=90))


def _cert_not_valid_after(cert: x509.Certificate) -> datetime:
    expires = getattr(cert, "not_valid_after_utc", None)
    if expires is not None:
        return expires
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _existing_cert_is_fresh() -> bool:
    if not (CA_CERT_PATH.exists() and CERT_PATH.exists() and KEY_PATH.exists()):
        return False
    try:
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        cert = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    except Exception:
        return False
    renewal_cutoff = datetime.now(timezone.utc) + timedelta(days=1)
    return _cert_not_valid_after(ca_cert) > renewal_cutoff and _cert_not_valid_after(cert) > renewal_cutoff


def gmail_message_view(message_id: str, *, internal_date: str | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": message_id,
        "threadId": f"thread-{message_id}",
        "labelIds": ["INBOX"],
        "snippet": f"snippet for {message_id}",
        "payload": {
            "headers": [
                {"name": "From", "value": "security@example.com"},
                {"name": "Subject", "value": f"Demo {message_id}"},
            ],
            "body": {"data": "redact-me"},
        },
        "raw": "redact-me",
        "secretDebug": "redact-me",
        "serverDebugSecret": "redact-me",
    }
    if internal_date is not None:
        item["internalDate"] = internal_date
    return item


def gmail_list_item(message_id: str) -> dict[str, str]:
    return {"id": message_id, "threadId": f"thread-{message_id}"}


def ensure_cert() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if _existing_cert_is_fresh():
        return
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Catchplate demo upstream CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Catchplate demo"),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "demo-upstream"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Catchplate demo"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("demo-upstream")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def request_view(request: Request) -> dict[str, Any]:
    headers = {key.lower(): value for key, value in request.headers.items()}
    authorization = headers.get("authorization")
    authorization_scheme = authorization.split(" ", 1)[0] if authorization else None
    return {
        "method": request.method,
        "path": request.url.path,
        "query": dict(request.query_params),
        "authorization": authorization,
        "authorization_present": authorization is not None,
        "authorization_scheme": authorization_scheme,
        "authorization_sha256": "sha256:" + hashlib.sha256(authorization.encode("utf-8")).hexdigest() if authorization else None,
        "credential_marker": {
            "Bearer demo-token-from-vault": "initial",
            "Bearer rotated-token-from-vault": "rotated",
        }.get(authorization, "other" if authorization else None),
        "proxy_authorization": headers.get("proxy-authorization"),
        "x_api_key": headers.get("x-api-key"),
        "catchplate_agent": headers.get("x-catchplate-agent"),
        "cookie": headers.get("cookie"),
    }


@app.api_route("/echo", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def echo(request: Request) -> dict[str, Any]:
    _record_request(request)
    view = request_view(request)
    # Normal success must not reflect the credential even in a field that the
    # response projection removes. Keep reflection explicit for its deny test.
    authorization = view.pop("authorization")
    view.pop("authorization_sha256")
    # Optional private acceptance oracle: return a comparison only, never the
    # supplied or observed digest. Existing sandbox responses stay unchanged.
    expected = view["query"].pop("expectedAuthorizationSha256", None)
    if expected is not None:
        actual = "sha256:" + hashlib.sha256((authorization or "").encode("utf-8")).hexdigest()
        view["authorization_matches_expected"] = hmac.compare_digest(expected.encode("utf-8"), actual.encode("ascii"))
        view["proxy_authorization_seen"] = "proxy-authorization" in request.headers
    view["query"]["_data_plane_token_seen"] = "x-catchplate-data-plane-token" in request.headers
    view["query"]["_cookie_seen"] = "cookie" in request.headers
    case = request.query_params.get("catalogProof")
    if case in {"full", "reflect_raw", "reflect_decoded"}:
        try:
            from scripts.operator_catalog_feature_checks import fixture_body
        except ModuleNotFoundError:
            from operator_catalog_feature_checks import fixture_body
        return Response(content=fixture_body(case, authorization,
            matched=view.get("authorization_matches_expected") is True,
            proxy_seen="proxy-authorization" in request.headers), media_type="application/json")
    if request.query_params.get("reflectCredential") == "1":
        view["credential_reflection"] = authorization
    return view


@app.api_route("/ordinary-client", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"])
async def ordinary_client(request: Request) -> Response:
    # This dedicated route consumes bytes; the pre-existing echo paths do not.
    # Count reached requests (including refused methods) without recording data.
    _record_request(request)
    import asyncio
    from starlette.requests import ClientDisconnect
    try:
        from scripts import operator_ordinary_client_fixture as fixture
    except ModuleNotFoundError:
        import operator_ordinary_client_fixture as fixture
    try:
        admission = fixture.admit_request(request.method, request.scope.get("raw_path", b""),
            request.scope.get("query_string", b""), request.scope.get("headers", []))
        body = await asyncio.wait_for(fixture.read_bounded_body(request.stream()),
            timeout=fixture.BODY_READ_TIMEOUT_SECONDS)
        outcome = fixture.verify_body(admission, body)
    except (fixture.FixtureRejected, TimeoutError, ClientDisconnect) as error:
        status = error.status_code if isinstance(error, fixture.FixtureRejected) else 400
        return Response(content=fixture.REJECTION_BODY, status_code=status,
            headers={"content-type": "application/json", "connection": "close"})
    # Explicit headers preserve the optional charset on 204. Starlette does not
    # generate a Content-Length for 204, and media_type=None adds no type header.
    return Response(content=outcome.body, status_code=outcome.status_code, headers=dict(outcome.headers))


@app.api_route("/approval/echo", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def approval_echo(request: Request) -> dict[str, Any]:
    return request_view(request)


@app.get("/stream-bytes")
async def stream_bytes(request: Request) -> Response:
    if request.query_params.get("reflectCredential") == "1":
        authorization = request.headers.get("authorization", "")
        body = b"s" * 16380 + authorization.encode("utf-8") + b"safe-tail"
        return Response(content=body, media_type="application/octet-stream")
    chunks = max(1, min(int(request.query_params.get("chunks", "8")), 64))
    chunk_size = max(1, min(int(request.query_params.get("chunkSize", "4096")), 16384))
    body = b"".join(bytes([index % 251]) * chunk_size for index in range(chunks))
    return Response(
        content=body,
        media_type="application/octet-stream",
        headers={
            "X-Catchplate-Stream-Bytes": str(len(body)),
            "X-Catchplate-Stream-Sha256": hashlib.sha256(body).hexdigest(),
        },
    )


@app.get("/proof-stream/{stream_format}")
async def structured_proof_stream(request: Request, stream_format: str) -> StreamingResponse:
    fixture = _STRUCTURED_PROOF_STREAMS.get(stream_format)
    if fixture is None:
        return StreamingResponse(iter([b"unknown stream fixture"]), status_code=404)
    _record_request(request)
    media_type, body = fixture

    async def stream_body():
        for offset in range(0, len(body), 17):
            yield body[offset : offset + 17]

    return StreamingResponse(stream_body(), media_type=media_type)


@app.api_route("/upload-bytes", methods=["POST", "PUT"])
async def upload_bytes(request: Request) -> dict[str, Any]:
    body = await request.body()
    view = request_view(request)
    view["bytes"] = len(body)
    view["sha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    return view


@app.api_route("/jsonl-redact", methods=["POST", "PUT"])
async def jsonl_redact(request: Request) -> StreamingResponse:
    view = request_view(request)
    pending = b""
    outputs: list[bytes] = []
    index = 0
    async for chunk in request.stream():
        pending += chunk
        while b"\n" in pending:
            raw_line, pending = pending.split(b"\n", 1)
            if not raw_line.strip():
                continue
            outputs.append(_jsonl_redact_response_line(raw_line, index, view))
            index += 1
    if pending.strip():
        outputs.append(_jsonl_redact_response_line(pending, index, view))

    async def lines():
        for line in outputs:
            yield line

    return StreamingResponse(lines(), media_type="application/x-ndjson")


def _jsonl_redact_response_line(raw_line: bytes, index: int, view: dict[str, Any]) -> bytes:
    item = json.loads(raw_line)
    nested = item.get("nested") if isinstance(item.get("nested"), dict) else {}
    saw_secret = "secret" in item or "secret" in nested
    response = {
        "index": item.get("index", index),
        "kept": item.get("kept"),
        "nested": nested,
        "sawSecret": saw_secret,
        "authorization_present": view["authorization_present"],
        "authorization_scheme": view["authorization_scheme"],
        "authorization_sha256": view["authorization_sha256"],
        "upstreamSecret": "must-be-redacted",
        "echoedSecret": item.get("secret") or nested.get("secret"),
    }
    return (json.dumps(response, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


@app.api_route("/json-array-redact", methods=["POST", "PUT"])
async def json_array_redact(request: Request) -> StreamingResponse:
    view = request_view(request)
    body = b""
    async for chunk in request.stream():
        body += chunk
    items = json.loads(body)
    if not isinstance(items, list):
        items = []

    async def stream_items():
        yield b"["
        for index, item in enumerate(items):
            if index:
                yield b","
            yield _json_array_redact_response_item(item, index, view)
        yield b"]"

    return StreamingResponse(stream_items(), media_type="application/json")


def _json_array_redact_response_item(item: dict[str, Any], index: int, view: dict[str, Any]) -> bytes:
    nested = item.get("nested") if isinstance(item.get("nested"), dict) else {}
    saw_secret = "secret" in item or "secret" in nested
    response = {
        "index": item.get("index", index),
        "kept": item.get("kept"),
        "nested": nested,
        "sawSecret": saw_secret,
        "authorization_present": view["authorization_present"],
        "authorization_scheme": view["authorization_scheme"],
        "authorization_sha256": view["authorization_sha256"],
        "upstreamSecret": "must-be-redacted",
        "echoedSecret": item.get("secret") or nested.get("secret"),
    }
    return json.dumps(response, separators=(",", ":"), sort_keys=True).encode("utf-8")


@app.api_route("/json-sse-redact", methods=["POST", "PUT"])
async def json_sse_redact(request: Request) -> StreamingResponse:
    view = request_view(request)
    body = b""
    async for chunk in request.stream():
        body += chunk
    items = _parse_sse_json_events(body)

    async def stream_events():
        for index, item in enumerate(items):
            yield _json_sse_redact_response_event(item, index, view)
        yield b"data: [DONE]\n\n"

    return StreamingResponse(stream_events(), media_type="text/event-stream")


def _parse_sse_json_events(raw: bytes) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    event_lines: list[bytes] = []
    for raw_line in raw.splitlines():
        line = raw_line.rstrip(b"\r")
        if not line:
            _append_sse_json_event(events, event_lines)
            event_lines = []
            continue
        event_lines.append(line)
    if event_lines:
        _append_sse_json_event(events, event_lines)
    return events


def _append_sse_json_event(events: list[dict[str, Any]], event_lines: list[bytes]) -> None:
    data_parts: list[bytes] = []
    for line in event_lines:
        if not line.startswith(b"data:"):
            continue
        value = line[5:]
        if value.startswith(b" "):
            value = value[1:]
        data_parts.append(value)
    if not data_parts:
        return
    data = b"\n".join(data_parts).strip()
    if data == b"[DONE]":
        return
    item = json.loads(data)
    if isinstance(item, dict):
        events.append(item)


def _json_sse_redact_response_event(item: dict[str, Any], index: int, view: dict[str, Any]) -> bytes:
    nested = item.get("nested") if isinstance(item.get("nested"), dict) else {}
    saw_secret = "secret" in item or "secret" in nested
    response = {
        "index": item.get("index", index),
        "kept": item.get("kept"),
        "nested": nested,
        "sawSecret": saw_secret,
        "authorization_present": view["authorization_present"],
        "authorization_scheme": view["authorization_scheme"],
        "authorization_sha256": view["authorization_sha256"],
        "upstreamSecret": "must-be-redacted",
        "echoedSecret": item.get("secret") or nested.get("secret"),
    }
    data = json.dumps(response, separators=(",", ":"), sort_keys=True)
    return (
        f"event: upstream-secret-{index}\n"
        f"id: event-secret-{index}\n"
        f"data: {data}\n\n"
    ).encode("utf-8")


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"secret", "privatetoken", "token", "padding", "upstreamsecret", "echoedsecret"}:
                return True
            if _contains_secret_key(item):
                return True
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


@app.api_route("/json-nested-redact", methods=["POST", "PUT"])
async def json_nested_redact(request: Request) -> StreamingResponse:
    _record_request(request)
    view = request_view(request)
    body = b""
    async for chunk in request.stream():
        body += chunk
    payload = json.loads(body)
    if not isinstance(payload, dict):
        payload = {}
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    settings = profile.get("settings") if isinstance(profile.get("settings"), dict) else {}
    audit = payload.get("audit") if isinstance(payload.get("audit"), dict) else {}
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    safe_items: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        safe_items.append(
            {
                "id": item.get("id", index),
                "details": {
                    "safe": details.get("safe"),
                    "secret": f"response-detail-secret-{index}",
                },
                "secret": f"response-item-secret-{index}",
            }
        )
    response = {
        "requestId": payload.get("requestId"),
        "profile": {
            "email": profile.get("email"),
            "settings": {
                "theme": settings.get("theme"),
                "token": "response-settings-token",
            },
            "secret": "response-profile-secret",
        },
        "items": safe_items,
        "audit": {
            "trace": audit.get("trace"),
            "privateToken": "response-audit-token",
        },
        "sawSecret": _contains_secret_key(payload),
        "authorization_present": view["authorization_present"],
        "authorization_scheme": view["authorization_scheme"],
        "authorization_sha256": view["authorization_sha256"],
        "upstreamSecret": "must-be-redacted",
        "echoedSecret": "top-secret-from-upstream",
    }
    body_out = json.dumps(response, separators=(",", ":"), sort_keys=True).encode("utf-8")

    async def stream_json():
        for offset in range(0, len(body_out), 311):
            yield body_out[offset : offset + 311]

    return StreamingResponse(stream_json(), media_type="application/json")


@app.api_route("/form-redact", methods=["POST", "PUT"])
async def form_redact(request: Request) -> StreamingResponse:
    view = request_view(request)
    body = b""
    async for chunk in request.stream():
        body += chunk
    pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    saw_secret = any(key in {"secret", "nested_secret", "padding"} for key, _ in pairs)
    kept_values = [value for key, value in pairs if key == "kept"]
    safe_values = [value for key, value in pairs if key == "safe"]
    response_pairs: list[tuple[str, str]] = []
    response_pairs.extend(("kept", value) for value in kept_values)
    response_pairs.extend(("safe", value) for value in safe_values)
    response_pairs.extend(
        [
            ("sawSecret", "true" if saw_secret else "false"),
            ("authorization_present", "true" if view["authorization_present"] else "false"),
            ("authorization_scheme", view["authorization_scheme"] or ""),
            ("authorization_sha256", view["authorization_sha256"] or ""),
            ("upstreamSecret", "must-be-redacted"),
            ("echoedSecret", "top-secret-from-upstream" if saw_secret else ""),
        ]
    )
    body_out = urlencode(response_pairs, doseq=True).encode("utf-8")

    async def stream_form():
        for offset in range(0, len(body_out), 257):
            yield body_out[offset : offset + 257]

    return StreamingResponse(stream_form(), media_type="application/x-www-form-urlencoded")


@app.api_route("/csv-redact", methods=["POST", "PUT"])
async def csv_redact(request: Request) -> StreamingResponse:
    view = request_view(request)
    body = b""
    async for chunk in request.stream():
        body += chunk
    reader = csv.DictReader(io.StringIO(body.decode("utf-8"), newline=""))
    rows = list(reader)
    secret_fields = {"secret", "token", "private", "padding", "upstreamsecret", "echoedsecret"}
    saw_secret = any(
        any((key or "").lower() in secret_fields and value for key, value in row.items())
        for row in rows
    )
    output = io.StringIO(newline="")
    fieldnames = [
        "id",
        "public",
        "safe_note",
        "sawSecret",
        "authorization_present",
        "authorization_scheme",
        "authorization_sha256",
        "upstreamSecret",
        "echoedSecret",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for index, row in enumerate(rows):
        writer.writerow(
            {
                "id": row.get("id") or str(index),
                "public": row.get("public") or "",
                "safe_note": row.get("safe_note") or "",
                "sawSecret": "true" if saw_secret else "false",
                "authorization_present": "true" if view["authorization_present"] else "false",
                "authorization_scheme": view["authorization_scheme"] or "",
                "authorization_sha256": view["authorization_sha256"] or "",
                "upstreamSecret": "must-be-redacted",
                "echoedSecret": "top-secret-from-upstream" if saw_secret else "",
            }
        )
    body_out = output.getvalue().encode("utf-8")

    async def stream_csv():
        for offset in range(0, len(body_out), 283):
            yield body_out[offset : offset + 283]

    return StreamingResponse(stream_csv(), media_type="text/csv")


@app.get("/gmail/v1/users/me/messages")
async def gmail_messages(request: Request) -> dict[str, Any]:
    _record_request(request)
    view = request_view(request)
    fixture_query = request.query_params.get("q") or ""
    if "catchplate-fixture-omit-internal-date" in fixture_query:
        view["messages"] = [
            gmail_list_item("pending-message-1"),
            gmail_list_item("pending-message-2"),
        ]
    elif "catchplate-fixture-old-internal-date" in fixture_query:
        view["messages"] = [gmail_list_item("old-list-message-1")]
    elif "catchplate-fixture-metadata-not-found" in fixture_query:
        view["messages"] = [
            gmail_list_item("recent-message-1"),
            gmail_list_item("missing-message-1"),
        ]
    elif "catchplate-fixture-duplicate-message-id" in fixture_query:
        view["messages"] = [
            gmail_list_item("duplicate-message-1"),
            gmail_list_item("duplicate-message-1"),
        ]
    else:
        view["messages"] = [
            gmail_list_item("recent-message-1"),
            gmail_list_item("recent-message-2"),
        ]
    return view


@app.get("/gmail/v1/users/me/messages/{message_id}")
async def gmail_message(message_id: str, request: Request) -> Any:
    _record_request(request)
    if request.query_params.get("format") == "metadata":
        if request.headers.get("authorization") not in {
            "Bearer demo-token-from-vault",
            "Bearer rotated-token-from-vault",
        }:
            return Response(
                content=json.dumps({"error": "metadata credential missing"}),
                status_code=401,
                media_type="application/json",
            )
        if message_id.startswith("missing"):
            return Response(
                content=json.dumps({"error": "not found"}),
                status_code=404,
                media_type="application/json",
            )
        return {
            "id": message_id,
            "internalDate": (
                _old_gmail_internal_date()
                if message_id.startswith("old")
                else _recent_gmail_internal_date()
            ),
        }
    view = request_view(request)
    view.update(
        gmail_message_view(
            message_id,
            internal_date=_old_gmail_internal_date() if message_id.startswith("old") else _recent_gmail_internal_date(),
        )
    )
    return view


@app.api_route("/2/tweets", methods=["GET", "POST", "DELETE"])
async def x_tweets(request: Request) -> dict[str, Any]:
    _record_request(request)
    view = request_view(request)
    view["data"] = [{"id": "tweet-1", "text": "demo"}]
    return view


@app.get("/_test/request-count")
async def request_count(method: str, path: str, run_id: str | None = None) -> dict[str, Any]:
    key = (method.upper(), path)
    count = (
        _REQUEST_COUNTS.get(key, 0)
        if run_id is None
        else _REQUEST_COUNTS_BY_RUN.get((*key, run_id), 0)
    )
    return {"method": key[0], "path": key[1], "runId": run_id, "count": count}


@app.api_route("/npm/{package}", methods=["PUT", "POST"])
async def npm_publish(package: str, request: Request) -> dict[str, Any]:
    payload = await request.json()
    versions = payload.get("versions") if isinstance(payload, dict) else None
    version = next(iter(versions)) if isinstance(versions, dict) and len(versions) == 1 else None
    view = request_view(request)
    view["package"] = package
    view["version"] = version
    view["published"] = True
    return view


@app.api_route("/npm/-/package/{package}/dist-tags/{tag}", methods=["PUT", "POST"])
async def npm_dist_tag(package: str, tag: str, request: Request) -> dict[str, Any]:
    view = request_view(request)
    view["package"] = package
    view["tag"] = tag
    view["dist_tag_written"] = True
    return view


if __name__ == "__main__":
    ensure_cert()
    # The canonical signed demo envelope permits no semantic response headers.
    # Transport metadata remains; do not add Uvicorn's Date/Server defaults.
    uvicorn.run(
        app, host="0.0.0.0", port=8443,
        ssl_keyfile=str(KEY_PATH), ssl_certfile=str(CERT_PATH),
        date_header=False, server_header=False,
    )
